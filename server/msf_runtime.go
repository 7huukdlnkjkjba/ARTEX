package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/msf"
)

// 自动派单兜底：worker 上报的漏洞常常没有锚定资产（asset_ids 为空或锚定失败），
// 旧逻辑此时 host=="" 直接 return，利用意图永远不会被派发。这里从 finding 的
// 摘要/证据文本里回收目标，保证"确认 → 派单"这条入口不因缺资产而断掉。
var (
	findingURLRe = regexp.MustCompile(`(?i)https?://[^\s"'<>()\[\]{}，。；、]+`)
	findingIPRe  = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?\b`)
)

// msfTargetFromFinding 从文本里抽取 (host, port)；找不到返回空。
func msfTargetFromFinding(text string) (string, int) {
	for _, raw := range findingURLRe.FindAllString(text, -1) {
		u, err := url.Parse(strings.TrimRight(raw, ".,;:"))
		if err != nil || u.Hostname() == "" {
			continue
		}
		port := 0
		if p := u.Port(); p != "" {
			port, _ = strconv.Atoi(p)
		}
		if port == 0 {
			if u.Scheme == "https" {
				port = 443
			} else {
				port = 80
			}
		}
		return u.Hostname(), port
	}
	if m := findingIPRe.FindStringSubmatch(text); m != nil {
		port := 0
		if m[2] != "" {
			port, _ = strconv.Atoi(m[2])
		}
		return m[1], port
	}
	return "", 0
}

// msfProc owns an ARTEX-managed msfrpcd instance so the Metasploit closed loop
// needs no manual start: on boot (unless disabled) ARTEX ensures an RPC endpoint
// is reachable, generating and persisting the password if needed.
type msfProc struct {
	mu       sync.Mutex
	cmd      *exec.Cmd
	password string
	port     int
	managed  bool // true = we started it; false = an external msfrpcd was reused
}

func (p *msfProc) Password() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.password
}

// Plaintext reports whether ARTEX itself started msfrpcd with -S (no TLS).
func (p *msfProc) Plaintext() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.managed
}

func (p *msfProc) Port() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.port == 0 {
		return 55553
	}
	return p.port
}

// msfAutoStartEnabled: default ON; ARTEX_MSF_AUTOSTART=0/false/off disables.
func msfAutoStartEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ARTEX_MSF_AUTOSTART"))) {
	case "0", "false", "off", "no":
		return false
	}
	return true
}

func msfRPCAddress() string {
	if a := strings.TrimSpace(os.Getenv("ARTEX_MSF_RPC_ADDR")); a != "" {
		return a
	}
	return "127.0.0.1"
}

// findMSFRPCD locates the msfrpcd launcher across PATH and the common Windows
// Metasploit install root.
func findMSFRPCD() string {
	for _, name := range []string{"msfrpcd", "msfrpcd.bat"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	if runtime.GOOS == "windows" {
		root := os.Getenv("METASPLOIT_ROOT")
		if root == "" {
			root = `C:\metasploit-framework`
		}
		p := filepath.Join(root, "bin", "msfrpcd.bat")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// msfPythonBin resolves the Python interpreter: ARTEX_MSF_PYTHON wins, then
// python/python3/py on PATH.
func msfPythonBin() string {
	if p := strings.TrimSpace(os.Getenv("ARTEX_MSF_PYTHON")); p != "" {
		return p
	}
	for _, name := range []string{"python", "python3", "py"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

func mcpModuleAvailable(python string) bool {
	if python == "" {
		return false
	}
	check := exec.Command(python, "-c", "import mcp_pymetasploit3")
	check.Stdout, check.Stderr = nil, nil
	return check.Run() == nil
}

func mcpConsoleAvailable() bool {
	_, err := exec.LookPath("mcp-pymetasploit3[mcp]")
	return err == nil
}

// mcpReady reports whether the launcher we would actually use is installed.
// When ARTEX_MSF_PYTHON pins an interpreter, that interpreter is authoritative
// (a console script elsewhere on PATH is ignored), which also makes the
// auto-install path testable against a clean venv.
func mcpReady() bool {
	if p := strings.TrimSpace(os.Getenv("ARTEX_MSF_PYTHON")); p != "" {
		return mcpModuleAvailable(p)
	}
	return mcpConsoleAvailable() || mcpModuleAvailable(msfPythonBin())
}

// findMCPLauncher resolves how to spawn mcp-pymetasploit3 without requiring the
// user to configure an MCP server row: console script first, then `python -m`.
func findMCPLauncher() (string, []string, bool) {
	if strings.TrimSpace(os.Getenv("ARTEX_MSF_PYTHON")) == "" {
		if p, err := exec.LookPath("mcp-pymetasploit3[mcp]"); err == nil {
			return p, nil, true
		}
	}
	python := msfPythonBin()
	if !mcpModuleAvailable(python) {
		return "", nil, false
	}
	return python, []string{"-m", "mcp_pymetasploit3"}, true
}

// msfAutoInstallEnabled: default ON; ARTEX_MSF_AUTO_INSTALL=0/false/off disables.
func msfAutoInstallEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ARTEX_MSF_AUTO_INSTALL"))) {
	case "0", "false", "off", "no":
		return false
	}
	return true
}

// ensureMCPPython installs mcp-pymetasploit3 on first boot when it is missing.
// It runs in the background so a slow/absent network never blocks ARTEX startup;
// every failure is logged and the closed loop degrades to "MCP unavailable".
func (s *Server) ensureMCPPython() {
	if mcpReady() {
		return
	}
	if !msfAutoInstallEnabled() {
		log.Printf("[msf] 未安装 mcp-pymetasploit3，且自动安装已关闭（ARTEX_MSF_AUTO_INSTALL）")
		return
	}
	python := msfPythonBin()
	if python == "" {
		log.Printf("[msf] 未找到 Python，无法自动安装 mcp-pymetasploit3；请安装 Python 3.11+ 后重启")
		return
	}
	log.Printf("[msf] 未检测到 mcp-pymetasploit3，开始自动安装（pip，最长 5 分钟）…")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	go func() {
		select {
		case <-s.ctx.Done():
			cancel()
		case <-ctx.Done():
		}
	}()
	cmd := exec.CommandContext(ctx, python, "-m", "pip", "install", "--disable-pip-version-check", "--upgrade", "mcp-pymetasploit3[mcp]")
	out, err := cmd.CombinedOutput()
	if err != nil {
		tail := strings.TrimSpace(string(out))
		if len(tail) > 800 {
			tail = tail[len(tail)-800:]
		}
		log.Printf("[msf] 自动安装失败：%v\n%s", err, tail)
		return
	}
	if !mcpReady() {
		log.Printf("[msf] pip 返回成功但仍无法导入 mcp_pymetasploit3（检查 PATH / venv）")
		return
	}
	log.Printf("[msf] mcp-pymetasploit3 自动安装完成")
}

// maybeStartMSF is called once during server construction. It is best-effort:
// every failure is logged and leaves the feature disabled instead of blocking
// startup.
func (s *Server) maybeStartMSF() {
	// 依赖安装与 RPC 自动启动解耦：即使 RPC 用外部实例（AUTOSTART=0），
	// 也仍然需要 mcp-pymetasploit3，否则闭环不可用。
	go s.ensureMCPPython() // 首次启动自动补齐 mcp-pymetasploit3（ARTEX_MSF_AUTO_INSTALL=0 可关）
	if !msfAutoStartEnabled() {
		log.Printf("[msf] 自动启动已关闭（ARTEX_MSF_AUTOSTART）")
		return
	}
	port := 55553
	if v := strings.TrimSpace(os.Getenv("ARTEX_MSF_RPC_PORT")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n < 65536 {
			port = n
		}
	}
	addr := msfRPCAddress()
	p := &msfProc{port: port}
	s.msfRPC = p

	// Reuse an already listening msfrpcd (docker-compose / operator-managed).
	if conn, err := net.DialTimeout("tcp", net.JoinHostPort(addr, strconv.Itoa(port)), 800*time.Millisecond); err == nil {
		_ = conn.Close()
		p.password = s.msfPasswordFromStore()
		log.Printf("[msf] 检测到外部 msfrpcd %s:%d，复用（managed=false）", addr, port)
		return
	}

	bin := findMSFRPCD()
	if bin == "" {
		log.Printf("[msf] 未找到 msfrpcd，跳过自动启动（安装 Metasploit 或在系统→MCP 手工配置后重启）")
		return
	}
	pw := s.msfPasswordFromStore()
	if pw == "" {
		pw = randomPassword()
		if s.m != nil && s.m.pg != nil {
			if err := s.m.pg.SetSetting("msf_rpc_password", pw); err != nil {
				log.Printf("[msf] 保存 RPC 密码失败：%v", err)
			}
		}
	}
	p.password = pw

	args := []string{"-P", pw, "-p", strconv.Itoa(port), "-S", "-n", "-a", addr}
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" && strings.HasSuffix(strings.ToLower(bin), ".bat") {
		cmd = exec.Command("cmd", append([]string{"/c", bin}, args...)...)
	} else {
		cmd = exec.Command(bin, args...)
	}
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		log.Printf("[msf] 启动 msfrpcd 失败：%v", err)
		return
	}
	p.cmd = cmd
	p.managed = true
	log.Printf("[msf] 已启动受管 msfrpcd pid=%d（%s:%d，明文仅监听 loopback）", cmd.Process.Pid, addr, port)

	// Wait for the RPC socket; msfrpcd needs a few seconds to boot the framework.
	go func() {
		deadline := time.Now().Add(90 * time.Second)
		for time.Now().Before(deadline) {
			if c, err := net.DialTimeout("tcp", net.JoinHostPort(addr, strconv.Itoa(port)), time.Second); err == nil {
				_ = c.Close()
				log.Printf("[msf] msfrpcd 就绪")
				return
			}
			select {
			case <-s.ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
		log.Printf("[msf] msfrpcd 90s 内未就绪；msf_execute 将报告连接失败")
	}()

	// Reap the child when the server shuts down.
	go func() {
		<-s.ctx.Done()
		p.stop()
	}()
}

// stop terminates the managed msfrpcd process tree.
func (p *msfProc) stop() {
	p.mu.Lock()
	cmd := p.cmd
	managed := p.managed
	p.cmd = nil
	p.managed = false
	p.mu.Unlock()
	if cmd == nil || cmd.Process == nil || !managed {
		return
	}
	if runtime.GOOS == "windows" {
		kill := exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(cmd.Process.Pid))
		if err := kill.Run(); err == nil {
			log.Printf("[msf] 已停止受管 msfrpcd")
			return
		}
	}
	_ = cmd.Process.Kill()
	log.Printf("[msf] 已停止受管 msfrpcd")
}

func randomPassword() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("artex-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// msfPasswordFromStore resolves the RPC password: env > settings.
func (s *Server) msfPasswordFromStore() string {
	if v := strings.TrimSpace(os.Getenv("ARTEX_MSF_RPC_PASSWORD")); v != "" {
		return v
	}
	if s.m != nil && s.m.pg != nil {
		if v, _, _ := s.m.pg.GetSetting("msf_rpc_password"); v != "" {
			return v
		}
	}
	return ""
}

// msfRPCAddrPort returns the address msf_execute should dial.
func (s *Server) msfRPCAddrPort() (string, int) {
	if s.msfRPC != nil {
		return msfRPCAddress(), s.msfRPC.Port()
	}
	return msfRPCAddress(), 55553
}

// msfAutoKick dispatches a high-priority exploit intent when a finding is
// confirmed and its class has a deterministic Metasploit path, so the loop starts
// without a human and without waiting for a planner round. A hint is still written
// to tell the planner the intent is already in the frontier.
func (s *Server) msfAutoKick(ctx context.Context, findingID int64) {
	if s.m == nil || s.m.pg == nil {
		return
	}
	f, err := s.m.pg.GetFinding(findingID)
	if err != nil || f == nil || f.Status != "confirmed" || f.TaskID == nil {
		return
	}
	class := msf.NormalizeClass(f.VulnClass + " " + f.Name)
	if class == "" {
		// No deterministic Metasploit path → hand the finding to the generic
		// Exploit Author, which writes and verifies a real script instead.
		s.kickExploitAuthor(ctx, f)
		return
	}
	task, ok := s.m.Task(strconv.FormatInt(*f.TaskID, 10))
	if !ok || task == nil || task.Store == nil {
		return
	}
	host, port := "", 0
	if len(f.AssetIDs) > 0 {
		if assets, err := s.m.pg.Assets().GetByIDs(f.AssetIDs); err == nil {
			for _, a := range assets {
				if a == nil {
					continue
				}
				if a.IP != "" {
					host = a.IP
				} else if a.Domain != "" {
					host = a.Domain
				}
				if a.Port != nil {
					port = *a.Port
				} else if len(a.OpenPorts) > 0 {
					if v, ok := a.OpenPorts[0]["port"].(float64); ok {
						port = int(v)
					}
				}
				if host != "" {
					break
				}
			}
		}
	}
	if host == "" {
		// 无资产锚点时从摘要/证据文本回收目标：否则自动派单入口会静默失效。
		host, port = msfTargetFromFinding(f.Summary + "\n" + f.Evidence)
	}
	if host == "" {
		return
	}
	target := host
	if port > 0 {
		target = fmt.Sprintf("%s:%d", host, port)
	}
	// 直接下发一条高优先级意图，而不是只给 planner 留提示：worker 池只从 frontier
	// 领取 open 意图，写进意图流后就不再依赖下一轮 planner 愿不愿意派单。
	// 同一漏洞已有 open/running 的利用意图时跳过，避免重复确认或重试造成扇出。
	if active, err := task.Store.HasActiveIntentForFinding(f.ID); err != nil {
		log.Printf("[msf] 检查漏洞 #%d 的既有利用意图失败：%v", f.ID, err)
	} else if active {
		log.Printf("[msf] 漏洞 #%d 已有未完成的利用意图，跳过重复派发", f.ID)
		return
	}
	intentID, err := task.Store.AddIntent(msfIntentPayload(f, class, target), 8, f.AssetIDs, "msf")
	if err != nil {
		log.Printf("[msf] 为确认漏洞 #%d 写入利用意图失败：%v", f.ID, err)
		// 写意图失败（DB 抖动等）时退回提示路径：至少让 planner 下一轮能看到并自行派单，
		// 不能因为自动派发失败把整条利用闭环静默丢掉。
		if _, hintErr := task.Store.AddNode(db.KindHint, map[string]any{
			"summary": "MSF 自动利用可用：" + target,
			"text": fmt.Sprintf("已确认漏洞 #%d（%s，类别 %s）命中 Metasploit 确定性利用路径，目标 %s。"+
				"自动派发意图失败，请手动派一条：worker 先 msf_plan 拿候选链，再 msf_execute 执行。"+
				"拿到 session 后按返回的取证结果写回 fact；失败按 msf_next 的 retry/degrade/stop 处理。",
				f.ID, f.Name, class, target),
			"auto": "msf",
		}, 0, "confirmed", "system", nil); hintErr != nil {
			log.Printf("[msf] 退回提示路径也失败：%v", hintErr)
			return
		}
		task.Notify()
		return
	}
	// 意图挂在漏洞节点下，保持"意图只能锚在已确认 fact/finding 上"的血缘约束。
	if f.NodeID != nil {
		_ = task.Store.Link(*f.NodeID, db.RelDerivedFrom, intentID)
	}
	if _, err := task.Store.AddNode(db.KindHint, map[string]any{
		"summary": "MSF 自动利用已派发：" + target,
		"text": fmt.Sprintf("已自动派发 Metasploit 利用意图 #%d（漏洞 #%d，%s，目标 %s）。"+
			"该意图已在 frontier，worker 会直接领取；不要为同一漏洞重复派单。", intentID, f.ID, class, target),
		"auto": "msf",
	}, 0, "confirmed", "system", nil); err != nil {
		log.Printf("[msf] 写入派发提示失败：%v", err)
	}
	// 任务已终态时引擎不领新意图：先复活（与 set_goals 同一条 admission 路径），
	// 否则这条意图会一直躺在 frontier 里，直到有人手动点「继续」。
	if isTerminalStatus(s.m.TaskStatus(task.ID)) {
		log.Printf("[msf] 任务 %s 已终态，复活以执行利用意图 #%d", task.ID, intentID)
		s.reviveTask(task)
	}
	task.Notify()
	log.Printf("[msf] 已为确认漏洞 #%d（%s）派发利用意图 #%d：%s", f.ID, class, intentID, target)
}

// kickExploitAuthor dispatches a generic exploit_author intent for a confirmed
// finding that has no deterministic Metasploit path. Dedup uses the same
// active-intent query as the MSF path, so re-confirmation cannot fan out.
func (s *Server) kickExploitAuthor(ctx context.Context, f *db.DBFinding) {
	if s.m == nil || s.m.pg == nil || f == nil || f.TaskID == nil {
		return
	}
	task, ok := s.m.Task(strconv.FormatInt(*f.TaskID, 10))
	if !ok || task == nil || task.Store == nil {
		return
	}
	host, port := "", 0
	if len(f.AssetIDs) > 0 {
		if assets, err := s.m.Assets().GetByIDs(f.AssetIDs); err == nil {
			for _, a := range assets {
				if a == nil {
					continue
				}
				if a.IP != "" {
					host = a.IP
				} else if a.Domain != "" {
					host = a.Domain
				}
				if a.Port != nil {
					port = *a.Port
				} else if len(a.OpenPorts) > 0 {
					if v, ok := a.OpenPorts[0]["port"].(float64); ok {
						port = int(v)
					}
				}
				if host != "" {
					break
				}
			}
		}
	}
	if host == "" {
		host, port = msfTargetFromFinding(f.Summary + "\n" + f.Evidence)
	}
	if host == "" {
		log.Printf("[exploit] 漏洞 #%d 无法确定目标主机，跳过 exploit_author 派单", f.ID)
		return
	}
	target := host
	if port > 0 {
		target = fmt.Sprintf("%s:%d", host, port)
	}
	if active, err := task.Store.HasActiveIntentForFinding(f.ID); err == nil && active {
		log.Printf("[exploit] 漏洞 #%d 已有未完成的利用意图，跳过重复派发", f.ID)
		return
	}
	vulnClass := strings.TrimSpace(f.VulnClass)
	if vulnClass == "" {
		vulnClass = f.Name
	}
	cve := ""
	if m := findingCVERe.FindString(f.VulnClass + " " + f.Name + " " + f.Summary); m != "" {
		cve = strings.ToUpper(m)
	}
	summary := fmt.Sprintf("为已确认漏洞 #%d「%s」写出可运行的 exp（目标 %s，类别 %s）："+
		"先用 web_search 找公开 PoC、必要时读目标源码，再 exploit_init/write/run 迭代，拿到真实回显后 exploit_verify；"+
		"打不通就 exploit_abandon 写清卡点。", f.ID, f.Name, target, vulnClass)
	intentID, err := task.Store.AddIntent(map[string]any{
		"summary":    summary,
		"action":     "exploit_author",
		"finding_id": f.ID,
		"target":     target,
		"vulnclass":  vulnClass,
		"cve":        cve,
		"language":   "python",
	}, 8, f.AssetIDs, "exploit")
	if err != nil {
		log.Printf("[exploit] 为漏洞 #%d 派单失败: %v", f.ID, err)
		return
	}
	if f.NodeID != nil {
		_ = task.Store.Link(*f.NodeID, db.RelDerivedFrom, intentID)
	}
	if _, err := task.Store.AddNode(db.KindHint, map[string]any{
		"summary": "Exploit Author 已派发：" + target,
		"text": fmt.Sprintf("已为漏洞 #%d 自动派发 exp 编写意图 #%d（目标 %s，类别 %s）。"+
			"该意图已在 frontier，不要为同一漏洞重复派单；若它 abandon，会写回 fact 说明卡点。",
			f.ID, intentID, target, vulnClass),
		"auto": "exploit",
	}, 0, "confirmed", "system", nil); err != nil {
		log.Printf("[exploit] 写入派发提示失败: %v", err)
	}
	if isTerminalStatus(s.m.TaskStatus(task.ID)) {
		log.Printf("[exploit] 任务 %s 已终态，复活以执行 exp 意图 #%d", task.ID, intentID)
		s.reviveTask(task)
	}
	task.Notify()
	log.Printf("[exploit] 已为漏洞 #%d（%s）派发 exploit_author 意图 #%d：%s", f.ID, vulnClass, intentID, target)
}

// msfIntentPayload builds the frontier intent for one confirmed finding. The
// summary must be self-contained: the worker may claim this intent without any
// planner round in between, so the intent itself has to say which tools to call
// and how to branch on failure.
func msfIntentPayload(f *db.DBFinding, class, target string) map[string]any {
	name := f.Name
	if name == "" {
		name = f.VulnClass
	}
	summary := fmt.Sprintf(
		"利用已确认漏洞 #%d「%s」（类别 %s，目标 %s）：先调用 msf_plan 取确定性候选链，再用 msf_execute 执行"+
			"（MCP 由平台托管，无需人启动）；msf_execute 拿到会话会自动采集证据并写回 fact，你只需核对结果并继续。"+
			"无会话或失败时按 msf_next 返回的 retry/degrade/stop 分支处理，禁止原样重试同一候选。",
		f.ID, name, class, target)
	return map[string]any{
		"summary":        summary,
		"action":         "msf_exploit",
		"msf_finding_id": f.ID,
		"msf_target":     target,
		"msf_class":      class,
	}
}

// StopManagedMSF terminates the msfrpcd process ARTEX started (no-op when we
// reused an external one). Called from the main shutdown path.
func (s *Server) StopManagedMSF() {
	if s.msfRPC != nil {
		s.msfRPC.stop()
	}
}
