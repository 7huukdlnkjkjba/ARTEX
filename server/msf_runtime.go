package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/msf"
)

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
	if !msfAutoStartEnabled() {
		log.Printf("[msf] 自动启动已关闭（ARTEX_MSF_AUTOSTART）")
		return
	}
	go s.ensureMCPPython() // 首次启动自动补齐 mcp-pymetasploit3（ARTEX_MSF_AUTO_INSTALL=0 可关）
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

// msfAutoKick wakes the planner with a hint when a finding is confirmed and its
// class has a deterministic Metasploit path, so the loop starts without a human.
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
		return
	}
	target := host
	if port > 0 {
		target = fmt.Sprintf("%s:%d", host, port)
	}
	text := fmt.Sprintf(
		"已确认漏洞 #%d（%s，类别 %s）命中 Metasploit 确定性利用路径，目标 %s。"+
			"请优先派一条意图：worker 先 msf_plan 拿候选链，再 msf_execute 自动执行（MCP 由平台托管，无需人启动）；"+
			"拿到 session 后按 session_post 取证并写回 fact；失败按返回的 action（retry/degrade/stop）处理。",
		f.ID, f.Name, class, target)
	if _, err := task.Store.AddNode(db.KindHint, map[string]any{
		"summary": "MSF 自动利用可用：" + target,
		"text":    text,
		"auto":    "msf",
	}, 0, "confirmed", "system", nil); err != nil {
		log.Printf("[msf] 写入自动利用提示失败：%v", err)
		return
	}
	task.Notify()
	log.Printf("[msf] 已为确认漏洞 #%d（%s）唤醒 planner：%s", f.ID, class, target)
}

// StopManagedMSF terminates the msfrpcd process ARTEX started (no-op when we
// reused an external one). Called from the main shutdown path.
func (s *Server) StopManagedMSF() {
	if s.msfRPC != nil {
		s.msfRPC.stop()
	}
}
