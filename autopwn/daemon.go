package autopwn

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/msfrt"
)

// Daemon is a running msfrpcd that this process started (or nil for a reused
// external one). Stop() kills the process tree and closes the log handle.
type Daemon struct {
	Cmd *exec.Cmd
	Log *os.File
}

// Stop terminates the daemon and releases its log handle. Safe on nil.
func (d *Daemon) Stop() {
	if d == nil {
		return
	}
	if d.Cmd != nil && d.Cmd.Process != nil {
		if runtime.GOOS == "windows" {
			_ = exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(d.Cmd.Process.Pid)).Run()
		}
		_ = d.Cmd.Process.Kill()
	}
	if d.Log != nil {
		_ = d.Log.Close()
		d.Log = nil
	}
}

// daemonSpec is how to launch an *external* msfrpcd (a normal Metasploit install).
type daemonSpec struct {
	Cmd   string
	Pre   []string
	Env   []string
	Label string
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// metasploitRoot resolves the Metasploit install root (METASPLOIT_ROOT wins).
func metasploitRoot() string {
	if r := strings.TrimSpace(os.Getenv("METASPLOIT_ROOT")); r != "" {
		return r
	}
	if runtime.GOOS == "windows" {
		return `C:\metasploit-framework`
	}
	return "/opt/metasploit-framework"
}

// msfDaemonSpec prefers launching the Ruby script directly with Metasploit's
// bundled interpreter over going through bin\msfrpcd.bat: the batch wrapper adds
// a cmd.exe layer that mangles passwords containing `!`/`&`/`^` and hides its own
// failures.
func msfDaemonSpec() (daemonSpec, error) {
	root := metasploitRoot()
	ruby := filepath.Join(root, "embedded", "bin", "ruby.exe")
	script := filepath.Join(root, "embedded", "framework", "msfrpcd")
	if runtime.GOOS == "windows" && fileExists(ruby) && fileExists(script) {
		return daemonSpec{
			Cmd:   ruby,
			Pre:   []string{script},
			Env:   rubyChildEnv(filepath.Join(root, "embedded", "bin"), filepath.Join(root, "embedded", "framework")),
			Label: ruby + " " + script,
		}, nil
	}
	for _, name := range []string{"msfrpcd", "msfrpcd.bat"} {
		p, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		if runtime.GOOS == "windows" && strings.HasSuffix(strings.ToLower(p), ".bat") {
			return daemonSpec{Cmd: "cmd", Pre: []string{"/c", p}, Env: os.Environ(), Label: p}, nil
		}
		return daemonSpec{Cmd: p, Env: os.Environ(), Label: p}, nil
	}
	return daemonSpec{}, fmt.Errorf("未找到 Metasploit（试过 %s 与 PATH）", ruby)
}

// rubyChildEnv puts the bundled Ruby first on PATH and clears ambient Ruby/Gem
// variables so the packaged install is used.
func rubyChildEnv(binDir, framework string) []string {
	drop := map[string]bool{
		"GEM_HOME": true, "GEM_PATH": true, "GEM_ROOT": true,
		"RUBY_ENGINE": true, "RUBY_ROOT": true, "BUNDLE_GEMFILE": true,
	}
	env := make([]string, 0, len(os.Environ())+2)
	for _, kv := range os.Environ() {
		name := kv
		if i := strings.Index(kv, "="); i >= 0 {
			name = kv[:i]
		}
		if drop[strings.ToUpper(name)] || strings.EqualFold(name, "PATH") {
			continue
		}
		env = append(env, kv)
	}
	path := binDir
	if old := os.Getenv("PATH"); old != "" {
		path += string(os.PathListSeparator) + old
	}
	out := append(env, "PATH="+path)
	if framework != "" {
		out = append(out, "BUNDLE_GEMFILE="+filepath.Join(framework, "Gemfile"))
	}
	return out
}

// PasswordOrRandom returns password, or a fresh 32-hex secret when it is empty.
func PasswordOrRandom(password string) string {
	if strings.TrimSpace(password) != "" {
		return password
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("artex-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// EnsureDaemon makes sure something answers on host:port.
//
// Order: an already-listening daemon is reused; otherwise an external Metasploit
// install is started; otherwise the Metasploit runtime baked into this binary is
// unpacked (first run) and started. ARTEX_MSF_BACKEND=external|embedded pins the
// choice (default auto).
func EnsureDaemon(ctx context.Context, host string, port int, password string, waitFor time.Duration, logf func(string, ...any)) (*Daemon, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	if reachable(addr) {
		logf("[*] 复用已运行的 msfrpcd %s", addr)
		return nil, nil
	}
	if waitFor <= 0 {
		waitFor = 180 * time.Second
	}
	backend := strings.ToLower(strings.TrimSpace(os.Getenv("ARTEX_MSF_BACKEND")))
	var externalErr error

	if backend != "embedded" {
		spec, err := msfDaemonSpec()
		if err == nil {
			var d *Daemon
			d, externalErr = startExternal(ctx, spec, addr, password, waitFor, logf)
			if externalErr == nil {
				return d, nil
			}
		} else {
			externalErr = err
		}
		if backend == "external" {
			return nil, externalErr
		}
		logf("[!] 外部 Metasploit 不可用：%v", externalErr)
		logf("[*] 改用内置运行时（单文件自解压）")
	}

	d, embErr := StartEmbedded(ctx, host, port, password, waitFor, logf)
	if embErr == nil {
		return d, nil
	}
	if externalErr != nil {
		return nil, fmt.Errorf("外部 Metasploit 启动失败（%v）；内置运行时也失败（%v）", externalErr, embErr)
	}
	return nil, embErr
}

// StartEmbedded unpacks the bundled Metasploit runtime (once per build) and
// starts msfrpcd from it. Exported so the ARTEX server can use the same backend.
func StartEmbedded(ctx context.Context, host string, port int, password string, waitFor time.Duration, logf func(string, ...any)) (*Daemon, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	a, err := msfrt.Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = a.Close() }()
	logf("[*] 内置运行时 %s（来源 %s，%.0f MB），检查解压状态…", a.Version, a.Source, float64(a.Size)/(1<<20))

	start := time.Now()
	rt, err := a.EnsureExtracted()
	if err != nil {
		return nil, err
	}
	if rt.Fresh {
		logf("[+] 首次运行：已解压到 %s（%.0fs）", rt.Root, time.Since(start).Seconds())
	} else {
		logf("[*] 复用已解压运行时 %s", rt.Root)
	}
	spec, err := rt.Spec()
	if err != nil {
		return nil, err
	}
	logPath := filepath.Join(rt.Root, "msfrpcd.log")
	cmd, log, err := spec.Start(host, port, "msf", password, logPath)
	if err != nil {
		return nil, err
	}
	logf("[*] 已启动内置 msfrpcd pid=%d（%s，日志 %s）", cmd.Process.Pid, net.JoinHostPort(host, strconv.Itoa(port)), logPath)
	d := &Daemon{Cmd: cmd, Log: log}
	return waitDaemon(ctx, d, net.JoinHostPort(host, strconv.Itoa(port)), logPath, waitFor, logf)
}

// startExternal starts an install-located msfrpcd, retrying once: a cold boot
// takes 20-60s and the first attempt after a previous instance died can lose the
// framework lock and exit at once.
func startExternal(ctx context.Context, spec daemonSpec, addr, password string, waitFor time.Duration, logf func(string, ...any)) (*Daemon, error) {
	var lastErr error
	for attempt := 1; attempt <= 2; attempt++ {
		d, logPath, err := spawnExternal(spec, addr, password, attempt, logf)
		if err == nil {
			return waitDaemon(ctx, d, addr, logPath, waitFor, logf)
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, err
		}
		logf("[!] 第 %d 次启动 msfrpcd 失败：%v", attempt, err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	return nil, lastErr
}

func spawnExternal(spec daemonSpec, addr, password string, attempt int, logf func(string, ...any)) (*Daemon, string, error) {
	args := append(append([]string{}, spec.Pre...),
		"-P", password, "-p", portOf(addr), "-S", "-n", "-f", "-a", hostOf(addr))
	cmd := exec.Command(spec.Cmd, args...)
	cmd.Env = spec.Env
	cmd.Stdin = nil
	logPath, f, err := openDaemonLog(addr)
	if err != nil {
		return nil, logPath, err
	}
	cmd.Stdout, cmd.Stderr = f, f
	if err := cmd.Start(); err != nil {
		_ = f.Close()
		return nil, logPath, fmt.Errorf("启动 msfrpcd 失败（%s）：%w", spec.Label, err)
	}
	logf("[*] 已启动 msfrpcd pid=%d（%s，第 %d 次，日志 %s）", cmd.Process.Pid, addr, attempt, logPath)
	return &Daemon{Cmd: cmd, Log: f}, logPath, nil
}

// waitDaemon polls the RPC socket, failing fast when the child exits and
// surfacing its log tail so "didn't come up" is never a mystery.
func waitDaemon(ctx context.Context, d *Daemon, addr, logPath string, waitFor time.Duration, logf func(string, ...any)) (*Daemon, error) {
	exited := make(chan int, 1)
	go func() {
		_ = d.Cmd.Wait()
		code := -1
		if d.Cmd.ProcessState != nil {
			code = d.Cmd.ProcessState.ExitCode()
		}
		exited <- code
	}()
	started := time.Now()
	deadline := time.Now().Add(waitFor)
	for time.Now().Before(deadline) {
		if reachable(addr) {
			logf("[+] msfrpcd 就绪：%s（%.0fs）", addr, time.Since(started).Seconds())
			return d, nil
		}
		select {
		case code := <-exited:
			d.Stop()
			return nil, fmt.Errorf("msfrpcd 启动后立即退出（exit=%d）：%s\n提示：① 确认端口无残留 msfrpcd（netstat -ano | findstr :%s）；② 若 ARTEX 在「下载」目录，Windows Defender/ASR 可能拦截子进程，换到 C:\\artex 再试；③ 也可先手工启动 msfrpcd 并复用（-msf-pass）",
				code, tailFile(logPath, 700), portOf(addr))
		case <-ctx.Done():
			d.Stop()
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	d.Stop()
	return nil, fmt.Errorf("msfrpcd 在 %s 内未就绪：%s", waitFor, tailFile(logPath, 700))
}

func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

func portOf(addr string) string {
	if _, p, err := net.SplitHostPort(addr); err == nil {
		return p
	}
	return "55553"
}

// tailFile returns the last n bytes of path ("" when unreadable).
func tailFile(path string, n int) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(b))
	if len(s) > n {
		s = "…" + s[len(s)-n:]
	}
	return s
}

func reachable(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 800*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// openDaemonLog picks a writable place for the daemon log. %TEMP% is sometimes
// ACL-restricted for binaries running out of a downloads folder (Defender/ASR),
// so the ARTEX cache dir is tried first and TEMP only as a fallback.
func openDaemonLog(addr string) (string, *os.File, error) {
	name := "msfrpcd-" + strings.ReplaceAll(addr, ":", "-") + ".log"
	candidates := []string{
		filepath.Join(msfrt.CacheBase(), "..", "logs"),
		os.TempDir(),
	}
	var lastErr error
	for _, dir := range candidates {
		dir = msfrt.LongPath(filepath.Clean(dir))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			lastErr = err
			continue
		}
		p := filepath.Join(dir, name)
		f, err := os.Create(p)
		if err == nil {
			return p, f, nil
		}
		lastErr = err
	}
	return "", nil, fmt.Errorf("创建 msfrpcd 日志失败：%w", lastErr)
}

