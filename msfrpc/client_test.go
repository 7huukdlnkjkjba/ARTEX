package msfrpc

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
)

// fakeMsfrpcd emulates the handful of msfrpcd endpoints the closed loop uses.
type fakeMsfrpcd struct {
	mu       sync.Mutex
	calls    [][]any // [method, token?, args...]
	password string
	handlers map[string]func(args []any) any
}

func newFake() *fakeMsfrpcd {
	f := &fakeMsfrpcd{password: "secret", handlers: map[string]func([]any) any{}}
	f.handlers["core.version"] = func([]any) any {
		return map[string]any{"version": "6.4.0-dev", "api": "1.0"}
	}
	f.handlers["session.list"] = func([]any) any {
		return map[string]any{
			"1": map[string]any{"type": "shell", "tunnel_peer": "10.0.0.5:4444", "via_exploit": "exploit/linux/ftp/vsftpd_234_backdoor", "username": "root"},
		}
	}
	f.handlers["module.info"] = func(args []any) any {
		if len(args) < 2 || args[1] != "exploit/linux/ftp/vsftpd_234_backdoor" {
			return map[string]any{"error_message": "module not found"}
		}
		return map[string]any{"name": "vsftpd_234_backdoor", "type": args[0]}
	}
	f.handlers["console.create"] = func([]any) any { return map[string]any{"id": 3, "busy": false} }
	f.handlers["console.write"] = func([]any) any { return map[string]any{"wrote": 12} }
	f.handlers["console.read"] = func([]any) any { return map[string]any{"data": "[*] started\n", "busy": false} }
	f.handlers["console.destroy"] = func([]any) any { return map[string]any{"result": "success"} }
	f.handlers["module.execute"] = func([]any) any {
		return map[string]any{"job_id": 7, "uuid": "abc"}
	}
	f.handlers["session.shell_write"] = func([]any) any { return map[string]any{"write_count": 3} }
	f.handlers["session.shell_read"] = func([]any) any { return "uid=0(root)\n" }
	f.handlers["session.meterpreter_read"] = func([]any) any { return "meterpreter > " }
	f.handlers["session.meterpreter_write"] = func([]any) any { return map[string]any{"result": "success"} }
	return f
}

func (f *fakeMsfrpcd) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/" {
		http.NotFound(w, r)
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "binary/message-pack" {
		http.Error(w, "bad content type "+ct, http.StatusBadRequest)
		return
	}
	raw, _ := io.ReadAll(r.Body)
	val, err := decode(raw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req, _ := val.([]any)
	if len(req) == 0 {
		http.Error(w, "empty request", http.StatusBadRequest)
		return
	}
	method, _ := req[0].(string)
	args := req[1:]

	f.mu.Lock()
	f.calls = append(f.calls, req)
	f.mu.Unlock()

	var reply any
	switch method {
	case "auth.login":
		user, _ := args[0].(string)
		pass, _ := args[1].(string)
		if user == "msf" && pass == f.password {
			reply = map[string]any{"result": "success", "token": "tok-123"}
		} else {
			reply = map[string]any{"result": "fail", "error_message": "Invalid Password"}
		}
	default:
		if len(args) == 0 || args[0] != "tok-123" {
			reply = map[string]any{"error_message": "Invalid Authentication Token"}
			break
		}
		args = args[1:]
		if h, ok := f.handlers[method]; ok {
			reply = h(args)
		} else {
			reply = map[string]any{"error_message": "unknown method " + method}
		}
	}
	body, err := encode(reply)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "binary/message-pack")
	_, _ = w.Write(body)
}

func (f *fakeMsfrpcd) lastCall(t *testing.T) []any {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		t.Fatal("没有收到任何 RPC 调用")
	}
	return f.calls[len(f.calls)-1]
}

func newTestClient(t *testing.T, f *fakeMsfrpcd, ssl bool) *Client {
	t.Helper()
	var srv *httptest.Server
	if ssl {
		srv = httptest.NewTLSServer(f)
	} else {
		srv = httptest.NewServer(f)
	}
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split host: %v", err)
	}
	port, _ := strconv.Atoi(portStr)
	return New(Options{Host: host, Port: port, SSL: ssl})
}

func TestLoginAndCall(t *testing.T) {
	f := newFake()
	c := newTestClient(t, f, false)
	ctx := context.Background()
	if c.Token() != "" {
		t.Fatal("初始 token 应为空")
	}
	if _, err := c.Call(ctx, "core.version"); err == nil {
		t.Fatal("未认证调用应报错")
	}
	if err := c.Login(ctx, "msf", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}
	if c.Token() != "tok-123" {
		t.Fatalf("token=%q", c.Token())
	}
	ver, err := c.Version(ctx)
	if err != nil || ver != "6.4.0-dev" {
		t.Fatalf("version=%q err=%v", ver, err)
	}
	// The token must be the first argument after the method name.
	call := f.lastCall(t)
	if call[0] != "core.version" || call[1] != "tok-123" {
		t.Fatalf("call=%v", call)
	}
}

func TestLoginRejectsBadPassword(t *testing.T) {
	f := newFake()
	c := newTestClient(t, f, false)
	err := c.Login(context.Background(), "msf", "wrong")
	if err == nil {
		t.Fatal("错误密码应失败")
	}
	if c.Token() != "" {
		t.Fatal("失败后不应有 token")
	}
}

func TestLoginOverTLS(t *testing.T) {
	f := newFake()
	c := newTestClient(t, f, true) // self-signed cert must be accepted
	if err := c.Login(context.Background(), "msf", "secret"); err != nil {
		t.Fatalf("TLS login: %v", err)
	}
}

func TestTypedHelpers(t *testing.T) {
	f := newFake()
	c := newTestClient(t, f, false)
	ctx := context.Background()
	if err := c.Login(ctx, "msf", "secret"); err != nil {
		t.Fatalf("login: %v", err)
	}

	sessions, err := c.Sessions(ctx)
	if err != nil {
		t.Fatalf("sessions: %v", err)
	}
	if s := sessions["1"]; s.Type != "shell" || s.ViaExploit == "" || s.TunnelPeer == "" {
		t.Fatalf("session=%+v", s)
	}

	if _, err := c.ModuleInfo(ctx, "exploit", "exploit/linux/ftp/vsftpd_234_backdoor"); err != nil {
		t.Fatalf("module info: %v", err)
	}
	if _, err := c.ModuleInfo(ctx, "exploit", "exploit/nope"); err == nil {
		t.Fatal("缺失模块应报错（用于 module_missing 分支）")
	}

	id, err := c.ConsoleCreate(ctx)
	if err != nil || id != 3 {
		t.Fatalf("console create id=%d err=%v", id, err)
	}
	if err := c.ConsoleWrite(ctx, id, "use x\nrun -j\n"); err != nil {
		t.Fatalf("console write: %v", err)
	}
	data, busy, err := c.ConsoleRead(ctx, id)
	if err != nil || data == "" || busy {
		t.Fatalf("console read data=%q busy=%v err=%v", data, busy, err)
	}
	if err := c.ConsoleDestroy(ctx, id); err != nil {
		t.Fatalf("console destroy: %v", err)
	}

	job, err := c.ModuleExecute(ctx, "exploit", "exploit/linux/ftp/vsftpd_234_backdoor", map[string]any{"RHOSTS": "10.0.0.5"})
	if err != nil || job["job_id"] == nil {
		t.Fatalf("execute job=%v err=%v", job, err)
	}

	out, err := c.SessionCommand(ctx, "1", "shell", "whoami\n")
	if err != nil || out == "" {
		t.Fatalf("shell cmd out=%q err=%v", out, err)
	}
	if _, err := c.SessionCommand(ctx, "1", "meterpreter", "sysinfo"); err != nil {
		t.Fatalf("meterpreter cmd: %v", err)
	}
}

// TestSessionListPayloadShape pins the decoded shape against a payload captured
// from a real msfrpcd 6.x response (session.list), so a codec regression shows
// up without needing a live daemon.
func TestSessionListPayloadShape(t *testing.T) {
	payload := map[string]any{
		"1": map[string]any{
			"type": "shell", "tunnel_peer": "10.0.0.5:4444", "via_exploit": "exploit/linux/ftp/vsftpd_234_backdoor",
			"via_payload": "payload/cmd/unix/generic", "desc": "Command shell", "info": "", "workspace": "false",
			"target_host": "", "username": "root", "uuid": "abc123", "exploit_uuid": "def456",
			"routes": []any{}, "arch": "cmd",
		},
	}
	raw, err := encode(payload)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := decode(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	blob, _ := json.Marshal(got)
	want := `{"1":{"arch":"cmd","desc":"Command shell","exploit_uuid":"def456","info":"","routes":[],"target_host":"","tunnel_peer":"10.0.0.5:4444","type":"shell","username":"root","uuid":"abc123","via_exploit":"exploit/linux/ftp/vsftpd_234_backdoor","via_payload":"payload/cmd/unix/generic","workspace":"false"}}`
	if string(blob) != want {
		t.Fatalf("payload shape drifted:\n got %s\nwant %s", blob, want)
	}
}
