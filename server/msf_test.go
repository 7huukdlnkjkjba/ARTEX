package server

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestSessionOutput(t *testing.T) {
	got := sessionOutput(`{"output":"uid=0(root) gid=0(root)\nhost\nLinux x 6.1"}`)
	if got == "" || got[:3] != "uid" {
		t.Fatalf("unexpected: %q", got)
	}
	if got := sessionOutput("plain text"); got != "plain text" {
		t.Fatalf("plain: %q", got)
	}
}

func TestParseSessionIDsAndDiff(t *testing.T) {
	before := parseSessionIDs(`{"1":{"type":"shell"}}`)
	if !before["1"] || len(before) != 1 {
		t.Fatalf("before=%v", before)
	}
	after := parseSessionIDs(`{"1":{"type":"shell"},"2":{"type":"meterpreter"}}`)
	got := diffSessions(before, after)
	if len(got) != 1 || got[0] != "2" {
		t.Fatalf("diff=%v", got)
	}
	if len(diffSessions(after, after)) != 0 {
		t.Fatal("no new sessions expected")
	}
}

func TestConsoleData(t *testing.T) {
	data, busy := consoleData(`{"data":"[*] started","busy":true}`)
	if data != "[*] started" || !busy {
		t.Fatalf("data=%q busy=%v", data, busy)
	}
	if d, _ := consoleData("not-json"); d != "not-json" {
		t.Fatalf("fallback=%q", d)
	}
}

func TestFindMCPLauncher(t *testing.T) {
	cmd, args, ok := findMCPLauncher()
	if !ok {
		t.Skip("mcp-pymetasploit3 not installed in this environment")
	}
	if cmd == "" {
		t.Fatal("empty command")
	}
	t.Logf("launcher: %s %v", cmd, args)
}

func TestScopeRowsAllowIPFromNet(t *testing.T) {
	rows := []db.TaskScope{{Kind: "ip", Net: "127.0.0.1/32"}}
	for _, h := range []string{"127.0.0.1", "http://127.0.0.1:8080/api/ping", "127.0.0.1:8080"} {
		if !scopeRowsAllow(rows, h) {
			t.Fatalf("%s 应命中授权范围", h)
		}
	}
	if scopeRowsAllow(rows, "127.0.0.2") {
		t.Fatal("127.0.0.2 不应命中")
	}
}

func TestScopeRowsAllowCIDRAndDomain(t *testing.T) {
	rows := []db.TaskScope{
		{Kind: "cidr", Net: "10.0.0.0/24"},
		{Kind: "root_domain", Domain: "example.com"},
	}
	for _, h := range []string{"10.0.0.9", "https://a.example.com/x", "example.com"} {
		if !scopeRowsAllow(rows, h) {
			t.Fatalf("%s 应命中授权范围", h)
		}
	}
	for _, h := range []string{"10.0.1.9", "example.net"} {
		if scopeRowsAllow(rows, h) {
			t.Fatalf("%s 不应命中授权范围", h)
		}
	}
}

func TestMSFTargetFromFinding(t *testing.T) {
	cases := []struct {
		text string
		host string
		port int
	}{
		{"PoC: curl http://127.0.0.1:8080/api/ping?host=x", "127.0.0.1", 8080},
		{"目标 https://example.com/login 存在反射", "example.com", 443},
		{"仅 IP 10.0.0.9:445 可达", "10.0.0.9", 445},
		{"没有可用的目标文本", "", 0},
	}
	for _, c := range cases {
		h, p := msfTargetFromFinding(c.text)
		if h != c.host || p != c.port {
			t.Fatalf("msfTargetFromFinding(%q)=(%q,%d) want (%q,%d)", c.text, h, p, c.host, c.port)
		}
	}
}
