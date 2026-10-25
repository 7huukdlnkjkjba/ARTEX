package server

import (
	"testing"
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
