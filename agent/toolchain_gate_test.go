package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

func fakeTool(name string, run func(context.Context, json.RawMessage) (actool.Result, error)) actool.CoreTool {
	if run == nil {
		run = func(context.Context, json.RawMessage) (actool.Result, error) { return actool.Text("ok"), nil }
	}
	return actool.Build(actool.Spec{
		Name:        name,
		Description: "fake " + name,
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"command": map[string]any{"type": "string"},
			},
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return run(ctx, in)
		},
	})
}

func TestClassifyHandroll(t *testing.T) {
	allowed := map[string]bool{"recon_http": true, "scan_rustscan": true, "sqlmap_run": true, "nuclei_run": true}
	cases := []struct {
		cmd    string
		target string // "" = must not be gated
	}{
		{"curl -s https://example.com/api?id=1", "recon_http"},
		{"curl.exe -k https://example.com", "recon_http"},
		{"wget -qO- http://example.com", "recon_http"},
		{"Invoke-WebRequest -Uri https://example.com", "recon_http"},
		{"irm https://example.com", "recon_http"},
		{`python -c "import requests;print(requests.get('http://x').status_code)"`, "recon_http"},
		{"nmap -sV -p- 10.0.0.5", "scan_rustscan"},
		{"rustscan -a 10.0.0.5", "scan_rustscan"},
		{"masscan 10.0.0.0/8 -p80", "scan_rustscan"},
		{"sqlmap -u http://x/?id=1 --dbs", "sqlmap_run"},
		{"nuclei -u http://x", "nuclei_run"},
		// not hand-rolls
		{"", ""},
		{"curl --version", ""},
		{"nmap --help", ""},
		{"ls -la", ""},
		{"echo curl", ""},
		{"grep curl access.log", ""},
		{"cat access.log | grep 'curl -'", ""},
		{"python script.py", ""},
		{"cat fallback.js | grep eval(", ""},
		{"msfconsole -q", ""},
		{"curl -s http://x/ | jq .", "recon_http"},
		{"cd /tmp && curl -s http://x/", "recon_http"},
		{"sudo nmap -sV 10.0.0.5", "scan_rustscan"},
	}
	for _, c := range cases {
		got := classifyHandroll(c.cmd, allowed)
		if c.target == "" {
			if got != nil {
				t.Errorf("classifyHandroll(%q) = %q, want nil", c.cmd, got.target)
			}
			continue
		}
		if got == nil {
			t.Errorf("classifyHandroll(%q) = nil, want %q", c.cmd, c.target)
			continue
		}
		if got.target != c.target {
			t.Errorf("classifyHandroll(%q) = %q, want %q", c.cmd, got.target, c.target)
		}
	}
}

func TestToolchainGateBlocksThenAllowsOverride(t *testing.T) {
	old := ToolchainGateEnabled
	ToolchainGateEnabled = func() bool { return true }
	t.Cleanup(func() { ToolchainGateEnabled = old })

	called := 0
	bash := fakeTool("Bash", func(_ context.Context, _ json.RawMessage) (actool.Result, error) {
		called++
		return actool.Text("ran"), nil
	})
	tools := []actool.CoreTool{bash, fakeTool("recon_http", nil), fakeTool("scan_rustscan", nil)}

	gated := ApplyToolchainGate(tools)
	var wrapped actool.CoreTool
	for _, tl := range gated {
		if tl.Name() == "Bash" {
			wrapped = tl
		}
	}
	if wrapped == nil || wrapped == bash {
		t.Fatal("Bash was not wrapped by the gate")
	}

	// 1) hand-rolled curl is refused, with the replacement tool named.
	res, err := wrapped.Call(context.Background(), json.RawMessage(`{"command":"curl -s http://x/"}`), nil)
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if !res.IsError {
		t.Fatal("curl should be refused")
	}
	if txt := res.Flatten(); !strings.Contains(txt, "recon_http") || !strings.Contains(txt, "override_reason") {
		t.Fatalf("refusal must name recon_http and the escape hatch, got: %s", txt)
	}
	if called != 0 {
		t.Fatal("inner Bash must not run when refused")
	}

	// 2) explicit override passes through.
	res, err = wrapped.Call(context.Background(), json.RawMessage(`{"command":"curl -F file=@a.png http://x/upload","override_reason":"file upload"}`), nil)
	if err != nil || res.IsError {
		t.Fatalf("override should run, err=%v res=%+v", err, res)
	}
	if called != 1 {
		t.Fatalf("inner Bash called %d times, want 1", called)
	}

	// 3) unrelated commands are untouched.
	if _, err := wrapped.Call(context.Background(), json.RawMessage(`{"command":"ls -la"}`), nil); err != nil {
		t.Fatal(err)
	}
	if called != 2 {
		t.Fatalf("ls should run, inner called %d times", called)
	}

	// 4) the added schema prop is advertised.
	props, _ := wrapped.InputSchema()["properties"].(map[string]any)
	if _, ok := props["override_reason"]; !ok {
		t.Fatal("override_reason missing from schema")
	}
}

func TestToolchainGateSkipsWhenReplacementMissing(t *testing.T) {
	old := ToolchainGateEnabled
	ToolchainGateEnabled = func() bool { return true }
	t.Cleanup(func() { ToolchainGateEnabled = old })

	bash := fakeTool("Bash", nil)
	out := ApplyToolchainGate([]actool.CoreTool{bash})
	if out[0] != bash {
		t.Fatal("Bash must not be gated when no replacement tool is available")
	}
}

func TestToolchainGateDisabled(t *testing.T) {
	old := ToolchainGateEnabled
	ToolchainGateEnabled = func() bool { return false }
	t.Cleanup(func() { ToolchainGateEnabled = old })

	bash := fakeTool("Bash", nil)
	out := ApplyToolchainGate([]actool.CoreTool{bash, fakeTool("recon_http", nil)})
	if out[0] != bash {
		t.Fatal("gate must be a no-op when disabled")
	}
}

func TestApplyBashPlatformNoteWindows(t *testing.T) {
	note := BashPlatformNote()
	if note == "" {
		t.Skip("not windows")
	}
	bash := fakeTool("Bash", nil)
	out := ApplyBashPlatformNote([]actool.CoreTool{bash})
	if !strings.Contains(out[0].Description(), "PowerShell") {
		t.Fatalf("Bash description must describe PowerShell, got %q", out[0].Description())
	}
}
