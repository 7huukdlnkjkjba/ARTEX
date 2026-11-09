package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDecodeWinShellcode(t *testing.T) {
	raw := []byte{0x90, 0x91, 0x92}
	b64 := base64.StdEncoding.EncodeToString(raw)
	for _, in := range []string{b64, "909192"} {
		got, err := decodeWinShellcode(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if string(got) != string(raw) {
			t.Errorf("%s => %x, want %x", in, got, raw)
		}
	}
	if _, err := decodeWinShellcode("@@@@"); err == nil {
		t.Error("invalid shellcode accepted")
	}
	if _, err := decodeWinShellcode(""); err == nil {
		t.Error("empty shellcode accepted")
	}
}

func TestWinInjectNormalize(t *testing.T) {
	sc := base64.StdEncoding.EncodeToString([]byte{0x90})
	p := &winInjectParams{PID: 4, ProcessName: "x.exe", Shellcode: sc}
	if _, err := p.Normalize(); err == nil {
		t.Error("pid 4 accepted")
	}
	p.PID = 100
	if _, err := p.Normalize(); err == nil || !strings.Contains(err.Error(), "confirm=true") {
		t.Errorf("confirm: %v", err)
	}
	p.DryRun = true
	if _, err := p.Normalize(); err != nil {
		t.Fatal(err)
	}
	p.Method = "apc"
	if _, err := p.Normalize(); err == nil {
		t.Error("apc accepted")
	}
}

func TestWinInjectToolsRegistered(t *testing.T) {
	found := false
	for _, tool := range (&Server{}).winInjectTools() {
		if tool.Name() == "win_inject" {
			found = true
			if !strings.Contains(tool.Description(), "confirm=true") {
				t.Error("description should mention confirm")
			}
		}
	}
	if !found {
		t.Fatal("win_inject not registered")
	}
}

func TestWinInjectDryRunSelf(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{
		"pid": os.Getpid(), "process_name": filepath.Base(exe),
		"shellcode": base64.StdEncoding.EncodeToString([]byte{0x90}),
		"dry_run":   true,
	})
	res, err := (&Server{}).toolWinInject().Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("dry run error: %s", res.Flatten())
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatal(err)
	}
	if out["status"] != "dry_run" || out["process_path"] == "" {
		t.Errorf("out = %+v", out)
	}
}

func TestWinInjectRequiresConfirm(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only")
	}
	exe, _ := os.Executable()
	raw, _ := json.Marshal(map[string]any{
		"pid": os.Getpid(), "process_name": filepath.Base(exe),
		"shellcode": base64.StdEncoding.EncodeToString([]byte{0x90}),
	})
	res, err := (&Server{}).toolWinInject().Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(res.Flatten(), "confirm=true") {
		t.Fatalf("res = %v %s", res.IsError, res.Flatten())
	}
}

func TestWinInjectProcessMismatch(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only")
	}
	raw, _ := json.Marshal(map[string]any{
		"pid": os.Getpid(), "process_name": "definitely-not-this.exe",
		"shellcode": base64.StdEncoding.EncodeToString([]byte{0x90}), "dry_run": true,
	})
	res, err := (&Server{}).toolWinInject().Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(res.Flatten(), "进程名不匹配") {
		t.Fatalf("res = %v %s", res.IsError, res.Flatten())
	}
}

// TestWinInjectLiveBenign is an explicit, opt-in live test. It builds a tiny
// helper process that just sleeps, injects a 3-byte "xor eax,eax; ret" stub into
// that helper only, and verifies CreateRemoteThread succeeded. It never targets
// a system/EDR process. Default runs skip; set ARTEX_WIN_INJECT_LIVE=1 to run.
func TestWinInjectLiveBenign(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only")
	}
	if os.Getenv("ARTEX_WIN_INJECT_LIVE") != "1" {
		t.Skip("set ARTEX_WIN_INJECT_LIVE=1 to run the live benign injection test")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "sleep.go")
	if err := os.WriteFile(src, []byte("package main\nimport \"time\"\nfunc main(){ time.Sleep(60*time.Second) }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "artex-sleep.exe")
	build := exec.Command("go", "build", "-o", exe, src)
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build helper: %v\n%s", err, out)
	}
	child := exec.Command(exe)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = child.Process.Kill()
		_, _ = child.Process.Wait()
	}()
	time.Sleep(300 * time.Millisecond)

	// 31 C0 C3 = xor eax,eax; ret. Thread returns immediately; no payload logic.
	raw, _ := json.Marshal(map[string]any{
		"pid": child.Process.Pid, "process_name": filepath.Base(exe),
		"shellcode": base64.StdEncoding.EncodeToString([]byte{0x31, 0xC0, 0xC3}),
		"confirm":   true,
	})
	res, err := (&Server{}).toolWinInject().Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("live injection failed: %s", res.Flatten())
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatal(err)
	}
	if out["status"] != "success" || out["injected_bytes"].(float64) != 3 {
		t.Fatalf("out = %+v", out)
	}
}
