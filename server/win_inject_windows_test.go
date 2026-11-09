//go:build windows

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWinInjectNormalizeWindows(t *testing.T) {
	p := &winInjectParams{Shellcode: base64.StdEncoding.EncodeToString([]byte{0x90}), Encoding: "base64"}
	sc, err := p.normalize()
	if err != nil || len(sc) != 1 || sc[0] != 0x90 {
		t.Fatalf("base64 = %x %v", sc, err)
	}
	p.Encoding = "hex"
	p.Shellcode = "9091"
	sc, err = p.normalize()
	if err != nil || len(sc) != 2 || sc[0] != 0x90 || sc[1] != 0x91 {
		t.Fatalf("hex = %x %v", sc, err)
	}
	p.Encoding = "raw"
	p.Shellcode = "abc"
	sc, err = p.normalize()
	if err != nil || string(sc) != "abc" {
		t.Fatalf("raw = %q %v", sc, err)
	}
	p.Shellcode = ""
	if _, err := p.normalize(); err == nil {
		t.Error("empty shellcode accepted")
	}
}

func TestWinInjectDryRunSelf(t *testing.T) {
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

// Opt-in live benign injection test; same helper-only target as before.
func TestWinInjectLiveBenign(t *testing.T) {
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
	if out["status"] != "success" || out["size"].(float64) != 3 {
		t.Fatalf("out = %+v", out)
	}
}
