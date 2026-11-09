package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
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
