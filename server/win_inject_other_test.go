//go:build !windows

package server

import (
	"encoding/base64"
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
