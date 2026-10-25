package server

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestAutoInstallMCP is an opt-in check: point ARTEX_MSF_PYTHON at a clean venv
// and it verifies that ensureMCPPython installs mcp-pymetasploit3.
//
//	ARTEX_MSF_INSTALL_TEST=1 ARTEX_MSF_PYTHON=<venv>/Scripts/python.exe \
//	go test ./server -run TestAutoInstallMCP -v -timeout 6m
func TestAutoInstallMCP(t *testing.T) {
	if os.Getenv("ARTEX_MSF_INSTALL_TEST") != "1" {
		t.Skip("set ARTEX_MSF_INSTALL_TEST=1 with ARTEX_MSF_PYTHON to run")
	}
	if os.Getenv("ARTEX_MSF_PYTHON") == "" {
		t.Fatal("ARTEX_MSF_PYTHON must point at a clean interpreter")
	}
	s := &Server{ctx: context.Background()}
	start := time.Now()
	s.ensureMCPPython()
	elapsed := time.Since(start)
	expectFail := os.Getenv("ARTEX_MSF_INSTALL_EXPECT_FAIL") == "1"
	ready := mcpReady()
	if expectFail {
		if ready {
			t.Fatalf("expected install to fail/skip, but mcp is ready (took %s)", elapsed)
		}
		t.Logf("graceful failure/skip in %s", elapsed)
		return
	}
	if !ready {
		t.Fatal("mcp-pymetasploit3 still missing after auto-install")
	}
	t.Logf("auto-install ok in %s", elapsed)
}
