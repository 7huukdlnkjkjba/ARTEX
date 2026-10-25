package server

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

// TestManagedMSFStart is an opt-in integration check: it spawns the managed
// msfrpcd (real Metasploit install required) and asserts the RPC socket opens.
//
//	ARTEX_MSF_MANUAL=1 go test ./server -run TestManagedMSFStart -v
func TestManagedMSFStart(t *testing.T) {
	if os.Getenv("ARTEX_MSF_MANUAL") != "1" {
		t.Skip("set ARTEX_MSF_MANUAL=1 to exercise a real msfrpcd")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &Server{ctx: ctx}
	defer s.StopManagedMSF()
	s.maybeStartMSF()
	if s.msfRPC == nil {
		t.Fatal("msfRPC not initialised")
	}
	addr := net.JoinHostPort("127.0.0.1", fmt.Sprint(s.msfRPC.Port()))
	deadline := time.Now().Add(90 * time.Second)
	for {
		if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("msfrpcd did not open %s", addr)
		}
		time.Sleep(2 * time.Second)
	}
	if s.msfRPC.Password() == "" {
		t.Fatal("empty RPC password")
	}
	if !s.msfRPC.Plaintext() {
		t.Fatal("managed msfrpcd should be plaintext (-S)")
	}
	t.Logf("managed msfrpcd ready on %s (plaintext, password len=%d)", addr, len(s.msfRPC.Password()))
}
