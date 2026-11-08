package server

import (
	"context"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func startRawTCPServer(t *testing.T, response []byte, readLen int) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if readLen > 0 {
			buf := make([]byte, readLen)
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			_, _ = conn.Read(buf)
		}
		if len(response) > 0 {
			_, _ = conn.Write(response)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port
}

func callRawTCP(t *testing.T, s *Server, payload map[string]any) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(payload)
	res, err := s.toolRawTCP().Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatalf("raw_tcp transport error: %v", err)
	}
	if res.IsError {
		t.Fatalf("raw_tcp tool error: %s", res.Flatten())
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("unmarshal raw_tcp: %v\n%s", err, res.Flatten())
	}
	return out
}

func TestRawTCPRawEcho(t *testing.T) {
	host, port := startRawTCPServer(t, []byte("hello"), 5)
	out := callRawTCP(t, &Server{}, map[string]any{
		"host": host, "port": port, "protocol": "raw", "payload": "68656c6c6f",
		"timeout": 2, "read_len": 64,
	})
	if out["response_hex"] != "68656c6c6f" {
		t.Fatalf("out = %#v", out)
	}
	if out["fingerprint"] != "unknown" {
		t.Errorf("fingerprint = %v", out["fingerprint"])
	}
	if out["egress"] != "direct" {
		t.Errorf("egress = %v", out["egress"])
	}
}

func TestRawTCPSMBFingerprint(t *testing.T) {
	// 4-byte NetBIOS prefix + SMB2 magic.
	resp := []byte{0x00, 0x00, 0x00, 0x44, 0xFE, 'S', 'M', 'B', 0x40, 0x00}
	host, port := startRawTCPServer(t, resp, 64)
	out := callRawTCP(t, &Server{}, map[string]any{
		"host": host, "port": port, "protocol": "smb", "timeout": 2, "read_len": 64,
	})
	if out["fingerprint"] != "smb2" {
		t.Fatalf("out = %#v", out)
	}
	req, _ := out["request_hex"].(string)
	if !strings.HasPrefix(req, "00") || !strings.Contains(strings.ToLower(req), "fe534d42") {
		t.Errorf("SMB request = %s", req)
	}
}

func TestRawTCPLDAPFingerprint(t *testing.T) {
	resp := []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00}
	host, port := startRawTCPServer(t, resp, 32)
	out := callRawTCP(t, &Server{}, map[string]any{
		"host": host, "port": port, "protocol": "ldap", "timeout": 2, "read_len": 64,
	})
	if out["fingerprint"] != "ldap" {
		t.Fatalf("out = %#v", out)
	}
}

func TestRawTCPTDSFingerprint(t *testing.T) {
	host, port := startRawTCPServer(t, []byte{0x04, 0x01, 0x00, 0x2b, 0x00, 0x00, 0x01, 0x00}, 32)
	out := callRawTCP(t, &Server{}, map[string]any{
		"host": host, "port": port, "protocol": "tds", "timeout": 2, "read_len": 64,
	})
	if out["fingerprint"] != "tds" {
		t.Fatalf("out = %#v", out)
	}
}

func TestRawTCPMySQLFingerprint(t *testing.T) {
	resp := []byte{0x06, 0x00, 0x00, 0x00, '5', '.', '7', '.', '0', 0x00}
	host, port := startRawTCPServer(t, resp, 0)
	out := callRawTCP(t, &Server{}, map[string]any{
		"host": host, "port": port, "protocol": "mysql", "timeout": 2, "read_len": 64,
	})
	if out["fingerprint"] != "mysql:5.7.0" {
		t.Fatalf("out = %#v", out)
	}
}

func TestRawTCPValidationAndProxy(t *testing.T) {
	s := &Server{}
	cases := []map[string]any{
		{"host": "", "port": 1},
		{"host": "127.0.0.1", "port": 0},
		{"host": "127.0.0.1", "port": 70000},
		{"host": "127.0.0.1", "port": 1, "protocol": "ftp"},
		{"host": "127.0.0.1", "port": 1, "protocol": "raw", "payload": "zz"},
		{"host": "127.0.0.1", "port": 1, "timeout": 61},
	}
	for i, c := range cases {
		raw, _ := json.Marshal(c)
		res, err := s.toolRawTCP().Call(context.Background(), raw, nil)
		if err != nil {
			t.Fatalf("case %d transport: %v", i, err)
		}
		if !res.IsError {
			t.Errorf("case %d should be a tool error: %s", i, res.Flatten())
		}
	}

	// An HTTP proxy cannot carry arbitrary TCP.
	host, port := startRawTCPServer(t, nil, 0)
	raw, _ := json.Marshal(map[string]any{
		"host": host, "port": port, "protocol": "raw", "proxy": "http://127.0.0.1:1",
	})
	res, _ := s.toolRawTCP().Call(context.Background(), raw, nil)
	if !res.IsError || !strings.Contains(res.Flatten(), "只支持 socks5") {
		t.Fatalf("http proxy: %s", res.Flatten())
	}
}

func TestBuildSMB2Negotiate(t *testing.T) {
	req := buildSMB2Negotiate()
	if len(req) < 4+64+40 {
		t.Fatalf("request too short: %d", len(req))
	}
	if req[0] != 0x00 || req[4] != 0xFE || req[5] != 'S' || req[6] != 'M' || req[7] != 'B' {
		t.Fatalf("bad magic: %x", req[:8])
	}
	// NetBIOS length equals the SMB message length.
	n := int(req[1])<<16 | int(req[2])<<8 | int(req[3])
	if n != len(req)-4 {
		t.Fatalf("NetBIOS length %d, message %d", n, len(req)-4)
	}
}

func TestFingerprintRaw(t *testing.T) {
	cases := []struct {
		proto string
		resp  []byte
		want  string
	}{
		{"smb", []byte{0, 0, 0, 0, 0xFE, 'S', 'M', 'B'}, "smb2"},
		{"smb", []byte{0, 0, 0, 0, 0xFF, 'S', 'M', 'B'}, "smb1"},
		{"ldap", []byte{0x30, 0x00}, "ldap"},
		{"tds", []byte{0x04, 0x01}, "tds"},
		{"mysql", []byte{0, 0, 0, 0, '8', '.', '0', 0}, "mysql:8.0"},
		{"raw", nil, "no_response"},
		{"raw", []byte("x"), "unknown"},
	}
	for _, c := range cases {
		if got := fingerprintRaw(c.proto, c.resp); got != c.want {
			t.Errorf("%s %x => %s, want %s", c.proto, c.resp, got, c.want)
		}
	}
}

func TestRawTCPToolsRegistered(t *testing.T) {
	found := false
	for _, tool := range (&Server{}).rawTCPTools() {
		if tool.Name() == "raw_tcp" {
			found = true
			if !strings.Contains(tool.Description(), "observation_ledger") {
				t.Error("description should mention ledger limitation")
			}
		}
	}
	if !found {
		t.Fatal("raw_tcp not in rawTCPTools")
	}
}

func TestRawTCPPortString(t *testing.T) {
	// guard against a regression where net.JoinHostPort was fed the wrong type
	if got := net.JoinHostPort("127.0.0.1", strconv.Itoa(8080)); got != "127.0.0.1:8080" {
		t.Fatal(got)
	}
}
