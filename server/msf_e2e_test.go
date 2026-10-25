package server

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// TestMSFExecuteLab is an opt-in end-to-end check of the Metasploit closed loop
// against an authorized local lab (fake vsftpd 2.3.4 on 2121 + running msfrpcd).
//
//	ARTEX_MSF_E2E=1 ARTEX_MSF_E2E_DSN='postgres://...' \
//	ARTEX_MSF_E2E_HOST=172.29.159.15 ARTEX_MSF_E2E_PORT=2121 \
//	ARTEX_MSF_E2E_PASSWORD=ArtexLab123 \
//	go test ./server -run TestMSFExecuteLab -v -count=1
func TestMSFExecuteLab(t *testing.T) {
	if os.Getenv("ARTEX_MSF_E2E") != "1" {
		t.Skip("set ARTEX_MSF_E2E=1 to run the lab closed loop")
	}
	dsn := os.Getenv("ARTEX_MSF_E2E_DSN")
	if dsn == "" {
		t.Skip("ARTEX_MSF_E2E_DSN not set")
	}
	host := os.Getenv("ARTEX_MSF_E2E_HOST")
	port := 2121
	if v := os.Getenv("ARTEX_MSF_E2E_PORT"); v != "" {
		_ = json.Unmarshal([]byte(v), &port)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	defer pg.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	s := &Server{ctx: ctx, m: &Manager{pg: pg}}
	s.msfRPC = &msfProc{password: os.Getenv("ARTEX_MSF_E2E_PASSWORD"), port: 55553}

	in, _ := json.Marshal(map[string]any{
		"vuln_class": "vsftpd 2.3.4", "host": host, "port": port,
		"service": "ftp", "lport": 4444,
	})
	res, err := s.msfExecuteTool().Call(ctx, in, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(resultText(res)), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, resultText(res))
	}
	sessions, _ := out["sessions"].([]any)
	if len(sessions) == 0 {
		t.Fatalf("no session: %s", resultText(res))
	}
	tr, _ := out["transcript"].([]any)
	evidence := ""
	for _, item := range tr {
		m, _ := item.(map[string]any)
		if m["step"] == "session" {
			evidence, _ = m["evidence"].(string)
		}
	}
	if evidence == "" {
		// Synthetic shells can take longer than the poll window to answer
		// interact_session; the session itself is the hard requirement.
		t.Logf("WARN: no session evidence captured (synthetic shell timing)")
	}
	t.Logf("session(s)=%v plan=%v evidence=%q", sessions, out["plan_id"], evidence)
}
