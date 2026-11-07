package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

type fakeCredentialSource struct {
	byID   map[int64]*db.CredentialRecord
	byTask map[int64][]*db.CredentialRecord
}

func (f *fakeCredentialSource) Get(_ context.Context, id int64) (*db.CredentialRecord, error) {
	return f.byID[id], nil
}

func (f *fakeCredentialSource) ListByTask(_ context.Context, taskID int64) ([]*db.CredentialRecord, error) {
	return f.byTask[taskID], nil
}

func TestResolveKerberoastCredentialExplicitWins(t *testing.T) {
	ts := NewToolSet(nil, "")
	ts.taskID = 100
	ts.credSource = &fakeCredentialSource{byID: map[int64]*db.CredentialRecord{
		7: {ID: 7, TaskID: 100, Username: "stored", CredType: db.CredPassword, Secret: "stored", Domain: "CORP.LOCAL"},
	}}
	p := &kerberoastParams{DC: "10.0.0.10", Domain: "CORP.LOCAL", Username: "alice", Password: "explicit", CredentialID: json.RawMessage("7")}
	cred, err := ts.resolveKerberoastCredential(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if cred.Source != "explicit" || cred.Username != "alice" || cred.Password != "explicit" {
		t.Fatalf("cred = %+v", cred)
	}
}

func TestResolveKerberoastCredentialByIDRejectsCrossTask(t *testing.T) {
	ts := NewToolSet(nil, "")
	ts.taskID = 100
	ts.credSource = &fakeCredentialSource{byID: map[int64]*db.CredentialRecord{
		7: {ID: 7, TaskID: 999, Username: "alice", CredType: db.CredPassword, Secret: "x", Domain: "CORP.LOCAL"},
	}}
	p := &kerberoastParams{DC: "10.0.0.10", Domain: "CORP.LOCAL", CredentialID: json.RawMessage("7")}
	if _, err := ts.resolveKerberoastCredential(context.Background(), p); err == nil || !strings.Contains(err.Error(), "不属于本任务") {
		t.Fatalf("want cross-task refusal, got %v", err)
	}
}

func TestResolveKerberoastCredentialAuto(t *testing.T) {
	ts := NewToolSet(nil, "")
	ts.taskID = 100
	ts.credSource = &fakeCredentialSource{byTask: map[int64][]*db.CredentialRecord{
		100: {
			{ID: 1, TaskID: 100, Username: "alice", CredType: db.CredPassword, Secret: "x", Domain: "CORP.LOCAL", Verified: true},
			{ID: 2, TaskID: 100, Username: "bob", CredType: db.CredHashNT, Secret: strings.Repeat("a", 32), Domain: "OTHER.LOCAL"},
		},
	}}
	p := &kerberoastParams{DC: "10.0.0.10", Domain: "CORP.LOCAL"}
	cred, err := ts.resolveKerberoastCredential(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if cred.Source != "auto" || cred.CredID != 1 || cred.Password != "x" {
		t.Fatalf("cred = %+v", cred)
	}
}

func TestKerberoastCredFromRecordRejectsLM(t *testing.T) {
	c := &db.CredentialRecord{ID: 3, TaskID: 1, Username: "alice", CredType: db.CredHashLM, Secret: strings.Repeat("a", 32), Domain: "CORP.LOCAL"}
	if _, err := kerberoastCredFromRecord(c, &kerberoastParams{Domain: "CORP.LOCAL"}, "credential_id"); err == nil || !strings.Contains(err.Error(), "LM") {
		t.Fatalf("want LM refusal, got %v", err)
	}
}

func TestKerberoastDryRun(t *testing.T) {
	oldLocate := kerberoastLocateRunner
	kerberoastLocateRunner = func() (kerberoastRunner, error) {
		return kerberoastRunner{Bin: "python3", BaseArgs: []string{"GetUserSPNs.py"}}, nil
	}
	t.Cleanup(func() { kerberoastLocateRunner = oldLocate })

	ts := NewToolSet(nil, "tester")
	out := callKerberoast(t, ts, map[string]any{
		"dc": "127.0.0.1", "domain": "CORP.LOCAL", "dry_run": true,
	})
	if out.Status != "dry_run" {
		t.Fatalf("status = %s, error=%s", out.Status, out.Error)
	}
	if out.Tooling == nil || out.Tooling["impacket_ready"] != true {
		t.Fatalf("tooling = %+v", out.Tooling)
	}
	for _, key := range []string{"kerberos_tcp_88", "ldap"} {
		if _, ok := out.Tooling[key]; !ok {
			t.Errorf("dry run missing %s: %+v", key, out.Tooling)
		}
	}
}
