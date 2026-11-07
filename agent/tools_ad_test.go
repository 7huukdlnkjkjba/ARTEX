package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

const kerbTestRC4Hash = "$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/sql01.corp.local:1433*$0123456789abcdef0123456789abcdef$deadbeefdeadbeefdeadbeefdeadbeef"
const kerbTestAESHash = "$krb5tgs$18$svc_web$CORP.LOCAL$*HTTP/web01.corp.local*$0123456789abcdef01234567$cafebabecafebabecafebabecafebabe"

const kerbTestOutput = `Impacket v0.11.0 - Copyright 2023 Fortra

ServicePrincipalName                 Name     MemberOf                                            PasswordLastSet      LastLogon  Delegation
-----------------------------------  -------  --------------------------------------------------  -------------------  ---------  ----------
MSSQLSvc/sql01.corp.local:1433       svc_sql  CN=Domain Admins,CN=Users,DC=corp,DC=local          2017-01-01 10:00:00  <never>
MSSQLSvc/sql02.corp.local:1433       svc_sql  CN=Domain Admins,CN=Users,DC=corp,DC=local          2017-01-01 10:00:00  <never>
HTTP/web01.corp.local                svc_web  CN=Users,DC=corp,DC=local                            2021-02-02 10:00:00  <never>
HOST/FS01$                           FS01$    CN=Computers,DC=corp,DC=local                        2022-03-03 10:00:00  <never>


$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/sql01.corp.local:1433*$0123456789abcdef0123456789abcdef$deadbeefdeadbeefdeadbeefdeadbeef
$krb5tgs$18$svc_web$CORP.LOCAL$*HTTP/web01.corp.local*$0123456789abcdef01234567$cafebabecafebabecafebabecafebabe
`

func TestParseKerberoastOutput(t *testing.T) {
	spns, hashes := parseKerberoastOutput(kerbTestOutput)
	if len(spns) != 4 {
		t.Fatalf("spns = %d, want 4: %+v", len(spns), spns)
	}
	if len(hashes) != 2 {
		t.Fatalf("hashes = %d, want 2: %+v", len(hashes), hashes)
	}

	rc4 := hashes[0]
	if rc4.AccountName != "svc_sql" || rc4.EType != 23 || rc4.HashcatMode != 13100 {
		t.Errorf("rc4 = %+v", rc4)
	}
	// GetUserSPNs embeds targetDomain/account (the last table row it used), so the
	// parser must replace it with the real SPN from the table.
	if rc4.SPN != "MSSQLSvc/sql02.corp.local:1433" {
		t.Errorf("rc4 SPN = %q, want the last table SPN for svc_sql", rc4.SPN)
	}
	if !strings.HasPrefix(rc4.Hash, "$krb5tgs$23$") {
		t.Errorf("rc4 hash lost: %q", rc4.Hash)
	}

	aes := hashes[1]
	if aes.AccountName != "svc_web" || aes.EType != 18 || aes.HashcatMode != 19700 {
		t.Errorf("aes = %+v", aes)
	}
	if aes.SPN != "HTTP/web01.corp.local" {
		t.Errorf("aes SPN = %q", aes.SPN)
	}

	foundMachine := false
	for _, s := range spns {
		if s.Machine && s.AccountName == "FS01$" {
			foundMachine = true
		}
	}
	if !foundMachine {
		t.Errorf("machine account not flagged: %+v", spns)
	}
}

func TestParseKerberoastOutputEmpty(t *testing.T) {
	spns, hashes := parseKerberoastOutput("Impacket v0.11.0\nNo entries found!\n")
	if len(spns) != 0 || len(hashes) != 0 {
		t.Fatalf("spns=%d hashes=%d, want 0/0", len(spns), len(hashes))
	}
}

func TestParseKrb5TgsHashLineRejectsGarbage(t *testing.T) {
	for _, in := range []string{
		"",
		"$krb5tgs$",
		"$krb5tgs$23$",
		"$krb5tgs$23$*user$REALM$spn$checksum$cipher",
		"$krb5tgs$xx$*user$REALM$spn*$checksum$cipher",
	} {
		if _, ok := parseKrb5TgsHashLine(in); ok {
			t.Errorf("accepted garbage %q", in)
		}
	}
}

func TestKerberoastParamsValidate(t *testing.T) {
	base := func() kerberoastParams {
		return kerberoastParams{DC: "10.0.0.10", Domain: "CORP.LOCAL", Username: `CORP\alice`, Password: "x"}
	}
	p := base()
	if err := p.Validate(); err != nil {
		t.Fatalf("valid params rejected: %v", err)
	}
	if p.Username != "alice" {
		t.Errorf("username = %q, want alice", p.Username)
	}
	if p.LDAPPort != 389 || p.TimeoutSec != 180 {
		t.Errorf("defaults not applied: %+v", p)
	}

	bad := []kerberoastParams{
		{DC: "", Domain: "CORP.LOCAL"},
		{DC: "10.0.0.10", Domain: ""},
		{DC: "http://10.0.0.10", Domain: "CORP.LOCAL"},
		{DC: "10.0.0.10", Domain: "CORP LOCAL"},
		{DC: "10.0.0.10", Domain: "CORP.LOCAL", Password: "x"},
		{DC: "10.0.0.10", Domain: "CORP.LOCAL", Username: "a", Password: "x", Hash: strings.Repeat("a", 32)},
		{DC: "10.0.0.10", Domain: "CORP.LOCAL", Username: "a", Hash: "nothex"},
		{DC: "10.0.0.10", Domain: "CORP.LOCAL", CredentialID: json.RawMessage(`"abc"`)},
		{DC: "10.0.0.10", Domain: "CORP.LOCAL", LDAPPort: 6360},
		{DC: "10.0.0.10", Domain: "CORP.LOCAL", TimeoutSec: 5},
	}
	for i, in := range bad {
		if err := in.Validate(); err == nil {
			t.Errorf("case %d accepted invalid params: %+v", i, in)
		}
	}
}

func TestNormalizeKerberoastHashes(t *testing.T) {
	nt := strings.Repeat("aB", 16)
	got, err := normalizeKerberoastHashes(nt)
	if err != nil {
		t.Fatal(err)
	}
	if got != kerbEmptyLMHash+":"+strings.ToLower(nt) {
		t.Errorf("got %q", got)
	}

	lm := strings.Repeat("1", 32)
	got, err = normalizeKerberoastHashes(lm + ":" + strings.Repeat("2", 32))
	if err != nil {
		t.Fatal(err)
	}
	if got != lm+":"+strings.Repeat("2", 32) {
		t.Errorf("got %q", got)
	}

	for _, bad := range []string{"", "abc", strings.Repeat("a", 33), strings.Repeat("a", 32) + ":" + "zz"} {
		if bad == "" {
			continue
		}
		if _, err := normalizeKerberoastHashes(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestBuildKerberoastArgs(t *testing.T) {
	p := &kerberoastParams{DC: "10.0.0.10", Domain: "CORP.LOCAL", TargetUser: "svc_sql"}
	args, err := buildKerberoastArgs(p, resolvedKerberoastCred{Username: "alice", Password: "P@ss"}, true)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if !strings.HasPrefix(joined, "CORP.LOCAL/alice:P@ss -dc-ip 10.0.0.10 -request-user svc_sql") {
		t.Errorf("args = %q", joined)
	}

	args, err = buildKerberoastArgs(p, resolvedKerberoastCred{Username: "alice", Hash: strings.Repeat("a", 32)}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(args, " "), "-hashes "+kerbEmptyLMHash+":"+strings.Repeat("a", 32)) {
		t.Errorf("hash arg missing: %v", args)
	}
	if strings.Contains(strings.Join(args, " "), "alice:") {
		t.Errorf("password separator present without password: %v", args)
	}

	// enumerate: no -request*
	p2 := &kerberoastParams{DC: "10.0.0.10", Domain: "CORP.LOCAL"}
	args, _ = buildKerberoastArgs(p2, resolvedKerberoastCred{Username: "alice", Password: "x"}, false)
	if strings.Contains(strings.Join(args, " "), "-request") {
		t.Errorf("enumerate args contain request: %v", args)
	}

	// request_all
	p3 := &kerberoastParams{DC: "10.0.0.10", Domain: "CORP.LOCAL", RequestAll: true}
	args, _ = buildKerberoastArgs(p3, resolvedKerberoastCred{Username: "alice", Password: "x"}, true)
	if !strings.Contains(strings.Join(args, " "), "-request") || strings.Contains(strings.Join(args, " "), "-request-user") {
		t.Errorf("request_all args = %v", args)
	}

	// no secret at all -> -no-pass
	args, _ = buildKerberoastArgs(p2, resolvedKerberoastCred{Username: "alice"}, false)
	if !strings.Contains(strings.Join(args, " "), "-no-pass") {
		t.Errorf("no-pass missing: %v", args)
	}
}

func TestPickKerberoastCredential(t *testing.T) {
	creds := []*db.CredentialRecord{
		{ID: 1, Username: "svc_sql", CredType: db.CredPassword, Secret: "x", Domain: "CORP"},
		{ID: 2, Username: "alice", CredType: db.CredHashNT, Secret: strings.Repeat("a", 32), Domain: "corp.local", Verified: true},
		{ID: 3, Username: "bob", CredType: db.CredPassword, Secret: "y", Domain: "EVIL.LOCAL", Verified: true},
		{ID: 4, Username: "carol", CredType: db.CredTicket, Secret: "t", Domain: "CORP.LOCAL"},
	}
	if got := pickKerberoastCredential(creds, "CORP.LOCAL", ""); got == nil || got.ID != 2 {
		t.Errorf("auto pick = %+v, want id 2 (verified)", got)
	}
	if got := pickKerberoastCredential(creds, "CORP.LOCAL", "svc_sql"); got == nil || got.ID != 1 {
		t.Errorf("username pick = %+v, want id 1", got)
	}
	if got := pickKerberoastCredential(creds, "evil.local", ""); got == nil || got.ID != 3 {
		t.Errorf("evil pick = %+v, want id 3", got)
	}
	if got := pickKerberoastCredential(creds, "OTHER.LOCAL", ""); got != nil {
		t.Errorf("cross-domain pick = %+v, want nil", got)
	}
}

func TestSameADDomain(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"CORP", "corp.local", true},
		{"CORP.LOCAL", "corp", true},
		{"corp.local", "CORP.LOCAL", true},
		{"corp.local", "evil.local", false},
		{"", "corp.local", false},
	}
	for _, c := range cases {
		if got := sameADDomain(c.a, c.b); got != c.want {
			t.Errorf("sameADDomain(%q,%q)=%v want %v", c.a, c.b, got, c.want)
		}
	}
}

// stubKerberoastRunner swaps the execution hooks for the duration of a test.
func stubKerberoastRunner(t *testing.T, out string, runErr error) *[]string {
	t.Helper()
	oldLocate, oldExec := kerberoastLocateRunner, kerberoastExecRunner
	var got []string
	kerberoastLocateRunner = func() (kerberoastRunner, error) {
		return kerberoastRunner{Bin: "python3", BaseArgs: []string{"GetUserSPNs.py"}}, nil
	}
	kerberoastExecRunner = func(_ context.Context, _ kerberoastRunner, args []string, _ time.Duration) (string, error) {
		got = append([]string{}, args...)
		return out, runErr
	}
	t.Cleanup(func() {
		kerberoastLocateRunner, kerberoastExecRunner = oldLocate, oldExec
	})
	return &got
}

func callKerberoast(t *testing.T, ts *ToolSet, payload any) kerberoastResult {
	t.Helper()
	raw, _ := json.Marshal(payload)
	res, err := ts.kerberoastHandler(context.Background(), raw)
	if err != nil {
		t.Fatalf("handler transport error: %v", err)
	}
	if res.IsError {
		t.Fatalf("handler tool error: %s", res.Flatten())
	}
	var out kerberoastResult
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("unmarshal result: %v\n%s", err, res.Flatten())
	}
	return out
}

func TestRedactKerberoastSecretKeepsHashes(t *testing.T) {
	secret := "abcd"
	hash := "$krb5tgs$23$*svc$CORP.LOCAL$x*$abcdabcd$abcd" // password appears as hex here
	out := "[-] login abcd failed\n" + hash
	got := redactKerberoastSecret(out, secret)
	if strings.Contains(got, "login abcd failed") {
		t.Errorf("password not redacted from log line: %q", got)
	}
	if !strings.Contains(got, hash) {
		t.Errorf("hash was corrupted by redaction: %q", got)
	}
}

func TestKerberoastHandlerTargeted(t *testing.T) {
	args := stubKerberoastRunner(t, kerbTestOutput, nil)
	ts := NewToolSet(nil, "tester")
	out := callKerberoast(t, ts, map[string]any{
		"dc": "10.0.0.10", "domain": "CORP.LOCAL",
		"username": `CORP\alice`, "password": "P@ssw0rd",
		"target_user": "svc_sql",
	})
	if out.Status != "success" {
		t.Fatalf("status = %s, error=%s", out.Status, out.Error)
	}
	if len(out.Hashes) != 2 || len(out.SPNs) != 4 {
		t.Errorf("hashes=%d spns=%d", len(out.Hashes), len(out.SPNs))
	}
	joined := strings.Join(*args, " ")
	if !strings.Contains(joined, "-request-user svc_sql") {
		t.Errorf("missing -request-user: %s", joined)
	}
	if out.Auth == nil || out.Auth.Username != "alice" || out.Auth.Source != "explicit" {
		t.Errorf("auth = %+v", out.Auth)
	}
}

func TestKerberoastHandlerEnumerate(t *testing.T) {
	enumOut := strings.Split(kerbTestOutput, "\n$krb5tgs$")[0]
	args := stubKerberoastRunner(t, enumOut, nil)
	ts := NewToolSet(nil, "tester")
	out := callKerberoast(t, ts, map[string]any{
		"dc": "10.0.0.10", "domain": "CORP.LOCAL", "username": "alice", "password": "x",
	})
	if out.Status != "enumerated" {
		t.Fatalf("status = %s, error=%s", out.Status, out.Error)
	}
	if len(out.Hashes) != 0 || len(out.SPNs) != 4 {
		t.Errorf("hashes=%d spns=%d", len(out.Hashes), len(out.SPNs))
	}
	joined := strings.Join(*args, " ")
	if strings.Contains(joined, "-request") {
		t.Errorf("enumerate must not request TGS: %s", joined)
	}
}

func TestKerberoastHandlerRunFailureIsActionable(t *testing.T) {
	// Real GetUserSPNs logs auth/clock errors via logging.error but exits 0; the
	// handler must still classify it as a failure instead of "no SPN found".
	for _, runErr := range []error{nil, errors.New("exit status 1")} {
		stubKerberoastRunner(t, "[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)", runErr)
		ts := NewToolSet(nil, "tester")
		out := callKerberoast(t, ts, map[string]any{
			"dc": "10.0.0.10", "domain": "CORP.LOCAL", "username": "alice", "password": "x",
		})
		if out.Status != "failed" {
			t.Fatalf("status = %s", out.Status)
		}
		if !strings.Contains(out.Error, "时钟偏差") {
			t.Errorf("error not classified: %q", out.Error)
		}
		if out.OutputTail == "" {
			t.Error("failure should carry a redacted output tail")
		}
	}
}

func TestKerberoastHandlerConnectionFailure(t *testing.T) {
	// Windows impacket reports a refused connection in Chinese and exits 0.
	stubKerberoastRunner(t, "[-] [WinError 10061] 由于目标计算机积极拒绝，无法连接。", nil)
	ts := NewToolSet(nil, "tester")
	out := callKerberoast(t, ts, map[string]any{
		"dc": "127.0.0.1", "domain": "CORP.LOCAL", "username": "alice", "password": "x",
	})
	if out.Status != "failed" || !strings.Contains(out.Error, "无法连接 DC") {
		t.Fatalf("out = %+v", out)
	}
}

func TestKerberoastHandlerNoCredential(t *testing.T) {
	ts := NewToolSet(nil, "tester")
	out := callKerberoast(t, ts, map[string]any{"dc": "10.0.0.10", "domain": "CORP.LOCAL"})
	if out.Status != "failed" || !strings.Contains(out.Error, "缺少域凭据") {
		t.Fatalf("out = %+v", out)
	}
}

func TestKerberoastToolInWorkerSet(t *testing.T) {
	found := false
	for _, tool := range NewToolSet(nil, "").WorkerTools() {
		if tool.Name() == "ad_kerberoast" {
			found = true
			if !strings.Contains(tool.Description(), "T1558.003") {
				t.Errorf("description missing MITRE id")
			}
			schema := tool.InputSchema()
			req, _ := schema["required"].([]string)
			if len(req) != 2 {
				t.Errorf("required = %v", schema["required"])
			}
		}
	}
	if !found {
		t.Fatal("ad_kerberoast not in WorkerTools")
	}
}

func TestKerberoastRunnerRealImpacketHelp(t *testing.T) {
	runner, err := locateKerberoastRunner()
	if err != nil {
		t.Skipf("impacket not installed: %v", err)
	}
	out, err := execKerberoastCommand(context.Background(), runner, []string{"-h"}, 15*time.Second)
	if err != nil {
		t.Fatalf("GetUserSPNs -h failed: %v\n%s", err, out)
	}
	if !strings.Contains(strings.ToLower(out), "usage") {
		t.Fatalf("unexpected -h output: %s", out)
	}
}

func TestKerberoastHandlerRealClosedDC(t *testing.T) {
	if os.Getenv("ARTEX_KERB_E2E") == "" {
		t.Skip("set ARTEX_KERB_E2E=1 to run the real impacket integration test")
	}
	ts := NewToolSet(nil, "tester")
	out := callKerberoast(t, ts, map[string]any{
		"dc": "127.0.0.1", "domain": "CORP.LOCAL", "username": "alice",
		"password": "wrong", "timeout_sec": 20,
	})
	if out.Status != "failed" || !strings.Contains(out.Error, "无法连接 DC") {
		t.Fatalf("out = %+v", out)
	}
	if out.OutputTail == "" || strings.Contains(out.OutputTail, "wrong") {
		t.Fatalf("output tail missing or leaked the password: %q", out.OutputTail)
	}
}

func TestKerberoastSeededForWorker(t *testing.T) {
	for _, seed := range BuiltinToolSeeds() {
		if seed.Key != "ad_kerberoast" {
			continue
		}
		if seed.Desc == "" || len(seed.Schema) == 0 {
			t.Fatalf("seed missing desc/schema: %+v", seed)
		}
		for _, a := range seed.Agents {
			if a == "worker" {
				return
			}
		}
		t.Fatalf("ad_kerberoast agents = %v, want worker", seed.Agents)
	}
	t.Fatal("ad_kerberoast not in BuiltinToolSeeds")
}

func TestKerberoastDomainToolNilStore(t *testing.T) {
	// The catalog builds tools with nil stores; calling ad_kerberoast there must
	// return the writeExpTool explanation, not panic or exec anything.
	ts := NewToolSet(nil, "")
	res, err := ts.kerberoast().Call(context.Background(), json.RawMessage(`{"dc":"10.0.0.10","domain":"CORP.LOCAL"}`), nil)
	if err != nil {
		t.Fatalf("transport error: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Flatten(), "任务上下文") {
		t.Fatalf("want task-context refusal, got IsError=%v %q", res.IsError, res.Flatten())
	}
}
