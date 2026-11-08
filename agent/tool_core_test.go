package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

func newTestLedger(t *testing.T) *ReceiptLedger {
	t.Helper()
	return newReceiptLedger(t.TempDir(), "test-run")
}

func TestReceiptLedgerRecordFindHas(t *testing.T) {
	dir := t.TempDir()
	l := newReceiptLedger(dir, "run-1")
	if l == nil {
		t.Fatal("nil ledger")
	}
	r1 := l.record(Receipt{
		Tool: "path_probe", URL: "http://example.com/admin", Method: "GET",
		Status: 200, ResponseHash: "h1", Complete: true,
	})
	if r1.ID == "" || r1.At == "" || r1.RunID != "run-1" {
		t.Fatalf("receipt = %+v", r1)
	}
	l.record(Receipt{
		Tool: "path_probe", URL: "http://example.com/private", Method: "GET",
		Status: 401, ResponseHash: "h2", Complete: false,
	})
	if !l.has("http://EXAMPLE.com/admin/", true) {
		t.Error("host case/trailing slash should match")
	}
	if !l.has("http://example.com/private", false) {
		t.Error("incomplete receipt should match when completeOnly=false")
	}
	if l.has("http://example.com/private", true) {
		t.Error("incomplete receipt matched completeOnly")
	}
	if l.has("http://example.com/missing", false) {
		t.Error("unknown URL matched")
	}
	if got, ok := l.find(r1.ID); !ok || got.ResponseHash != "h1" {
		t.Errorf("find = %+v ok=%v", got, ok)
	}
	// Reload from disk.
	l2 := newReceiptLedger(dir, "run-1")
	if !l2.has("http://example.com/admin", true) {
		t.Error("reloaded ledger lost receipt")
	}
}

func TestCitedURLsAndKey(t *testing.T) {
	got := citedURLs("see https://Example.com/a/, and (http://x.test/b).")
	if len(got) != 2 || got[0] != "https://Example.com/a/" || got[1] != "http://x.test/b" {
		t.Fatalf("cited = %#v", got)
	}
	if receiptURLKey("https://EXAMPLE.com/a/#frag") != receiptURLKey("https://example.com/a") {
		t.Error("receiptURLKey should normalize case/fragment/trailing slash")
	}
}

func TestFindingGate(t *testing.T) {
	l := newTestLedger(t)
	r1 := l.record(Receipt{Tool: "t", URL: "http://example.com/admin", Method: "GET", Status: 200, ResponseHash: "h1", Complete: true})
	r2 := l.record(Receipt{Tool: "t", URL: "http://example.com/admin", Method: "GET", Status: 200, ResponseHash: "h2", Complete: true})
	r3 := l.record(Receipt{Tool: "t", URL: "http://example.com/other", Method: "GET", Status: 200, ResponseHash: "h1", Complete: true})
	r4 := l.record(Receipt{Tool: "t", URL: "http://example.com/bad", Method: "GET", Status: 0, Complete: false})
	rc := l.record(Receipt{Tool: "calibrate", URL: "http://example.com/admin", Method: "GET", Status: 200, ResponseHash: "h1", Complete: true})

	ok := newFindingGate(l, "differential", []string{r1.ID})
	if err := ok.verify("see http://example.com/admin"); err != nil {
		t.Fatalf("valid gate rejected: %v", err)
	}
	if err := ok.verify("no url here"); err == nil {
		t.Error("missing URL accepted")
	}
	if err := newFindingGate(l, "unproven", []string{r1.ID}).verify("http://example.com/admin"); err == nil {
		t.Error("unproven accepted")
	}
	if err := newFindingGate(l, "differential", nil).verify("http://example.com/admin"); err == nil {
		t.Error("empty observation_ids accepted")
	}
	if err := newFindingGate(l, "differential", []string{"missing"}).verify("http://example.com/admin"); err == nil {
		t.Error("missing receipt accepted")
	}
	if err := newFindingGate(l, "differential", []string{r1.ID, r2.ID}).verify("http://example.com/admin"); err == nil {
		t.Error("inconsistent response hashes accepted")
	}
	if err := newFindingGate(l, "differential", []string{r3.ID}).verify("http://example.com/admin"); err == nil {
		t.Error("mismatched observation URL accepted")
	}
	if err := newFindingGate(l, "differential", []string{r4.ID}).verify("http://example.com/bad"); err == nil {
		t.Error("incomplete observation accepted")
	}
	if err := newFindingGate(l, "differential", []string{rc.ID}).verify("http://example.com/admin"); err == nil {
		t.Error("calibration receipt accepted")
	}
	if err := newFindingGate(nil, "differential", []string{r1.ID}).verify("http://example.com/admin"); err == nil {
		t.Error("nil ledger accepted")
	}
}

func TestProbeFetchRecordsReceipt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "hello probe")
	}))
	defer srv.Close()

	ts := NewToolSet(nil, "tester")
	ts.SetReceiptLedger(t.TempDir(), "run")
	r, err := ts.probeFetch(context.Background(), "test", srv.URL+"/x", "", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Complete || r.Status != 201 || r.Body != "hello probe" || r.ReceiptID == "" {
		t.Fatalf("probe = %+v", r)
	}
	if r.SHA256 == "" || r.Headers["content-type"] != "text/plain" {
		t.Errorf("hashes/headers = %+v", r)
	}
	rec, ok := ts.ledger.find(r.ReceiptID)
	if !ok || !rec.Complete || rec.ResponseHash != r.SHA256 || rec.URL == "" {
		t.Errorf("receipt = %+v ok=%v", rec, ok)
	}
}

func TestProbeFetchErrorRecordsIncomplete(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	ts := NewToolSet(nil, "tester")
	ts.SetReceiptLedger(t.TempDir(), "run")
	r, err := ts.probeFetch(context.Background(), "test", url, "", 2*time.Second)
	if err == nil {
		t.Fatal("expected error")
	}
	if r.ReceiptID == "" {
		t.Fatal("error probe did not record a receipt")
	}
	rec, ok := ts.ledger.find(r.ReceiptID)
	if !ok || rec.Complete {
		t.Errorf("receipt = %+v ok=%v", rec, ok)
	}
}

func TestProbeFetchWithCookie(t *testing.T) {
	var gotCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCookie = r.Header.Get("Cookie")
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	ts := NewToolSet(nil, "tester")
	ts.SetReceiptLedger(t.TempDir(), "run")
	r, err := ts.probeFetchWithCookie(context.Background(), "test", srv.URL, "session=secret", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if gotCookie != "session=secret" || !r.Complete {
		t.Fatalf("cookie=%q r=%+v", gotCookie, r)
	}
	rec, _ := ts.ledger.find(r.ReceiptID)
	if rec.Principal == "" || rec.Principal == "session=secret" {
		t.Errorf("principal should be hashed, got %q", rec.Principal)
	}
}

func callPathProbe(t *testing.T, ts *ToolSet, payload any) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(payload)
	res, err := ts.toolPathProbe().Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatalf("path_probe transport: %v", err)
	}
	if res.IsError {
		t.Fatalf("path_probe error: %s", res.Flatten())
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("unmarshal path_probe: %v\n%s", err, res.Flatten())
	}
	return out
}

func TestPathProbeAndSoft404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/" {
			_, _ = io.WriteString(w, "real admin page")
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	ts := NewToolSet(nil, "tester")
	ts.SetReceiptLedger(t.TempDir(), "run")
	out := callPathProbe(t, ts, map[string]any{
		"base_url": srv.URL, "paths": []string{"/admin/", "/missing"}, "timeout_ms": 2000, "concurrency": 2,
	})
	if out["probed"].(float64) != 2 {
		t.Errorf("probed = %v", out["probed"])
	}
	found, _ := out["found"].([]any)
	if len(found) != 1 {
		t.Fatalf("found = %#v", out["found"])
	}
	hit := found[0].(map[string]any)
	if hit["path"] != "/admin/" || hit["receipt_id"] == "" {
		t.Errorf("hit = %#v", hit)
	}
	if !ts.ledger.has(srv.URL+"/admin/", true) {
		t.Error("hit not in ledger")
	}

	soft := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "not found page")
	}))
	defer soft.Close()
	ts2 := NewToolSet(nil, "tester")
	ts2.SetReceiptLedger(t.TempDir(), "run")
	out2 := callPathProbe(t, ts2, map[string]any{
		"base_url": soft.URL, "paths": []string{"/admin/"}, "timeout_ms": 2000,
	})
	if len(out2["found"].([]any)) != 0 {
		t.Fatalf("soft-404 not filtered: %#v", out2["found"])
	}
}

func callAdminSurface(t *testing.T, ts *ToolSet, payload any) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(payload)
	res, err := ts.toolAdminSurface().Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatalf("admin_surface transport: %v", err)
	}
	if res.IsError {
		t.Fatalf("admin_surface error: %s", res.Flatten())
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("unmarshal admin_surface: %v", err)
	}
	return out
}

func TestAdminSurface(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/actuator" {
			_, _ = io.WriteString(w, `{"_links":{"health":{"href":"/actuator/health"},"self":{"href":"/actuator"}}}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	ts := NewToolSet(nil, "tester")
	ts.SetReceiptLedger(t.TempDir(), "run")
	out := callAdminSurface(t, ts, map[string]any{"base_url": srv.URL, "timeout_ms": 2000})
	found, _ := out["found"].([]any)
	if len(found) != 1 {
		t.Fatalf("found = %#v", out["found"])
	}
	f := found[0].(map[string]any)
	if f["kind"] != "spring-actuator" || f["receipt_id"] == "" || f["proof_kind"] != string(ProofReflection) {
		t.Errorf("found = %#v", f)
	}
}

func callFingerprint(t *testing.T, ts *ToolSet, payload any) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(payload)
	res, err := ts.toolFingerprint().Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatalf("fingerprint transport: %v", err)
	}
	if res.IsError {
		t.Fatalf("fingerprint error: %s", res.Flatten())
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("unmarshal fingerprint: %v", err)
	}
	return out
}

func TestFingerprint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	ts := NewToolSet(nil, "tester")
	ts.SetReceiptLedger(t.TempDir(), "run")
	out := callFingerprint(t, ts, map[string]any{"base_url": srv.URL, "timeout_ms": 2000})
	waf, _ := out["waf"].([]any)
	if len(waf) != 1 || waf[0] != "cloudflare" {
		t.Errorf("waf = %#v", waf)
	}
	missing, _ := out["missing_headers"].([]any)
	foundHSTS := false
	for _, m := range missing {
		if m == "strict-transport-security" {
			foundHSTS = true
		}
	}
	if !foundHSTS {
		t.Errorf("missing = %#v", missing)
	}
	if out["receipt_id"] == "" {
		t.Error("fingerprint missing receipt_id")
	}
}

func callAuthProbe(t *testing.T, ts *ToolSet, payload any) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(payload)
	res, err := ts.toolAuthProbe().Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatalf("auth_probe transport: %v", err)
	}
	if res.IsError {
		t.Fatalf("auth_probe error: %s", res.Flatten())
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("unmarshal auth_probe: %v", err)
	}
	return out
}

func TestAuthProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/public":
			_, _ = io.WriteString(w, "public")
		case "/private":
			if r.Header.Get("Cookie") == "session=ok" {
				_, _ = io.WriteString(w, "private")
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer srv.Close()

	ts := NewToolSet(nil, "tester")
	ts.SetReceiptLedger(t.TempDir(), "run")
	out := callAuthProbe(t, ts, map[string]any{
		"urls":   []string{srv.URL + "/public", srv.URL + "/private"},
		"cookie": "session=ok", "timeout_ms": 2000,
	})
	anon, _ := out["anonymous"].([]any)
	auth, _ := out["auth_required"].([]any)
	if len(anon) != 1 || len(auth) != 1 {
		t.Fatalf("anon=%#v auth=%#v", anon, auth)
	}
	if auth[0].(map[string]any)["auth_status"].(float64) != 200 {
		t.Errorf("auth hit = %#v", auth[0])
	}

	edge := callAuthProbe(t, ts, map[string]any{
		"urls":       []string{srv.URL + "/a", srv.URL + "/b", srv.URL + "/c", srv.URL + "/d"},
		"timeout_ms": 2000,
	})
	if edge["edge_blocked"] != true {
		t.Fatalf("edge = %#v", edge)
	}
}

func TestReportFindingGatedDB(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("core gate", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)
	ts := NewToolSet(d.Exploration(task.ExplorationID), "tester")
	ts.SetTaskID(task.ID)
	intent, err := ts.ts.AddIntent(map[string]any{"summary": "gate test"}, 5, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	ts.SetOwnerNode(intent)
	ts.SetReceiptLedger(t.TempDir(), "run")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "secret admin")
	}))
	defer srv.Close()
	r, err := ts.probeFetch(context.Background(), "test", srv.URL+"/admin", "", 2*time.Second)
	if err != nil || r.ReceiptID == "" {
		t.Fatalf("probe = %+v err=%v", r, err)
	}
	raw, _ := json.Marshal(map[string]any{
		"vulnclass": "exposed-admin", "name": "Exposed admin", "severity": "high",
		"summary":    "anonymous admin page at " + srv.URL + "/admin",
		"evidence":   "HTTP 200 with secret admin at " + srv.URL + "/admin",
		"proof_kind": "differential", "observation_ids": []string{r.ReceiptID},
		"intent_id": intent,
	})
	res, err := ts.toolReportFindingGated().Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatalf("handler transport: %v", err)
	}
	if res.IsError {
		t.Fatalf("gated finding rejected: %s", res.Flatten())
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, res.Flatten())
	}
	id, _ := out["finding_id"].(float64)
	if id <= 0 {
		t.Fatalf("finding_id = %v", out["finding_id"])
	}
	if f, err := d.GetFinding(int64(id)); err != nil || f == nil {
		t.Fatalf("finding not persisted: %+v %v", f, err)
	}
}

func TestCoreToolsInWorkerSetAndSeeds(t *testing.T) {
	want := []string{"path_probe", "admin_surface", "fingerprint", "auth_probe", "report_finding_gated"}
	names := map[string]bool{}
	for _, tool := range NewToolSet(nil, "").WorkerTools() {
		names[tool.Name()] = true
	}
	seeds := map[string]bool{}
	for _, seed := range BuiltinToolSeeds() {
		for _, a := range seed.Agents {
			if a == "worker" {
				seeds[seed.Key] = true
			}
		}
	}
	for _, name := range want {
		if !names[name] {
			t.Errorf("%s not in WorkerTools", name)
		}
		if !seeds[name] {
			t.Errorf("%s not seeded for worker", name)
		}
	}
}

func TestCoreToolsNilStore(t *testing.T) {
	ts := NewToolSet(nil, "")
	// Probe tools only need a ledger (optional) and scope; they must survive nil
	// exploration/asset stores. Invalid input should be a tool error, not a panic.
	probes := []struct {
		name  string
		tool  actool.CoreTool
		input string
	}{
		{"path_probe", ts.toolPathProbe(), `{"base_url":""}`},
		{"admin_surface", ts.toolAdminSurface(), `{"base_url":""}`},
		{"fingerprint", ts.toolFingerprint(), `{"base_url":""}`},
		{"auth_probe", ts.toolAuthProbe(), `{"urls":[]}`},
	}
	for _, c := range probes {
		res, err := c.tool.Call(context.Background(), json.RawMessage(c.input), nil)
		if err != nil {
			t.Fatalf("%s transport: %v", c.name, err)
		}
		if !res.IsError {
			t.Errorf("%s should reject invalid input, got %s", c.name, res.Flatten())
		}
	}
	// The gated finding writer needs the task exploration graph.
	res, err := ts.toolReportFindingGated().Call(context.Background(), json.RawMessage(`{"vulnclass":"x","name":"x","severity":"low","summary":"http://127.0.0.1/","evidence":"http://127.0.0.1/","proof_kind":"differential","observation_ids":["x"]}`), nil)
	if err != nil {
		t.Fatalf("report_finding_gated transport: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Flatten(), "任务上下文") {
		t.Errorf("report_finding_gated nil store: IsError=%v %q", res.IsError, res.Flatten())
	}
}

func TestToolchainRuleMentionsGatedFinding(t *testing.T) {
	if !strings.Contains(toolchainRule, "report_finding_gated") {
		t.Fatal("toolchainRule must mention report_finding_gated")
	}
}
