package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func callReconHTTP(t *testing.T, ts *ToolSet, payload any) ReconHTTPResult {
	t.Helper()
	raw, _ := json.Marshal(payload)
	res, err := ts.reconHTTPHandler(context.Background(), raw)
	if err != nil {
		t.Fatalf("handler transport error: %v", err)
	}
	if res.IsError {
		t.Fatalf("handler tool error: %s", res.Flatten())
	}
	var out ReconHTTPResult
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("unmarshal result: %v\n%s", err, res.Flatten())
	}
	return out
}

func callReconHTTPError(t *testing.T, ts *ToolSet, payload any) string {
	t.Helper()
	raw, _ := json.Marshal(payload)
	res, err := ts.reconHTTPHandler(context.Background(), raw)
	if err != nil {
		t.Fatalf("handler transport error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("want tool error, got %s", res.Flatten())
	}
	return res.Flatten()
}

func callHTTPDiff(t *testing.T, ts *ToolSet, payload any) HTTPDiffResult {
	t.Helper()
	raw, _ := json.Marshal(payload)
	res, err := ts.httpDiffHandler(context.Background(), raw)
	if err != nil {
		t.Fatalf("handler transport error: %v", err)
	}
	if res.IsError {
		t.Fatalf("handler tool error: %s", res.Flatten())
	}
	var out HTTPDiffResult
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("unmarshal result: %v\n%s", err, res.Flatten())
	}
	return out
}

func callHTTPDiffError(t *testing.T, ts *ToolSet, payload any) string {
	t.Helper()
	raw, _ := json.Marshal(payload)
	res, err := ts.httpDiffHandler(context.Background(), raw)
	if err != nil {
		t.Fatalf("handler transport error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("want tool error, got %s", res.Flatten())
	}
	return res.Flatten()
}

func TestReconHTTPBasic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "one")
		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "hello world")
	}))
	defer srv.Close()

	ts := NewToolSet(nil, "tester")
	out := callReconHTTP(t, ts, map[string]any{"url": srv.URL + "/x"})
	if out.Status != "success" || out.StatusCode != 201 {
		t.Fatalf("out = %+v", out)
	}
	if out.BodyPreview != "hello world" || out.BodyLen != 11 {
		t.Errorf("body = %q len=%d", out.BodyPreview, out.BodyLen)
	}
	if out.Headers.Get("X-Test") != "one" {
		t.Errorf("headers = %+v", out.Headers)
	}
	if got := out.Headers.Values("Set-Cookie"); len(got) != 1 || got[0] != "a=1" {
		t.Errorf("set-cookie = %+v", got)
	}
	if out.ContentType != "text/plain" || out.Host != "127.0.0.1" {
		t.Errorf("content_type=%q host=%q", out.ContentType, out.Host)
	}
	if len(out.NextSteps) == 0 {
		t.Error("success should carry next_steps")
	}
}

func TestReconHTTPRedirect(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if r.URL.Path == "/redir" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "final")
	}))
	defer srv.Close()

	ts := NewToolSet(nil, "tester")
	noFollow := callReconHTTP(t, ts, map[string]any{"url": srv.URL + "/redir"})
	if noFollow.StatusCode != 302 {
		t.Fatalf("no-follow status = %d", noFollow.StatusCode)
	}
	if len(noFollow.Redirects) != 1 || !strings.HasSuffix(noFollow.Redirects[0], "/final") {
		t.Errorf("redirects = %+v", noFollow.Redirects)
	}
	if hits != 1 {
		t.Errorf("no-follow hits = %d, want 1", hits)
	}

	follow := callReconHTTP(t, ts, map[string]any{"url": srv.URL + "/redir", "follow": true})
	if follow.StatusCode != 200 || !strings.HasSuffix(follow.FinalURL, "/final") {
		t.Fatalf("follow = %+v", follow)
	}
	if hits != 3 {
		t.Errorf("follow hits = %d, want 3", hits)
	}
}

func TestReconHTTPUserAgent(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.UserAgent()
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	ts := NewToolSet(nil, "tester")
	ts.SetHTTPUserAgent("task-ua/1.0")
	_ = callReconHTTP(t, ts, map[string]any{"url": srv.URL})
	if gotUA != "task-ua/1.0" {
		t.Errorf("ua = %q, want task-ua/1.0", gotUA)
	}
	_ = callReconHTTP(t, ts, map[string]any{"url": srv.URL, "headers": map[string]string{"User-Agent": "explicit/2.0"}})
	if gotUA != "explicit/2.0" {
		t.Errorf("explicit ua = %q", gotUA)
	}
}

func TestReconHTTPDryRun(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()

	ts := NewToolSet(nil, "tester")
	out := callReconHTTP(t, ts, map[string]any{"url": srv.URL + "/x", "dry_run": true})
	if out.Status != "dry_run" {
		t.Fatalf("out = %+v", out)
	}
	if hits != 0 {
		t.Errorf("dry_run sent %d requests", hits)
	}
	if !out.Insecure || out.TimeoutSec != 15 {
		t.Errorf("dry run config = %+v", out)
	}
}

func TestReconHTTPValidation(t *testing.T) {
	ts := NewToolSet(nil, "tester")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	cases := []map[string]any{
		{"url": "ftp://example.com/x"},
		{"url": "example.com/x"},
		{"url": srv.URL, "method": "TRACE"},
		{"url": srv.URL, "headers": map[string]string{"X": "a\r\nb"}},
		{"url": srv.URL, "timeout_sec": 61},
	}
	for i, c := range cases {
		msg := callReconHTTPError(t, ts, c)
		if msg == "" {
			t.Errorf("case %d: empty error message", i)
		}
	}
}

func TestReconHTTPTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1200 * time.Millisecond)
	}))
	defer srv.Close()

	ts := NewToolSet(nil, "tester")
	out := callReconHTTP(t, ts, map[string]any{"url": srv.URL, "timeout_sec": 1})
	if out.Status != "failed" || out.ErrorKind != "timeout" {
		t.Fatalf("out = %+v", out)
	}
}

func TestReconHTTPSelfSigned(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "tls ok")
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	defer srv.Close()

	ts := NewToolSet(nil, "tester")
	out := callReconHTTP(t, ts, map[string]any{"url": srv.URL})
	if out.Status != "success" || out.BodyPreview != "tls ok" {
		t.Fatalf("insecure default = %+v", out)
	}
	strict := callReconHTTP(t, ts, map[string]any{"url": srv.URL, "insecure": false})
	if strict.Status != "failed" || strict.ErrorKind != "tls" {
		t.Fatalf("strict tls = %+v", strict)
	}
}

func TestHTTPDiffBasic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("id") {
		case "1":
			_, _ = io.WriteString(w, "hello baseline")
		case "2":
			_, _ = io.WriteString(w, "hello baseline plus extra content that is longer")
		case "admin":
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, "forbidden")
		case "500":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, "boom")
		case "case":
			_, _ = io.WriteString(w, "HELLO BASELINE")
		default:
			_, _ = io.WriteString(w, "hello baseline")
		}
	}))
	defer srv.Close()

	ts := NewToolSet(nil, "tester")
	out := callHTTPDiff(t, ts, map[string]any{
		"url_template": srv.URL + "/?id={v}",
		"baseline":     "1",
		"variants":     []string{"2", "admin", "500", "case"},
	})
	if out.Status != "success" {
		t.Fatalf("out = %+v", out)
	}
	if out.Baseline.StatusCode != 200 || out.Summary.VariantCount != 4 {
		t.Errorf("baseline=%+v summary=%+v", out.Baseline, out.Summary)
	}
	if out.Summary.StatusDiff != 2 || out.Summary.LenDiff != 1 || out.Summary.ContentDiff != 1 {
		t.Errorf("summary = %+v", out.Summary)
	}
	if out.Summary.Signals != 4 {
		t.Errorf("signals = %d, want 4", out.Summary.Signals)
	}
	for _, d := range out.Diffs {
		if d.Signal != "same" && d.Signal != "error" && d.Preview == "" {
			t.Errorf("signal %s without preview: %+v", d.Signal, d)
		}
	}
}

func TestHTTPDiffStatusFlip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("id") == "base" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, "no")
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "yes")
	}))
	defer srv.Close()

	ts := NewToolSet(nil, "tester")
	out := callHTTPDiff(t, ts, map[string]any{
		"url_template": srv.URL + "/?id={v}",
		"baseline":     "base",
		"variants":     []string{"flip"},
	})
	if out.Diffs[0].Signal != "status_flip" || out.Summary.StatusFlip != 1 {
		t.Fatalf("out = %+v", out)
	}
}

func TestHTTPDiffDryRun(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()

	ts := NewToolSet(nil, "tester")
	out := callHTTPDiff(t, ts, map[string]any{
		"url_template": srv.URL + "/?id={v}",
		"baseline":     "1",
		"variants":     []string{"2", "3"},
		"dry_run":      true,
	})
	if out.Status != "dry_run" || out.Summary.VariantCount != 2 {
		t.Fatalf("out = %+v", out)
	}
	if hits != 0 {
		t.Errorf("dry_run sent %d requests", hits)
	}
}

func TestHTTPDiffBaselineFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	ts := NewToolSet(nil, "tester")
	out := callHTTPDiff(t, ts, map[string]any{
		"url_template": url + "/?id={v}",
		"baseline":     "1",
		"variants":     []string{"2"},
	})
	if out.Status != "failed" || !strings.Contains(out.Error, "baseline") {
		t.Fatalf("out = %+v", out)
	}
}

func TestHTTPDiffHostChangeRejected(t *testing.T) {
	ts := NewToolSet(nil, "tester")
	msg := callHTTPDiffError(t, ts, map[string]any{
		"url_template": "http://{v}.example.com/?id=1",
		"baseline":     "a",
		"variants":     []string{"b"},
	})
	if !strings.Contains(msg, "主机名") {
		t.Fatalf("msg = %s", msg)
	}
}

func TestHTTPDiffVariantLimit(t *testing.T) {
	ts := NewToolSet(nil, "tester")
	variants := make([]string, 21)
	for i := range variants {
		variants[i] = fmt.Sprintf("%d", i)
	}
	msg := callHTTPDiffError(t, ts, map[string]any{
		"url_template": "http://127.0.0.1/?id={v}",
		"baseline":     "0",
		"variants":     variants,
	})
	if !strings.Contains(msg, "最多 20") {
		t.Fatalf("msg = %s", msg)
	}
}

func TestHTTPDiffValidation(t *testing.T) {
	ts := NewToolSet(nil, "tester")
	cases := []map[string]any{
		{"url_template": "http://127.0.0.1/?id=1", "baseline": "1", "variants": []string{"2"}},
		{"url_template": "http://127.0.0.1/?id={v}", "baseline": "1", "variants": []string{}},
		{"url_template": "http://127.0.0.1/?id={v}", "baseline": strings.Repeat("a", 1025), "variants": []string{"2"}},
		{"url_template": "http://127.0.0.1/?id={v}", "baseline": "1", "variants": []string{"2"}, "timeout_sec": 5},
		{"url_template": "http://127.0.0.1/?id={v}", "baseline": "1", "variants": []string{"2"}, "method": "TRACE"},
	}
	for i, c := range cases {
		if msg := callHTTPDiffError(t, ts, c); msg == "" {
			t.Errorf("case %d: empty error", i)
		}
	}
}

func TestBodySimilarityAndSignal(t *testing.T) {
	if got := bodySimilarity([]byte("abc"), []byte("abc")); got != 1 {
		t.Errorf("same similarity = %v", got)
	}
	if got := bodySimilarity(nil, nil); got != 1 {
		t.Errorf("empty similarity = %v", got)
	}
	if got := bodySimilarity([]byte("abc"), []byte("xyz")); got != 0 {
		t.Errorf("different similarity = %v", got)
	}
	if got := bodySimilarity([]byte("abc"), []byte("abd")); got < 0.6 || got > 0.7 {
		t.Errorf("prefix similarity = %v", got)
	}
	cases := []struct {
		baseStatus, status, baseLen, bodyLen int
		same                                 bool
		sim                                  float64
		want                                 string
	}{
		{200, 302, 10, 10, false, 0.1, "status_flip"},
		{200, 403, 10, 10, false, 0.1, "status_diff"},
		{200, 200, 0, 10, false, 0.0, "len_diff_from_empty"},
		{200, 200, 100, 150, false, 0.1, "len_diff_40pct"},
		{200, 200, 100, 100, false, 0.5, "content_diff_same_size"},
		{200, 200, 1000, 1200, false, 0.5, "content_diff"},
		{200, 200, 100, 100, true, 1.0, "same"},
	}
	for i, c := range cases {
		if got := httpDiffSignal(c.baseStatus, c.status, c.baseLen, c.bodyLen, c.same, c.sim); got != c.want {
			t.Errorf("case %d: got %s, want %s", i, got, c.want)
		}
	}
}

func TestHTTPToolsInWorkerSetAndSeeds(t *testing.T) {
	names := map[string]bool{}
	for _, tool := range NewToolSet(nil, "").WorkerTools() {
		names[tool.Name()] = true
		if tool.Name() == "recon_http" || tool.Name() == "http_diff" {
			if !strings.Contains(tool.Description(), "T1595") {
				t.Errorf("%s description missing T1595", tool.Name())
			}
		}
	}
	for _, want := range []string{"recon_http", "http_diff"} {
		if !names[want] {
			t.Errorf("%s not in WorkerTools", want)
		}
	}
	seeds := map[string]bool{}
	for _, seed := range BuiltinToolSeeds() {
		for _, a := range seed.Agents {
			if a == "worker" {
				seeds[seed.Key] = true
			}
		}
	}
	for _, want := range []string{"recon_http", "http_diff"} {
		if !seeds[want] {
			t.Errorf("%s not seeded for worker", want)
		}
	}
}

func TestHTTPToolsNilStore(t *testing.T) {
	ts := NewToolSet(nil, "")
	res, err := ts.toolReconHTTP().Call(context.Background(), json.RawMessage(`{"url":"http://127.0.0.1/"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(res.Flatten(), "任务上下文") {
		t.Fatalf("recon_http nil store: IsError=%v %q", res.IsError, res.Flatten())
	}
	res, err = ts.toolHTTPDiff().Call(context.Background(), json.RawMessage(`{"url_template":"http://127.0.0.1/?id={v}","baseline":"1","variants":["2"]}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(res.Flatten(), "任务上下文") {
		t.Fatalf("http_diff nil store: IsError=%v %q", res.IsError, res.Flatten())
	}
}

func TestToolchainRuleMentionsHTTPTools(t *testing.T) {
	for _, want := range []string{"recon_http", "http_diff"} {
		if !strings.Contains(toolchainRule, want) {
			t.Errorf("toolchainRule missing %s", want)
		}
	}
}

func TestReconHTTPViaHTTPProxy(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "proxied")
	}))
	defer target.Close()

	var proxyHits int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&proxyHits, 1)
		req, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		req.Host = r.Host
		for k, vs := range r.Header {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	defer proxy.Close()

	ts := NewToolSet(nil, "tester")
	ts.SetHTTPProxy(proxy.URL, "")
	out := callReconHTTP(t, ts, map[string]any{"url": target.URL})
	if out.Status != "success" || out.BodyPreview != "proxied" {
		t.Fatalf("out = %+v", out)
	}
	if got := atomic.LoadInt32(&proxyHits); got != 1 {
		t.Errorf("proxy hits = %d, want 1", got)
	}
	if !strings.Contains(out.Proxy, "127.0.0.1") {
		t.Errorf("proxy field = %q", out.Proxy)
	}
}

func TestNewHTTPClientAndProxyRedaction(t *testing.T) {
	ts := NewToolSet(nil, "")
	if c, err := ts.newHTTPClient(true); err != nil || c == nil {
		t.Fatalf("direct client: %v", err)
	}
	ts.SetHTTPProxy("socks5://127.0.0.1:1", "")
	if c, err := ts.newHTTPClient(true); err != nil || c == nil {
		t.Fatalf("socks client: %v", err)
	}
	ts.SetHTTPProxy("http://user:secret@127.0.0.1:8080", "")
	if got := ts.httpProxyDisplay(); strings.Contains(got, "secret") {
		t.Errorf("proxy display leaked password: %s", got)
	} else if !strings.Contains(got, "***@") {
		t.Errorf("proxy display not redacted: %s", got)
	}
	ts.SetHTTPProxy("ftp://127.0.0.1:1", "")
	if _, err := ts.newHTTPClient(true); err == nil {
		t.Fatal("unsupported proxy scheme accepted")
	}
	if got := redactHTTPText("http://u:p@example.com/x"); strings.Contains(got, "u:p") {
		t.Errorf("redactHTTPText leaked credentials: %s", got)
	}
	if got := redactURLUserinfo("http://u:p@example.com/x"); strings.Contains(got, "u:p") || !strings.Contains(got, "***@") {
		t.Errorf("redactURLUserinfo = %q", got)
	}
}
