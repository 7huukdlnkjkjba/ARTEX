package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNormalizeTargetURL(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "", true},
		{"example.com/a?b=1", "http://example.com/a?b=1", false},
		{"https://example.com", "https://example.com", false},
		{"  http://127.0.0.1:8080/  ", "http://127.0.0.1:8080/", false},
		{"ftp://example.com", "", true},
		{"http:///nohost", "", true},
	}
	for _, c := range cases {
		u, err := normalizeTargetURL(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("normalizeTargetURL(%q) = %v, want error", c.in, u)
			}
			continue
		}
		if err != nil {
			t.Errorf("normalizeTargetURL(%q) error: %v", c.in, err)
			continue
		}
		if u.String() != c.want {
			t.Errorf("normalizeTargetURL(%q) = %q, want %q", c.in, u.String(), c.want)
		}
	}
}

func TestIsWAFBlocked(t *testing.T) {
	cases := []struct {
		status int
		body   string
		waf    string
		want   bool
	}{
		{403, "anything", "", true},
		{200, "request blocked by edge", "", true},
		{200, "blocked", "cloudflare", true},
		{200, "normal page content", "", false},
		{500, "SQL syntax error", "cloudflare", false}, // 5xx 非拦截状态码
	}
	for _, c := range cases {
		if got := isWAFBlocked(c.status, c.body, c.waf); got != c.want {
			t.Errorf("isWAFBlocked(%d, %q, %q) = %v, want %v", c.status, c.body, c.waf, got, c.want)
		}
	}
}

func TestDetectWAFFromResponse(t *testing.T) {
	if got := detectWAFFromResponse("HTTP/1.1 200 OK\nCf-Ray: abc\n", "ok"); got != "cloudflare" {
		t.Errorf("header detection = %q, want cloudflare", got)
	}
	if got := detectWAFFromResponse("HTTP/1.1 403 Forbidden\n", "request blocked by mod_security"); got != "modsecurity" {
		t.Errorf("body detection = %q, want modsecurity", got)
	}
	if got := detectWAFFromResponse("HTTP/1.1 200 OK\nServer: nginx\n", "hello"); got != "" {
		t.Errorf("no-WAF detection = %q, want empty", got)
	}
}

// TestWAFProbeBypass 用本地 httptest 靶场验证：明文注入被拦、变形放行时
// 结论应为 bypassable 且证据覆盖全部变体。
func TestWAFProbeBypass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("id")
		switch {
		case q == "":
			_, _ = w.Write([]byte("ok"))
		case strings.Contains(q, "' OR '"):
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Request blocked by web application firewall"))
		default:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("SQL syntax error near input"))
		}
	}))
	defer srv.Close()

	res := WAFProbe(context.Background(), srv.URL, 5*time.Second)
	if res.Verdict != "bypassable" || !res.Bypassable {
		t.Fatalf("verdict=%q bypassable=%v error=%q evidence=%v", res.Verdict, res.Bypassable, res.Error, res.Evidence)
	}
	if res.Score < 60 || res.BypassMethod == "" {
		t.Fatalf("score=%d method=%q", res.Score, res.BypassMethod)
	}
	if len(res.Evidence) != 8 {
		t.Fatalf("evidence len=%d, want 8: %v", len(res.Evidence), res.Evidence)
	}
	if res.WAFDetected != "" {
		t.Fatalf("waf=%q, want empty（基线正常、仅注入被拦）", res.WAFDetected)
	}
}

// TestWAFProbeHard 验证全变体被拦时结论为 hard。
func TestWAFProbeHard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cf-Ray", "test")
		if r.URL.Query().Get("id") == "" {
			_, _ = w.Write([]byte("ok"))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Access denied by security policy"))
	}))
	defer srv.Close()

	res := WAFProbe(context.Background(), srv.URL, 5*time.Second)
	if res.Verdict != "hard" || res.Bypassable {
		t.Fatalf("verdict=%q bypassable=%v evidence=%v", res.Verdict, res.Bypassable, res.Evidence)
	}
	if res.Score != 10 {
		t.Fatalf("score=%d, want 10", res.Score)
	}
}

// TestWAFProbeSkip 验证非法目标直接 skip，不发请求。
func TestWAFProbeSkip(t *testing.T) {
	res := WAFProbe(context.Background(), "ftp://example.com", time.Second)
	if res.Verdict != "skip" || res.Error == "" {
		t.Fatalf("verdict=%q error=%q", res.Verdict, res.Error)
	}
}

// TestWAFBypassProbeHandler 验证 HTTP 层：请求体解析、超时钳制与 JSON 响应。
func TestWAFBypassProbeHandler(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	s := &Server{}
	rec := httptest.NewRecorder()
	body := `{"target":"` + target.URL + `","timeout_seconds":0}`
	s.wafBypassProbe(rec, httptest.NewRequest(http.MethodPost, "/api/waf-probe", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var res WAFProbeResult
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode response: %v (%s)", err, rec.Body.String())
	}
	if res.Target != target.URL || res.Verdict != "skip" {
		t.Fatalf("target=%q verdict=%q", res.Target, res.Verdict)
	}

	// 非法 JSON 应 400。
	rec = httptest.NewRecorder()
	s.wafBypassProbe(rec, httptest.NewRequest(http.MethodPost, "/api/waf-probe", strings.NewReader("{")))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid body status=%d, want 400", rec.Code)
	}
}
