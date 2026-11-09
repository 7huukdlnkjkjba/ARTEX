package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func callWebAudit(t *testing.T, s *Server, payload map[string]any) WebAuditResult {
	t.Helper()
	raw, _ := json.Marshal(payload)
	res, err := s.toolWebAudit().Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool error: %s", res.Flatten())
	}
	var out WebAuditResult
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, res.Flatten())
	}
	return out
}

func TestWebAuditEndToEnd(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<html><!-- debug: test@example.com -->
<body>
<form action="/login" method="post"></form>
<script src="/app.js"></script>
<script>fetch('/api/inline'); var x=document.write(location.hash)</script>
<link rel="stylesheet" href="/style.css">
</body></html>`))
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`
fetch('/api/v1/admin/deleteUser');
axios.get("/api/v2/users");
const token = "abc12345";
const aws = "AKIA1234567890ABCDEF";
document.getElementById("x").innerHTML = location.hash;
`))
	})
	mux.HandleFunc("/style.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		_, _ = w.Write([]byte(`body{color:red}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	out := callWebAudit(t, &Server{}, map[string]any{
		"url": srv.URL + "/", "max_files": 10, "max_size": 1 << 20,
	})
	if out.Status != "success" || out.Egress != "direct" {
		t.Fatalf("out = %+v", out)
	}
	if !containsString(out.Forms, "POST "+srv.URL+"/login") {
		t.Errorf("forms = %v", out.Forms)
	}
	if !containsString(out.JSPaths, srv.URL+"/app.js") {
		t.Errorf("js = %v", out.JSPaths)
	}
	if !containsString(out.CSSPaths, srv.URL+"/style.css") {
		t.Errorf("css = %v", out.CSSPaths)
	}
	for _, want := range []string{"/api/v1/admin/deleteUser", "/api/v2/users", "/api/inline"} {
		if !containsString(out.APIRoutes, want) {
			t.Errorf("api %s missing: %v", want, out.APIRoutes)
		}
	}
	if !containsString(out.Secrets, "HARDCODED:token = \"abc12345\"") {
		t.Errorf("hardcoded secret missing: %v", out.Secrets)
	}
	if !strings.Contains(strings.Join(out.Secrets, "\n"), "AWS_AK:AKIA1234567890ABCDEF") {
		t.Errorf("aws secret missing: %v", out.Secrets)
	}
	if !containsString(out.DOMXSSSinks, ".innerHTML =") {
		t.Errorf("dom sink missing: %v", out.DOMXSSSinks)
	}
	if !containsString(out.HTMLComments, "debug: test@example.com") {
		t.Errorf("comment missing: %v", out.HTMLComments)
	}
}

func TestAuditWebAuditJSShortGenericNoPanic(t *testing.T) {
	res := &WebAuditResult{}
	auditWebAuditJS(`token = "abc12345"`, res)
	if len(res.Secrets) == 0 {
		t.Fatal("short generic secret not detected")
	}
}

func TestResolveWebAuditURL(t *testing.T) {
	base, _ := url.Parse("https://example.com/a/b")
	for raw, want := range map[string]string{
		"/x.js":             "https://example.com/x.js",
		"https://cdn/x":     "https://cdn/x",
		"javascript:void":   "",
		"data:text/plain,x": "",
		"#frag":             "",
	} {
		if got := resolveWebAuditURL(base, raw); got != want {
			t.Errorf("%s => %s, want %s", raw, got, want)
		}
	}
}

func TestWebAuditToolsRegistered(t *testing.T) {
	found := false
	for _, tool := range (&Server{}).webAuditTools() {
		if tool.Name() == "web_audit" {
			found = true
		}
	}
	if !found {
		t.Fatal("web_audit not registered")
	}
}

func containsString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
