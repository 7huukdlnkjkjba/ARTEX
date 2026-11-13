package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// 目录必须自带一个免 Key 来源，否则「内置免费池」首次启动就是空的。
func TestBuiltinFreeSourcesHaveKeylessDefault(t *testing.T) {
	srcs := builtinFreeSources()
	if len(srcs) == 0 {
		t.Fatal("free source catalog is empty")
	}
	seen := map[string]bool{}
	keyless := 0
	for _, s := range srcs {
		if s.Key == "" || s.Name == "" || s.BaseURL == "" {
			t.Fatalf("incomplete source: %+v", s)
		}
		if seen[s.Key] {
			t.Fatalf("duplicate source key %q", s.Key)
		}
		seen[s.Key] = true
		// 远端来源必须走 https；只有显式标记为 Local 的回环端点允许 http。
		u, err := url.Parse(s.BaseURL)
		if err != nil {
			t.Fatalf("%s: unparsable base URL %q: %v", s.Key, s.BaseURL, err)
		}
		if u.Scheme != "https" {
			loopback := u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1"
			if u.Scheme != "http" || !s.Local || !loopback {
				t.Fatalf("%s: base URL should be https (http is only for Local sources), got %q", s.Key, s.BaseURL)
			}
		}
		if s.Keyless {
			keyless++
			if len(s.Models) == 0 {
				t.Fatalf("%s: keyless source needs a default model", s.Key)
			}
		}
	}
	if keyless == 0 {
		t.Fatal("catalog has no keyless source: a fresh install would have an empty pool")
	}
	if _, ok := freeSourceByKey("pollinations"); !ok {
		t.Fatal("pollinations (keyless default) missing from catalog")
	}
}

// probeFreeAccount must reject a 200 that is not a chat completion — otherwise a
// captive portal / error page would look like a healthy free source.
func TestProbeFreeAccountRequiresChoices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"error":"rate limited"}`))
	}))
	defer srv.Close()

	src := freeSource{Key: "t", Name: "t", BaseURL: srv.URL, Models: []string{"m"}}
	ok, _, msg := probeFreeAccount(src, "", "m")
	if ok {
		t.Fatal("probe accepted a non-completion body")
	}
	if !strings.Contains(msg, "chat/completion") {
		t.Fatalf("unexpected probe error: %q", msg)
	}
}

func TestProbeFreeAccountAcceptsCompletion(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"OK"}}]}`))
	}))
	defer srv.Close()

	src := freeSource{Key: "t", Name: "t", BaseURL: srv.URL, Models: []string{"m"}}
	ok, ms, msg := probeFreeAccount(src, "sk-test", "m")
	if !ok || msg != "" {
		t.Fatalf("probe failed: ok=%v msg=%q", ok, msg)
	}
	if gotAuth != "Bearer sk-test" {
		t.Fatalf("authorization header = %q", gotAuth)
	}
	if ms < 0 {
		t.Fatalf("latency = %d", ms)
	}
}

// Pool member names must stay unique so a second account of the same source does
// not collide with the UNIQUE(name) constraint on llm_profiles.
func TestProfileNameForFreeAccountDeduplicates(t *testing.T) {
	src := freeSource{Key: "pollinations", Name: "Pollinations"}
	existing := []*db.LLMProfile{{Name: "免费池·Pollinations"}, {Name: "免费池·Pollinations #2"}}
	got := profileNameForFreeAccount(src, existing, "")
	if got != "免费池·Pollinations #3" {
		t.Fatalf("name = %q, want 免费池·Pollinations #3", got)
	}
	got = profileNameForFreeAccount(src, nil, "工作号")
	if !strings.Contains(got, "工作号") {
		t.Fatalf("label missing from generated name: %q", got)
	}
}

// 操作员已经在环境里导出的 Key 应被直接复用，不再要求他在池子里重填一遍。
func TestSourceEnvKeyUsesExportedKey(t *testing.T) {
	t.Setenv("GEMINI_API_KEY", "")
	t.Setenv("GOOGLE_API_KEY", "google-key")
	if got := sourceEnvKey(freeSource{Key: "gemini", EnvKey: "GEMINI_API_KEY"}); got != "google-key" {
		t.Fatalf("gemini alias = %q, want google-key", got)
	}

	t.Setenv("CEREBRAS_API_KEY", "cerebras-key")
	if got := sourceEnvKey(freeSource{Key: "cerebras", EnvKey: "CEREBRAS_API_KEY"}); got != "cerebras-key" {
		t.Fatalf("cerebras = %q", got)
	}

	t.Setenv("OPENROUTER_API_KEY", "")
	if got := sourceEnvKey(freeSource{Key: "openrouter", EnvKey: "OPENROUTER_API_KEY"}); got != "" {
		t.Fatalf("unset key leaked: %q", got)
	}
}

// 同一个端点写成 https://x/v1/ 与 https://X/v1 必须视为同一份配置，否则池子会
// 在已有 profile 旁边再建一份重复配置。
func TestNormalizeBaseURL(t *testing.T) {
	cases := map[string]string{
		"https://openrouter.ai/api/v1/":      "https://openrouter.ai/api/v1",
		"  HTTPS://API.GROQ.COM/openai/v1  ": "https://api.groq.com/openai/v1",
		"":                                   "",
	}
	for in, want := range cases {
		if got := normalizeBaseURL(in); got != want {
			t.Fatalf("normalizeBaseURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// 只有真的有东西在监听时才把本地来源放进池子，避免默认成员长期不可用。
func TestLocalEndpointUp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	if !localEndpointUp(srv.URL) {
		t.Fatalf("localEndpointUp(%q) = false, want true", srv.URL)
	}
	if localEndpointUp("http://127.0.0.1:1/v1") {
		t.Fatal("localEndpointUp reported closed port as up")
	}
	if localEndpointUp("::bad url") {
		t.Fatal("localEndpointUp accepted an unparsable URL")
	}
}
