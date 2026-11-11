package server

import (
	"net/http"
	"net/http/httptest"
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
		if !strings.HasPrefix(s.BaseURL, "https://") {
			t.Fatalf("%s: base URL should be https, got %q", s.Key, s.BaseURL)
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
