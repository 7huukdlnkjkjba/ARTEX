package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

func TestIsLocalEndpoint(t *testing.T) {
	local := []string{
		"http://localhost:11434/v1",
		"http://127.0.0.1:11434/v1",
		"127.0.0.1:11434/v1",
		"http://[::1]:8000/v1",
		"http://10.0.0.5:8000/v1",
		"http://172.16.1.9:1234/v1",
		"http://172.31.255.1:1234/v1",
		"http://192.168.1.20:8080/v1",
		"http://ollama:11434/v1",
		"http://host.docker.internal:11434/v1",
		"http://lm.studio.local:1234/v1",
	}
	for _, s := range local {
		if !IsLocalEndpoint(s) {
			t.Fatalf("expected local: %s", s)
		}
	}
	remote := []string{
		"",
		"https://api.openai.com/v1",
		"https://api.deepseek.com/v1",
		"http://172.15.0.1:1234/v1",
		"http://172.32.0.1:1234/v1",
		"https://example.com",
	}
	for _, s := range remote {
		if IsLocalEndpoint(s) {
			t.Fatalf("expected remote: %s", s)
		}
	}
}

func TestConfigFromLocalAliases(t *testing.T) {
	for _, provider := range []string{"ollama", "local", "lmstudio", "vllm", "openai-compatible"} {
		c := ConfigFrom(provider, "qwen2.5:7b", "http://127.0.0.1:11434/v1", "", "")
		if c.Format != llm.FormatOpenAI {
			t.Fatalf("%s: format = %v, want openai", provider, c.Format)
		}
		if !c.KeyOptional() {
			t.Fatalf("%s: local endpoint must allow an empty key", provider)
		}
		if c.EffectiveKey() != "local" {
			t.Fatalf("%s: effective key = %q, want local", provider, c.EffectiveKey())
		}
	}
}

func TestConfigFromCloudStillRequiresKey(t *testing.T) {
	c := ConfigFrom("openai", "gpt-4o", "https://api.openai.com/v1", "", "")
	if c.KeyOptional() {
		t.Fatal("cloud endpoint without key must not be usable")
	}
	if c.EffectiveKey() != "" {
		t.Fatalf("cloud effective key = %q, want empty", c.EffectiveKey())
	}
}

func TestFromEnvLocalWithoutKey(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("ARTEX_LLM_PROVIDER", "")
	t.Setenv("ARTEX_LLM_BASE_URL", "http://127.0.0.1:11434/v1")
	t.Setenv("ARTEX_LLM_MODEL", "qwen2.5:7b")

	c, ok := FromEnv()
	if !ok {
		t.Fatal("local base URL without key should be accepted")
	}
	if c.Provider() != "openai" {
		t.Fatalf("provider = %s, want openai", c.Provider())
	}
	if c.Model != "qwen2.5:7b" {
		t.Fatalf("model = %s", c.Model)
	}
	if _, err := c.NewProvider(); err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
}

func TestFromEnvCloudWithoutKeyRejected(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("ARTEX_LLM_PROVIDER", "")
	t.Setenv("ARTEX_LLM_BASE_URL", "https://api.openai.com/v1")
	if _, ok := FromEnv(); ok {
		t.Fatal("cloud base URL without key must be rejected")
	}
}

// A local OpenAI-compatible server with no auth must work end-to-end: this is
// the Ollama / LM Studio / llama.cpp case the local-AI integration targets.
func TestLocalEndpointConnectionWithoutKey(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("authorization")
		if r.URL.Path != "/v1/chat/completions" && r.URL.Path != "/chat/completions" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1}}`))
	}))
	defer srv.Close()

	cfg := ConfigFrom("openai", "qwen2.5:7b", srv.URL+"/v1", "", "")
	cfg.Stream = false
	lat, reply, err := TestConnection(context.Background(), cfg)
	if err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
	if lat <= 0 {
		t.Fatalf("latency = %v", lat)
	}
	if reply == "" {
		t.Fatal("empty reply")
	}
	if gotAuth != "Bearer local" {
		t.Fatalf("auth header = %q, want Bearer local", gotAuth)
	}
}
