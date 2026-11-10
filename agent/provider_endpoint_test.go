package agent

import "testing"

func TestDefaultAnthropicBaseURL(t *testing.T) {
	cases := []struct{ model, want string }{
		{"deepseek-chat", "https://api.deepseek.com/anthropic"},
		{"DeepSeek-Reasoner", "https://api.deepseek.com/anthropic"},
		{"  deepseek-chat  ", "https://api.deepseek.com/anthropic"},
		{"claude-opus-4-8", ""},
		{"gpt-4o", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := DefaultAnthropicBaseURL(c.model); got != c.want {
			t.Errorf("DefaultAnthropicBaseURL(%q) = %q, want %q", c.model, got, c.want)
		}
	}
}

// An empty Base URL on an Anthropic-format profile must resolve to the vendor's
// official compatible endpoint for known third-party models — otherwise the
// request silently goes to api.anthropic.com and is rejected (403).
func TestConfigFromInfersThirdPartyAnthropicEndpoint(t *testing.T) {
	c := ConfigFrom("anthropic", "deepseek-chat", "", "sk-test", "")
	if c.BaseURL != "https://api.deepseek.com/anthropic" {
		t.Fatalf("deepseek base URL not inferred: %q", c.BaseURL)
	}
	if c.Provider() != "anthropic" {
		t.Fatalf("format changed: %q", c.Provider())
	}

	// An explicit relay endpoint always wins over inference.
	c = ConfigFrom("anthropic", "deepseek-chat", "https://relay.example/anthropic", "sk-test", "")
	if c.BaseURL != "https://relay.example/anthropic" {
		t.Fatalf("explicit base URL overridden: %q", c.BaseURL)
	}

	// Claude models keep the SDK's official default (empty BaseURL).
	c = ConfigFrom("anthropic", "claude-opus-4-8", "", "sk-test", "")
	if c.BaseURL != "" {
		t.Fatalf("claude base URL should stay empty: %q", c.BaseURL)
	}

	// A full endpoint URL is still normalized, and inference does not fire.
	c = ConfigFrom("anthropic", "deepseek-chat", "https://api.deepseek.com/anthropic/v1/messages", "sk-test", "")
	if c.BaseURL != "https://api.deepseek.com/anthropic" {
		t.Fatalf("endpoint URL not normalized: %q", c.BaseURL)
	}
}
