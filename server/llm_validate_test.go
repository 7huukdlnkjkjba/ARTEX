package server

import (
	"strings"
	"testing"
)

func TestValidateAnthropicEndpoint(t *testing.T) {
	cases := []struct {
		name    string
		format  string
		model   string
		baseURL string
		wantErr string // substring; "" = pass
	}{
		{"deepseek inferred", "anthropic", "deepseek-chat", "", ""},
		{"claude official", "anthropic", "claude-opus-4-8", "", ""},
		{"explicit base", "anthropic", "some-model", "https://relay.example/anthropic", ""},
		{"openai format", "openai", "gpt-4o", "", ""},
		{"unknown model", "anthropic", "some-model", "", "api.anthropic.com"},
		{"unknown model deepseek-ish", "anthropic", "deepseek-coder-custom", "", ""},
	}
	for _, c := range cases {
		err := validateAnthropicEndpoint(c.format, c.model, c.baseURL)
		if c.wantErr == "" {
			if err != nil {
				t.Errorf("%s: unexpected error: %v", c.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: want error containing %q, got %v", c.name, c.wantErr, err)
		}
	}
}
