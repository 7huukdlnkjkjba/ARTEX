package server

import (
	"context"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// The built-in Chat2API profile must exist after startup, stay inactive, and
// never duplicate on later boots (operators may edit or delete it by hand).
func TestSeedChat2APIProfileIsBuiltinAndIdempotent(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	td := t.TempDir()
	s := New(context.Background(), m, td, td, td)

	// The constructor seeds it once; call again to prove the seed is idempotent.
	s.seedChat2APIProfile()

	byName := func() []*db.LLMProfile {
		profs, err := m.pg.ListProfiles()
		if err != nil {
			t.Fatalf("list profiles: %v", err)
		}
		var out []*db.LLMProfile
		for _, p := range profs {
			if p.Name == chat2apiProfileName {
				out = append(out, p)
			}
		}
		return out
	}

	got := byName()
	if len(got) != 1 {
		t.Fatalf("built-in Chat2API profile count = %d, want 1", len(got))
	}
	p := got[0]
	if p.Format != "openai" {
		t.Fatalf("format = %q, want openai", p.Format)
	}
	if p.BaseURL != chat2apiBaseURL {
		t.Fatalf("base_url = %q, want %q", p.BaseURL, chat2apiBaseURL)
	}
	if p.Model != chat2apiDefaultModel {
		t.Fatalf("model = %q, want %q", p.Model, chat2apiDefaultModel)
	}
	if p.IsDefault {
		t.Fatal("built-in profile must not be auto-activated")
	}
	if !p.PoolExclude {
		t.Fatal("built-in profile must stay out of the failover chain by default")
	}
	if p.APIKeyHint == "" {
		t.Fatal("built-in profile should explain that a local proxy needs no key")
	}
}
