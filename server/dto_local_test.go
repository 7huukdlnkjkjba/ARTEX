package server

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestLocalProfileHintIsHumanReadable(t *testing.T) {
	p := &db.LLMProfile{
		BaseURL: "http://127.0.0.1:11434/v1",
		Model:   "qwen2.5:7b",
		Format:  "openai",
		// ListProfiles omits the secret; the hint is all the DTO sees.
		APIKeyHint: "…ocal",
	}
	d := llmProfileDTO(p)
	if d.APIKeyHint != "本地端点" {
		t.Fatalf("hint = %q, want 本地端点", d.APIKeyHint)
	}
}
