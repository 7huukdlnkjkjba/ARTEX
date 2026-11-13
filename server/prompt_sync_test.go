package server

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestBuiltinPromptNote(t *testing.T) {
	builtin := []string{"内置默认", " 恢复为内置默认 ", "恢复为内置默认"}
	for _, n := range builtin {
		if !builtinPromptNote(n) {
			t.Errorf("builtinPromptNote(%q) = false, want true", n)
		}
	}
	user := []string{"", "手动编辑", "v2 指挥+执行双姿态", "test", "restore test fixture"}
	for _, n := range user {
		if builtinPromptNote(n) {
			t.Errorf("builtinPromptNote(%q) = true, want false (must not clobber user edits)", n)
		}
	}
}

// TestSyncBuiltinPromptUpgradesOnlyCodeOwnedVersions runs against the dev PG; it
// creates a throwaway custom agent so the real built-in prompts are never touched.
func TestSyncBuiltinPromptUpgradesOnlyCodeOwnedVersions(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	// Cleanup LIFO: DeleteAgent below must run before the pool closes (a defer
	// would close it first and silently leak the temp agent).
	t.Cleanup(func() { _ = pg.Close() })

	const key = "zz_prompt_sync_test"
	_ = pg.DeleteAgent(key)
	a, err := pg.CreateAgent(key, "prompt sync test", "")
	if err != nil {
		t.Skipf("cannot create temp agent (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = pg.DeleteAgent(key) })

	// Case 1: code-owned old default → upgraded to the new default.
	if _, err := pg.SavePrompt(a.ID, "OLD BUILTIN", "内置默认", "system"); err != nil {
		t.Fatal(err)
	}
	syncBuiltinPrompt(pg, key, "NEW BUILTIN")
	got, note, ver, err := pg.CurrentPromptMeta(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got != "NEW BUILTIN" {
		t.Fatalf("built-in prompt not upgraded: %q (note=%q v%d)", got, note, ver)
	}
	if ver < 2 {
		t.Fatalf("upgrade must append a new version, got v%d", ver)
	}

	// Case 2: user-edited prompt → left alone.
	if _, err := pg.SavePrompt(a.ID, "USER CUSTOM", "手动编辑", "ui"); err != nil {
		t.Fatal(err)
	}
	syncBuiltinPrompt(pg, key, "ANOTHER DEFAULT")
	got, _, _, err = pg.CurrentPromptMeta(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got != "USER CUSTOM" {
		t.Fatalf("user prompt was clobbered: %q", got)
	}

	// Case 3: already current → idempotent (no new version).
	_, _, before, _ := pg.CurrentPromptMeta(a.ID)
	syncBuiltinPrompt(pg, key, "USER CUSTOM")
	_, _, after, _ := pg.CurrentPromptMeta(a.ID)
	if before != after {
		t.Fatalf("idempotent sync appended a version: %d -> %d", before, after)
	}
}
