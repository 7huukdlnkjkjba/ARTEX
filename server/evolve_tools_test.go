package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pgdb "github.com/Autumn-27/artex/db"
)

func newEvolveTestTools(t *testing.T) (*EvolveTools, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "agent", "prompts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "agent", "prompts", "worker.md"), []byte("hello worker"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "skills", "demo"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "skills", "demo", "SKILL.md"), []byte("# demo"), 0o644); err != nil {
		t.Fatal(err)
	}
	return &EvolveTools{RepoRoot: root, DataDir: t.TempDir()}, root
}

func TestEvolveSafePathAndRead(t *testing.T) {
	et, _ := newEvolveTestTools(t)
	out, err := et.EvolveRead(EvolveReadArgs{Path: "agent/prompts/worker.md"})
	if err != nil || out != "hello worker" {
		t.Fatalf("read = %q %v", out, err)
	}
	for _, bad := range []string{
		"../etc/passwd",
		"agent/prompts/../../x",
		"/etc/passwd",
		"go.mod",
		"agent/prompts/../..",
		"scripts/evolve_costs.sql",
	} {
		if _, err := et.safePath(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestEvolveTargetToPath(t *testing.T) {
	et, _ := newEvolveTestTools(t)
	p, err := et.targetToPath("prompt:worker")
	if err != nil || p != "agent/prompts/worker.md" {
		t.Fatalf("prompt path = %q %v", p, err)
	}
	p, err = et.targetToPath("skill:demo")
	if err != nil || p != "skills/demo/SKILL.md" {
		t.Fatalf("skill path = %q %v", p, err)
	}
	for _, bad := range []string{"go:foo", "prompt:../x", "skill:../x", "prompt:"} {
		if _, err := et.targetToPath(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSamePrefixAndToolMentions(t *testing.T) {
	if !samePrefix([]byte("abcdef"), []byte("abcxyz"), 3) {
		t.Error("prefix should match")
	}
	if samePrefix([]byte("abcdef"), []byte("abcxyz"), 4) {
		t.Error("prefix should differ")
	}
	if !samePrefix([]byte("ab"), []byte("abc"), 99) {
		// bounded to the shorter slice
	}
	if countToolMentions("use recon_http and recon_http") != 2 {
		t.Error("tool mentions")
	}
}

func TestShouldUseShadowDeterministic(t *testing.T) {
	a := ShouldUseShadow(123, "prompt:worker")
	b := ShouldUseShadow(123, "prompt:worker")
	if a != b {
		t.Fatal("not deterministic")
	}
}

func TestEstimateCacheMissCost(t *testing.T) {
	if got := estimateCacheMissCost(nil, "prompt:x", 1000000); got <= 0 {
		t.Fatalf("cost = %v", got)
	}
}

func TestEvolveToolsRegistered(t *testing.T) {
	names := map[string]bool{}
	for _, tool := range (&Server{}).evolveTools() {
		names[tool.Name()] = true
	}
	for _, want := range []string{"evolve_leaks", "evolve_begin", "evolve_read",
		"evolve_propose", "evolve_trial", "evolve_compare", "evolve_promote", "evolve_abandon"} {
		if !names[want] {
			t.Errorf("missing %s", want)
		}
	}
}

func TestEvolveReadRejectsOutOfScope(t *testing.T) {
	et, _ := newEvolveTestTools(t)
	if _, err := et.EvolveRead(EvolveReadArgs{Path: "go.mod"}); err == nil ||
		!strings.Contains(err.Error(), "out of evolve scope") {
		t.Fatalf("err = %v", err)
	}
}

func TestEvolveProposalLifecycleDB(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("ARTEX_PG_DSN not set")
	}
	d, err := pgdb.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := pgdb.EnsureGenomeSchema(d.DB); err != nil {
		t.Fatal(err)
	}
	et, root := newEvolveTestTools(t)
	et.DB = d.DB
	old, err := os.ReadFile(filepath.Join(root, "agent", "prompts", "worker.md"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := et.EvolvePropose(ProposeArgs{
		RunID: 0, Target: "prompt:worker",
		SpecificChange: "删掉一句冗余", Rationale: "减少 token",
		EvidenceIDs: []string{"leak:1"}, ExpectedEffect: "avg_cost_cny 下降",
		ValidationMetric: "avg_cost_cny 下降", RollbackCondition: "成本上升即回滚",
	})
	if err != nil {
		t.Fatal(err)
	}
	var proposal struct {
		ProposalID int64 `json:"proposal_id"`
	}
	if err := json.Unmarshal([]byte(out), &proposal); err != nil || proposal.ProposalID <= 0 {
		t.Fatalf("proposal = %s %v", out, err)
	}
	defer d.Exec(`DELETE FROM evolve_trials WHERE proposal_id=$1`, proposal.ProposalID)
	defer d.Exec(`DELETE FROM evolve_costs WHERE proposal_id=$1`, proposal.ProposalID)
	defer d.Exec(`DELETE FROM evolve_proposals WHERE id=$1`, proposal.ProposalID)

	trial, err := et.EvolveTrial(TrialArgs{ProposalID: proposal.ProposalID, NewContent: string(old), Confirm: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(trial, `"verdict":"pass"`) {
		t.Fatalf("trial = %s", trial)
	}
}
