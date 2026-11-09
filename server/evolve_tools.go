package server

// EvolveTools is the code side of "AI improves AI": the model may only edit
// whitelisted prompt/skill text, and every promotion is gated by measured cost
// (or explicitly inconclusive until shadow samples exist). It cannot modify Go,
// SQL, guard, scope or RoE.

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/artex/cost"
	pgdb "github.com/Autumn-27/artex/db"
	"github.com/lib/pq"
)

type EvolveTools struct {
	DB       *sql.DB
	RepoRoot string
	DataDir  string
}

type EvolveReadArgs struct {
	Path string `json:"path"`
}

func (t *EvolveTools) EvolveRead(args EvolveReadArgs) (string, error) {
	full, err := t.safePath(args.Path)
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(full)
	if err != nil {
		return "", err
	}
	if len(b) > 64*1024 {
		b = b[:64*1024]
	}
	return string(b), nil
}

func (t *EvolveTools) safePath(p string) (string, error) {
	if t == nil || strings.TrimSpace(t.RepoRoot) == "" {
		return "", fmt.Errorf("evolve root not configured")
	}
	clean := filepath.Clean(strings.TrimSpace(p))
	if clean == "." || filepath.IsAbs(clean) || clean == ".." ||
		strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes sandbox: %s", p)
	}
	clean = filepath.ToSlash(clean)
	allowed := []string{"agent/prompts/", ".agents/skills/", "skills/"}
	ok := false
	for _, a := range allowed {
		if strings.HasPrefix(clean, a) {
			ok = true
			break
		}
	}
	if !ok {
		return "", fmt.Errorf("path out of evolve scope: %s", p)
	}
	full := filepath.Join(t.RepoRoot, filepath.FromSlash(clean))
	rel, err := filepath.Rel(t.RepoRoot, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes sandbox: %s", p)
	}
	return full, nil
}

type ProposeArgs struct {
	RunID             int64    `json:"run_id"`
	Target            string   `json:"target"`
	SpecificChange    string   `json:"specific_change"`
	Rationale         string   `json:"rationale"`
	EvidenceIDs       []string `json:"evidence_ids"`
	ExpectedEffect    string   `json:"expected_effect"`
	ValidationMetric  string   `json:"validation_metric"`
	RollbackCondition string   `json:"rollback_condition"`
}

func (t *EvolveTools) EvolvePropose(args ProposeArgs) (string, error) {
	for _, v := range []string{args.Target, args.SpecificChange, args.Rationale,
		args.ExpectedEffect, args.ValidationMetric, args.RollbackCondition} {
		if strings.TrimSpace(v) == "" {
			return "", fmt.Errorf("evolve_propose: all text fields required")
		}
	}
	if len(args.EvidenceIDs) == 0 {
		return "", fmt.Errorf("evolve_propose: evidence_ids required")
	}
	var id int64
	err := t.DB.QueryRow(
		`INSERT INTO evolve_proposals
		 (run_id, target, specific_change, rationale, evidence_ids,
		  expected_effect, validation_metric, rollback_condition, status)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'proposed') RETURNING id`,
		args.RunID, args.Target, args.SpecificChange, args.Rationale,
		pq.Array(args.EvidenceIDs), args.ExpectedEffect,
		args.ValidationMetric, args.RollbackCondition).Scan(&id)
	if err != nil {
		return "", err
	}
	out, _ := json.Marshal(map[string]any{"proposal_id": id, "status": "proposed"})
	return string(out), nil
}

type TrialArgs struct {
	ProposalID int64  `json:"proposal_id"`
	NewContent string `json:"new_content"`
	Confirm    bool   `json:"confirm"`
}

// OfflineReplay is zero-LLM static validation: token growth, cache-prefix
// stability and tool-mention growth.
func (t *EvolveTools) OfflineReplay(proposalID int64, newContent string) (string, float64, error) {
	var target string
	if err := t.DB.QueryRow(`SELECT target FROM evolve_proposals WHERE id=$1`, proposalID).Scan(&target); err != nil {
		return "fail", 0, fmt.Errorf("proposal not found: %w", err)
	}
	oldPath, err := t.targetToPath(target)
	if err != nil {
		return "fail", 0, err
	}
	oldContent, err := os.ReadFile(filepath.Join(t.RepoRoot, oldPath))
	if err != nil {
		return "fail", 0, err
	}
	if strings.TrimSpace(newContent) == "" {
		return "fail", 0, fmt.Errorf("new_content 为空")
	}

	oldTok := roughTokenCount(string(oldContent))
	newTok := roughTokenCount(newContent)
	if newTok > int(float64(oldTok)*1.1) {
		return "fail", 0, fmt.Errorf("prompt bloat: %d -> %d tokens", oldTok, newTok)
	}

	// Compare the first half of the old content as a byte prefix. The old code
	// passed a token count as a byte length, which could read out of range.
	prefixLen := len(oldContent) / 2
	if prefixLen > len(newContent) {
		prefixLen = len(newContent)
	}
	if !samePrefix(oldContent, []byte(newContent), prefixLen) {
		extra := estimateCacheMissCost(t.DB, target, oldTok/2)
		if extra > 0.01 {
			return "fail", extra, fmt.Errorf("cache invalidation cost: ¥%.4f", extra)
		}
		return "inconclusive", extra, nil
	}

	if countToolMentions(newContent) > countToolMentions(string(oldContent)) {
		return "fail", 0, fmt.Errorf("more tool mentions may increase turns")
	}
	return "pass", 0, nil
}

func (t *EvolveTools) EvolveTrial(args TrialArgs) (string, error) {
	if !args.Confirm {
		return "", fmt.Errorf("evolve_trial requires confirm=true")
	}
	verdict, extra, err := t.OfflineReplay(args.ProposalID, args.NewContent)
	pid := args.ProposalID
	_ = pgdb.RecordEvolutionCost(t.DB, 0, &pid, "replay", extra, verdict)
	_, _ = t.DB.Exec(
		`INSERT INTO evolve_trials (proposal_id, fixture, verdict, detail)
		 VALUES ($1,'offline-replay',$2,$3)`, args.ProposalID, verdict, fmt.Sprintf("extra=%.4f", extra))
	if err != nil {
		return "", err
	}
	out, _ := json.Marshal(map[string]any{"proposal_id": args.ProposalID, "verdict": verdict, "extra_cost": extra})
	return string(out), nil
}

type CompareArgs struct {
	ProposalID    int64 `json:"proposal_id"`
	ExpectedTasks int   `json:"expected_tasks"`
}

func (t *EvolveTools) EvolveCompare(args CompareArgs) (string, error) {
	if args.ExpectedTasks <= 0 {
		args.ExpectedTasks = 20
	}
	var target string
	if err := t.DB.QueryRow(`SELECT target FROM evolve_proposals WHERE id=$1`, args.ProposalID).Scan(&target); err != nil {
		return "", err
	}
	curRev, _, err := pgdb.CurrentRevision(t.DB, target)
	if err != nil {
		return "", err
	}
	base, err := pgdb.GeneCostProfileOf(t.DB, target, curRev, 50)
	if err != nil {
		return "", err
	}
	if base.SampleCount < 3 {
		return "", fmt.Errorf("baseline samples < 3, cannot compare")
	}
	var evoCost float64
	_ = t.DB.QueryRow(`SELECT COALESCE(SUM(cost_cny),0) FROM evolve_costs WHERE proposal_id=$1`, args.ProposalID).Scan(&evoCost)

	var variantSamples int
	_ = t.DB.QueryRow(`
		SELECT COUNT(*) FROM genome_phenotypes
		WHERE genome_snapshot->>$1 IS NOT NULL AND is_shadow=true`, target).Scan(&variantSamples)
	if variantSamples < 3 {
		out, _ := json.Marshal(map[string]any{
			"verdict": "inconclusive", "action": "enter_shadow", "samples": variantSamples,
			"note": "need >=3 shadow samples before cost comparison; no synthetic samples are fabricated",
		})
		return string(out), nil
	}
	variant, err := pgdb.GeneCostProfileOf(t.DB, target, curRev+1, 50)
	if err != nil {
		return "", err
	}
	verdict, net := pgdb.CostAwareVerdict(base, variant, args.ExpectedTasks, evoCost)
	switch verdict {
	case "pass":
		_, _ = t.DB.Exec(`UPDATE evolve_proposals SET status='accepted' WHERE id=$1`, args.ProposalID)
	case "fail":
		_, _ = t.DB.Exec(`UPDATE evolve_proposals SET status='retired' WHERE id=$1`, args.ProposalID)
	}
	out, _ := json.Marshal(map[string]any{
		"verdict": verdict, "net_benefit": net,
		"baseline": base, "variant": variant, "evo_cost": evoCost,
	})
	return string(out), nil
}

type PromoteArgs struct {
	ProposalID int64  `json:"proposal_id"`
	NewContent string `json:"new_content"`
	Confirm    bool   `json:"confirm"`
}

func (t *EvolveTools) EvolvePromote(args PromoteArgs) (string, error) {
	if !args.Confirm {
		return "", fmt.Errorf("evolve_promote requires confirm=true")
	}
	var status, target string
	err := t.DB.QueryRow(`SELECT status, target FROM evolve_proposals WHERE id=$1`, args.ProposalID).
		Scan(&status, &target)
	if err != nil {
		return "", err
	}
	if status != "accepted" {
		return "", fmt.Errorf("proposal not accepted (status=%s)", status)
	}
	var evoCost float64
	_ = t.DB.QueryRow(`SELECT COALESCE(SUM(cost_cny),0) FROM evolve_costs WHERE proposal_id=$1`, args.ProposalID).Scan(&evoCost)
	curRev, _, err := pgdb.CurrentRevision(t.DB, target)
	if err != nil {
		return "", err
	}
	base, _ := pgdb.GeneCostProfileOf(t.DB, target, curRev, 50)
	variant, _ := pgdb.GeneCostProfileOf(t.DB, target, curRev+1, 50)
	verdict, net := pgdb.CostAwareVerdict(base, variant, 20, evoCost)
	if verdict != "pass" || net <= 0 {
		return "", fmt.Errorf("net benefit not positive: verdict=%s net=%.4f", verdict, net)
	}

	filePath, err := t.targetToPath(target)
	if err != nil {
		return "", err
	}
	full := filepath.Join(t.RepoRoot, filePath)
	old, err := os.ReadFile(full)
	if err != nil {
		return "", err
	}
	backup := full + ".evolve-backup-" + fmt.Sprint(time.Now().Unix())
	if err := os.WriteFile(backup, old, 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(full, []byte(args.NewContent), 0o644); err != nil {
		return "", err
	}
	parts := strings.SplitN(target, ":", 2)
	gene, err := pgdb.RegisterGeneRevision(t.DB, target, parts[0], filePath, []byte(args.NewContent), &curRev, "active")
	if err != nil {
		return "", err
	}
	_ = pgdb.RetireGene(t.DB, target, curRev, []string{fmt.Sprint(args.ProposalID)})
	_ = pgdb.AddEvent(t.DB, "selection", target, &curRev, &gene.Revision,
		[]string{fmt.Sprint(args.ProposalID)}, &args.ProposalID, net)
	_, _ = t.DB.Exec(`UPDATE evolve_proposals SET status='verified' WHERE id=$1`, args.ProposalID)

	out, _ := json.Marshal(map[string]any{
		"gene_key": target, "revision": gene.Revision,
		"path": filePath, "backup": backup, "net_benefit": net,
	})
	return string(out), nil
}

type AbandonArgs struct {
	ProposalID int64  `json:"proposal_id"`
	Reason     string `json:"reason"`
}

func (t *EvolveTools) EvolveAbandon(args AbandonArgs) (string, error) {
	if strings.TrimSpace(args.Reason) == "" {
		return "", fmt.Errorf("reason required")
	}
	res, err := t.DB.Exec(
		`UPDATE evolve_proposals SET status='retired' WHERE id=$1 AND status IN ('proposed','accepted')`,
		args.ProposalID)
	if err != nil {
		return "", err
	}
	n, _ := res.RowsAffected()
	_ = pgdb.AddEvent(t.DB, "retirement", "", nil, nil,
		[]string{fmt.Sprint(args.ProposalID)}, &args.ProposalID, 0)
	out, _ := json.Marshal(map[string]any{"proposal_id": args.ProposalID, "retired": n > 0, "reason": args.Reason})
	return string(out), nil
}

func (t *EvolveTools) EvolveLeaks() (string, error) {
	leaks, err := FindCostLeaks(t.DB)
	if err != nil {
		return "", err
	}
	out, _ := json.Marshal(map[string]any{"leaks": leaks, "count": len(leaks)})
	return string(out), nil
}

func (t *EvolveTools) EvolveBegin(taskID, intentID int64) (string, error) {
	leaks, err := FindCostLeaks(t.DB)
	if err != nil {
		return "", err
	}
	if len(leaks) == 0 {
		return `{"status":"no_cost_leak"}`, nil
	}
	leak := leaks[0]
	workspace := filepath.Join(t.DataDir, "evolve", fmt.Sprint(taskID))
	var runID int64
	err = t.DB.QueryRow(
		`INSERT INTO evolve_runs (task_id, intent_id, target, workspace, status)
		 VALUES ($1,$2,$3,$4,'analyzing') RETURNING id`,
		taskID, intentID, leak.Gene, workspace).Scan(&runID)
	if err != nil {
		return "", err
	}
	out, _ := json.Marshal(map[string]any{
		"run_id": runID, "target": leak.Gene, "leak": leak,
		"workspace": workspace, "status": "analyzing",
		"next": "evolve_read target, then evolve_propose with evidence_ids",
	})
	return string(out), nil
}

func (t *EvolveTools) targetToPath(target string) (string, error) {
	parts := strings.SplitN(target, ":", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("bad target: %s", target)
	}
	name := strings.TrimSpace(parts[1])
	if name == "" || strings.ContainsAny(name, `/\`) || name == "." || name == ".." {
		return "", fmt.Errorf("bad target name: %s", target)
	}
	switch parts[0] {
	case "prompt":
		if !strings.HasSuffix(name, ".md") {
			name += ".md"
		}
		return "agent/prompts/" + name, nil
	case "skill":
		if _, err := os.Stat(filepath.Join(t.RepoRoot, ".agents", "skills", name, "SKILL.md")); err == nil {
			return ".agents/skills/" + name + "/SKILL.md", nil
		}
		return "skills/" + name + "/SKILL.md", nil
	default:
		return "", fmt.Errorf("unsupported target category: %s", parts[0])
	}
}

func roughTokenCount(s string) int { return len(s) / 4 }

func samePrefix(old, new []byte, prefixLen int) bool {
	if prefixLen < 0 {
		prefixLen = 0
	}
	if prefixLen > len(old) || prefixLen > len(new) {
		prefixLen = len(old)
		if len(new) < prefixLen {
			prefixLen = len(new)
		}
	}
	return string(old[:prefixLen]) == string(new[:prefixLen])
}

func countToolMentions(s string) int {
	n := 0
	for _, tool := range []string{"recon_http", "http_diff", "scan_rustscan", "nuclei_run",
		"sqlmap_run", "raw_tcp", "msf_plan", "msf_execute", "path_probe"} {
		n += strings.Count(s, tool)
	}
	return n
}

// estimateCacheMissCost uses the configured input/cache-read spread, so an
// operator who overrides ARTEX_PRICE_* gets a realistic estimate.
func estimateCacheMissCost(_ *sql.DB, _ string, prefixTokens int) float64 {
	cfg := cost.Default()
	diff := cfg.InputPerMTok - cfg.CacheReadPerMTok
	if diff < 0 {
		diff = 0
	}
	return float64(prefixTokens) / 1_000_000 * diff
}

// ShouldUseShadow deterministically marks ~1/10 of tasks as shadow candidates.
// The phenotype hook does not claim a shadow gene exists; compare still requires
// real shadow samples.
func ShouldUseShadow(taskID int64, geneKey string) bool {
	h := int64(0)
	for _, c := range geneKey {
		h = h*31 + int64(c)
	}
	return (taskID+h)%10 == 0
}
