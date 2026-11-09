package db

// Genome / self-evolution primitives. The genome is a versioned set of text
// assets (prompts/skills) plus the cost profile of each revision. The AI can
// propose a change; Go decides pass/fail from measured cost, not from the model.

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lib/pq"
)

type GenomeGene struct {
	ID          int64     `json:"id"`
	GeneKey     string    `json:"gene_key"`
	Category    string    `json:"category"` // prompt|skill|param|workflow|planner_policy
	Revision    int       `json:"revision"`
	ContentHash string    `json:"content_hash"`
	ContentRef  string    `json:"content_ref"`
	ParentRev   *int      `json:"parent_rev"`
	Status      string    `json:"status"` // active|shadow|retired|quarantined
	CreatedAt   time.Time `json:"created_at"`
}

type GeneCostProfile struct {
	GeneKey      string  `json:"gene_key"`
	Revision     int     `json:"revision"`
	AvgCostCNY   float64 `json:"avg_cost_cny"`
	SampleCount  int     `json:"sample_count"`
	CacheHitRate float64 `json:"cache_hit_rate"`
	AvgTurns     float64 `json:"avg_turns"`
	AvgInputTok  float64 `json:"avg_input_tok"`
}

const genomeSchema = `
CREATE TABLE IF NOT EXISTS genome_genes (
  id           BIGSERIAL PRIMARY KEY,
  gene_key     TEXT NOT NULL,
  category     TEXT NOT NULL,
  revision     INT NOT NULL,
  content_hash TEXT NOT NULL,
  content_ref  TEXT NOT NULL,
  parent_rev   INT,
  status       TEXT NOT NULL DEFAULT 'active',
  created_at   TIMESTAMPTZ DEFAULT now(),
  UNIQUE(gene_key, revision)
);
CREATE INDEX IF NOT EXISTS idx_genome_genes_key ON genome_genes(gene_key, status);

CREATE TABLE IF NOT EXISTS genome_phenotypes (
  id              BIGSERIAL PRIMARY KEY,
  task_id         BIGINT NOT NULL,
  genome_snapshot JSONB NOT NULL,
  fitness         JSONB NOT NULL,
  is_shadow       BOOLEAN DEFAULT false,
  created_at      TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_genome_phenotypes_task ON genome_phenotypes(task_id);
CREATE INDEX IF NOT EXISTS idx_genome_phenotypes_shadow ON genome_phenotypes(is_shadow, created_at DESC);

CREATE TABLE IF NOT EXISTS genome_events (
  id              BIGSERIAL PRIMARY KEY,
  event_type      TEXT NOT NULL,
  gene_key        TEXT NOT NULL,
  from_rev        INT,
  to_rev          INT,
  evidence        TEXT[],
  proposal_id     BIGINT,
  net_benefit_cny DOUBLE PRECISION,
  created_at      TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_genome_events_key ON genome_events(gene_key, created_at DESC);

CREATE TABLE IF NOT EXISTS evolve_costs (
  id          BIGSERIAL PRIMARY KEY,
  task_id     BIGINT NOT NULL,
  proposal_id BIGINT,
  kind        TEXT NOT NULL,
  cost_cny    DOUBLE PRECISION NOT NULL DEFAULT 0,
  detail      TEXT,
  created_at  TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_evolve_costs_task ON evolve_costs(task_id);
CREATE INDEX IF NOT EXISTS idx_evolve_costs_proposal ON evolve_costs(proposal_id);

CREATE TABLE IF NOT EXISTS evolve_runs (
  id         BIGSERIAL PRIMARY KEY,
  task_id    BIGINT NOT NULL,
  intent_id  BIGINT,
  target     TEXT NOT NULL,
  workspace  TEXT,
  status     TEXT NOT NULL DEFAULT 'analyzing',
  created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_evolve_runs_task ON evolve_runs(task_id);

CREATE TABLE IF NOT EXISTS evolve_proposals (
  id                 BIGSERIAL PRIMARY KEY,
  run_id             BIGINT,
  target             TEXT NOT NULL,
  specific_change    TEXT NOT NULL,
  rationale          TEXT NOT NULL,
  evidence_ids       TEXT[] NOT NULL DEFAULT '{}',
  expected_effect    TEXT NOT NULL,
  validation_metric  TEXT NOT NULL,
  rollback_condition TEXT NOT NULL,
  status             TEXT NOT NULL DEFAULT 'proposed',
  created_at         TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_evolve_proposals_status ON evolve_proposals(status, created_at DESC);

CREATE TABLE IF NOT EXISTS evolve_trials (
  id          BIGSERIAL PRIMARY KEY,
  proposal_id BIGINT NOT NULL,
  fixture     TEXT NOT NULL,
  verdict     TEXT NOT NULL,
  detail      TEXT,
  created_at  TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_evolve_trials_proposal ON evolve_trials(proposal_id);
`

func EnsureGenomeSchema(db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("nil db")
	}
	_, err := db.Exec(genomeSchema)
	return err
}

func HashContent(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func ActiveGenome(db *sql.DB) (map[string]int, error) {
	rows, err := db.Query(`SELECT gene_key, revision FROM genome_genes WHERE status='active'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var k string
		var r int
		if err := rows.Scan(&k, &r); err != nil {
			return nil, err
		}
		out[k] = r
	}
	return out, rows.Err()
}

func CurrentRevision(db *sql.DB, geneKey string) (int, string, error) {
	var rev int
	var status string
	err := db.QueryRow(
		`SELECT revision, status FROM genome_genes WHERE gene_key=$1 ORDER BY revision DESC LIMIT 1`,
		geneKey).Scan(&rev, &status)
	if err == sql.ErrNoRows {
		return 0, "", ErrGeneNotFound
	}
	return rev, status, err
}

func RegisterGeneRevision(db *sql.DB, geneKey, category, contentRef string, content []byte,
	parentRev *int, status string) (*GenomeGene, error) {
	if db == nil {
		return nil, fmt.Errorf("nil db")
	}
	if status == "" {
		status = "active"
	}
	var maxRev sql.NullInt64
	if err := db.QueryRow(`SELECT MAX(revision) FROM genome_genes WHERE gene_key=$1`, geneKey).Scan(&maxRev); err != nil {
		return nil, err
	}
	next := 1
	if maxRev.Valid {
		next = int(maxRev.Int64) + 1
	}
	hash := HashContent(content)
	var id int64
	err := db.QueryRow(
		`INSERT INTO genome_genes (gene_key, category, revision, content_hash, content_ref, parent_rev, status)
		 VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
		geneKey, category, next, hash, contentRef, parentRev, status).Scan(&id)
	if err != nil {
		return nil, err
	}
	return &GenomeGene{ID: id, GeneKey: geneKey, Category: category, Revision: next,
		ContentHash: hash, ContentRef: contentRef, ParentRev: parentRev, Status: status}, nil
}

func RetireGene(db *sql.DB, geneKey string, revision int, evidence []string) error {
	res, err := db.Exec(`UPDATE genome_genes SET status='retired' WHERE gene_key=$1 AND revision=$2`, geneKey, revision)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("gene not found: %s r%d", geneKey, revision)
	}
	_, err = db.Exec(
		`INSERT INTO genome_events (event_type, gene_key, from_rev, evidence) VALUES ('retirement',$1,$2,$3)`,
		geneKey, revision, pq.Array(evidence))
	return err
}

func AddEvent(db *sql.DB, eventType, geneKey string, fromRev, toRev *int,
	evidence []string, proposalID *int64, netBenefit float64) error {
	_, err := db.Exec(
		`INSERT INTO genome_events (event_type, gene_key, from_rev, to_rev, evidence, proposal_id, net_benefit_cny)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		eventType, geneKey, fromRev, toRev, pq.Array(evidence), proposalID, netBenefit)
	return err
}

type Fitness struct {
	OutcomeMet        bool    `json:"outcome_met"`
	CoverageDelta     float64 `json:"coverage_delta"`
	ReworkCount       int     `json:"rework_count"`
	CostCNY           float64 `json:"cost_cny"`
	ElapsedSec        int     `json:"elapsed_sec"`
	VerificationDepth int     `json:"verification_depth"`
	InputTokens       int64   `json:"input_tokens"`
	CacheReadTokens   int64   `json:"cache_read_tokens"`
	Turns             int     `json:"turns"`
}

func (f Fitness) CacheHitRate() float64 {
	if f.InputTokens <= 0 {
		return 0
	}
	return float64(f.CacheReadTokens) / float64(f.InputTokens)
}

func RecordPhenotype(db *sql.DB, taskID int64, fitness Fitness, isShadow bool) error {
	genome, err := ActiveGenome(db)
	if err != nil {
		return err
	}
	snap, _ := json.Marshal(genome)
	fit, _ := json.Marshal(fitness)
	_, err = db.Exec(
		`INSERT INTO genome_phenotypes (task_id, genome_snapshot, fitness, is_shadow) VALUES ($1,$2,$3,$4)`,
		taskID, snap, fit, isShadow)
	return err
}

func GeneCostProfileOf(db *sql.DB, geneKey string, revision, limit int) (GeneCostProfile, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := db.Query(`
		SELECT fitness FROM genome_phenotypes
		WHERE genome_snapshot->>$1 = $2 AND is_shadow=false
		ORDER BY created_at DESC LIMIT $3`,
		geneKey, fmt.Sprint(revision), limit)
	if err != nil {
		return GeneCostProfile{}, err
	}
	defer rows.Close()
	p := GeneCostProfile{GeneKey: geneKey, Revision: revision}
	var n int
	var sumCost, sumHit, sumTurns, sumInput float64
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return p, err
		}
		var f Fitness
		if json.Unmarshal(raw, &f) != nil {
			continue
		}
		n++
		sumCost += f.CostCNY
		sumHit += f.CacheHitRate()
		sumTurns += float64(f.Turns)
		sumInput += float64(f.InputTokens)
	}
	if n > 0 {
		p.SampleCount = n
		p.AvgCostCNY = sumCost / float64(n)
		p.CacheHitRate = sumHit / float64(n)
		p.AvgTurns = sumTurns / float64(n)
		p.AvgInputTok = sumInput / float64(n)
	}
	return p, rows.Err()
}

// NetBenefitPositive: saving = (old - new) * expected tasks; only > evolution cost.
func NetBenefitPositive(oldCost, newCost float64, expectedTasks int, evolutionCost float64) bool {
	saving := (oldCost - newCost) * float64(expectedTasks)
	return saving > evolutionCost
}

// CostAwareVerdict is the cost-first gate; it never accepts a variant that is
// more expensive, loses >10% cache hit rate, or adds turns.
func CostAwareVerdict(baseline, variant GeneCostProfile, expectedTasks int,
	evolutionCost float64) (string, float64) {
	if baseline.SampleCount < 3 || variant.SampleCount < 1 {
		return "inconclusive", 0
	}
	if variant.AvgCostCNY > baseline.AvgCostCNY*1.05 {
		return "fail", 0
	}
	if variant.CacheHitRate < baseline.CacheHitRate*0.9 {
		return "fail", 0
	}
	if variant.AvgTurns > baseline.AvgTurns*1.05 {
		return "fail", 0
	}
	saving := (baseline.AvgCostCNY - variant.AvgCostCNY) * float64(expectedTasks)
	net := saving - evolutionCost
	if net <= 0 {
		return "inconclusive", net
	}
	return "pass", net
}

func DetectCostDrift(db *sql.DB, geneKey string, window int, threshold float64) (bool, float64, error) {
	if window <= 0 {
		window = 5
	}
	rows, err := db.Query(`
		SELECT fitness FROM genome_phenotypes
		WHERE genome_snapshot->>$1 IS NOT NULL AND is_shadow=false
		ORDER BY created_at DESC LIMIT $2`, geneKey, window*2)
	if err != nil {
		return false, 0, err
	}
	defer rows.Close()
	var costs []float64
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return false, 0, err
		}
		var f Fitness
		if json.Unmarshal(raw, &f) == nil {
			costs = append(costs, f.CostCNY)
		}
	}
	if len(costs) < window*2 {
		return false, 0, nil
	}
	recent := avg(costs[:window])
	historical := avg(costs[window:])
	if historical <= 0 {
		return false, 0, nil
	}
	ratio := recent / historical
	return ratio > 1+threshold, ratio, nil
}

func avg(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	var s float64
	for _, x := range xs {
		s += x
	}
	return s / float64(len(xs))
}

// EvolutionBudgetOK: evolution spend must stay under 5% of the task cost.
func EvolutionBudgetOK(db *sql.DB, taskID int64, taskCostCNY float64) (bool, float64, error) {
	var spent float64
	err := db.QueryRow(`SELECT COALESCE(SUM(cost_cny),0) FROM evolve_costs WHERE task_id=$1`, taskID).Scan(&spent)
	if err != nil {
		return false, 0, err
	}
	limit := taskCostCNY * 0.05
	return spent <= limit, limit, nil
}

func RecordEvolutionCost(db *sql.DB, taskID int64, proposalID *int64, kind string, cost float64, detail string) error {
	_, err := db.Exec(
		`INSERT INTO evolve_costs (task_id, proposal_id, kind, cost_cny, detail) VALUES ($1,$2,$3,$4,$5)`,
		taskID, proposalID, kind, cost, detail)
	return err
}

var ErrGeneNotFound = fmt.Errorf("gene not found")
