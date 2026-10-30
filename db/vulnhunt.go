package db

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// VulnHunter run lifecycle states.
const (
	VHRunClone    = "clone"
	VHRunBuilding = "building"
	VHRunFuzzing  = "fuzzing"
	VHRunTriaging = "triaging"
	VHRunDone     = "done"
	VHRunFailed   = "failed"
)

type VulnHuntRun struct {
	ID          int64
	TaskID      int64
	IntentID    *int64
	TargetSpec  string // repo:URL@commit | binary:/path | api:URL
	Fuzzer      string // libfuzzer | aflpp | http_fuzz
	Workspace   string
	Status      string
	DurationSec int
	CrashCount  int
	UniqueCount int
	LastError   string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type VulnHuntCrash struct {
	ID            int64
	RunID         int64
	Signature     string
	Kind          string
	Stack         string
	PocPath       string
	MinimizedPath string
	DuplicateOf   *int64
	FindingID     *int64
	CreatedAt     time.Time
}

type VulnHuntStore struct{ db *DB }

func NewVulnHuntStore(db *DB) *VulnHuntStore { return &VulnHuntStore{db: db} }

func (s *VulnHuntStore) EnsureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS vulnhunt_runs (
  id BIGSERIAL PRIMARY KEY,
  task_id BIGINT NOT NULL,
  intent_id BIGINT,
  target_spec TEXT NOT NULL,
  fuzzer TEXT NOT NULL,
  workspace TEXT NOT NULL,
  status TEXT NOT NULL,
  duration_sec INT NOT NULL DEFAULT 0,
  crash_count INT NOT NULL DEFAULT 0,
  unique_count INT NOT NULL DEFAULT 0,
  last_error TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_vhr_task ON vulnhunt_runs(task_id, status);
CREATE TABLE IF NOT EXISTS vulnhunt_crashes (
  id BIGSERIAL PRIMARY KEY,
  run_id BIGINT NOT NULL REFERENCES vulnhunt_runs(id) ON DELETE CASCADE,
  signature TEXT NOT NULL,
  kind TEXT NOT NULL,
  stack TEXT NOT NULL,
  poc_path TEXT NOT NULL,
  minimized_path TEXT NOT NULL DEFAULT '',
  duplicate_of BIGINT,
  finding_id BIGINT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_vhr_sig ON vulnhunt_crashes(run_id, signature);
`)
	return err
}

func (s *VulnHuntStore) CreateRun(ctx context.Context, r *VulnHuntRun) (int64, error) {
	if r.TaskID <= 0 || r.TargetSpec == "" || r.Fuzzer == "" || r.Workspace == "" {
		return 0, errors.New("vulnhunt run: task_id/target_spec/fuzzer/workspace required")
	}
	if r.Status == "" {
		r.Status = VHRunClone
	}
	var id int64
	err := s.db.QueryRowContext(ctx, `
INSERT INTO vulnhunt_runs(task_id,intent_id,target_spec,fuzzer,workspace,status,duration_sec)
VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
		r.TaskID, r.IntentID, r.TargetSpec, r.Fuzzer, r.Workspace, r.Status, r.DurationSec).Scan(&id)
	return id, err
}

// SetWorkspace binds a run to its final workspace. Runs are inserted before the
// workspace path (which embeds the run id) is known, so init creates the row with
// a placeholder and fixes it immediately afterwards.
func (s *VulnHuntStore) SetWorkspace(ctx context.Context, id int64, workspace string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE vulnhunt_runs SET workspace=$2,updated_at=now() WHERE id=$1`, id, workspace)
	return err
}

func (s *VulnHuntStore) SetRunStatus(ctx context.Context, id int64, status, lastErr string, crashes, unique int) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE vulnhunt_runs SET status=$2,last_error=$3,crash_count=$4,unique_count=$5,updated_at=now() WHERE id=$1`,
		id, status, lastErr, crashes, unique)
	return err
}

const vhRunCols = `id,task_id,intent_id,target_spec,fuzzer,workspace,status,duration_sec,crash_count,unique_count,last_error,created_at,updated_at`

func scanVHRun(row interface{ Scan(...any) error }) (*VulnHuntRun, error) {
	r := &VulnHuntRun{}
	err := row.Scan(&r.ID, &r.TaskID, &r.IntentID, &r.TargetSpec, &r.Fuzzer, &r.Workspace, &r.Status,
		&r.DurationSec, &r.CrashCount, &r.UniqueCount, &r.LastError, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (s *VulnHuntStore) GetRun(ctx context.Context, id int64) (*VulnHuntRun, error) {
	return scanVHRun(s.db.QueryRowContext(ctx, `SELECT `+vhRunCols+` FROM vulnhunt_runs WHERE id=$1`, id))
}

func (s *VulnHuntStore) LatestRunForIntent(ctx context.Context, taskID, intentID int64) (*VulnHuntRun, error) {
	return scanVHRun(s.db.QueryRowContext(ctx, `SELECT `+vhRunCols+` FROM vulnhunt_runs
WHERE task_id=$1 AND intent_id=$2 ORDER BY id DESC LIMIT 1`, taskID, intentID))
}

func (s *VulnHuntStore) AddCrash(ctx context.Context, c *VulnHuntCrash) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `
INSERT INTO vulnhunt_crashes(run_id,signature,kind,stack,poc_path,minimized_path,duplicate_of,finding_id)
VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
		c.RunID, c.Signature, c.Kind, c.Stack, c.PocPath, c.MinimizedPath, c.DuplicateOf, c.FindingID).Scan(&id)
	return id, err
}

func (s *VulnHuntStore) MarkDuplicate(ctx context.Context, id int64, duplicateOf int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE vulnhunt_crashes SET duplicate_of=$2 WHERE id=$1`, id, duplicateOf)
	return err
}

func (s *VulnHuntStore) AttachFinding(ctx context.Context, id, findingID int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE vulnhunt_crashes SET finding_id=$2 WHERE id=$1`, id, findingID)
	return err
}

func (s *VulnHuntStore) ListCrashes(ctx context.Context, runID int64) ([]*VulnHuntCrash, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,run_id,signature,kind,stack,poc_path,minimized_path,duplicate_of,finding_id,created_at
FROM vulnhunt_crashes WHERE run_id=$1 ORDER BY id`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*VulnHuntCrash
	for rows.Next() {
		c := &VulnHuntCrash{}
		if err := rows.Scan(&c.ID, &c.RunID, &c.Signature, &c.Kind, &c.Stack, &c.PocPath,
			&c.MinimizedPath, &c.DuplicateOf, &c.FindingID, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SignatureExists returns the id of the first crash with this signature, or 0.
func (s *VulnHuntStore) SignatureExists(ctx context.Context, runID int64, sig string) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `SELECT id FROM vulnhunt_crashes WHERE run_id=$1 AND signature=$2`, runID, sig).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return id, err
}

// CrashByPath resolves a crash by either its original or minimized PoC path.
func (s *VulnHuntStore) CrashByPath(ctx context.Context, runID int64, path string) (*VulnHuntCrash, error) {
	rows, err := s.ListCrashes(ctx, runID)
	if err != nil {
		return nil, err
	}
	for _, c := range rows {
		if c.PocPath == path || (c.MinimizedPath != "" && c.MinimizedPath == path) {
			return c, nil
		}
	}
	return nil, nil
}
