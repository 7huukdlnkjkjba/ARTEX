package server

// Task-terminal phenotype sampling. This is deliberately best-effort: a genome
// write failure must never change the task's terminal status.

import (
	"database/sql"
	"fmt"

	pgdb "github.com/Autumn-27/artex/db"
)

// OnTaskFinished records one task phenotype and appends cost-drift events for
// active genes. It performs no model calls.
func OnTaskFinished(conn *sql.DB, taskID int64, taskCostCNY float64,
	outcomeMet bool, coverageDelta float64, rework int, elapsedSec, verificationDepth, turns int,
	inputTokens, cacheReadTokens int64) error {
	if conn == nil || taskID <= 0 {
		return fmt.Errorf("invalid task/db")
	}
	f := pgdb.Fitness{
		OutcomeMet:        outcomeMet,
		CoverageDelta:     coverageDelta,
		ReworkCount:       rework,
		CostCNY:           taskCostCNY,
		ElapsedSec:        elapsedSec,
		VerificationDepth: verificationDepth,
		Turns:             turns,
		InputTokens:       inputTokens,
		CacheReadTokens:   cacheReadTokens,
	}
	// No synthetic shadow: a task is only shadow when an actual shadow revision
	// was used. Phase 1 records the active phenotype.
	if err := pgdb.RecordPhenotype(conn, taskID, f, false); err != nil {
		return err
	}
	genes, _ := pgdb.ActiveGenome(conn)
	for gene := range genes {
		if drifted, ratio, _ := pgdb.DetectCostDrift(conn, gene, 5, 0.2); drifted {
			_ = pgdb.AddEvent(conn, "drift", gene, nil, nil,
				[]string{fmt.Sprintf("cost_drift_ratio=%.3f", ratio)}, nil, 0)
		}
	}
	return nil
}
