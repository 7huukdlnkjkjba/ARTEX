package server

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	pgdb "github.com/Autumn-27/artex/db"
)

func TestFindCostLeaksDB(t *testing.T) {
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
	taskID := time.Now().UnixNano()
	snap := map[string]int{"prompt:leak-test": 1}
	raw, _ := json.Marshal(snap)
	fit, _ := json.Marshal(pgdb.Fitness{
		CostCNY: 1.0, InputTokens: 1000, CacheReadTokens: 0, Turns: 5, ReworkCount: 2,
	})
	if _, err := d.Exec(`INSERT INTO genome_phenotypes(task_id, genome_snapshot, fitness, is_shadow)
		VALUES ($1,$2,$3,false)`, taskID, raw, fit); err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM genome_phenotypes WHERE task_id=$1`, taskID)

	leaks, err := FindCostLeaks(d.DB)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, l := range leaks {
		if l.Gene == "prompt:leak-test" && l.Reason == "low_cache_hit" {
			found = true
		}
	}
	if !found {
		t.Fatalf("low_cache_hit not found: %+v", leaks)
	}
}
