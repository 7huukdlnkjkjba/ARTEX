package server

// Pure-SQL cost attribution. This file never calls an LLM; it only answers
// "where is the spend going" so the evolution agent can choose one target.

import (
	"database/sql"
	"fmt"
)

type CostLeak struct {
	Gene    string  `json:"gene"`
	Reason  string  `json:"reason"`
	Value   float64 `json:"value"`
	Detail  string  `json:"detail"`
	TaskIDs []int64 `json:"task_ids,omitempty"`
}

// FindCostLeaks returns partial results even if one rule query fails; the
// evolution path should still be able to act on the remaining signals.
func FindCostLeaks(db *sql.DB) ([]CostLeak, error) {
	if db == nil {
		return nil, fmt.Errorf("nil db")
	}
	var leaks []CostLeak
	seen := map[string]bool{}
	add := func(l CostLeak) {
		key := l.Gene + "|" + l.Reason
		if l.Gene == "" || seen[key] {
			return
		}
		seen[key] = true
		leaks = append(leaks, l)
	}

	// Rule 1: cache hit rate < 50% over the last 7 days.
	rows, err := db.Query(`
		SELECT gene FROM (
		  SELECT jsonb_object_keys(genome_snapshot) AS gene,
		         AVG(CASE WHEN (fitness->>'input_tokens')::float > 0
		                  THEN (fitness->>'cache_read_tokens')::float /
		                       (fitness->>'input_tokens')::float END) AS hit
		  FROM genome_phenotypes
		  WHERE created_at > now() - interval '7 days' AND is_shadow=false
		  GROUP BY gene
		) x WHERE hit IS NOT NULL AND hit < 0.5`)
	if err == nil {
		for rows.Next() {
			var gene string
			if rows.Scan(&gene) == nil {
				add(CostLeak{Gene: gene, Reason: "low_cache_hit", Value: 0.5,
					Detail: "7 天平均缓存命中率 < 50%"})
			}
		}
		rows.Close()
	}

	// Rule 2: average input tokens rose >20% in the last 3 days vs the prior 11.
	rows, err = db.Query(`
		WITH recent AS (
		  SELECT genome_snapshot, AVG((fitness->>'input_tokens')::float) AS tok
		  FROM genome_phenotypes
		  WHERE created_at > now() - interval '3 days' AND is_shadow=false
		  GROUP BY genome_snapshot
		), old AS (
		  SELECT genome_snapshot, AVG((fitness->>'input_tokens')::float) AS tok
		  FROM genome_phenotypes
		  WHERE created_at BETWEEN now() - interval '14 days' AND now() - interval '3 days'
		    AND is_shadow=false
		  GROUP BY genome_snapshot
		)
		SELECT jsonb_object_keys(r.genome_snapshot)
		FROM recent r JOIN old o USING (genome_snapshot)
		WHERE r.tok > o.tok * 1.2`)
	if err == nil {
		for rows.Next() {
			var gene string
			if rows.Scan(&gene) == nil {
				add(CostLeak{Gene: gene, Reason: "token_bloat", Value: 1.2,
					Detail: "近 3 天平均 input tokens 比之前高 20%+"})
			}
		}
		rows.Close()
	}

	// Rule 3: top-cost tasks (>2x average).
	rows, err = db.Query(`
		SELECT task_id, (fitness->>'cost_cny')::float AS cost
		FROM genome_phenotypes
		WHERE is_shadow=false AND (fitness->>'cost_cny')::float >
		  (SELECT AVG((fitness->>'cost_cny')::float) * 2 FROM genome_phenotypes WHERE is_shadow=false)
		ORDER BY cost DESC LIMIT 10`)
	if err == nil {
		var ids []int64
		for rows.Next() {
			var id int64
			var c float64
			if rows.Scan(&id, &c) == nil {
				ids = append(ids, id)
			}
		}
		rows.Close()
		if len(ids) > 0 {
			add(CostLeak{Gene: "worker_pool", Reason: "high_cost_tasks",
				Value: float64(len(ids)), Detail: "单任务成本超过均值 2 倍", TaskIDs: ids})
		}
	}

	// Rule 4: repeated intent summaries >=3 in one task (actual schema has no
	// intent_signature column; payload->>'summary' is the stable key).
	rows, err = db.Query(`
		SELECT t.id, COUNT(*) AS c
		FROM exploration_nodes n
		JOIN tasks t ON t.exploration_id = n.exploration_id
		WHERE n.kind='intent' AND COALESCE(n.state,'') <> 'deleted'
		GROUP BY t.id, n.payload->>'summary'
		HAVING COUNT(*) >= 3
		ORDER BY c DESC LIMIT 10`)
	if err == nil {
		for rows.Next() {
			var taskID int64
			var c int
			if rows.Scan(&taskID, &c) == nil {
				add(CostLeak{Gene: "planner_policy:dedup", Reason: "repeated_intent",
					Value: float64(c), Detail: "同一任务重复派发相同 summary 的意图",
					TaskIDs: []int64{taskID}})
			}
		}
		rows.Close()
	}

	// Rule 5: rework above median.
	rows, err = db.Query(`
		WITH med AS (
		  SELECT PERCENTILE_CONT(0.5) WITHIN GROUP (
		    ORDER BY (fitness->>'rework_count')::float) AS m
		  FROM genome_phenotypes WHERE is_shadow=false
		)
		SELECT task_id, (fitness->>'rework_count')::int
		FROM genome_phenotypes, med
		WHERE is_shadow=false AND (fitness->>'rework_count')::float > m
		ORDER BY (fitness->>'rework_count')::int DESC LIMIT 10`)
	if err == nil {
		for rows.Next() {
			var id int64
			var rc int
			if rows.Scan(&id, &rc) == nil {
				add(CostLeak{Gene: "prompt:worker", Reason: "high_rework",
					Value: float64(rc), Detail: "返工次数高于中位数", TaskIDs: []int64{id}})
			}
		}
		rows.Close()
	}

	return leaks, nil
}
