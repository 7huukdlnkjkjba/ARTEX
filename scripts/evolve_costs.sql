-- Self-evolution accounting. Read-only operational queries.

-- Per gene revision: average cost, cache hit rate, sample count.
SELECT gene_key, revision, status,
       AVG((fitness->>'cost_cny')::float) AS avg_cost,
       AVG((fitness->>'cache_read_tokens')::float /
           NULLIF((fitness->>'input_tokens')::float, 0)) AS cache_hit,
       COUNT(*) AS samples
FROM genome_genes g
LEFT JOIN genome_phenotypes p
  ON p.genome_snapshot->>g.gene_key = g.revision::text
GROUP BY gene_key, revision, status
ORDER BY avg_cost DESC NULLS LAST;

-- Evolution spend vs task spend (task spend uses the same token price table,
-- so this is a proportional view, not an absolute invoice).
SELECT
  (SELECT COALESCE(SUM(cost_cny), 0) FROM evolve_costs) AS evolution_spent,
  (SELECT COALESCE(SUM(
       ((input_tokens - cache_read) * 2.0
        + cache_read * 0.5
        + output_tokens * 8.0) / 1000000.0), 0)
     FROM llm_usage) AS task_spent_approx,
  ROUND(
    (SELECT COALESCE(SUM(cost_cny), 0) FROM evolve_costs) /
    NULLIF((SELECT COALESCE(SUM(
       ((input_tokens - cache_read) * 2.0
        + cache_read * 0.5
        + output_tokens * 8.0) / 1000000.0), 0)
     FROM llm_usage), 0) * 100, 2) AS evolution_pct;
