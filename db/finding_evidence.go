package db

import (
	"encoding/json"
	"strconv"
)

// 本文件只提供「证据闸门」用到的两条只读查询：从一个 finding 出发，取回它关联的
// 意图以及这些意图产出的 fact/hint。msf 自动派单前要先判断该漏洞是否已经有可复现
// 证据，旧逻辑只能看 finding 自身的 summary/evidence，无法感知 exploit_verify /
// exploit_author 的执行结果，所以补上这两条按 finding 反查的入口。

// IntentsByFinding 返回所有指向该 finding 的意图（含已终止的）。自动派单的两条
// 路径写的锚字段不同——Metasploit 用 msf_finding_id，通用 Exploit Author 用
// finding_id（与 HasActiveIntentForFinding 的判据一致），两条都要查，否则闸门会
// 漏掉另一半证据。
//
// 每条结果是指令 payload 合并上 id / status（节点 state）后的 map：调用方按
// action 判类型、按 status 判成败，不必再自己解 payload。
func (s *ExplorationStore) IntentsByFinding(findingID int64) ([]map[string]any, error) {
	if findingID <= 0 {
		return nil, nil
	}
	rows, err := s.db.Query(`SELECT id, state, payload FROM exploration_nodes
WHERE exploration_id = $1 AND kind = 'intent'
  AND (payload->>'msf_finding_id' = $2 OR payload->>'finding_id' = $2)
ORDER BY id`, s.expID, strconv.FormatInt(findingID, 10))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []map[string]any
	for rows.Next() {
		var (
			id    int64
			state string
			raw   []byte
		)
		if err := rows.Scan(&id, &state, &raw); err != nil {
			return nil, err
		}
		item := map[string]any{}
		if len(raw) > 0 {
			// payload 是历史数据，解析失败不应让整次查询失败：只保留 id/status。
			_ = json.Unmarshal(raw, &item)
		}
		item["id"] = id
		item["status"] = state
		item["state"] = state
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// NodesByFinding 返回该 finding 关联意图「产出」的 fact/hint 节点（intent --yields-->
// fact）。闸门要在这些节点里找「已验证 / 拿到回显」这类显式标记，因为它比
// finding 自己的 summary 更接近一次真实复现。
//
// 每条结果合并了 payload 的键，并把 summary + detail 拼成 text 供调用方直接扫描。
func (s *ExplorationStore) NodesByFinding(findingID int64) ([]map[string]any, error) {
	if findingID <= 0 {
		return nil, nil
	}
	rows, err := s.db.Query(`SELECT n.id, n.kind, n.state, n.payload
FROM exploration_nodes n
WHERE n.exploration_id = $1 AND n.kind IN ('fact', 'hint')
  AND n.id IN (
    SELECT e.dst_id
    FROM exploration_edges e
    JOIN exploration_nodes i ON i.id = e.src_id AND i.exploration_id = e.exploration_id
    WHERE e.exploration_id = $1 AND e.rel = $3 AND i.kind = 'intent'
      AND (i.payload->>'msf_finding_id' = $2 OR i.payload->>'finding_id' = $2)
  )
ORDER BY n.id`, s.expID, strconv.FormatInt(findingID, 10), RelYields)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []map[string]any
	for rows.Next() {
		var (
			id    int64
			kind  string
			state string
			raw   []byte
		)
		if err := rows.Scan(&id, &kind, &state, &raw); err != nil {
			return nil, err
		}
		item := map[string]any{}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &item)
		}
		summary, _ := item["summary"].(string)
		detail, _ := item["detail"].(string)
		if text, ok := item["text"].(string); ok && text != "" {
			summary = text
		}
		item["text"] = summary + "\n" + detail
		item["id"] = id
		item["kind"] = kind
		item["state"] = state
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
