package server

// AI-callable self-evolution tools. The tools only expose prompt/skill text and
// proposal lifecycle; Go gates promotion by measured cost. No Go/SQL/guard/scope
// writes are reachable from this surface.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/Autumn-27/artex/agent"
	pgdb "github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

func (s *Server) evolveTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolEvolveLeaks(),
		s.toolEvolveBegin(),
		s.toolEvolveRead(),
		s.toolEvolvePropose(),
		s.toolEvolveTrial(),
		s.toolEvolveCompare(),
		s.toolEvolvePromote(),
		s.toolEvolveAbandon(),
	}
}

func (s *Server) seedEvolveTools() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	workerAgents, _ := json.Marshal([]string{"worker"})
	for _, t := range s.evolveTools() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.PG().SeedTool(t.Name(), t.Description(), schema, workerAgents); err != nil {
			log.Printf("[tools] seed %s 失败: %v", t.Name(), err)
		}
	}
}

func (s *Server) evolveToolsForTask() (*EvolveTools, error) {
	if s.m == nil || s.m.pg == nil {
		return nil, fmt.Errorf("数据库不可用")
	}
	root, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	return &EvolveTools{DB: s.m.pg.DB, RepoRoot: root, DataDir: s.m.dir}, nil
}

func (s *Server) toolEvolveLeaks() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        "evolve_leaks",
		Description: "【自进化·归因】纯 SQL 找烧钱点（低缓存命中/token 膨胀/高成本任务/重复意图/高返工），零 LLM 成本。只说明哪里烧钱，不说明怎么改。",
		Schema:      objSchema(map[string]any{}),
		ReadOnly:    func(json.RawMessage) bool { return true },
		Permissions: sessionPerm,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			t, err := s.evolveToolsForTask()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			out, err := t.EvolveLeaks()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(out), nil
		},
	})
}

func (s *Server) toolEvolveBegin() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        "evolve_begin",
		Description: "【自进化·开始】选最贵的一个 cost leak，建 evolve_run（不调模型），返回 run_id/target/leak。之后用 evolve_read/propose/trial/compare/promote。",
		Schema: objSchema(map[string]any{
			"task_id":   map[string]any{"type": "integer", "description": "可选：任务 id；默认当前 RunInfo.TaskID"},
			"intent_id": map[string]any{"type": "integer", "description": "可选：意图节点 id；默认当前 RunInfo.IntentID"},
		}),
		ReadOnly:    func(json.RawMessage) bool { return false },
		Permissions: sessionPerm,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct {
				TaskID   int64 `json:"task_id"`
				IntentID int64 `json:"intent_id"`
			}
			_ = json.Unmarshal(in, &a)
			ri := agent.RunInfoFrom(ctx)
			if a.TaskID <= 0 {
				a.TaskID = ri.TaskID
			}
			if a.IntentID <= 0 {
				a.IntentID = ri.IntentID
			}
			if a.TaskID <= 0 {
				return actool.Errorf("需要 task_id 或任务上下文"), nil
			}
			// Budget gate: don't spend evolution effort on a task that was too
			// cheap, and keep evolution spend under 5% of the task cost.
			_, spent := s.taskSpend(fmt.Sprint(a.TaskID))
			if spent < 0.5 {
				return actool.Text(`{"status":"skip_too_cheap","reason":"task cost < ¥0.5"}`), nil
			}
			if ok, limit, err := pgdb.EvolutionBudgetOK(s.m.pg.DB, a.TaskID, spent); err != nil {
				return actool.Errorf("进化预算检查失败: " + err.Error()), nil
			} else if !ok {
				return actool.Text(fmt.Sprintf(`{"status":"budget_exceeded","limit_cny":%.4f}`, limit)), nil
			}
			t, err := s.evolveToolsForTask()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			out, err := t.EvolveBegin(a.TaskID, a.IntentID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(out), nil
		},
	})
}

func (s *Server) toolEvolveRead() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        "evolve_read",
		Description: "【自进化·读】只读 agent/prompts/、.agents/skills/、skills/ 下的文本资产（≤64KB）。路径越界拒绝。",
		Schema: objSchema(map[string]any{
			"path": strParam("相对路径，如 agent/prompts/vulnhunter_prompt.md"),
		}, "path"),
		ReadOnly:    func(json.RawMessage) bool { return true },
		Permissions: sessionPerm,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a EvolveReadArgs
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败：" + err.Error()), nil
			}
			t, err := s.evolveToolsForTask()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			out, err := t.EvolveRead(a)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(out), nil
		},
	})
}

func (s *Server) toolEvolvePropose() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        "evolve_propose",
		Description: "【自进化·提案】提交一条最小 prompt/skill 改动提案；必须带 evidence_ids、validation_metric、rollback_condition。只写 evolve_proposals，不改文件。",
		Schema: objSchema(map[string]any{
			"run_id":             map[string]any{"type": "integer", "description": "可选 evolve_run id"},
			"target":             strParam("prompt:<name> 或 skill:<name>"),
			"specific_change":    strParam("最小改动（改一句/删一句/调默认值）"),
			"rationale":          strParam("为什么能省钱/不更差"),
			"evidence_ids":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "来自 evolve_leaks/观察台账的证据 id"},
			"expected_effect":    strParam("预期效果，如 avg_cost_cny 下降"),
			"validation_metric":  strParam("验证指标，默认 avg_cost_cny 下降"),
			"rollback_condition": strParam("回滚条件"),
		}, "target", "specific_change", "rationale", "evidence_ids", "expected_effect", "validation_metric", "rollback_condition"),
		ReadOnly:    func(json.RawMessage) bool { return false },
		Permissions: sessionPerm,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a ProposeArgs
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败：" + err.Error()), nil
			}
			t, err := s.evolveToolsForTask()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			out, err := t.EvolvePropose(a)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(out), nil
		},
	})
}

func (s *Server) toolEvolveTrial() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        "evolve_trial",
		Description: "【自进化·离线验证】对提案跑零 LLM 静态检查：token 增长≤10%、缓存前缀不变、工具提及不增加。必须 confirm=true；不跑真实任务。",
		Schema: objSchema(map[string]any{
			"proposal_id": map[string]any{"type": "integer"},
			"new_content": strParam("改后的完整 prompt/skill 文本"),
			"confirm":     map[string]any{"type": "boolean", "description": "必须 true"},
		}, "proposal_id", "new_content", "confirm"),
		ReadOnly:    func(json.RawMessage) bool { return false },
		Permissions: sessionPerm,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a TrialArgs
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败：" + err.Error()), nil
			}
			t, err := s.evolveToolsForTask()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			out, err := t.EvolveTrial(a)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(out), nil
		},
	})
}

func (s *Server) toolEvolveCompare() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        "evolve_compare",
		Description: "【自进化·成本判定】基线 vs 变体成本档案；样本不足返回 enter_shadow（不伪造样本），通过才把提案标 accepted。判定由 Go 代码做，模型不能宣布 pass。",
		Schema: objSchema(map[string]any{
			"proposal_id":    map[string]any{"type": "integer"},
			"expected_tasks": map[string]any{"type": "integer", "description": "预计后续任务数，默认 20"},
		}, "proposal_id"),
		ReadOnly:    func(json.RawMessage) bool { return false },
		Permissions: sessionPerm,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a CompareArgs
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败：" + err.Error()), nil
			}
			t, err := s.evolveToolsForTask()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			out, err := t.EvolveCompare(a)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(out), nil
		},
	})
}

func (s *Server) toolEvolvePromote() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        "evolve_promote",
		Description: "【自进化·晋升】只对 accepted 提案、且净收益重新核验为正时写回文件；写前备份，写后登记 gene revision、retire 旧版、记 selection 事件。必须 confirm=true。",
		Schema: objSchema(map[string]any{
			"proposal_id": map[string]any{"type": "integer"},
			"new_content": strParam("改后的完整文本"),
			"confirm":     map[string]any{"type": "boolean", "description": "必须 true"},
		}, "proposal_id", "new_content", "confirm"),
		ReadOnly:    func(json.RawMessage) bool { return false },
		Permissions: sessionPerm,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a PromoteArgs
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败：" + err.Error()), nil
			}
			t, err := s.evolveToolsForTask()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			out, err := t.EvolvePromote(a)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(out), nil
		},
	})
}

func (s *Server) toolEvolveAbandon() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        "evolve_abandon",
		Description: "【自进化·放弃】把 proposed/accepted 提案标 retired，并记 retirement 事件；必须给原因。",
		Schema: objSchema(map[string]any{
			"proposal_id": map[string]any{"type": "integer"},
			"reason":      strParam("为什么省不下来/不推进"),
		}, "proposal_id", "reason"),
		ReadOnly:    func(json.RawMessage) bool { return false },
		Permissions: sessionPerm,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a AbandonArgs
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败：" + err.Error()), nil
			}
			t, err := s.evolveToolsForTask()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			out, err := t.EvolveAbandon(a)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(out), nil
		},
	})
}
