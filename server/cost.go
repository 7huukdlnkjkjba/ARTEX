package server

import (
	"fmt"
	"iter"
	"math"

	"github.com/Autumn-27/artex/cost"
	"github.com/Autumn-27/norma/llm"
)

// Session cost control (¥): one vulnerability-hunting session (a task) gets a
// money budget, default ¥6 at DeepSeek list price. Spend is computed from the
// always-on llm_usage ledger, so it is accurate across agent lanes, pool
// rotation/failover and interrupted runs.
//
// Two enforcement points cooperate:
//  1. the engine gate (plannerLoop / workerLoop) stops *new* work at the cap and
//     folds the task into a graceful pause after the in-flight runs drain;
//  2. the provider wrapper below stops *in-flight* runs at the next model call by
//     returning a local "budget exhausted" completion. That call spends nothing,
//     and the run ends as a normal text-only turn (the design already writes
//     findings back incrementally, so nothing is lost in the model's head).
//
// Both are needed: without (2) a single long worker could overshoot the budget by
// many yuan before its turn budget ran out; without (1) the task would keep
// waking the planner and creating zero-cost no-op rounds forever.

// costConfig resolves the live price table + budget. Called per check (a few
// indexed settings reads) so a settings change applies to the next call.
func (s *Server) costConfig() cost.Config {
	if s == nil || s.m == nil {
		return cost.Default()
	}
	return cost.Load(s.m.pg)
}

// taskSpend returns the task's resolved config and its CNY spend so far.
func (s *Server) taskSpend(taskID string) (cost.Config, float64) {
	cfg := s.costConfig()
	if !cfg.Enabled() || taskID == "" || s.m == nil || s.m.pg == nil {
		return cfg, 0
	}
	totals, err := s.m.pg.TaskTokenTotals(taskID)
	if err != nil {
		return cfg, 0
	}
	return cfg, cfg.Spend(totals)
}

// budgetStop reports whether this task has used up its session budget, and if so
// asks the engine to start the graceful stop. The returned text is what the model
// "sees" as its own final answer.
func (s *Server) budgetStop(taskID string) (bool, string) {
	cfg, spent := s.taskSpend(taskID)
	if !cfg.Enabled() || spent < cfg.BudgetCNY {
		return false, ""
	}
	if s.engine != nil {
		s.engine.BudgetReached(taskID)
	}
	return true, fmt.Sprintf(
		"【本次会话预算已用尽】本次会话的模型花费已达 ¥%.2f 上限（当前约 ¥%.2f）。系统已停止新的模型调用：本次运行到此结束，已经写回的事实、资产和漏洞全部保留。",
		cfg.BudgetCNY, spent)
}

// budgetStopStream renders the local stop as a normal assistant turn so the
// harness ends the run on a clean end_turn instead of a provider error (which
// would trigger retries and mark the intent blocked).
func budgetStopStream(text string) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		if !yield(llm.StreamEvent{Type: llm.SEMessageStart}, nil) {
			return
		}
		if !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: text}, nil) {
			return
		}
		if !yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn"}, nil) {
			return
		}
		yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
	}
}

// budgetStopMessage is the non-streaming counterpart of budgetStopStream.
func budgetStopMessage(text string) (llm.Message, string, llm.Usage, error) {
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(text)}},
		"end_turn", llm.Usage{}, nil
}

// roundCNY rounds to fen for display, so the UI never shows 5.999999.
func roundCNY(v float64) float64 { return math.Round(v*100) / 100 }
