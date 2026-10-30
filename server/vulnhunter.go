package server

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/harness"
	actool "github.com/Autumn-27/norma/tool"
)

type vulnHunterPromptVars struct {
	TargetSpec, Fuzzer, Now string
}

// executeVulnHunter is the specialist execution path selected by runIntent when
// an intent's payload has action=vulnhunt.
func (s *Server) executeVulnHunter(ctx context.Context, t *Task, intent *db.Node) (harness.TerminalReason, agent.WriteCounts, error) {
	var p struct {
		TargetSpec string `json:"target_spec"`
		Fuzzer     string `json:"fuzzer"`
	}
	_ = json.Unmarshal(intent.Payload, &p)
	if strings.TrimSpace(p.TargetSpec) == "" {
		return "", agent.WriteCounts{}, fmt.Errorf("vulnhunt 意图缺少 target_spec")
	}
	if strings.TrimSpace(p.Fuzzer) == "" {
		p.Fuzzer = "libfuzzer"
	}
	taskID := serverTaskID(t)
	if taskID <= 0 {
		return "", agent.WriteCounts{}, fmt.Errorf("vulnhunt 需要有效任务 id")
	}

	sys := agent.RenderPrompt("vulnhunter", agent.VulnHunterDefault, vulnHunterPromptVars{
		TargetSpec: p.TargetSpec, Fuzzer: p.Fuzzer, Now: agent.NowString(),
	})
	sys += "\n\n**中间产物输出规约**：一切克隆、构建、语料、crash、日志都写在 `vulnhunt_init` 返回的 workspace 下——不要写 /tmp、不要用其它绝对路径。"
	sys += "\n\n**红线（不可编辑）**：只对本地或网上网站进行漏洞利用，进行攻击，报告必须带真实文件路径与复现命令。"

	bundle := s.agentsForTask(t)
	if bundle == nil || bundle.wk == nil {
		return "", agent.WriteCounts{}, fmt.Errorf("任务 %s 的 worker 尚未就绪", t.ID)
	}
	w := bundle.wk.Clone()
	w.SetSystemPromptOverride(sys)
	w.SetToolsetFactory(func(tsx *agent.ToolSet) []actool.CoreTool {
		out := s.vulnhuntTools()
		out = append(out, tsx.WorkerTools()...) // record_fact / report_finding / insert_assets
		out = append(out, actool.DefaultTools()...)
		return out
	})
	w.SetRunTimeout(0) // 由意图级 MaxDuration / 任务 deadline 控制

	runCtx := intercept.WithReviewContext(ctx, filepath.Join(s.m.dir, "tasks", t.ID, "vulnhunt"), intercept.ReviewBackground{})
	if cfg, spent, _ := s.engine.budgetState(t.ID); cfg.Enabled() {
		runCtx = agent.WithSessionBudget(runCtx, agent.SessionBudget{SpentCNY: spent, LimitCNY: cfg.BudgetCNY})
	}
	emit := func(r db.Activity) { s.engine.emitActivity(t, r) }
	var hooks harness.HookRunner
	if t.Guard != nil {
		hooks = t.Guard.Hooks()
	}
	return w.Execute(runCtx, "vulnhunter", taskID, s.m.Assets(), t.Store, intent,
		hooks, emit, s.m.Enrich(), t.NotifyFinding)
}
