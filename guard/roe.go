package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strings"

	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/hook"
)

type RoEConfig struct {
	Mode     func() string
	Scope    func(taskID int64) []ScopeRule
	TaskIDOf func(ctx context.Context) int64
}

func (g *Guard) SetRoE(cfg RoEConfig) {
	g.mu.Lock()
	g.roe = cfg
	g.mu.Unlock()
}

func (c RoEConfig) mode() string {
	if c.Mode == nil {
		return "warn"
	}
	switch strings.ToLower(strings.TrimSpace(c.Mode())) {
	case "off":
		return "off"
	case "strict":
		return "strict"
	default:
		return "warn"
	}
}

func (g *Guard) checkRoE(ctx context.Context, ev hook.Event, cmd string) (hook.Result, bool) {
	g.mu.Lock()
	cfg := g.roe
	g.mu.Unlock()
	if cfg.Scope == nil {
		return hook.Result{}, false
	}
	mode := cfg.mode()
	if mode == "off" {
		return hook.Result{}, false
	}
	var taskID int64
	if cfg.TaskIDOf != nil {
		taskID = cfg.TaskIDOf(ctx)
	}
	if taskID <= 0 {
		return hook.Result{}, false
	}
	hosts := roeHosts(ev.ToolName, ev.Input, cmd)
	if len(hosts) == 0 {
		return hook.Result{}, false
	}
	matcher := NewScopeMatcher(cfg.Scope(taskID))
	var out []string
	unknown := false
	for _, h := range hosts {
		switch matcher.Check(h) {
		case ScopeOut:
			out = append(out, h)
		case ScopeUnknown:
			unknown = true
		}
	}
	if len(out) == 0 {
		return hook.Result{}, false
	}
	if unknown {
		log.Printf("[guard][roe] task %d 部分目标无范围规则可依: %v", taskID, hosts)
	}
	reason := roeMessage(out, cfg.Scope(taskID))
	if mode == "strict" {
		return g.roeAsk(ctx, ev, reason)
	}
	g.record(ev.ToolName, "allow", reason, cmd)
	log.Printf("[guard][roe] task %d 范围外目标(warn 放行): %s", taskID, reason)
	return hook.Result{}, false
}

func (g *Guard) roeAsk(ctx context.Context, ev hook.Event, reason string) (hook.Result, bool) {
	if g.interceptor == nil {
		return g.block(ev.ToolName, systemBlockMessage(reason), ""), true
	}
	if ctx.Err() != nil {
		return g.block(ev.ToolName, systemBlockMessage("工作已取消，平台安全管控阻止执行"), ""), true
	}
	dec := intercept.Decision{Action: "ask", RuleName: "内置 RoE 范围强制", Message: reason}
	convID := intercept.ConvIDFromContext(ctx)
	if !g.interceptor.HandleAsk(ctx, convID, dec, ev.ToolName, ev.Input) {
		return g.block(ev.ToolName, systemBlockMessage("RoE 范围外目标，人工审批未通过（用户拒绝或审批超时）"), ""), true
	}
	g.interceptor.Log(ctx, convID, dec, ev.ToolName, ev.Input, "allowed")
	return hook.Result{}, false
}

func roeMessage(out []string, rules []ScopeRule) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "RoE 授权范围检查:目标 %s 不在本任务已登记范围内", strings.Join(out, ", "))
	if len(rules) > 0 {
		parts := make([]string, 0, len(rules))
		for _, r := range rules {
			parts = append(parts, r.Kind+"="+r.Value)
		}
		fmt.Fprintf(&sb, "（登记范围: %s）", strings.Join(parts, ", "))
	}
	sb.WriteString("。如需放行:把目标加入任务范围(add_task_scope),或在系统设置把 roe_enforcement 改为 warn(仅告警)/off(关闭)。")
	return sb.String()
}

func roeHosts(toolName string, input []byte, cmd string) []string {
	if cmd != "" {
		return ExtractHosts(cmd)
	}
	if toolName == "WebFetch" {
		var in struct {
			URL string `json:"url"`
		}
		if json.Unmarshal(input, &in) == nil && in.URL != "" {
			if u, err := url.Parse(in.URL); err == nil && u.Hostname() != "" {
				return []string{u.Hostname()}
			}
		}
	}
	return nil
}
