package server

// 漏洞挖掘自研闭环（v0.3.26 形态）。
//
// 与 v0.3.23 的通用自研（agent/selfevolve.go：打不动就 skill_draft → skill_test →
// skill_promote）相比，vuln_miner 把「造工具」升级为「先取证、再造工具」：
//
//	触发（引擎）：意图 blocked/exhausted 且失败文本/近期 finding 命中 WAF、源码泄露、
//	              逻辑报错等信号 → 派 action=vuln_miner 意图（每任务最多 1 条）。
//	取证（worker）：web_audit 抓前端资源 / audit_source 做 Source→Sink / ghidra_decompile
//	              出伪代码；只对「可控 source + 危险 sink + 可达」的链路动手。
//	造工具：       skill_draft 写自包含 EXP（含基线 vs 绕过差异验证）→ skill_test 真跑
//	              → skill_promote 固化为 sk_waf_bypass_<target> 之类工具。
//	复用：        晋升后的工具行绑定 worker，下一个意图 AugmentTools 重建工具集时即可见；
//	              同时写 fact/hint 告诉后续 worker「直接调用，不要重写脚本」。
//
// 证据纪律：没有真实回显不晋升；晋升后回查 tools 表确认可用；失败也要写 fact 收口。

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/harness"
	actool "github.com/Autumn-27/norma/tool"
)

const (
	vulnMinerAction     = "vuln_miner"
	vulnMinerMaxPerTask = 1
	vulnMinerPriority   = 9
)

// vulnMinerEnabled 默认开；ARTEX_VULN_MINER=off 关闭（与 ARTEX_SELF_EVOLVE 独立）。
func vulnMinerEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ARTEX_VULN_MINER"))) {
	case "off", "0", "false", "no":
		return false
	}
	return true
}

// intentIsVulnMiner 判断意图是否 vuln_miner。
func intentIsVulnMiner(intent *db.Node) bool {
	if intent == nil || len(intent.Payload) == 0 {
		return false
	}
	var p struct {
		Action string `json:"action"`
	}
	if json.Unmarshal(intent.Payload, &p) != nil {
		return false
	}
	return p.Action == vulnMinerAction
}

// ---------- 触发信号 ----------

type vulnMinerSignalRule struct {
	Reason string
	Words  []string
}

// 顺序即优先级：先 WAF，再源码泄露，最后逻辑报错。
var vulnMinerSignalRules = []vulnMinerSignalRule{
	{"waf_bypass", []string{
		"waf", "cloudflare", "akamai", "modsecurity", "imperva", "safedog", "安全狗", "宝塔", "长亭",
		"拦截", "intercept", "blocked", "403 forbidden", "access denied", "challenge", "captcha",
		"anti-bot", "机器人验证", "js challenge",
	}},
	{"source_exposure", []string{
		"source-to-sink", "sourcemap", ".map", "bundle", "chunk.js", "混淆", "obfuscat",
		"源码泄露", "源码暴露", "js 源码", "前端源码", "未授权访问源码",
	}},
	{"logic_flaw", []string{
		"confusing_error", "unhandled_type", "stack trace", "stacktrace", "debug=true",
		"逻辑漏洞", "类型混淆", "报错泄露",
	}},
}

// classifyVulnMinerSignal 是所有文本拼接后按关键词判型；空字符串表示不触发。
func classifyVulnMinerSignal(texts ...string) string {
	var b strings.Builder
	for _, t := range texts {
		if t != "" {
			b.WriteString(t)
			b.WriteByte('\n')
		}
	}
	hay := strings.ToLower(b.String())
	for _, rule := range vulnMinerSignalRules {
		for _, w := range rule.Words {
			if strings.Contains(hay, strings.ToLower(w)) {
				return rule.Reason
			}
		}
	}
	return ""
}

// vulnMinerSkillName 生成确定性的技能名：晋升后工具 key = sk_<skill>。
// 例：https://shop.example.com/x.js + waf_bypass → waf_bypass_shop_example_com
func vulnMinerSkillName(target, reason string) string {
	prefix := "waf_bypass_"
	switch reason {
	case "source_exposure":
		prefix = "src_exp_"
	case "logic_flaw":
		prefix = "logic_exp_"
	}
	host := strings.TrimSpace(target)
	if h, err := auditURLHost(host); err == nil {
		host = h
	}
	slug := strings.ToLower(host)
	slug = reVulnMinerSlug.ReplaceAllString(slug, "_")
	slug = strings.Trim(slug, "_")
	if slug == "" {
		slug = "target"
	}
	if max := 64 - len(prefix); len(slug) > max {
		slug = strings.Trim(slug[:max], "_")
	}
	return prefix + slug
}

var reVulnMinerSlug = regexp.MustCompile(`[^a-z0-9]+`)

// vulnMinerQueueAllowed 是触发闸门（纯函数，便于单测）：只对失败收场、至少失败过
// 一次、本任务尚未派过挖掘意图、且信号判型非空的情况放行。
func vulnMinerQueueAllowed(state string, fails, dispatched int, reason string) bool {
	if state != "blocked" && state != "exhausted" {
		return false
	}
	if fails < 1 || dispatched >= vulnMinerMaxPerTask {
		return false
	}
	return reason != ""
}

// ---------- 引擎侧触发 ----------

// maybeQueueVulnMiner 在意图失败收场时判断是否升级为 vuln_miner；返回 true 表示
// 已派发，调用方不应再派通用 self_evolve（避免同一失败连派两条自研）。
func (e *Engine) maybeQueueVulnMiner(t *Task, intent *db.Node, state string, runErr error) bool {
	if t == nil || t.Store == nil || intent == nil {
		return false
	}
	if !agent.SelfEvolveEnabled() || !vulnMinerEnabled() {
		return false
	}
	if state != "blocked" && state != "exhausted" {
		return false
	}
	if intentIsVulnMiner(intent) {
		return false // 挖掘意图自己失败也要收口，不再递归
	}
	fails, err := t.Store.CountUnsuccessfulIntents()
	if err != nil {
		return false
	}
	dispatched, err := t.Store.CountIntentsByAction(vulnMinerAction)
	if err != nil {
		return false
	}
	target := intentTargetText(intent)
	errText := ""
	if runErr != nil {
		errText = runErr.Error()
	}
	findingText, findingTarget, findingEvidence := e.taskFindingDigest(t.ID, 20)
	if u := firstURLInText(target); u != "" {
		target = u // summary 里的 URL 比整句摘要更适合做目标与技能名
	}
	if target == "" || target == "当前目标" {
		if findingTarget != "" {
			target = findingTarget
		}
	}
	if target == "" || target == "当前目标" {
		return false // 没有可操作目标：交给通用 self_evolve，别浪费唯一的挖掘配额
	}
	reason := classifyVulnMinerSignal(target, string(intent.Payload), errText, findingText)
	if !vulnMinerQueueAllowed(state, fails, dispatched, reason) {
		return false
	}
	evidence := strings.TrimSpace(findingEvidence)
	if evidence == "" {
		evidence = vulnMinerTruncate(strings.TrimSpace(errText), 1200)
	}
	skill := vulnMinerSkillName(target, reason)
	toolKey := skillToolKey(skill)
	if toolKey == "" {
		toolKey = "sk_" + strings.ReplaceAll(skill, "-", "_")
	}
	anchors, _ := t.Store.Anchors(intent.ID)
	id, err := t.Store.AddIntent(vulnMinerIntentPayload(target, reason, skill, errText, evidence, anchors), vulnMinerPriority, anchors, "vuln-miner")
	if err != nil {
		log.Printf("[vuln-miner] task %s 派发挖掘意图失败: %v", t.ID, err)
		return false
	}
	log.Printf("[vuln-miner] task %s 意图 #%d 失败(%s, %s) → 派发挖掘意图 #%d (target=%s, skill=%s)",
		t.ID, intent.ID, state, reason, id, target, skill)
	e.emitActivity(t, db.Activity{
		Worker:  "system",
		Kind:    "system",
		Summary: fmt.Sprintf("【漏洞挖掘】意图 #%d 以 %s 收场（信号 %s），派发挖掘意图 #%d：%s", intent.ID, state, reason, id, target),
		Detail:  vulnMinerTruncate(errText, 500),
	})
	if _, err := t.Store.AddNode(db.KindHint, map[string]any{
		"text": fmt.Sprintf("【漏洞挖掘触发】意图 #%d 因 %s 失败。平台已派发 vuln_miner 意图 #%d（目标 %s，预期工具 %s）："+
			"它会拉源码做 Source→Sink 取证并现场造工具。规划时不要再排同目标同参数的重复探测；等它产出工具或 fact 收口。",
			intent.ID, reason, id, target, toolKey),
		"auto": "vuln-miner",
	}, 0, "active", "system", nil); err != nil {
		log.Printf("[vuln-miner] task %s 写触发 hint 失败: %v", t.ID, err)
	}
	return true
}

// vulnMinerIntentPayload 是派发契约：executeVulnMiner 只认 target/reason/skill/evidence，
// planner 与后续 worker 读 summary/instruction。抽成纯函数便于单测字段稳定性。
func vulnMinerIntentPayload(target, reason, skill, errText, evidence string, anchors []int64) map[string]any {
	toolKey := skillToolKey(skill)
	if toolKey == "" {
		toolKey = "sk_" + strings.ReplaceAll(skill, "-", "_")
	}
	return map[string]any{
		"summary": fmt.Sprintf("【漏洞挖掘】%s：先 web_audit/audit_source 取证，找到可控 Source→Sink 后现场写绕过 EXP，"+
			"skill_test 真跑验证，再 skill_promote 固化为 %s 工具交给后续 worker", target, toolKey),
		"action":      vulnMinerAction,
		"target":      target,
		"reason":      reason,
		"skill":       skill,
		"evidence":    vulnMinerTruncate(strings.TrimSpace(evidence), 1200),
		"fail_reason": vulnMinerTruncate(strings.TrimSpace(errText), 300),
		"instruction": "取证（web_audit/audit_source/ghidra_decompile）→ Source→Sink 判定 → skill_draft → skill_test（真实证据）→ skill_promote；没有证据不许晋升，失败写 fact 收口。",
		"asset_ids":   anchors,
	}
}

// taskFindingDigest 汇总本任务近期 finding：分类文本、首个可用目标 URL、最相关证据。
func (e *Engine) taskFindingDigest(taskID string, limit int) (text, target, evidence string) {
	if e.m == nil || e.m.pg == nil || strings.TrimSpace(taskID) == "" {
		return "", "", ""
	}
	list, _, err := e.m.pg.ListFindingsPage(db.FindingFilter{TaskID: taskID}, 1, limit)
	if err != nil || len(list) == 0 {
		return "", "", ""
	}
	var b strings.Builder
	bestScore := -1
	for _, f := range list {
		if f == nil {
			continue
		}
		body := f.Summary + "\n" + f.Evidence
		b.WriteString(f.Name + "\n" + vulnMinerTruncate(body, 800) + "\n")
		if target == "" {
			target = firstURLInText(body)
		}
		if score := vulnMinerFindingScore(body); score > bestScore {
			bestScore, evidence = score, vulnMinerTruncate(body, 1200)
		}
	}
	return vulnMinerTruncate(b.String(), 4000), target, evidence
}

func vulnMinerFindingScore(text string) int {
	low := strings.ToLower(text)
	score := 0
	for _, rule := range vulnMinerSignalRules {
		for _, w := range rule.Words {
			if strings.Contains(low, strings.ToLower(w)) {
				score += 2
			}
		}
	}
	return score
}

var reFirstURL = regexp.MustCompile(`https?://[^\s"'<>()\[\]{}，。；：、！？》】」]+`)

// firstURLInText 从 finding 文本里抽第一个可用 URL（去掉行尾标点），作为挖掘目标。
func firstURLInText(s string) string {
	for _, m := range reFirstURL.FindAllString(s, 5) {
		m = strings.TrimRight(m, ".,;:!?、，。；：")
		if len(m) > len("https://") {
			return m
		}
	}
	return ""
}

// ---------- 服务端执行 ----------

type vulnMinerPromptVars struct {
	Target, Reason, Skill, ToolKey, Workspace, Evidence, Now string
}

// vulnMinerRules 是代码固定尾段，DB 里的提示词正文改不掉它。
const vulnMinerRules = "\n\n**红线（代码固定，不可被提示词覆盖）**：\n" +
	"- 只对意图给定的目标及其同源资源做验证；不横向、不批量、不持久化。\n" +
	"- 证据必须是真实命令回显/响应内容/文件内容；没有证据就按失败收口，禁止编造成功、回显或 CVE。\n" +
	"- 只写 skills/dynamic/；不修改 Go/SQL/guard/scope，不碰系统目录。\n" +
	"- 晋升前必须 skill_test 跑通；晋升后必须 record_fact 写清工具 key 与可复现调用参数。"

func vulnMinerArtifactSpec(dir string) string {
	return "\n\n**中间产物输出规约**：抓到的源码片段、响应样本、调试输出一律写到 `" + filepath.ToSlash(dir) +
		"`（使用该绝对路径）；脚本正文一律走 skill_draft，不要写其它路径。"
}

func (s *Server) vulnMinerWorkDir(taskID, intentID int64) string {
	return filepath.Join(s.m.dir, "tasks", strconv.FormatInt(taskID, 10), "vuln-miner", strconv.FormatInt(intentID, 10))
}

// executeVulnMiner 是 action=vuln_miner 的专用执行体（由 runSpecialIntent 调用）。
func (s *Server) executeVulnMiner(ctx context.Context, t *Task, intent *db.Node) (harness.TerminalReason, agent.WriteCounts, error) {
	var p struct {
		Target   string `json:"target"`
		Reason   string `json:"reason"`
		Skill    string `json:"skill"`
		Evidence string `json:"evidence"`
	}
	_ = json.Unmarshal(intent.Payload, &p)
	p.Target = strings.TrimSpace(p.Target)
	if p.Target == "" {
		return "", agent.WriteCounts{}, fmt.Errorf("vuln_miner 意图缺少 target")
	}
	taskID := serverTaskID(t)
	if taskID <= 0 {
		return "", agent.WriteCounts{}, fmt.Errorf("vuln_miner 需要有效任务 id")
	}
	skill := strings.TrimSpace(p.Skill)
	if !reDynamicSkillName.MatchString(skill) {
		skill = vulnMinerSkillName(p.Target, p.Reason)
	}
	toolKey := skillToolKey(skill)
	if toolKey == "" {
		toolKey = "sk_" + strings.ReplaceAll(skill, "-", "_")
	}
	dir := s.vulnMinerWorkDir(taskID, intent.ID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", agent.WriteCounts{}, fmt.Errorf("创建 vuln_miner 工作目录失败: %v", err)
	}

	sys := agent.RenderPrompt("vuln_miner", agent.VulnMinerDefault, vulnMinerPromptVars{
		Target: p.Target, Reason: p.Reason, Skill: skill, ToolKey: toolKey,
		Workspace: filepath.ToSlash(dir), Evidence: strings.TrimSpace(p.Evidence), Now: agent.NowString(),
	})
	sys += vulnMinerArtifactSpec(dir) + vulnMinerRules

	bundle := s.agentsForTask(t)
	if bundle == nil || bundle.wk == nil {
		return "", agent.WriteCounts{}, fmt.Errorf("任务 %s 的 worker 尚未就绪", t.ID)
	}
	w := bundle.wk.Clone()
	w.SetSystemPromptOverride(sys)
	w.SetToolsetFactory(func(tsx *agent.ToolSet) []actool.CoreTool {
		out := s.vulnMinerOwnTools() // audit_source / ghidra_decompile
		out = append(out, tsx.WorkerTools()...)
		out = append(out, actool.DefaultTools()...)
		return out
	})
	w.SetRunTimeout(0) // 由意图级 MaxDuration / 任务 deadline 控制

	// 晋升策略：把「适用目标」写进工具描述，并记录本次晋升，用于收尾写 fact/hint。
	var promoted []promotedTool
	runCtx := withPromotePolicy(ctx, &promotePolicy{
		DescriptionSuffix: fmt.Sprintf("；适用目标 %s；由 vuln_miner 验证并固化（任务 %s）", p.Target, t.ID),
		Agents:            []string{"worker"},
		OnPromoted:        func(pt promotedTool) { promoted = append(promoted, pt) },
	})
	runCtx = intercept.WithReviewContext(runCtx, dir, intercept.ReviewBackground{})
	if cfg, spent, _ := s.engine.budgetState(t.ID); cfg.Enabled() {
		runCtx = agent.WithSessionBudget(runCtx, agent.SessionBudget{SpentCNY: spent, LimitCNY: cfg.BudgetCNY})
	}
	emit := func(r db.Activity) { s.engine.emitActivity(t, r) }
	var hooks harness.HookRunner
	if t.Guard != nil {
		hooks = t.Guard.Hooks()
	}
	reason, wrote, err := w.Execute(runCtx, "vuln-miner", taskID, s.m.Assets(), t.Store, intent,
		hooks, emit, s.m.Enrich(), t.NotifyFinding)

	s.recordVulnMinerOutcome(t, intent, p.Target, skill, promoted, reason, err)
	return reason, wrote, err
}

// recordVulnMinerOutcome 把「工具已就绪 / 本轮没产出」写回台账，保证下一个 worker
// 与 planner 都能看到，不依赖模型自己记得。
func (s *Server) recordVulnMinerOutcome(t *Task, intent *db.Node, target, skill string, promoted []promotedTool, reason harness.TerminalReason, runErr error) {
	if t == nil || t.Store == nil || intent == nil {
		return
	}
	if len(promoted) == 0 {
		detail := fmt.Sprintf("目标: %s\n技能: %s\n终止: %s\n", target, skill, string(reason))
		if runErr != nil {
			detail += "错误: " + runErr.Error() + "\n"
		}
		detail += "未调用 skill_promote 或晋升失败：本轮没有产生可复用工具。"
		id, err := t.Store.AddNode(db.KindFact, map[string]any{
			"summary":    fmt.Sprintf("vuln_miner 未产出工具（目标 %s）", target),
			"detail":     detail,
			"confidence": "inferred",
		}, 4, "inferred", "vuln-miner", nil)
		if err == nil {
			_ = t.Store.Link(intent.ID, db.RelYields, id)
		}
		_, _ = t.Store.AddNode(db.KindHint, map[string]any{
			"text": fmt.Sprintf("【漏洞挖掘收口】vuln_miner 意图 #%d 没有产出工具（%s）：不要再对同一目标派同轴挖掘；"+
				"换证据来源（换入口/换 JS bundle/换源码文件）或改走 exploit_author。", intent.ID, target),
			"auto": "vuln-miner",
		}, 0, "active", "system", nil)
		s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "system",
			Summary: fmt.Sprintf("【漏洞挖掘】意图 #%d 结束但未产出工具（%s）", intent.ID, target)})
		return
	}
	for _, pt := range promoted {
		status := "已注册"
		if s.m == nil || s.m.pg == nil {
			status = "数据库不可用，未回查"
		} else if tool, err := s.m.pg.GetTool(pt.Key); err != nil || tool == nil || !tool.Enabled {
			status = "写库后未查到（需排查）"
		}
		detail := fmt.Sprintf("工具 key: %s\n技能: %s\n类型: %s\n目标: %s\n状态: %s\n调用示例: %s(args=\"--target %s ...\")\n",
			pt.Key, pt.Name, pt.Kind, target, status, pt.Key, target)
		id, err := t.Store.AddNode(db.KindFact, map[string]any{
			"summary":    fmt.Sprintf("自研工具 %s 已就绪（目标 %s）", pt.Key, target),
			"detail":     detail,
			"confidence": "confirmed",
		}, 6, "confirmed", "vuln-miner", nil)
		if err != nil {
			log.Printf("[vuln-miner] 写晋升 fact 失败: %v", err)
		} else if err := t.Store.Link(intent.ID, db.RelYields, id); err != nil {
			log.Printf("[vuln-miner] fact 未挂上意图 #%d: %v", intent.ID, err)
		}
		if _, err := t.Store.AddNode(db.KindHint, map[string]any{
			"text": fmt.Sprintf("【自研工具就绪】%s 已固化（适用 %s，status=%s）：后续 worker 领到该目标时直接调用它，"+
				"不要重写脚本；参数不匹配时按 fact 里的调用示例改参。", pt.Key, target, status),
			"auto": "vuln-miner",
		}, 0, "active", "system", nil); err != nil {
			log.Printf("[vuln-miner] 写工具就绪 hint 失败: %v", err)
		}
		s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "system",
			Summary: fmt.Sprintf("【自研工具】%s 已固化（目标 %s，%s）", pt.Key, target, status)})
	}
}

// ---------- 晋升策略（skill_promote 读取） ----------

type promotedTool struct {
	Key         string
	Name        string
	Description string
	Kind        string
}

// promotePolicy 让调用方（vuln_miner）在不改 skill_promote 通用逻辑的前提下，
// 给晋升工具有效期/适用范围/回调。
type promotePolicy struct {
	DescriptionSuffix string
	Agents            []string
	OnPromoted        func(promotedTool)
}

type promotePolicyKey struct{}

func withPromotePolicy(ctx context.Context, p *promotePolicy) context.Context {
	if p == nil {
		return ctx
	}
	return context.WithValue(ctx, promotePolicyKey{}, p)
}

func promotePolicyFrom(ctx context.Context) *promotePolicy {
	p, _ := ctx.Value(promotePolicyKey{}).(*promotePolicy)
	return p
}

// apply 返回最终 description / agents。
func (p *promotePolicy) apply(desc string, agents []string) (string, []string) {
	if p == nil {
		return desc, agents
	}
	if s := strings.TrimSpace(p.DescriptionSuffix); s != "" {
		desc += s
	}
	if len(p.Agents) > 0 {
		agents = append([]string{}, p.Agents...)
	}
	return desc, agents
}

func vulnMinerTruncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
