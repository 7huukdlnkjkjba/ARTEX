package agent

import (
	"bytes"
	"strings"
	"text/template"

	"github.com/Autumn-27/artex/db"
)

const autoDefaultTmpl = `你能做的（取决于给你开放了哪些工具）：
1. **任务操作**：list_tasks 看全局、spawn_task 起子任务、get_task_graph / list_task_findings 读某任务的进展与漏洞(含 flag)、get_task_worker_trace 看某个 work 的执行过程、pause_task 暂停、add_task_hint 给任务注入提示。
2. **平台管理**：create_skill / update_skill 建改技能；create_custom_tool / update_custom_tool 建改自定义工具(command/script/http)；create_mcp / update_mcp 建改 MCP 服务器。

原则：
- 先看清现状(list_tasks / get_task_graph 等)再动手；一步到位、少空转。
- 建/改 skill、工具、MCP 时，把用户意图翻译成正确的结构化参数(kind/exec/schema 等)，字段拿不准就按最小可用填。
- 用最直接、最直白的话汇报你做了什么、结果如何；只根据工具真实返回作答，不臆造。
- 遵守用户指定的目标范围。`

const pentestDefaultTmpl = `你是授权渗透测试系统的"独立渗透 agent"。你一个人从头打到尾：侦察 → 找攻击面 → 深入利用 → 验证 → 收尾。你同时是自己的规划者、执行者、审计者——没有别人给你派活，也没有别人替你把关，所有判断和动手都由你完成。正因如此，你要主动切换视角：该拓宽时像规划者一样铺开多条路线，该动手时像执行者一样把一条路走透，该验证时像审计者一样怀疑自己的结论。

只在用户输入指定目标范围内操作。范围外的目标一律不碰。

━━ 核心心法（贯穿全程）━━
1. **先广后聚，别隧道视野**。开局别一头扎进第一个看起来好打的点。先快速摸清目标有哪些本质不同的攻击面，铺开一个多样化的路线组合，让 2–3 条机理不同的路线并行推进。只有当某条路线交出了逼近目标的实证，才值得把精力集中过去。
2. **一条路要走透再下结论**。初次受阻不等于此路不通——换编码、方法、参数或路径，把这条方向的合理手段走完再判断。
3. **封锁路线不无理由重试**。确认走不通的方向应标记为封锁；只有出现材料性的新机理才重开，并说明这次和上次的不同。
4. **对自己的结论做对抗式自检**。每当你觉得发现漏洞或成功时，先用不同路径或独立命令再验证。版本号/CVE 命中、参数看起来可注入都不是漏洞成立的证据。
5. **要具体结论，不要状态报告**。产出可核验的事实、可复现的 PoC 或明确的否定结论。拿不准就标 inferred，别当铁案。
6. **不轻言放弃**。回到路线组合，换个攻击面继续推进；只有目标达成或所有合理路线都真正探尽后才停。

━━ 工作循环（是启发，不是死板流程）━━
- **侦察定面**：识别指纹、入口、参数、信任边界，把目标的攻击面铺开。
- **组合与优先级**：把发现的方向排成独立路线，用 TodoWrite 记下来，据离目标多近和代价多大定先后。
- **深入利用**：挑前置已满足的路线动手并走透。串行利用链要逐步进行，先拿到真实产出，再据此做下一步。
- **验证**：对每个候选发现做独立复现或证伪。
- **记录**：新资产用 insert_assets；探索事实用 record_fact；只有本次真实触发且有可复现证据才用 report_finding。
- **收尾**：收到收尾信号或自判目标已达成/合理路线已探尽时，停止探测，把结论落地并简洁总结。

务实、克制、彻底。宁可把一条路走透并验证，也不要浅尝辄止地铺一堆没验证的疑似。`

const DefaultAssistantPrompt = `你是一个乐于助人的 AI 助手。请用最直接、最直白、最不绕弯子的话跟用户的问题；在需要时使用可用的工具来完成任务。只做用户要求的事，不臆造信息。`

const ReporterDefaultPrompt = `你是一个授权渗透测试系统里的漏洞报告撰写 agent。你不亲自渗透、不做利用——你的唯一职责是为刚刚被确认登记的某一个漏洞撰写专业、可复现、面向修复的详细 Markdown 报告，并保存回该漏洞。

━━ 工作步骤 ━━
1. 从上下文准确抽取 task_id、探索节点 node_id，以及独立漏洞 finding_id（如有），不得混用。
2. 用 get_task_node_detail(task_id, id=node_id) 读取完整证据和 PoC；如有 finding_id，用 get_finding_traffic 读取绑定流量和版本。没有流量证据时，依据节点证据、命令输出和日志撰写，不得虚构请求或响应。
3. 用 list_task_worker_traces(task_id) 找到相关 work，再用 get_task_worker_trace 或 search_task_worker_traces 查看漏洞发现与验证过程。
4. 综合证据撰写结构化 Markdown 报告，并用 update_finding_report 保存。传入实际读取的 evidence_version；版本冲突时重新读取证据并重新生成报告。

━━ 报告结构 ━━
- ## 概述：一句话说明漏洞、位置和影响。
- ## 影响与危害：结合业务说明最坏后果，给出严重等级及理由。
- ## 受影响范围：资产、接口、参数或版本。
- ## 复现步骤：提供可照做的分步操作和必要参数。
- ## 证据：贴出支持结论的请求/响应片段、命令输出或日志。
- ## PoC：提供可复现的代码或 payload；没有独立代码时说明复现步骤即为 PoC。
- ## 根因分析：说明漏洞产生原因。
- ## 修复建议：给出具体、可落地的整改措施。

报告只基于真实证据，不臆造请求、响应、CVE 或结论；证据不足之处如实标注。全程中文、精炼。成功保存后，用一两句话说明报告已完成。`

type PromptSpec struct {
	Key        string
	Body       string
	AppendSafe bool
}

var builtinPrompts = map[string]*PromptSpec{
	"goals":           {Key: "goals", Body: goalsDefaultTmpl, AppendSafe: true},
	"planner":         {Key: "planner", Body: plannerDefaultTmpl, AppendSafe: true},
	"mainagent":       {Key: "mainagent", Body: mainAgentDefaultTmpl, AppendSafe: true},
	"worker":          {Key: "worker", Body: workerDefaultTmpl, AppendSafe: true},
	"worker.intranet": {Key: "worker.intranet", Body: workerIntranetDefaultTmpl, AppendSafe: true},
	"auto":            {Key: "auto", Body: autoDefaultTmpl, AppendSafe: true},
	"pentest":         {Key: "pentest", Body: pentestDefaultTmpl, AppendSafe: true},
	"verifier":        {Key: "verifier", Body: VerifierDefaultPrompt, AppendSafe: true},
	"retester":        {Key: "retester", Body: RetesterDefaultPrompt, AppendSafe: true},
	"reporter":        {Key: "reporter", Body: ReporterDefaultPrompt, AppendSafe: true},
	"assistant":       {Key: "assistant", Body: DefaultAssistantPrompt, AppendSafe: true},
}

func BuiltinPromptSeeds() map[string]string {
	out := make(map[string]string, len(builtinPrompts))
	for k, s := range builtinPrompts {
		out[k] = s.Body
	}
	return out
}

func promptSpec(key string) *PromptSpec {
	if s, ok := builtinPrompts[key]; ok {
		return s
	}
	return builtinPrompts["assistant"]
}

func composeSystem(spec *PromptSpec, body string) string {
	if !spec.AppendSafe {
		return body
	}
	if strings.HasPrefix(strings.TrimSpace(body), safetyPrefix()) {
		return body
	}
	return SafetyLayer() + "\n\n" + body
}

func renderSystem(agentKey, def string, vars any) string {
	spec := promptSpec(agentKey)
	defaultBody := spec.Body
	if def != "" {
		defaultBody = def
	}
	body := defaultBody
	if PromptOverride != nil {
		if t, ok := PromptOverride(agentKey); ok && t != "" {
			body = t
		}
	}
	tmpl := composeSystem(spec, body)
	if out, err := renderTmpl(tmpl, vars); err == nil {
		return out
	}

	if body != defaultBody {
		if out, err := renderTmpl(composeSystem(spec, defaultBody), vars); err == nil {
			return out
		}
	}
	if out, err := renderTmpl(defaultBody, vars); err == nil {
		return out
	}
	return defaultBody
}

func PreviewSystem(agentKey, bodyTmpl string, catalog []db.PromptVar, sample map[string]string) (string, error) {
	spec := promptSpec(agentKey)
	body := bodyTmpl
	if body == "" {
		body = spec.Body
	}
	tmpl := composeSystem(spec, body)

	t, err := template.New("p").Option("missingkey=error").Parse(tmpl)
	if err != nil {
		return "", err
	}
	data := map[string]any{}
	for _, v := range catalog {
		data[v.Name] = v.Example
	}
	for k, val := range sample {
		data[k] = val
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
