package agent

// 工具路由闸门(toolchain gate)。
//
// 背景(实战数据,2026-11):平台上 worker 共 1911 次工具调用里,recon_http /
// http_diff / scan_rustscan / path_probe / admin_surface / fingerprint /
// auth_probe / report_finding_gated / sqlmap_run / nuclei_run / web_audit /
// raw_tcp / db_dump 的调用次数是 **0**;Bash 占全部 transcript 工具调用的 72%
// (1668/2316),模型宁可反复手搓 curl / Invoke-WebRequest 也不碰专用工具。
//
// 只写提示词没有用——toolchainRule 早就在系统提示里,照样零调用。真正能把行为
// 掰过来的只有执行层:在 Bash 被调用时识别“高置信度的手搓动作”,直接拒绝并给出
// 对应的专用工具与最小调用示例;确实无法表达的场景(文件上传、流式响应、大文件
// 下载、私有脚本)必须由模型显式填写 override_reason 才放行。
//
// 设计边界:
//   - 只拦高置信度、有明确替代工具的模式(curl/wget/Invoke-WebRequest 的 HTTP、
//     nmap/rustscan/masscan 端口扫描、sqlmap、nuclei);
//   - 替代工具不在本 agent 的最终工具列表里时不拦(避免把模型逼进死路);
//   - 逃生口是显式参数而不是隐藏开关:override_reason 随输入留痕,便于复盘;
//   - 版本/帮助探测(curl --version 等)放行,不制造无意义摩擦。

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"runtime"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

// ToolchainGateEnabled reports whether the Bash routing gate is active. Default
// ON: the measured failure mode is “tools exist but are never called”, and a
// prompt-only fix has already been tried and failed. Set ARTEX_TOOLCHAIN_GATE=off
// (or 0/false/no) to disable without rebuilding.
var ToolchainGateEnabled = func() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ARTEX_TOOLCHAIN_GATE"))) {
	case "off", "0", "false", "no":
		return false
	}
	return true
}

// handrollRule maps one high-confidence hand-rolled command family to the
// platform tool that is supposed to replace it.
type handrollRule struct {
	target  string         // replacement tool name; must be in the agent's tool list
	re      *regexp.Regexp // matches a real invocation (not a version/help probe)
	why     string         // one-line reason: what the tool does that Bash cannot
	example string         // smallest useful call
}

// 顺序即优先级:更专用的模式排在更宽的模式之前。
//
// 每条正则都以“命令起点”锚定(行首、;、换行、&、|、()。不能简单用前面的空白:
// `grep curl access.log` / `echo curl` 里的 curl 是参数,不是要执行的命令,按空白
// 匹配会把正常命令误拦。
const handrollCmdStart = `(?:^|[;\n&|(])\s*(?:(?:sudo|time|nohup|command)\s+|env\s+(?:\S+=\S+\s+)*)?`

var handrollRules = []handrollRule{
	{
		target:  "sqlmap_run",
		re:      regexp.MustCompile(`(?i)` + handrollCmdStart + `sqlmap(?:\.py)?\b`),
		why:     "sqlmap_run 会走任务 scope/代理/隧道、限速并留痕,dump 还强制 confirm=true+table",
		example: `sqlmap_run({"url":"http://TARGET/item?id=1","action":"detect"})`,
	},
	{
		target:  "nuclei_run",
		re:      regexp.MustCompile(`(?i)` + handrollCmdStart + `nuclei\b`),
		why:     "nuclei_run 默认 critical/high/medium、限速 50、不开 interactsh,模板与目标都受 scope 约束",
		example: `nuclei_run({"target":"http://TARGET"})`,
	},
	{
		target:  "scan_rustscan",
		re:      regexp.MustCompile(`(?i)` + handrollCmdStart + `(?:nmap|rustscan|masscan)\b`),
		why:     "scan_rustscan 只返回开放端口,自动走任务代理/隧道并把端口开放写回资产,不产生噪音漏洞",
		example: `scan_rustscan({"target":"10.0.0.5","ports":"1-65535"})`,
	},
	{
		target: "recon_http",
		re: regexp.MustCompile(`(?i)` + handrollCmdStart +
			`(?:curl(?:\.exe)?|wget|invoke-webrequest|iwr|invoke-restmethod|irm)\b` +
			`|` + handrollCmdStart + `python[0-9.]*\s+-c\b[\s\S]*\b(?:requests|urllib|http\.client|httpx)\b`),
		why:     "recon_http 会走任务 MITM/隧道代理、记录观察台账(可被 report_finding_gated 引用)并回结构化状态码/响应头",
		example: `recon_http({"url":"http://TARGET/","method":"GET"})`,
	},
}

// probeFlags are version/help probes that should never be gated: they teach the
// model what is installed without performing recon.
var probeFlags = []string{"--version", "-version", "--help", "-help", "--usage", " /?"}

func looksLikeProbe(cmd string) bool {
	l := strings.ToLower(cmd)
	for _, f := range probeFlags {
		if strings.Contains(l, f) {
			return true
		}
	}
	return false
}

// classifyHandroll returns the rule a command should be routed through, or nil
// when the command is not a high-confidence hand-roll. allowed is the set of
// tool names actually present for this agent: a rule whose replacement tool is
// absent is never applied (no dead-end redirects).
func classifyHandroll(cmd string, allowed map[string]bool) *handrollRule {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" || looksLikeProbe(cmd) {
		return nil
	}
	for i := range handrollRules {
		r := &handrollRules[i]
		if !allowed[r.target] {
			continue
		}
		if r.re.MatchString(cmd) {
			return r
		}
	}
	return nil
}

// gateErrorText is what the model sees instead of the command's output. It is
// deliberately compact (tool errors are re-sent every turn) and names the exact
// replacement plus the escape hatch.
func gateErrorText(r *handrollRule, cmd string) string {
	return "[工具闸门] 这条 Bash 命令被判定为手搓 " + shortCommand(cmd) + "。\n" +
		"请改用 `" + r.target + "`:" + r.why + "。\n" +
		"最小调用:" + r.example + "\n" +
		"如果确实需要原生命令(文件上传、流式响应、大文件落地、私有脚本、工具不覆盖的参数),把同样的命令连同 " +
		"override_reason:\"为什么专用工具表达不了\" 一起重发,闸门会放行。"
}

// shortCommand keeps error text small: the first line, capped.
func shortCommand(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if i := strings.IndexByte(cmd, '\n'); i >= 0 {
		cmd = cmd[:i]
	}
	const max = 80
	if len(cmd) > max {
		cmd = cmd[:max] + "…"
	}
	return "`" + cmd + "`"
}

// gatedBash wraps the SDK Bash tool: it keeps every behavioral method and only
// intercepts Call to refuse high-confidence hand-rolls. The added
// override_reason property is the explicit escape hatch.
type gatedBash struct {
	actool.CoreTool
	allowed map[string]bool
	schema  map[string]any
	desc    string
}

func (g *gatedBash) Description() string         { return g.desc }
func (g *gatedBash) InputSchema() map[string]any { return g.schema }

func (g *gatedBash) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	var args struct {
		Command        string `json:"command"`
		OverrideReason string `json:"override_reason"`
	}
	_ = json.Unmarshal(in, &args)
	if strings.TrimSpace(args.OverrideReason) == "" {
		if m := classifyHandroll(args.Command, g.allowed); m != nil {
			return actool.Errorf(gateErrorText(m, args.Command)), nil
		}
	}
	return g.CoreTool.Call(ctx, in, tc)
}

// BashPlatformNote describes the shell that Bash actually runs, because the SDK
// tool is named "Bash" but on Windows it executes Windows PowerShell 5.1 (no
// &&, no $(), no here-doc). The 2026-11 transcript shows 6+ retries of the same
// curl command failing with PowerShell's InvalidEndOfLine before the model gave
// up — pure cost, zero progress. Returns "" on platforms where Bash really is
// bash (the note would only add tokens).
func BashPlatformNote() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	return "\n\n**当前 Bash 工具的真实执行环境:Windows PowerShell 5.1(不是 bash)**:" +
		"不支持 `&&`、`||`、`$()`、here-doc;多条命令用 `;` 分隔,条件串联用 `; if ($?) { ... }`;" +
		"`curl` 是 `Invoke-WebRequest` 的别名(参数不同),需要真 curl 时写 `curl.exe`;" +
		"路径用正斜杠或双引号,单引号不转义。错误里出现 `ParserError`/`InvalidEndOfLine` 就是语法用错了。"
}

// ApplyBashPlatformNote appends BashPlatformNote to the Bash tool's description.
// Code-owned: a DB description override cannot drop it.
func ApplyBashPlatformNote(tools []actool.CoreTool) []actool.CoreTool {
	note := BashPlatformNote()
	if note == "" {
		return tools
	}
	for i, t := range tools {
		if t.Name() == "Bash" {
			tools[i] = DecorateTool(t, t.Description()+note, t.InputSchema())
			break
		}
	}
	return tools
}

// ApplyToolchainGate wraps Bash when at least one replacement tool is actually
// available. Idempotent: an already-wrapped Bash passes through.
func ApplyToolchainGate(tools []actool.CoreTool) []actool.CoreTool {
	if !ToolchainGateEnabled() {
		return tools
	}
	allowed := make(map[string]bool, len(tools)+4)
	for _, t := range tools {
		allowed[t.Name()] = true
	}
	var applicable []*handrollRule
	for i := range handrollRules {
		if allowed[handrollRules[i].target] {
			applicable = append(applicable, &handrollRules[i])
		}
	}
	if len(applicable) == 0 {
		return tools
	}
	for i, t := range tools {
		if t.Name() != "Bash" {
			continue
		}
		if _, ok := t.(*gatedBash); ok {
			return tools // already gated
		}
		schema := schemaWithExtraProp(t.InputSchema(), "override_reason",
			"仅当专用工具确实无法表达时才填:为什么必须用原生命令(文件上传/流式响应/大文件落地/私有脚本/工具不覆盖的参数)。填了才放行。")
		tools[i] = &gatedBash{
			CoreTool: t,
			allowed:  allowed,
			schema:   schema,
			desc:     t.Description() + gateDescription(applicable),
		}
		return tools
	}
	return tools
}

// schemaWithExtraProp deep-copies a JSON-Schema map and adds one optional string
// property, so the original schema (possibly shared with the SDK) is untouched.
func schemaWithExtraProp(schema map[string]any, name, desc string) map[string]any {
	b, err := json.Marshal(schema)
	if err != nil {
		return schema
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return schema
	}
	props, _ := out["properties"].(map[string]any)
	if props == nil {
		props = map[string]any{}
		out["properties"] = props
	}
	props[name] = map[string]any{"type": "string", "description": desc}
	return out
}

// gateDescription tells the model, up front, which hand-rolled families will be
// refused and how to use the escape hatch — so it does not have to learn by
// getting rejected.
func gateDescription(rules []*handrollRule) string {
	var b strings.Builder
	b.WriteString("\n\n**工具闸门(代码强制)**:以下手搓命令会被直接拒绝并提示对应工具——")
	for i, r := range rules {
		if i > 0 {
			b.WriteString(";")
		}
		b.WriteString(r.target)
	}
	b.WriteString("。确需原生命令时在本次调用里加 `override_reason` 说明原因。")
	return b.String()
}

// 编译期断言:gatedBash 必须实现 actool.CoreTool。
var _ actool.CoreTool = (*gatedBash)(nil)
