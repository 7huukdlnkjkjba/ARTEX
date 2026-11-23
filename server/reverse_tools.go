package server

// 逆向取证工具（vuln_miner 专用）：audit_source / ghidra_decompile。
//
// 它们只被 vuln_miner 意图的专用 worker 使用（不进 tools 表、不参与 per-agent
// 绑定），因为产物是「给写 EXP 用的证据」，不是通用探测能力：
//
//	audit_source      —— 把源码/JS bundle 切成 sink/source 行号证据，给出 Source→Sink
//	                     flow，并标记「同语句拼接」的候选（写 EXP 的第一优先级）。
//	ghidra_decompile  —— 用内置 Ghidra 的无头分析器出伪代码（开源，替代 IDA）；
//	                     找不到 Ghidra/JDK 时诚实返回 tool_missing，绝不返回占位伪代码。
//
// 两条都只读：不执行样本、不写目标、不做网络利用。

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/guard"
	actool "github.com/Autumn-27/norma/tool"
)

const (
	auditSourceMaxBytes = 4 << 20 // 单文件 4MB 上限
	auditSourceMaxHits  = 120     // sink/source 各最多保留 120 条（控制回传体积）
	auditSourceMaxFlows = 40      // flow 上限
	auditSourceWindow   = 40      // source 与 sink 的最大行距
)

// auditHit 是一条命中的危险行/输入行。
type auditHit struct {
	Line    int    `json:"line"`
	Kind    string `json:"kind"` // 例如 js_eval / php_system / js_location_hash
	Code    string `json:"code"` // 原始行（截断）
	Pattern string `json:"pattern"`
}

// auditFlow 是一条 Source→Sink 候选链路。Concatenated 表示 sink 行本身出现
// 字符串拼接/模板插值——这类通常是「危险函数直接拼接外部输入」，优先写 EXP。
type auditFlow struct {
	SinkLine     int    `json:"sink_line"`
	SourceLine   int    `json:"source_line"`
	Sink         string `json:"sink"`
	Source       string `json:"source"`
	Concatenated bool   `json:"concatenated"`
	Snippet      string `json:"snippet"`
}

type auditSourceResult struct {
	Status    string      `json:"status"`
	Target    string      `json:"target"`
	Language  string      `json:"language"`
	Bytes     int         `json:"bytes"`
	Egress    string      `json:"egress,omitempty"`
	Sinks     []auditHit  `json:"sinks,omitempty"`
	Sources   []auditHit  `json:"sources,omitempty"`
	Flows     []auditFlow `json:"flows,omitempty"`
	Summary   string      `json:"summary"`
	Notes     []string    `json:"notes,omitempty"`
	Truncated bool        `json:"truncated,omitempty"`
}

// vulnMinerOwnTools 是 vuln_miner 专用工具集（不 seed、不绑定通用 worker）。
func (s *Server) vulnMinerOwnTools() []actool.CoreTool {
	return []actool.CoreTool{s.toolAuditSource(), s.toolGhidraDecompile()}
}

// ---------- audit_source ----------

type auditPattern struct {
	Name string
	Re   *regexp.Regexp
}

type auditLangSpec struct {
	Sinks   []auditPattern
	Sources []auditPattern
}

var auditJS = auditLangSpec{
	Sinks: []auditPattern{
		{"js_eval", regexp.MustCompile(`\beval\s*\(`)},
		{"js_function_ctor", regexp.MustCompile(`\bnew\s+Function\s*\(|\bFunction\s*\(`)},
		{"js_timer_string", regexp.MustCompile(`\bset(Timeout|Interval)\s*\(\s*['"\x60]`)},
		{"js_innerhtml", regexp.MustCompile(`\.(innerHTML|outerHTML)\s*=`)},
		{"js_insert_adjacent", regexp.MustCompile(`\binsertAdjacentHTML\s*\(`)},
		{"js_document_write", regexp.MustCompile(`\bdocument\.write(ln)?\s*\(`)},
		{"js_location_assign", regexp.MustCompile(`\b(location|window\.location)\s*(=|\.href\s*=|\.assign\s*\(|\.replace\s*\()`)},
		{"js_script_element", regexp.MustCompile(`createElement\s*\(\s*['"]script`)},
		{"js_react_dangerous_html", regexp.MustCompile(`dangerouslySetInnerHTML`)},
		{"js_postmessage", regexp.MustCompile(`\.postMessage\s*\(`)},
		{"js_wasm_instantiate", regexp.MustCompile(`WebAssembly\.instantiate`)},
	},
	Sources: []auditPattern{
		{"js_location", regexp.MustCompile(`\b(location|window\.location)\.(hash|search|href)`)},
		{"js_document_url", regexp.MustCompile(`document\.(URL|documentURI|referrer)`)},
		{"js_window_name", regexp.MustCompile(`window\.name`)},
		{"js_cookie", regexp.MustCompile(`document\.cookie`)},
		{"js_storage", regexp.MustCompile(`\b(localStorage|sessionStorage)\b`)},
		{"js_urlsearchparams", regexp.MustCompile(`URLSearchParams`)},
		{"js_event_data", regexp.MustCompile(`\bevent\.data\b`)},
		{"js_jquery_hash", regexp.MustCompile(`\|\|\s*\$\(location\.hash`)},
	},
}

var auditPHP = auditLangSpec{
	Sinks: []auditPattern{
		{"php_eval", regexp.MustCompile(`\beval\s*\(`)},
		{"php_assert", regexp.MustCompile(`\bassert\s*\(`)},
		{"php_cmd", regexp.MustCompile(`\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\(`)},
		{"php_unserialize", regexp.MustCompile(`\bunserialize\s*\(`)},
		{"php_include", regexp.MustCompile(`\b(include|include_once|require|require_once)\s*[\(\s]`)},
		{"php_create_function", regexp.MustCompile(`\bcreate_function\s*\(`)},
		{"php_preg_e", regexp.MustCompile(`\bpreg_replace\s*\([^;]*/e['"]?`)},
		{"php_call_user_func", regexp.MustCompile(`\bcall_user_func(_array)?\s*\(`)},
	},
	Sources: []auditPattern{
		{"php_superglobal", regexp.MustCompile(`\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\b`)},
		{"php_input", regexp.MustCompile(`php://input`)},
	},
}

var auditJava = auditLangSpec{
	Sinks: []auditPattern{
		{"java_runtime_exec", regexp.MustCompile(`Runtime\.getRuntime\(\)\s*\.\s*exec\s*\(`)},
		{"java_process_builder", regexp.MustCompile(`new\s+ProcessBuilder\s*\(`)},
		{"java_script_engine", regexp.MustCompile(`\b(ScriptEngine|ScriptEngineManager)\b[^;]*\.eval\s*\(`)},
		{"java_deserialize", regexp.MustCompile(`\b(ObjectInputStream|readObject)\b`)},
		{"java_spel", regexp.MustCompile(`\b(SpelExpressionParser|parseExpression)\b`)},
		{"java_jndi", regexp.MustCompile(`\bInitialContext\b[^;]*\.lookup\s*\(`)},
		{"java_forname", regexp.MustCompile(`Class\.forName\s*\(`)},
		{"java_method_invoke", regexp.MustCompile(`\.invoke\s*\(`)},
	},
	Sources: []auditPattern{
		{"java_param", regexp.MustCompile(`getParameter\s*\(`)},
		{"java_header", regexp.MustCompile(`getHeader\s*\(`)},
		{"java_inputstream", regexp.MustCompile(`getInputStream\s*\(`)},
		{"java_querystring", regexp.MustCompile(`getQueryString\s*\(`)},
	},
}

var auditPython = auditLangSpec{
	Sinks: []auditPattern{
		{"py_eval", regexp.MustCompile(`\beval\s*\(`)},
		{"py_exec", regexp.MustCompile(`\bexec\s*\(`)},
		{"py_pickle", regexp.MustCompile(`\bpickle\.loads?\s*\(`)},
		{"py_yaml", regexp.MustCompile(`\byaml\.load\s*\(`)},
		{"py_os_cmd", regexp.MustCompile(`\bos\.(system|popen)\s*\(`)},
		{"py_subprocess", regexp.MustCompile(`\bsubprocess\.(run|Popen|call|check_output)\s*\(`)},
		{"py_import", regexp.MustCompile(`\b__import__\s*\(`)},
		{"py_compile", regexp.MustCompile(`\bcompile\s*\(`)},
	},
	Sources: []auditPattern{
		{"py_request", regexp.MustCompile(`request\.(args|form|json|values|GET|POST)`)},
		{"py_argv", regexp.MustCompile(`sys\.argv`)},
		{"py_input", regexp.MustCompile(`\binput\s*\(`)},
	},
}

// auditConcatMarkers 标记「同语句拼接/动态求值」：危险函数参数来自拼接时，
// 通常意味着攻击者可以直接把 payload 拼进执行上下文。
var auditConcatMarkers = []*regexp.Regexp{
	regexp.MustCompile(`\+\s*[A-Za-z_$]`),
	regexp.MustCompile(`[A-Za-z0-9_$)\]]\s*\+`),
	regexp.MustCompile("`"),
	regexp.MustCompile(`\$\{`),
	regexp.MustCompile(`\.concat\s*\(`),
	regexp.MustCompile(`\.\s*\$[A-Za-z_]`), // PHP 的 "a" . $b 拼接
	regexp.MustCompile(`String\.fromCharCode|atob\s*\(|decodeURIComponent\s*\(|unescape\s*\(`),
	regexp.MustCompile(`\b(sprintf|format)\s*\(`),
}

func (s *Server) toolAuditSource() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "audit_source",
		Description: "【逆向核心·源码审计】对本地源码文件或 http(s) URL（JS bundle / PHP / Java / Python）做 Source→Sink 静态审计：" +
			"去掉注释/字符串后匹配危险函数（eval/Function/innerHTML/unserialize/exec…），标记外部可控 source，" +
			"输出 flows[]（sink 行号 + 最近 source 行号 + 是否同语句拼接）。" +
			"只做静态提取，不执行代码；跨域 URL 仍受任务 scope 约束。",
		Schema: objSchema(map[string]any{
			"target":    strParam("本地源码路径，或 http(s) URL（JS 文件/页面源码）"),
			"language":  strParam("js | php | java | python；auto=按扩展名/内容判断（默认 auto）"),
			"max_bytes": map[string]any{"type": "integer", "description": fmt.Sprintf("最多读取字节数，默认 %d", auditSourceMaxBytes)},
		}, "target"),
		ReadOnly:    func(json.RawMessage) bool { return true },
		Permissions: sessionPerm,
		Run: func(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			var a struct {
				Target   string `json:"target"`
				Language string `json:"language"`
				MaxBytes int    `json:"max_bytes"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			a.Target = strings.TrimSpace(a.Target)
			if a.Target == "" {
				return actool.Errorf("target 不能为空"), nil
			}
			// 相对路径按本次运行的 intent 工作目录解析（与 Bash/Read 的语义一致）。
			if !strings.HasPrefix(a.Target, "http://") && !strings.HasPrefix(a.Target, "https://") &&
				!filepath.IsAbs(a.Target) && tc != nil && tc.WorkingDir != "" {
				a.Target = filepath.Join(tc.WorkingDir, a.Target)
			}
			maxBytes := a.MaxBytes
			if maxBytes <= 0 || maxBytes > auditSourceMaxBytes {
				maxBytes = auditSourceMaxBytes
			}
			src, language, egress, err := s.readAuditTarget(ctx, a.Target, a.Language, maxBytes)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			res := scanAuditSource(src, language)
			res.Target, res.Egress = a.Target, egress
			return jsonResult(res)
		},
	})
}

// readAuditTarget 读取目标源码：URL 走任务 MITM + scope 校验；本地路径受限读。
func (s *Server) readAuditTarget(ctx context.Context, target, language string, maxBytes int) (string, string, string, error) {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		h, err := auditURLHost(target)
		if err != nil {
			return "", "", "", err
		}
		ri := agent.RunInfoFrom(ctx)
		if inScope, known := guard.HostInTaskScope(ri.TaskID, h); known && !inScope {
			return "", "", "", fmt.Errorf("目标 %s 不在任务 scope 内", h)
		}
		client, egress := s.webAuditHTTPClient(ri.TaskID)
		body, err := fetchWebAuditRaw(ctx, client, target, maxBytes)
		if err != nil {
			return "", "", "", fmt.Errorf("抓取 %s 失败: %v", target, err)
		}
		return body, auditDetectLanguage(target, body, language), egress, nil
	}
	st, err := os.Stat(target)
	if err != nil {
		return "", "", "", fmt.Errorf("读取本地源码失败: %v", err)
	}
	if st.IsDir() {
		return "", "", "", fmt.Errorf("%s 是目录：audit_source 只收单个文件（先定位具体 JS/源码文件）", target)
	}
	if st.Size() > int64(maxBytes) {
		return "", "", "", fmt.Errorf("文件过大（%d 字节，上限 %d）：先切出目标片段再审计", st.Size(), maxBytes)
	}
	raw, err := os.ReadFile(target)
	if err != nil {
		return "", "", "", fmt.Errorf("读取本地源码失败: %v", err)
	}
	return string(raw), auditDetectLanguage(target, string(raw), language), "local", nil
}

func auditURLHost(raw string) (string, error) {
	rest := strings.TrimPrefix(strings.TrimPrefix(raw, "https://"), "http://")
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	host := rest
	if i := strings.LastIndex(host, "@"); i >= 0 {
		host = host[i+1:]
	}
	if i := strings.LastIndex(host, ":"); i >= 0 && !strings.Contains(host[i:], "]") {
		host = host[:i]
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return "", fmt.Errorf("非法 URL: %s", raw)
	}
	return host, nil
}

func auditDetectLanguage(target, src, want string) string {
	switch strings.ToLower(strings.TrimSpace(want)) {
	case "js", "javascript", "ts", "typescript":
		return "js"
	case "php":
		return "php"
	case "java":
		return "java"
	case "py", "python":
		return "python"
	}
	lower := strings.ToLower(target)
	switch {
	case strings.Contains(lower, ".js"), strings.Contains(lower, ".mjs"), strings.Contains(lower, ".cjs"), strings.Contains(lower, ".jsx"), strings.Contains(lower, ".ts"):
		return "js"
	case strings.HasSuffix(lower, ".php"), strings.Contains(lower, ".php?"):
		return "php"
	case strings.HasSuffix(lower, ".java"):
		return "java"
	case strings.HasSuffix(lower, ".py"):
		return "python"
	}
	head := src
	if len(head) > 2048 {
		head = head[:2048]
	}
	switch {
	case strings.Contains(head, "<?php"):
		return "php"
	case strings.Contains(head, "import java."), strings.Contains(head, "public class "):
		return "java"
	case strings.Contains(head, "def "), strings.Contains(head, "import os"):
		return "python"
	default:
		return "js"
	}
}

// scanAuditSource 是纯函数（无 IO），便于单测。
func scanAuditSource(src, language string) auditSourceResult {
	spec := auditSpecFor(language)
	masked := maskAuditSource(src, language)
	lines := strings.Split(src, "\n")
	starts := auditLineStarts(masked)

	res := auditSourceResult{Status: "success", Language: language, Bytes: len(src)}
	res.Sinks = auditMatches(masked, starts, lines, spec.Sinks, auditSourceMaxHits)
	res.Sources = auditMatches(masked, starts, lines, spec.Sources, auditSourceMaxHits)
	res.Flows = auditFlows(res.Sinks, res.Sources, lines, auditSourceMaxFlows)

	concat := 0
	for _, f := range res.Flows {
		if f.Concatenated {
			concat++
		}
	}
	res.Summary = fmt.Sprintf("发现 %d 个 sink、%d 个外部 source，%d 条 Source→Sink 候选（其中 %d 条同语句拼接）",
		len(res.Sinks), len(res.Sources), len(res.Flows), concat)
	if len(res.Sinks) == 0 {
		res.Summary += "；当前切片没有危险函数，换文件/换 bundle 再审计，不要凭猜测写 EXP"
	} else if concat == 0 {
		res.Summary += "；没有同语句拼接的 sink：先确认 source 是否能进入 sink 参数，再决定是否写 EXP"
	}
	res.Notes = []string{
		"flows[].sink_line / source_line 是原始文件行号（1 起），可直接作为 record_fact 的证据",
		"concatenated=true 的 flow 优先级最高：危险函数参数由外部输入拼接",
		"sink 命中不等于漏洞：必须证明 source 可控且能到达 sink",
	}
	return res
}

func auditSpecFor(language string) auditLangSpec {
	switch language {
	case "php":
		return auditPHP
	case "java":
		return auditJava
	case "python":
		return auditPython
	default:
		return auditJS
	}
}

func auditLineStarts(s string) []int {
	starts := []int{0}
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			starts = append(starts, i+1)
		}
	}
	return starts
}

func auditLineAt(starts []int, off int) int {
	return sort.Search(len(starts), func(i int) bool { return starts[i] > off })
}

func auditMatches(masked string, starts []int, lines []string, pats []auditPattern, limit int) []auditHit {
	var out []auditHit
	seen := map[string]bool{}
	for _, p := range pats {
		for _, loc := range p.Re.FindAllStringIndex(masked, limit) {
			ln := auditLineAt(starts, loc[0])
			key := fmt.Sprintf("%d|%s", ln, p.Name)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, auditHit{Line: ln, Kind: p.Name, Code: auditLineSnippet(lines, ln), Pattern: p.Re.String()})
			if len(out) >= limit {
				sort.Slice(out, func(i, j int) bool { return out[i].Line < out[j].Line })
				return out
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Line == out[j].Line {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Line < out[j].Line
	})
	return out
}

func auditLineSnippet(lines []string, line int) string {
	if line < 1 || line > len(lines) {
		return ""
	}
	s := strings.TrimSpace(lines[line-1])
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

func auditFlows(sinks, sources []auditHit, lines []string, limit int) []auditFlow {
	var out []auditFlow
	for _, sink := range sinks {
		best := auditHit{}
		bestDist := auditSourceWindow + 1
		for _, src := range sources {
			d := auditAbs(sink.Line - src.Line)
			if d <= auditSourceWindow && (d < bestDist || (d == bestDist && src.Line <= sink.Line)) {
				best, bestDist = src, d
			}
		}
		concat := auditIsConcatenated(lines, sink.Line) || (best.Line > 0 && best.Line == sink.Line)
		// 跨行数据流：source 先被拼进变量（如 $cmd = "ping ".$_GET['ip']），
		// 下一两行再进 sink（system($cmd)）。这类同样是「危险函数拼接」。
		if !concat && best.Line > 0 && auditAbs(best.Line-sink.Line) <= 5 && auditIsConcatenated(lines, best.Line) {
			concat = true
		}
		if best.Line == 0 && !concat {
			continue
		}
		out = append(out, auditFlow{
			SinkLine: sink.Line, SourceLine: best.Line,
			Sink: sink.Kind, Source: best.Kind, Concatenated: concat,
			Snippet: auditSnippetAround(lines, sink.Line, 1),
		})
		if len(out) >= limit {
			break
		}
	}
	return out
}

func auditIsConcatenated(lines []string, line int) bool {
	if line < 1 || line > len(lines) {
		return false
	}
	code := lines[line-1]
	for _, re := range auditConcatMarkers {
		if re.MatchString(code) {
			return true
		}
	}
	return false
}

func auditSnippetAround(lines []string, line, radius int) string {
	from, to := line-radius, line+radius
	if from < 1 {
		from = 1
	}
	if to > len(lines) {
		to = len(lines)
	}
	var b strings.Builder
	for i := from; i <= to; i++ {
		fmt.Fprintf(&b, "%d: %s\n", i, strings.TrimRight(lines[i-1], "\r"))
	}
	s := b.String()
	if len(s) > 1200 {
		s = s[:1200] + "\n...[snippet 截断]"
	}
	return s
}

func auditAbs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// ---------- 源码遮罩：去掉注释/字符串，避免把注释里的 eval 当成 sink ----------

func maskAuditSource(src, language string) string {
	if language == "python" {
		return maskAuditPython(src)
	}
	b := []byte(src)
	out := make([]byte, len(b))
	copy(out, b)
	n := len(b)
	blank := func(from, to int) {
		if from < 0 {
			from = 0
		}
		if to > n {
			to = n
		}
		for k := from; k < to; k++ {
			if out[k] != '\n' && out[k] != '\r' {
				out[k] = ' '
			}
		}
	}
	i := 0
	for i < n {
		c := b[i]
		switch {
		case c == '/' && i+1 < n && b[i+1] == '/':
			j := i
			for j < n && b[j] != '\n' {
				j++
			}
			blank(i, j)
			i = j
		case c == '/' && i+1 < n && b[i+1] == '*':
			j := i + 2
			for j+1 < n && !(b[j] == '*' && b[j+1] == '/') {
				j++
			}
			if j+1 < n {
				j += 2
			}
			blank(i, j)
			i = j
		case c == '#' && language == "php":
			j := i
			for j < n && b[j] != '\n' {
				j++
			}
			blank(i, j)
			i = j
		case c == '\'' || c == '"' || (c == '`' && language == "js"):
			q := c
			j := i + 1
			for j < n {
				if b[j] == '\\' {
					j += 2
					continue
				}
				if b[j] == q {
					j++
					break
				}
				j++
			}
			if j > n {
				j = n
			}
			blank(i+1, j-1)
			i = j
		default:
			i++
		}
	}
	return string(out)
}

func maskAuditPython(src string) string {
	b := []byte(src)
	out := make([]byte, len(b))
	copy(out, b)
	n := len(b)
	blank := func(from, to int) {
		if from < 0 {
			from = 0
		}
		if to > n {
			to = n
		}
		for k := from; k < to; k++ {
			if out[k] != '\n' && out[k] != '\r' {
				out[k] = ' '
			}
		}
	}
	i := 0
	for i < n {
		c := b[i]
		switch {
		case c == '#':
			j := i
			for j < n && b[j] != '\n' {
				j++
			}
			blank(i, j)
			i = j
		case c == '\'' || c == '"':
			triple := i+2 < n && b[i+1] == c && b[i+2] == c
			if triple {
				j := i + 3
				for j+2 < n && !(b[j] == c && b[j+1] == c && b[j+2] == c) {
					j++
				}
				if j+2 < n {
					j += 3
				} else {
					j = n
				}
				blank(i+1, j-1)
				i = j
				continue
			}
			j := i + 1
			for j < n {
				if b[j] == '\\' {
					j += 2
					continue
				}
				if b[j] == c || b[j] == '\n' {
					j++
					break
				}
				j++
			}
			if j > n {
				j = n
			}
			blank(i+1, j-1)
			i = j
		default:
			i++
		}
	}
	return string(out)
}
