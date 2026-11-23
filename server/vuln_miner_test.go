package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func TestVulnMinerIntentPayload(t *testing.T) {
	payload := vulnMinerIntentPayload("https://shop.example.com", "waf_bypass",
		"waf_bypass_shop_example_com", "403 Forbidden", "Cloudflare blocked POST /api/login", []int64{7})
	for k, want := range map[string]string{
		"action": vulnMinerAction,
		"target": "https://shop.example.com",
		"reason": "waf_bypass",
		"skill":  "waf_bypass_shop_example_com",
	} {
		if got, _ := payload[k].(string); got != want {
			t.Fatalf("payload[%s] = %q, want %q", k, got, want)
		}
	}
	if s, _ := payload["summary"].(string); !strings.Contains(s, "sk_waf_bypass_shop_example_com") {
		t.Fatalf("summary 未带晋升后的工具 key: %q", s)
	}
	if s, _ := payload["instruction"].(string); !strings.Contains(s, "skill_promote") {
		t.Fatalf("instruction 未要求固化: %q", s)
	}
	if ids, _ := payload["asset_ids"].([]int64); len(ids) != 1 || ids[0] != 7 {
		t.Fatalf("asset_ids 未透传: %v", payload["asset_ids"])
	}
	if s, _ := payload["evidence"].(string); !strings.Contains(s, "Cloudflare") {
		t.Fatalf("evidence 未透传: %q", s)
	}
}

func TestFirstURLInText(t *testing.T) {
	cases := []struct{ in, want string }{
		{"WAF 拦截 http://10.0.0.5:8080/admin，返回 403", "http://10.0.0.5:8080/admin"},
		{"见 https://a.example.com/x.js。", "https://a.example.com/x.js"},
		{"没有链接", ""},
	}
	for _, c := range cases {
		if got := firstURLInText(c.in); got != c.want {
			t.Fatalf("firstURLInText(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestVulnMinerSkillName(t *testing.T) {
	cases := []struct{ target, reason, want string }{
		{"https://shop.example.com/x.js", "waf_bypass", "waf_bypass_shop_example_com"},
		{"http://10.0.0.5:8080/api", "waf_bypass", "waf_bypass_10_0_0_5"},
		{"https://a.example.com:8443/a?b=1", "source_exposure", "src_exp_a_example_com"},
		{"", "logic_flaw", "logic_exp_target"},
		{strings.Repeat("a", 100), "waf_bypass", "waf_bypass_" + strings.Repeat("a", 53)},
	}
	for _, c := range cases {
		got := vulnMinerSkillName(c.target, c.reason)
		if got != c.want {
			t.Fatalf("vulnMinerSkillName(%q,%q) = %q, want %q", c.target, c.reason, got, c.want)
		}
		if !reDynamicSkillName.MatchString(got) {
			t.Fatalf("技能名不合法: %q", got)
		}
		if key := skillToolKey(got); key == "" || !strings.HasPrefix(key, "sk_") {
			t.Fatalf("工具 key 非法: %q -> %q", got, key)
		}
	}
}

func TestClassifyVulnMinerSignal(t *testing.T) {
	cases := []struct {
		name  string
		texts []string
		want  string
	}{
		{"waf", []string{"目标返回 403 Forbidden，疑似 Cloudflare 拦截"}, "waf_bypass"},
		{"chinese-waf", []string{"请求被安全狗拦截"}, "waf_bypass"},
		{"source", []string{"发现 app.chunk.js 与 sourcemap 暴露"}, "source_exposure"},
		{"logic", []string{"debug=true 时报错泄露 stack trace"}, "logic_flaw"},
		{"none", []string{"端口关闭", "连接超时"}, ""},
	}
	for _, c := range cases {
		if got := classifyVulnMinerSignal(c.texts...); got != c.want {
			t.Fatalf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestVulnMinerQueueAllowed(t *testing.T) {
	cases := []struct {
		name       string
		state      string
		fails      int
		dispatched int
		reason     string
		want       bool
	}{
		{"blocked+waf", "blocked", 1, 0, "waf_bypass", true},
		{"exhausted+source", "exhausted", 2, 0, "source_exposure", true},
		{"done", "done", 3, 0, "waf_bypass", false},
		{"no-failure", "blocked", 0, 0, "waf_bypass", false},
		{"cap-reached", "blocked", 3, vulnMinerMaxPerTask, "waf_bypass", false},
		{"no-signal", "blocked", 3, 0, "", false},
	}
	for _, c := range cases {
		if got := vulnMinerQueueAllowed(c.state, c.fails, c.dispatched, c.reason); got != c.want {
			t.Fatalf("%s: vulnMinerQueueAllowed(%q,%d,%d,%q) = %v, want %v",
				c.name, c.state, c.fails, c.dispatched, c.reason, got, c.want)
		}
	}
}

func TestIntentIsVulnMinerPayload(t *testing.T) {
	if !intentIsVulnMiner(&db.Node{Payload: []byte(`{"action":"vuln_miner"}`)}) {
		t.Fatal("action=vuln_miner 应被识别")
	}
	if intentIsVulnMiner(&db.Node{Payload: []byte(`{"action":"self_evolve"}`)}) {
		t.Fatal("self_evolve 不应被当成 vuln_miner")
	}
	if intentIsVulnMiner(nil) {
		t.Fatal("nil 意图不应被识别")
	}
}

func TestScanAuditSourceJS(t *testing.T) {
	src := "const p = new URLSearchParams(location.hash.slice(1));\n" +
		"// eval(userInput) 只是注释，不算 sink\n" +
		"const out = eval(\"var x=\" + p.get(\"q\"));\n" +
		"document.querySelector(\"#a\").innerHTML = p.get(\"q\");\n"
	res := scanAuditSource(src, "js")
	if res.Status != "success" || res.Language != "js" {
		t.Fatalf("unexpected result: %+v", res)
	}
	var evalLine, innerLine int
	for _, s := range res.Sinks {
		switch s.Kind {
		case "js_eval":
			evalLine = s.Line
		case "js_innerhtml":
			innerLine = s.Line
		}
	}
	if evalLine != 3 {
		t.Fatalf("eval sink 行号 = %d, want 3（注释里的 eval 不能算）", evalLine)
	}
	if innerLine != 4 {
		t.Fatalf("innerHTML sink 行号 = %d, want 4", innerLine)
	}
	if len(res.Flows) == 0 {
		t.Fatal("应当至少有一条 Source→Sink flow")
	}
	concat := 0
	for _, f := range res.Flows {
		if f.Concatenated {
			concat++
		}
	}
	if concat == 0 {
		t.Fatal("eval(\"var x=\" + ...) 应标记为同语句拼接")
	}
	if !strings.Contains(res.Summary, "sink") {
		t.Fatalf("summary 缺少统计: %q", res.Summary)
	}
}

func TestScanAuditSourcePHPCrossLineConcat(t *testing.T) {
	src := "<?php\n" +
		"$cmd = \"ping \" . $_GET['ip'];\n" +
		"system($cmd);\n"
	res := scanAuditSource(src, "php")
	if len(res.Sinks) != 1 || res.Sinks[0].Kind != "php_cmd" {
		t.Fatalf("php sink 识别失败: %+v", res.Sinks)
	}
	if len(res.Flows) != 1 {
		t.Fatalf("php flow 数量 = %d, want 1: %+v", len(res.Flows), res.Flows)
	}
	if !res.Flows[0].Concatenated {
		t.Fatal("source 行拼接后流入 sink，应标记 concatenated")
	}
}

func TestVulnMinerPromptRenders(t *testing.T) {
	sys := agent.RenderPrompt("vuln_miner", agent.VulnMinerDefault, vulnMinerPromptVars{
		Target: "https://shop.example.com", Reason: "waf_bypass",
		Skill: "waf_bypass_shop_example_com", ToolKey: "sk_waf_bypass_shop_example_com",
		Workspace: "C:/data/tasks/1/vuln-miner/2", Now: agent.NowString(),
	})
	for _, want := range []string{
		"https://shop.example.com", "waf_bypass_shop_example_com", "sk_waf_bypass_shop_example_com",
		"audit_source", "web_audit", "skill_draft", "skill_test", "skill_promote",
	} {
		if !strings.Contains(sys, want) {
			t.Fatalf("vuln_miner 提示词缺少 %q", want)
		}
	}
	if strings.Contains(sys, "{{.") {
		t.Fatal("提示词仍有未渲染的模板变量")
	}
}

func TestPromotePolicyApply(t *testing.T) {
	var got *promotedTool
	p := &promotePolicy{
		DescriptionSuffix: "；适用目标 https://x",
		Agents:            []string{"worker"},
		OnPromoted:        func(pt promotedTool) { got = &pt },
	}
	desc, agents := p.apply("desc", []string{"planner"})
	if !strings.Contains(desc, "适用目标") {
		t.Fatalf("描述未附加后缀: %q", desc)
	}
	if len(agents) != 1 || agents[0] != "worker" {
		t.Fatalf("agents 未覆盖: %v", agents)
	}
	p.OnPromoted(promotedTool{Key: "sk_x"})
	if got == nil || got.Key != "sk_x" {
		t.Fatal("OnPromoted 未回调")
	}

	// 无策略时保持原样
	var nilPolicy *promotePolicy
	desc2, agents2 := nilPolicy.apply("d", []string{"a"})
	if desc2 != "d" || len(agents2) != 1 || agents2[0] != "a" {
		t.Fatalf("nil policy 改变了入参: %q %v", desc2, agents2)
	}

	// context 往返
	ctx := withPromotePolicy(context.Background(), p)
	if promotePolicyFrom(ctx) != p {
		t.Fatal("promotePolicy ctx 往返失败")
	}
	if promotePolicyFrom(context.Background()) != nil {
		t.Fatal("空 ctx 不应取到策略")
	}
}

func TestAuditSourceToolLocalFile(t *testing.T) {
	s := &Server{skillDir: t.TempDir()}
	path := filepath.Join(t.TempDir(), "app.js")
	src := "const q = location.search;\neval(\"1+\" + q);\n"
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	in, _ := json.Marshal(map[string]any{"target": path, "language": "js"})
	res, err := s.toolAuditSource().Call(context.Background(), in, nil)
	if err != nil || res.IsError {
		t.Fatalf("audit_source: err=%v res=%+v", err, res)
	}
	out := res.Flatten()
	for _, want := range []string{"js_eval", "js_location", "flows", "sink_line"} {
		if !strings.Contains(out, want) {
			t.Fatalf("audit_source 输出缺少 %q: %s", want, out)
		}
	}
}

func TestAuditSourceToolURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, "const q = location.hash;\neval('x' + q);\n")
	}))
	defer srv.Close()

	s := &Server{skillDir: t.TempDir()}
	in, _ := json.Marshal(map[string]any{"target": srv.URL + "/app.js", "language": "js"})
	res, err := s.toolAuditSource().Call(context.Background(), in, nil)
	if err != nil || res.IsError {
		t.Fatalf("audit_source(url): err=%v res=%+v", err, res)
	}
	out := res.Flatten()
	if !strings.Contains(out, "js_eval") {
		t.Fatalf("URL 抓取后未识别 sink: %s", out)
	}
}

func TestAuditSourceToolRejectsDir(t *testing.T) {
	s := &Server{skillDir: t.TempDir()}
	in, _ := json.Marshal(map[string]any{"target": t.TempDir()})
	res, err := s.toolAuditSource().Call(context.Background(), in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("目录应返回错误，而不是静默成功")
	}
}

func TestGhidraValidation(t *testing.T) {
	s := &Server{skillDir: t.TempDir()}
	in, _ := json.Marshal(map[string]any{"binary_path": filepath.Join(t.TempDir(), "missing.bin")})
	res, err := s.toolGhidraDecompile().Call(context.Background(), in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("不存在的二进制应返回错误")
	}
}

func TestFindGhidraHomeEnvOverride(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "support"), 0o755); err != nil {
		t.Fatal(err)
	}
	headless := filepath.Join(home, "support", "analyzeHeadless.bat")
	if err := os.WriteFile(headless, []byte("@echo off\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_GHIDRA_HOME", home)
	if got := findGhidraHome(); got != home {
		t.Fatalf("findGhidraHome() = %q, want %q", got, home)
	}
	if got := ghidraHeadlessPath(home); got != headless && !strings.HasSuffix(got, "analyzeHeadless") {
		t.Fatalf("ghidraHeadlessPath() = %q", got)
	}

	// 无效目录必须判负，避免把任意路径当 Ghidra。
	if ghidraHeadlessPath(t.TempDir()) != "" {
		t.Fatal("没有 support/analyzeHeadless 的目录不应被接受")
	}
}

func TestParseJavaMajor(t *testing.T) {
	cases := []struct {
		out  string
		want int
	}{
		{`openjdk version "25.0.2" 2026-01-20`, 25},
		{`openjdk version "17.0.19" 2026-04-21`, 17},
		{`java version "1.8.0_411"`, 1},
		{`no version here`, 0},
	}
	for _, c := range cases {
		if got := parseJavaMajor([]byte(c.out)); got != c.want {
			t.Fatalf("parseJavaMajor(%q) = %d, want %d", c.out, got, c.want)
		}
	}
	if ghidraMinJavaMajor < 21 {
		t.Fatalf("Ghidra 12 需要 JDK 21+，当前门槛 %d", ghidraMinJavaMajor)
	}
}

// TestGhidraDecompileLive 真跑一次内置 Ghidra（约 30-60s）。默认跳过：
// ARTEX_GHIDRA_LIVE=1 时执行，用来验证「工具真的能出伪代码」。
func TestGhidraDecompileLive(t *testing.T) {
	if os.Getenv("ARTEX_GHIDRA_LIVE") != "1" {
		t.Skip("设置 ARTEX_GHIDRA_LIVE=1 才跑真实 Ghidra 分析")
	}
	home := findGhidraHome()
	if home == "" {
		t.Skip("本机没有找到 Ghidra")
	}
	if ghidraJavaHome() == "" {
		t.Skip("本机没有 JDK 21+")
	}
	// 样本优先级：ARTEX_GHIDRA_LIVE_BIN > 当前测试进程二进制。
	// 进程二进制通常带几万函数，分析会很慢；小样本用环境变量指定。
	bin := strings.TrimSpace(os.Getenv("ARTEX_GHIDRA_LIVE_BIN"))
	if bin == "" {
		var err error
		bin, err = os.Executable()
		if err != nil {
			t.Skip("拿不到测试进程二进制")
		}
	}
	if st, err := os.Stat(bin); err != nil || st.Size() > 64<<20 {
		t.Skip("测试二进制不可用或过大")
	}
	s := &Server{skillDir: t.TempDir()}
	in, _ := json.Marshal(map[string]any{"binary_path": bin, "max_functions": 1, "timeout_sec": 600})
	res, err := s.toolGhidraDecompile().Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("toolGhidraDecompile: %v", err)
	}
	if res.IsError {
		t.Fatalf("工具报错: %s", res.Flatten())
	}
	out := res.Flatten()
	if !strings.Contains(out, "pseudocode") {
		t.Fatalf("没有伪代码输出: %s", out)
	}
	// 真伪代码至少要有函数头（// name @ addr）与 C 函数体，避免只看 key 就当成成功。
	if !strings.Contains(out, "// ") || !strings.Contains(out, "@ ") {
		t.Fatalf("伪代码里没有函数头: %s", out)
	}
}
