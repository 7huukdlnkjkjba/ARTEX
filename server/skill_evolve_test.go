package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// newSkillEvolveServer 起一个只带临时技能目录的 Server（这些工具不依赖 Manager）。
func newSkillEvolveServer(t *testing.T) *Server {
	t.Helper()
	return &Server{skillDir: t.TempDir()}
}

// TestSkillDraftWritesScriptAndSkillMD 覆盖 skill_draft 的落盘语义：
// <skillDir>/dynamic/<name>/<name>.sh 与同目录 SKILL.md 都要生成。
func TestSkillDraftWritesScriptAndSkillMD(t *testing.T) {
	s := newSkillEvolveServer(t)
	in, _ := json.Marshal(map[string]any{
		"name":        "waf-bypass-x",
		"description": "分块传输绕过某云 WAF 的 UNION 拦截",
		"code":        "#!/usr/bin/env bash\necho bypassed\n",
		"lang":        "sh",
	})
	res, err := s.toolSkillDraft().Call(context.Background(), in, nil)
	if err != nil || res.IsError {
		t.Fatalf("skill_draft: err=%v res=%+v", err, res)
	}
	script := filepath.Join(s.skillDir, "dynamic", "waf-bypass-x", "waf-bypass-x.sh")
	b, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("脚本未落盘: %v", err)
	}
	if !strings.Contains(string(b), "echo bypassed") {
		t.Fatalf("脚本内容不对: %s", b)
	}
	md, err := os.ReadFile(filepath.Join(s.skillDir, "dynamic", "waf-bypass-x", "SKILL.md"))
	if err != nil {
		t.Fatalf("SKILL.md 未生成: %v", err)
	}
	if !strings.Contains(string(md), "name: waf-bypass-x") || !strings.Contains(string(md), "分块传输") {
		t.Fatalf("SKILL.md 内容不对:\n%s", md)
	}
}

func TestSkillDraftRejectsBadInput(t *testing.T) {
	s := newSkillEvolveServer(t)
	cases := []map[string]any{
		{"name": "../etc/passwd", "description": "x", "code": "echo x"},
		{"name": "Bad Name", "description": "x", "code": "echo x"},
		{"name": "ok", "description": "x", "code": ""},
		{"name": "ok", "description": "x", "code": "echo x", "lang": "go"},
	}
	for i, c := range cases {
		in, _ := json.Marshal(c)
		res, err := s.toolSkillDraft().Call(context.Background(), in, nil)
		if err != nil {
			t.Fatalf("case %d unexpected err: %v", i, err)
		}
		if !res.IsError {
			t.Fatalf("case %d 应该被拒绝: %+v", i, c)
		}
	}
}

// TestSkillTestExecutesScript 验证 skill_test 是真实执行入口：拿到 stdout 与 exit code。
func TestSkillTestExecutesScript(t *testing.T) {
	if posixShell() == "" {
		t.Skip("没有可用的 bash/sh，跳过执行测试")
	}
	s := newSkillEvolveServer(t)
	draft, _ := json.Marshal(map[string]any{
		"name":        "echo-probe",
		"description": "打印参数",
		"code":        "#!/usr/bin/env bash\necho \"probe:$1\"\nexit 0\n",
		"lang":        "sh",
	})
	if r, err := s.toolSkillDraft().Call(context.Background(), draft, nil); err != nil || r.IsError {
		t.Fatalf("draft: %v %+v", err, r)
	}

	in, _ := json.Marshal(map[string]any{"name": "echo-probe", "args": "hello"})
	res, err := s.toolSkillTest().Call(context.Background(), in, nil)
	if err != nil || res.IsError {
		t.Fatalf("skill_test: err=%v res=%+v", err, res)
	}
	out := res.Flatten()
	var got struct {
		Status   string `json:"status"`
		ExitCode int    `json:"exit_code"`
		Output   string `json:"output"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("结果不是 JSON: %v\n%s", err, out)
	}
	if got.ExitCode != 0 || got.Status != "success" {
		t.Fatalf("exit=%d status=%s output=%q", got.ExitCode, got.Status, got.Output)
	}
	if !strings.Contains(got.Output, "probe:hello") {
		t.Fatalf("没拿到真实 stdout: %q", got.Output)
	}
}

// TestSkillTestMissingScript：没先 draft 就 test，必须报错而不是空跑。
func TestSkillTestMissingScript(t *testing.T) {
	s := newSkillEvolveServer(t)
	in, _ := json.Marshal(map[string]any{"name": "nope"})
	res, err := s.toolSkillTest().Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !res.IsError {
		t.Fatalf("缺脚本应报错: %+v", res)
	}
}

// TestSkillPromoteRegistersTool 需要 PostgreSQL；没有库时跳过。
func TestSkillPromoteRegistersTool(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer pg.Close()

	s := newSkillEvolveServer(t)
	s.m = &Manager{pg: pg}
	draft, _ := json.Marshal(map[string]any{
		"name":        "promote-probe",
		"description": "晋升测试",
		"code":        "#!/usr/bin/env bash\necho ok\n",
		"lang":        "sh",
	})
	if r, err := s.toolSkillDraft().Call(context.Background(), draft, nil); err != nil || r.IsError {
		t.Fatalf("draft: %v %+v", err, r)
	}
	in, _ := json.Marshal(map[string]any{"name": "promote-probe"})
	res, err := s.toolSkillPromote().Call(context.Background(), in, nil)
	if err != nil || res.IsError {
		t.Fatalf("promote: err=%v res=%+v", err, res)
	}
	row, err := pg.GetTool("sk_promote_probe")
	if err != nil || row == nil {
		t.Fatalf("tools 行没写进去: %v %+v", err, row)
	}
	if row.Kind != "command" || row.System {
		t.Fatalf("晋升行应为自定义 command 工具: kind=%s system=%v", row.Kind, row.System)
	}
	if len(row.Agents) != 1 || row.Agents[0] != "worker" {
		t.Fatalf("默认应绑 worker: %v", row.Agents)
	}
	_ = pg.DeleteCustomTool("sk_promote_probe")
}

// TestSkillPromoteWithoutDB：没有库时明确报错，不 panic。
func TestSkillPromoteWithoutDB(t *testing.T) {
	s := newSkillEvolveServer(t)
	in, _ := json.Marshal(map[string]any{"name": "x"})
	res, err := s.toolSkillPromote().Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !res.IsError {
		t.Fatalf("无 DB 应报错: %+v", res)
	}
}

// promotedPythonSource 必须幂等，且 shebang 仍在第一行（否则直接执行会坏）。
func TestPromotedPythonSource(t *testing.T) {
	plain := "print('hi')\n"
	once := promotedPythonSource(plain)
	if !strings.Contains(once, "ARTEX_PROMOTED_ARGV") || !strings.Contains(once, plain) {
		t.Fatalf("垫片未插入: %s", once)
	}
	if twice := promotedPythonSource(once); twice != once {
		t.Fatal("重复晋升不应重复插入垫片")
	}

	shebang := "#!/usr/bin/env python3\nprint('hi')\n"
	got := promotedPythonSource(shebang)
	if !strings.HasPrefix(got, "#!/usr/bin/env python3\n") {
		t.Fatalf("shebang 被破坏: %q", got[:40])
	}
	if !strings.Contains(got, "ARTEX_PROMOTED_ARGV") {
		t.Fatal("shebang 场景未插入垫片")
	}
}

// 晋升后的 Python 工具必须真的拿到 argv：自定义 script 工具只给 stdin/TOOL_ARGS，
// 垫片负责还原。这里直接跑 execPython，验证 args → argv 的整条链路。
func TestPromotedPythonToolGetsArgv(t *testing.T) {
	interp := detectPython()
	if interp == "" {
		t.Skip("本机没有可用 python，跳过")
	}
	code := promotedPythonSource("import sys\nprint('|'.join(sys.argv[1:]))\n")
	out, err := execPython(context.Background(), interp, "sk_argv_probe", code,
		map[string]any{"args": `--target http://x --param "a b"`}, t.TempDir(), nil, 20000000000)
	if err != nil {
		t.Fatalf("execPython: %v", err)
	}
	if !strings.Contains(out, "--target|http://x|--param|a b") {
		t.Fatalf("晋升工具没有拿到 argv: %q", out)
	}
}
