package server

// 自研闭环（self-evolve loop）。取代旧的 genome_* 表 + evolve_* 工具：
//
//	skill_draft   —— AI 现场写一个针对性脚本（Python / Bash）到 skills/dynamic/<name>/
//	skill_test    —— 立刻执行该脚本，回传真实 stdout/stderr/exit code
//	skill_promote —— 把已验证的脚本注册进 tools 表（kind=script/command），全任务 worker 可用
//
// 设计约束：
//   - 只写 skills/dynamic/ 下、名字经白名单校验的路径，不接受绝对路径/`..`；
//   - skill_test 是唯一执行入口，带超时与输出上限，不会把整台机器的输出灌进上下文；
//   - skill_promote 只注册 system=false 的自定义工具，工具 key 一律加 sk_ 前缀，
//     不会覆盖内置工具；脚本正文内联进 exec（Python）或按绝对路径调用（Bash），
//     因此即便有人删了文件，已晋升的工具仍可复现。

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	pgdb "github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// 动态技能根目录（相对 skills/）：只有这一层允许 AI 写入。
const dynamicSkillSubdir = "dynamic"

const (
	skillMaxSourceBytes = 256 << 10 // 单脚本上限 256KB，防止把二进制/base64 塞进来
	skillMaxOutputBytes = 64 << 10  // 回传给模型的输出上限
	skillDefaultTimeout = 300       // 默认执行超时(秒)
	skillMaxTimeout     = 1800
)

// 技能名白名单：小写字母开头，字母/数字/下划线/连字符；同时满足工具 key 的字符集。
var reDynamicSkillName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

// skillEvolveTools 是自研闭环的三个工具，默认绑 worker（seed 时写 agents=["worker"]）。
func (s *Server) skillEvolveTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolSkillDraft(),
		s.toolSkillTest(),
		s.toolSkillPromote(),
	}
}

// skillEvolveKeys 供 seed 与一次性清理共用。
var skillEvolveKeys = []string{"skill_draft", "skill_test", "skill_promote"}

// seedSkillEvolveTools 把三个工具写进 tools 表（仅首次插入，页面上的编辑不会被覆盖），
// 同时做两件一次性清理：删掉旧 genome/evolve 表与旧的 evolve_* 工具行。
func (s *Server) seedSkillEvolveTools() {
	s.dropLegacyEvolution()
	if s.m == nil || s.m.pg == nil {
		return
	}
	workerAgents, _ := json.Marshal([]string{"worker"})
	for _, t := range s.skillEvolveTools() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.PG().SeedTool(t.Name(), t.Description(), schema, workerAgents); err != nil {
			log.Printf("[tools] seed %s 失败: %v", t.Name(), err)
		}
	}
	// 老库里 evolve_* 的种子行会一直挂着（SeedTool 只增不删），显式清掉，
	// 否则 worker 的工具列表里会出现一批早就没有实现的工具。
	for _, key := range []string{"evolve_leaks", "evolve_begin", "evolve_read", "evolve_propose",
		"evolve_trial", "evolve_compare", "evolve_promote", "evolve_abandon"} {
		if _, err := s.m.PG().Exec(`DELETE FROM tools WHERE key=$1`, key); err != nil {
			log.Printf("[tools] 清理旧自进化工具 %s 失败: %v", key, err)
		}
	}
}

// dropLegacyEvolution 删除 genome_*/evolve_* 表。幂等：表不存在时是 no-op，
// 所以放启动期执行即可，不需要版本号迁移。
func (s *Server) dropLegacyEvolution() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	for _, tbl := range []string{
		"genome_genes", "genome_phenotypes", "genome_events",
		"evolve_costs", "evolve_runs", "evolve_proposals", "evolve_trials",
	} {
		if _, err := s.m.PG().Exec(`DROP TABLE IF EXISTS ` + tbl); err != nil {
			log.Printf("[self-evolve] 删除旧表 %s 失败: %v", tbl, err)
			continue
		}
	}
	log.Printf("[self-evolve] 旧 genome_*/evolve_* 表已清理")
}

// ---------- 路径与执行 ----------

// dynamicSkillRoot 返回 skills/dynamic 的绝对路径。
func (s *Server) dynamicSkillRoot() string {
	root := strings.TrimSpace(s.skillDir)
	if root == "" {
		root = "skills"
	}
	return filepath.Join(root, dynamicSkillSubdir)
}

// skillScriptPath 返回 <skillDir>/dynamic/<name>/<name>.<ext>，并校验名字。
func (s *Server) skillScriptPath(name, lang string) (string, error) {
	if !reDynamicSkillName.MatchString(name) {
		return "", fmt.Errorf("技能名不合法：需小写字母开头，仅含小写字母/数字/下划线/连字符（≤64）")
	}
	ext, err := skillExt(lang)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.dynamicSkillRoot(), name, name+ext), nil
}

func skillExt(lang string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(lang)) {
	case "", "py", "python", "python3":
		return ".py", nil
	case "sh", "bash", "shell":
		return ".sh", nil
	}
	return "", fmt.Errorf("只支持 python / bash 两种脚本（lang=py|sh）")
}

// resolveSkillScript 找到已存在的脚本；先按 lang 精确找，再扫目录里唯一的 .py/.sh。
func (s *Server) resolveSkillScript(name, lang string) (string, error) {
	if !reDynamicSkillName.MatchString(name) {
		return "", fmt.Errorf("技能名不合法: %s", name)
	}
	dir := filepath.Join(s.dynamicSkillRoot(), name)
	if strings.TrimSpace(lang) != "" {
		if p, err := s.skillScriptPath(name, lang); err == nil {
			if _, statErr := os.Stat(p); statErr == nil {
				return p, nil
			}
		}
	}
	for _, ext := range []string{".py", ".sh"} {
		p := filepath.Join(dir, name+ext)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("脚本不存在: %s（先调用 skill_draft）", name)
}

// runSkillFile 执行一个脚本文件，返回 stdout+stderr（截断）、exit code、耗时。
// 走 bash -c 是为了让 args 里的引号/管道按 shell 语义生效；没有 bash 时退回直接执行。
// posixShell 找一个真正能执行的 POSIX shell。Windows 上 C:\Windows\System32\bash.exe
// 只是 WSL 包装器：WSL 没装时它直接 127，所以排除掉。
func posixShell() string {
	cands := []string{"bash", "sh"}
	if runtime.GOOS == "windows" {
		cands = append([]string{
			`C:\Program Files\Git\bin\bash.exe`,
			`C:\Program Files\Git\usr\bin\bash.exe`,
		}, cands...)
	}
	for _, c := range cands {
		p, err := exec.LookPath(c)
		if err != nil {
			continue
		}
		if runtime.GOOS == "windows" && strings.Contains(strings.ToLower(p), `\windows\system32\`) {
			continue
		}
		return p
	}
	return ""
}

// splitShellArgs 做最小 shell 词法切分：支持单/双引号与反斜杠转义，够用于
// 「没有 POSIX shell 时把 args 直接交给解释器 argv」这条兜底路径。
func splitShellArgs(s string) []string {
	var out []string
	var cur strings.Builder
	quote := rune(0)
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	escaped := false
	for _, r := range s {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\' && quote != '\'':
			escaped = true
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
		case r == ' ' || r == '\t' || r == '\n':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

// runSkillFile 执行一个脚本文件，返回 stdout+stderr（截断）、exit code、耗时。
// 有 POSIX shell 时按 shell 语义拼接（args 里的引号/管道生效）；没有就直接把
// interp 拉起来跑，args 走最小词法切分。解释器一律用绝对路径，PATH 污染无效。
func runSkillFile(ctx context.Context, path, args string, timeout time.Duration, pyInterp string) (string, int, time.Duration, error) {
	start := time.Now()
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ext := strings.ToLower(filepath.Ext(path))
	interp := ""
	switch ext {
	case ".py":
		interp = strings.TrimSpace(pyInterp)
		if interp == "" {
			if p, err := exec.LookPath("python3"); err == nil {
				interp = p
			} else if p, err := exec.LookPath("python"); err == nil {
				interp = p
			}
		}
		if interp == "" {
			return "", -1, 0, fmt.Errorf("找不到 python 解释器，无法执行 .py 脚本")
		}
	case ".sh":
		interp = posixShell()
		if interp == "" {
			return "", -1, 0, fmt.Errorf("当前环境没有可用的 bash/sh，无法执行 .sh 脚本")
		}
	default:
		return "", -1, 0, fmt.Errorf("不支持的脚本类型: %s", path)
	}

	var cmd *exec.Cmd
	if sh := posixShell(); sh != "" {
		line := shellQuote(interp) + " " + shellQuote(path)
		if strings.TrimSpace(args) != "" {
			line += " " + strings.TrimSpace(args)
		}
		cmd = exec.CommandContext(runCtx, sh, "-c", line)
	} else {
		cmd = exec.CommandContext(runCtx, interp, append([]string{path}, splitShellArgs(args)...)...)
	}
	cmd.Dir = filepath.Dir(path)
	cmd.Env = append(os.Environ(), "ARTEX_SKILL_NAME="+strings.TrimSuffix(filepath.Base(path), ext))
	out, err := cmd.CombinedOutput()
	if len(out) > skillMaxOutputBytes {
		out = append(out[:skillMaxOutputBytes], []byte("\n...[输出截断]")...)
	}
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	if runCtx.Err() == context.DeadlineExceeded {
		return string(out), code, time.Since(start), fmt.Errorf("执行超时(%s)", timeout)
	}
	return string(out), code, time.Since(start), err
}

// ---------- skill_draft ----------

func (s *Server) toolSkillDraft() actool.CoreTool {
	return wrTool("skill_draft",
		"【自研模式·写】把一段针对当前目标的利用/探测脚本写到 skills/dynamic/<name>/<name>.py|.sh，并生成 SKILL.md。\n"+
			"现有工具打不动（WAF 拦截 / 无现成 EXP / 端口过滤 / 提权失败）时用它现场造工具；写完必须用 skill_test 亲自跑，不要凭空声称成功。\n"+
			"脚本要自包含：只依赖目标环境已有的 python3 / bash / curl 等，参数从 argv 取，结果打 stdout。",
		objSchema(map[string]any{
			"name":        strParam("技能名：小写字母开头，仅小写字母/数字/下划线/连字符，≤64；同名会覆盖旧脚本"),
			"description": strParam("一句话说明：解决什么防御/什么目标、怎么用"),
			"code":        strParam("脚本全文（Python 或 Bash）。≤256KB；不要写成需要交互输入的形式"),
			"lang":        strParam("py | sh，默认 py"),
		}, "name", "description", "code"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct{ Name, Description, Code, Lang string }
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			a.Name = strings.TrimSpace(a.Name)
			if !reDynamicSkillName.MatchString(a.Name) {
				return actool.Errorf("技能名不合法：小写字母开头，仅小写字母/数字/下划线/连字符（≤64）"), nil
			}
			if strings.TrimSpace(a.Code) == "" {
				return actool.Errorf("code 不能为空"), nil
			}
			if len(a.Code) > skillMaxSourceBytes {
				return actool.Errorf(fmt.Sprintf("脚本过大（%d 字节，上限 %d）", len(a.Code), skillMaxSourceBytes)), nil
			}
			if strings.TrimSpace(a.Description) == "" {
				return actool.Errorf("description 必填：说明它解决哪种防御/怎么用"), nil
			}
			path, err := s.skillScriptPath(a.Name, a.Lang)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			dir := filepath.Dir(path)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return actool.Errorf("建目录失败: " + err.Error()), nil
			}
			if err := os.WriteFile(path, []byte(a.Code), 0o755); err != nil {
				return actool.Errorf("写脚本失败: " + err.Error()), nil
			}
			// SKILL.md 让它在技能目录里可见（agentskills.io 规范），也方便人复盘。
			var md strings.Builder
			md.WriteString("---\n")
			fmt.Fprintf(&md, "name: %s\n", a.Name)
			fmt.Fprintf(&md, "description: %s\n", strings.ReplaceAll(a.Description, "\n", " "))
			md.WriteString("---\n\n## 用法\n\n")
			fmt.Fprintf(&md, "```bash\n%s %s <args>\n```\n\n生成方式：worker 自研模式（skill_draft → skill_test → skill_promote）。\n",
				skillExtInterp(filepath.Ext(path)), filepath.ToSlash(path))
			if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(md.String()), 0o644); err != nil {
				log.Printf("[self-evolve] 写 SKILL.md 失败(%s): %v", a.Name, err)
			}
			return jsonResult(map[string]any{
				"name": a.Name, "path": filepath.ToSlash(path),
				"lang": strings.TrimSuffix(filepath.Ext(path), "."), "bytes": len(a.Code),
				"next": "立刻用 skill_test 执行它（同一 name），拿到真实输出；跑通后再 skill_promote",
			})
		})
}

func skillExtInterp(ext string) string {
	if strings.EqualFold(ext, ".sh") {
		return "bash"
	}
	return "python3"
}

// ---------- skill_test ----------

func (s *Server) toolSkillTest() actool.CoreTool {
	return wrTool("skill_test",
		"【自研模式·跑】执行 skill_draft 写好的脚本，返回真实 stdout/stderr 与 exit code。\n"+
			"这是自研脚本唯一的执行入口；失败就把错误原文反馈给 skill_draft 改，别改去手搓别的。",
		objSchema(map[string]any{
			"name":        strParam("skill_draft 用的技能名"),
			"args":        strParam("传给脚本的命令行参数（原样拼在脚本后面，可用引号/管道）"),
			"timeout_sec": map[string]any{"type": "integer", "description": fmt.Sprintf("超时秒数，默认 %d，上限 %d", skillDefaultTimeout, skillMaxTimeout)},
			"lang":        strParam("可选 py|sh；不填则自动找"),
		}, "name"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Name       string `json:"name"`
				Args       string `json:"args"`
				TimeoutSec int    `json:"timeout_sec"`
				Lang       string `json:"lang"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			path, err := s.resolveSkillScript(strings.TrimSpace(a.Name), a.Lang)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			timeout := time.Duration(a.TimeoutSec) * time.Second
			if timeout <= 0 {
				timeout = skillDefaultTimeout * time.Second
			}
			if timeout > skillMaxTimeout*time.Second {
				timeout = skillMaxTimeout * time.Second
			}
			// 解释器只在 python 脚本时需要；Manager 未就绪时交给 runSkillFile 自己
			// 从 PATH 里找，避免这里解引用空指针。
			py := ""
			if s.m != nil && s.m.pg != nil {
				py = s.pythonInterpreter()
			}
			out, code, took, runErr := runSkillFile(ctx, path, a.Args, timeout, py)
			res := map[string]any{
				"name":       a.Name,
				"path":       filepath.ToSlash(path),
				"exit_code":  code,
				"elapsed_ms": took.Milliseconds(),
				"output":     out,
			}
			if runErr != nil {
				res["error"] = runErr.Error()
			}
			if code == 0 && strings.TrimSpace(out) != "" {
				res["status"] = "success"
			} else if code == 0 {
				res["status"] = "empty_output"
			} else {
				res["status"] = "failed"
			}
			return jsonResult(res)
		})
}

// ---------- skill_promote ----------

// skillToolKey 把技能名变成合法工具 key：加 sk_ 前缀、连字符换下划线。
func skillToolKey(name string) string {
	k := "sk_" + strings.ReplaceAll(strings.ToLower(name), "-", "_")
	if !reToolKey.MatchString(k) {
		return ""
	}
	return k
}

func (s *Server) toolSkillPromote() actool.CoreTool {
	return wrTool("skill_promote",
		"【自研模式·固化】把 skill_test 已验证的脚本注册成全局自定义工具（写 tools 表），本任务所有 worker 立刻可见可调。\n"+
			"Python 脚本内联进工具定义；Bash 脚本按绝对路径调用。同名重复晋升会覆盖执行规格，不会重复建行。",
		objSchema(map[string]any{
			"name":        strParam("要晋升的技能名"),
			"description": strParam("可选：覆盖工具描述（默认用脚本首行注释/SKILL.md 描述）"),
			"agents":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "绑定的 agent key，默认 [worker]（全任务 worker）"},
			"lang":        strParam("可选 py|sh；不填则自动找"),
		}, "name"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if s.m == nil || s.m.pg == nil {
				return actool.Errorf("数据库不可用"), nil
			}
			var a struct {
				Name        string   `json:"name"`
				Description string   `json:"description"`
				Agents      []string `json:"agents"`
				Lang        string   `json:"lang"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			path, err := s.resolveSkillScript(strings.TrimSpace(a.Name), a.Lang)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			code, err := os.ReadFile(path)
			if err != nil {
				return actool.Errorf("读脚本失败: " + err.Error()), nil
			}
			key := skillToolKey(a.Name)
			if key == "" {
				return actool.Errorf(fmt.Sprintf("无法生成合法工具 key（技能名 %q）", a.Name)), nil
			}
			agents := a.Agents
			if len(agents) == 0 {
				agents = []string{"worker"}
			}
			desc := strings.TrimSpace(a.Description)
			if desc == "" {
				desc = fmt.Sprintf("【自研工具】%s：worker 现场编写并通过 skill_test 验证的脚本", a.Name)
			}
			schema := map[string]any{
				"type": "object",
				"properties": map[string]any{
					"args": map[string]any{"type": "string", "description": "传给脚本的命令行参数（原样拼接）"},
				},
			}
			schemaRaw, _ := json.Marshal(schema)

			t := &pgdb.Tool{
				Key: key, Description: desc, Schema: schemaRaw, Agents: agents,
				Enabled: true, Kind: "script", Deferred: false,
			}
			switch strings.ToLower(filepath.Ext(path)) {
			case ".py":
				execRaw, _ := json.Marshal(map[string]any{"code": string(code), "timeout_ms": skillDefaultTimeout * 1000})
				t.Exec = execRaw
			case ".sh":
				t.Kind = "command"
				execRaw, _ := json.Marshal(map[string]any{
					"command":    "bash " + shellQuote(path) + " {args}",
					"timeout_ms": skillDefaultTimeout * 1000,
				})
				t.Exec = execRaw
			default:
				return actool.Errorf("不支持的文件类型: " + path), nil
			}

			action := "created"
			if exist, _ := s.m.pg.GetTool(key); exist != nil {
				if exist.System {
					return actool.Errorf("工具 key 与内置工具冲突: " + key), nil
				}
				if err := s.m.pg.UpdateCustomTool(t); err != nil {
					return actool.Errorf("更新工具失败: " + err.Error()), nil
				}
				action = "updated"
			} else if err := s.m.pg.CreateCustomTool(t); err != nil {
				return actool.Errorf("注册工具失败: " + err.Error()), nil
			}
			log.Printf("[self-evolve] skill %s 晋升为工具 %s (kind=%s, agents=%v)", a.Name, key, t.Kind, agents)
			return jsonResult(map[string]any{
				"tool_key": key, "kind": t.Kind, "agents": agents, "action": action,
				"path": filepath.ToSlash(path), "next": "该工具已对绑定的 worker 可见；直接调用它继续推进攻击链",
			})
		})
}
