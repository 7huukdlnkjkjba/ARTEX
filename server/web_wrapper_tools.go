package server

// Controlled web-exploitation wrappers: sqlmap and nuclei.
//
// Both are external tools with a reputation for noise; this layer keeps the
// defaults conservative (level/risk 1, one thread, rate limit, no destructive
// sqlmap actions), enforces task scope, routes through the task MITM when it is
// available, and turns only parsed results into findings.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
	actool "github.com/Autumn-27/norma/tool"
)

func (s *Server) webWrapperTools() []actool.CoreTool {
	return []actool.CoreTool{s.toolSQLMap(), s.toolNuclei()}
}

func (s *Server) seedWebWrapperTools() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	workerAgents, _ := json.Marshal([]string{"worker"})
	for _, t := range s.webWrapperTools() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.PG().SeedTool(t.Name(), t.Description(), schema, workerAgents); err != nil {
			log.Printf("[tools] seed %s 失败: %v", t.Name(), err)
		}
	}
}

func (s *Server) taskMITMProxy(taskID int64) string {
	if s.m == nil || taskID <= 0 {
		return ""
	}
	addr, _ := s.m.TaskProxyForTask(taskID)
	if addr == "" {
		return ""
	}
	return "http://" + addr
}

func hostFromTarget(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	if h, _, err := net.SplitHostPort(raw); err == nil {
		return h
	}
	if i := strings.IndexAny(raw, "/?#"); i >= 0 {
		raw = raw[:i]
	}
	return strings.TrimSpace(raw)
}

func (s *Server) targetInScope(taskID int64, host string) bool {
	if in, known := guard.HostInTaskScope(taskID, host); known && !in {
		return false
	}
	return true
}

func (s *Server) recordServerFinding(ctx context.Context, ri agent.RunInfo, vulnClass, name, severity, summary, evidence, worker string) int64 {
	if s.m == nil || ri.TaskID <= 0 {
		return 0
	}
	task, ok := s.m.Task(strconv.FormatInt(ri.TaskID, 10))
	if !ok || task == nil || task.Store == nil {
		return 0
	}
	severity = normalizeSeverity(severity)
	rec, err := task.Store.RecordFinding(ctx, db.RecordFindingInput{
		TaskID: ri.TaskID, ExplorationID: task.ExpID, IntentID: ri.IntentID,
		VulnClass: vulnClass, Name: name, Severity: severity,
		Summary: summary, Evidence: truncateForTool(evidence), Worker: worker,
	})
	if err != nil || rec == nil {
		return 0
	}
	return rec.FindingID
}

func normalizeSeverity(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical", "high", "medium", "low", "info":
		return strings.ToLower(strings.TrimSpace(sev))
	default:
		return "medium"
	}
}

// ---------------------------------------------------------------- sqlmap

type sqlmapParams struct {
	URL        string `json:"url"`
	Data       string `json:"data,omitempty"`
	Param      string `json:"param,omitempty"`
	Action     string `json:"action"`
	DB         string `json:"db,omitempty"`
	Table      string `json:"table,omitempty"`
	Technique  string `json:"technique,omitempty"`
	Confirm    bool   `json:"confirm,omitempty"`
	DryRun     bool   `json:"dry_run,omitempty"`
	TimeoutSec int    `json:"timeout_sec,omitempty"`
}

type sqlmapRunner struct {
	Bin  string
	Base []string
}

func findSQLMap() (sqlmapRunner, error) {
	for _, name := range []string{"sqlmap", "sqlmap.py"} {
		p, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		if strings.HasSuffix(strings.ToLower(p), ".py") {
			py := msfPythonBin()
			if py == "" {
				return sqlmapRunner{}, fmt.Errorf("找到 %s 但没有 Python 解释器", p)
			}
			return sqlmapRunner{Bin: py, Base: []string{p}}, nil
		}
		return sqlmapRunner{Bin: p}, nil
	}
	return sqlmapRunner{}, fmt.Errorf("未找到 sqlmap（需要 sqlmap 或 sqlmap.py 在 PATH）")
}

func (s *Server) toolSQLMap() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "sqlmap_run",
		Description: "【SQLi 受控 sqlmap】对已确认/高度可疑的注入点跑 sqlmap。" +
			"默认 --batch --smart --level=1 --risk=1 --threads=1 --timeout=10 --retries=1 --technique=BE --flush-session；" +
			"支持 action=detect|dbs|current-user|is-dba|dump。dump 必须 confirm=true 且给 table，绝不自动 --os-shell/--file-write。" +
			"走任务 MITM（若开启）→ 目标；解析 is vulnerable/DBMS/current user/dbs 后回写 finding。",
		Schema: objSchema(map[string]any{
			"url":         strParam("注入点完整 URL（含参数，如 https://x/item?id=1）"),
			"data":        strParam("可选：POST data"),
			"param":       strParam("可选：只测指定参数，如 id"),
			"action":      strParam("detect | dbs | current-user | is-dba | dump（默认 detect）"),
			"db":          strParam("dump 时数据库名（可选）"),
			"table":       strParam("dump 时表名（dump 必填）"),
			"technique":   strParam("sqlmap --technique，默认 BE（布尔/报错）；可 BE/BEU/BEUST/BEUSTQ"),
			"confirm":     map[string]any{"type": "boolean", "description": "dump 需要显式 true；detect/dbs 不需要"},
			"dry_run":     map[string]any{"type": "boolean", "description": "只解析工具/参数/代理，不执行"},
			"timeout_sec": map[string]any{"type": "integer", "description": "默认 300，上限 900", "default": 300},
		}, "url", "action"),
		ReadOnly:    func(json.RawMessage) bool { return false },
		Permissions: sessionPerm,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a sqlmapParams
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败：" + err.Error()), nil
			}
			a.URL = strings.TrimSpace(a.URL)
			if a.URL == "" {
				return actool.Errorf("url 必填"), nil
			}
			a.Action = strings.ToLower(strings.TrimSpace(a.Action))
			if a.Action == "" {
				a.Action = "detect"
			}
			switch a.Action {
			case "detect", "dbs", "current-user", "is-dba", "dump":
			default:
				return actool.Errorf("action 只支持 detect/dbs/current-user/is-dba/dump"), nil
			}
			if a.Action == "dump" {
				if !a.Confirm {
					return actool.Errorf("dump 是高影响动作：确认 RoE 与目标后设置 confirm=true；否则先用 detect/dbs"), nil
				}
				if strings.TrimSpace(a.Table) == "" {
					return actool.Errorf("dump 必须指定 table，禁止无范围整库导出"), nil
				}
			}
			if a.TimeoutSec <= 0 {
				a.TimeoutSec = 300
			}
			if a.TimeoutSec > 900 {
				a.TimeoutSec = 900
			}
			a.Technique = strings.ToUpper(strings.TrimSpace(a.Technique))
			if a.Technique == "" {
				a.Technique = "BE"
			}
			for _, r := range a.Technique {
				if !strings.ContainsRune("BEUSTQ", r) {
					return actool.Errorf("technique 只允许 B/E/U/S/T/Q 组合"), nil
				}
			}
			host := hostFromTarget(a.URL)
			ri := agent.RunInfoFrom(ctx)
			if host == "" {
				return actool.Errorf("无法从 url 解析 host"), nil
			}
			if !s.targetInScope(ri.TaskID, host) {
				return actool.Errorf(fmt.Sprintf("目标 %s 不在任务 scope 内", host)), nil
			}
			runner, err := findSQLMap()
			if err != nil {
				return jsonResult(map[string]any{"status": "tool_missing", "error": err.Error(),
					"next_steps": []string{"pip install sqlmap"}})
			}
			proxy := s.taskMITMProxy(ri.TaskID)
			args, err := buildSQLMapArgs(&a, proxy, "")
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if a.DryRun {
				return jsonResult(map[string]any{
					"status": "dry_run", "url": a.URL, "action": a.Action,
					"bin": runner.Bin, "base": runner.Base, "args": args,
					"proxy": proxy, "egress": egressLabel(proxy),
				})
			}
			outDir := ""
			if s.m != nil && s.m.dir != "" {
				base := filepath.Join(s.m.dir, "tmp")
				_ = os.MkdirAll(base, 0o755)
				if d, err := os.MkdirTemp(base, "artex-sqlmap-*"); err == nil {
					outDir = d
					defer os.RemoveAll(d)
				}
			}
			args, err = buildSQLMapArgs(&a, proxy, outDir)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			cmdArgs := append(append([]string{}, runner.Base...), args...)
			runCtx, cancel := context.WithTimeout(ctx, time.Duration(a.TimeoutSec)*time.Second)
			defer cancel()
			cmd := exec.CommandContext(runCtx, runner.Bin, cmdArgs...)
			var stdout, stderr strings.Builder
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			runErr := cmd.Run()
			out := stdout.String() + "\n" + stderr.String()
			parsed := parseSQLMapOutput(out)
			findingID := int64(0)
			if parsed["injectable"] == true {
				findingID = s.recordServerFinding(ctx, ri, "sqli",
					"SQL 注入", "critical",
					fmt.Sprintf("sqlmap 确认注入点 %s（param=%s）", a.URL, a.Param),
					out, "sqlmap_run")
			}
			res := map[string]any{
				"status": "success", "url": a.URL, "action": a.Action,
				"proxy": proxy, "egress": egressLabel(proxy),
				"parsed": parsed, "output_tail": truncateForTool(out),
			}
			if runErr != nil {
				res["status"] = "failed"
				res["error"] = runErr.Error()
				res["next_steps"] = sqlmapNextSteps(out)
			} else if parsed["injectable"] != true {
				res["status"] = "not_injectable"
			}
			if findingID > 0 {
				res["finding_id"] = findingID
			}
			return jsonResult(res)
		},
	})
}

func egressLabel(proxy string) string {
	if proxy != "" {
		return "task_mitm"
	}
	return "direct"
}

func buildSQLMapArgs(a *sqlmapParams, proxy, outDir string) ([]string, error) {
	if a == nil {
		return nil, fmt.Errorf("nil sqlmap params")
	}
	args := []string{
		"-u", a.URL,
		"--batch", "--smart",
		"--level=1", "--risk=1", "--threads=1",
		"--timeout=10", "--retries=1",
		"--technique=" + a.Technique,
		"--flush-session", "--disable-coloring",
	}
	if strings.TrimSpace(a.Data) != "" {
		args = append(args, "--data", a.Data)
	}
	if strings.TrimSpace(a.Param) != "" {
		args = append(args, "-p", strings.TrimSpace(a.Param))
	}
	if proxy != "" {
		args = append(args, "--proxy="+proxy)
	}
	if outDir != "" {
		args = append(args, "--output-dir", outDir)
	}
	switch a.Action {
	case "dbs":
		args = append(args, "--dbs")
	case "current-user":
		args = append(args, "--current-user")
	case "is-dba":
		args = append(args, "--is-dba")
	case "dump":
		args = append(args, "--dump")
		if strings.TrimSpace(a.DB) != "" {
			args = append(args, "-D", strings.TrimSpace(a.DB))
		}
		if strings.TrimSpace(a.Table) != "" {
			args = append(args, "-T", strings.TrimSpace(a.Table))
		}
	}
	return args, nil
}

func parseSQLMapOutput(out string) map[string]any {
	low := strings.ToLower(out)
	parsed := map[string]any{
		"injectable":   strings.Contains(low, "is vulnerable") || strings.Contains(low, "is injectable"),
		"dbms":         sqlmapField(out, "back-end DBMS:"),
		"current_db":   sqlmapField(out, "current database:"),
		"current_user": sqlmapField(out, "current user:"),
		"is_dba":       strings.Contains(low, "current user is dba: true") || strings.Contains(low, "current user is dba: yes"),
	}
	if dbs := sqlmapDatabases(out); len(dbs) > 0 {
		parsed["databases"] = dbs
	}
	if types := sqlmapInjectionTypes(out); len(types) > 0 {
		parsed["injection_types"] = types
	}
	return parsed
}

func sqlmapField(out, prefix string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}

func sqlmapDatabases(out string) []string {
	var dbs []string
	in := false
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "available databases") {
			in = true
			continue
		}
		if !in {
			continue
		}
		if strings.HasPrefix(line, "[*]") {
			if v := strings.TrimSpace(strings.TrimPrefix(line, "[*]")); v != "" {
				dbs = append(dbs, v)
			}
			continue
		}
		if line == "" || strings.HasPrefix(line, "[") {
			continue
		}
		break
	}
	return dbs
}

func sqlmapInjectionTypes(out string) []string {
	var types []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Type:") || strings.HasPrefix(line, "Title:") || strings.HasPrefix(line, "Payload:") {
			types = append(types, line)
		}
	}
	return types
}

func sqlmapNextSteps(out string) []string {
	low := strings.ToLower(out)
	switch {
	case strings.Contains(low, "connection timed out") || strings.Contains(low, "unable to connect"):
		return []string{"确认目标可达；隔离内网先 tunnel_deploy；必要时用 --proxy 的 task MITM"}
	case strings.Contains(low, "not injectable") || strings.Contains(low, "does not seem to be injectable"):
		return []string{"换参数/方法/编码复测；不要用 sqlmap 硬扫无信号点"}
	case strings.Contains(low, "waf") || strings.Contains(low, "blocked"):
		return []string{"先做 WAF 指纹与 payload 变形；降低 level/risk，避免封 IP"}
	}
	return []string{"先用 detect 确认，再 dbs/dump；dump 需 confirm=true 且指定 table"}
}

// ---------------------------------------------------------------- nuclei

type nucleiParams struct {
	Target     string `json:"target"`
	Tags       string `json:"tags,omitempty"`
	Template   string `json:"template,omitempty"`
	Severity   string `json:"severity,omitempty"`
	DryRun     bool   `json:"dry_run,omitempty"`
	TimeoutSec int    `json:"timeout_sec,omitempty"`
}

func (s *Server) toolNuclei() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "nuclei_run",
		Description: "【受控 nuclei】对目标跑 nuclei 模板，JSONL 解析后回写 finding。" +
			"默认 -severity critical,high,medium -rl 50 -timeout 10 -retries 1 -omit-raw -ni -duc -no-color；" +
			"支持 tags/template 缩小范围；走任务 MITM（若开启）→ 目标；不做全端口/全模板轰炸。",
		Schema: objSchema(map[string]any{
			"target":      strParam("目标 URL 或 host"),
			"tags":        strParam("可选：nuclei tags，如 cve,rce,exposure"),
			"template":    strParam("可选：模板路径或 template-id"),
			"severity":    strParam("默认 critical,high,medium"),
			"dry_run":     map[string]any{"type": "boolean", "description": "只解析工具/参数/代理，不执行"},
			"timeout_sec": map[string]any{"type": "integer", "description": "默认 300，上限 900", "default": 300},
		}, "target"),
		ReadOnly:    func(json.RawMessage) bool { return false },
		Permissions: sessionPerm,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a nucleiParams
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败：" + err.Error()), nil
			}
			a.Target = strings.TrimSpace(a.Target)
			if a.Target == "" {
				return actool.Errorf("target 必填"), nil
			}
			a.Severity = strings.TrimSpace(a.Severity)
			if a.Severity == "" {
				a.Severity = "critical,high,medium"
			}
			for _, s := range strings.Split(a.Severity, ",") {
				switch strings.ToLower(strings.TrimSpace(s)) {
				case "critical", "high", "medium", "low", "info", "unknown":
				default:
					return actool.Errorf("severity 只允许 critical/high/medium/low/info/unknown"), nil
				}
			}
			if a.TimeoutSec <= 0 {
				a.TimeoutSec = 300
			}
			if a.TimeoutSec > 900 {
				a.TimeoutSec = 900
			}
			host := hostFromTarget(a.Target)
			ri := agent.RunInfoFrom(ctx)
			if host == "" {
				return actool.Errorf("无法从 target 解析 host"), nil
			}
			if !s.targetInScope(ri.TaskID, host) {
				return actool.Errorf(fmt.Sprintf("目标 %s 不在任务 scope 内", host)), nil
			}
			bin, err := exec.LookPath("nuclei")
			if err != nil {
				return jsonResult(map[string]any{"status": "tool_missing", "error": err.Error(),
					"next_steps": []string{"go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"}})
			}
			proxy := s.taskMITMProxy(ri.TaskID)
			args := buildNucleiArgs(&a, proxy)
			if a.DryRun {
				return jsonResult(map[string]any{
					"status": "dry_run", "target": a.Target, "bin": bin, "args": args,
					"proxy": proxy, "egress": egressLabel(proxy),
				})
			}
			runCtx, cancel := context.WithTimeout(ctx, time.Duration(a.TimeoutSec)*time.Second)
			defer cancel()
			cmd := exec.CommandContext(runCtx, bin, args...)
			var stdout, stderr strings.Builder
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			runErr := cmd.Run()
			lines, parseErr := parseNucleiJSONL(stdout.String())
			if parseErr != nil && runErr == nil {
				runErr = parseErr
			}
			var findingIDs []int64
			for _, r := range lines {
				if fid := s.recordServerFinding(ctx, ri, r.TemplateID, r.Name, r.Severity,
					fmt.Sprintf("%s @ %s", r.Name, r.MatchedAt),
					fmt.Sprintf("template=%s\nmatched-at=%s\nhost=%s", r.TemplateID, r.MatchedAt, r.Host),
					"nuclei_run"); fid > 0 {
					findingIDs = append(findingIDs, fid)
				}
			}
			res := map[string]any{
				"status": "success", "target": a.Target,
				"proxy": proxy, "egress": egressLabel(proxy),
				"finding_count": len(findingIDs), "finding_ids": findingIDs,
				"output_tail": truncateForTool(stdout.String()),
			}
			if runErr != nil {
				res["status"] = "failed"
				res["error"] = runErr.Error()
			}
			return jsonResult(res)
		},
	})
}

func buildNucleiArgs(a *nucleiParams, proxy string) []string {
	args := []string{
		"-u", a.Target,
		"-severity", a.Severity,
		"-rl", "50", "-timeout", "10", "-retries", "1",
		"-jsonl", "-silent", "-nc", "-or", "-ni", "-duc",
	}
	if strings.TrimSpace(a.Tags) != "" {
		args = append(args, "-tags", strings.TrimSpace(a.Tags))
	}
	if strings.TrimSpace(a.Template) != "" {
		args = append(args, "-t", strings.TrimSpace(a.Template))
	}
	if proxy != "" {
		args = append(args, "-proxy", proxy)
	}
	return args
}

type nucleiResultLine struct {
	TemplateID string `json:"template-id"`
	Name       string `json:"name"`
	Severity   string `json:"severity"`
	Host       string `json:"host"`
	MatchedAt  string `json:"matched-at"`
	Info       struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
	} `json:"info"`
}

func parseNucleiJSONL(out string) ([]nucleiResultLine, error) {
	var lines []nucleiResultLine
	seen := map[string]bool{}
	for _, raw := range strings.Split(out, "\n") {
		raw = strings.TrimSpace(raw)
		if raw == "" || !strings.HasPrefix(raw, "{") {
			continue
		}
		var r nucleiResultLine
		if err := json.Unmarshal([]byte(raw), &r); err != nil {
			continue
		}
		if r.Info.Name != "" {
			r.Name = r.Info.Name
		}
		if r.Info.Severity != "" {
			r.Severity = r.Info.Severity
		}
		if r.Name == "" {
			r.Name = r.TemplateID
		}
		if r.Severity == "" {
			r.Severity = "medium"
		}
		key := r.TemplateID + "|" + r.MatchedAt
		if seen[key] {
			continue
		}
		seen[key] = true
		lines = append(lines, r)
	}
	return lines, nil
}
