// Package netauto 把 ARTEX（AI 自主渗透系统）的"图 + 资产 + 漏洞 + 证据 + 范围强制"
// 底座，改造成一台**确定性的网络自动化攻击引擎**：
//
//	输入  目标（CIDR / 域名 / URL / 主机:端口）+ 攻击剧本（JSON/YAML）
//	过程  发现 → 端口/服务 → 指纹 → 弱口令 → 注入/配置缺陷探测 → 复验
//	输出  证据化发现（confirmed / inferred 严格分级）+ JSON/HTML 报告 + 可选落 ARTEX 库
//
// 与 ARTEX 原生的关系：
//   - 不再依赖 LLM 做逐步决策 —— 攻击步骤由剧本（Campaign）静态声明，引擎按阶段推进；
//   - 复用 ARTEX 的授权范围强制（guard.ScopeEnforcer）、资产库（db.AssetStore）、
//     漏洞库（RecordFinding / AddFinding）与证据链模型；
//   - 因此"同一个漏洞"既能由 AI agent 报出，也能由本引擎自动报出，落在同一张表里。
//
// 三级产物与 ARTEX 一致，防幻觉的结构基础不变：
//
//	资产   Host / Port / Fingerprint
//	事实   Inference（含**否定结论**：扫了没打下来也要落库）
//	漏洞   Finding（只有**本次真实触发并留下证据**才允许 confirmed）
package netauto

import (
	"encoding/json"
	"time"
)

// ---------------------------------------------------------------- 攻击面模型

// TargetKind 是目标的解析类型。
type TargetKind string

const (
	TargetDomain TargetKind = "domain" // example.com（含子域展开）
	TargetIP     TargetKind = "ip"     // 1.2.3.4
	TargetCIDR   TargetKind = "cidr"   // 10.0.0.0/24
	TargetURL    TargetKind = "url"    // https://app.example.com:8443/base
	TargetHost   TargetKind = "host"   // host:port
)

// Target 是一条解析后的攻击目标。所有下游模块只吃 Host/IP/Port 三元组，
// 域名只是"用来解析出 IP 的入口"。
type Target struct {
	Kind     TargetKind `json:"kind"`
	Raw      string     `json:"raw"`                // 原始输入，保留以便报告回溯
	Domain   string     `json:"domain,omitempty"`   // 域名（含子域）
	IP       string     `json:"ip,omitempty"`       // 解析出的 IP
	Port     int        `json:"port,omitempty"`     // 0 = 未指定，走端口策略
	Scheme   string     `json:"scheme,omitempty"`   // http/https，URL 输入时携带
	Hostname string     `json:"hostname,omitempty"` // URL host 头用（可能与 Domain 不同）
}

// Host 是一台存活主机（攻击面一等公民）。
type Host struct {
	ID       int64  `json:"id"`
	IP       string `json:"ip"`
	Domain   string `json:"domain,omitempty"` // 首次发现时用的名字（可能为空）
	Alive    bool   `json:"alive"`
	Method   string `json:"method"` // 判定存活的手法：icmp/tcp/arp/tls
	RTTms    int64  `json:"rtt_ms"`
	OS       string `json:"os,omitempty"`
	LastSeen string `json:"last_seen"`
}

// Port 是一条"主机:端口"暴露面。
type Port struct {
	ID       int64    `json:"id"`
	IP       string   `json:"ip"`
	Port     int      `json:"port"`
	Proto    string   `json:"proto"` // tcp/udp
	State    string   `json:"state"` // open/closed/filtered
	Service  string   `json:"service"`
	Product  string   `json:"product,omitempty"`
	Version  string   `json:"version,omitempty"`
	Banner   string   `json:"banner,omitempty"`
	TLS      bool     `json:"tls"`
	CertCN   string   `json:"cert_cn,omitempty"`
	CertSANs []string `json:"cert_sans,omitempty"`
	LastSeen string   `json:"last_seen"`
}

// Fingerprint 是一个 Web 服务的指纹（URL 维度）。
type Fingerprint struct {
	ID       int64    `json:"id"`
	URL      string   `json:"url"`
	IP       string   `json:"ip,omitempty"`
	Status   int      `json:"status"`
	Title    string   `json:"title,omitempty"`
	Server   string   `json:"server,omitempty"`
	Tech     []string `json:"tech,omitempty"`
	Length   int64    `json:"length"`
	Redirect string   `json:"redirect,omitempty"`
	CPE      []string `json:"cpe,omitempty"`
	LastSeen string   `json:"last_seen"`
}

// Credential 是一条可用凭证（弱口令/默认口令命中）。
type Credential struct {
	Service  string `json:"service"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
	Key      string `json:"key,omitempty"`
	Note     string `json:"note,omitempty"`
}

// ---------------------------------------------------------------- 攻击产物

// Severity 对齐 ARTEX 白名单（db.ValidSeverity）。
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
)

// Confidence 是发现的置信等级，这是整套机制的关键：
//
//	confirmed —— 本次真实触发过，且留有可复现的原始证据（HTTP 原文 / 协议回包）。
//	inferred  —— 有嫌疑但没触发成功（版本匹配、报错可疑、路径存在）。**禁止**当成漏洞。
//
// 这条约束直接封死"版本匹配 = 漏洞"这类幻觉。
type Confidence string

const (
	ConfConfirmed Confidence = "confirmed"
	ConfInferred  Confidence = "inferred"
)

// Evidence 是一条原始证据。evidence 只存"能被复核的字节"，不存结论。
type Evidence struct {
	Kind      string          `json:"kind"` // http_response/tcp_banner/protocol_reply/auth_success/command_output
	Request   string          `json:"request,omitempty"`
	Response  string          `json:"response,omitempty"`
	Transport string          `json:"transport,omitempty"` // tcp/tls/http
	Meta      json.RawMessage `json:"meta,omitempty"`
	At        string          `json:"at"`
}

// Finding 是一次攻击产出。
type Finding struct {
	ID          int64      `json:"id"`
	CampaignID  string     `json:"campaign_id"`
	Stage       string     `json:"stage"`     // 出自哪个攻击阶段
	Module      string     `json:"module"`    // 出自哪个攻击模块
	VulnClass   string     `json:"vulnclass"` // 漏洞类：sql_injection/weak_credential/...
	Name        string     `json:"name"`      // 人类可读名
	Severity    Severity   `json:"severity"`
	Confidence  Confidence `json:"confidence"`
	Target      string     `json:"target"` // host:port 或 URL
	Endpoint    string     `json:"endpoint,omitempty"`
	Param       string     `json:"param,omitempty"`
	Payload     string     `json:"payload,omitempty"`
	Summary     string     `json:"summary"`
	Remediation string     `json:"remediation,omitempty"`
	Evidence    []Evidence `json:"evidence,omitempty"`
	Assets      []string   `json:"assets,omitempty"` // 关联资产键（用于落 ARTEX 库时锚定）
	CreatedAt   string     `json:"created_at"`
}

// Confirmed 便捷判断。
func (f *Finding) Confirmed() bool { return f.Confidence == ConfConfirmed }

// Inference 是探索结论（含**否定结论**：扫过、试过、没打下来，也必须留痕）。
type Inference struct {
	ID         int64  `json:"id"`
	CampaignID string `json:"campaign_id"`
	Stage      string `json:"stage"`
	Module     string `json:"module"`
	Target     string `json:"target"`
	Summary    string `json:"summary"`
	Negative   bool   `json:"negative"` // true = 否定结论（没发现 / 没打通）
	CreatedAt  string `json:"created_at"`
}

// CampaignResult 是一次攻击战役的最终产物。
type CampaignResult struct {
	CampaignID  string         `json:"campaign_id"`
	Goal        string         `json:"goal"`
	StartedAt   string         `json:"started_at"`
	FinishedAt  string         `json:"finished_at"`
	DurationSec int64          `json:"duration_sec"`
	StageStats  []StageRun     `json:"stage_stats"`
	Hosts       []*Host        `json:"hosts"`
	Ports       []*Port        `json:"ports"`
	Web         []*Fingerprint `json:"web"`
	Creds       []*Credential  `json:"credentials,omitempty"`
	Findings    []*Finding     `json:"findings"`
	Inferences  []*Inference   `json:"inferences"`
	Errors      []string       `json:"errors,omitempty"`
}

// Stats 汇总各等级发现数量。
func (r *CampaignResult) Stats() map[string]int {
	out := map[string]int{
		"hosts": len(r.Hosts), "ports": len(r.Ports), "web": len(r.Web),
		"credentials": len(r.Creds), "findings": len(r.Findings),
		"confirmed": 0, "inferred": 0,
		"critical": 0, "high": 0, "medium": 0, "low": 0,
	}
	for _, f := range r.Findings {
		if f.Confirmed() {
			out["confirmed"]++
		} else {
			out["inferred"]++
		}
		out[string(f.Severity)]++
	}
	return out
}

// StageRun 记录一个阶段的执行统计。
type StageRun struct {
	Name      string   `json:"name"`
	Modules   []string `json:"modules"`
	StartedAt string   `json:"started_at"`
	EndedAt   string   `json:"ended_at"`
	Duration  int64    `json:"duration_ms"`
	Probes    int64    `json:"probes"`   // 发出的请求/连接数
	Hits      int64    `json:"hits"`     // 有意义的命中数
	Findings  int      `json:"findings"` // 本阶段新增发现
	Notes     []string `json:"notes,omitempty"`
}

func now() string { return time.Now().Format(time.RFC3339) }
