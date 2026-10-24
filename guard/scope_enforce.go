// Package guard — 授权范围强制层（scope_enforce.go）。
//
// 背景：上游 ARTEX 快照里 guard 包自述「RoE authorization-scope mechanism was
// removed」——task_scope 只作为提示词文字与覆盖度分母存在，执行期没有任何强制
// 校验。对一个无人值守、自主扩张入口面的 AI 来说，这是最危险的一处缺口：模型
// 越界时没有任何机械阻断。
//
// 本文件补上这一层。设计取舍：
//
//  1. 默认 fail-closed：命中范围外的目标一律阻断，不做静默放行。越界探测在真实
//     世界是法律风险，不是可用性问题。
//  2. 无 scope 时 fail-open 并留审计：任务尚未登记任何 scope 时（开局拆目标阶段）
//     放行，避免把 bootstrapping 打死；但每次放行都记审计，便于事后对账。
//  3. 只拦「能解析出目标标识」的调用：解析不出主机/域名的命令放行（例如 ls、
//     本地脚本）。这是有意的取舍——静态解析 shell 无法穷尽（base64、管道、变量
//     拼接都能逃掉），追求覆盖会大量误伤。真正的兜底是操作员只给授权目标。
//  4. 本层位于拦截链最前，且**不受** intercept_enabled_tools / 规则启用状态影响：
//     授权范围是平台硬边界，不是可配置策略。
//  5. scope 集合按任务缓存，TTL 30s：planner/worker 每轮都要拦，逐次查库太贵；
//     同时保证 add_task_scope 后 30 秒内生效。
package guard

import (
	"context"
	"encoding/json"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/hook"
)

// ScopeStore 是范围强制层需要的最小存储接口。用接口而非 *db.AssetStore，
// 是为了能在测试里注入假实现，也让本层不依赖 db 包的具体形状。
type ScopeStore interface {
	ListTaskScope(taskID int64) ([]db.TaskScope, error)
}

var (
	scopeStoreMu sync.RWMutex
	scopeStore   ScopeStore

	scopeCacheMu sync.Mutex
	scopeCache   = map[int64]cachedScope{}

	// ScopeEnforceEnabled 是总开关解析器。nil = 默认开启（fail-closed）。
	ScopeEnforceEnabled func() bool

	// scopeCacheTTL 是单任务 scope 集合的缓存时长。
	scopeCacheTTL = 30 * time.Second
)

type cachedScope struct {
	at    time.Time
	scope *taskScopeSet
}

// SetScopeStore 注入范围查询后端（server 启动时调用一次）。
func SetScopeStore(s ScopeStore) {
	scopeStoreMu.Lock()
	scopeStore = s
	scopeStoreMu.Unlock()
	scopeCacheMu.Lock()
	scopeCache = map[int64]cachedScope{}
	scopeCacheMu.Unlock()
}

func currentScopeStore() ScopeStore {
	scopeStoreMu.RLock()
	defer scopeStoreMu.RUnlock()
	return scopeStore
}

func scopeEnforceOn() bool {
	if ScopeEnforceEnabled == nil {
		return true
	}
	return ScopeEnforceEnabled()
}

// taskScopeSet 是一个任务已登记范围的判定集合。
type taskScopeSet struct {
	rootDomains map[string]bool // a.example.com 命中 example.com
	hosts       map[string]bool // 精确主机名 / 子域
	nets        []*net.IPNet    // CIDR
	ips         map[string]bool // 单 IP
	// unresolved 为 true 表示存在无法静态判定的 scope 行（company/icp/keyword）。
	// 这类行意味着"范围由别处定义"，遇到判定不了的目标时应转人工，而不是静默拒绝。
	unresolved bool
	rows       int
}

// loadScope 取任务的范围集合，带 TTL 缓存。
func loadScope(taskID int64) *taskScopeSet {
	now := time.Now()
	scopeCacheMu.Lock()
	if c, ok := scopeCache[taskID]; ok && now.Sub(c.at) < scopeCacheTTL {
		scopeCacheMu.Unlock()
		return c.scope
	}
	scopeCacheMu.Unlock()

	st := currentScopeStore()
	if st == nil {
		return nil
	}
	rows, err := st.ListTaskScope(taskID)
	if err != nil {
		// 查询失败按"未知"处理：返回 nil 让调用方 fail-open，并留审计。
		return nil
	}
	set := buildScopeSet(rows)
	scopeCacheMu.Lock()
	scopeCache[taskID] = cachedScope{at: now, scope: set}
	scopeCacheMu.Unlock()
	return set
}

// InvalidateScopeCache 在 scope 变更后立即失效缓存（add_task_scope 写回时调用）。
func InvalidateScopeCache(taskID int64) {
	scopeCacheMu.Lock()
	delete(scopeCache, taskID)
	scopeCacheMu.Unlock()
}

func buildScopeSet(rows []db.TaskScope) *taskScopeSet {
	set := &taskScopeSet{
		rootDomains: map[string]bool{},
		hosts:       map[string]bool{},
		ips:         map[string]bool{},
	}
	for _, r := range rows {
		set.rows++
		switch r.Kind {
		case "root_domain":
			if d := normalizeHost(firstNonEmpty(r.Domain, r.Value)); d != "" {
				set.rootDomains[d] = true
			}
		case "subdomain":
			if d := normalizeHost(firstNonEmpty(r.Domain, r.Value)); d != "" {
				set.hosts[d] = true
			}
		case "ip":
			if ip := normalizeHost(firstNonEmpty(r.Value, r.Domain)); ip != "" {
				set.ips[ip] = true
			}
		case "cidr":
			if _, n, err := net.ParseCIDR(strings.TrimSpace(firstNonEmpty(r.Net, r.Value))); err == nil {
				set.nets = append(set.nets, n)
			}
		default:
			// company / icp / keyword：范围由资产图或关键词定义，静态判定不了。
			set.unresolved = true
		}
	}
	return set
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// normalizeHost 把 URL / host:port / 大小写 / 尾点统一成裸主机名。
func normalizeHost(v string) string {
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
	if i := strings.Index(v, "@"); i >= 0 { // user:pass@host
		v = v[i+1:]
	}
	if h, _, err := net.SplitHostPort(v); err == nil {
		v = h
	} else if strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]") {
		v = strings.Trim(v, "[]")
	}
	return strings.TrimSuffix(strings.ToLower(v), ".")
}

// hostInScope 判定一个主机是否落在已登记范围内。
func (s *taskScopeSet) hostInScope(host string) bool {
	if s == nil || s.rows == 0 {
		return true // 未登记范围：fail-open（由调用方记审计）
	}
	host = normalizeHost(host)
	if host == "" {
		return true
	}
	if s.hosts[host] || s.ips[host] {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, n := range s.nets {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	// 域名：root_domain 允许其后缀子域。
	for rd := range s.rootDomains {
		if host == rd || strings.HasSuffix(host, "."+rd) {
			return true
		}
	}
	return false
}

// ---- 目标抽取 ----

var (
	// urlRe 抓 http(s) URL 中的主机。
	urlRe = regexp.MustCompile(`(?i)\bhttps?://([^\s/?#"'` + "`" + `<>)\]]+)`)
	// ipv4Re 抓裸 IPv4。
	ipv4Re = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
	// hostRe 抓形如 a.b.tld 的域名。
	hostRe = regexp.MustCompile(`(?i)\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|cn|io|dev|app|cloud|site|top|xyz|info|biz|edu|gov|me|co|ru|jp|kr|hk|tw|sg|us|uk|de|fr|nl|eu|tech|store|online|shop|ai))\b`)
	// hostArgRe / hostArgQuotedRe 抓命令行里以 -h/--host/-u/--url/-t/--target 等传入的
	// 主机参数。Go 的 regexp 不支持反向引用，故引号/非引号分成两条。
	hostArgRe       = regexp.MustCompile(`(?i)(?:^|\s)(?:-h|--host|-u|--url|-t|--target|--hosts|-d|--domain)[=\s]+([^\s"']+)`)
	hostArgQuotedRe = regexp.MustCompile(`(?i)(?:^|\s)(?:-h|--host|-u|--url|-t|--target|--hosts|-d|--domain)[=\s]+"([^"]+)"`)
)

// extractHosts 从一段文本里抽出所有可判定的目标主机。
func extractHosts(text string) []string {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(h string) {
		h = normalizeHost(h)
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		out = append(out, h)
	}
	for _, m := range urlRe.FindAllStringSubmatch(text, -1) {
		add(m[1])
	}
	for _, m := range hostArgQuotedRe.FindAllStringSubmatch(text, -1) {
		add(m[1])
	}
	for _, m := range hostArgRe.FindAllStringSubmatch(text, -1) {
		add(m[1])
	}
	for _, m := range hostRe.FindAllStringSubmatch(text, -1) {
		add(m[1])
	}
	for _, m := range ipv4Re.FindAllStringSubmatch(text, -1) {
		if net.ParseIP(m[1]) != nil {
			add(m[1])
		}
	}
	return out
}

// extractScopeInput 从工具名 + 入参 JSON 里取出可判定的目标面。
// 返回 ok=false 表示这个调用没有可解析的目标标识，范围层不参与判定。
func extractScopeInput(toolName string, input []byte) (string, bool) {
	text := string(input)
	switch toolName {
	case "Bash", "shell_open":
		var in struct {
			Command string `json:"command"`
		}
		if json.Unmarshal(input, &in) == nil && strings.TrimSpace(in.Command) != "" {
			return in.Command, true
		}
	case "shell_send":
		var in struct {
			Text string `json:"text"`
		}
		if json.Unmarshal(input, &in) == nil && strings.TrimSpace(in.Text) != "" {
			return in.Text, true
		}
	case "WebFetch":
		var in struct {
			URL string `json:"url"`
		}
		if json.Unmarshal(input, &in) == nil && strings.TrimSpace(in.URL) != "" {
			return in.URL, true
		}
	case "web_search":
		// 搜索是只读信息收集，不打目标，范围层不拦。
		return "", false
	default:
		// 其余工具（含 MCP / 自定义工具）：入参里出现 URL 就判。
		if strings.Contains(text, "://") {
			return text, true
		}
	}
	return "", false
}

// scopeDecision 是范围层的判定结果。
type scopeDecision struct {
	block   bool
	ask     bool // 无法静态判定（company/icp/keyword 范围）→ 转人工
	reason  string
	unknown bool // 未登记范围 / 查询失败 → 放行但留审计
	targets []string
}

// evaluateScope 判定一次工具调用是否越界。
func evaluateScope(ctx context.Context, toolName string, input []byte) scopeDecision {
	if !scopeEnforceOn() {
		return scopeDecision{}
	}
	taskIDStr, agentName := intercept.TaskInfoFromContext(ctx)
	taskID, err := strconv.ParseInt(strings.TrimSpace(taskIDStr), 10, 64)
	if err != nil || taskID <= 0 {
		return scopeDecision{} // 非任务级调用（chat / 无归属）不判
	}
	text, ok := extractScopeInput(toolName, input)
	if !ok {
		return scopeDecision{}
	}
	hosts := extractHosts(text)
	if len(hosts) == 0 {
		return scopeDecision{}
	}
	set := loadScope(taskID)
	if set == nil || set.rows == 0 {
		return scopeDecision{unknown: true, targets: hosts} // fail-open + 审计
	}
	var out []string
	for _, h := range hosts {
		if !set.hostInScope(h) {
			out = append(out, h)
		}
	}
	if len(out) == 0 {
		return scopeDecision{targets: hosts}
	}
	// 范围内有 company/icp/keyword 这类静态判定不了的 scope 行时，转人工裁决而不是直接
	// 拒绝——否则公司资产维度会被整片误杀。
	if set.unresolved {
		return scopeDecision{
			block: true, ask: true, targets: out,
			reason: "目标 " + strings.Join(out, ", ") + " 未命中本任务已登记的静态范围，且本任务存在 company/icp/keyword 类范围行（静态无法判定），需人工确认。",
		}
	}
	return scopeDecision{
		block: true, targets: out,
		reason: "目标 " + strings.Join(out, ", ") + " 不在本任务的授权范围内（agent=" + agentName + "）。仅在已登记范围内探测。",
	}
}

// applyScope 把范围判定接进拦截链。它由 preToolUse 在最前面调用，且在
// intercept_enabled_tools 之外——授权范围不可被配置关闭。
func (g *Guard) applyScope(ctx context.Context, ev hook.Event) hook.Result {
	dec := evaluateScope(ctx, ev.ToolName, ev.Input)
	if !dec.block {
		if dec.unknown && len(dec.targets) > 0 {
			g.record(ev.ToolName, "allow", "范围层：任务未登记范围，放行 "+strings.Join(dec.targets, ","), "")
		}
		return hook.Result{}
	}
	if dec.ask && g.interceptor != nil {
		askDec := intercept.Decision{
			Action:         "ask",
			Message:        "[范围层] " + dec.reason,
			RuleName:       "[平台] 授权范围强制",
			TimeoutEnabled: true,
			TimeoutSeconds: 600,
			TimeoutAction:  "deny",
		}
		g.logScopeDecision(ctx, ev.ToolName, ev.Input, askDec, "pending")
		if g.interceptor.HandleAsk(ctx, intercept.ConvIDFromContext(ctx), askDec, ev.ToolName, ev.Input) {
			return hook.Result{}
		}
		g.record(ev.ToolName, "block", "范围层：人工审批未通过 — "+dec.reason, "")
		return hook.Result{Decision: "block", Message: systemBlockMessage("人工审批未通过（越界目标未获授权）：" + dec.reason)}
	}
	// 直接拒绝也要落拦截历史，否则"审批记录"页看不到任何范围层判决，只剩内存审计。
	g.logScopeDecision(ctx, ev.ToolName, ev.Input, intercept.Decision{
		Action:   "deny",
		Message:  "[范围层] " + dec.reason,
		RuleName: "[平台] 授权范围强制",
	}, "denied")
	g.record(ev.ToolName, "block", "范围层：越界 — "+dec.reason, "")
	return hook.Result{Decision: "block", Message: systemBlockMessage("【授权范围】" + dec.reason)}
}

// logScopeDecision 把范围层判决写进拦截历史（与规则/裁判同表，便于统一查看）。
func (g *Guard) logScopeDecision(ctx context.Context, toolName string, input []byte, dec intercept.Decision, status string) {
	if g.interceptor == nil {
		return
	}
	g.interceptor.Log(ctx, intercept.ConvIDFromContext(ctx), dec, toolName, input, status)
}
