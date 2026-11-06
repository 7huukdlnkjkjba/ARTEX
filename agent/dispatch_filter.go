package agent

// 本文件实现「派活前的端点筛选/评分」与「派活时的硬跳过」：
//
//   - EvaluateAssetDispatch：给单个资产打分（带 ID 参数 / API 端点 / 非常规端口 /
//     未鉴权面板加分），并给出静态资源 / CDN 边缘 / 历史 404-412 的硬跳过原因。
//   - NegationIndex：从 fact 图汇总「同一资产 × 同一类探测连续 404/412」的否定结论。
//     同一组合累计 ≥ NegationRepeats 次即拉黑，add_intent 读到已否定组合直接拒派。
//
// 设计目标：planner 不再反复派工去啃 fact 库里已经记了"没有"的目标，也不再优先
// 消耗静态资源 / CDN 边缘；frontier 的 priority 由资产价值自动定档（高分先打）。

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

const (
	dispatchMaxScore  = 10
	assetTypeEndpoint = "endpoint"

	// NegationRepeats 是「同一资产 × 同一类探测」被拉黑所需的连续 404/412 次数。
	// 只出现一次 404 可能是个别路径/瞬时问题；连续两次即视为该组合不存在。
	NegationRepeats = 2
	// negationFactScanCap 限制否定索引单次扫描的 fact 数量（最新在前）。
	negationFactScanCap = 2000
)

// 探测类：否定结论按「资产 × 探测类」聚合，避免一个 404 把同资产上的其它探测也封死。
const (
	ProbeInjection   = "injection"   // 注入/SSRF/XSS/反序列化/上传等
	ProbeAuth        = "auth"        // 登录/口令/认证/越权
	ProbeExposure    = "exposure"    // 泄露/备份/敏感文件/调试面
	ProbeExploit     = "exploit"     // 利用/提权/横向
	ProbeFingerprint = "fingerprint" // 指纹/版本/技术栈
	ProbeDiscovery   = "discovery"   // 目录/路径/端点枚举
	ProbeAPI         = "api"         // 接口/参数
	ProbeGeneric     = "generic"
)

// AssetDispatch 是一个资产的派发评估结果。
type AssetDispatch struct {
	Score    int      `json:"score"`               // 0-10，越高越值得先打
	Priority int      `json:"priority"`            // 由 Score 映射出的 frontier 优先级
	Reasons  []string `json:"reasons,omitempty"`   // 加分依据（可读）
	Skip     string   `json:"skip,omitempty"`      // 非空 = 硬跳过原因（不派）
	SkipKind string   `json:"skip_kind,omitempty"` // static / cdn / http_404_412
}

// DispatchPriorityForScore 把端点评分映射为 frontier 优先级（priority DESC 先领）。
// 评分低的资产低于默认档 5，避免它们挤占真正高价值的意图。
func DispatchPriorityForScore(score int) int {
	switch {
	case score >= 8:
		return 10
	case score >= 6:
		return 9
	case score >= 4:
		return 7
	case score >= 2:
		return 6
	default:
		return 4
	}
}

// EvaluateAssetDispatch 对单个资产做派发评分/硬跳过判定。纯函数，不查库。
//
// 高分信号：带 ID 参数（含路径 ID）、API 端点、非常规端口、未鉴权面板、写方法、
// 受保护入口（401/403）、已知高风险组件。
// 硬跳过：静态资源、CDN 边缘节点、资产最近一次响应是 404/412。
func EvaluateAssetDispatch(a *db.Asset) AssetDispatch {
	if a == nil {
		return AssetDispatch{Priority: DispatchPriorityForScore(0)}
	}
	p := assetURLPath(a)
	host := assetHost(a)

	// ---- 硬跳过（优先于任何加分）----
	if ext := staticPathExt(p); ext != "" {
		return AssetDispatch{Skip: "静态资源(" + ext + ")，不派", SkipKind: "static"}
	}
	if isCDNEdgeHost(host) || cdnCNAMERecord(a) {
		return AssetDispatch{Skip: "CDN 边缘节点(" + host + ")，不派", SkipKind: "cdn"}
	}
	if isStaticHost(host) && !looksAPIPath(p) {
		return AssetDispatch{Skip: "静态资源站点(" + host + ")，不派", SkipKind: "static"}
	}
	if a.StatusCode != nil && (*a.StatusCode == 404 || *a.StatusCode == 412) {
		return AssetDispatch{Skip: fmt.Sprintf("历史响应 %d，不派", *a.StatusCode), SkipKind: "http_404_412"}
	}

	score := 0
	var reasons []string
	add := func(points int, reason string) {
		if points <= 0 || reason == "" {
			return
		}
		score += points
		reasons = append(reasons, reason)
	}

	if a.Type == assetTypeEndpoint {
		add(2, "endpoint 资产")
	}
	if looksAPIPath(p) {
		add(2, "API 路径")
	}
	if names := idParamNames(a.Params); len(names) > 0 {
		add(3, "带 ID 参数:"+strings.Join(limitStrings(names, 3), ","))
	} else if names := idParamNamesFromURL(assetRawURL(a)); len(names) > 0 {
		add(3, "URL 带 ID 参数:"+strings.Join(limitStrings(names, 3), ","))
	}
	if pathHasID(p) {
		add(2, "路径含 ID 段")
	}
	if port := assetEffectivePort(a); port > 0 && port != 80 && port != 443 {
		add(2, fmt.Sprintf("非常规端口 %d", port))
	}
	if len(a.Params) > 0 {
		add(1, fmt.Sprintf("%d 个可测参数", len(a.Params)))
	}
	if kw, ok := panelKeyword(p); ok {
		status := 0
		if a.StatusCode != nil {
			status = *a.StatusCode
		}
		login := isLoginSurface(p + " " + a.PageTitle)
		switch {
		case status == 200 && !login:
			add(3, "未鉴权面板:"+kw)
		case status == 200 && login:
			add(1, "登录入口:"+kw)
		case status == 301 || status == 302:
			add(1, "面板入口:"+kw)
		case status == 401 || status == 403:
			add(1, "受保护面板:"+kw)
		default:
			add(2, "面板路径:"+kw)
		}
	}
	if writeMethod(a.Method) {
		add(1, "写方法 "+strings.ToUpper(strings.TrimSpace(a.Method)))
	}
	if a.StatusCode != nil {
		switch *a.StatusCode {
		case 401, 403:
			add(1, fmt.Sprintf("受保护入口 %d", *a.StatusCode))
		case 200, 201, 204:
			add(1, fmt.Sprintf("存活 %d", *a.StatusCode))
		}
	}
	if tech := riskyTech(a.Technologies); tech != "" {
		add(1, "已知组件 "+tech)
	}

	if score > dispatchMaxScore {
		score = dispatchMaxScore
	}
	if len(reasons) > 4 {
		reasons = reasons[:4]
	}
	return AssetDispatch{Score: score, Priority: DispatchPriorityForScore(score), Reasons: reasons}
}

// --- URL / 路径工具 ---

// assetRawURL 还原资产的 URL（没有 url 时用 domain/ip + port 拼）。
func assetRawURL(a *db.Asset) string {
	if a == nil {
		return ""
	}
	if u := strings.TrimSpace(a.URL); u != "" {
		if !strings.Contains(u, "://") {
			u = "http://" + u
		}
		return u
	}
	host := strings.TrimSpace(a.Domain)
	if host == "" {
		host = strings.TrimSpace(a.IP)
	}
	if host == "" {
		return ""
	}
	port := 0
	if a.Port != nil {
		port = *a.Port
	}
	scheme := "http"
	if port == 443 {
		scheme = "https"
	}
	if port > 0 && !((scheme == "http" && port == 80) || (scheme == "https" && port == 443)) {
		if strings.Contains(host, ":") { // IPv6 字面量
			return scheme + "://[" + host + "]:" + strconv.Itoa(port)
		}
		return scheme + "://" + host + ":" + strconv.Itoa(port)
	}
	return scheme + "://" + host
}

func assetURLPath(a *db.Asset) string {
	u, err := url.Parse(assetRawURL(a))
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Path)
}

func assetHost(a *db.Asset) string {
	if a == nil {
		return ""
	}
	if u, err := url.Parse(assetRawURL(a)); err == nil && u.Host != "" {
		return strings.ToLower(u.Hostname())
	}
	return strings.ToLower(strings.TrimSpace(a.Domain))
}

func assetEffectivePort(a *db.Asset) int {
	if a == nil {
		return 0
	}
	if a.Port != nil && *a.Port > 0 {
		return *a.Port
	}
	u, err := url.Parse(assetRawURL(a))
	if err != nil {
		return 0
	}
	if ps := u.Port(); ps != "" {
		if n, err := strconv.Atoi(ps); err == nil {
			return n
		}
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return 443
	case "http":
		return 80
	}
	return 0
}

func assetDispatchLabel(a *db.Asset) string {
	if a == nil {
		return ""
	}
	for _, s := range []string{a.URL, a.Domain, a.IP, a.AppName, a.RootDomain} {
		if strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return fmt.Sprintf("#%d", a.ID)
}

// --- 静态资源 / CDN 边缘 ---

var staticPathExts = map[string]bool{
	".js": true, ".mjs": true, ".css": true, ".map": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true,
	".svg": true, ".ico": true, ".bmp": true,
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
	".less": true, ".scss": true,
}

func staticPathExt(p string) string {
	ext := strings.ToLower(path.Ext(p))
	if staticPathExts[ext] {
		return ext
	}
	return ""
}

var staticHostLabels = map[string]bool{
	"static": true, "assets": true, "img": true, "images": true,
	"css": true, "js": true, "fonts": true,
}

// isStaticHost 判定静态资源专用主机名（static./assets./img./fonts. 等）。
func isStaticHost(host string) bool {
	if host == "" {
		return false
	}
	first := strings.SplitN(host, ".", 2)[0]
	if staticHostLabels[first] {
		return true
	}
	// static1 / static-2 这类编号主机
	if strings.HasPrefix(first, "static") && len(first) <= 12 {
		return true
	}
	return false
}

// cdnHostSuffixes 是各家 CDN 边缘域名后缀（命中即视为边缘节点，不派）。
var cdnHostSuffixes = []string{
	"cloudfront.net", "akamaiedge.net", "edgekey.net", "edgesuite.net",
	"fastly.net", "cdn.jsdelivr.net", "jsdelivr.net", "unpkg.com",
	"alicdn.com", "cdngslb.com", "tencentcdn.com", "kunlun.com", "kunlunca.com",
	"wscdns.com", "cdnevip.com", "azureedge.net", "azurefd.net",
	"trafficmanager.net", "cloudflare.net", "cdn77.org", "stackpathdns.com",
	"llnwd.net", "cachefly.net", "chinacache.com", "wscloudcdn.com", "cdn20.com",
}

func isCDNEdgeHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return false
	}
	for _, suffix := range cdnHostSuffixes {
		if h == suffix || strings.HasSuffix(h, "."+suffix) {
			return true
		}
	}
	first := strings.SplitN(h, ".", 2)[0]
	return first == "cdn" || first == "edge" ||
		strings.HasPrefix(first, "cdn-") || strings.HasPrefix(first, "edge-") ||
		(strings.HasPrefix(first, "cdn") && len(first) <= 10)
}

// cdnCNAMERecord 判定子域资产是否 CNAME 到 CDN 厂商边缘域名。
func cdnCNAMERecord(a *db.Asset) bool {
	if a == nil || !strings.EqualFold(strings.TrimSpace(a.RecordType), "CNAME") {
		return false
	}
	for _, v := range a.RecordValue {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" {
			continue
		}
		for _, suffix := range cdnHostSuffixes {
			if v == suffix || strings.HasSuffix(v, "."+suffix) {
				return true
			}
		}
		if strings.Contains(v, "cdn") {
			return true
		}
	}
	return false
}

// --- API / ID 参数 / 面板 ---

var apiPathSegments = map[string]bool{
	"api": true, "rest": true, "graphql": true, "gql": true, "rpc": true,
	"v1": true, "v2": true, "v3": true, "openapi": true, "swagger": true,
}

func looksAPIPath(p string) bool {
	for _, seg := range strings.Split(strings.Trim(p, "/"), "/") {
		if apiPathSegments[strings.ToLower(seg)] {
			return true
		}
	}
	return false
}

// idParamRe 匹配 id / user_id / orderId 等 ID 型参数名。
var idParamRe = regexp.MustCompile(`(?i)^(?:.*_)?(?:id|uid|uuid|guid|pid|rid|cid|oid|tid|sid|nid|key|token|code|no|num)$`)

func idParamNames(params []map[string]any) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, p := range params {
		name := paramField(p, "name")
		if name == "" || !idParamRe.MatchString(name) {
			continue
		}
		key := strings.ToLower(name)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// idParamNamesFromURL 从 URL query 提取 ID 型参数名（资产未登记 params 时的兜底）。
func idParamNamesFromURL(raw string) []string {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	var out []string
	seen := map[string]struct{}{}
	for key := range u.Query() {
		if !idParamRe.MatchString(key) {
			continue
		}
		lk := strings.ToLower(key)
		if _, ok := seen[lk]; ok {
			continue
		}
		seen[lk] = struct{}{}
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func paramField(p map[string]any, key string) string {
	if p == nil {
		return ""
	}
	switch v := p[key].(type) {
	case string:
		return strings.TrimSpace(v)
	case json.Number:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return ""
}

// pathIDRe 匹配 REST 风格路径里的数字 / UUID 段（/user/123、/order/<uuid>）。
var pathIDRe = regexp.MustCompile(`/(\d{1,18}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(/|$)`)

func pathHasID(p string) bool { return pathIDRe.MatchString(p) }

var panelKeywords = []string{
	"admin", "administrator", "manage", "manager", "console", "dashboard",
	"system", "panel", "backend", "wp-admin", "phpmyadmin", "pma", "grafana",
	"jenkins", "kibana", "druid", "actuator", "swagger", "nacos", "zabbix", "jolokia",
}

func panelKeyword(p string) (string, bool) {
	for _, seg := range strings.Split(strings.Trim(p, "/"), "/") {
		s := strings.ToLower(seg)
		for _, kw := range panelKeywords {
			if s == kw || strings.HasPrefix(s, kw+".") || strings.HasPrefix(s, kw+"-") {
				return kw, true
			}
		}
	}
	return "", false
}

func isLoginSurface(text string) bool {
	s := strings.ToLower(text)
	for _, kw := range []string{"login", "signin", "sign in", "登录", "登陆", "认证", "sso"} {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

func writeMethod(m string) bool {
	switch strings.ToUpper(strings.TrimSpace(m)) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	}
	return false
}

var riskyTechTokens = []string{
	"shiro", "spring", "fastjson", "struts", "weblogic", "tomcat", "thinkphp",
	"laravel", "jboss", "jenkins", "gitlab", "grafana", "nacos", "druid",
	"solr", "zabbix", "yii", "django", "flask",
}

func riskyTech(techs []string) string {
	for _, t := range techs {
		lt := strings.ToLower(strings.TrimSpace(t))
		for _, token := range riskyTechTokens {
			if strings.Contains(lt, token) {
				return strings.TrimSpace(t)
			}
		}
	}
	return ""
}

// --- 探测类识别 ---

type probeRule struct {
	kind     string
	keywords []string
}

// probeRules 顺序即优先级：越具体的探测类越靠前（注入 > 认证 > 泄露 > 利用 >
// 指纹 > 发现 > 接口），避免"探测接口注入"被误归为 discovery。
var probeRules = []probeRule{
	{ProbeInjection, []string{
		"注入", "sqli", "sql injection", "xss", "ssrf", "ssti", "模板注入",
		"命令执行", "rce", "反序列化", "deserializ", "xxe", "文件上传", "upload",
		"表达式注入", "jndi",
	}},
	{ProbeAuth, []string{
		"登录", "登陆", "口令", "密码", "弱口令", "爆破", "认证", "鉴权",
		"越权", "未授权", "auth", "login", "signin", "password", "credential", "bypass",
	}},
	{ProbeExposure, []string{
		"泄露", "备份", "源码", ".git", "svn", "敏感文件", "配置文件", "swagger",
		"actuator", "目录遍历", "路径遍历", "信息泄露", "debug", "phpinfo", ".env",
	}},
	{ProbeExploit, []string{
		"利用", "getshell", "提权", "横向", "反弹", "上线", "shell", "exploit",
		"privilege", "pivot",
	}},
	{ProbeFingerprint, []string{
		"指纹", "版本", "技术栈", "组件", "识别", "banner", "fingerprint",
	}},
	{ProbeDiscovery, []string{
		"目录", "路径", "枚举", "扫描", "探测", "发现", "爬取", "爬虫", "子域",
		"endpoint", "discover", "dirscan", "dirb", "fuzz", "path",
	}},
	{ProbeAPI, []string{
		"接口", "参数", "api", "graphql", "rest",
	}},
}

// probeKindForText 从意图 summary / 事实文本识别探测类；识别不出归 generic。
func probeKindForText(text string) string {
	s := strings.ToLower(text)
	for _, rule := range probeRules {
		for _, kw := range rule.keywords {
			if matchKeyword(s, kw) {
				return rule.kind
			}
		}
	}
	return ProbeGeneric
}

// matchKeyword 对中文关键词用包含匹配；对纯 ASCII 关键词用词边界匹配，避免
// "auth" 命中 "author"、"path" 命中 "sympathy" 这类误判。
func matchKeyword(s, kw string) bool {
	if kw == "" {
		return false
	}
	if !isASCII(kw) {
		return strings.Contains(s, kw)
	}
	return hasToken(s, kw)
}

func hasToken(s, token string) bool {
	for from := 0; from <= len(s)-len(token); {
		i := strings.Index(s[from:], token)
		if i < 0 {
			return false
		}
		i += from
		beforeOK := i == 0 || !isASCIILetter(s[i-1])
		after := i + len(token)
		afterOK := after == len(s) || !isASCIILetter(s[after])
		if beforeOK && afterOK {
			return true
		}
		from = i + 1
	}
	return false
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7f {
			return false
		}
	}
	return true
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func normalizeProbe(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case ProbeInjection:
		return ProbeInjection
	case ProbeAuth:
		return ProbeAuth
	case ProbeExposure:
		return ProbeExposure
	case ProbeExploit:
		return ProbeExploit
	case ProbeFingerprint:
		return ProbeFingerprint
	case ProbeDiscovery:
		return ProbeDiscovery
	case ProbeAPI:
		return ProbeAPI
	case ProbeGeneric:
		return ProbeGeneric
	}
	return ""
}

// --- 404/412 识别 ---

// httpMissRe 只认被上下文包围的 404/412（避免把长度 4120、id=412 误判成状态码）。
var httpMissRe = regexp.MustCompile(`(?:^|[\s:()\[\]"'>,-])(404|412)(?:$|[\s.,;:)\]}"'])`)

var missContextTokens = []string{
	"http", "https", "状态", "状态码", "返回码", "status", "响应", "返回", "请求", "访问",
	"not found", "precondition failed", "curl", "wget", "get", "post", "head",
}

// httpMissStatuses 从事实文本提取 404/412 状态码（需同时出现 HTTP 语境词）。
func httpMissStatuses(text string) []int {
	s := strings.ToLower(text)
	ctx := false
	for _, token := range missContextTokens {
		if matchKeyword(s, token) {
			ctx = true
			break
		}
	}
	if !ctx {
		return nil
	}
	var out []int
	seen := map[int]struct{}{}
	for _, m := range httpMissRe.FindAllStringSubmatch(s, -1) {
		n, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}

// --- 否定索引（已拉黑集合）---

type negationKey struct {
	assetID int64
	probe   string
}

// negationHit 是「资产 × 探测类」的否定累计。
type negationHit struct {
	AssetID    int64
	Probe      string
	Hits       int // 连续 404/412 次数
	LastStatus int // 最近一次状态码（404/412）
	FactIDs    []int64
	Negated    bool // 已拉黑（达到阈值后粘性，不因后续其它事实撤销）
	lastHit    bool
}

// NegationIndex 汇总本任务 fact 图里的已否定组合。
type NegationIndex struct {
	byKey   map[negationKey]*negationHit
	byAsset map[int64][]*negationHit
}

func newNegationIndex() *NegationIndex {
	return &NegationIndex{
		byKey:   map[negationKey]*negationHit{},
		byAsset: map[int64][]*negationHit{},
	}
}

func (n *NegationIndex) empty() bool { return n == nil || len(n.byKey) == 0 }

func (n *NegationIndex) get(assetID int64, probe string) *negationHit {
	if n == nil {
		return nil
	}
	return n.byKey[negationKey{assetID: assetID, probe: probe}]
}

// addHit 记一次 404/412。连续命中累计；达到阈值或显式否定即拉黑（粘性）。
func (n *NegationIndex) addHit(assetID int64, probe string, status int, factID int64, explicit bool) {
	if n == nil || assetID <= 0 {
		return
	}
	if probe == "" {
		probe = ProbeGeneric
	}
	key := negationKey{assetID: assetID, probe: probe}
	h := n.byKey[key]
	if h == nil {
		h = &negationHit{AssetID: assetID, Probe: probe}
		n.byKey[key] = h
		n.byAsset[assetID] = append(n.byAsset[assetID], h)
	}
	if h.lastHit {
		h.Hits++
	} else {
		h.Hits = 1
	}
	h.lastHit = true
	if status > 0 {
		h.LastStatus = status
	}
	if factID > 0 {
		h.FactIDs = append(h.FactIDs, factID)
	}
	if explicit || h.Hits >= NegationRepeats {
		h.Negated = true
	}
}

// clear 打断连续计数（同资产同探测类出现非 404/412 结果）；已拉黑不撤销。
func (n *NegationIndex) clear(assetID int64, probe string) {
	if n == nil || assetID <= 0 {
		return
	}
	if probe == "" {
		probe = ProbeGeneric
	}
	h := n.byKey[negationKey{assetID: assetID, probe: probe}]
	if h == nil || h.Negated {
		return
	}
	h.Hits = 0
	h.lastHit = false
}

// wouldNegate 预测「再记一条该组合的 404/412」是否会达到拉黑阈值。
func (n *NegationIndex) wouldNegate(assetID int64, probe string) (hits int, negated bool) {
	if n == nil {
		return 1, NegationRepeats <= 1
	}
	if probe == "" {
		probe = ProbeGeneric
	}
	h := n.byKey[negationKey{assetID: assetID, probe: probe}]
	if h == nil {
		hits = 1
		return hits, hits >= NegationRepeats
	}
	if h.Negated {
		return h.Hits, true
	}
	if h.lastHit {
		hits = h.Hits + 1
	} else {
		hits = 1
	}
	return hits, hits >= NegationRepeats
}

// recordHit 供 record_fact 在落库后更新内存索引（同一批 facts 内也能连续计数）。
func (n *NegationIndex) recordHit(assetID int64, probe string, status int, factID int64) {
	n.addHit(assetID, probe, status, factID, false)
}

// blocked 判断某资产在当前探测类下是否已否定。endpoint 资产一旦确认 404/412，
// 该端点本身就不存在，任何探测类都不再派；service/subdomain 只封对应探测类
// （api 与 discovery 视为同一类"摸端点"探测，避免 404 事实被归到 discovery 后
// 与 planner 写的 api 意图对不上）。
func (n *NegationIndex) blocked(a *db.Asset, probe string) (*negationHit, bool) {
	if n == nil || a == nil {
		return nil, false
	}
	if probe != "" {
		for _, h := range n.byAsset[a.ID] {
			if !h.Negated {
				continue
			}
			if h.Probe == probe || sameProbeFamily(h.Probe, probe) {
				return h, true
			}
		}
	}
	if a.Type == assetTypeEndpoint {
		for _, h := range n.byAsset[a.ID] {
			if h.Negated {
				return h, true
			}
		}
	}
	return nil, false
}

// sameProbeFamily 把语义相近的探测类归为一族：api 与 discovery 都是"摸端点/路径"。
func sameProbeFamily(a, b string) bool {
	family := func(p string) string {
		switch p {
		case ProbeAPI, ProbeDiscovery:
			return "endpoint-discovery"
		default:
			return p
		}
	}
	return family(a) == family(b)
}

// negatedProbes 返回某资产上已拉黑的探测类（按连续次数降序）。
func (n *NegationIndex) negatedProbes(assetID int64) []*negationHit {
	if n == nil {
		return nil
	}
	var out []*negationHit
	for _, h := range n.byAsset[assetID] {
		if h.Negated {
			out = append(out, h)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Hits > out[j].Hits })
	return out
}

// summary 输出已拉黑组合（按连续次数降序，最多 limit 条）。
func (n *NegationIndex) summary(limit int) []map[string]any {
	if n == nil {
		return nil
	}
	var all []*negationHit
	for _, h := range n.byKey {
		if h.Negated {
			all = append(all, h)
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Hits != all[j].Hits {
			return all[i].Hits > all[j].Hits
		}
		if all[i].AssetID != all[j].AssetID {
			return all[i].AssetID < all[j].AssetID
		}
		return all[i].Probe < all[j].Probe
	})
	if limit > 0 && len(all) > limit {
		all = all[:limit]
	}
	out := make([]map[string]any, 0, len(all))
	for _, h := range all {
		out = append(out, map[string]any{
			"asset_id": h.AssetID,
			"probe":    h.Probe,
			"hits":     h.Hits,
			"status":   h.LastStatus,
		})
	}
	return out
}

// buildNegationIndex 读取本任务 fact 图并构建否定索引。facts 传 nil 时自行查询。
func buildNegationIndex(ts *db.ExplorationStore, facts []*db.Node) *NegationIndex {
	if ts == nil {
		return newNegationIndex()
	}
	if facts == nil {
		facts, _ = ts.ListByKind(db.KindFact, negationFactScanCap)
	}
	nodeIDs := make([]int64, 0, len(facts))
	for _, f := range facts {
		if f != nil {
			nodeIDs = append(nodeIDs, f.ID)
		}
	}
	anchors, _ := ts.NodeAnchorMap(nodeIDs)
	// 历史 fact 可能没有直接锚点（早期 record_fact 不继承意图资产）：从产生它的
	// 意图补一次，且只补「单锚点意图」——多锚点无法判断 404 属于哪个资产，补了会
	// 把整个意图的目标全拉黑。
	if extra, err := ts.FactIntentAssetMap(nodeIDs); err == nil {
		for factID, ids := range extra {
			if len(anchors[factID]) == 0 && len(ids) == 1 {
				anchors[factID] = ids
			}
		}
	}
	return buildNegationIndexFrom(facts, anchors)
}

// buildNegationIndexFrom 是纯函数版本（anchors: nodeID → asset ids），便于单测。
func buildNegationIndexFrom(facts []*db.Node, anchors map[int64][]int64) *NegationIndex {
	idx := newNegationIndex()
	// facts 按 id 降序（最新在前）；从旧到新回放，才能算"连续"。
	for i := len(facts) - 1; i >= 0; i-- {
		f := facts[i]
		if f == nil || f.Kind != db.KindFact || f.State == db.StateOrigin {
			continue
		}
		var p map[string]any
		if json.Unmarshal(f.Payload, &p) != nil {
			continue
		}
		assetIDs := anchors[f.ID]
		if len(assetIDs) == 0 {
			assetIDs = factPayloadAssetIDs(p)
		}
		if len(assetIDs) == 0 {
			continue
		}
		text := factText(p)
		probe := normalizeProbe(stringField(p, "probe"))
		if probe == "" {
			probe = probeKindForText(text)
		}
		explicit := boolField(p, "negated")
		statuses := httpMissStatuses(text)
		if explicit || len(statuses) > 0 {
			status := 0
			if len(statuses) > 0 {
				status = statuses[len(statuses)-1]
			}
			for _, aid := range assetIDs {
				idx.addHit(aid, probe, status, f.ID, explicit)
			}
			continue
		}
		// 同一资产同探测类出现非 404/412 结果 → 连续计数中断。
		for _, aid := range assetIDs {
			idx.clear(aid, probe)
		}
	}
	return idx
}

func factText(p map[string]any) string {
	var b strings.Builder
	for _, k := range []string{"summary", "detail", "evidence"} {
		if s := strings.TrimSpace(stringField(p, k)); s != "" {
			b.WriteString(s)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func stringField(p map[string]any, key string) string {
	if p == nil {
		return ""
	}
	if s, ok := p[key].(string); ok {
		return s
	}
	return ""
}

func boolField(p map[string]any, key string) bool {
	if p == nil {
		return false
	}
	b, _ := p[key].(bool)
	return b
}

func factPayloadAssetIDs(p map[string]any) []int64 {
	var out []int64
	appendID := func(v any) {
		switch n := v.(type) {
		case float64:
			if n > 0 {
				out = append(out, int64(n))
			}
		case int64:
			if n > 0 {
				out = append(out, n)
			}
		case json.Number:
			if id, err := n.Int64(); err == nil && id > 0 {
				out = append(out, id)
			}
		}
	}
	switch v := p["asset_ids"].(type) {
	case []any:
		for _, item := range v {
			appendID(item)
		}
	case []int64:
		for _, item := range v {
			appendID(item)
		}
	default:
		appendID(v)
	}
	return out
}

// --- 资产列表标注 ---

// scoredAssetView 是资产 + 派发评分的返回视图（嵌入 db.Asset，字段平铺）。
type scoredAssetView struct {
	*db.Asset
	DispatchScore    int              `json:"dispatch_score"`
	DispatchPriority int              `json:"dispatch_priority"`
	DispatchReasons  []string         `json:"dispatch_reasons,omitempty"`
	DispatchSkip     string           `json:"dispatch_skip,omitempty"`
	DispatchNegated  []map[string]any `json:"dispatch_negated,omitempty"`
}

// annotateAssets 给资产列表补派发评分/跳过/已否定标注，并按"可派优先、评分降序"
// 排序（静态资源/CDN/404-412 沉底）。nil neg 表示不做否定检查。
func (t *ToolSet) annotateAssets(assets []*db.Asset, neg *NegationIndex) []scoredAssetView {
	if len(assets) == 0 {
		return nil
	}
	out := make([]scoredAssetView, 0, len(assets))
	for _, a := range assets {
		if a == nil {
			continue
		}
		d := EvaluateAssetDispatch(a)
		v := scoredAssetView{
			Asset:            a,
			DispatchScore:    d.Score,
			DispatchPriority: d.Priority,
			DispatchReasons:  d.Reasons,
			DispatchSkip:     d.Skip,
		}
		for _, h := range neg.negatedProbes(a.ID) {
			v.DispatchNegated = append(v.DispatchNegated, map[string]any{
				"probe": h.Probe, "hits": h.Hits, "status": h.LastStatus,
			})
		}
		if v.DispatchSkip == "" {
			if h, blocked := neg.blocked(a, ""); blocked {
				if h != nil {
					v.DispatchSkip = fmt.Sprintf("已否定（%s 类探测连续 %d 次 %d）", h.Probe, h.Hits, h.LastStatus)
				} else {
					v.DispatchSkip = "已否定"
				}
			}
		}
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool {
		iSkip, jSkip := out[i].DispatchSkip != "", out[j].DispatchSkip != ""
		if iSkip != jSkip {
			return !iSkip // 可派在前
		}
		iNeg, jNeg := len(out[i].DispatchNegated) > 0, len(out[j].DispatchNegated) > 0
		if iNeg != jNeg {
			return !iNeg // 有已否定探测类的沉到干净资产之后
		}
		if out[i].DispatchScore != out[j].DispatchScore {
			return out[i].DispatchScore > out[j].DispatchScore
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// --- 小工具 ---

// dispatchOverview 生成 graph_overview 的 dispatch 块：
//   - targets：未测的 endpoint/service 资产里按派发评分降序的前 N 个（高分先打）；
//   - skipped：静态资源 / CDN 边缘 / 历史 404-412 / 已否定的硬过滤计数；
//   - negated：fact 图里已拉黑的「资产 × 探测类」组合。
//
// 只在任务上下文、覆盖度功能开启时调用；任何查询失败都降级为返回已拿到的部分。
func (t *ToolSet) dispatchOverview(factNodes []*db.Node) map[string]any {
	if t == nil || t.as == nil || t.ts == nil || t.taskID <= 0 {
		return nil
	}
	// 一次取回未测资产（endpoint/service/…），再在内存里评分排序。限制 200 条采样，
	// 避免每轮规划都为全量大范围任务跑一次重查询。
	cands, _, err := t.as.ListUntestedAssetsWithSources(t.taskID, "", 200, 0)
	if err != nil {
		cands = nil
	}
	neg := buildNegationIndex(t.ts, factNodes)

	skip := map[string]int{"static": 0, "cdn": 0, "http_404_412": 0, "negated": 0}
	type rankRow struct {
		asset *db.Asset
		d     AssetDispatch
	}
	var rows []rankRow
	if len(cands) > 0 {
		ids := make([]int64, 0, len(cands))
		for _, c := range cands {
			ids = append(ids, c.ID)
		}
		assets, err := t.as.GetByIDsInScope(t.taskID, ids)
		if err == nil {
			for _, a := range assets {
				d := EvaluateAssetDispatch(a)
				if d.Skip != "" {
					skip[d.SkipKind]++
					continue
				}
				if _, blocked := neg.blocked(a, ""); blocked { // endpoint 资产已确认不存在
					skip["negated"]++
					continue
				}
				if d.Score <= 0 {
					continue
				}
				rows = append(rows, rankRow{asset: a, d: d})
			}
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].d.Score != rows[j].d.Score {
			return rows[i].d.Score > rows[j].d.Score
		}
		return rows[i].asset.ID < rows[j].asset.ID
	})
	const topTargets = 8
	if len(rows) > topTargets {
		rows = rows[:topTargets]
	}
	targets := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		targets = append(targets, map[string]any{
			"asset_id": r.asset.ID,
			"label":    assetDispatchLabel(r.asset),
			"type":     r.asset.Type,
			"score":    r.d.Score,
			"priority": r.d.Priority,
			"reasons":  r.d.Reasons,
		})
	}

	block := map[string]any{}
	if len(targets) > 0 {
		block["targets"] = targets
	}
	skipOut := map[string]int{}
	for k, v := range skip {
		if v > 0 {
			skipOut[k] = v
		}
	}
	if len(skipOut) > 0 {
		block["skipped"] = skipOut
	}
	if ns := neg.summary(8); len(ns) > 0 {
		ids := make([]int64, 0, len(ns))
		for _, item := range ns {
			if id, ok := item["asset_id"].(int64); ok && id > 0 {
				ids = append(ids, id)
			}
		}
		labels := map[int64]string{}
		if assets, err := t.as.GetByIDs(ids); err == nil {
			for _, a := range assets {
				labels[a.ID] = assetDispatchLabel(a)
			}
		}
		for _, item := range ns {
			if id, ok := item["asset_id"].(int64); ok {
				if label := labels[id]; label != "" {
					item["label"] = label
				}
			}
		}
		block["negated"] = ns
	}
	if len(block) == 0 {
		return nil
	}
	block["note"] = "targets 按端点派发评分降序（带 ID 参数/API/非常规端口/未鉴权面板优先）；skipped 是静态资源/CDN 边缘/历史 404-412 的硬过滤；negated 是已连续 404-412 的「资产 × 探测类」组合，禁止再派。"
	return block
}

func limitStrings(in []string, n int) []string {
	if n <= 0 || len(in) <= n {
		return in
	}
	return in[:n]
}

func formatAssetIDs(ids []int64) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, fmt.Sprintf("#%d", id))
	}
	return strings.Join(parts, "、")
}
