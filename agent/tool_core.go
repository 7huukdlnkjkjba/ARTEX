package agent

// 证据核心(core): 观察台账 + 证明等级 + 闸门式 finding 写回。
//
// 设计目标(执行归代码,决策归 AI):
//   - 代码负责: 发请求、记录 receipt(request/response hash、状态、完整性)、
//     soft-404 校准、产品内容正则、鉴权三态、证明等级校验、写 finding;
//   - AI 负责: 选择目标/路径/候选、解读结果、判断是否值得成为漏洞、选择 proof_kind。
//
// 观察台账是 per-intent 的 observation_ledger.json: 每条完整请求都有
// receipt_id + response_hash。report_finding_gated 只接受本意图台账里存在、
// 请求完整、且被 finding 文本引用的 URL; 这样模型不能凭印象/版本猜测写回。
//
// 与用户草案的差异:
//   - probeFetch 复用 httpclient.go 的 newHTTPClient/fetchHTTP,因此自动走任务
//     MITM/隧道/全局代理,保持流量录制与稳定 UA;
//   - probeFetch 返回 receipt_id,路径探测并发时不再读裸 receipts 切片(避免竞态);
//   - finding gate 额外校验 observation 的 URL 与引用 URL 匹配;
//   - finding 写回复用 findingRecorder(若接入)并通知 planner,带上资产锚点。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// --- proof kinds ---

type ProofKind string

const (
	ProofUnproven       ProofKind = "unproven"
	ProofStatic         ProofKind = "static_analysis"
	ProofReflection     ProofKind = "reflection_observed"
	ProofDifferential   ProofKind = "differential"
	ProofContentHash    ProofKind = "content_hash_migration"
	ProofIdentityMarker ProofKind = "identity_marker"
	ProofServerState    ProofKind = "server_state"
	ProofOOBCallback    ProofKind = "oob_callback"
)

var proofRank = map[ProofKind]int{
	ProofUnproven: 0, ProofStatic: 1, ProofReflection: 2, ProofDifferential: 3,
	ProofContentHash: 4, ProofIdentityMarker: 5, ProofServerState: 6, ProofOOBCallback: 7,
}

func coerceProofKind(v string) ProofKind {
	p := ProofKind(strings.TrimSpace(strings.ToLower(v)))
	if _, ok := proofRank[p]; ok {
		return p
	}
	return ProofUnproven
}

// --- receipt ledger ---

type Receipt struct {
	ID           string `json:"id"`
	RunID        string `json:"run_id"`
	Tool         string `json:"tool"`
	URL          string `json:"url"`
	Method       string `json:"method"`
	Status       int    `json:"status"`
	RequestHash  string `json:"request_hash"`
	ResponseHash string `json:"response_hash"`
	Principal    string `json:"principal,omitempty"`
	Complete     bool   `json:"complete"`
	At           string `json:"at"`
}

type ReceiptLedger struct {
	mu       sync.Mutex
	path     string
	runID    string
	receipts []Receipt
}

func newReceiptLedger(root, runID string) *ReceiptLedger {
	if root == "" {
		return nil
	}
	l := &ReceiptLedger{path: filepath.Join(root, "observation_ledger.json"), runID: runID}
	if raw, err := os.ReadFile(l.path); err == nil {
		_ = json.Unmarshal(raw, &l.receipts)
	}
	return l
}

// SetReceiptLedger initializes this run's observation ledger. root is the
// per-intent working directory; an empty root disables the ledger (probe tools
// still work, but report_finding_gated refuses to write).
func (t *ToolSet) SetReceiptLedger(root, runID string) {
	t.ledger = newReceiptLedger(root, runID)
}

func (l *ReceiptLedger) record(r Receipt) Receipt {
	if l == nil {
		return r
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if r.ID == "" {
		// len(l.receipts) is inside the mutex and makes the ID unique even when
		// Windows' coarse clock returns the same nanosecond for two rapid probes.
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s|%d|%d|%d",
			r.Tool, r.URL, r.Method, r.RequestHash, r.Status, time.Now().UnixNano(), len(l.receipts))))
		r.ID = hex.EncodeToString(sum[:])[:16]
	}
	if r.At == "" {
		r.At = time.Now().UTC().Format(time.RFC3339)
	}
	if r.RunID == "" {
		r.RunID = l.runID
	}
	l.receipts = append(l.receipts, r)
	raw, _ := json.MarshalIndent(l.receipts, "", "  ")
	_ = os.MkdirAll(filepath.Dir(l.path), 0o755)
	_ = os.WriteFile(l.path, raw, 0o600)
	return r
}

func (l *ReceiptLedger) has(rawURL string, completeOnly bool) bool {
	if l == nil {
		return false
	}
	key := receiptURLKey(rawURL)
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, r := range l.receipts {
		if receiptURLKey(r.URL) != key {
			continue
		}
		if completeOnly && !r.Complete {
			continue
		}
		return true
	}
	return false
}

func (l *ReceiptLedger) find(id string) (Receipt, bool) {
	if l == nil {
		return Receipt{}, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, r := range l.receipts {
		if r.ID == id {
			return r, true
		}
	}
	return Receipt{}, false
}

// receiptURLKey normalizes host case, fragments and a trailing slash so a model
// citing "https://HOST/path/" still matches a probe recorded as
// "https://host/path". Query strings stay significant.
func receiptURLKey(raw string) string {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return strings.TrimRight(raw, "/")
	}
	u.Fragment = ""
	u.Host = strings.ToLower(u.Host)
	if (u.Scheme == "http" && u.Port() == "80") || (u.Scheme == "https" && u.Port() == "443") {
		u.Host = u.Hostname()
	}
	return strings.TrimRight(u.String(), "/")
}

var citationURLRe = regexp.MustCompile(`https?://[^\s"'\]\)]+`)

func citedURLs(text string) []string {
	raw := citationURLRe.FindAllString(text, -1)
	out := make([]string, 0, len(raw))
	for _, u := range raw {
		out = append(out, strings.TrimRight(u, ".,;:)]}>'"))
	}
	return out
}

type findingGate struct {
	ledger         *ReceiptLedger
	proofKind      ProofKind
	observationIDs []string
}

func newFindingGate(l *ReceiptLedger, proof string, obsIDs []string) findingGate {
	ids := make([]string, 0, len(obsIDs))
	for _, id := range obsIDs {
		if id = strings.TrimSpace(id); id != "" {
			ids = append(ids, id)
		}
	}
	return findingGate{ledger: l, proofKind: coerceProofKind(proof), observationIDs: ids}
}

func (g findingGate) verify(text string) error {
	if g.ledger == nil {
		return fmt.Errorf("观察台账未初始化（本 run 缺少工作目录）；不能使用闸门写回")
	}
	urls := citedURLs(text)
	if len(urls) == 0 {
		return fmt.Errorf("finding 未引用任何 URL，无法对照本意图观察台账")
	}
	for _, u := range urls {
		if !g.ledger.has(u, true) {
			return fmt.Errorf("引用 URL 不在本意图观察台账（或请求不完整）: %s", u)
		}
	}
	if g.proofKind == ProofUnproven {
		return fmt.Errorf("finding 必须声明 proof_kind，unproven 不允许写回")
	}
	if len(g.observationIDs) == 0 {
		return fmt.Errorf("finding 必须提供 observation_ids（path_probe/admin_surface/fingerprint/auth_probe 返回的 receipt_id）")
	}
	var refHash string
	for _, id := range g.observationIDs {
		r, ok := g.ledger.find(id)
		if !ok || !r.Complete {
			return fmt.Errorf("observation_id %s 不在本意图台账或请求不完整", id)
		}
		if r.Tool == "calibrate" {
			return fmt.Errorf("observation_id %s 来自 soft-404 校准，不能作为 finding 证据", id)
		}
		matched := false
		for _, u := range urls {
			if receiptURLKey(u) == receiptURLKey(r.URL) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("observation_id %s 的 URL (%s) 与 finding 引用的 URL 不匹配", id, r.URL)
		}
		if refHash == "" {
			refHash = r.ResponseHash
		} else if r.ResponseHash != refHash {
			return fmt.Errorf("多条 observation 的 response_hash 不一致，无法绑定同一证据")
		}
	}
	return nil
}

// --- probe ---

type probeResult struct {
	Status      int
	Headers     map[string]string
	Body        string
	Bytes       int
	ContentType string
	SHA256      string
	Complete    bool
	ReceiptID   string
}

func (t *ToolSet) probeFetch(ctx context.Context, tool, rawURL, method string, timeout time.Duration) (probeResult, error) {
	return t.probeFetchWithHeaders(ctx, tool, rawURL, method, nil, "", timeout)
}

func (t *ToolSet) probeFetchWithCookie(ctx context.Context, tool, rawURL, cookie string, timeout time.Duration) (probeResult, error) {
	return t.probeFetchWithHeaders(ctx, tool, rawURL, http.MethodGet, map[string]string{"Cookie": cookie}, hashString(cookie), timeout)
}

// probeFetchWithHeaders is the single probe path: timeout/scope/method validation,
// task proxy + stable UA (via fetchHTTP), receipt recording and hashes.
func (t *ToolSet) probeFetchWithHeaders(ctx context.Context, tool, rawURL, method string, headers map[string]string, principal string, timeout time.Duration) (probeResult, error) {
	var out probeResult
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if timeout > 60*time.Second {
		timeout = 60 * time.Second
	}
	m, err := normalizeHTTPMethod(method)
	if err != nil {
		return out, err
	}
	u, err := parseReconURL(rawURL)
	if err != nil {
		return out, err
	}
	if err := t.assertInScope(u.Hostname()); err != nil {
		return out, err
	}
	if err := validateHTTPHeaders(headers); err != nil {
		return out, err
	}
	client, err := t.newHTTPClient(true)
	if err != nil {
		return out, err
	}
	reqBody, _ := json.Marshal(map[string]string{
		"method": m, "url": rawURL, "principal": principal,
	})
	reqSum := sha256.Sum256(reqBody)
	reqHash := hex.EncodeToString(reqSum[:])

	fr := t.fetchHTTP(ctx, client, rawURL, httpFetchOptions{
		Method: m, Headers: headers, Follow: false, Timeout: timeout,
	})
	if fr.Error != "" {
		r := t.ledger.record(Receipt{
			Tool: tool, URL: rawURL, Method: m, Status: fr.Status,
			RequestHash: reqHash, Principal: principal, Complete: false,
		})
		out.Status = fr.Status
		out.ReceiptID = r.ID
		return out, fmt.Errorf("%s", fr.Error)
	}
	hdrs := map[string]string{}
	for k := range fr.Headers {
		hdrs[strings.ToLower(k)] = fr.Headers.Get(k)
	}
	sum := sha256.Sum256(fr.Body)
	out = probeResult{
		Status: fr.Status, Headers: hdrs, Body: string(fr.Body), Bytes: fr.BodyLen,
		ContentType: fr.Headers.Get("Content-Type"),
		SHA256:      hex.EncodeToString(sum[:]), Complete: true,
	}
	r := t.ledger.record(Receipt{
		Tool: tool, URL: rawURL, Method: m, Status: fr.Status,
		RequestHash: reqHash, ResponseHash: out.SHA256,
		Principal: principal, Complete: true,
	})
	out.ReceiptID = r.ID
	return out, nil
}

func discoverySignature(r probeResult) string {
	words := 0
	for _, f := range strings.Fields(r.Body) {
		if f != "" {
			words++
		}
	}
	lines := strings.Count(r.Body, "\n") + 1
	ct := strings.ToLower(strings.TrimSpace(strings.SplitN(r.ContentType, ";", 2)[0]))
	return fmt.Sprintf("%d|%s|%s|%d|%d|%d|%s", r.Status, ct, r.SHA256, r.Bytes, words, lines, r.Headers["location"])
}

func randomToken(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	now := uint64(time.Now().UnixNano())
	for i := range b {
		now = now*6364136223846793005 + 1442695040888963407
		b[i] = chars[int((now>>33)%uint64(len(chars)))]
	}
	return string(b)
}

// calibrateSoft404 probes three random paths; any signature that comes back is a
// soft-404 template. Real hits matching one of these signatures are discarded.
func (t *ToolSet) calibrateSoft404(ctx context.Context, origin string, timeout time.Duration) map[string]bool {
	sigs := map[string]bool{}
	for i := 0; i < 3; i++ {
		r, err := t.probeFetch(ctx, "calibrate", strings.TrimRight(origin, "/")+"/zzqq-"+randomToken(12), "", timeout)
		if err != nil || !r.Complete {
			continue
		}
		sigs[discoverySignature(r)] = true
	}
	return sigs
}

// --- path_probe ---

var sensitivePaths = []string{
	"/.git/config", "/.git/HEAD", "/.svn/entries", "/.DS_Store", "/.env", "/.env.local",
	"/.env.production", "/web.config", "/robots.txt", "/crossdomain.xml",
	"/phpinfo.php", "/info.php", "/server-status", "/server-info", "/.htaccess",
	"/.htpasswd", "/swagger", "/swagger/", "/swagger-ui", "/swagger-ui.html",
	"/swagger.json", "/api-docs", "/api-docs/swagger.json", "/v2/api-docs",
	"/v3/api-docs", "/openapi.json", "/openapi.yaml", "/graphql", "/actuator",
	"/actuator/health", "/actuator/env", "/actuator/heapdump", "/actuator/configprops",
	"/actuator/beans", "/druid/", "/druid/index.html", "/console/", "/admin/",
	"/manager/html", "/manager/status", "/debug/pprof", "/debug/pprof/",
	"/debug/vars", "/metrics", "/health", "/status", "/_cat/indices",
	"/backup.sql", "/backup.zip", "/dump.sql", "/db.sql", "/database.sql",
	"/WEB-INF/web.xml", "/META-INF/", "/composer.json", "/package.json",
	"/.well-known/security.txt", "/sitemap.xml", "/.well-known/openid-configuration",
	"/.well-known/oauth-authorization-server", "/saml/metadata",
}

type pathHit struct {
	Path        string `json:"path"`
	Status      int    `json:"status"`
	Bytes       int    `json:"bytes"`
	ContentType string `json:"content_type"`
	ReceiptID   string `json:"receipt_id"`
}

func (t *ToolSet) toolPathProbe() actool.CoreTool {
	return writeTool("path_probe",
		"敏感路径探测（soft-404 校准 + 观察台账）。对 base_url 下的路径并发 GET，过滤 404/410 与 soft-404 模板，返回命中路径 + 状态码 + 字节数 + 台账 receipt_id。\n"+
			"执行归代码：scope、代理/录制、并发/超时、soft-404 签名、receipt 记录；路径选择与结果解读归你。命中不等于漏洞，需进一步验证。",
		obj(map[string]any{
			"base_url":    str("目标 origin，如 https://host:8443"),
			"paths":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "可选：路径列表；留空用内置敏感路径字典"},
			"timeout_ms":  map[string]any{"type": "integer", "description": "单请求超时 ms，默认 10000，上限 60000", "default": 10000},
			"concurrency": map[string]any{"type": "integer", "description": "并发数，默认 8，上限 32", "default": 8},
		}, "base_url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				BaseURL     string   `json:"base_url"`
				Paths       []string `json:"paths"`
				TimeoutMs   int      `json:"timeout_ms"`
				Concurrency int      `json:"concurrency"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败：" + err.Error()), nil
			}
			if strings.TrimSpace(a.BaseURL) == "" {
				return actool.Errorf("base_url 必填"), nil
			}
			u, err := parseReconURL(a.BaseURL)
			if err != nil {
				return actool.Errorf("base_url 非法：" + err.Error()), nil
			}
			origin := u.Scheme + "://" + u.Host
			timeout := time.Duration(a.TimeoutMs) * time.Millisecond
			if timeout <= 0 {
				timeout = 10 * time.Second
			}
			if timeout > 60*time.Second {
				timeout = 60 * time.Second
			}
			conc := a.Concurrency
			if conc <= 0 {
				conc = 8
			}
			if conc > 32 {
				conc = 32
			}
			paths := normalizeProbePaths(a.Paths)
			if len(a.Paths) > 0 && len(paths) == 0 {
				return actool.Errorf("paths 只接受路径（不要带 http:// 前缀，也不要用 /）"), nil
			}
			if len(paths) == 0 {
				paths = normalizeProbePaths(sensitivePaths)
			}
			if len(paths) == 0 {
				return actool.Errorf("没有可探测的路径"), nil
			}
			soft := t.calibrateSoft404(ctx, origin, timeout)
			var mu sync.Mutex
			hits := []pathHit{}
			sem := make(chan struct{}, conc)
			var wg sync.WaitGroup
			for _, p := range paths {
				wg.Add(1)
				go func(p string) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					full := origin + p
					r, err := t.probeFetch(ctx, "path_probe", full, "", timeout)
					if err != nil || !r.Complete {
						return
					}
					if r.Status == 404 || r.Status == 410 || soft[discoverySignature(r)] {
						return
					}
					mu.Lock()
					hits = append(hits, pathHit{
						Path: p, Status: r.Status, Bytes: r.Bytes,
						ContentType: r.ContentType, ReceiptID: r.ReceiptID,
					})
					mu.Unlock()
				}(p)
			}
			wg.Wait()
			sort.Slice(hits, func(i, j int) bool {
				if hits[i].Path == hits[j].Path {
					return hits[i].Status < hits[j].Status
				}
				return hits[i].Path < hits[j].Path
			})
			return jsonResult(map[string]any{
				"base_url": origin, "probed": len(paths), "found": hits,
			})
		})
}

func normalizeProbePaths(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, p := range in {
		p = strings.TrimSpace(p)
		if p == "" || strings.Contains(p, "://") {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		if p == "/" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// --- admin_surface ---

type adminSurface struct {
	Path     string
	Kind     string
	Evidence *regexp.Regexp
}

var adminSurfaces = []adminSurface{
	{"/actuator", "spring-actuator", regexp.MustCompile(`"_links"\s*:\s*\{[\s\S]*"(?:health|self)"\s*:`)},
	{"/actuator/env", "actuator-env", regexp.MustCompile(`"propertySources"\s*:`)},
	{"/actuator/health", "actuator-health", regexp.MustCompile(`"status"\s*:\s*"(?:UP|DOWN|OUT_OF_SERVICE|UNKNOWN)"`)},
	{"/actuator/heapdump", "actuator-heapdump", regexp.MustCompile(`^JAVA PROFILE 1\.0`)},
	{"/actuator/configprops", "actuator-configprops", regexp.MustCompile(`"(?:contexts|beans)"\s*:`)},
	{"/actuator/mappings", "actuator-mappings", regexp.MustCompile(`"(?:contexts|dispatcherServlets)"\s*:`)},
	{"/swagger-ui.html", "swagger-ui", regexp.MustCompile(`(?i)swagger-ui|SwaggerUIBundle`)},
	{"/swagger-ui/index.html", "swagger-ui", regexp.MustCompile(`(?i)swagger-ui|SwaggerUIBundle`)},
	{"/v3/api-docs", "openapi-v3", regexp.MustCompile(`"(?:openapi|swagger)"\s*:`)},
	{"/v2/api-docs", "openapi-v2", regexp.MustCompile(`"(?:openapi|swagger)"\s*:`)},
	{"/openapi.json", "openapi", regexp.MustCompile(`"(?:openapi|swagger)"\s*:`)},
	{"/druid/index.html", "druid-console", regexp.MustCompile(`(?i)Druid Stat|druid\.js`)},
	{"/nacos/", "nacos-console", regexp.MustCompile(`(?i)nacos.*(?:console|login)|nacos-logo`)},
	{"/eureka/apps", "eureka-registry", regexp.MustCompile(`<applications(?:\s|>)`)},
	{"/jenkins/login", "jenkins", regexp.MustCompile(`(?i)jenkins\.js|Jenkins-Crumb`)},
	{"/manager/html", "tomcat-manager", regexp.MustCompile(`Tomcat Web Application Manager`)},
	{"/_cat/indices", "elasticsearch-cat", regexp.MustCompile(`\b(?:green|yellow|red)\s+(?:open|close)\s+`)},
	{"/api/v1/pods", "k8s-pods", regexp.MustCompile(`"kind"\s*:\s*"PodList"`)},
	{"/metrics", "metrics-endpoint", regexp.MustCompile(`(?m)^# (?:HELP|TYPE) `)},
}

func (t *ToolSet) toolAdminSurface() actool.CoreTool {
	return writeTool("admin_surface",
		"框架管理面板发现（soft-404 校准 + 产品内容正则 + 观察台账）。返回 found（内容证据匹配，带 receipt_id）与 candidates（仅 2xx 但内容未匹配）。\n"+
			"执行归代码：请求、soft-404、正则、receipt；是否利用/上报由你判断。found 是暴露面证据，不等于已利用。",
		obj(map[string]any{
			"base_url":   str("目标 origin"),
			"timeout_ms": map[string]any{"type": "integer", "description": "单请求超时 ms，默认 8000，上限 30000", "default": 8000},
		}, "base_url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				BaseURL   string `json:"base_url"`
				TimeoutMs int    `json:"timeout_ms"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败：" + err.Error()), nil
			}
			if strings.TrimSpace(a.BaseURL) == "" {
				return actool.Errorf("base_url 必填"), nil
			}
			u, err := parseReconURL(a.BaseURL)
			if err != nil {
				return actool.Errorf("base_url 非法：" + err.Error()), nil
			}
			origin := u.Scheme + "://" + u.Host
			timeout := time.Duration(a.TimeoutMs) * time.Millisecond
			if timeout <= 0 {
				timeout = 8 * time.Second
			}
			if timeout > 30*time.Second {
				timeout = 30 * time.Second
			}
			runCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
			defer cancel()
			soft := t.calibrateSoft404(runCtx, origin, timeout)
			type found struct {
				URL       string `json:"url"`
				Kind      string `json:"kind"`
				Status    int    `json:"status"`
				Bytes     int    `json:"bytes"`
				ReceiptID string `json:"receipt_id"`
				Proof     string `json:"proof_kind"`
			}
			type cand struct {
				URL       string `json:"url"`
				Reason    string `json:"reason"`
				ReceiptID string `json:"receipt_id,omitempty"`
			}
			founds := []found{}
			cands := []cand{}
			for _, s := range adminSurfaces {
				full := origin + s.Path
				r, err := t.probeFetch(runCtx, "admin_surface", full, "", timeout)
				if err != nil || !r.Complete {
					continue
				}
				if r.Status < 200 || r.Status >= 300 || r.Bytes == 0 {
					continue
				}
				if soft[discoverySignature(r)] {
					continue
				}
				if s.Evidence.MatchString(r.Body) {
					founds = append(founds, found{
						URL: full, Kind: s.Kind, Status: r.Status, Bytes: r.Bytes,
						ReceiptID: r.ReceiptID, Proof: string(ProofReflection),
					})
				} else {
					cands = append(cands, cand{
						URL: full, Reason: "product-content-unverified", ReceiptID: r.ReceiptID,
					})
				}
			}
			return jsonResult(map[string]any{
				"base_url": origin, "probed": len(adminSurfaces), "found": founds, "candidates": cands,
			})
		})
}

// --- fingerprint ---

type wafSig struct {
	Name   string
	Header string
	Value  *regexp.Regexp
}

var wafSigs = []wafSig{
	{"cloudflare", "server", regexp.MustCompile(`(?i)cloudflare`)},
	{"cloudflare", "cf-ray", regexp.MustCompile(`.*`)},
	{"akamai", "server", regexp.MustCompile(`(?i)akamai`)},
	{"fastly", "server", regexp.MustCompile(`(?i)fastly`)},
	{"aws-waf", "x-amzn-requestid", regexp.MustCompile(`.*`)},
	{"aws-cf", "x-amz-cf-id", regexp.MustCompile(`.*`)},
	{"aliyun-waf", "server", regexp.MustCompile(`(?i)tengine`)},
	{"qcloud-waf", "server", regexp.MustCompile(`(?i)sqr`)},
	{"baidu-yunjia", "server", regexp.MustCompile(`(?i)yunjiasu`)},
	{"safedog", "x-powered-by", regexp.MustCompile(`(?i)safedog|waf`)},
	{"baota", "server", regexp.MustCompile(`(?i)bt[_-]?(?:waf|firewall)`)},
	{"qiniu-cdn", "x-qiniu-zone", regexp.MustCompile(`.*`)},
	{"modsecurity", "server", regexp.MustCompile(`(?i)mod_security`)},
}

var securityHeaders = []string{
	"strict-transport-security", "content-security-policy",
	"x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy",
}

func (t *ToolSet) toolFingerprint() actool.CoreTool {
	return writeTool("fingerprint",
		"WAF/CDN 识别 + 安全响应头审计 + cookie 安全属性检查（返回 receipt_id 供闸门引用）。",
		obj(map[string]any{
			"base_url":   str("目标 URL"),
			"timeout_ms": map[string]any{"type": "integer", "description": "超时 ms，默认 10000，上限 60000", "default": 10000},
		}, "base_url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				BaseURL   string `json:"base_url"`
				TimeoutMs int    `json:"timeout_ms"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败：" + err.Error()), nil
			}
			if strings.TrimSpace(a.BaseURL) == "" {
				return actool.Errorf("base_url 必填"), nil
			}
			timeout := time.Duration(a.TimeoutMs) * time.Millisecond
			if timeout <= 0 {
				timeout = 10 * time.Second
			}
			if timeout > 60*time.Second {
				timeout = 60 * time.Second
			}
			r, err := t.probeFetch(ctx, "fingerprint", a.BaseURL, "", timeout)
			if err != nil {
				return actool.Errorf("请求失败: " + err.Error()), nil
			}
			if !r.Complete {
				return actool.Errorf("请求不完整：未拿到完整响应"), nil
			}
			waf := []string{}
			for _, s := range wafSigs {
				if v, ok := r.Headers[s.Header]; ok && s.Value.MatchString(v) {
					dup := false
					for _, w := range waf {
						if w == s.Name {
							dup = true
							break
						}
					}
					if !dup {
						waf = append(waf, s.Name)
					}
				}
			}
			missing := []string{}
			present := map[string]string{}
			for _, h := range securityHeaders {
				if v, ok := r.Headers[h]; ok && v != "" {
					present[h] = v
				} else {
					missing = append(missing, h)
				}
			}
			return jsonResult(map[string]any{
				"base_url": a.BaseURL, "status": r.Status, "receipt_id": r.ReceiptID,
				"server": r.Headers["server"], "powered_by": r.Headers["x-powered-by"],
				"waf": waf, "security_headers": present, "missing_headers": missing,
			})
		})
}

// --- auth_probe ---

func (t *ToolSet) toolAuthProbe() actool.CoreTool {
	return writeTool("auth_probe",
		"端点鉴权三态：anonymous / auth_required / ambiguous。带 edge_blocked 检测（全 403/429 = 边缘拦截，不是端点鉴权）。可选 cookie 做认证对照；返回 receipt_id。",
		obj(map[string]any{
			"urls":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "要探测的完整 URL 列表"},
			"cookie":     str("可选：带 cookie 做认证对照（不写回结果）"),
			"timeout_ms": map[string]any{"type": "integer", "description": "单请求超时 ms，默认 8000，上限 30000", "default": 8000},
		}, "urls"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				URLs      []string `json:"urls"`
				Cookie    string   `json:"cookie"`
				TimeoutMs int      `json:"timeout_ms"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败：" + err.Error()), nil
			}
			if len(a.URLs) == 0 {
				return actool.Errorf("urls 必填"), nil
			}
			if len(a.URLs) > 100 {
				return actool.Errorf("urls 最多 100 个"), nil
			}
			timeout := time.Duration(a.TimeoutMs) * time.Millisecond
			if timeout <= 0 {
				timeout = 8 * time.Second
			}
			if timeout > 30*time.Second {
				timeout = 30 * time.Second
			}
			runCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
			defer cancel()
			type anonHit struct {
				URL       string `json:"url"`
				Status    int    `json:"status"`
				ReceiptID string `json:"receipt_id,omitempty"`
			}
			type authHit struct {
				URL           string `json:"url"`
				AnonStatus    int    `json:"anon_status"`
				AuthStatus    int    `json:"auth_status"`
				ReceiptID     string `json:"receipt_id,omitempty"`
				AuthReceiptID string `json:"auth_receipt_id,omitempty"`
			}
			type ambHit struct {
				URL       string `json:"url"`
				AnonCode  int    `json:"anon_status"`
				Note      string `json:"note"`
				ReceiptID string `json:"receipt_id,omitempty"`
			}
			anons := []anonHit{}
			auths := []authHit{}
			ambs := []ambHit{}
			statusTally := map[int]int{}
			for _, raw := range a.URLs {
				rAnon, err := t.probeFetch(runCtx, "auth_probe", raw, "", timeout)
				if err != nil || !rAnon.Complete {
					continue
				}
				statusTally[rAnon.Status]++
				anonOK := rAnon.Status >= 200 && rAnon.Status < 300
				anonAuth := rAnon.Status == 401 || rAnon.Status == 403
				anonRedirect := rAnon.Status >= 300 && rAnon.Status < 400
				rid := rAnon.ReceiptID
				if a.Cookie == "" {
					switch {
					case anonRedirect:
						ambs = append(ambs, ambHit{URL: raw, AnonCode: rAnon.Status, Note: fmt.Sprintf("auth redirect %d", rAnon.Status), ReceiptID: rid})
					case anonOK:
						anons = append(anons, anonHit{URL: raw, Status: rAnon.Status, ReceiptID: rid})
					case anonAuth:
						auths = append(auths, authHit{URL: raw, AnonStatus: rAnon.Status, AuthStatus: 0, ReceiptID: rid})
					default:
						ambs = append(ambs, ambHit{URL: raw, AnonCode: rAnon.Status, Note: fmt.Sprintf("status %d", rAnon.Status), ReceiptID: rid})
					}
					continue
				}
				rAuth, err := t.probeFetchWithCookie(runCtx, "auth_probe", raw, a.Cookie, timeout)
				if err != nil || !rAuth.Complete {
					ambs = append(ambs, ambHit{URL: raw, AnonCode: rAnon.Status, Note: "auth request failed", ReceiptID: rid})
					continue
				}
				authOK := rAuth.Status >= 200 && rAuth.Status < 300
				switch {
				case anonOK:
					anons = append(anons, anonHit{URL: raw, Status: rAnon.Status, ReceiptID: rid})
				case !anonOK && authOK:
					auths = append(auths, authHit{
						URL: raw, AnonStatus: rAnon.Status, AuthStatus: rAuth.Status,
						ReceiptID: rid, AuthReceiptID: rAuth.ReceiptID,
					})
				case anonAuth && !authOK:
					auths = append(auths, authHit{
						URL: raw, AnonStatus: rAnon.Status, AuthStatus: rAuth.Status,
						ReceiptID: rid, AuthReceiptID: rAuth.ReceiptID,
					})
				default:
					ambs = append(ambs, ambHit{
						URL: raw, AnonCode: rAnon.Status,
						Note: fmt.Sprintf("anon=%d auth=%d", rAnon.Status, rAuth.Status), ReceiptID: rid,
					})
				}
			}
			total := len(anons) + len(auths) + len(ambs)
			domStatus, domCount := 0, 0
			for s, c := range statusTally {
				if c > domCount {
					domStatus, domCount = s, c
				}
			}
			edge := total >= 4 && float64(domCount)/float64(total) >= 0.8 &&
				(domStatus == 403 || domStatus == 429)
			return jsonResult(map[string]any{
				"probed": total, "edge_blocked": edge, "anonymous": anons,
				"auth_required": auths, "ambiguous": ambs,
			})
		})
}

func hashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:16]
}

// --- gated finding ---

func (t *ToolSet) toolReportFindingGated() actool.CoreTool {
	return t.writeExpTool("report_finding_gated",
		"登记确认漏洞（证据闸门版）。必须带 proof_kind（非 unproven）+ observation_ids（path_probe/admin_surface/fingerprint/auth_probe 返回的 receipt_id）。\n"+
			"引用的每个 URL 必须在本意图观察台账里且请求完整；每条 observation 的 URL 必须与引用 URL 匹配、response_hash 一致。不满足整条拒绝。\n"+
			"执行归代码：闸门校验、资产锚定、finding 写回/合并/通知；是否上报、proof_kind 选择由你决定。",
		obj(map[string]any{
			"vulnclass":       str("漏洞类别"),
			"name":            str("漏洞名称"),
			"severity":        str("critical|high|medium|low"),
			"summary":         str("摘要，必须含真实 URL"),
			"evidence":        str("证据文本，引用的每个 URL 必须在台账里"),
			"proof_kind":      str("unproven|static_analysis|reflection_observed|differential|content_hash_migration|identity_marker|server_state|oob_callback（unproven 会被拒绝）"),
			"observation_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "本意图观察台账的 receipt_id 列表"},
			"intent_id":       idp("产生本 finding 的意图 id（省略用当前意图）"),
		}, "vulnclass", "name", "severity", "summary", "evidence", "proof_kind", "observation_ids"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				VulnClass      string   `json:"vulnclass"`
				Name           string   `json:"name"`
				Severity       string   `json:"severity"`
				Summary        string   `json:"summary"`
				Evidence       string   `json:"evidence"`
				ProofKind      string   `json:"proof_kind"`
				ObservationIDs []string `json:"observation_ids"`
				IntentID       int64    `json:"intent_id"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败：" + err.Error()), nil
			}
			if strings.TrimSpace(a.Name) == "" || strings.TrimSpace(a.Summary) == "" {
				return actool.Errorf("name/summary 必填"), nil
			}
			if strings.TrimSpace(a.VulnClass) == "" {
				return actool.Errorf("vulnclass 必填"), nil
			}
			if strings.TrimSpace(a.Evidence) == "" {
				return actool.Errorf("evidence 必填（必须引用台账里的 URL）"), nil
			}
			gate := newFindingGate(t.ledger, a.ProofKind, a.ObservationIDs)
			if err := gate.verify(a.Summary + "\n" + a.Evidence); err != nil {
				return actool.Errorf("finding 写回被拒: " + err.Error()), nil
			}
			sev := strings.ToLower(strings.TrimSpace(a.Severity))
			switch sev {
			case "critical", "high", "medium", "low":
			default:
				sev = "low"
			}
			intentID := a.IntentID
			if intentID <= 0 {
				intentID = t.ownerNode
			}
			text := a.Summary + "\n" + a.Evidence
			input := db.RecordFindingInput{
				TaskID: t.taskID, ExplorationID: t.ts.ID(), IntentID: intentID,
				VulnClass: a.VulnClass, Name: a.Name, Severity: sev,
				Summary: a.Summary, Evidence: a.Evidence, Worker: t.worker,
				AssetIDs: t.citedAssetIDs(text),
			}
			var recorded *db.RecordedFinding
			var err error
			if t.findingRecorder != nil {
				recorded, err = t.findingRecorder.Record(ctx, input, nil)
			} else {
				recorded, err = t.ts.RecordFinding(ctx, input)
			}
			if err != nil {
				return actool.Errorf("写回失败: " + err.Error()), nil
			}
			if recorded == nil {
				return actool.Errorf("写回失败: 未返回 finding 记录"), nil
			}
			t.writes.Findings++
			if t.notifyFinding != nil {
				t.notifyFinding(intentID, a.Summary)
			} else if t.notify != nil {
				t.notify()
			}
			return jsonResult(map[string]any{
				"finding_id": recorded.FindingID, "node_id": recorded.NodeID,
				"merged": recorded.Merged, "proof_kind": string(gate.proofKind),
				"observation_ids": gate.observationIDs,
			})
		})
}

// citedAssetIDs resolves assets from the HTTP URLs cited in the finding, so the
// gated finding participates in the same merge/asset anchoring as report_finding.
func (t *ToolSet) citedAssetIDs(text string) []int64 {
	if t.as == nil {
		return nil
	}
	seen := map[int64]bool{}
	ids := []int64{}
	for _, u := range citedURLs(text) {
		parsed, err := url.Parse(u)
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		assets, err := t.as.QueryByHost(parsed.Hostname(), 0)
		if err != nil {
			continue
		}
		for _, a := range assets {
			if a == nil || seen[a.ID] {
				continue
			}
			seen[a.ID] = true
			ids = append(ids, a.ID)
			break
		}
		if len(ids) >= 5 {
			break
		}
	}
	return ids
}
