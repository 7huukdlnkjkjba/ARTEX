package server

// web_audit: fetch a page and its same-host (or explicitly allowed) JS/CSS,
// extract forms, comments, API routes, secrets and DOM-XSS sinks. The HTTP
// client uses the task MITM proxy when available so the traffic recorder keeps
// the chain; every asset fetch is scope-checked to avoid turning an HTML src
// attribute into an SSRF primitive.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/agent"
	pgdb "github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
	actool "github.com/Autumn-27/norma/tool"
	"golang.org/x/net/html"
)

type WebAuditParams struct {
	URL             string `json:"url"`
	MaxFiles        int    `json:"max_files"`
	MaxSize         int    `json:"max_size"`
	IncludeExternal bool   `json:"include_external,omitempty"`
}

type WebAuditResult struct {
	Status       string   `json:"status"`
	TargetURL    string   `json:"target_url"`
	Egress       string   `json:"egress,omitempty"`
	Forms        []string `json:"forms,omitempty"`
	HTMLComments []string `json:"html_comments,omitempty"`
	JSPaths      []string `json:"js_paths,omitempty"`
	CSSPaths     []string `json:"css_paths,omitempty"`
	APIRoutes    []string `json:"api_routes,omitempty"`
	Secrets      []string `json:"secrets,omitempty"`
	DOMXSSSinks  []string `json:"dom_xss_sinks,omitempty"`
	Errors       []string `json:"errors,omitempty"`
}

func (s *Server) webAuditTools() []actool.CoreTool {
	return []actool.CoreTool{s.toolWebAudit()}
}

func (s *Server) seedWebAuditTools() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	workerAgents, _ := json.Marshal([]string{"worker"})
	for _, t := range s.webAuditTools() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.PG().SeedTool(t.Name(), t.Description(), schema, workerAgents); err != nil {
			log.Printf("[tools] seed web_audit 失败: %v", err)
		}
	}
}

func (s *Server) toolWebAudit() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "web_audit",
		Description: "【前端源码审计】抓取页面 + 外部 JS/CSS，解析表单/注释/API 路由/硬编码密钥/DOM XSS sink。" +
			"默认只抓同 host 资源；include_external=true 才抓跨域 CDN。走任务 MITM（若有）→ 目标，自动进流量台账。" +
			"只做静态提取，不执行 JS；密钥 finding 自动回写（若任务上下文可用）。",
		Schema: objSchema(map[string]any{
			"url":              strParam("目标页面 URL，如 https://example.com"),
			"max_files":        map[string]any{"type": "integer", "description": "最多抓取外部 JS/CSS 文件数，默认 20，上限 100"},
			"max_size":         map[string]any{"type": "integer", "description": "单文件最大字节数，默认 2MB，上限 8MB"},
			"include_external": map[string]any{"type": "boolean", "description": "是否抓取跨域 CDN 资源（默认 false；仍受 scope 约束）"},
		}, "url"),
		ReadOnly:    func(json.RawMessage) bool { return false },
		Permissions: sessionPerm,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a WebAuditParams
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败：" + err.Error()), nil
			}
			a.URL = strings.TrimSpace(a.URL)
			if a.URL == "" {
				return actool.Errorf("url 不能为空"), nil
			}
			if a.MaxFiles <= 0 {
				a.MaxFiles = 20
			}
			if a.MaxFiles > 100 {
				a.MaxFiles = 100
			}
			if a.MaxSize <= 0 {
				a.MaxSize = 2 << 20
			}
			if a.MaxSize > 8<<20 {
				a.MaxSize = 8 << 20
			}
			u, err := url.Parse(a.URL)
			if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
				return actool.Errorf("非法 URL（只支持 http/https）"), nil
			}
			ri := agent.RunInfoFrom(ctx)
			if inScope, known := guard.HostInTaskScope(ri.TaskID, u.Hostname()); known && !inScope {
				return actool.Errorf(fmt.Sprintf("目标 %s 不在任务 scope 内", u.Hostname())), nil
			}
			client, egress := s.webAuditHTTPClient(ri.TaskID)
			res := WebAuditResult{Status: "success", TargetURL: a.URL, Egress: egress}

			htmlContent, err := fetchWebAuditRaw(ctx, client, a.URL, a.MaxSize)
			if err != nil {
				return actool.Errorf("抓取 HTML 失败: " + err.Error()), nil
			}
			doc, err := html.Parse(strings.NewReader(htmlContent))
			if err != nil {
				return actool.Errorf("HTML 解析失败: " + err.Error()), nil
			}

			var jsURLs, cssURLs []string
			var inlineJS strings.Builder
			extractWebAuditResources(doc, u, &jsURLs, &cssURLs, &inlineJS, &res)
			res.JSPaths = uniqueStrings(res.JSPaths)
			res.CSSPaths = uniqueStrings(res.CSSPaths)
			res.Forms = uniqueStrings(res.Forms)
			res.HTMLComments = uniqueStrings(res.HTMLComments)

			var wg sync.WaitGroup
			var mu sync.Mutex
			sem := make(chan struct{}, 5)
			count := 0
			runAsset := func(rawURL, typ string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				if !webAuditAssetAllowed(ri.TaskID, u.Hostname(), rawURL, a.IncludeExternal) {
					mu.Lock()
					res.Errors = append(res.Errors, fmt.Sprintf("[%s] skipped out-of-scope: %s", typ, rawURL))
					mu.Unlock()
					return
				}
				content, err := fetchWebAuditRaw(ctx, client, rawURL, a.MaxSize)
				if err != nil {
					mu.Lock()
					res.Errors = append(res.Errors, fmt.Sprintf("[%s] %s: %v", typ, rawURL, err))
					mu.Unlock()
					return
				}
				if typ == "js" {
					mu.Lock()
					auditWebAuditJS(content, &res)
					mu.Unlock()
				}
			}
			for _, ju := range jsURLs {
				if count >= a.MaxFiles {
					break
				}
				count++
				wg.Add(1)
				go runAsset(ju, "js")
			}
			for _, cu := range cssURLs {
				if count >= a.MaxFiles {
					break
				}
				count++
				wg.Add(1)
				go runAsset(cu, "css")
			}
			wg.Wait()

			if inlineJS.Len() > 0 {
				auditWebAuditJS(inlineJS.String(), &res)
			}
			res.APIRoutes = uniqueStrings(res.APIRoutes)
			res.Secrets = uniqueStrings(res.Secrets)
			res.DOMXSSSinks = uniqueStrings(res.DOMXSSSinks)

			if len(res.Secrets) > 0 && ri.TaskID > 0 {
				if fid := s.recordWebAuditFinding(ctx, a.URL, res.Secrets); fid > 0 {
					res.Errors = append(res.Errors, fmt.Sprintf("已写入 finding_id: %d", fid))
				}
			}
			return jsonResult(res)
		},
	})
}

// webAuditHTTPClient keeps the task MITM when configured. TLS verification is
// disabled because the task MITM re-signs target certificates; this is a
// deliberately scoped probe, not a general-purpose HTTP client.
func (s *Server) webAuditHTTPClient(taskID int64) (*http.Client, string) {
	tr := &http.Transport{
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          20,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // task MITM CA
	}
	egress := "direct"
	if s.m != nil && taskID > 0 {
		if addr, _ := s.m.TaskProxyForTask(taskID); addr != "" {
			if pu, err := url.Parse("http://" + addr); err == nil {
				tr.Proxy = http.ProxyURL(pu)
				egress = "task_mitm"
			}
		}
	}
	return &http.Client{Transport: tr, Timeout: 25 * time.Second}, egress
}

func fetchWebAuditRaw(ctx context.Context, client *http.Client, rawURL string, maxSize int) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(ct, "application/octet-stream") || strings.HasPrefix(ct, "image/") ||
		strings.HasPrefix(ct, "audio/") || strings.HasPrefix(ct, "video/") {
		return "", fmt.Errorf("跳过非文本资源: %s", ct)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxSize)))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func extractWebAuditResources(n *html.Node, base *url.URL, jsURLs, cssURLs *[]string, inlineJS *strings.Builder, res *WebAuditResult) {
	if n.Type == html.ElementNode {
		switch strings.ToLower(n.Data) {
		case "script":
			src := ""
			for _, attr := range n.Attr {
				if strings.EqualFold(attr.Key, "src") {
					src = strings.TrimSpace(attr.Val)
				}
			}
			if src != "" {
				if u := resolveWebAuditURL(base, src); u != "" {
					*jsURLs = append(*jsURLs, u)
					res.JSPaths = append(res.JSPaths, u)
				}
			} else {
				inlineJS.WriteString(webAuditText(n) + "\n")
			}
		case "link":
			isCSS := false
			href := ""
			for _, attr := range n.Attr {
				if strings.EqualFold(attr.Key, "rel") && strings.Contains(strings.ToLower(attr.Val), "stylesheet") {
					isCSS = true
				}
				if strings.EqualFold(attr.Key, "href") {
					href = strings.TrimSpace(attr.Val)
				}
			}
			if isCSS && href != "" {
				if u := resolveWebAuditURL(base, href); u != "" {
					*cssURLs = append(*cssURLs, u)
					res.CSSPaths = append(res.CSSPaths, u)
				}
			}
		case "form":
			action, method := "", "GET"
			for _, attr := range n.Attr {
				switch strings.ToLower(attr.Key) {
				case "action":
					action = strings.TrimSpace(attr.Val)
				case "method":
					if strings.TrimSpace(attr.Val) != "" {
						method = strings.ToUpper(strings.TrimSpace(attr.Val))
					}
				}
			}
			if action != "" {
				if u := resolveWebAuditURL(base, action); u != "" {
					res.Forms = append(res.Forms, method+" "+u)
				}
			}
		}
	}
	if n.Type == html.CommentNode {
		text := strings.TrimSpace(n.Data)
		if len(text) > 5 && !strings.Contains(strings.ToLower(text), "ie") &&
			!strings.Contains(strings.ToLower(text), "bootstrap") {
			if len(text) > 500 {
				text = text[:500] + "…"
			}
			res.HTMLComments = append(res.HTMLComments, text)
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		extractWebAuditResources(c, base, jsURLs, cssURLs, inlineJS, res)
	}
}

func webAuditText(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(x *html.Node) {
		if x.Type == html.TextNode {
			b.WriteString(x.Data)
		}
		for c := x.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return b.String()
}

func resolveWebAuditURL(base *url.URL, raw string) string {
	if raw == "" || strings.HasPrefix(strings.ToLower(raw), "javascript:") ||
		strings.HasPrefix(strings.ToLower(raw), "data:") || strings.HasPrefix(raw, "#") {
		return ""
	}
	u, err := base.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	return u.String()
}

func webAuditAssetAllowed(taskID int64, mainHost, rawURL string, includeExternal bool) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return false
	}
	if strings.EqualFold(u.Hostname(), mainHost) {
		return true
	}
	if !includeExternal {
		return false
	}
	if in, known := guard.HostInTaskScope(taskID, u.Hostname()); known && !in {
		return false
	}
	return true
}

var (
	webAuditReAPI  = regexp.MustCompile("(?:fetch|axios\\.(?:get|post|put|delete)|ajax|\\$\\.(?:get|post|ajax))\\s*\\(\\s*['\"`]([a-zA-Z0-9_\\-/.:]+)['\"`]")
	webAuditReAPI2 = regexp.MustCompile("['\"`](/api/[a-zA-Z0-9_\\-/.:]+)['\"`]")
	webAuditReAWS  = regexp.MustCompile(`(AKIA[0-9A-Z]{16})`)
	webAuditReAli  = regexp.MustCompile(`(LTAI[a-zA-Z0-9]{12,20})`)
	webAuditReJWT  = regexp.MustCompile(`(eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,})`)
	webAuditReGen  = regexp.MustCompile(`(?i)(?:password|passwd|secret|api_key|token)\s*[:=]\s*['"` + "`" + `]([a-zA-Z0-9_\-\.!@#$%^&*]{8,64})['"` + "`" + `]`)
	webAuditReDOM  = regexp.MustCompile(`(\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|eval\s*\(|dangerouslySetInnerHTML|setTimeout\s*\(\s*['"` + "`" + `][^'"]*['"` + "`" + `])`)
)

func auditWebAuditJS(js string, res *WebAuditResult) {
	for _, m := range webAuditReAPI.FindAllStringSubmatch(js, -1) {
		if len(m) > 1 && !strings.HasPrefix(strings.ToLower(m[1]), "http") {
			res.APIRoutes = append(res.APIRoutes, m[1])
		}
	}
	for _, m := range webAuditReAPI2.FindAllStringSubmatch(js, -1) {
		if len(m) > 1 {
			res.APIRoutes = append(res.APIRoutes, m[1])
		}
	}
	for _, m := range webAuditReAWS.FindAllStringSubmatch(js, -1) {
		res.Secrets = append(res.Secrets, "AWS_AK:"+m[1])
	}
	for _, m := range webAuditReAli.FindAllStringSubmatch(js, -1) {
		res.Secrets = append(res.Secrets, "Aliyun_AK:"+m[1])
	}
	for _, m := range webAuditReJWT.FindAllStringSubmatch(js, -1) {
		res.Secrets = append(res.Secrets, "JWT:"+shortenWebAudit(m[1], 20)+"...")
	}
	for _, m := range webAuditReGen.FindAllStringSubmatch(js, -1) {
		res.Secrets = append(res.Secrets, "HARDCODED:"+shortenWebAudit(m[0], 50))
	}
	for _, m := range webAuditReDOM.FindAllString(js, -1) {
		res.DOMXSSSinks = append(res.DOMXSSSinks, strings.TrimSpace(m))
	}
}

func shortenWebAudit(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func uniqueStrings(input []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(input))
	for _, v := range input {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func (s *Server) recordWebAuditFinding(ctx context.Context, targetURL string, secrets []string) int64 {
	ri := agent.RunInfoFrom(ctx)
	if ri.TaskID <= 0 || s.m == nil {
		return 0
	}
	task, ok := s.m.Task(fmt.Sprint(ri.TaskID))
	if !ok || task == nil || task.Store == nil {
		return 0
	}
	rec, err := task.Store.RecordFinding(ctx, pgdb.RecordFindingInput{
		TaskID: ri.TaskID, ExplorationID: task.ExpID, IntentID: ri.IntentID,
		VulnClass: "hardcoded-secrets", Name: "前端硬编码敏感信息",
		Severity: "high",
		Summary:  fmt.Sprintf("在 %s 的前端 JS 中发现 %d 个硬编码凭证/密钥", targetURL, len(secrets)),
		Evidence: "提取到的密钥:\n" + truncateForTool(strings.Join(secrets, "\n")),
		Worker:   "web_audit",
	})
	if err != nil || rec == nil {
		return 0
	}
	return rec.FindingID
}
