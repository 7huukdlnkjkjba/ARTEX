package agent

// HTTP 黑盒侦察工具（极限高生存力重构版）:
//   - recon_http: 单请求侦察，采用全新零复用 TCP 连接，避免任何中间设备导致的脏连接断开。
//   - http_diff: 自动复用加固后的 HTTP Client，保障高并发状态下的超时和错误隔离。

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strings"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

// ==============================================================================
// 核心高生存力 HTTP 执行引擎
// ==============================================================================

type hardcoreHTTPResult struct {
	Status           int
	StatusText       string
	Proto            string
	Headers          http.Header
	Preview          string
	Body             []byte
	BodyLen          int
	BodyTruncated    bool
	PreviewTruncated bool
	FinalURL         string
	Redirects        []string
	RedirectLimitHit bool
	ElapsedMs        int64
	Error            string
	ErrorKind        string
}

// defaultHTTPUserAgent 是本工具在任务未配置稳定 UA 时的兜底值。
const defaultHTTPUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// applyDefaultHeaders 补全 UA/Accept：优先用任务级稳定 UA（worker 的 SetHTTPUserAgent，
// 与 Bash 出口保持一致），未配置时才落回浏览器 UA。网络重试会重建 Request，必须重新调用。
func (t *ToolSet) applyDefaultHeaders(req *http.Request) {
	if req.Header.Get("User-Agent") == "" {
		ua := strings.TrimSpace(t.httpUA)
		if ua == "" {
			ua = defaultHTTPUserAgent
		}
		req.Header.Set("User-Agent", ua)
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "*/*")
	}
}

// executeHardcoreHTTP 是替代原 fetchHTTP 的底层核心。
// 针对高并发、WAF拦截、代理隧道抖动做了极限优化：禁用连接池、强制 1.1、自动重试。
func (t *ToolSet) executeHardcoreHTTP(ctx context.Context, targetURL, method string, headers map[string]string, body string, follow, insecure bool, timeout time.Duration) hardcoreHTTPResult {
	res := hardcoreHTTPResult{}
	start := time.Now()
	defer func() { res.ElapsedMs = time.Since(start).Milliseconds() }()

	// 1. 复用平台原生的 client 构建逻辑（确保代理/MITM/隧道正常）
	client, err := t.newHTTPClient(insecure)
	if err != nil {
		res.Error = "构造 HTTP Client 失败: " + err.Error()
		res.ErrorKind = "config"
		return res
	}

	// 2. 深度劫持底层 Transport，注入极限生存属性
	if tr, ok := client.Transport.(*http.Transport); ok {
		// 彻底禁用 Keep-Alive，不再复用任何可能被污染的 TCP 连接
		tr.DisableKeepAlives = true
		tr.MaxIdleConns = 0
		tr.MaxIdleConnsPerHost = 0
		// 强制退回 HTTP/1.1，绕过各种中间件对 H2 协议流的黑洞问题
		tr.ForceAttemptHTTP2 = false
		// 细化各阶段超时，避免 DNS 或 TLS 黑洞拖死整个请求
		tr.TLSHandshakeTimeout = 5 * time.Second
		tr.ResponseHeaderTimeout = timeout
		tr.ExpectContinueTimeout = 1 * time.Second
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: insecure}
		} else {
			tr.TLSClientConfig.InsecureSkipVerify = insecure
		}
	} else {
		// 兜底：极端情况下平台没有给出标准 Transport
		client.Transport = &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: -1}).DialContext,
			ForceAttemptHTTP2:     false,
			DisableKeepAlives:     true,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: timeout,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: insecure},
		}
	}

	client.Timeout = timeout
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// 重定向链要记录（含不跟随模式下的第一跳 3xx），供模型判断跳转目标；
		// 每一跳都必须仍在任务 scope 内。
		res.Redirects = append(res.Redirects, req.URL.String())
		if err := t.assertInScope(req.URL.Hostname()); err != nil {
			return err
		}
		if !follow {
			return http.ErrUseLastResponse // 不跟随重定向，直接把 3xx 返回
		}
		if len(via) >= 5 {
			res.RedirectLimitHit = true
			return errors.New("stopped after 5 redirects")
		}
		return nil
	}

	// 3. 构造 Request
	var bodyReader io.ReadCloser
	if body != "" {
		bodyReader = io.NopCloser(bytes.NewReader([]byte(body)))
	}

	req, err := http.NewRequestWithContext(ctx, method, targetURL, bodyReader)
	if err != nil {
		res.Error = "构造 Request 失败: " + err.Error()
		res.ErrorKind = "invalid_request"
		return res
	}

	// 4. 注入 Headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	t.applyDefaultHeaders(req)

	// 5. 发送请求并附带网络层指数退避重试
	var resp *http.Response
	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		resp, err = client.Do(req)
		if err == nil {
			break // 成功拿到响应
		}

		errStr := err.Error()
		isRetryable := strings.Contains(errStr, "EOF") ||
			strings.Contains(errStr, "connection reset") ||
			strings.Contains(errStr, "timeout") ||
			strings.Contains(errStr, "no route to host")

		if !isRetryable || i == maxRetries-1 {
			break // 遇到不可重试的错误，或者重试次数耗尽
		}

		// 指数退避（200ms, 400ms）并克隆新 Request 重放
		time.Sleep(time.Duration(i+1) * 200 * time.Millisecond)
		var retryBody io.ReadCloser
		if body != "" {
			retryBody = io.NopCloser(bytes.NewReader([]byte(body)))
		}
		req, _ = http.NewRequestWithContext(ctx, method, targetURL, retryBody)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		t.applyDefaultHeaders(req)
	}

	// 6. 精准错误分类（让 AI 知道是网络问题还是配置问题）
	if err != nil {
		res.Error = err.Error()
		var dnsErr *net.DNSError
		var opErr *net.OpError
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			res.ErrorKind = "timeout"
		case errors.As(err, &dnsErr):
			res.ErrorKind = "dns"
		case errors.As(err, &opErr):
			if opErr.Op == "dial" {
				res.ErrorKind = "refused"
			} else {
				res.ErrorKind = "network"
			}
		case strings.Contains(err.Error(), "tls:"):
			res.ErrorKind = "tls"
		case strings.Contains(err.Error(), "proxyconnect"):
			res.ErrorKind = "proxy"
		default:
			res.ErrorKind = "unknown"
		}
		return res
	}
	defer resp.Body.Close()

	// 7. 解析响应
	res.Status = resp.StatusCode
	res.StatusText = resp.Status
	res.Proto = resp.Proto
	res.Headers = resp.Header
	res.FinalURL = resp.Request.URL.String()

	// 限制读取大小为 4KB
	maxRead := int64(4096)
	bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, maxRead))
	if readErr != nil {
		res.Error = "读取响应体失败: " + readErr.Error()
		res.ErrorKind = "read"
	}

	res.Body = bodyBytes
	res.Preview = string(bodyBytes)

	if cl := resp.Header.Get("Content-Length"); cl != "" {
		fmt.Sscanf(cl, "%d", &res.BodyLen)
	} else {
		res.BodyLen = len(bodyBytes)
	}

	if res.BodyLen > int(maxRead) {
		res.BodyTruncated = true
		res.PreviewTruncated = true
	}

	return res
}

func reconHTTPErrorSteps(kind string) []string {
	switch kind {
	case "timeout":
		return []string{"调大 timeout_sec；确认目标/代理可达", "先 scan_rustscan 确认端口开放，或 dry_run 检查配置"}
	case "dns":
		return []string{"确认 DNS/代理；必要时直接用 IP 并设置 Host 头", "检查是否应走任务隧道（socks5）"}
	case "refused":
		return []string{"确认端口/服务是否开放（可先用 scan_rustscan）", "确认 target 的 scheme/端口是否正确（80/443/自定义端口）"}
	case "tls":
		return []string{"自签名靶场设 insecure=true；否则检查任务 MITM CA", "确认 SNI/Host 与证书是否匹配"}
	case "proxy":
		return []string{"检查任务隧道/全局代理是否存活", "无隧道时确认是否直连；必要时先 dry_run"}
	case "scope":
		return []string{"目标不在本任务 scope：先 add_task_scope 或换授权目标", "重定向到 scope 外也会被拒绝"}
	case "config":
		return []string{"检查代理配置/CA 文件；可先 dry_run", "必要时临时直连（需确认 RoE 允许）"}
	case "read":
		return []string{"响应体读取失败：目标可能提前断开或流式响应；可重试或改用 curl 仅做只读确认", "查看 status_code/headers 是否已拿到"}
	default:
		return []string{"看 error 与 url；先 dry_run 排除配置问题", "确认目标可达、方法/头合法；必要时缩小请求"}
	}
}

// ==============================================================================
// 工具一：recon_http 单请求侦察
// ==============================================================================

type ReconHTTPParams struct {
	URL        string            `json:"url"`
	Method     string            `json:"method,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body,omitempty"`
	Follow     bool              `json:"follow,omitempty"`
	Insecure   *bool             `json:"insecure,omitempty"`
	TimeoutSec int               `json:"timeout_sec,omitempty"`
	DryRun     bool              `json:"dry_run,omitempty"`
}

func (p *ReconHTTPParams) Validate() error {
	p.URL = strings.TrimSpace(p.URL)
	if p.URL == "" {
		return fmt.Errorf("url 必填")
	}
	m, err := normalizeHTTPMethod(p.Method)
	if err != nil {
		return err
	}
	p.Method = m
	if err := validateHTTPHeaders(p.Headers); err != nil {
		return err
	}
	if len(p.Body) > 1<<20 {
		return fmt.Errorf("body 过大（上限 1MB）")
	}
	if p.TimeoutSec == 0 {
		p.TimeoutSec = 15
	}
	if p.TimeoutSec < 1 || p.TimeoutSec > 60 {
		return fmt.Errorf("timeout_sec 取值 1..60")
	}
	return nil
}

type ReconHTTPResult struct {
	ModuleID         string      `json:"module_id"`
	MITRE            string      `json:"mitre"`
	Status           string      `json:"status"` // success | failed | dry_run
	URL              string      `json:"url"`
	FinalURL         string      `json:"final_url,omitempty"`
	Method           string      `json:"method"`
	Host             string      `json:"host"`
	StatusCode       int         `json:"status_code"`
	StatusText       string      `json:"status_text,omitempty"`
	Proto            string      `json:"proto,omitempty"`
	Headers          http.Header `json:"headers,omitempty"`
	ContentType      string      `json:"content_type,omitempty"`
	BodyPreview      string      `json:"body_preview,omitempty"`
	BodyLen          int         `json:"body_len"`
	BodyTruncated    bool        `json:"body_truncated,omitempty"`
	PreviewTruncated bool        `json:"preview_truncated,omitempty"`
	Redirects        []string    `json:"redirects,omitempty"`
	RedirectLimitHit bool        `json:"redirect_limit_hit,omitempty"`
	Insecure         bool        `json:"insecure"`
	Proxy            string      `json:"proxy,omitempty"`
	TimeoutSec       int         `json:"timeout_sec"`
	NextSteps        []string    `json:"next_steps,omitempty"`
	Error            string      `json:"error,omitempty"`
	ErrorKind        string      `json:"error_kind,omitempty"`
	ElapsedMs        int64       `json:"elapsed_ms"`
}

func (t *ToolSet) toolReconHTTP() actool.CoreTool {
	return t.writeExpTool("recon_http",
		"【侦察 · HTTP 单请求 · T1595】对单个 URL 发一次 HTTP(S) 请求，返回状态码、响应头、响应体预览（前 4KB）、长度与重定向链。用于指纹识别、路径/参数/认证基线探测。\n"+
			"执行归代码：URL/方法/头校验、scope、任务代理与流量录制、超时、TLS/重定向处理、错误分类；**不自动写 fact/finding**——根据结果由你决定。\n"+
			"默认不跟随重定向（follow=true 才跟随，最多 5 跳且重定向目标也必须在本任务 scope 内）；默认 insecure=true 以兼容自签名靶场。\n"+
			"单请求侦察优先用它替代手搓 curl；需要基线与变体对比时用 http_diff。",
		obj(map[string]any{
			"url":     str("完整 URL，必须带 http:// 或 https://"),
			"method":  str("GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS，默认 GET"),
			"headers": map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "自定义请求头；Host 可用于 vhost 探测。工具不自动维护 cookie jar，需要同一会话时显式传 Cookie/Authorization"},
			"body":    str("请求体（POST/PUT/PATCH 用；上限 1MB）"),
			"follow":  map[string]any{"type": "boolean", "description": "是否跟随重定向，默认 false（最多 5 跳，且每跳都校验 scope）"},
			"insecure": map[string]any{
				"type": "boolean", "description": "跳过 TLS 证书校验，默认 true（自签名靶场常用）；设为 false 时用系统 CA + 任务 MITM CA",
				"default": true,
			},
			"timeout_sec": map[string]any{"type": "integer", "description": "单请求超时秒数，默认 15，范围 1..60", "default": 15},
			"dry_run":     map[string]any{"type": "boolean", "description": "只校验 URL/scope/代理配置，不发请求"},
		}, "url"),
		t.reconHTTPHandler)
}

func (t *ToolSet) reconHTTPHandler(ctx context.Context, in json.RawMessage) (actool.Result, error) {
	var p ReconHTTPParams
	if err := json.Unmarshal(in, &p); err != nil {
		return actool.Errorf("参数解析失败：" + err.Error()), nil
	}
	if err := p.Validate(); err != nil {
		return actool.Errorf(err.Error()), nil
	}
	u, err := parseReconURL(p.URL)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	if err := t.assertInScope(u.Hostname()); err != nil {
		return actool.Errorf(err.Error()), nil
	}

	insecure := derefBool(p.Insecure, true)
	start := time.Now()
	res := ReconHTTPResult{
		ModuleID: "recon.http", MITRE: "T1595", Status: "failed",
		URL: redactURLUserinfo(p.URL), Method: p.Method, Host: u.Hostname(),
		Insecure: insecure, Proxy: t.httpProxyDisplay(), TimeoutSec: p.TimeoutSec,
	}
	if p.DryRun {
		if _, err := t.newHTTPClient(insecure); err != nil {
			res.ErrorKind, res.Error = "config", err.Error()
			res.NextSteps = reconHTTPErrorSteps("config")
			res.ElapsedMs = time.Since(start).Milliseconds()
			return jsonResult(res)
		}
		res.Status = "dry_run"
		res.ElapsedMs = time.Since(start).Milliseconds()
		res.NextSteps = []string{
			"dry_run 通过后直接调用；若返回 TLS 错误可设 insecure=true",
			"需要对比基线与变体时改用 http_diff（同一主机、同一方法/头/身份）",
		}
		return jsonResult(res)
	}

	// 调用底层高生存力执行器
	fr := t.executeHardcoreHTTP(ctx, p.URL, p.Method, p.Headers, p.Body, p.Follow, insecure, time.Duration(p.TimeoutSec)*time.Second)

	res.ElapsedMs = time.Since(start).Milliseconds()
	res.StatusCode = fr.Status
	res.StatusText = fr.StatusText
	res.Proto = fr.Proto
	res.Headers = fr.Headers
	if fr.Headers != nil {
		res.ContentType = fr.Headers.Get("Content-Type")
	}
	res.BodyPreview = fr.Preview
	res.BodyLen = fr.BodyLen
	res.BodyTruncated = fr.BodyTruncated
	res.PreviewTruncated = fr.PreviewTruncated
	res.FinalURL = redactURLUserinfo(fr.FinalURL)
	res.Redirects = redactURLList(fr.Redirects)
	res.RedirectLimitHit = fr.RedirectLimitHit

	if fr.Error != "" {
		res.Status = "failed"
		res.Error = fr.Error
		res.ErrorKind = fr.ErrorKind
		res.NextSteps = reconHTTPErrorSteps(fr.ErrorKind)
		return jsonResult(res)
	}
	res.Status = "success"
	res.NextSteps = []string{
		"根据 status_code/headers/body_preview 判断指纹、框架、认证入口；不要把 200 本身当漏洞",
		"需要基线 vs 变体（IDOR/越权/注入/认证差异）时用 http_diff，并保持方法/头/身份一致",
		"若本任务已开启流量录制，需要完整响应体时用 traffic_search/traffic_get；否则重新请求（本工具只回 4KB 预览）",
	}
	if res.RedirectLimitHit {
		res.NextSteps = append(res.NextSteps, "已到 5 跳重定向上限（返回最后一跳 3xx）；确认链路后再决定是否继续")
	}
	return jsonResult(res)
}

// ==============================================================================
// 工具二：http_diff 差分引擎
// ==============================================================================

type HTTPDiffParams struct {
	URLTemplate  string            `json:"url_template"`
	Baseline     string            `json:"baseline"`
	Variants     []string          `json:"variants"`
	Method       string            `json:"method,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	BodyTemplate string            `json:"body_template,omitempty"`
	Follow       bool              `json:"follow,omitempty"`
	Insecure     *bool             `json:"insecure,omitempty"`
	TimeoutSec   int               `json:"timeout_sec,omitempty"`
	DryRun       bool              `json:"dry_run,omitempty"`
}

func (p *HTTPDiffParams) Validate() error {
	p.URLTemplate = strings.TrimSpace(p.URLTemplate)
	if p.URLTemplate == "" {
		return fmt.Errorf("url_template 必填")
	}
	if len(p.URLTemplate) > 2048 {
		return fmt.Errorf("url_template 过长（上限 2048）")
	}
	if !strings.Contains(p.URLTemplate, "{v}") {
		return fmt.Errorf("url_template 必须包含 {v} 占位符，例如 https://x/api?id={v}")
	}
	if len(p.Baseline) > 1024 {
		return fmt.Errorf("baseline 值过长（上限 1024）；大 body 用 body_template 承载")
	}
	if strings.Count(p.URLTemplate, "{v}") > 10 {
		return fmt.Errorf("url_template 里 {v} 太多（上限 10 个）")
	}
	if len(p.Variants) == 0 {
		return fmt.Errorf("variants 至少 1 个")
	}
	seen := map[string]bool{}
	variants := make([]string, 0, len(p.Variants))
	for _, v := range p.Variants {
		if len(v) > 1024 {
			return fmt.Errorf("variant 过长（上限 1024）：%.64s…", v)
		}
		if seen[v] {
			continue
		}
		seen[v] = true
		variants = append(variants, v)
	}
	if len(variants) == 0 {
		return fmt.Errorf("variants 去重后为空")
	}
	if len(variants) > 20 {
		return fmt.Errorf("variants 最多 20 个（当前 %d）；请分批发以控制噪声", len(variants))
	}
	p.Variants = variants

	m, err := normalizeHTTPMethod(p.Method)
	if err != nil {
		return err
	}
	p.Method = m
	if err := validateHTTPHeaders(p.Headers); err != nil {
		return err
	}
	if len(p.BodyTemplate) > 1<<16 {
		return fmt.Errorf("body_template 过大（上限 64KB）")
	}
	if p.TimeoutSec == 0 {
		p.TimeoutSec = 60
	}
	if p.TimeoutSec < 10 || p.TimeoutSec > 300 {
		return fmt.Errorf("timeout_sec 取值 10..300（整次差分总预算）")
	}
	return nil
}

type HTTPDiffBaseline struct {
	URL           string      `json:"url"`
	StatusCode    int         `json:"status_code"`
	BodyLen       int         `json:"body_len"`
	BodyTruncated bool        `json:"body_truncated,omitempty"`
	ContentType   string      `json:"content_type,omitempty"`
	Location      string      `json:"location,omitempty"`
	BodySHA256    string      `json:"body_sha256,omitempty"`
	Preview       string      `json:"preview,omitempty"`
	Headers       http.Header `json:"headers,omitempty"`
	ElapsedMs     int64       `json:"elapsed_ms"`
	Error         string      `json:"error,omitempty"`
	ErrorKind     string      `json:"error_kind,omitempty"`
}

type HTTPDiffItem struct {
	Variant        string  `json:"variant"`
	URL            string  `json:"url"`
	StatusCode     int     `json:"status_code"`
	BodyLen        int     `json:"body_len"`
	StatusSame     bool    `json:"status_same"`
	LenDelta       int     `json:"len_delta"`
	LenDeltaPct    float64 `json:"len_delta_pct"`
	Similarity     float64 `json:"similarity"`
	ContentChanged bool    `json:"content_changed"`
	Signal         string  `json:"signal"`
	BodySHA256     string  `json:"body_sha256,omitempty"`
	ContentType    string  `json:"content_type,omitempty"`
	Location       string  `json:"location,omitempty"`
	Preview        string  `json:"preview,omitempty"`
	ElapsedMs      int64   `json:"elapsed_ms"`
	Error          string  `json:"error,omitempty"`
	ErrorKind      string  `json:"error_kind,omitempty"`
	BodyTruncated  bool    `json:"body_truncated,omitempty"`
}

type HTTPDiffSummary struct {
	VariantCount int `json:"variant_count"`
	Signals      int `json:"signals"`
	StatusFlip   int `json:"status_flip"`
	StatusDiff   int `json:"status_diff"`
	LenDiff      int `json:"len_diff"`
	ContentDiff  int `json:"content_diff"`
	Errors       int `json:"errors"`
	Same         int `json:"same"`
}

type HTTPDiffResult struct {
	ModuleID      string           `json:"module_id"`
	MITRE         string           `json:"mitre"`
	Status        string           `json:"status"` // success | partial | failed | dry_run
	URLTemplate   string           `json:"url_template"`
	Method        string           `json:"method"`
	Host          string           `json:"host"`
	BaselineValue string           `json:"baseline_value"`
	Baseline      HTTPDiffBaseline `json:"baseline"`
	Diffs         []HTTPDiffItem   `json:"diffs"`
	Summary       HTTPDiffSummary  `json:"summary"`
	Insecure      bool             `json:"insecure"`
	Proxy         string           `json:"proxy,omitempty"`
	TimeoutSec    int              `json:"timeout_sec"`
	NextSteps     []string         `json:"next_steps,omitempty"`
	Warnings      []string         `json:"warnings,omitempty"`
	Error         string           `json:"error,omitempty"`
	ErrorKind     string           `json:"error_kind,omitempty"`
	ElapsedMs     int64            `json:"elapsed_ms"`
}

func (t *ToolSet) toolHTTPDiff() actool.CoreTool {
	return t.writeExpTool("http_diff",
		"【黑盒核心 · 差分 · T1595】对同一 URL 模板发一次基线请求 + 多个变体请求，比较状态码/长度/内容相似度，输出可行动信号（status_flip/status_diff/len_diff/content_diff）。用于 IDOR/越权/注入/认证差异；**没有基线就没有信号**。\n"+
			"执行归代码：模板/变体/方法/头校验、scope、同一主机约束、任务代理与录制、总超时、相似度与信号计算；**diff 只是信号，不是漏洞**——必须换方法/身份复测确认后再 report_finding。\n"+
			"变体值需自行 URL 编码；默认不跟随重定向（避免掩盖差异），follow=true 时每跳都校验 scope。",
		obj(map[string]any{
			"url_template": str("URL 模板，用 {v} 表示参数位，如 https://x.com/api?id={v}；{v} 不能改变主机名"),
			"baseline":     str("基线值（正常/低权值），如 1 或自己的 user id"),
			"variants": map[string]any{
				"type": "array", "minItems": 1, "maxItems": 20,
				"items":       map[string]any{"type": "string"},
				"description": "变体值列表，如 [\"2\",\"9999\",\"admin\"]（去重、最多 20 个）",
			},
			"method":        str("GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS，默认 GET"),
			"headers":       map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "基线/变体共用的请求头（Cookie/Authorization/Content-Type 等）；工具不自动维护 cookie jar，需要同一会话时显式传 Cookie"},
			"body_template": str("可选：请求体模板，同样用 {v} 替换；POST/PUT/PATCH 用"),
			"follow":        map[string]any{"type": "boolean", "description": "是否跟随重定向，默认 false（避免重定向掩盖差异）；每跳都校验 scope"},
			"insecure": map[string]any{
				"type": "boolean", "description": "跳过 TLS 证书校验，默认 true；false 时用系统 CA + 任务 MITM CA",
				"default": true,
			},
			"timeout_sec": map[string]any{"type": "integer", "description": "整次差分总超时秒数（含基线+全部变体），默认 60，范围 10..300", "default": 60},
			"dry_run":     map[string]any{"type": "boolean", "description": "只校验模板/变体/scope/代理配置，不发请求"},
		}, "url_template", "baseline", "variants"),
		t.httpDiffHandler)
}

func (t *ToolSet) httpDiffHandler(ctx context.Context, in json.RawMessage) (actool.Result, error) {
	var p HTTPDiffParams
	if err := json.Unmarshal(in, &p); err != nil {
		return actool.Errorf("参数解析失败：" + err.Error()), nil
	}
	if err := p.Validate(); err != nil {
		return actool.Errorf(err.Error()), nil
	}
	baselineURL := strings.ReplaceAll(p.URLTemplate, "{v}", p.Baseline)
	baseU, err := parseReconURL(baselineURL)
	if err != nil {
		return actool.Errorf("baseline URL 非法（baseline 值需 URL 编码）：" + err.Error()), nil
	}
	for _, v := range p.Variants {
		vu, verr := parseReconURL(strings.ReplaceAll(p.URLTemplate, "{v}", v))
		if verr != nil {
			return actool.Errorf(fmt.Sprintf("variant %q 的 URL 非法（值需 URL 编码）：%v", v, verr)), nil
		}
		if !strings.EqualFold(vu.Hostname(), baseU.Hostname()) {
			return actool.Errorf(fmt.Sprintf("url_template 的 {v} 不能改变主机名（baseline=%s, variant=%s）；只允许在路径/查询/请求体里变化", baseU.Hostname(), vu.Hostname())), nil
		}
	}
	if err := t.assertInScope(baseU.Hostname()); err != nil {
		return actool.Errorf(err.Error()), nil
	}

	insecure := derefBool(p.Insecure, true)
	start := time.Now()
	res := HTTPDiffResult{
		ModuleID: "recon.http_diff", MITRE: "T1595", Status: "failed",
		URLTemplate: redactURLUserinfo(p.URLTemplate), Method: p.Method, Host: baseU.Hostname(),
		BaselineValue: p.Baseline, Diffs: []HTTPDiffItem{},
		Insecure: insecure, Proxy: t.httpProxyDisplay(), TimeoutSec: p.TimeoutSec,
		Summary: HTTPDiffSummary{VariantCount: len(p.Variants)},
	}
	if p.DryRun {
		if _, err := t.newHTTPClient(insecure); err != nil {
			res.ErrorKind, res.Error = "config", err.Error()
			res.NextSteps = reconHTTPErrorSteps("config")
			res.ElapsedMs = time.Since(start).Milliseconds()
			return jsonResult(res)
		}
		res.Status = "dry_run"
		res.Summary.VariantCount = len(p.Variants)
		res.ElapsedMs = time.Since(start).Milliseconds()
		res.NextSteps = []string{
			"dry_run 通过后发起差分；先小批量（3-5 个变体）确认基线稳定",
			"变体值需 URL 编码；不要用会改变主机名的模板",
		}
		return jsonResult(res)
	}

	totalCtx, cancel := context.WithTimeout(ctx, time.Duration(p.TimeoutSec)*time.Second)
	defer cancel()
	deadline := time.Now().Add(time.Duration(p.TimeoutSec) * time.Second)

	// 使用硬核 HTTP 执行器处理 Baseline 请求
	baseFR := t.executeHardcoreHTTP(totalCtx, baselineURL, p.Method, p.Headers, strings.ReplaceAll(p.BodyTemplate, "{v}", p.Baseline), p.Follow, insecure, minDuration(15*time.Second, time.Until(deadline)))

	res.Baseline = HTTPDiffBaseline{
		URL: redactURLUserinfo(baselineURL), StatusCode: baseFR.Status, BodyLen: baseFR.BodyLen,
		BodyTruncated: baseFR.BodyTruncated, ContentType: baseFR.Headers.Get("Content-Type"),
		Location: baseFR.Headers.Get("Location"), BodySHA256: sha256Hex(baseFR.Body),
		Preview: string(previewBytes(baseFR.Body, 1024)), Headers: baseFR.Headers,
		ElapsedMs: baseFR.ElapsedMs, Error: baseFR.Error, ErrorKind: baseFR.ErrorKind,
	}
	if baseFR.Error != "" {
		res.Status = "failed"
		res.Error = "baseline 请求失败：" + baseFR.Error
		res.ErrorKind = baseFR.ErrorKind
		res.NextSteps = reconHTTPErrorSteps(baseFR.ErrorKind)
		res.ElapsedMs = time.Since(start).Milliseconds()
		return jsonResult(res)
	}
	if baseFR.BodyTruncated {
		res.Warnings = append(res.Warnings, "baseline 响应体超过 1MB，只比较前 1MB")
	}

	for _, v := range p.Variants {
		vURL := strings.ReplaceAll(p.URLTemplate, "{v}", v)
		remaining := time.Until(deadline)
		var fr hardcoreHTTPResult
		if remaining <= 0 {
			fr = hardcoreHTTPResult{ErrorKind: "timeout", Error: "整次差分超时（timeout_sec）"}
		} else {
			per := 15 * time.Second
			if remaining < per {
				per = remaining
			}
			fr = t.executeHardcoreHTTP(totalCtx, vURL, p.Method, p.Headers, strings.ReplaceAll(p.BodyTemplate, "{v}", v), p.Follow, insecure, per)
		}
		item := HTTPDiffItem{
			Variant: v, URL: redactURLUserinfo(vURL), StatusCode: fr.Status, BodyLen: fr.BodyLen,
			StatusSame: fr.Status == baseFR.Status, LenDelta: fr.BodyLen - baseFR.BodyLen,
			ContentType: fr.Headers.Get("Content-Type"), Location: fr.Headers.Get("Location"),
			BodySHA256: sha256Hex(fr.Body), ElapsedMs: fr.ElapsedMs,
			Error: fr.Error, ErrorKind: fr.ErrorKind, BodyTruncated: fr.BodyTruncated,
		}
		if baseFR.BodyLen > 0 {
			item.LenDeltaPct = math.Round(float64(item.LenDelta)/float64(baseFR.BodyLen)*10000) / 100
		}
		if fr.Error != "" {
			item.Signal = "error"
			res.Summary.Errors++
		} else {
			item.ContentChanged = !bytes.Equal(baseFR.Body, fr.Body)
			item.Similarity = math.Round(bodySimilarity(baseFR.Body, fr.Body)*10000) / 10000
			item.Signal = httpDiffSignal(baseFR.Status, fr.Status, baseFR.BodyLen, fr.BodyLen,
				!item.ContentChanged, item.Similarity)
			switch item.Signal {
			case "status_flip":
				res.Summary.StatusFlip++
			case "status_diff":
				res.Summary.StatusDiff++
			case "len_diff_40pct", "len_diff_from_empty":
				res.Summary.LenDiff++
			case "content_diff", "content_diff_same_size":
				res.Summary.ContentDiff++
			case "same":
				res.Summary.Same++
			}
			if item.Signal != "same" {
				item.Preview = string(previewBytes(fr.Body, 512))
			}
			if fr.BodyTruncated {
				res.Warnings = append(res.Warnings, fmt.Sprintf("variant %q 响应体超过 1MB，只比较前 1MB", v))
			}
		}
		res.Diffs = append(res.Diffs, item)
	}

	res.Summary.VariantCount = len(p.Variants)
	res.Summary.Signals = res.Summary.StatusFlip + res.Summary.StatusDiff + res.Summary.LenDiff + res.Summary.ContentDiff
	res.Status = "success"
	if res.Summary.Errors > 0 {
		res.Status = "partial"
	}
	res.NextSteps = httpDiffNextSteps(res.Summary)
	res.ElapsedMs = time.Since(start).Milliseconds()
	return jsonResult(res)
}

// ==============================================================================
// 辅助工具函数
// ==============================================================================

func httpDiffSignal(baseStatus, status, baseLen, bodyLen int, sameBody bool, similarity float64) string {
	switch {
	case status != baseStatus && status >= 200 && status < 400:
		return "status_flip"
	case status != baseStatus:
		return "status_diff"
	case baseLen == 0 && bodyLen > 0:
		return "len_diff_from_empty"
	case baseLen > 0 && math.Abs(float64(bodyLen-baseLen))/float64(baseLen) > 0.4:
		return "len_diff_40pct"
	case !sameBody && similarity < 0.98:
		if absInt(bodyLen-baseLen) < 200 {
			return "content_diff_same_size"
		}
		return "content_diff"
	default:
		return "same"
	}
}

func bodySimilarity(a, b []byte) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1
	}
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	same := 0
	for i := 0; i < n; i++ {
		if a[i] == b[i] {
			same++
		}
	}
	denom := len(a)
	if len(b) > denom {
		denom = len(b)
	}
	return float64(same) / float64(denom)
}

func httpDiffNextSteps(s HTTPDiffSummary) []string {
	steps := []string{
		"diff 只是信号，不是漏洞：先看 status_flip/len_diff，再看 content_diff；必须换方法/身份/参数复测确认",
		"401/403 → 200/302 属 status_flip；401 vs 403 属 status_diff——先确认是认证/授权差异还是登录态/重定向导致",
		"content_diff_same_size 是弱信号：先看 preview 排除 CSRF token、时间戳、随机串等动态内容",
	}
	if s.Errors > 0 {
		steps = append(steps, "有变体请求失败（error/error_kind）：先修 URL 编码/超时/代理，再重跑该变体")
	}
	if s.Signals == 0 && s.Errors == 0 {
		steps = append(steps, "本轮无明显差异：换变体/方法/头/身份，或先确认 baseline 与变体走的是同一端点")
	}
	steps = append(steps, "确认可复现后，用 report_finding 上报，evidence 里带上 baseline/variant 的状态码、长度、preview 与 URL")
	return steps
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func minDuration(a, b time.Duration) time.Duration {
	if b <= 0 || b < a {
		return b
	}
	return a
}
