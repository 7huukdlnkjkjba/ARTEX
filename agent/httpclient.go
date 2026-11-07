package agent

// In-process HTTP client plumbing for recon_http / http_diff.
//
// The client must use the same per-run egress path as Bash:
//   - the task recording MITM (HTTP proxy) when capture is on — so these requests
//     are visible to traffic_search and evidence binding;
//   - a task-tunnel SOCKS5 (socks5://...) when the target is only reachable
//     through a foothold;
//   - the global egress proxy, or direct, when neither applies.
//
// InsecureSkipVerify defaults to true because pentest targets routinely use
// self-signed certs; callers can set insecure=false to verify (and the task MITM
// CA from the proxy setup is then trusted).

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	xproxy "golang.org/x/net/proxy"
)

const (
	httpFetchMaxBody = 1 << 20 // 1 MiB: enough for diff/compare, bounded per request
	httpFetchPreview = 4096
)

var httpCredRe = regexp.MustCompile(`://[^/\s]+@`)

// redactURLUserinfo removes user:password from a URL for tool results/transcripts.
// Non-URL text falls back to the regex redactor.
func redactURLUserinfo(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return redactHTTPText(raw)
	}
	u.User = nil
	s := u.String()
	if i := strings.Index(s, "://"); i >= 0 {
		return s[:i+3] + "***@" + s[i+3:]
	}
	return redactHTTPText(raw)
}

func redactURLList(urls []string) []string {
	if len(urls) == 0 {
		return nil
	}
	out := make([]string, len(urls))
	for i, u := range urls {
		out[i] = redactURLUserinfo(u)
	}
	return out
}

// SetHTTPProxy wires the per-run egress proxy into the in-process HTTP tools.
// addr may be empty (direct), http(s)://..., or socks5://[user:pass@]host:port.
// caCert is the recording MITM's CA path, used only when insecure=false.
func (t *ToolSet) SetHTTPProxy(addr, caCert string) {
	t.httpProxyAddr = strings.TrimSpace(addr)
	t.httpProxyCA = strings.TrimSpace(caCert)
}

// SetHTTPUserAgent wires the task's stable UA for in-process recon requests.
func (t *ToolSet) SetHTTPUserAgent(ua string) { t.httpUA = strings.TrimSpace(ua) }

// httpProxyDisplay redacts credentials from a proxy URL for tool results.
func (t *ToolSet) httpProxyDisplay() string {
	if t.httpProxyAddr == "" {
		return ""
	}
	raw := t.httpProxyAddr
	if !strings.Contains(raw, "://") {
		if i := strings.Index(raw, "@"); i >= 0 {
			return "***@" + raw[i+1:]
		}
	}
	return redactURLUserinfo(raw)
}

// newHTTPClient builds a client honoring the run's proxy and TLS settings.
func (t *ToolSet) newHTTPClient(insecure bool) (*http.Client, error) {
	tr := &http.Transport{
		// A custom TLS config disables automatic h2; keep HTTP/1.1 so the MITM
		// and traffic recorder see a single, predictable stream.
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          20,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure}, //nolint:gosec // pentest targets commonly self-sign
	}
	if !insecure && t.httpProxyCA != "" {
		pem, err := os.ReadFile(t.httpProxyCA)
		if err != nil {
			return nil, fmt.Errorf("读取代理 CA 失败: %v", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("代理 CA 不是有效 PEM: %s", t.httpProxyCA)
		}
		tr.TLSClientConfig.RootCAs = pool
	}

	addr := t.httpProxyAddr
	if addr == "" {
		return &http.Client{Transport: tr}, nil
	}
	raw := addr
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("代理地址无效: %s", redactHTTPText(addr))
	}
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h":
		var auth *xproxy.Auth
		if u.User != nil {
			pass, _ := u.User.Password()
			auth = &xproxy.Auth{User: u.User.Username(), Password: pass}
		}
		dialer, derr := xproxy.SOCKS5("tcp", u.Host, auth, xproxy.Direct)
		if derr != nil {
			return nil, fmt.Errorf("SOCKS5 代理配置失败: %v", derr)
		}
		if cd, ok := dialer.(xproxy.ContextDialer); ok {
			tr.DialContext = cd.DialContext
		} else {
			tr.DialContext = func(_ context.Context, network, address string) (net.Conn, error) {
				return dialer.Dial(network, address)
			}
		}
	case "http", "https":
		tr.Proxy = http.ProxyURL(u)
	default:
		return nil, fmt.Errorf("不支持的代理协议 %s（支持 http/https/socks5）", u.Scheme)
	}
	return &http.Client{Transport: tr}, nil
}

// httpFetchOptions is one request's shape. Timeout is per request.
type httpFetchOptions struct {
	Method  string
	Headers map[string]string
	Body    string
	Follow  bool
	Timeout time.Duration
}

// httpFetchResult is the internal (non-JSON) response shape used by both tools.
type httpFetchResult struct {
	Status           int
	StatusText       string
	Proto            string
	Headers          http.Header
	Body             []byte
	BodyLen          int
	BodyTruncated    bool
	Preview          string
	PreviewTruncated bool
	FinalURL         string
	Redirects        []string
	RedirectLimitHit bool
	ElapsedMs        int64
	Error            string
	ErrorKind        string
}

// fetchHTTP performs one request. It shares the client's Transport but applies a
// per-call redirect policy so follow=true/false is independently controlled.
func (t *ToolSet) fetchHTTP(ctx context.Context, client *http.Client, rawURL string, opts httpFetchOptions) httpFetchResult {
	start := time.Now()
	res := httpFetchResult{}

	reqCtx := ctx
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		reqCtx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(reqCtx, opts.Method, rawURL, strings.NewReader(opts.Body))
	if err != nil {
		res.ErrorKind, res.Error = "request", redactHTTPText(err.Error())
		res.ElapsedMs = time.Since(start).Milliseconds()
		return res
	}
	for k, v := range opts.Headers {
		if strings.EqualFold(k, "Host") {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	if req.Header.Get("User-Agent") == "" {
		ua := t.httpUA
		if ua == "" {
			ua = "artex-recon/1.0"
		}
		req.Header.Set("User-Agent", ua)
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "*/*")
	}

	c := *client
	var redirects []string
	limitHit := false
	c.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		redirects = append(redirects, next.URL.String())
		if !opts.Follow {
			return http.ErrUseLastResponse
		}
		if next.URL.Scheme != "http" && next.URL.Scheme != "https" {
			return fmt.Errorf("redirect 到不支持的协议 %s", next.URL.Scheme)
		}
		if err := t.assertInScope(next.URL.Hostname()); err != nil {
			return fmt.Errorf("redirect 目标越界: %w", err)
		}
		if len(via) >= 5 {
			limitHit = true
			return http.ErrUseLastResponse
		}
		return nil
	}

	resp, err := c.Do(req)
	res.ElapsedMs = time.Since(start).Milliseconds()
	res.Redirects = redirects
	res.RedirectLimitHit = limitHit
	if err != nil {
		res.ErrorKind, res.Error = classifyHTTPError(err)
		return res
	}
	defer resp.Body.Close()

	res.Status = resp.StatusCode
	res.StatusText = resp.Status
	res.Proto = resp.Proto
	res.Headers = resp.Header.Clone()
	res.FinalURL = resp.Request.URL.String()

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, httpFetchMaxBody+1))
	if len(body) > httpFetchMaxBody {
		body = body[:httpFetchMaxBody]
		res.BodyTruncated = true
	}
	res.Body = body
	res.BodyLen = len(body)
	if resp.ContentLength > 0 && resp.ContentLength > int64(res.BodyLen) {
		res.BodyTruncated = true
	}
	res.Preview = string(previewBytes(res.Body, httpFetchPreview))
	res.PreviewTruncated = len(res.Body) > httpFetchPreview
	if readErr != nil {
		res.ErrorKind = "read"
		res.Error = redactHTTPText("读取响应体失败: " + readErr.Error())
	}
	return res
}

// parseReconURL validates an absolute http(s) URL.
func parseReconURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("url 必填")
	}
	if !strings.Contains(raw, "://") {
		return nil, fmt.Errorf("url 需带 http:// 或 https://（例如 %s）", "http://"+raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("url 解析失败: %v", redactHTTPText(err.Error()))
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("只支持 http/https，拒绝 scheme=%s", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("url 缺少主机名")
	}
	return u, nil
}

func normalizeHTTPMethod(m string) (string, error) {
	m = strings.ToUpper(strings.TrimSpace(m))
	if m == "" {
		return http.MethodGet, nil
	}
	switch m {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete,
		http.MethodPatch, http.MethodHead, http.MethodOptions:
		return m, nil
	default:
		return "", fmt.Errorf("method 只支持 GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS")
	}
}

func validateHTTPHeaders(h map[string]string) error {
	for k, v := range h {
		name := strings.TrimSpace(k)
		if name == "" || strings.ContainsAny(name, "\r\n: \t") {
			return fmt.Errorf("header 名非法: %q", k)
		}
		if strings.ContainsAny(v, "\r\n") {
			return fmt.Errorf("header %s 的值不能包含换行", name)
		}
		if len(v) > 8192 {
			return fmt.Errorf("header %s 的值过长（上限 8KB）", name)
		}
		if strings.EqualFold(name, "Content-Length") || strings.EqualFold(name, "Transfer-Encoding") {
			return fmt.Errorf("不要手动设置 %s，让 HTTP 客户端计算", name)
		}
	}
	return nil
}

func derefBool(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

func previewBytes(b []byte, n int) []byte {
	if n <= 0 || len(b) <= n {
		return b
	}
	return b[:n]
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func redactHTTPText(s string) string {
	return httpCredRe.ReplaceAllString(s, "://***@")
}

// classifyHTTPError maps Go transport errors to a small stable vocabulary the
// model can act on. Messages are redacted (a URL may embed userinfo).
func classifyHTTPError(err error) (kind, msg string) {
	if err == nil {
		return "", ""
	}
	text := redactHTTPText(err.Error())
	low := strings.ToLower(text)
	var netErr net.Error
	var dnsErr *net.DNSError
	switch {
	case errors.Is(err, context.DeadlineExceeded) ||
		(errors.As(err, &netErr) && netErr.Timeout()) ||
		strings.Contains(low, "i/o timeout") || strings.Contains(low, "deadline exceeded") ||
		strings.Contains(low, "timed out"):
		return "timeout", "请求超时（可调大 timeout_sec；目标/代理可能不可达）"
	case errors.Is(err, context.Canceled):
		return "cancelled", "请求被取消（任务/工具超时或人工终止）"
	case errors.As(err, &dnsErr) || strings.Contains(low, "no such host") ||
		strings.Contains(low, "server misbehaving") || strings.Contains(low, "name resolution"):
		return "dns", "域名解析失败（确认 DNS/代理，或直接用 IP）"
	case strings.Contains(low, "connection refused") || strings.Contains(low, "actively refused") ||
		strings.Contains(low, "winerror 10061"):
		return "refused", "连接被拒绝（端口未开放或被防火墙过滤）"
	case strings.Contains(low, "certificate") || strings.Contains(low, "x509") ||
		strings.Contains(low, "remote error: tls") || strings.Contains(low, "tls:"):
		return "tls", "TLS 证书校验失败（可设 insecure=true，或检查任务 MITM CA）"
	case strings.Contains(low, "proxyconnect") || strings.Contains(low, "proxy"):
		return "proxy", "代理连接失败（检查任务隧道/全局代理）"
	case strings.Contains(low, "越界") || strings.Contains(low, "scope"):
		return "scope", kerbTruncate(text, 300)
	default:
		return "request", kerbTruncate(text, 300)
	}
}
