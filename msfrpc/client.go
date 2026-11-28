package msfrpc

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrNotAuthenticated is returned when a call needs a session token and Login
// has not succeeded yet.
var ErrNotAuthenticated = errors.New("msfrpc: 未认证")

// Options describes one msfrpcd endpoint.
type Options struct {
	Host    string
	Port    int
	SSL     bool // msfrpcd defaults to TLS; `msfrpcd -S` runs plaintext
	Timeout time.Duration
}

// Client is a single msfrpcd endpoint. It is safe for concurrent use once
// logged in.
type Client struct {
	opts Options
	http *http.Client

	mu    sync.RWMutex
	token string
}

// New builds a client. No connection is made until the first call, so an
// unreachable or TLS-mismatched endpoint surfaces from Login.
func New(o Options) *Client {
	if o.Host == "" {
		o.Host = "127.0.0.1"
	}
	if o.Port == 0 {
		o.Port = 55553
	}
	if o.Timeout <= 0 {
		o.Timeout = 60 * time.Second
	}
	tr := &http.Transport{
		// msfrpcd ships a self-signed certificate; pinning it is not possible
		// (it is generated at install time), so TLS is used for confidentiality
		// over loopback/LAN only.
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // self-signed msfrpcd cert
		DialContext:       (&net.Dialer{Timeout: 15 * time.Second}).DialContext,
		DisableKeepAlives: false,
		MaxIdleConns:      4,
	}
	return &Client{opts: o, http: &http.Client{Timeout: o.Timeout, Transport: tr}}
}

// URL is the RPC endpoint (always /api/, the only path msfrpcd serves).
func (c *Client) URL() string {
	scheme := "http"
	if c.opts.SSL {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s/api/", scheme, net.JoinHostPort(c.opts.Host, strconv.Itoa(c.opts.Port)))
}

// Close releases idle connections.
func (c *Client) Close() { c.http.CloseIdleConnections() }

// Login authenticates and stores the session token. msfrpcd's default user is
// "msf"; the token returned by auth.login is valid for this connection's
// lifetime, so no permanent token is minted.
func (c *Client) Login(ctx context.Context, user, password string) error {
	if user == "" {
		user = "msf"
	}
	res, err := c.Call(ctx, "auth.login", user, password)
	if err != nil {
		return err
	}
	m, ok := res.(map[string]any)
	if !ok {
		return fmt.Errorf("auth.login 返回类型异常：%T", res)
	}
	if s := asString(m["result"]); s != "success" {
		reason := asString(m["error_message"])
		if reason == "" {
			reason = s
		}
		if reason == "" {
			reason = "unknown"
		}
		return fmt.Errorf("msfrpcd 认证失败：%s", reason)
	}
	token := asString(m["token"])
	if token == "" {
		return errors.New("auth.login 成功但没有返回 token")
	}
	c.mu.Lock()
	c.token = token
	c.mu.Unlock()
	return nil
}

// Token reports the current session token ("" before Login).
func (c *Client) Token() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.token
}

// Call posts [method, token?, args...] as MessagePack and returns the decoded
// reply. A reply carrying an error field becomes a Go error.
func (c *Client) Call(ctx context.Context, method string, args ...any) (any, error) {
	payload := make([]any, 0, len(args)+2)
	payload = append(payload, method)
	if method != "auth.login" {
		token := c.Token()
		if token == "" {
			return nil, ErrNotAuthenticated
		}
		args = append([]any{token}, args...)
	}
	payload = append(payload, args...)

	body, err := encode(payload)
	if err != nil {
		return nil, fmt.Errorf("msfrpc: 编码 %s 请求失败：%w", method, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "binary/message-pack")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("msfrpc: %s 请求失败：%w", method, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, fmt.Errorf("msfrpc: 读取 %s 响应失败：%w", method, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("msfrpc: %s 返回 HTTP %d：%s", method, resp.StatusCode, truncate(string(raw), 200))
	}
	val, err := decode(raw)
	if err != nil {
		return nil, fmt.Errorf("msfrpc: 解析 %s 响应失败：%w", method, err)
	}
	if m, ok := val.(map[string]any); ok {
		if msg := rpcError(m); msg != "" {
			return nil, fmt.Errorf("msfrpc: %s 失败：%s", method, msg)
		}
	}
	return val, nil
}

// rpcError extracts the daemon's error text from a reply map.
func rpcError(m map[string]any) string {
	for _, k := range []string{"error_message", "error"} {
		v, ok := m[k]
		if !ok || v == nil {
			continue
		}
		if s := asString(v); s != "" {
			return s
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Typed surface used by the Metasploit closed loop
// ---------------------------------------------------------------------------

// Session is one entry of session.list.
type Session struct {
	ID         string
	Type       string // "shell" or "meterpreter"
	TunnelPeer string
	ViaExploit string
	Username   string
	Info       map[string]any
}

// Version returns the framework version string (core.version).
func (c *Client) Version(ctx context.Context) (string, error) {
	res, err := c.Call(ctx, "core.version")
	if err != nil {
		return "", err
	}
	m, _ := res.(map[string]any)
	return asString(m["version"]), nil
}

// Sessions lists live sessions keyed by id.
func (c *Client) Sessions(ctx context.Context) (map[string]Session, error) {
	res, err := c.Call(ctx, "session.list")
	if err != nil {
		return nil, err
	}
	raw, ok := res.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("session.list 返回类型异常：%T", res)
	}
	out := make(map[string]Session, len(raw))
	for id, v := range raw {
		info, _ := v.(map[string]any)
		out[id] = Session{
			ID:         id,
			Type:       strings.ToLower(asString(info["type"])),
			TunnelPeer: asString(info["tunnel_peer"]),
			ViaExploit: asString(info["via_exploit"]),
			Username:   asString(info["username"]),
			Info:       info,
		}
	}
	return out, nil
}

// ModuleInfo fetches a module's metadata; it doubles as the "does this module
// exist in this MSF build?" check.
func (c *Client) ModuleInfo(ctx context.Context, moduleType, name string) (map[string]any, error) {
	res, err := c.Call(ctx, "module.info", moduleType, name)
	if err != nil {
		return nil, err
	}
	m, ok := res.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("module.info(%s) 返回类型异常：%T", name, res)
	}
	return m, nil
}

// ModuleExecute starts a module. Unlike console scripting it only accepts the
// core options (RHOSTS/RPORT/PAYLOAD/LHOST/LPORT/…), which is why the closed
// loop prefers consoles and falls back here.
func (c *Client) ModuleExecute(ctx context.Context, moduleType, name string, opts map[string]any) (map[string]any, error) {
	res, err := c.Call(ctx, "module.execute", moduleType, name, opts)
	if err != nil {
		return nil, err
	}
	m, ok := res.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("module.execute(%s) 返回类型异常：%T", name, res)
	}
	return m, nil
}

// ConsoleCreate opens a console and returns its id.
func (c *Client) ConsoleCreate(ctx context.Context) (int, error) {
	res, err := c.Call(ctx, "console.create")
	if err != nil {
		return 0, err
	}
	m, ok := res.(map[string]any)
	if !ok {
		return 0, fmt.Errorf("console.create 返回类型异常：%T", res)
	}
	id := int(asInt(m["id"]))
	if id == 0 {
		if raw := asString(m["id"]); raw != "" {
			if n, convErr := strconv.Atoi(raw); convErr == nil {
				id = n
			}
		}
	}
	return id, nil
}

// ConsoleWrite feeds one or more commands to a console.
func (c *Client) ConsoleWrite(ctx context.Context, id int, data string) error {
	_, err := c.Call(ctx, "console.write", id, data)
	return err
}

// ConsoleRead drains a console's output.
func (c *Client) ConsoleRead(ctx context.Context, id int) (data string, busy bool, err error) {
	res, err := c.Call(ctx, "console.read", id)
	if err != nil {
		return "", false, err
	}
	m, _ := res.(map[string]any)
	return asString(m["data"]), asBool(m["busy"]), nil
}

// ConsoleDestroy closes a console.
func (c *Client) ConsoleDestroy(ctx context.Context, id int) error {
	_, err := c.Call(ctx, "console.destroy", id)
	return err
}

// SessionCommand runs one command inside a shell/meterpreter session and
// returns whatever output was ready. msfrpcd exposes write/read per session
// type, so the call is split by session kind.
func (c *Client) SessionCommand(ctx context.Context, id, sessionType, command string) (string, error) {
	if sessionType == "meterpreter" {
		if _, err := c.Call(ctx, "session.meterpreter_write", id, command+"\n"); err != nil {
			return "", err
		}
		res, err := c.Call(ctx, "session.meterpreter_read", id)
		if err != nil {
			return "", err
		}
		return asString(res), nil
	}
	if _, err := c.Call(ctx, "session.shell_write", id, command); err != nil {
		return "", err
	}
	res, err := c.Call(ctx, "session.shell_read", id)
	if err != nil {
		return "", err
	}
	return asString(res), nil
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

func asString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	case nil:
		return ""
	default:
		return fmt.Sprint(x)
	}
}

func asInt(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case uint64:
		return int64(x)
	case float64:
		return int64(x)
	case string:
		n, _ := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		return n
	default:
		return 0
	}
}

func asBool(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(x, "true")
	default:
		return false
	}
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
