package server

// Native raw-TCP probes: the reachability answer for isolated intranets.
//
// The platform already has HTTP egress via the task MITM; raw TCP (SMB/LDAP/
// TDS/MySQL/arbitrary banners) cannot go through that HTTP proxy. This tool
// therefore prefers the task's tunnel SOCKS5 upstream, then a global SOCKS5,
// then direct. Protocol construction and fingerprinting are code, not model
// guesses; the model only decides which target/protocol to try.
//
// It deliberately does NOT do authentication, brute force or exploitation; it
// answers "what speaks on this port" and hands the bytes back.

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/guard"
	actool "github.com/Autumn-27/norma/tool"
	xproxy "golang.org/x/net/proxy"
)

const (
	rawTCPMaxPayload = 64 << 10
	rawTCPMaxRead    = 64 << 10
)

func (s *Server) rawTCPTools() []actool.CoreTool {
	return []actool.CoreTool{s.toolRawTCP()}
}

func (s *Server) seedRawTCPTools() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	workerAgents, _ := json.Marshal([]string{"worker"})
	for _, t := range s.rawTCPTools() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.PG().SeedTool(t.Name(), t.Description(), schema, workerAgents); err != nil {
			log.Printf("[tools] seed %s 失败: %v", t.Name(), err)
		}
	}
}

// rawDialer chooses the raw-TCP egress path. Returns the connection and a
// redacted egress label for the result (task_socks5 / global_socks5 / direct).
func (s *Server) rawDialer(ctx context.Context, taskID int64, host string, port int, proxyRaw string) (net.Conn, string, error) {
	proxyRaw = strings.TrimSpace(proxyRaw)
	via := "direct"
	if proxyRaw == "" && s.m != nil {
		if u := s.m.TaskSocks5ForTask(taskID); u != "" {
			proxyRaw, via = u, "task_socks5"
		}
	}
	if proxyRaw == "" && s.m != nil {
		if gp := s.m.GlobalProxy(); strings.HasPrefix(strings.ToLower(gp), "socks5://") ||
			strings.HasPrefix(strings.ToLower(gp), "socks5h://") {
			proxyRaw, via = gp, "global_socks5"
		}
	}
	if via == "direct" && strings.TrimSpace(proxyRaw) != "" {
		via = "explicit_socks5"
	}
	target := net.JoinHostPort(host, strconv.Itoa(port))
	if proxyRaw != "" {
		if !isSocks5URL(proxyRaw) {
			return nil, "", fmt.Errorf("raw_tcp 只支持 socks5/socks5h 代理；收到 %s（HTTP 代理无法承载任意 TCP）", redactRawProxy(proxyRaw))
		}
		conn, err := dialSocks5Raw(ctx, proxyRaw, target)
		if err != nil {
			return nil, via, fmt.Errorf("经 %s 连接 %s 失败: %w", via, target, err)
		}
		return conn, via, nil
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, via, err
	}
	return conn, via, nil
}

func isSocks5URL(raw string) bool {
	low := strings.ToLower(strings.TrimSpace(raw))
	return strings.HasPrefix(low, "socks5://") || strings.HasPrefix(low, "socks5h://")
}

func dialSocks5Raw(ctx context.Context, proxyRaw, target string) (net.Conn, error) {
	u, err := url.Parse(proxyRaw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("socks5 代理地址非法")
	}
	var auth *xproxy.Auth
	if u.User != nil {
		pass, _ := u.User.Password()
		auth = &xproxy.Auth{User: u.User.Username(), Password: pass}
	}
	dialer, err := xproxy.SOCKS5("tcp", u.Host, auth, xproxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("socks5 初始化失败: %w", err)
	}
	if cd, ok := dialer.(xproxy.ContextDialer); ok {
		return cd.DialContext(ctx, "tcp", target)
	}
	return dialer.Dial("tcp", target)
}

func redactRawProxy(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.User != nil {
		return u.Redacted()
	}
	return raw
}

func (s *Server) toolRawTCP() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "raw_tcp",
		Description: "【原生 TCP 协议交互】直连/经任务隧道 SOCKS5 对目标端口发原始字节，按协议返回结构化指纹。" +
			"支持 protocol=raw（payload 为 hex）| smb（SMB2 NEGOTIATE）| ldap（匿名 BindRequest）| mysql（读服务端握手）| tds（TDS PRELOGIN）。" +
			"执行归代码：连接、超时、协议构造、响应解析、SMB2/LDAP/TDS/MySQL 指纹；不做认证/爆破/利用，是否继续由你判断。" +
			"内网隔离时先 tunnel_deploy，raw_tcp 会自动使用该任务的 SOCKS5 上游；也可显式传 proxy=socks5://...。" +
			"⚠️ raw TCP 观察不进入 observation_ledger；确认漏洞请用 report_finding（非 HTTP）或 exploit_author。",
		Schema: objSchema(map[string]any{
			"host":     strParam("目标 IP/域名"),
			"port":     map[string]any{"type": "integer", "description": "目标端口 1..65535"},
			"protocol": strParam("raw | smb | ldap | mysql | tds（默认 raw）"),
			"payload":  strParam("raw 协议的 hex 字节串（如 00000085ff534d42...）；其它协议自动构造"),
			"proxy":    strParam("可选：socks5://[user:pass@]host:port；留空自动用任务隧道 SOCKS5 / 全局 SOCKS5 / 直连"),
			"timeout":  map[string]any{"type": "integer", "description": "超时秒数，默认 8，范围 1..60", "default": 8},
			"read_len": map[string]any{"type": "integer", "description": "最多读取字节数，默认 4096，上限 65536", "default": 4096},
		}, "host", "port"),
		ReadOnly:    func(json.RawMessage) bool { return false },
		Permissions: sessionPerm,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct {
				Host     string `json:"host"`
				Protocol string `json:"protocol"`
				Payload  string `json:"payload"`
				Proxy    string `json:"proxy"`
				Port     int    `json:"port"`
				Timeout  int    `json:"timeout"`
				ReadLen  int    `json:"read_len"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败：" + err.Error()), nil
			}
			host := strings.TrimSpace(a.Host)
			if host == "" || strings.ContainsAny(host, " \t\r\n/\\") {
				return actool.Errorf("host 非法：只填 IP/域名"), nil
			}
			if a.Port <= 0 || a.Port > 65535 {
				return actool.Errorf("port 非法（1..65535）"), nil
			}
			proto := strings.ToLower(strings.TrimSpace(a.Protocol))
			if proto == "" {
				proto = "raw"
			}
			switch proto {
			case "raw", "smb", "ldap", "mysql", "tds":
			default:
				return actool.Errorf("protocol 只支持 raw/smb/ldap/mysql/tds"), nil
			}
			if a.Timeout <= 0 {
				a.Timeout = 8
			}
			if a.Timeout > 60 {
				return actool.Errorf("timeout 上限 60 秒"), nil
			}
			if a.ReadLen <= 0 {
				a.ReadLen = 4096
			}
			if a.ReadLen > rawTCPMaxRead {
				a.ReadLen = rawTCPMaxRead
			}
			ri := agent.RunInfoFrom(ctx)
			if inScope, known := guard.HostInTaskScope(ri.TaskID, host); known && !inScope {
				return actool.Errorf(fmt.Sprintf("目标 %s 不在任务已登记的 scope 内", host)), nil
			}

			var req []byte
			switch proto {
			case "smb":
				req = buildSMB2Negotiate()
			case "ldap":
				req = buildLDAPBindProbe()
			case "mysql":
				// MySQL server sends the initial handshake; no client request.
				req = nil
			case "tds":
				req = buildTDSPrelogin()
			default:
				if strings.TrimSpace(a.Payload) != "" {
					var err error
					req, err = hex.DecodeString(strings.TrimSpace(a.Payload))
					if err != nil {
						return actool.Errorf("payload 不是合法 hex: " + err.Error()), nil
					}
				}
			}
			if len(req) > rawTCPMaxPayload {
				return actool.Errorf("payload 过大（上限 64KB）"), nil
			}

			start := time.Now()
			conn, via, err := s.rawDialer(ctx, ri.TaskID, host, a.Port, a.Proxy)
			if err != nil {
				hint := "；若目标在隔离内网，先 tunnel_deploy，确保任务有 alive SOCKS5 隧道"
				return actool.Errorf("连接失败: " + err.Error() + hint), nil
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(time.Duration(a.Timeout) * time.Second))
			if len(req) > 0 {
				if _, err := conn.Write(req); err != nil {
					return actool.Errorf("发送失败: " + err.Error()), nil
				}
			}
			resp, readErr := readRawResponse(conn, a.ReadLen)
			elapsed := time.Since(start).Milliseconds()

			out := map[string]any{
				"host": host, "port": a.Port, "protocol": proto,
				"egress": via, "elapsed_ms": elapsed,
				"request_hex": hex.EncodeToString(req), "request_len": len(req),
				"response_hex": hex.EncodeToString(resp), "response_len": len(resp),
				"fingerprint": fingerprintRaw(proto, resp),
			}
			if a.Proxy != "" {
				out["proxy"] = redactRawProxy(a.Proxy)
			} else if via != "direct" {
				out["proxy"] = redactRawProxy(proxyForResult(s, ri.TaskID, via))
			}
			if readErr != nil {
				if ne, ok := readErr.(net.Error); !ok || !ne.Timeout() {
					out["read_error"] = readErr.Error()
				}
			}
			return jsonResult(out)
		},
	})
}

// proxyForResult is best-effort only: the egress label is the authoritative
// signal; the raw URL is already redacted before it reaches the model.
func proxyForResult(s *Server, taskID int64, via string) string {
	if s == nil || s.m == nil {
		return ""
	}
	if via == "task_socks5" {
		return s.m.TaskSocks5ForTask(taskID)
	}
	if via == "global_socks5" {
		return s.m.GlobalProxy()
	}
	return ""
}

func readRawResponse(conn net.Conn, max int) ([]byte, error) {
	out := make([]byte, 0, 256)
	buf := make([]byte, max)
	for len(out) < max {
		n, err := conn.Read(buf[:max-len(out)])
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err != nil {
			if err == io.EOF && len(out) > 0 {
				return out, nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() && len(out) > 0 {
				return out, nil
			}
			return out, err
		}
		if n == 0 {
			break
		}
		// After the first chunk, don't wait the full timeout for a quiet protocol.
		_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	}
	return out, nil
}

// buildSMB2Negotiate builds an SMB2 NEGOTIATE request (dialects 2.0.2 and 2.1)
// with the 4-byte NetBIOS length prefix.
func buildSMB2Negotiate() []byte {
	body := make([]byte, 40)
	binary.LittleEndian.PutUint16(body[0:], 36) // StructureSize
	binary.LittleEndian.PutUint16(body[2:], 2)  // DialectCount
	binary.LittleEndian.PutUint16(body[4:], 1)  // SecurityMode: signing enabled
	// [6:8] reserved, [8:12] capabilities, [12:28] ClientGuid, [28:36] start time
	binary.LittleEndian.PutUint16(body[36:], 0x0202)
	binary.LittleEndian.PutUint16(body[38:], 0x0210)

	hdr := make([]byte, 64)
	copy(hdr, []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(hdr[4:], 64) // StructureSize
	// CreditCharge/Status/Command/Credits/Flags/... all zero.
	msg := append(hdr, body...)
	return append([]byte{0x00, byte(len(msg) >> 16), byte(len(msg) >> 8), byte(len(msg))}, msg...)
}

// buildLDAPBindProbe builds an anonymous LDAPv3 BindRequest.
func buildLDAPBindProbe() []byte {
	// SEQUENCE { messageID=1, bindRequest { version=3, name="", simple="" } }
	return []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00}
}

// buildTDSPrelogin builds a minimal TDS PRELOGIN (SQL Server probe).
func buildTDSPrelogin() []byte {
	payload := []byte{
		0x00, 0x00, 0x1A, 0x00, 0x06, 0x01, 0x00, 0x20, 0x00, 0x01,
		0x02, 0x00, 0x21, 0x00, 0x01, 0x03, 0x00, 0x22, 0x00, 0x04,
		0x04, 0x00, 0x26, 0x00, 0x01, 0xff,
	}
	hdr := []byte{0x12, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00}
	binary.BigEndian.PutUint16(hdr[2:], uint16(len(payload)+8))
	return append(hdr, payload...)
}

func fingerprintRaw(protocol string, resp []byte) string {
	switch strings.ToLower(protocol) {
	case "smb":
		if len(resp) >= 8 && resp[4] == 0xFE && resp[5] == 'S' && resp[6] == 'M' && resp[7] == 'B' {
			return "smb2"
		}
		if len(resp) >= 8 && resp[4] == 0xFF && resp[5] == 'S' && resp[6] == 'M' && resp[7] == 'B' {
			return "smb1"
		}
	case "ldap":
		if len(resp) > 0 && resp[0] == 0x30 {
			return "ldap"
		}
	case "mysql":
		if len(resp) > 4 {
			if i := strings.IndexByte(string(resp[4:]), 0); i > 0 {
				return "mysql:" + string(resp[4:4+i])
			}
		}
	case "tds":
		if len(resp) > 0 && resp[0] == 0x04 {
			return "tds"
		}
	}
	if len(resp) == 0 {
		return "no_response"
	}
	return "unknown"
}
