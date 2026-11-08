package server

// impacket_proxy runs impacket scripts through the task's SOCKS5 tunnel using
// proxychains. It is intentionally Linux/proxychains-only: on Windows there is
// no proxychains, so the tool returns tool_missing instead of pretending that
// direct execution reaches an isolated DC.
//
// We use TaskSocks5ForTask (the tunnel upstream), not TaskProxyForTask (the
// HTTP MITM). proxychains speaks SOCKS5; feeding it the HTTP proxy address is a
// common and silent failure mode.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	actool "github.com/Autumn-27/norma/tool"
)

type impacketProxyParams struct {
	Script     string   `json:"script"`
	Args       []string `json:"args"`
	TimeoutSec int      `json:"timeout_sec,omitempty"`
	DryRun     bool     `json:"dry_run,omitempty"`
}

func (s *Server) impacketProxyTools() []actool.CoreTool {
	return []actool.CoreTool{s.toolImpacketProxy()}
}

func (s *Server) seedImpacketProxyTools() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	workerAgents, _ := json.Marshal([]string{"worker"})
	for _, t := range s.impacketProxyTools() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.PG().SeedTool(t.Name(), t.Description(), schema, workerAgents); err != nil {
			log.Printf("[tools] seed %s 失败: %v", t.Name(), err)
		}
	}
}

func findProxychains() (string, error) {
	for _, name := range []string{"proxychains4", "proxychains"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("未找到 proxychains（仅 Linux；Windows 不支持）")
}

func (s *Server) toolImpacketProxy() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "impacket_proxy",
		Description: "【impacket 经任务隧道】让 AS-REP/DCSync/委派等 impacket 脚本走任务 SOCKS5 隧道（proxychains）。" +
			"执行归代码：取任务 SOCKS5 上游 → 写临时 proxychains 配置 → 执行脚本 → 返回输出；无隧道时明确返回 no_tunnel，不伪装直连成功。" +
			"仅 Linux/proxychains；Windows 返回 tool_missing。script 只接受 impacket 脚本名（GetNPUsers.py/secretsdump.py/...），args 为脚本参数。",
		Schema: objSchema(map[string]any{
			"script":      strParam("impacket 脚本名，如 GetNPUsers.py / secretsdump.py / findDelegation.py"),
			"args":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "传给脚本的参数（不含 python/proxychains）"},
			"timeout_sec": map[string]any{"type": "integer", "description": "默认 180，上限 900", "default": 180},
			"dry_run":     map[string]any{"type": "boolean", "description": "只解析隧道/工具/参数，不执行"},
		}, "script", "args"),
		ReadOnly:    func(json.RawMessage) bool { return false },
		Permissions: sessionPerm,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a impacketProxyParams
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败：" + err.Error()), nil
			}
			a.Script = strings.TrimSpace(a.Script)
			if !validImpacketScriptName(a.Script) {
				return actool.Errorf("script 非法：只接受 impacket 脚本名（不能含路径分隔符）"), nil
			}
			if len(a.Args) > 64 {
				return actool.Errorf("args 过多（上限 64）"), nil
			}
			if a.TimeoutSec <= 0 {
				a.TimeoutSec = 180
			}
			if a.TimeoutSec > 900 {
				a.TimeoutSec = 900
			}
			ri := agent.RunInfoFrom(ctx)

			pc, pcErr := findProxychains()
			if pcErr != nil {
				return jsonResult(map[string]any{
					"status": "tool_missing", "error": pcErr.Error(),
					"next_steps": []string{
						"在 Linux 上安装 proxychains-ng（apt install proxychains4 / yum install proxychains-ng）",
						"Windows 无 proxychains；把 impacket 放到跳板/会话侧执行",
					},
				})
			}
			script, err := findServerImpacketScript(a.Script)
			if err != nil {
				return jsonResult(map[string]any{
					"status": "tool_missing", "error": err.Error(),
					"next_steps": []string{"pip install impacket", "或设 ARTEX_IMPACKET_SCRIPTS 指向 Scripts 目录"},
				})
			}
			socks5 := ""
			if s.m != nil && ri.TaskID > 0 {
				socks5 = s.m.TaskSocks5ForTask(ri.TaskID)
			}
			if socks5 == "" {
				return jsonResult(map[string]any{
					"status": "no_tunnel", "script": a.Script,
					"next_steps": []string{"先 tunnel_deploy 建 alive SOCKS5 隧道；再重试 impacket_proxy"},
				})
			}
			host, port, user, pass, err := parseSocks5URL(socks5)
			if err != nil {
				return actool.Errorf("任务 SOCKS5 地址非法: " + err.Error()), nil
			}
			python := ""
			runTarget := script
			if strings.HasSuffix(strings.ToLower(script), ".py") {
				python = msfPythonBin()
				if python == "" {
					return actool.Errorf("找到 .py 脚本但没有 Python 解释器"), nil
				}
				runTarget = python
			}
			confPath, cleanup, err := writeProxychainsConf(host, port, user, pass)
			if err != nil {
				return actool.Errorf("写 proxychains 配置失败: " + err.Error()), nil
			}
			defer cleanup()

			cmdArgs := []string{"-f", confPath, runTarget}
			if python != "" {
				cmdArgs = append(cmdArgs, script)
			}
			cmdArgs = append(cmdArgs, a.Args...)
			if a.DryRun {
				return jsonResult(map[string]any{
					"status": "dry_run", "script": script, "python": python,
					"proxychains": pc, "args": cmdArgs,
					"proxy": redactSocks5(socks5), "egress": "task_socks5",
				})
			}
			runCtx, cancel := context.WithTimeout(ctx, time.Duration(a.TimeoutSec)*time.Second)
			defer cancel()
			cmd := exec.CommandContext(runCtx, pc, cmdArgs...)
			cmd.Env = append(os.Environ(), "PROXYCHAINS_CONF_FILE="+confPath, "PROXYCHAINS_QUIET_MODE=1")
			var stdout, stderr strings.Builder
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			runErr := cmd.Run()
			out := stdout.String() + "\n" + stderr.String()
			res := map[string]any{
				"status": "success", "script": a.Script,
				"proxy": redactSocks5(socks5), "egress": "task_socks5",
				"output_tail": truncateForTool(out),
			}
			if runErr != nil {
				res["status"] = "failed"
				res["error"] = runErr.Error()
				res["next_steps"] = impacketProxyNextSteps(out)
			}
			return jsonResult(res)
		},
	})
}

func validImpacketScriptName(name string) bool {
	if name == "" || strings.ContainsAny(name, `/\`) || name == "." || name == ".." {
		return false
	}
	low := strings.ToLower(name)
	return strings.HasSuffix(low, ".py") || strings.HasPrefix(low, "impacket-")
}

func findServerImpacketScript(name string) (string, error) {
	if dir := strings.TrimSpace(os.Getenv("ARTEX_IMPACKET_SCRIPTS")); dir != "" {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	if py := msfPythonBin(); py != "" {
		dir := filepath.Dir(py)
		for _, sub := range []string{"Scripts", ""} {
			p := filepath.Join(dir, sub, name)
			if _, err := os.Stat(p); err == nil {
				return p, nil
			}
		}
	}
	return "", fmt.Errorf("未找到 impacket 脚本 %s", name)
}

func parseSocks5URL(raw string) (host string, port int, user, pass string, err error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", 0, "", "", fmt.Errorf("非法 SOCKS5 URL")
	}
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h":
	default:
		return "", 0, "", "", fmt.Errorf("不是 socks5 URL")
	}
	h, p, err := net.SplitHostPort(u.Host)
	if err != nil {
		return "", 0, "", "", fmt.Errorf("SOCKS5 地址缺少端口")
	}
	n, err := strconv.Atoi(p)
	if err != nil || n <= 0 || n > 65535 {
		return "", 0, "", "", fmt.Errorf("SOCKS5 端口非法")
	}
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	return h, n, user, pass, nil
}

func writeProxychainsConf(host string, port int, user, pass string) (string, func(), error) {
	f, err := os.CreateTemp("", "artex-proxychains-*.conf")
	if err != nil {
		return "", func() {}, err
	}
	line := fmt.Sprintf("socks5 %s %d", host, port)
	if user != "" {
		line += " " + user + " " + pass
	}
	conf := "strict_chain\nproxy_dns\ntcp_read_time_out 15000\ntcp_connect_time_out 8000\n[ProxyList]\n" + line + "\n"
	if _, err := f.WriteString(conf); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", func() {}, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return "", func() {}, err
	}
	return f.Name(), func() { _ = os.Remove(f.Name()) }, nil
}

func redactSocks5(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.User != nil {
		return u.Redacted()
	}
	return raw
}

func impacketProxyNextSteps(out string) []string {
	low := strings.ToLower(out)
	switch {
	case strings.Contains(low, "proxychains") && strings.Contains(low, "error"):
		return []string{"确认任务 SOCKS5 仍 alive；proxychains 配置由工具生成，不要手改"}
	case strings.Contains(low, "clock skew") || strings.Contains(low, "krb_ap_err_skew"):
		return []string{"同步操作机与 DC 时间（chrony/w32tm）"}
	case strings.Contains(low, "connection refused") || strings.Contains(low, "timed out"):
		return []string{"确认隧道出口能到 DC 88/389/445；必要时重开 tunnel_deploy"}
	case strings.Contains(low, "invalid credentials") || strings.Contains(low, "logon failure"):
		return []string{"核对域凭据；失败会消耗 badPwdCount"}
	}
	return []string{"先 dry_run 确认 script/tunnel/proxychains 就绪"}
}
