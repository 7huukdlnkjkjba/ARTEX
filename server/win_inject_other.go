//go:build !windows

package server

import (
	"context"
	"encoding/json"

	actool "github.com/Autumn-27/norma/tool"
)

func (s *Server) winInjectTools() []actool.CoreTool {
	return []actool.CoreTool{s.toolWinInject()}
}

func (s *Server) seedWinInjectTools() {}

func (s *Server) toolWinInject() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        "win_inject",
		Description: "【Windows 进程注入】仅 Windows 可用；当前平台返回 tool_unsupported。",
		Schema:      winInjectSchema(),
		ReadOnly:    func(json.RawMessage) bool { return false },
		Permissions: sessionPerm,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return jsonResult(map[string]any{
				"status": "tool_unsupported",
				"error":  "win_inject 仅支持 Windows；当前平台不可用",
			})
		},
	})
}
