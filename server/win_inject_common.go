//go:build !windows

package server

// Shared validation/schema for win_inject. The actual injection implementation
// is Windows-only (win_inject_windows.go); other platforms register a stub that
// returns tool_unsupported so the tool table stays consistent.

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

const winInjectMaxShellcode = 1 << 20

type winInjectParams struct {
	PID         int    `json:"pid"`
	ProcessName string `json:"process_name"`
	Shellcode   string `json:"shellcode"`
	Method      string `json:"method,omitempty"`
	Confirm     bool   `json:"confirm,omitempty"`
	DryRun      bool   `json:"dry_run,omitempty"`
}

func winInjectSchema() map[string]any {
	return objSchema(map[string]any{
		"pid":          map[string]any{"type": "integer", "description": "目标进程 PID（必须 >4）"},
		"process_name": strParam("目标进程名，必须与实际进程路径 basename 完全匹配，如 explorer.exe"),
		"shellcode":    strParam("Base64 或 hex 编码的 raw shellcode（≤1MB）；不生成 shellcode"),
		"method":       strParam("createremote（默认；APC 未实现）"),
		"confirm":      map[string]any{"type": "boolean", "description": "实际注入必须显式 true；dry_run 不需要"},
		"dry_run":      map[string]any{"type": "boolean", "description": "只校验 PID/进程名/shellcode，不分配内存不注入"},
	}, "pid", "process_name", "shellcode")
}

func (p *winInjectParams) Normalize() ([]byte, error) {
	if p.PID <= 4 {
		return nil, fmt.Errorf("pid 必须 > 4（拒绝 System/Idle）")
	}
	p.ProcessName = strings.TrimSpace(p.ProcessName)
	if p.ProcessName == "" {
		return nil, fmt.Errorf("process_name 必填：必须与实际进程 basename 匹配")
	}
	p.Method = strings.ToLower(strings.TrimSpace(p.Method))
	if p.Method == "" {
		p.Method = "createremote"
	}
	if p.Method != "createremote" {
		return nil, fmt.Errorf("method 只支持 createremote（APC 未实现）")
	}
	sc, err := decodeWinShellcode(p.Shellcode)
	if err != nil {
		return nil, err
	}
	if !p.Confirm && !p.DryRun {
		return nil, fmt.Errorf("进程注入是高影响操作：确认目标和 RoE 后设置 confirm=true；可先用 dry_run=true 校验")
	}
	return sc, nil
}

func decodeWinShellcode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("shellcode 为空")
	}
	// Prefer hex when the input is unambiguously hex (even length, all hex
	// digits); otherwise a hex string like "9090" would be silently decoded as
	// base64.
	candidate := strings.TrimPrefix(strings.ToLower(s), "0x")
	if len(candidate)%2 == 0 && candidate != "" && isHex(candidate) {
		if b, err := hex.DecodeString(candidate); err == nil && len(b) > 0 {
			if len(b) > winInjectMaxShellcode {
				return nil, fmt.Errorf("shellcode 超过 1MB")
			}
			return b, nil
		}
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) > 0 {
		if len(b) > winInjectMaxShellcode {
			return nil, fmt.Errorf("shellcode 超过 1MB")
		}
		return b, nil
	}
	return nil, fmt.Errorf("shellcode 需为 Base64 或 hex")
}

func isHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func winInjectResult(p *winInjectParams, processPath string, sc []byte, status string) map[string]any {
	res := map[string]any{
		"status": status, "pid": p.PID, "process_name": p.ProcessName,
		"process_path": processPath, "method": p.Method, "injected_bytes": len(sc),
	}
	if status == "dry_run" {
		res["note"] = "仅校验；未调用 OpenProcess/VirtualAllocEx/WriteProcessMemory/CreateRemoteThread"
	}
	return res
}
