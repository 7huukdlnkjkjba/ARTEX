package msfrt

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

// Start launches msfrpcd from the unpacked runtime.
//
// It runs `ruby msfrpcd` directly (never through cmd.exe / the .bat wrapper), so
// a password containing shell metacharacters is passed verbatim and failures are
// visible in the log instead of being swallowed by the batch layer. `-f` keeps
// the daemon in the foreground: the process we start is the process we stop.
//
// The returned *os.File is the daemon's log; it must stay open while the daemon
// runs (close it in the stop path, not here).
func (s Spec) Start(host string, port int, user, password, logPath string) (*exec.Cmd, *os.File, error) {
	if user == "" {
		user = "msf"
	}
	args := append(append([]string{}, s.Args...),
		"-U", user,
		"-P", password,
		"-p", strconv.Itoa(port),
		"-S", // plaintext: only ever bound to loopback here
		"-n", // no database
		"-f", // foreground: do not try to fork on Windows
		"-a", host,
	)
	cmd := exec.Command(s.Cmd, args...)
	cmd.Dir = s.Dir
	cmd.Env = s.Env
	cmd.Stdin = nil
	if logPath == "" {
		logPath = filepath.Join(s.Dir, "msfrpcd.log")
	}
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return nil, nil, fmt.Errorf("创建日志目录失败：%w", err)
	}
	f, err := os.Create(logPath)
	if err != nil {
		return nil, nil, fmt.Errorf("创建 msfrpcd 日志失败：%w", err)
	}
	cmd.Stdout, cmd.Stderr = f, f
	if err := cmd.Start(); err != nil {
		_ = f.Close()
		return nil, nil, fmt.Errorf("启动内置 msfrpcd 失败（%s）：%w", s.Cmd, err)
	}
	return cmd, f, nil
}
