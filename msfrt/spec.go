package msfrt

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Spec is everything needed to run msfrpcd from an unpacked runtime.
type Spec struct {
	Cmd  string   // embedded ruby
	Args []string // msfrpcd script path (options appended by the launcher)
	Env  []string // child environment (bundled ruby on PATH, GEM_* cleared)
	Dir  string   // working directory (the framework root)
}

// Spec builds the launch spec, verifying that the unpacked tree really contains
// a Ruby and the framework entry point.
func (r *Runtime) Spec() (Spec, error) {
	embedded := filepath.Join(r.Root, "embedded")
	binDir := filepath.Join(embedded, "bin")
	framework := filepath.Join(embedded, "framework")
	ruby := filepath.Join(binDir, "ruby.exe")
	if runtime.GOOS != "windows" {
		ruby = filepath.Join(binDir, "ruby")
	}
	script := filepath.Join(framework, "msfrpcd")
	for _, p := range []string{ruby, script} {
		if st, err := os.Stat(p); err != nil || st.IsDir() {
			return Spec{}, fmt.Errorf("内置运行时缺少 %s（解压不完整？删除 %s 后重试）", p, r.Root)
		}
	}
	return Spec{
		Cmd:  ruby,
		Args: []string{script},
		Env:  rubyEnv(binDir, framework),
		Dir:  framework,
	}, nil
}

// rubyEnv mirrors what bin\msfrpcd.bat does: bundled bin first on PATH, ambient
// Ruby/Gem variables cleared so the embedded install wins, and Gemfile pinned to
// the bundled framework.
func rubyEnv(binDir, framework string) []string {
	drop := map[string]bool{
		"GEM_HOME": true, "GEM_PATH": true, "GEM_ROOT": true,
		"RUBY_ENGINE": true, "RUBY_ROOT": true, "BUNDLE_GEMFILE": true,
	}
	env := make([]string, 0, len(os.Environ())+2)
	for _, kv := range os.Environ() {
		name := kv
		if i := strings.Index(kv, "="); i >= 0 {
			name = kv[:i]
		}
		if drop[strings.ToUpper(name)] || strings.EqualFold(name, "PATH") {
			continue
		}
		env = append(env, kv)
	}
	path := binDir
	if old := os.Getenv("PATH"); old != "" {
		path += string(os.PathListSeparator) + old
	}
	return append(env, "PATH="+path, "BUNDLE_GEMFILE="+filepath.Join(framework, "Gemfile"))
}
