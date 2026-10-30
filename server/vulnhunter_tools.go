package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// vulnhuntWorkDir is the per-run workspace: <dataDir>/tasks/<taskID>/vulnhunt/<runID>.
func (s *Server) vulnhuntWorkDir(taskID, runID int64) string {
	return filepath.Join(s.m.dir, "tasks", strconv.FormatInt(taskID, 10), "vulnhunt", strconv.FormatInt(runID, 10))
}

func (s *Server) currentVulnHunt(ctx context.Context) (*db.VulnHuntRun, error) {
	ri := agent.RunInfoFrom(ctx)
	if ri.TaskID <= 0 {
		return nil, fmt.Errorf("需要任务上下文")
	}
	r, err := db.NewVulnHuntStore(s.m.pg).LatestRunForIntent(ctx, ri.TaskID, ri.IntentID)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("当前意图还没有 vulnhunt run（先 vulnhunt_init）")
	}
	return r, nil
}

func (s *Server) vulnhuntTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolVHInit(), s.toolVHWriteHarness(), s.toolVHBuild(),
		s.toolVHFuzz(), s.toolVHTriage(), s.toolVHReport(),
	}
}

func (s *Server) toolVHInit() actool.CoreTool {
	return wrTool("vulnhunt_init",
		"初始化一次漏洞挖掘 run：target_spec 形如 repo:URL@commit / binary:/path / api:URL；fuzzer 形如 libfuzzer / aflpp / http_fuzz。系统会建工作目录并克隆/拷贝目标。一个意图只 init 一次。",
		objSchema(map[string]any{
			"target_spec":  strParam("repo:https://...@<commit> | binary:/path | api:https://..."),
			"fuzzer":       strParam("libfuzzer | aflpp | http_fuzz"),
			"duration_sec": map[string]any{"type": "integer", "description": "fuzz 时长，默认 300，上限 1800"},
		}, "target_spec", "fuzzer"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TargetSpec  string `json:"target_spec"`
				Fuzzer      string `json:"fuzzer"`
				DurationSec int    `json:"duration_sec"`
			}
			_ = json.Unmarshal(in, &a)
			ri := agent.RunInfoFrom(ctx)
			if ri.TaskID <= 0 || ri.IntentID <= 0 {
				return actool.Errorf("vulnhunt_init 需要任务/意图上下文"), nil
			}
			if !strings.Contains(a.TargetSpec, ":") {
				return actool.Errorf("target_spec 必须含 scheme:（repo:/binary:/api:）"), nil
			}
			fuzzer := strings.ToLower(strings.TrimSpace(a.Fuzzer))
			switch fuzzer {
			case "libfuzzer", "aflpp", "http_fuzz":
			default:
				return actool.Errorf("fuzzer 必须是 libfuzzer / aflpp / http_fuzz"), nil
			}
			if a.DurationSec <= 0 {
				a.DurationSec = 300
			}
			if a.DurationSec > 1800 {
				a.DurationSec = 1800
			}
			store := db.NewVulnHuntStore(s.m.pg)
			if err := store.EnsureSchema(ctx); err != nil {
				return actool.Errorf("vulnhunt 表初始化失败: " + err.Error()), nil
			}
			// Insert first (workspace embeds the run id), then bind the real path.
			placeholder := filepath.Join(s.m.dir, "tasks", strconv.FormatInt(ri.TaskID, 10), "vulnhunt",
				"pending-"+strconv.FormatInt(time.Now().UnixNano(), 10))
			intentID := ri.IntentID
			runID, err := store.CreateRun(ctx, &db.VulnHuntRun{
				TaskID: ri.TaskID, IntentID: &intentID, TargetSpec: strings.TrimSpace(a.TargetSpec),
				Fuzzer: fuzzer, Workspace: placeholder, Status: db.VHRunClone, DurationSec: a.DurationSec,
			})
			if err != nil {
				return actool.Errorf("创建 run 失败: " + err.Error()), nil
			}
			ws := s.vulnhuntWorkDir(ri.TaskID, runID)
			if err := store.SetWorkspace(ctx, runID, ws); err != nil {
				return actool.Errorf("绑定 workspace 失败: " + err.Error()), nil
			}
			for _, sub := range []string{"src", "build", "crashes", "corpus", "logs"} {
				if err := os.MkdirAll(filepath.Join(ws, sub), 0o755); err != nil {
					return actool.Errorf("建目录失败: " + err.Error()), nil
				}
			}
			if err := s.vulnhuntPrepare(ctx, ws, strings.TrimSpace(a.TargetSpec)); err != nil {
				_ = store.SetRunStatus(ctx, runID, db.VHRunFailed, err.Error(), 0, 0)
				return actool.Errorf("准备目标失败: " + err.Error()), nil
			}
			_ = store.SetRunStatus(ctx, runID, db.VHRunBuilding, "", 0, 0)
			return jsonResult(map[string]any{"run_id": runID, "workspace": ws, "fuzzer": fuzzer})
		})
}

func (s *Server) vulnhuntPrepare(ctx context.Context, ws, spec string) error {
	switch {
	case strings.HasPrefix(spec, "repo:"):
		rest := strings.TrimPrefix(spec, "repo:")
		url, commit := rest, ""
		if i := strings.LastIndex(rest, "@"); i > 0 {
			url, commit = rest[:i], rest[i+1:]
		}
		dst := filepath.Join(ws, "src")
		if _, err := os.Stat(filepath.Join(dst, ".git")); err == nil {
			return fmt.Errorf("src 已存在")
		}
		cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", url, dst)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("git clone: %v: %s", err, truncateOutput(string(out)))
		}
		if commit != "" {
			cmd = exec.CommandContext(ctx, "git", "-C", dst, "fetch", "--depth", "1", "origin", commit)
			if out, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("git fetch %s: %v: %s", commit, err, truncateOutput(string(out)))
			}
			cmd = exec.CommandContext(ctx, "git", "-C", dst, "checkout", commit)
			if out, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("git checkout %s: %v: %s", commit, err, truncateOutput(string(out)))
			}
		}
	case strings.HasPrefix(spec, "binary:"):
		p := strings.TrimPrefix(spec, "binary:")
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		dst := filepath.Join(ws, "src", filepath.Base(p))
		if err := os.WriteFile(dst, data, 0o755); err != nil {
			return err
		}
	case strings.HasPrefix(spec, "api:"):
		// http_fuzz: no copy; write the target URL for the harness to read.
		return os.WriteFile(filepath.Join(ws, "src", "TARGET_URL"), []byte(strings.TrimPrefix(spec, "api:")), 0o644)
	default:
		return fmt.Errorf("unknown target_spec scheme: %s", spec)
	}
	return nil
}

func (s *Server) toolVHWriteHarness() actool.CoreTool {
	return wrTool("vulnhunt_write_harness",
		"写 harness 源码（libFuzzer: LLVMFuzzerTestOneInput；AFL++: __AFL_FUZZ_TESTCASE_BUF）。写到 run 工作区的 build/harness.c。",
		objSchema(map[string]any{"code": strParam("完整 harness 源码")}, "code"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Code string `json:"code"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Code) == "" {
				return actool.Errorf("code 不能为空"), nil
			}
			r, err := s.currentVulnHunt(ctx)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			path := filepath.Join(r.Workspace, "build", "harness.c")
			if err := os.WriteFile(path, []byte(a.Code), 0o644); err != nil {
				return actool.Errorf("写 harness 失败: " + err.Error()), nil
			}
			return jsonResult(map[string]any{"run_id": r.ID, "path": path, "bytes": len(a.Code)})
		})
}

func (s *Server) toolVHBuild() actool.CoreTool {
	return wrTool("vulnhunt_build",
		"跑构建：默认 clang -fsanitize=address,fuzzer -g -O1 build/harness.c src/*.c -o build/fuzz（libfuzzer）/ afl-clang-fast（aflpp）。返回退出码、stdout、stderr。",
		objSchema(map[string]any{
			"build_cmd": strParam("可选：自定义构建命令（在 workspace 下执行）"),
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				BuildCmd string `json:"build_cmd"`
			}
			_ = json.Unmarshal(in, &a)
			r, err := s.currentVulnHunt(ctx)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			cmdStr := strings.TrimSpace(a.BuildCmd)
			if cmdStr == "" {
				cmdStr = s.defaultVHBuild(r)
			}
			runCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
			defer cancel()
			cmd := exec.CommandContext(runCtx, "bash", "-c", cmdStr)
			cmd.Dir = r.Workspace
			var stdout, stderr strings.Builder
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			runErr := cmd.Run()
			exitCode := 0
			if runErr != nil {
				var ee *exec.ExitError
				if errors.As(runErr, &ee) {
					exitCode = ee.ExitCode()
				} else {
					exitCode = -1
				}
			}
			store := db.NewVulnHuntStore(s.m.pg)
			if exitCode != 0 {
				_ = store.SetRunStatus(ctx, r.ID, db.VHRunFailed, truncateOutput(stderr.String()), 0, 0)
			} else {
				_ = store.SetRunStatus(ctx, r.ID, db.VHRunFuzzing, "", 0, 0)
			}
			return jsonResult(map[string]any{
				"run_id": r.ID, "exit_code": exitCode,
				"stdout": truncateOutput(stdout.String()), "stderr": truncateOutput(stderr.String()),
			})
		})
}

func (s *Server) defaultVHBuild(r *db.VulnHuntRun) string {
	switch r.Fuzzer {
	case "libfuzzer":
		return "clang -fsanitize=address,fuzzer -g -O1 build/harness.c $(find src -maxdepth 2 -type f \\( -name '*.c' -o -name '*.cc' -o -name '*.cpp' \\) | tr '\\n' ' ') -o build/fuzz"
	case "aflpp":
		return "AFL_USE_ASAN=1 afl-clang-fast -g -O1 build/harness.c $(find src -maxdepth 2 -type f \\( -name '*.c' -o -name '*.cc' -o -name '*.cpp' \\) | tr '\\n' ' ') -o build/fuzz"
	case "http_fuzz":
		return "echo 'http_fuzz: harness runs in Python, skip C build'"
	default:
		return "echo 'unknown fuzzer'"
	}
}

func (s *Server) toolVHFuzz() actool.CoreTool {
	return wrTool("vulnhunt_fuzz",
		"跑 fuzzer。libFuzzer: build/fuzz -max_total_time=<sec> -artifact_prefix=crashes/ corpus/；AFL++: timeout <sec> afl-fuzz -i corpus -o crashes -- build/fuzz @@。返回 crash 文件列表。",
		objSchema(map[string]any{
			"duration_sec": map[string]any{"type": "integer", "description": "默认 300，上限 1800"},
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				DurationSec int `json:"duration_sec"`
			}
			_ = json.Unmarshal(in, &a)
			if a.DurationSec <= 0 {
				a.DurationSec = 300
			}
			if a.DurationSec > 1800 {
				a.DurationSec = 1800
			}
			r, err := s.currentVulnHunt(ctx)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if r.Fuzzer == "http_fuzz" {
				return actool.Errorf("http_fuzz 暂不支持自动运行：请用 Bash 跑工作区里的 Python harness，并把崩溃/异常样本放进 crashes/"), nil
			}
			bin := filepath.Join(r.Workspace, "build", "fuzz")
			if _, err := os.Stat(bin); err != nil {
				return actool.Errorf("build/fuzz 不存在，先 vulnhunt_build"), nil
			}
			_ = os.MkdirAll(filepath.Join(r.Workspace, "crashes"), 0o755)
			runCtx, cancel := context.WithTimeout(ctx, time.Duration(a.DurationSec+90)*time.Second)
			defer cancel()
			var script string
			if r.Fuzzer == "libfuzzer" {
				script = fmt.Sprintf("build/fuzz -max_total_time=%d -artifact_prefix=crashes/ corpus/ 2>&1 | tail -200", a.DurationSec)
			} else {
				script = fmt.Sprintf("timeout %d afl-fuzz -i corpus -o crashes -V %d -- build/fuzz @@ 2>&1 | tail -200", a.DurationSec, a.DurationSec)
			}
			cmd := exec.CommandContext(runCtx, "bash", "-c", script)
			cmd.Dir = r.Workspace
			var stdout, stderr strings.Builder
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			_ = cmd.Run()
			crashes := s.listCrashFiles(r.Workspace)
			store := db.NewVulnHuntStore(s.m.pg)
			_ = store.SetRunStatus(ctx, r.ID, db.VHRunTriaging, "", len(crashes), 0)
			return jsonResult(map[string]any{
				"run_id": r.ID, "duration_sec": a.DurationSec, "crash_count": len(crashes),
				"crashes": crashes,
				"stdout":  truncateOutput(stdout.String()), "stderr": truncateOutput(stderr.String()),
			})
		})
}

func (s *Server) listCrashFiles(ws string) []string {
	var out []string
	dirs := []string{filepath.Join(ws, "crashes"), filepath.Join(ws, "build", "crashes")}
	for _, dir := range dirs {
		_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			name := d.Name()
			if name == "README.txt" || strings.HasPrefix(name, "min-") || !isCrashArtifact(name) {
				return nil
			}
			// libFuzzer writes artifacts directly under crashes/; AFL++ writes them
			// under crashes/<instance>/crashes/. The queue under .../queue/ is NOT a
			// crash set, so require the parent directory to literally be "crashes".
			if filepath.Base(filepath.Dir(path)) == "crashes" {
				out = append(out, path)
			}
			return nil
		})
	}
	return out
}

// isCrashArtifact matches libFuzzer (crash-/leak-/timeout-/oom-) and AFL++
// (id:...) crash file names.
func isCrashArtifact(name string) bool {
	for _, p := range []string{"crash", "leak", "timeout", "oom", "id:"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

var (
	vhKindRe  = regexp.MustCompile(`(AddressSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|LeakSanitizer):\s*([A-Za-z0-9_-]+)`)
	vhFrameRe = regexp.MustCompile(`(?m)^\s+#(\d+)\s+0x[0-9a-f]+\s+in\s+(\S+)`)
)

func (s *Server) toolVHTriage() actool.CoreTool {
	return wrTool("vulnhunt_triage",
		"复跑一个 crash，解析 sanitizer 输出，计算 signature（class + 栈顶 3 帧），最小化（有 afl-tmin 就用，没有则保留原 PoC），去重（同 signature 只留一条）。返回 crash_id / signature / kind / duplicate_of / minimized_path。",
		objSchema(map[string]any{"crash_path": strParam("crash 文件路径（绝对或相对 workspace）")}, "crash_path"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				CrashPath string `json:"crash_path"`
			}
			_ = json.Unmarshal(in, &a)
			r, err := s.currentVulnHunt(ctx)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			crashPath := strings.TrimSpace(a.CrashPath)
			if crashPath == "" {
				return actool.Errorf("crash_path 必填"), nil
			}
			if !filepath.IsAbs(crashPath) {
				crashPath = filepath.Join(r.Workspace, crashPath)
			}
			if _, err := os.Stat(crashPath); err != nil {
				return actool.Errorf("crash 文件不存在: " + crashPath), nil
			}
			stack, kind := s.runCrashForStack(ctx, r, crashPath)
			if stack == "" {
				return actool.Errorf("复跑 crash 没有产出 sanitizer 栈（路径错或构建已变）"), nil
			}
			sig := computeVHSignature(kind, stack)
			store := db.NewVulnHuntStore(s.m.pg)
			if existing, _ := store.SignatureExists(ctx, r.ID, sig); existing > 0 {
				// The unique (run_id, signature) index is the dedup source of truth:
				// do NOT insert a second row for the same signature.
				return jsonResult(map[string]any{
					"crash_id": existing, "signature": sig, "kind": kind, "duplicate_of": existing,
					"crash_path": crashPath,
				})
			}
			minimized := s.tryMinimize(ctx, r, crashPath)
			id, err := store.AddCrash(ctx, &db.VulnHuntCrash{
				RunID: r.ID, Signature: sig, Kind: kind, Stack: stack,
				PocPath: crashPath, MinimizedPath: minimized,
			})
			if err != nil {
				// Lost a race with a concurrent triage: return the winner.
				if existing, _ := store.SignatureExists(ctx, r.ID, sig); existing > 0 {
					return jsonResult(map[string]any{"crash_id": existing, "signature": sig, "kind": kind, "duplicate_of": existing})
				}
				return actool.Errorf("登记 crash 失败: " + err.Error()), nil
			}
			crashes, _ := store.ListCrashes(ctx, r.ID)
			unique := 0
			for _, c := range crashes {
				if c.DuplicateOf == nil {
					unique++
				}
			}
			_ = store.SetRunStatus(ctx, r.ID, db.VHRunTriaging, "", len(crashes), unique)
			return jsonResult(map[string]any{
				"crash_id": id, "signature": sig, "kind": kind, "minimized_path": minimized,
			})
		})
}

// runCrashForStack replays a crash and returns the sanitizer kind + top frames.
func (s *Server) runCrashForStack(ctx context.Context, r *db.VulnHuntRun, crashPath string) (stack, kind string) {
	runCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	var script string
	if r.Fuzzer == "aflpp" {
		script = "build/fuzz < " + shQuote(crashPath) + " 2>&1 | head -400"
	} else {
		script = "build/fuzz " + shQuote(crashPath) + " 2>&1 | head -400"
	}
	cmd := exec.CommandContext(runCtx, "bash", "-c", script)
	cmd.Dir = r.Workspace
	out, _ := cmd.CombinedOutput()
	text := string(out)
	if m := vhKindRe.FindStringSubmatch(text); m != nil {
		kind = m[1] + ":" + m[2]
	}
	var b strings.Builder
	frames := 0
	for _, m := range vhFrameRe.FindAllStringSubmatch(text, -1) {
		b.WriteString(m[0] + "\n")
		frames++
		if frames >= 3 {
			break
		}
	}
	return strings.TrimSpace(b.String()), kind
}

func computeVHSignature(kind, stack string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(kind) + "|" + strings.TrimSpace(stack)))
	return hex.EncodeToString(sum[:])[:16]
}

func (s *Server) tryMinimize(ctx context.Context, r *db.VulnHuntRun, crashPath string) string {
	if r.Fuzzer != "aflpp" {
		return ""
	}
	out := filepath.Join(r.Workspace, "crashes", "min-"+filepath.Base(crashPath))
	runCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "bash", "-c",
		"afl-tmin -i "+shQuote(crashPath)+" -o "+shQuote(out)+" -- build/fuzz @@ 2>/dev/null")
	cmd.Dir = r.Workspace
	if err := cmd.Run(); err == nil {
		if _, err := os.Stat(out); err == nil {
			return out
		}
	}
	return ""
}

func (s *Server) toolVHReport() actool.CoreTool {
	return wrTool("vulnhunt_report",
		"把一个唯一 crash 提升为 finding。evidence 必须含：复现命令、sanitizer 栈、最小 PoC、影响说明。",
		objSchema(map[string]any{
			"crash_path": strParam("crash 文件路径"),
			"title":      strParam("漏洞标题"),
			"evidence":   strParam("证据（复现命令 + 栈 + PoC + 影响）"),
			"severity":   strParam("critical | high | medium | low"),
		}, "crash_path", "title", "evidence"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				CrashPath string `json:"crash_path"`
				Title     string `json:"title"`
				Evidence  string `json:"evidence"`
				Severity  string `json:"severity"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Title) == "" || strings.TrimSpace(a.Evidence) == "" {
				return actool.Errorf("title / evidence 必填"), nil
			}
			r, err := s.currentVulnHunt(ctx)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			crashPath := strings.TrimSpace(a.CrashPath)
			if crashPath != "" && !filepath.IsAbs(crashPath) {
				crashPath = filepath.Join(r.Workspace, crashPath)
			}
			store := db.NewVulnHuntStore(s.m.pg)
			var target *db.VulnHuntCrash
			if crashPath != "" {
				target, _ = store.CrashByPath(ctx, r.ID, crashPath)
			}
			if target == nil {
				return actool.Errorf("该 crash_path 未在 triage 中登记（先 vulnhunt_triage）"), nil
			}
			if target.DuplicateOf != nil {
				return actool.Errorf(fmt.Sprintf("该 crash 是重复（duplicate_of=%d），不提升为 finding", *target.DuplicateOf)), nil
			}
			if target.FindingID != nil {
				return jsonResult(map[string]any{"finding_id": *target.FindingID, "crash_id": target.ID})
			}
			findingID, err := s.createVHFinding(ctx, r, a.Title, a.Evidence, a.Severity)
			if err != nil {
				return actool.Errorf("创建 finding 失败: " + err.Error()), nil
			}
			_ = store.AttachFinding(ctx, target.ID, findingID)
			crashes, _ := store.ListCrashes(ctx, r.ID)
			unique := 0
			for _, c := range crashes {
				if c.DuplicateOf == nil {
					unique++
				}
			}
			_ = store.SetRunStatus(ctx, r.ID, db.VHRunDone, "", len(crashes), unique)
			return jsonResult(map[string]any{"finding_id": findingID, "crash_id": target.ID})
		})
}

func (s *Server) createVHFinding(ctx context.Context, r *db.VulnHuntRun, title, evidence, severity string) (int64, error) {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "high", "medium", "low":
		severity = strings.ToLower(strings.TrimSpace(severity))
	default:
		severity = "high"
	}
	task, ok := s.m.Task(strconv.FormatInt(r.TaskID, 10))
	if !ok || task == nil || task.Store == nil {
		return 0, fmt.Errorf("task %d not found", r.TaskID)
	}
	recorded, err := task.Store.RecordFinding(ctx, db.RecordFindingInput{
		TaskID: r.TaskID, Worker: "vulnhunter",
		VulnClass: "fuzzing", Name: title, Severity: severity,
		Summary:  "VulnHunter 在 " + r.TargetSpec + " 发现崩溃",
		Evidence: evidence,
	})
	if err != nil {
		return 0, err
	}
	return recorded.FindingID, nil
}

// shQuote quotes a path for safe interpolation into a bash -c script.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
