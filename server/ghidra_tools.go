package server

// ghidra_decompile：用内置 Ghidra（开源，替代 IDA）做无头反编译，供 vuln_miner
// 在二进制目标上做危险函数 / Source→Sink 分析。
//
// 为什么不走 IDA：IDA 是闭源商业软件，无法随项目分发；Ghidra 是 Apache-2.0，
// 解压即用，headless 分析器（support/analyzeHeadless）可以在无 GUI 的 worker 里跑。
//
// 集成约定：
//   - Ghidra 根目录按 ARTEX_GHIDRA_HOME → <exe目录>/ghidra → <cwd>/ghidra →
//     本机内置路径 → PATH(analyzeHeadless) 的顺序查找；目录内必须有 support/analyzeHeadless[.bat]。
//   - Ghidra 12.x 需要 JDK 21+：按 ARTEX_GHIDRA_JAVA_HOME → JAVA_HOME → 常见安装目录
//     逐个真实探测 `java -version`，只接受 major ≥ 21 的 JDK；找不到就返回 java_missing，
//     不猜、不静默降级。
//   - 每次分析用独立临时 project，跑完 -deleteProject + 删临时目录；产物只读回内存。
//   - 找不到工具时返回 status=tool_missing，绝不返回占位伪代码。

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

const (
	ghidraMaxBinaryBytes = 512 << 20 // 512MB
	ghidraMaxOutputBytes = 512 << 10 // 回传伪代码上限 512KB
	ghidraMaxFunctions   = 20
	ghidraDefaultTimeout = 900 // 秒，15 分钟
	ghidraMaxTimeout     = 1800
	ghidraMinJavaMajor   = 21
)

// ghidraMinJavaMajor 校验用：Ghidra 12.x 要求 JDK 21+。
var ghidraJavaVersionRe = regexp.MustCompile(`version "(\d+)`)

// ghidraDecompileScript 是 headless -postScript 用的 GhidraScript（Java）。
// 参数通过环境变量传入（避免 cmd/bat 的引号转义问题）：
//
//	ARTEX_GHIDRA_OUT  输出文件
//	ARTEX_GHIDRA_FUNC 可选，只反编译该函数名
//	ARTEX_GHIDRA_MAX  可选，不指定函数时最多输出几个
const ghidraDecompileScript = `import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;

public class ArtexDecompile extends GhidraScript {
    @Override
    public void run() throws Exception {
        String outPath = System.getenv("ARTEX_GHIDRA_OUT");
        String want = System.getenv("ARTEX_GHIDRA_FUNC");
        String lim = System.getenv("ARTEX_GHIDRA_MAX");
        int limit = 5;
        try { if (lim != null && !lim.isEmpty()) limit = Integer.parseInt(lim); } catch (Exception e) { }
        if (outPath == null || outPath.isEmpty()) { println("ARTEX_GHIDRA_OUT not set"); return; }
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        FunctionManager fm = currentProgram.getFunctionManager();
        StringBuilder sb = new StringBuilder();
        int n = 0;
        for (Function f : fm.getFunctions(true)) {
            if (want != null && !want.isEmpty() && !f.getName().equals(want)) continue;
            DecompileResults res = di.decompileFunction(f, 60, monitor);
            if (res == null || !res.decompileCompleted()) continue;
            sb.append("// ").append(f.getName()).append(" @ ").append(f.getEntryPoint()).append("\n");
            sb.append(res.getDecompiledFunction().getC()).append("\n\n");
            n++;
            if ((want == null || want.isEmpty()) && n >= limit) break;
        }
        try (Writer w = new OutputStreamWriter(new FileOutputStream(outPath), "UTF-8")) { w.write(sb.toString()); }
        di.dispose();
        println("ARTEX_DECOMPILE_OK functions=" + n);
    }
}
`

func (s *Server) toolGhidraDecompile() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "ghidra_decompile",
		Description: "【逆向核心·二进制】用内置 Ghidra 无头分析器（support/analyzeHeadless）把二进制反编译成伪代码，" +
			"供 vuln_miner 做危险函数 / Source→Sink 分析；支持指定函数名或最多 N 个函数。" +
			"Ghidra 或 JDK 21+ 不可用时返回 status=tool_missing / java_missing（不返回占位伪代码）。只读：不运行样本。",
		Schema: objSchema(map[string]any{
			"binary_path":   strParam("本地二进制文件绝对路径（PE/ELF/Mach-O/固件均可）"),
			"function":      strParam("可选：只反编译指定函数名"),
			"max_functions": map[string]any{"type": "integer", "description": fmt.Sprintf("不指定 function 时最多输出函数数，默认 5，上限 %d", ghidraMaxFunctions)},
			"timeout_sec":   map[string]any{"type": "integer", "description": fmt.Sprintf("分析超时秒数，默认 %d，上限 %d", ghidraDefaultTimeout, ghidraMaxTimeout)},
		}, "binary_path"),
		ReadOnly:    func(json.RawMessage) bool { return true },
		Permissions: sessionPerm,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct {
				BinaryPath   string `json:"binary_path"`
				Function     string `json:"function"`
				MaxFunctions int    `json:"max_functions"`
				TimeoutSec   int    `json:"timeout_sec"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			a.BinaryPath = strings.TrimSpace(a.BinaryPath)
			if a.BinaryPath == "" {
				return actool.Errorf("binary_path 不能为空"), nil
			}
			st, err := os.Stat(a.BinaryPath)
			if err != nil {
				return actool.Errorf("二进制不存在: " + err.Error()), nil
			}
			if st.IsDir() {
				return actool.Errorf(fmt.Sprintf("%s 是目录，不是二进制文件", a.BinaryPath)), nil
			}
			if st.Size() > ghidraMaxBinaryBytes {
				return actool.Errorf(fmt.Sprintf("二进制过大（%d 字节，上限 %d）", st.Size(), ghidraMaxBinaryBytes)), nil
			}

			home := findGhidraHome()
			if home == "" {
				return jsonResult(map[string]any{
					"status": "tool_missing", "binary": a.BinaryPath,
					"hint": "未找到 Ghidra。把 Ghidra 解压到 ARTEX 目录下的 ghidra/（需含 support/analyzeHeadless[.bat]），" +
						"或设置 ARTEX_GHIDRA_HOME 指向 Ghidra 根目录；不要伪造伪代码。",
				})
			}
			javaHome := ghidraJavaHome()
			if javaHome == "" {
				return jsonResult(map[string]any{
					"status": "java_missing", "binary": a.BinaryPath, "ghidra_home": home,
					"hint": fmt.Sprintf("Ghidra 需要 JDK %d+，未找到可用 JDK：设置 ARTEX_GHIDRA_JAVA_HOME 或安装 JDK %d+。", ghidraMinJavaMajor, ghidraMinJavaMajor),
				})
			}

			limit := a.MaxFunctions
			if limit <= 0 {
				limit = 5
			}
			if limit > ghidraMaxFunctions {
				limit = ghidraMaxFunctions
			}
			timeout := time.Duration(a.TimeoutSec) * time.Second
			if timeout <= 0 {
				timeout = ghidraDefaultTimeout * time.Second
			}
			if timeout > ghidraMaxTimeout*time.Second {
				timeout = ghidraMaxTimeout * time.Second
			}

			start := time.Now()
			text, n, err := runGhidraDecompile(ctx, home, javaHome, a.BinaryPath, strings.TrimSpace(a.Function), limit, timeout)
			res := map[string]any{
				"status": "success", "tool": "ghidra", "binary": a.BinaryPath,
				"ghidra_home": home, "java_home": javaHome,
				"elapsed_ms": time.Since(start).Milliseconds(),
			}
			if err != nil {
				res["status"] = "failed"
				res["error"] = err.Error()
			}
			if strings.TrimSpace(text) == "" {
				if res["status"] == "success" {
					res["status"] = "empty"
				}
				res["hint"] = "Ghidra 没有输出伪代码：确认二进制架构受支持、函数名是否正确；必要时先只给 binary_path 跑默认前 5 个函数"
			} else {
				if len(text) > ghidraMaxOutputBytes {
					text = text[:ghidraMaxOutputBytes] + "\n...[伪代码截断]"
				}
				res["pseudocode"] = text
				res["functions"] = n
			}
			return jsonResult(res)
		},
	})
}

// ghidraHeadlessPath 校验一个候选根目录并返回 analyzeHeadless 路径。
func ghidraHeadlessPath(home string) string {
	home = strings.TrimSpace(home)
	if home == "" {
		return ""
	}
	names := []string{"analyzeHeadless", "analyzeHeadless.bat"}
	if runtime.GOOS == "windows" {
		names = []string{"analyzeHeadless.bat", "analyzeHeadless"}
	}
	// 允许直接指向 support/ 或脚本本身
	if st, err := os.Stat(home); err == nil && !st.IsDir() {
		base := strings.ToLower(filepath.Base(home))
		if strings.HasPrefix(base, "analyzeheadless") {
			return home
		}
	}
	for _, n := range names {
		p := filepath.Join(home, "support", n)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// findGhidraHome 返回可用的 Ghidra 根目录；空字符串=没有。
func findGhidraHome() string {
	var cands []string
	if v := strings.TrimSpace(os.Getenv("ARTEX_GHIDRA_HOME")); v != "" {
		cands = append(cands, v)
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		cands = append(cands, filepath.Join(dir, "ghidra"), filepath.Join(dir, "tools", "ghidra"))
	}
	if wd, err := os.Getwd(); err == nil {
		cands = append(cands, filepath.Join(wd, "ghidra"), filepath.Join(wd, "tools", "ghidra"))
	}
	cands = append(cands,
		`C:\ghidra`, `C:\tools\ghidra`,
		"/opt/ghidra", "/usr/share/ghidra", "/usr/local/ghidra",
	)
	for _, c := range cands {
		if ghidraHeadlessPath(c) != "" {
			return c
		}
	}
	// PATH 里的 analyzeHeadless：<home>/support/analyzeHeadless
	if p, err := exec.LookPath("analyzeHeadless"); err == nil {
		return filepath.Dir(filepath.Dir(p))
	}
	if p, err := exec.LookPath("analyzeHeadless.bat"); err == nil {
		return filepath.Dir(filepath.Dir(p))
	}
	return ""
}

var (
	ghidraJavaOnce   sync.Once
	ghidraJavaCached string
)

// ghidraJavaHome 选一个 major ≥ 21 的 JDK（结果缓存；探测只发生一次）。
func ghidraJavaHome() string {
	ghidraJavaOnce.Do(func() { ghidraJavaCached = detectGhidraJava() })
	return ghidraJavaCached
}

func detectGhidraJava() string {
	var cands []string
	for _, env := range []string{"ARTEX_GHIDRA_JAVA_HOME", "JAVA_HOME"} {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			cands = append(cands, v)
		}
	}
	if runtime.GOOS == "windows" {
		for _, root := range []string{
			`C:\Program Files\Java`,
			`C:\Program Files\Eclipse Adoptium`,
			`C:\Program Files\Microsoft`,
			`C:\Program Files\Zulu`,
		} {
			matches, _ := filepath.Glob(filepath.Join(root, "jdk*"))
			sort.Sort(sort.Reverse(sort.StringSlice(matches))) // 新版优先（jdk-25 > jdk-21）
			cands = append(cands, matches...)
		}
	} else {
		matches, _ := filepath.Glob("/usr/lib/jvm/*")
		sort.Sort(sort.Reverse(sort.StringSlice(matches)))
		cands = append(cands, matches...)
	}
	seen := map[string]bool{}
	for _, c := range cands {
		c = strings.TrimSpace(c)
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		if ghidraJavaMajor(c) >= ghidraMinJavaMajor {
			return c
		}
	}
	return ""
}

// ghidraJavaMajor 真实执行 <home>/bin/java -version 并解析 major；失败返回 0。
func ghidraJavaMajor(home string) int {
	bin := filepath.Join(home, "bin", "java")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if st, err := os.Stat(bin); err != nil || st.IsDir() {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// java -version 把版本写到 stderr，stdout 为空；合并输出再匹配。
	out, _ := exec.CommandContext(ctx, bin, "-version").CombinedOutput()
	return parseJavaMajor(out)
}

// parseJavaMajor 从 `java -version` 输出里取 major（1.8 视为 1）；解析失败返回 0。
func parseJavaMajor(out []byte) int {
	m := ghidraJavaVersionRe.FindSubmatch(out)
	if len(m) < 2 {
		return 0
	}
	n, _ := strconv.Atoi(string(m[1]))
	return n
}

// runGhidraDecompile 跑一次 headless 分析：独立临时 project + 脚本目录，产物只回内存。
func runGhidraDecompile(ctx context.Context, home, javaHome, binary, function string, limit int, timeout time.Duration) (string, int, error) {
	headless := ghidraHeadlessPath(home)
	if headless == "" {
		return "", 0, fmt.Errorf("Ghidra 目录无效（缺少 support/analyzeHeadless）: %s", home)
	}
	dir, err := os.MkdirTemp("", "artex-ghidra-*")
	if err != nil {
		return "", 0, fmt.Errorf("创建临时目录失败: %v", err)
	}
	defer os.RemoveAll(dir)
	projDir := filepath.Join(dir, "proj")
	scriptDir := filepath.Join(dir, "scripts")
	if err := os.MkdirAll(projDir, 0o755); err != nil {
		return "", 0, fmt.Errorf("创建 project 目录失败: %v", err)
	}
	if err := os.MkdirAll(scriptDir, 0o755); err != nil {
		return "", 0, fmt.Errorf("创建脚本目录失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(scriptDir, "ArtexDecompile.java"), []byte(ghidraDecompileScript), 0o644); err != nil {
		return "", 0, fmt.Errorf("写 GhidraScript 失败: %v", err)
	}
	outPath := filepath.Join(dir, "pseudocode.c")

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// 分析阶段单独设上限：大二进制（带符号的 Go/Rust 产物）光 auto-analysis 就能跑十几分钟，
	// 不设限会吃掉整个 worker 预算。分析被截断后仍会进入 postScript，能拿到部分伪代码。
	analysisSec := int(timeout.Seconds()) - 30
	if analysisSec > 600 {
		analysisSec = 600
	}
	if analysisSec < 60 {
		analysisSec = 60
	}
	args := []string{
		projDir, "ARTEX",
		"-import", binary,
		"-analysisTimeoutPerFile", strconv.Itoa(analysisSec),
		"-scriptPath", scriptDir,
		"-postScript", "ArtexDecompile.java",
		"-deleteProject",
	}
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// .bat 必须经 cmd 执行；Go 负责给含空格的参数加引号。
		cmd = exec.CommandContext(runCtx, "cmd", append([]string{"/c", headless}, args...)...)
	} else {
		cmd = exec.CommandContext(runCtx, headless, args...)
	}
	env := withEnv(os.Environ(), "JAVA_HOME", javaHome)
	env = withEnv(env, "ARTEX_GHIDRA_OUT", outPath)
	env = withEnv(env, "ARTEX_GHIDRA_FUNC", function)
	env = withEnv(env, "ARTEX_GHIDRA_MAX", strconv.Itoa(limit))
	if strings.TrimSpace(os.Getenv("GHIDRA_HEADLESS_MAXMEM")) == "" {
		env = withEnv(env, "GHIDRA_HEADLESS_MAXMEM", "2G")
	}
	cmd.Env = env

	raw, runErr := cmd.CombinedOutput()
	text := ""
	if b, err := os.ReadFile(outPath); err == nil {
		text = string(b)
	}
	if runCtx.Err() == context.DeadlineExceeded {
		return text, 0, fmt.Errorf("Ghidra 分析超时(%s)：可先用 max_functions 限制范围，或对更小的切片分析", timeout)
	}
	if runErr != nil {
		return text, 0, fmt.Errorf("Ghidra 无头分析失败: %v %s", runErr, ghidraOutputTail(string(raw), 1500))
	}
	return text, countDecompiledFuncs(text), nil
}

// countDecompiledFuncs 数伪代码里 "// name @ addr" 的函数头数量。
func countDecompiledFuncs(text string) int {
	n := 0
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "// ") && strings.Contains(line, " @ ") {
			n++
		}
	}
	return n
}

// withEnv 覆盖式设置环境变量（同名旧值先删掉，避免重复键）。
func withEnv(env []string, key, val string) []string {
	prefix := key + "="
	out := env[:0]
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			continue
		}
		out = append(out, e)
	}
	return append(out, prefix+val)
}

func ghidraOutputTail(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) > max {
		s = s[len(s)-max:]
	}
	return s
}
