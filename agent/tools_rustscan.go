package agent

// RustScan 侦察工具(按用户给的 worker 草案移植为 ARTEX AI 工具)。
//
// 边界(执行归代码,决策归 AI):
//   - 代码负责: 参数校验、scope、依赖发现、进程执行、输出解析、端口去重排序、
//     fact 回写、错误分类;
//   - 不负责: 根据端口猜服务、判断漏洞、决定下一步打哪个模块 —— 这些留给模型。
//     端口开放本身不是漏洞,所以只写 fact,不写 finding。
//
// 与草案的差异:
//   - 使用通用 t.assertInScope (支持 IP/FQDN/CIDR,并对 CIDR 两端做范围校验);
//   - 支持 ARTEX_RUSTSCAN_PATH / data/tools/rustscan 的二进制发现;
//   - 解析 RustScan 默认输出、greppable 输出与 Nmap 风格行,剥离 ANSI;
//   - 无开放端口时 fact 标 inferred(单次扫描不能当"端口全关"铁案);
//   - 支持 timeout_sec、CIDR 过大保护、dry_run 目标解析。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/config"
	actool "github.com/Autumn-27/norma/tool"
)

const (
	rustscanModuleID       = "scan.rustscan"
	rustscanMITRE          = "T1046"
	rustscanDefaultTimeout = 300 * time.Second
	rustscanMaxTimeout     = 900 * time.Second
	rustscanMaxOutput      = 8 << 20
	rustscanOutputTail     = 2000
	rustscanDefaultBatch   = 4500
	rustscanDefaultPortTMO = 1500
	rustscanDefaultULimit  = 5000
	rustscanMaxCIDRHosts   = 1 << 16 // /16 及更小;更大的范围必须显式 allow_large_range
)

var (
	errRustscanTimeout = errors.New("rustscan command timeout")

	rustscanPortsRe    = regexp.MustCompile(`^[0-9,\-]+$`)
	rustscanDomainRe   = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)
	rustscanScriptRe   = regexp.MustCompile(`^[A-Za-z0-9_.*, -]+$`)
	rustscanNmapLineRe = regexp.MustCompile(`(?i)^(\d{1,5})/(tcp|udp)\s+open(?:\s+(\S+))?`)
	rustscanANSIRe     = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)
)

// 测试可替换的执行钩子:让 handler 能在没有 rustscan 的机器上被验证。
var (
	rustscanFind = findRustscanBinary
	rustscanRun  = execRustscanCommand
)

// RustscanParams 是端口扫描的强类型参数。
type RustscanParams struct {
	Target          string `json:"target"`                      // IP、域名、CIDR，必填
	Ports           string `json:"ports,omitempty"`             // 端口范围，默认 1-65535
	BatchSize       int    `json:"batch_size,omitempty"`        // 并发批次，默认 4500
	TimeoutMs       int    `json:"timeout_ms,omitempty"`        // 单端口超时，默认 1500ms
	ULimit          int    `json:"ulimit,omitempty"`            // fd 上限，默认 5000
	Script          string `json:"script,omitempty"`            // 可选：扫描后跑的 Nmap 脚本
	ExcludePorts    string `json:"exclude_ports,omitempty"`     // 排除端口
	TimeoutSec      int    `json:"timeout_sec,omitempty"`       // 整次扫描超时，默认 300s
	AllowLargeRange bool   `json:"allow_large_range,omitempty"` // 允许 > /16 的 CIDR
	DryRun          bool   `json:"dry_run,omitempty"`           // 只校验目标/依赖，不扫描
}

// OpenPort 是一个开放端口。Service 只来自 Nmap 风格的输出行；RustScan 的
// "Open host:port" 不提供 service，服务判断留给模型。
type OpenPort struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // tcp / udp
	Service  string `json:"service,omitempty"`
}

type RustscanResult struct {
	ModuleID    string         `json:"module_id"`
	MITRE       string         `json:"mitre"`
	Status      string         `json:"status"` // success | failed | dry_run
	Target      string         `json:"target"`
	Ports       string         `json:"ports,omitempty"`
	ResolvedIPs []string       `json:"resolved_ips,omitempty"`
	OpenPorts   []OpenPort     `json:"open_ports"`
	PortCount   int            `json:"port_count"`
	Command     string         `json:"command,omitempty"`
	Tooling     map[string]any `json:"tooling,omitempty"`
	NextSteps   []string       `json:"next_steps,omitempty"`
	Warnings    []string       `json:"warnings,omitempty"`
	FactID      int64          `json:"fact_id,omitempty"`
	Error       string         `json:"error,omitempty"`
	OutputTail  string         `json:"output_tail,omitempty"`
	ElapsedMs   int64          `json:"elapsed_ms"`
}

// Validate normalizes target/ports defaults and rejects values that could be
// ambiguous for rustscan or turn into an unintended option.
func (p *RustscanParams) Validate() error {
	p.Target = strings.TrimSpace(p.Target)
	p.Ports = strings.TrimSpace(p.Ports)
	p.ExcludePorts = strings.TrimSpace(p.ExcludePorts)
	p.Script = strings.TrimSpace(p.Script)

	if p.Target == "" {
		return fmt.Errorf("target 必填：IP / 域名 / CIDR")
	}
	if err := p.normalizeTarget(); err != nil {
		return err
	}
	if p.Ports == "" {
		p.Ports = "1-65535"
	}
	if len(p.Ports) > 512 || !rustscanPortsRe.MatchString(p.Ports) {
		return fmt.Errorf("ports 格式非法：只接受数字、逗号和范围，如 1-65535 或 22,80,443")
	}
	if p.ExcludePorts != "" {
		if len(p.ExcludePorts) > 512 || !rustscanPortsRe.MatchString(p.ExcludePorts) {
			return fmt.Errorf("exclude_ports 格式非法：只接受数字、逗号和范围")
		}
	}
	if p.BatchSize <= 0 {
		p.BatchSize = rustscanDefaultBatch
	}
	if p.BatchSize > 65535 {
		return fmt.Errorf("batch_size 过大（1..65535）")
	}
	if p.TimeoutMs <= 0 {
		p.TimeoutMs = rustscanDefaultPortTMO
	}
	if p.TimeoutMs > 60000 {
		return fmt.Errorf("timeout_ms 过大（1..60000）")
	}
	if p.ULimit <= 0 {
		p.ULimit = rustscanDefaultULimit
	}
	if p.ULimit > 1000000 {
		return fmt.Errorf("ulimit 过大（1..1000000）")
	}
	if p.TimeoutSec <= 0 {
		p.TimeoutSec = int(rustscanDefaultTimeout / time.Second)
	}
	if p.TimeoutSec < 10 || p.TimeoutSec > int(rustscanMaxTimeout/time.Second) {
		return fmt.Errorf("timeout_sec 取值 10..%d", int(rustscanMaxTimeout/time.Second))
	}
	if p.Script != "" {
		if len(p.Script) > 256 || strings.HasPrefix(p.Script, "-") || !rustscanScriptRe.MatchString(p.Script) {
			return fmt.Errorf("script 格式非法：只接受 Nmap 脚本名（字母/数字/下划线/逗号/空格/星号/短横线），且不能以 - 开头")
		}
	}
	return nil
}

func (p *RustscanParams) normalizeTarget() error {
	t := strings.TrimSpace(p.Target)
	if strings.Contains(t, "://") {
		u, err := url.Parse(t)
		if err != nil || strings.TrimSpace(u.Hostname()) == "" {
			return fmt.Errorf("target URL 解析失败：%s", p.Target)
		}
		t = u.Hostname()
		if port := u.Port(); port != "" {
			p.addPort(port)
		}
	}
	if host, port, err := net.SplitHostPort(t); err == nil {
		t = strings.Trim(host, "[]")
		if port == "" {
			return fmt.Errorf("target 里的端口为空：host:port")
		}
		p.addPort(port)
	}
	t = strings.TrimSuffix(t, ".")
	if t == "" {
		return fmt.Errorf("target 为空")
	}
	if strings.ContainsAny(t, " \t\r\n;|&$`<>") {
		return fmt.Errorf("target 含非法字符：只填 IP / 域名 / CIDR")
	}
	if _, ipnet, err := net.ParseCIDR(t); err == nil {
		if n := cidrHostCount(ipnet); n > rustscanMaxCIDRHosts && !p.AllowLargeRange {
			return fmt.Errorf("CIDR %s 包含 %d 个地址，超过单次上限 %d；缩小范围，或显式 allow_large_range=true", t, n, rustscanMaxCIDRHosts)
		}
		p.Target = t
		return nil
	}
	if net.ParseIP(t) != nil {
		p.Target = t
		return nil
	}
	if !rustscanDomainRe.MatchString(t) || strings.Contains(t, "..") {
		return fmt.Errorf("target 格式非法：只填 IP / 域名 / CIDR（不要带路径或空格）")
	}
	p.Target = t
	return nil
}

func (p *RustscanParams) addPort(port string) {
	port = strings.TrimSpace(port)
	if port == "" {
		return
	}
	if p.Ports == "" {
		p.Ports = port
		return
	}
	p.Ports += "," + port
}

// findRustscanBinary resolves rustscan in this order:
// ARTEX_RUSTSCAN_PATH > PATH > <base>/data/tools/rustscan[.exe] > <base>/tools/rustscan[.exe].
func findRustscanBinary() (string, error) {
	if p := strings.TrimSpace(os.Getenv("ARTEX_RUSTSCAN_PATH")); p != "" {
		if err := rustscanExecutable(p); err != nil {
			return "", fmt.Errorf("ARTEX_RUSTSCAN_PATH=%s 不可用：%v", p, err)
		}
		return p, nil
	}
	if p, err := exec.LookPath("rustscan"); err == nil {
		return p, nil
	}
	base := config.BaseDir()
	for _, p := range []string{
		filepath.Join(base, "data", "tools", "rustscan"),
		filepath.Join(base, "data", "tools", "rustscan.exe"),
		filepath.Join(base, "tools", "rustscan"),
		filepath.Join(base, "tools", "rustscan.exe"),
	} {
		if rustscanExecutable(p) == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("依赖缺失：未找到 rustscan（PATH / data/tools/rustscan / ARTEX_RUSTSCAN_PATH）；安装：cargo install rustscan 或从 GitHub release 下载后放入 data/tools/")
}

func rustscanExecutable(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.IsDir() {
		return fmt.Errorf("是目录")
	}
	if runtime.GOOS != "windows" && st.Mode()&0o111 == 0 {
		return fmt.Errorf("没有执行权限")
	}
	return nil
}

func buildRustscanArgs(p *RustscanParams) []string {
	args := []string{
		"-a", p.Target,
		"-p", p.Ports,
		"-b", strconv.Itoa(p.BatchSize),
		"-t", strconv.Itoa(p.TimeoutMs),
		"--ulimit", strconv.Itoa(p.ULimit),
	}
	if p.ExcludePorts != "" {
		args = append(args, "--exclude-ports", p.ExcludePorts)
	}
	if p.Script != "" {
		args = append(args, "--scripts", p.Script)
	}
	return args
}

func execRustscanCommand(ctx context.Context, bin string, args []string, timeout time.Duration) (string, error) {
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, bin, args...)
	// Keep the stream clean for parsing; stripANSI is a second safety net.
	cmd.Env = append(os.Environ(), "NO_COLOR=1", "TERM=dumb")
	var stdout, stderr cappedBuffer
	stdout.max, stderr.max = rustscanMaxOutput, rustscanMaxOutput
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	text := stdout.String() + "\n" + stderr.String()
	if stdout.truncated || stderr.truncated {
		text += "\n...[输出已截断]"
	}
	if runErr != nil {
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			return text, errRustscanTimeout
		}
		return text, runErr
	}
	return text, nil
}

func stripANSI(s string) string { return rustscanANSIRe.ReplaceAllString(s, "") }

// parseRustscanOutput accepts RustScan's default "Open host:port", greppable
// "host -> [22,80]" and Nmap-style "22/tcp open ssh" lines. It dedups and sorts
// by port so the same scan is deterministic for the model and for tests.
func parseRustscanOutput(out string) []OpenPort {
	ports := []OpenPort{}
	seen := map[string]int{} // "proto/port" -> index in ports

	add := func(port int, proto, service string) {
		if port <= 0 || port > 65535 {
			return
		}
		proto = strings.ToLower(strings.TrimSpace(proto))
		if proto == "" {
			proto = "tcp"
		}
		key := proto + "/" + strconv.Itoa(port)
		if i, ok := seen[key]; ok {
			if ports[i].Service == "" && service != "" {
				ports[i].Service = service
			}
			return
		}
		seen[key] = len(ports)
		ports = append(ports, OpenPort{Port: port, Protocol: proto, Service: service})
	}

	for _, rawLine := range strings.Split(stripANSI(out), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "Open ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if i := strings.LastIndex(fields[1], ":"); i >= 0 {
					if port, err := strconv.Atoi(strings.TrimSpace(fields[1][i+1:])); err == nil {
						add(port, "tcp", "")
					}
				}
			}
			continue
		}
		if strings.Contains(line, "->") {
			parts := strings.SplitN(line, "->", 2)
			list := strings.TrimSpace(parts[1])
			list = strings.Trim(list, "[]")
			for _, item := range strings.Split(list, ",") {
				if port, err := strconv.Atoi(strings.TrimSpace(item)); err == nil {
					add(port, "tcp", "")
				}
			}
			continue
		}
		if m := rustscanNmapLineRe.FindStringSubmatch(line); m != nil {
			port, _ := strconv.Atoi(m[1])
			add(port, m[2], strings.TrimSpace(m[3]))
		}
	}
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].Port == ports[j].Port {
			return ports[i].Protocol < ports[j].Protocol
		}
		return ports[i].Port < ports[j].Port
	})
	return ports
}

func formatRustscanPorts(ports []OpenPort, limit int) string {
	if len(ports) == 0 {
		return "无"
	}
	if limit <= 0 || limit > len(ports) {
		limit = len(ports)
	}
	var b strings.Builder
	for i := 0; i < limit; i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		p := ports[i]
		fmt.Fprintf(&b, "%d/%s", p.Port, p.Protocol)
		if p.Service != "" {
			fmt.Fprintf(&b, "(%s)", p.Service)
		}
	}
	if limit < len(ports) {
		fmt.Fprintf(&b, " …(共 %d 个)", len(ports))
	}
	return b.String()
}

func resolveRustscanTargets(target string) ([]string, uint64, error) {
	if _, n, err := net.ParseCIDR(target); err == nil {
		first, last := cidrEndpoints(n)
		return []string{first.String(), last.String()}, cidrHostCount(n), nil
	}
	if ip := net.ParseIP(target); ip != nil {
		return []string{ip.String()}, 1, nil
	}
	addrs, err := net.LookupHost(target)
	if err != nil {
		return nil, 0, err
	}
	seen := map[string]bool{}
	out := []string{}
	for _, a := range addrs {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out, uint64(len(out)), nil
}

func rustscanErrorMessage(runErr error, out string, timeout time.Duration) string {
	low := strings.ToLower(out)
	if runErr != nil {
		low += "\n" + strings.ToLower(runErr.Error())
	}
	switch {
	case errors.Is(runErr, errRustscanTimeout):
		return fmt.Sprintf("RustScan 执行超时（%ds）：缩小 CIDR/端口范围，或提高 timeout_sec", int(timeout/time.Second))
	case strings.Contains(low, "permission denied") || strings.Contains(low, "operation not permitted"):
		return "RustScan 权限不足：检查二进制执行权限；ulimit 过高时降低 ulimit，或改用非受限运行方式"
	case strings.Contains(low, "could not resolve") || strings.Contains(low, "failed to lookup") || strings.Contains(low, "dns"):
		return "RustScan 目标解析失败：确认 target 可解析；CIDR 直接填网段，域名先确认 DNS"
	case strings.Contains(low, "unexpected argument") || strings.Contains(low, "invalid value") || strings.Contains(low, "error:"):
		return "RustScan 参数无效：" + rustscanFirstLine(out, runErr.Error())
	case strings.Contains(low, "no such file") || strings.Contains(low, "not found"):
		return "RustScan 依赖缺失：" + rustscanFirstLine(out, runErr.Error())
	default:
		return "RustScan 执行失败：" + rustscanFirstLine(out, runErr.Error())
	}
}

func rustscanFirstLine(out, fallback string) string {
	for _, line := range strings.Split(stripANSI(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Open ") || strings.Contains(line, "->") {
			continue
		}
		return kerbTruncate(line, 300)
	}
	return kerbTruncate(fallback, 300)
}

func (t *ToolSet) toolRustscan() actool.CoreTool {
	return t.writeExpTool("scan_rustscan",
		"【侦察 · T1046】用 RustScan 快速扫描目标 TCP 端口（默认 1-65535，秒级~分钟级），返回结构化开放端口并回写 fact。\n"+
			"代码只负责执行、解析、去重排序和 scope 校验；**端口→服务的判断、漏洞判定、下一步打哪个模块由你决定**——端口开放本身不是漏洞，不要直接 report_finding。\n"+
			"支持 IP / 域名 / CIDR（URL 或 host:port 会自动拆成 host+port）；默认拒绝 > /16 的大范围，需要时显式 allow_large_range=true。\n"+
			"dry_run=true 只解析目标并校验 rustscan 二进制，不发起扫描。OPSEC=MEDIUM~HIGH：全端口扫描噪声大，先确认 scope；目标在隔离内网时先建隧道/会话，本工具从 ARTEX 宿主发起。",
		obj(map[string]any{
			"target":            str("IP / 域名 / CIDR（也接受 URL 或 host:port，会自动拆出 host 与端口），必填"),
			"ports":             str("端口范围，如 1-65535 或 22,80,443，默认全端口"),
			"batch_size":        intp("并发批次，默认 4500（1..65535）"),
			"timeout_ms":        intp("单端口超时 ms，默认 1500（1..60000）"),
			"ulimit":            intp("文件描述符上限，默认 5000（1..1000000）"),
			"script":            str("可选：扫描后跑的 Nmap 脚本（如 vuln），会显著增加噪声与耗时"),
			"exclude_ports":     str("排除端口，如 9100,161"),
			"timeout_sec":       map[string]any{"type": "integer", "description": "整次扫描超时秒数，默认 300，范围 10..900", "default": 300},
			"allow_large_range": map[string]any{"type": "boolean", "description": "允许大于 /16 的 CIDR（默认 false；大范围扫描极慢且噪声高）"},
			"dry_run":           map[string]any{"type": "boolean", "description": "只解析目标与校验 rustscan 依赖，不发起扫描"},
		}, "target"),
		t.rustscanHandler)
}

func (t *ToolSet) rustscanHandler(ctx context.Context, in json.RawMessage) (actool.Result, error) {
	var p RustscanParams
	if err := json.Unmarshal(in, &p); err != nil {
		return actool.Errorf("参数解析失败：" + err.Error()), nil
	}
	if err := p.Validate(); err != nil {
		return actool.Errorf(err.Error()), nil
	}
	if err := t.assertInScope(p.Target); err != nil {
		return actool.Errorf(err.Error()), nil
	}

	start := time.Now()
	res := RustscanResult{
		ModuleID: rustscanModuleID, MITRE: rustscanMITRE, Status: "failed",
		Target: p.Target, Ports: p.Ports, OpenPorts: []OpenPort{},
	}

	bin, err := rustscanFind()
	if err != nil {
		res.Error = err.Error()
		res.NextSteps = []string{
			"安装 RustScan：cargo install rustscan，或从 GitHub release 下载后放入 data/tools/",
			"也可设置 ARTEX_RUSTSCAN_PATH 指向二进制绝对路径",
			"临时替代：先用已有 gogo/naabu 做端口发现，并把结果写入 fact；不要手写全端口扫描脚本",
		}
		res.ElapsedMs = time.Since(start).Milliseconds()
		return jsonResult(res)
	}

	args := buildRustscanArgs(&p)
	res.Command = strings.Join(append([]string{filepath.Base(bin)}, args...), " ")
	res.Tooling = map[string]any{"rustscan_path": bin}

	if p.DryRun {
		ips, count, rerr := resolveRustscanTargets(p.Target)
		res.Status = "dry_run"
		res.Tooling["command_preview"] = res.Command
		if rerr != nil {
			res.Status = "failed"
			res.Error = "目标解析失败：" + rerr.Error()
			res.NextSteps = []string{"确认 target 是可达的 IP/域名/CIDR", "域名先做 DNS 解析，或直接填 IP"}
			res.ElapsedMs = time.Since(start).Milliseconds()
			return jsonResult(res)
		}
		res.ResolvedIPs = ips
		res.Tooling["address_count"] = count
		if count > 1 {
			res.Tooling["note"] = "CIDR 大范围只展示首尾地址；实际扫描地址数见 address_count"
		}
		res.NextSteps = []string{
			"dry_run 通过后，用同样的 target 发起扫描；先小范围（单机/24）验证速度与噪声",
			"拿开放端口后按服务决定下一步：22→SSH、445→SMB、389/636→LDAP、88→Kerberos、3389→RDP、1433→MSSQL、3306→MySQL、6379→Redis、80/443/8080→HTTP",
		}
		res.ElapsedMs = time.Since(start).Milliseconds()
		return jsonResult(res)
	}

	out, runErr := rustscanRun(ctx, bin, args, time.Duration(p.TimeoutSec)*time.Second)
	res.OpenPorts = parseRustscanOutput(out)
	res.PortCount = len(res.OpenPorts)
	res.ElapsedMs = time.Since(start).Milliseconds()

	if runErr != nil && len(res.OpenPorts) == 0 {
		res.Status = "failed"
		res.Error = rustscanErrorMessage(runErr, out, time.Duration(p.TimeoutSec)*time.Second)
		res.OutputTail = kerbTruncate(stripANSI(out), rustscanOutputTail)
		res.NextSteps = rustscanFailureNextSteps(res.Error)
		return jsonResult(res)
	}

	res.Status = "success"
	if ips, _, rerr := resolveRustscanTargets(p.Target); rerr == nil {
		res.ResolvedIPs = ips
	}
	if runErr != nil {
		res.Warnings = append(res.Warnings, "部分扫描失败："+rustscanErrorMessage(runErr, out, time.Duration(p.TimeoutSec)*time.Second))
	}
	t.recordRustscanFact(ctx, &res)
	res.NextSteps = rustscanNextSteps(res.OpenPorts)
	return jsonResult(res)
}

func rustscanNextSteps(ports []OpenPort) []string {
	if len(ports) == 0 {
		return []string{
			"单次扫描没有 Open 行：可能是全关、被防火墙过滤、目标不可达或 ICMP/UDP 限制；不要直接下“端口全关”的结论",
			"换源/换协议/换端口范围复核（如常见的 22,80,443,445,3389,8080），或先确认目标存活",
			"如果目标在隔离内网，先建隧道/会话再从目标侧扫描，不要从平台侧盲目直连",
		}
	}
	return []string{
		"按端口判断服务：22→SSH、445→SMB、389/636→LDAP、88→Kerberos、3389→RDP、1433→MSSQL、3306→MySQL、6379→Redis、80/443/8080→HTTP",
		"对高价值服务（SMB/LDAP/Kerberos/MSSQL/Redis/HTTP 管理口）调对应模块做指纹与漏洞验证；不要只凭端口 open 写 finding",
		"需要服务版本时加 script（Nmap 脚本，噪声更高）或后续用专门的服务识别工具",
		"把开放端口作为资产/事实写回后，再决定下一步攻击面",
	}
}

func rustscanFailureNextSteps(msg string) []string {
	switch {
	case strings.Contains(msg, "超时"):
		return []string{
			"缩小 target（单机或 /24）或缩小 ports 范围",
			"提高 timeout_sec；确认目标/中间设备没有丢包",
		}
	case strings.Contains(msg, "权限"):
		return []string{
			"检查 rustscan 二进制执行权限（chmod +x）",
			"降低 ulimit；必要时用非 root 的常规权限运行",
		}
	case strings.Contains(msg, "解析"):
		return []string{
			"确认 target 拼写与 DNS；必要时直接填 IP/CIDR",
			"检查是否有代理/隧道影响 DNS",
		}
	default:
		return []string{
			"先 dry_run=true 校验 target 解析与 rustscan 依赖",
			"缩小端口范围或目标范围重试；查看 output_tail 里的原始错误",
		}
	}
}

func (t *ToolSet) recordRustscanFact(ctx context.Context, res *RustscanResult) {
	if t.ts == nil {
		return
	}
	ports := formatRustscanPorts(res.OpenPorts, 300)
	summary := fmt.Sprintf("RustScan %s：发现 %d 个开放端口", res.Target, res.PortCount)
	detail := fmt.Sprintf("开放端口（%s）：%s", res.Ports, ports)
	confidence := FactConfidenceObserved
	if res.PortCount == 0 {
		summary = fmt.Sprintf("RustScan %s：未发现开放端口", res.Target)
		detail = fmt.Sprintf("端口范围 %s 的单次扫描没有 Open 行；可能是全关、被过滤、目标不可达或 ICMP/UDP 限制。结论标 inferred，换源/换端口复核后再下否定结论。", res.Ports)
		confidence = FactConfidenceInferred
	}
	evidence := fmt.Sprintf("%s -> %d open (%s)", res.Command, res.PortCount, formatRustscanPorts(res.OpenPorts, 8))
	if res.Command == "" {
		evidence = fmt.Sprintf("rustscan -a %s -p %s -> %d open", res.Target, res.Ports, res.PortCount)
	}
	assetIDs := []json.RawMessage{}
	for _, id := range t.rustscanAssetIDs(res.Target) {
		assetIDs = append(assetIDs, json.RawMessage(strconv.FormatInt(id, 10)))
	}
	id, note, err := t.recordOneFactChecked(factItem{
		Summary:    summary,
		Detail:     detail,
		Evidence:   evidence,
		Confidence: confidence,
		IntentID:   json.RawMessage(strconv.FormatInt(t.ownerNode, 10)),
		AssetIDs:   assetIDs,
	}, t.ownerNode, nil)
	if err != nil {
		res.Warnings = append(res.Warnings, "fact 回写失败："+err.Error())
		return
	}
	res.FactID = id
	if note != "" {
		res.Warnings = append(res.Warnings, note)
	}
}

func (t *ToolSet) rustscanAssetIDs(target string) []int64 {
	if t.as == nil || strings.Contains(target, "/") {
		return nil
	}
	if assets, err := t.as.QueryByHost(target, 0); err == nil {
		for _, a := range assets {
			if a != nil {
				return []int64{a.ID}
			}
		}
	}
	return nil
}
