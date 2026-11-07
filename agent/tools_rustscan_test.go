package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseRustscanOutput(t *testing.T) {
	out := `
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
Open 10.0.0.1:22
` + "\x1b[32mOpen\x1b[0m 10.0.0.1:80" + `
10.0.0.1 -> [443,445]
3389/tcp open ms-wbt-server
53/udp open domain
22/tcp open ssh
22/tcp closed ssh
`
	ports := parseRustscanOutput(out)
	if len(ports) != 6 {
		t.Fatalf("ports = %d, want 6: %+v", len(ports), ports)
	}
	want := []int{22, 53, 80, 443, 445, 3389}
	for i, p := range ports {
		if p.Port != want[i] {
			t.Errorf("ports[%d] = %d, want %d (%+v)", i, p.Port, want[i], ports)
		}
	}
	if ports[0].Service != "ssh" {
		t.Errorf("22 service = %q, want ssh (Nmap line should fill it)", ports[0].Service)
	}
	if ports[1].Protocol != "udp" || ports[1].Service != "domain" {
		t.Errorf("53 = %+v", ports[1])
	}
}

func TestParseRustscanOutputClosedOnly(t *testing.T) {
	ports := parseRustscanOutput("22/tcp closed ssh\n80/tcp filtered http\n")
	if len(ports) != 0 {
		t.Fatalf("ports = %+v, want none", ports)
	}
	if ports == nil {
		t.Fatal("parser should return an empty slice, not nil")
	}
}

func TestRustscanParamsValidate(t *testing.T) {
	p := RustscanParams{Target: "10.0.0.1"}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if p.Ports != "1-65535" || p.BatchSize != 4500 || p.TimeoutMs != 1500 || p.ULimit != 5000 || p.TimeoutSec != 300 {
		t.Errorf("defaults = %+v", p)
	}

	u := RustscanParams{Target: "http://10.0.0.1:8080/path?q=1"}
	if err := u.Validate(); err != nil {
		t.Fatal(err)
	}
	if u.Target != "10.0.0.1" || u.Ports != "8080" {
		t.Errorf("url normalize = %+v", u)
	}

	h := RustscanParams{Target: "10.0.0.1:8443"}
	if err := h.Validate(); err != nil {
		t.Fatal(err)
	}
	if h.Target != "10.0.0.1" || h.Ports != "8443" {
		t.Errorf("host:port normalize = %+v", h)
	}

	c := RustscanParams{Target: "10.0.0.0/24"}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid /24 rejected: %v", err)
	}
	big := RustscanParams{Target: "10.0.0.0/8"}
	if err := big.Validate(); err == nil {
		t.Error("/8 should be rejected by default")
	}
	big.AllowLargeRange = true
	if err := big.Validate(); err != nil {
		t.Errorf("/8 with allow_large_range rejected: %v", err)
	}

	bad := []RustscanParams{
		{Target: ""},
		{Target: "10.0.0.1; rm -rf /"},
		{Target: "10.0.0.1/abc"},
		{Target: "10.0.0.1", Ports: "1-65535; id"},
		{Target: "10.0.0.1", ExcludePorts: "1; id"},
		{Target: "10.0.0.1", Script: "-sV"},
		{Target: "10.0.0.1", TimeoutSec: 5},
		{Target: "10.0.0.1", BatchSize: 70000},
		{Target: "10.0.0.1", TimeoutMs: 70000},
		{Target: "10.0.0.1", ULimit: 2000000},
	}
	for i, in := range bad {
		if err := in.Validate(); err == nil {
			t.Errorf("case %d accepted invalid params: %+v", i, in)
		}
	}
}

func TestBuildRustscanArgs(t *testing.T) {
	p := &RustscanParams{
		Target: "10.0.0.1", Ports: "22,80", BatchSize: 100, TimeoutMs: 500, ULimit: 1000,
		ExcludePorts: "9100", Script: "vuln",
	}
	args := strings.Join(buildRustscanArgs(p), " ")
	for _, want := range []string{"-a 10.0.0.1", "-p 22,80", "-b 100", "-t 500", "--ulimit 1000", "--exclude-ports 9100", "--scripts vuln"} {
		if !strings.Contains(args, want) {
			t.Errorf("args missing %q: %s", want, args)
		}
	}
}

func stubRustscan(t *testing.T, out string, runErr error) {
	t.Helper()
	oldFind, oldRun := rustscanFind, rustscanRun
	rustscanFind = func() (string, error) { return "rustscan", nil }
	rustscanRun = func(_ context.Context, _ string, _ []string, _ time.Duration) (string, error) {
		return out, runErr
	}
	t.Cleanup(func() { rustscanFind, rustscanRun = oldFind, oldRun })
}

func callRustscan(t *testing.T, ts *ToolSet, payload any) RustscanResult {
	t.Helper()
	raw, _ := json.Marshal(payload)
	res, err := ts.rustscanHandler(context.Background(), raw)
	if err != nil {
		t.Fatalf("handler transport error: %v", err)
	}
	if res.IsError {
		t.Fatalf("handler tool error: %s", res.Flatten())
	}
	var out RustscanResult
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("unmarshal result: %v\n%s", err, res.Flatten())
	}
	return out
}

func TestRustscanHandlerSuccess(t *testing.T) {
	stubRustscan(t, "Open 10.0.0.1:22\nOpen 10.0.0.1:445\n", nil)
	ts := NewToolSet(nil, "tester")
	out := callRustscan(t, ts, map[string]any{"target": "10.0.0.1"})
	if out.Status != "success" || out.PortCount != 2 {
		t.Fatalf("out = %+v", out)
	}
	if len(out.OpenPorts) != 2 || out.OpenPorts[0].Port != 22 || out.OpenPorts[1].Port != 445 {
		t.Errorf("open_ports = %+v", out.OpenPorts)
	}
	if len(out.NextSteps) == 0 {
		t.Error("success should include next_steps")
	}
	if !strings.Contains(out.Command, "rustscan") {
		t.Errorf("command = %q", out.Command)
	}
}

func TestRustscanHandlerDryRun(t *testing.T) {
	stubRustscan(t, "", nil)
	ts := NewToolSet(nil, "tester")
	out := callRustscan(t, ts, map[string]any{"target": "127.0.0.1", "dry_run": true})
	if out.Status != "dry_run" {
		t.Fatalf("out = %+v", out)
	}
	if len(out.ResolvedIPs) != 1 || out.ResolvedIPs[0] != "127.0.0.1" {
		t.Errorf("resolved_ips = %+v", out.ResolvedIPs)
	}
	if out.Tooling == nil || out.Tooling["command_preview"] == "" {
		t.Errorf("tooling = %+v", out.Tooling)
	}
}

func TestRustscanHandlerFailure(t *testing.T) {
	stubRustscan(t, "Permission denied (os error 13)", errors.New("exit status 1"))
	ts := NewToolSet(nil, "tester")
	out := callRustscan(t, ts, map[string]any{"target": "10.0.0.1"})
	if out.Status != "failed" || !strings.Contains(out.Error, "权限") {
		t.Fatalf("out = %+v", out)
	}
	if out.OutputTail == "" {
		t.Error("failure should carry output_tail")
	}
	if len(out.NextSteps) == 0 {
		t.Error("failure should carry next_steps")
	}
}

func TestRustscanToolInWorkerSet(t *testing.T) {
	found := false
	for _, tool := range NewToolSet(nil, "").WorkerTools() {
		if tool.Name() == "scan_rustscan" {
			found = true
			if !strings.Contains(tool.Description(), "T1046") {
				t.Error("description missing T1046")
			}
		}
	}
	if !found {
		t.Fatal("scan_rustscan not in WorkerTools")
	}
	for _, seed := range BuiltinToolSeeds() {
		if seed.Key != "scan_rustscan" {
			continue
		}
		for _, a := range seed.Agents {
			if a == "worker" {
				return
			}
		}
		t.Fatalf("scan_rustscan agents = %v, want worker", seed.Agents)
	}
	t.Fatal("scan_rustscan not in BuiltinToolSeeds")
}

func TestRustscanDomainToolNilStore(t *testing.T) {
	ts := NewToolSet(nil, "")
	res, err := ts.toolRustscan().Call(context.Background(), json.RawMessage(`{"target":"10.0.0.1"}`), nil)
	if err != nil {
		t.Fatalf("transport error: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Flatten(), "任务上下文") {
		t.Fatalf("want task-context refusal, got IsError=%v %q", res.IsError, res.Flatten())
	}
}

func TestToolchainRuleMentionsRustscan(t *testing.T) {
	if !strings.Contains(toolchainRule, "scan_rustscan") {
		t.Fatal("worker toolchain rule must require scan_rustscan for port scans")
	}
}

func TestCidrEndpointsAndHostCount(t *testing.T) {
	_, n, err := net.ParseCIDR("10.0.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	first, last := cidrEndpoints(n)
	if first.String() != "10.0.0.0" || last.String() != "10.0.0.255" {
		t.Errorf("endpoints = %s..%s", first, last)
	}
	if got := cidrHostCount(n); got != 256 {
		t.Errorf("host count = %d, want 256", got)
	}
}
