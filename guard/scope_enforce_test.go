package guard

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
)

// fakeScopeStore 注入固定的 task_scope 行，避免测试依赖数据库。
type fakeScopeStore struct {
	rows map[int64][]db.TaskScope
	err  error
}

func (f *fakeScopeStore) ListTaskScope(taskID int64) ([]db.TaskScope, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.rows[taskID], nil
}

// withScopeStore 装好假存储与缓存清理，返回恢复函数。
func withScopeStore(t *testing.T, rows map[int64][]db.TaskScope) {
	t.Helper()
	SetScopeStore(&fakeScopeStore{rows: rows})
	t.Cleanup(func() { SetScopeStore(nil) })
}

// bashCall 用给定命令行跑一次 Bash 调用，返回是否被阻断。
func bashCall(g *Guard, ctx context.Context, cmd string) bool {
	input, _ := json.Marshal(map[string]string{"command": cmd})
	b, _, _ := g.Hooks().PreToolUse(ctx, "Bash", input)
	return b
}

func taskCtx(taskID string) context.Context {
	return intercept.WithTaskContext(context.Background(), taskID, "worker", nil)
}

// 范围内目标放行、范围外目标阻断——这是本层存在的唯一理由。
func TestScopeBlocksOutOfScopeHost(t *testing.T) {
	withScopeStore(t, map[int64][]db.TaskScope{
		7: {
			{TaskID: 7, Kind: "root_domain", Domain: "acme.com"},
			{TaskID: 7, Kind: "ip", Value: "10.0.0.5"},
		},
	})
	g := New()
	ctx := taskCtx("7")

	for _, cmd := range []string{
		`curl -s https://acme.com/api`,
		`nmap -sV sub.acme.com`,
		`curl http://10.0.0.5:8080/`,
	} {
		if bashCall(g, ctx, cmd) {
			t.Errorf("范围内命令不应被阻断: %q", cmd)
		}
	}
	for _, cmd := range []string{
		`curl -s https://evil.example.net/`,
		`nmap -sV 8.8.8.8`,
		`sqlmap -u http://not-acme.com/x?id=1`,
	} {
		if !bashCall(g, ctx, cmd) {
			t.Errorf("范围外命令必须被阻断: %q", cmd)
		}
	}
}

// CIDR 范围内的任意地址放行，范围外阻断。
func TestScopeCIDR(t *testing.T) {
	withScopeStore(t, map[int64][]db.TaskScope{
		9: {{TaskID: 9, Kind: "cidr", Net: "10.1.0.0/16"}},
	})
	g := New()
	ctx := taskCtx("9")
	if bashCall(g, ctx, `curl http://10.1.2.3:7001/`) {
		t.Error("CIDR 内地址不应被阻断")
	}
	if !bashCall(g, ctx, `curl http://10.2.2.3:7001/`) {
		t.Error("CIDR 外地址必须被阻断")
	}
}

// 未登记任何 scope 时 fail-open，但必须留下审计痕迹。
func TestScopeFailOpenWhenNoScope(t *testing.T) {
	withScopeStore(t, map[int64][]db.TaskScope{})
	g := New()
	ctx := taskCtx("11")
	if bashCall(g, ctx, `curl http://whatever.example.org/`) {
		t.Error("未登记范围时应放行（fail-open）")
	}
	found := false
	for _, e := range g.Audit() {
		if e.Action == "allow" && len(e.Reason) > 0 {
			found = true
		}
	}
	if !found {
		t.Error("fail-open 必须留审计")
	}
}

// 没有任务归属的调用（chat / 非任务级）不参与范围判定。
func TestScopeSkipsNonTaskCalls(t *testing.T) {
	withScopeStore(t, map[int64][]db.TaskScope{
		7: {{TaskID: 7, Kind: "root_domain", Domain: "acme.com"}},
	})
	g := New()
	if bashCall(g, context.Background(), `curl http://evil.example.net/`) {
		t.Error("无任务归属的调用不应被判越界")
	}
}

// 含 company/icp/keyword 这类静态判定不了的 scope 行时，越界目标转人工审批
// （无 interceptor 时按拒绝处理），而不是静默通过。
func TestScopeUnresolvedGoesToApproval(t *testing.T) {
	withScopeStore(t, map[int64][]db.TaskScope{
		13: {
			{TaskID: 13, Kind: "root_domain", Domain: "acme.com"},
			{TaskID: 13, Kind: "company", CompanyID: ptrInt64(3)},
		},
	})
	g := New() // 无 interceptor：HandleAsk 不可用 → 按拒绝处理
	ctx := taskCtx("13")
	if !bashCall(g, ctx, `curl http://other.example.net/`) {
		t.Error("存在无法静态判定的 scope 行时，越界目标应阻断（无审批通道时）")
	}
	if bashCall(g, ctx, `curl http://acme.com/`) {
		t.Error("范围内的静态目标不应被阻断")
	}
}

func ptrInt64(v int64) *int64 { return &v }

// 目标抽取：URL / host:port / 裸 IP / 命令行参数 / 大小写与尾点归一。
func TestScopeEnforceExtractHosts(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{`curl -s https://ACME.com:8443/a?b=1`, []string{"acme.com"}},
		{`nmap -sV -p 80,443 10.0.0.5`, []string{"10.0.0.5"}},
		{`ffuf -u http://sub.acme.com/FUZZ -w w.txt`, []string{"sub.acme.com"}},
		{`python3 scan.py --target api.acme.com`, []string{"api.acme.com"}},
		{`echo hello`, nil},
	}
	for _, c := range cases {
		got := extractHosts(c.in)
		if len(got) != len(c.want) {
			t.Errorf("extractHosts(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("extractHosts(%q)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

// hostInScope 的边界：父域包含子域、精确子域不放宽、尾点与大小写归一。
func TestHostInScope(t *testing.T) {
	set := buildScopeSet([]db.TaskScope{
		{Kind: "root_domain", Domain: "acme.com"},
		{Kind: "subdomain", Domain: "vpn.other.com"},
		{Kind: "ip", Value: "192.168.1.10"},
	})
	for _, h := range []string{"acme.com", "ACME.COM.", "a.b.acme.com", "vpn.other.com", "192.168.1.10"} {
		if !set.hostInScope(h) {
			t.Errorf("%q 应在范围内", h)
		}
	}
	for _, h := range []string{"notacme.com", "acme.com.evil.net", "x.vpn.other.com", "192.168.1.11"} {
		if set.hostInScope(h) {
			t.Errorf("%q 不应在范围内", h)
		}
	}
}

// 总开关可以整体停用范围层（用于救援/调试），默认为开。
func TestScopeEnforceSwitch(t *testing.T) {
	withScopeStore(t, map[int64][]db.TaskScope{
		7: {{TaskID: 7, Kind: "root_domain", Domain: "acme.com"}},
	})
	defer func() { ScopeEnforceEnabled = nil }()
	ScopeEnforceEnabled = func() bool { return false }
	g := New()
	if bashCall(g, taskCtx("7"), `curl http://evil.example.net/`) {
		t.Error("总开关关闭时不应阻断")
	}
	ScopeEnforceEnabled = func() bool { return true }
	if !bashCall(g, taskCtx("7"), `curl http://evil.example.net/`) {
		t.Error("总开关打开时必须阻断")
	}
}
