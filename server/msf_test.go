package server

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestDiffSessions(t *testing.T) {
	before := map[string]bool{"1": true}
	after := map[string]bool{"1": true, "2": true}
	got := diffSessions(before, after)
	if len(got) != 1 || got[0] != "2" {
		t.Fatalf("diff=%v", got)
	}
	if len(diffSessions(after, after)) != 0 {
		t.Fatal("no new sessions expected")
	}
	if ids := keysOf(after); len(ids) != 2 || ids[0] != "1" || ids[1] != "2" {
		t.Fatalf("keysOf=%v", ids)
	}
}

func TestTruncateForTool(t *testing.T) {
	if got := truncateForTool("short"); got != "short" {
		t.Fatalf("short=%q", got)
	}
	long := make([]byte, 900)
	for i := range long {
		long[i] = 'a'
	}
	if got := truncateForTool(string(long)); len(got) != 503 {
		t.Fatalf("len=%d", len(got))
	}
}

func TestScopeRowsAllowIPFromNet(t *testing.T) {
	rows := []db.TaskScope{{Kind: "ip", Net: "127.0.0.1/32"}}
	for _, h := range []string{"127.0.0.1", "http://127.0.0.1:8080/api/ping", "127.0.0.1:8080"} {
		if !scopeRowsAllow(rows, h) {
			t.Fatalf("%s 应命中授权范围", h)
		}
	}
	if scopeRowsAllow(rows, "127.0.0.2") {
		t.Fatal("127.0.0.2 不应命中")
	}
}

func TestScopeRowsAllowCIDRAndDomain(t *testing.T) {
	rows := []db.TaskScope{
		{Kind: "cidr", Net: "10.0.0.0/24"},
		{Kind: "root_domain", Domain: "example.com"},
	}
	if !scopeRowsAllow(rows, "10.0.0.7") {
		t.Fatal("CIDR 内的地址应命中")
	}
	if !scopeRowsAllow(rows, "a.example.com") {
		t.Fatal("子域应命中 root_domain")
	}
	if scopeRowsAllow(rows, "10.0.1.7") || scopeRowsAllow(rows, "evilexample.com") {
		t.Fatal("越界目标不应命中")
	}
}

func TestNormalizeScopeTarget(t *testing.T) {
	cases := map[string]string{
		"http://Example.COM:8080/path?q=1": "example.com",
		"10.0.0.5:443":                     "10.0.0.5",
		"host.example.com.":                "host.example.com",
		"  ":                               "",
	}
	for in, want := range cases {
		if got := normalizeScopeTarget(in); got != want {
			t.Fatalf("normalize(%q)=%q want %q", in, got, want)
		}
	}
}
