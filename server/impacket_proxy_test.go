package server

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestParseSocks5URL(t *testing.T) {
	host, port, user, pass, err := parseSocks5URL("socks5://alice:secret@127.0.0.1:1080")
	if err != nil {
		t.Fatal(err)
	}
	if host != "127.0.0.1" || port != 1080 || user != "alice" || pass != "secret" {
		t.Fatalf("got %s %d %s %s", host, port, user, pass)
	}

	host, port, user, pass, err = parseSocks5URL("socks5h://[::1]:1080")
	if err != nil {
		t.Fatal(err)
	}
	if host != "::1" || port != 1080 || user != "" || pass != "" {
		t.Fatalf("ipv6 got %s %d %s %s", host, port, user, pass)
	}

	for _, bad := range []string{"http://127.0.0.1:8080", "socks5://127.0.0.1", "socks5://127.0.0.1:99999"} {
		if _, _, _, _, err := parseSocks5URL(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestWriteProxychainsConf(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMP", dir)
	t.Setenv("TEMP", dir)
	path, cleanup, err := writeProxychainsConf("127.0.0.1", 1080, "alice", "secret")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	conf := string(b)
	for _, want := range []string{"[ProxyList]", "socks5 127.0.0.1 1080 alice secret", "proxy_dns"} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q in %q", want, conf)
		}
	}
}

func TestValidImpacketScriptName(t *testing.T) {
	ok := []string{"GetNPUsers.py", "secretsdump.py", "impacket-secretsdump"}
	for _, v := range ok {
		if !validImpacketScriptName(v) {
			t.Errorf("%s rejected", v)
		}
	}
	bad := []string{"", "../x.py", `C:\x\y.py`, "foo", ".."}
	for _, v := range bad {
		if validImpacketScriptName(v) {
			t.Errorf("%s accepted", v)
		}
	}
}

func TestRedactSocks5(t *testing.T) {
	got := redactSocks5("socks5://alice:secret@127.0.0.1:1080")
	if strings.Contains(got, "secret") {
		t.Fatalf("secret leaked: %s", got)
	}
}

func TestImpacketProxyToolsRegistered(t *testing.T) {
	found := false
	for _, tool := range (&Server{}).impacketProxyTools() {
		if tool.Name() == "impacket_proxy" {
			found = true
			if !strings.Contains(tool.Description(), "proxychains") {
				t.Error("description should mention proxychains limitation")
			}
		}
	}
	if !found {
		t.Fatal("impacket_proxy not registered")
	}
}

func TestImpacketProxyRejectsPathScript(t *testing.T) {
	s := &Server{}
	raw, _ := json.Marshal(map[string]any{"script": "../GetNPUsers.py", "args": []string{}})
	res, err := s.toolImpacketProxy().Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(res.Flatten(), "script 非法") {
		t.Fatalf("res = %v %s", res.IsError, res.Flatten())
	}
}
