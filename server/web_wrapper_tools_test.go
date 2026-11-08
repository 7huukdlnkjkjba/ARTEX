package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

const sqlmapTestOut = `
[07:00:00] [INFO] testing connection to the target URL
[07:00:01] [INFO] GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 1 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1=1
---
[07:00:02] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0
current database: 'app'
current user: 'root@localhost'
current user is DBA: True
available databases [2]:
[*] app
[*] mysql
`

func TestParseSQLMapOutput(t *testing.T) {
	p := parseSQLMapOutput(sqlmapTestOut)
	if p["injectable"] != true {
		t.Errorf("injectable = %v", p["injectable"])
	}
	if p["dbms"] != "MySQL >= 5.0" {
		t.Errorf("dbms = %v", p["dbms"])
	}
	if p["current_db"] != "'app'" {
		t.Errorf("current_db = %v", p["current_db"])
	}
	if p["current_user"] != "'root@localhost'" {
		t.Errorf("current_user = %v", p["current_user"])
	}
	if p["is_dba"] != true {
		t.Errorf("is_dba = %v", p["is_dba"])
	}
	dbs, _ := p["databases"].([]string)
	if len(dbs) != 2 || dbs[0] != "app" || dbs[1] != "mysql" {
		t.Errorf("databases = %v", p["databases"])
	}
	types, _ := p["injection_types"].([]string)
	if len(types) != 3 {
		t.Errorf("types = %v", types)
	}
}

func TestBuildSQLMapArgs(t *testing.T) {
	a := &sqlmapParams{URL: "http://127.0.0.1/item?id=1", Action: "detect", Technique: "BE"}
	args, err := buildSQLMapArgs(a, "", "")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{"--batch", "--smart", "--level=1", "--risk=1", "--threads=1", "--technique=BE", "--flush-session"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %s in %s", want, joined)
		}
	}
	for _, bad := range []string{"--os-shell", "--sql-shell", "--file-write", "--dump"} {
		if strings.Contains(joined, bad) {
			t.Errorf("unexpected %s in %s", bad, joined)
		}
	}

	a.Action = "dump"
	a.Table = "users"
	args, err = buildSQLMapArgs(a, "http://127.0.0.1:8080", "")
	if err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(args, " ")
	if !strings.Contains(joined, "--dump") || !strings.Contains(joined, "-T users") ||
		!strings.Contains(joined, "--proxy=http://127.0.0.1:8080") {
		t.Errorf("dump args = %s", joined)
	}
}

func TestSQLMapDumpRequiresConfirmAndTable(t *testing.T) {
	s := &Server{}
	for _, tc := range []map[string]any{
		{"url": "http://127.0.0.1/?id=1", "action": "dump"},
		{"url": "http://127.0.0.1/?id=1", "action": "dump", "confirm": true},
	} {
		raw, _ := json.Marshal(tc)
		res, err := s.toolSQLMap().Call(context.Background(), raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError || !strings.Contains(res.Flatten(), "confirm=true") &&
			!strings.Contains(res.Flatten(), "table") {
			t.Fatalf("expected confirm/table error, got %v %s", res.IsError, res.Flatten())
		}
	}
}

func TestSQLMapDryRun(t *testing.T) {
	s := &Server{}
	raw, _ := json.Marshal(map[string]any{
		"url": "http://127.0.0.1:8080/?id=1", "action": "detect", "dry_run": true,
	})
	res, err := s.toolSQLMap().Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("dry run error: %s", res.Flatten())
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatal(err)
	}
	if out["status"] != "dry_run" {
		t.Errorf("out = %v", out)
	}
}

func TestNucleiParseJSONL(t *testing.T) {
	out := `{"template-id":"CVE-2024-1","info":{"name":"Example RCE","severity":"critical"},"host":"https://x","matched-at":"https://x/a"}
{"template-id":"CVE-2024-1","info":{"name":"Example RCE","severity":"critical"},"host":"https://x","matched-at":"https://x/a"}
{"template-id":"tech-detect","info":{"name":"Tech","severity":"info"},"host":"https://x","matched-at":"https://x"}
[INF] not json
`
	lines, err := parseNucleiJSONL(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 {
		t.Fatalf("lines = %d: %+v", len(lines), lines)
	}
	if lines[0].Name != "Example RCE" || lines[0].Severity != "critical" {
		t.Errorf("line0 = %+v", lines[0])
	}
}

func TestBuildNucleiArgs(t *testing.T) {
	a := &nucleiParams{Target: "https://x", Severity: "critical,high", Tags: "cve", Template: "CVE-2024-1"}
	args := buildNucleiArgs(a, "http://127.0.0.1:8080")
	joined := strings.Join(args, " ")
	for _, want := range []string{"-u https://x", "-severity critical,high", "-rl 50", "-ni", "-duc", "-tags cve", "-t CVE-2024-1", "-proxy http://127.0.0.1:8080"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %s in %s", want, joined)
		}
	}
}

func TestNucleiDryRun(t *testing.T) {
	s := &Server{}
	raw, _ := json.Marshal(map[string]any{"target": "http://127.0.0.1:8080", "dry_run": true})
	res, err := s.toolNuclei().Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("dry run error: %s", res.Flatten())
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatal(err)
	}
	if out["status"] != "dry_run" {
		t.Errorf("out = %v", out)
	}
}

func TestWebWrapperToolsRegistered(t *testing.T) {
	names := map[string]bool{}
	for _, tool := range (&Server{}).webWrapperTools() {
		names[tool.Name()] = true
	}
	for _, want := range []string{"sqlmap_run", "nuclei_run"} {
		if !names[want] {
			t.Errorf("missing %s", want)
		}
	}
}

func TestHostFromTarget(t *testing.T) {
	cases := map[string]string{
		"https://example.com/a?b=1": "example.com",
		"http://127.0.0.1:8080/x":   "127.0.0.1",
		"example.com:443":           "example.com",
		"example.com/path":          "example.com",
	}
	for in, want := range cases {
		if got := hostFromTarget(in); got != want {
			t.Errorf("%s => %s, want %s", in, got, want)
		}
	}
}
