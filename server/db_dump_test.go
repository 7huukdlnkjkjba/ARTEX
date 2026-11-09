package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestDBDumpNormalize(t *testing.T) {
	p := &dbDumpParams{DBType: "mysql", Host: "127.0.0.1", TargetDB: "app"}
	if err := p.Normalize(); err != nil {
		t.Fatal(err)
	}
	if p.Port != 3306 || p.Action != "list" || p.LimitRows != 10 || p.SSLMode != "disable" {
		t.Fatalf("normalize = %+v", p)
	}

	p = &dbDumpParams{DBType: "postgres", Host: "db", TargetDB: "app", Action: "dump"}
	if err := p.Normalize(); err == nil || !strings.Contains(err.Error(), "confirm=true") {
		t.Fatalf("dump without confirm: %v", err)
	}
	p.Confirm = true
	if err := p.Normalize(); err != nil {
		t.Fatal(err)
	}
	if p.Port != 5432 {
		t.Errorf("pg port = %d", p.Port)
	}

	bad := &dbDumpParams{DBType: "oracle", Host: "x", TargetDB: "y"}
	if err := bad.Normalize(); err == nil {
		t.Error("oracle accepted")
	}
	bad = &dbDumpParams{DBType: "mysql", Host: "x", TargetDB: "y", SSLMode: "bogus"}
	if err := bad.Normalize(); err == nil {
		t.Error("bogus sslmode accepted")
	}
}

func TestBuildDBDSN(t *testing.T) {
	my := &dbDumpParams{DBType: "mysql", Host: "127.0.0.1", Port: 3306, TargetDB: "app"}
	dsn, driver, err := buildDBDSN(my, "alice", "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if driver != "mysql" || !strings.Contains(dsn, "alice:s3cret@tcp(127.0.0.1:3306)/app") {
		t.Errorf("mysql dsn = %s driver=%s", dsn, driver)
	}

	pg := &dbDumpParams{DBType: "postgres", Host: "db.local", Port: 5432, TargetDB: "app", SSLMode: "require"}
	dsn, driver, err = buildDBDSN(pg, "alice", "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if driver != "postgres" || !strings.Contains(dsn, "postgres://alice:s3cret@db.local:5432/app") ||
		!strings.Contains(dsn, "sslmode=require") {
		t.Errorf("pg dsn = %s driver=%s", dsn, driver)
	}
}

func TestQuoteDBIdent(t *testing.T) {
	if got := quoteDBIdent("mysql", "weird`name"); got != "`weird``name`" {
		t.Errorf("mysql = %s", got)
	}
	if got := quoteDBIdent("postgres", `weird"name`); got != `"weird""name"` {
		t.Errorf("pg = %s", got)
	}
}

func TestDBCellTruncates(t *testing.T) {
	got := dbCell(strings.Repeat("a", 10), 4)
	if !strings.Contains(got.(string), "truncated") {
		t.Errorf("dbCell = %v", got)
	}
	if dbCell(nil, 4) != nil {
		t.Error("nil cell")
	}
}

func TestDBDumpToolsRegistered(t *testing.T) {
	found := false
	for _, tool := range (&Server{}).dbDumpTools() {
		if tool.Name() == "db_dump" {
			found = true
			if !strings.Contains(tool.Description(), "confirm=true") {
				t.Error("description should mention confirm")
			}
		}
	}
	if !found {
		t.Fatal("db_dump not registered")
	}
}

func TestDBDumpDumpRequiresConfirm(t *testing.T) {
	s := &Server{}
	raw, _ := json.Marshal(map[string]any{
		"db_type": "mysql", "host": "127.0.0.1", "target_db": "app", "action": "dump",
	})
	res, err := s.toolDBDump().Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(res.Flatten(), "confirm=true") {
		t.Fatalf("res = %v %s", res.IsError, res.Flatten())
	}
}

func TestDBDumpNeedsCredential(t *testing.T) {
	s := &Server{}
	raw, _ := json.Marshal(map[string]any{
		"db_type": "mysql", "host": "127.0.0.1", "target_db": "app", "action": "list",
	})
	res, err := s.toolDBDump().Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(res.Flatten(), "credential_id") {
		t.Fatalf("res = %v %s", res.IsError, res.Flatten())
	}
}
