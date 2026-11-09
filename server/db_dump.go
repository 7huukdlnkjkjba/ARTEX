package server

// db_dump reads a bounded, read-only slice of a MySQL/PostgreSQL database after
// an operator/agent already obtained credentials. It never writes, never runs
// UPDATE/DELETE/DDL, quotes every identifier, limits rows and cells, and keeps
// sensitive rows out of finding evidence.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
)

type dbDumpParams struct {
	DBType       string   `json:"db_type"`
	Host         string   `json:"host"`
	Port         int      `json:"port,omitempty"`
	Username     string   `json:"username,omitempty"`
	Password     string   `json:"password,omitempty"`
	CredentialID int64    `json:"credential_id,omitempty"`
	TargetDB     string   `json:"target_db"`
	Tables       []string `json:"tables,omitempty"`
	Action       string   `json:"action,omitempty"` // list | dump
	LimitRows    int      `json:"limit_rows,omitempty"`
	SSLMode      string   `json:"sslmode,omitempty"`
	Confirm      bool     `json:"confirm,omitempty"`
	TimeoutSec   int      `json:"timeout_sec,omitempty"`
}

func (p *dbDumpParams) Normalize() error {
	p.DBType = strings.ToLower(strings.TrimSpace(p.DBType))
	switch p.DBType {
	case "mysql", "postgres":
	default:
		return fmt.Errorf("db_type 只支持 mysql/postgres")
	}
	p.Host = strings.TrimSpace(p.Host)
	p.TargetDB = strings.TrimSpace(p.TargetDB)
	if p.Host == "" || p.TargetDB == "" {
		return fmt.Errorf("host/target_db 必填")
	}
	if p.Port == 0 {
		if p.DBType == "mysql" {
			p.Port = 3306
		} else {
			p.Port = 5432
		}
	}
	if p.Port <= 0 || p.Port > 65535 {
		return fmt.Errorf("port 非法")
	}
	p.Action = strings.ToLower(strings.TrimSpace(p.Action))
	if p.Action == "" {
		p.Action = "list"
	}
	switch p.Action {
	case "list", "dump":
	default:
		return fmt.Errorf("action 只支持 list/dump")
	}
	if p.LimitRows <= 0 {
		p.LimitRows = 10
	}
	if p.LimitRows > 100 {
		p.LimitRows = 100
	}
	if p.TimeoutSec <= 0 {
		p.TimeoutSec = 300
	}
	if p.TimeoutSec > 900 {
		p.TimeoutSec = 900
	}
	p.SSLMode = strings.ToLower(strings.TrimSpace(p.SSLMode))
	if p.SSLMode == "" {
		p.SSLMode = "disable"
	}
	switch p.SSLMode {
	case "disable", "require", "verify-ca", "verify-full":
	default:
		return fmt.Errorf("sslmode 只支持 disable/require/verify-ca/verify-full")
	}
	if len(p.Tables) > 20 {
		return fmt.Errorf("tables 过多（上限 20）")
	}
	if p.Action == "dump" && !p.Confirm {
		return fmt.Errorf("dump 是高影响动作：确认 RoE 与目标后设置 confirm=true；可先用 action=list")
	}
	return nil
}

func (s *Server) dbDumpTools() []actool.CoreTool {
	return []actool.CoreTool{s.toolDBDump()}
}

func (s *Server) seedDBDumpTools() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	workerAgents, _ := json.Marshal([]string{"worker"})
	for _, t := range s.dbDumpTools() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.PG().SeedTool(t.Name(), t.Description(), schema, workerAgents); err != nil {
			log.Printf("[tools] seed %s 失败: %v", t.Name(), err)
		}
	}
}

func (s *Server) toolDBDump() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "db_dump",
		Description: "【数据库直连·受控脱库】用已获得凭据连接 MySQL/PostgreSQL，action=list 列表，action=dump 读取指定表前 N 行。" +
			"执行归代码：scope、DSN、只读连接、标识符转义、行/单元格上限；dump 必须 confirm=true，tables 可限定，禁止写操作。" +
			"返回 rows 给模型；finding evidence 只写表名/行数，不写数据。",
		Schema: objSchema(map[string]any{
			"db_type":       strParam("mysql | postgres"),
			"host":          strParam("数据库主机"),
			"port":          map[string]any{"type": "integer", "description": "默认 mysql=3306, postgres=5432"},
			"username":      strParam("可选：用户名（显式凭据）"),
			"password":      strParam("可选：密码（优先 credential_id）"),
			"credential_id": map[string]any{"type": "integer", "description": "平台凭据 id（仅 password 类型）"},
			"target_db":     strParam("database 名"),
			"tables":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "可选：只读这些表（最多 20）；不传则列出/读取全部表"},
			"action":        strParam("list | dump（默认 list）"),
			"limit_rows":    map[string]any{"type": "integer", "description": "每表前 N 行，默认 10，上限 100"},
			"sslmode":       strParam("postgres sslmode：disable/require/verify-ca/verify-full；默认 disable"),
			"confirm":       map[string]any{"type": "boolean", "description": "dump 必须显式 true；list 不需要"},
			"timeout_sec":   map[string]any{"type": "integer", "description": "默认 300，上限 900"},
		}, "db_type", "host", "target_db"),
		ReadOnly:    func(json.RawMessage) bool { return false },
		Permissions: sessionPerm,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var p dbDumpParams
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败：" + err.Error()), nil
			}
			if err := p.Normalize(); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			ri := agent.RunInfoFrom(ctx)
			if in, known := guard.HostInTaskScope(ri.TaskID, p.Host); known && !in {
				return actool.Errorf(fmt.Sprintf("目标 %s 不在任务 scope 内", p.Host)), nil
			}
			user, pass, err := s.dbDumpCredential(ctx, &p, ri)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			dsn, driver, err := buildDBDSN(&p, user, pass)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			conn, err := sql.Open(driver, dsn)
			if err != nil {
				return actool.Errorf("DSN 解析失败：" + err.Error()), nil
			}
			defer conn.Close()
			conn.SetMaxOpenConns(1)
			conn.SetMaxIdleConns(1)
			runCtx, cancel := context.WithTimeout(ctx, time.Duration(p.TimeoutSec)*time.Second)
			defer cancel()
			if err := conn.PingContext(runCtx); err != nil {
				return jsonResult(map[string]any{
					"status": "failed", "error": dbConnError(err, p.DBType),
					"next_steps": []string{"确认 host/port/凭据；隔离内网先 tunnel_deploy，或把 DB 端口转发出来"},
				})
			}
			tables, err := listDBTables(runCtx, conn, p.DBType, p.TargetDB, p.Tables)
			if err != nil {
				return jsonResult(map[string]any{"status": "failed", "error": err.Error()})
			}
			if p.Action == "list" {
				return jsonResult(map[string]any{
					"status": "success", "db_type": p.DBType, "target_db": p.TargetDB,
					"tables": tables, "tables_count": len(tables),
				})
			}
			data, totalRows, truncated, err := dumpDBTables(runCtx, conn, &p, tables)
			if err != nil {
				return jsonResult(map[string]any{"status": "failed", "error": err.Error()})
			}
			findingID := int64(0)
			if totalRows > 0 {
				findingID = s.recordServerFinding(ctx, ri, "db-exposure",
					"数据库凭据可直连并读取数据", "high",
					fmt.Sprintf("直连 %s (%s/%s) 成功，读取 %d 表 / %d 行", p.Host, p.DBType, p.TargetDB, len(tables), totalRows),
					fmt.Sprintf("host=%s db_type=%s database=%s tables=%s rows=%d",
						p.Host, p.DBType, p.TargetDB, strings.Join(tables, ","), totalRows),
					"db_dump")
			}
			res := map[string]any{
				"status": "success", "db_type": p.DBType, "target_db": p.TargetDB,
				"tables": tables, "tables_count": len(tables),
				"rows": totalRows, "truncated": truncated, "data": data,
			}
			if findingID > 0 {
				res["finding_id"] = findingID
			}
			return jsonResult(res)
		},
	})
}

func (s *Server) dbDumpCredential(ctx context.Context, p *dbDumpParams, ri agent.RunInfo) (string, string, error) {
	if p.CredentialID > 0 {
		if s.credStore == nil {
			return "", "", fmt.Errorf("凭据库不可用")
		}
		c, err := s.credStore.Get(ctx, p.CredentialID)
		if err != nil || c == nil {
			return "", "", fmt.Errorf("凭据 %d 不存在", p.CredentialID)
		}
		if ri.TaskID > 0 && c.TaskID != ri.TaskID {
			return "", "", fmt.Errorf("凭据不属于本任务")
		}
		if c.CredType != db.CredPassword {
			return "", "", fmt.Errorf("db_dump 只支持 password 类型凭据（当前 %s）", c.CredType)
		}
		user := strings.TrimSpace(c.Username)
		if user == "" {
			return "", "", fmt.Errorf("凭据缺少用户名")
		}
		return user, c.Secret, nil
	}
	user := strings.TrimSpace(p.Username)
	if user == "" {
		return "", "", fmt.Errorf("需要 credential_id 或 username/password")
	}
	return user, p.Password, nil
}

func buildDBDSN(p *dbDumpParams, user, pass string) (string, string, error) {
	addr := net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
	switch p.DBType {
	case "mysql":
		cfg := mysql.NewConfig()
		cfg.User = user
		cfg.Passwd = pass
		cfg.Net = "tcp"
		cfg.Addr = addr
		cfg.DBName = p.TargetDB
		cfg.Timeout = 5 * time.Second
		cfg.ReadTimeout = 15 * time.Second
		cfg.WriteTimeout = 15 * time.Second
		cfg.AllowNativePasswords = true
		cfg.ParseTime = true
		return cfg.FormatDSN(), "mysql", nil
	case "postgres":
		u := &url.URL{Scheme: "postgres", User: url.UserPassword(user, pass), Host: addr, Path: "/" + p.TargetDB}
		q := u.Query()
		q.Set("sslmode", p.SSLMode)
		q.Set("connect_timeout", "5")
		u.RawQuery = q.Encode()
		return u.String(), "postgres", nil
	}
	return "", "", fmt.Errorf("unsupported db_type")
}

func listDBTables(ctx context.Context, conn *sql.DB, dbType, dbName string, wanted []string) ([]string, error) {
	var q string
	switch dbType {
	case "mysql":
		q = "SHOW TABLES"
	case "postgres":
		q = "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename"
	default:
		return nil, fmt.Errorf("unsupported db_type")
	}
	rows, err := conn.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("枚举表失败：%w", err)
	}
	defer rows.Close()
	var all []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err == nil && name != "" {
			all = append(all, name)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("枚举表失败：%w", err)
	}
	if len(wanted) == 0 {
		if len(all) > 100 {
			all = all[:100]
		}
		return all, nil
	}
	allow := map[string]bool{}
	for _, t := range all {
		allow[t] = true
	}
	var out []string
	seen := map[string]bool{}
	for _, t := range wanted {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		if !allow[t] {
			return nil, fmt.Errorf("表 %q 不在目标库中", t)
		}
		seen[t] = true
		out = append(out, t)
	}
	return out, nil
}

func dumpDBTables(ctx context.Context, conn *sql.DB, p *dbDumpParams, tables []string) ([]map[string]any, int, bool, error) {
	const maxCell = 2048
	const maxTotal = 512 << 10
	var out []map[string]any
	totalRows := 0
	totalBytes := 0
	truncated := false
	for _, table := range tables {
		if totalRows >= 2000 || totalBytes >= maxTotal {
			truncated = true
			break
		}
		quoted := quoteDBIdent(p.DBType, table)
		query := "SELECT * FROM " + quoted + " LIMIT ?"
		args := []any{p.LimitRows}
		if p.DBType == "postgres" {
			query = "SELECT * FROM " + quoted + " LIMIT $1"
		}
		rows, err := conn.QueryContext(ctx, query, args...)
		if err != nil {
			out = append(out, map[string]any{"table": table, "error": err.Error()})
			continue
		}
		cols, _ := rows.Columns()
		var tableRows []map[string]any
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				continue
			}
			row := map[string]any{}
			for i, c := range cols {
				row[c] = dbCell(vals[i], maxCell)
			}
			b, _ := json.Marshal(row)
			if totalBytes+len(b) > maxTotal {
				truncated = true
				break
			}
			totalBytes += len(b)
			tableRows = append(tableRows, row)
			totalRows++
		}
		_ = rows.Close()
		out = append(out, map[string]any{"table": table, "rows": tableRows})
		if truncated {
			break
		}
	}
	return out, totalRows, truncated, nil
}

func dbCell(v any, max int) any {
	switch x := v.(type) {
	case nil:
		return nil
	case []byte:
		s := string(x)
		if len(s) > max {
			return s[:max] + "…[truncated]"
		}
		return s
	case time.Time:
		return x.Format(time.RFC3339)
	case string:
		if len(x) > max {
			return x[:max] + "…[truncated]"
		}
		return x
	default:
		s := fmt.Sprint(x)
		if len(s) > max {
			return s[:max] + "…[truncated]"
		}
		return s
	}
}

func quoteDBIdent(dbType, name string) string {
	if dbType == "mysql" {
		return "`" + strings.ReplaceAll(name, "`", "``") + "`"
	}
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

func dbConnError(err error, dbType string) string {
	if err == nil {
		return ""
	}
	low := strings.ToLower(err.Error())
	switch {
	case strings.Contains(low, "access denied") || strings.Contains(low, "password authentication failed"):
		return "认证失败：用户名/密码错误或无权限"
	case strings.Contains(low, "connection refused") || strings.Contains(low, "no such host") ||
		strings.Contains(low, "i/o timeout") || strings.Contains(low, "connect: connection"):
		return "连接失败：host/port 不可达；隔离内网先建隧道"
	case strings.Contains(low, "unknown database") || strings.Contains(low, "does not exist"):
		return "target_db 不存在"
	default:
		return fmt.Sprintf("%s 连接失败：%v", dbType, err)
	}
}
