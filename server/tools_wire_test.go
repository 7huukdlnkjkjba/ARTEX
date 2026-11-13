package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

func names(tools []actool.CoreTool) map[string]actool.CoreTool {
	m := map[string]actool.CoreTool{}
	for _, t := range tools {
		m[t.Name()] = t
	}
	return m
}

// TestWireTools verifies end-to-end against the live dev PG: wireTools seeds the
// catalog, ToolResolve keeps record_fact for worker but drops it for planner (not
// bound), and an edited description + injected default flow through.
func TestWireTools(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	// Register close as a cleanup, not a defer: t.Cleanup functions run LIFO AFTER
	// the test body, while a defer would close the pool BEFORE the restore cleanup
	// below and make that restore silently fail (how the dev DB got stuck on
	// "EDITED DESC" once).
	t.Cleanup(func() { _ = pg.Close() })

	wireTools(pg, nil) // nil domainReg: test only covers filter/decoration, not injection
	t.Cleanup(func() { agent.ToolResolve = nil })
	// Prevent interactive-shell Bash decoration: if the worker agent has
	// interactive_shell=true in the DB, ToolResolve would append a note to
	// Bash's description. Disable that for this test so the undecorated
	// pass-through assertion holds regardless of DB state.
	t.Setenv("AGENT_CORE_DISABLE_INTERACTIVE_SHELL", "1")

	// Seeding populated the catalog.
	rf, err := pg.GetTool("record_fact")
	if err != nil || rf == nil {
		t.Fatalf("record_fact not seeded: %v", err)
	}

	// Build a base as the worker does: its domain tools + defaults, resolved for
	// "worker" then for "planner".
	ts := agent.NewToolSet(nil, "")
	base := append(ts.WorkerTools(), actool.DefaultTools()...)
	ctx := context.Background()

	worker := names(agent.ToolResolve(ctx, "worker", base))
	if _, ok := worker["record_fact"]; !ok {
		t.Error("worker lost record_fact")
	}
	// SDK generic tools aren't seeded → ToolResolve passes them through, but Bash
	// now carries two code-owned additions: the real-shell note (Windows only) and
	// the toolchain gate (worker has recon_http etc.). Assert the gate is present
	// and the original behavior is preserved.
	if bash, ok := worker["Bash"]; !ok {
		t.Error("worker lost Bash (should be kept)")
	} else {
		if !strings.Contains(bash.Description(), "工具闸门") {
			t.Errorf("Bash should carry the toolchain gate note, got %q", bash.Description())
		}
		props, _ := bash.InputSchema()["properties"].(map[string]any)
		if _, ok := props["override_reason"]; !ok {
			t.Error("gated Bash must advertise override_reason")
		}
		// End-to-end enforcement: a hand-rolled curl must be refused by the
		// resolved tool, naming the platform replacement. This is the behavior
		// that turns "tools exist but are never called" into "use the tool".
		res, err := bash.Call(ctx, json.RawMessage(`{"command":"curl -s http://example.com/"}`), nil)
		if err != nil {
			t.Fatalf("Bash call returned go error: %v", err)
		}
		if !res.IsError || !strings.Contains(res.Flatten(), "recon_http") {
			t.Fatalf("curl should be routed to recon_http, got isError=%v %q", res.IsError, res.Flatten())
		}
	}
	// planner is not bound to record_fact → resolving a base that contains it drops it.
	planner := names(agent.ToolResolve(ctx, "planner", base))
	if _, ok := planner["record_fact"]; ok {
		t.Error("planner should not get record_fact (not bound)")
	}

	// Edit description + add a default to a scalar param, then confirm the resolved
	// worker tool reflects both. Restore the CODE default afterwards (not the
	// pre-test snapshot: if a previous interrupted run left this row dirty, the
	// snapshot would faithfully preserve the dirt).
	t.Cleanup(func() {
		for _, s := range agent.BuiltinToolSeeds() {
			if s.Key == rf.Key {
				schema, _ := json.Marshal(s.Schema)
				agents, _ := json.Marshal(s.Agents)
				_ = pg.UpsertToolForce(s.Key, s.Desc, schema, agents)
			}
		}
	})
	var schema map[string]any
	_ = json.Unmarshal(rf.Schema, &schema)
	if props, ok := schema["properties"].(map[string]any); ok {
		if conf, ok := props["confidence"].(map[string]any); ok {
			conf["default"] = "inferred"
		}
	}
	edited := mustJSON(schema)
	if err := pg.UpdateTool(rf.Key, "EDITED DESC", edited, mustJSON([]string{"worker"}), true); err != nil {
		t.Fatal(err)
	}

	worker2 := names(agent.ToolResolve(ctx, "worker", base))
	got := worker2["record_fact"]
	if got == nil {
		t.Fatal("record_fact missing after edit")
	}
	if got.Description() != "EDITED DESC" {
		t.Errorf("description = %q, want EDITED DESC", got.Description())
	}
	// Default injection: omit confidence → handler input should carry the default.
	// We can't run the real handler (nil store), but InputSchema must show the default.
	sc := got.InputSchema()
	props := sc["properties"].(map[string]any)
	conf := props["confidence"].(map[string]any)
	if conf["default"] != "inferred" {
		t.Errorf("confidence.default = %v, want inferred", conf["default"])
	}
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
