package agent

import (
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
)

type scopeStoreStub struct{ rows []db.TaskScope }

func (s scopeStoreStub) ListTaskScope(int64) ([]db.TaskScope, error) { return s.rows, nil }

// TestMainAgentScopeExemption pins the boundary split: the main agent's ToolSet
// runs with the scope hard stop off (human interface, operator owns the target
// decision), while an unmodified ToolSet — worker/planner — stays fail-closed.
func TestMainAgentScopeExemption(t *testing.T) {
	guard.SetScopeStore(scopeStoreStub{rows: []db.TaskScope{
		{Kind: "root_domain", Domain: "in.example"},
	}})
	t.Cleanup(func() { guard.SetScopeStore(nil) })

	// 独占 task id，避免与其它用例共用 scope 缓存（TTL 30s）。
	const taskID = int64(987654321)

	strict := NewToolSet(nil, "worker")
	strict.SetTaskID(taskID)
	if err := strict.assertInScope("out.example"); err == nil {
		t.Fatal("worker ToolSet must deny a host outside the registered scope")
	}

	main := NewToolSet(nil, "human")
	main.SetTaskID(taskID)
	main.SetScopeEnforcement(false)
	if err := main.assertInScope("out.example"); err != nil {
		t.Fatalf("main agent must be exempt from the scope hard stop, got %v", err)
	}
}
