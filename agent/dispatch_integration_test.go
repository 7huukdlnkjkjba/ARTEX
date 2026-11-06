package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// 派单筛选 + 自动拉黑的落库集成测试（PG 不可用时自动 skip）。
// 覆盖：404/412 连续两次 → 事实标 negated → add_intent 硬拒；
// 静态资源 → add_intent 硬拒；高价值端点省略 priority → 自动定档。
func TestAddIntentDispatchGuard(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTaskWithOptions(fmt.Sprintf("dispatch-guard-%s", t.Name()), "dispatch guard integration", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.DeleteTask(task.ID) }()

	ts := NewToolSet(d.Exploration(task.ExplorationID), "worker-dispatch")
	ts.SetAssetStore(d.Assets(), d.Companies())
	ts.SetTaskID(task.ID)

	insertOne := func(item map[string]any) int64 {
		t.Helper()
		out := callInsertAssets(t, ts, map[string]any{"assets": []any{item}})
		raw, _ := json.Marshal(out["results"])
		var rs []struct {
			ID int64 `json:"id"`
		}
		if err := json.Unmarshal(raw, &rs); err != nil || len(rs) == 0 || rs[0].ID <= 0 {
			t.Fatalf("insert_assets 未返回 id: %v raw=%s", err, raw)
		}
		return rs[0].ID
	}

	planner := NewToolSet(ts.ts, "planner")
	planner.SetAssetStore(d.Assets(), d.Companies())
	planner.SetTaskID(task.ID)
	callIntent := func(input string) string {
		t.Helper()
		res, err := planner.addIntent().Call(context.Background(), json.RawMessage(input), nil)
		if err != nil {
			t.Fatalf("add_intent call: %v", err)
		}
		return res.Flatten()
	}

	// 1) 同一 endpoint 连续两次 404 → 自动拉黑，add_intent 拒派。
	apiID := insertOne(map[string]any{
		"type":   "endpoint",
		"url":    "https://dispatch.example.com/api/v1/user?id=1",
		"method": "GET",
		"params": []any{map[string]any{"location": "query", "name": "id", "value": "1"}},
	})
	rec := ts.recordFact()
	for i := 0; i < NegationRepeats; i++ {
		text := callFactTool(t, rec, fmt.Sprintf(`{"summary":"探测 /api/v1/user 返回 404，接口不存在","detail":"GET https://dispatch.example.com/api/v1/user?id=1","evidence":"GET /api/v1/user?id=1 -> 404","asset_ids":[%d]}`, apiID))
		if i == NegationRepeats-1 && !strings.Contains(text, "已标记否定") {
			t.Fatalf("第 %d 次 404 后应提示已拉黑，got %q", i+1, text)
		}
	}
	blocked := callIntent(fmt.Sprintf(`{"summary":"继续枚举 /api/v1/user 的参数","asset_ids":[%d]}`, apiID))
	if !strings.Contains(blocked, "已否定") && !strings.Contains(blocked, "拒绝派发") {
		t.Fatalf("已否定目标应被拒派，got %q", blocked)
	}

	// 2) 静态资源 → add_intent 直接跳过。
	staticID := insertOne(map[string]any{
		"type":        "service",
		"url":         "https://dispatch.example.com/static/app.js",
		"status_code": 200,
	})
	staticMsg := callIntent(fmt.Sprintf(`{"summary":"测试这个 JS 的接口","asset_ids":[%d]}`, staticID))
	if !strings.Contains(staticMsg, "静态资源") {
		t.Fatalf("静态资源应被跳过，got %q", staticMsg)
	}

	// 3) 高价值端点省略 priority → 按端点评分自动定档。
	freshID := insertOne(map[string]any{
		"type":   "endpoint",
		"url":    "https://dispatch.example.com/api/v1/order?id=9",
		"method": "POST",
		"params": []any{map[string]any{"location": "query", "name": "id", "value": "9"}},
	})
	autoMsg := callIntent(fmt.Sprintf(`{"summary":"测试 /api/v1/order 的越权","asset_ids":[%d]}`, freshID))
	if !strings.Contains(autoMsg, "intent created") || !strings.Contains(autoMsg, "自动优先级") {
		t.Fatalf("省略 priority 时应自动定档，got %q", autoMsg)
	}

	// 4) graph_overview 的 dispatch 块与 list_assets 标注应带上评分。
	overview := planner.graphOverviewData()
	disp, ok := overview["dispatch"].(map[string]any)
	if !ok {
		t.Fatalf("graph_overview 缺 dispatch 块: %#v", overview)
	}
	targets, ok := disp["targets"].([]map[string]any)
	if !ok || len(targets) == 0 {
		t.Fatalf("dispatch.targets 为空: %#v", disp)
	}
	found := false
	for _, tg := range targets {
		if id, _ := tg["asset_id"].(int64); id == freshID {
			found = true
		}
	}
	if !found {
		t.Fatalf("新端点应进入 dispatch.targets: %#v", targets)
	}
	listed := callReadJSON(t, planner.listAssets(), fmt.Sprintf(`{"id":%d}`, freshID))
	if !strings.Contains(fmt.Sprint(listed), "dispatch_score") {
		t.Fatalf("list_assets 应带派发评分: %#v", listed)
	}

	// 5) 历史 fact 没有直接锚点：从产生它的单锚点意图回填，同样拉黑。
	legacyID := insertOne(map[string]any{
		"type":   "endpoint",
		"url":    "https://dispatch.example.com/legacy/manage",
		"method": "GET",
	})
	legacyIntent, err := planner.addOneIntent(intentItem{
		Summary:  "枚举 legacy 目录",
		AssetIDs: []json.RawMessage{json.RawMessage(fmt.Sprintf("%d", legacyID))},
	})
	if err != nil {
		t.Fatalf("创建 legacy 意图: %v", err)
	}
	for i := 0; i < NegationRepeats; i++ {
		factID, err := ts.ts.AddNode(db.KindFact, map[string]any{
			"summary":    "探测 /legacy/manage 返回 404",
			"evidence":   "GET /legacy/manage -> 404",
			"confidence": "observed",
		}, 5, "confirmed", "worker", nil) // 故意不带锚点
		if err != nil {
			t.Fatal(err)
		}
		if err := ts.ts.Link(legacyIntent, db.RelYields, factID); err != nil {
			t.Fatal(err)
		}
	}
	legacyMsg := callIntent(fmt.Sprintf(`{"summary":"继续枚举 legacy 目录","asset_ids":[%d]}`, legacyID))
	if !strings.Contains(legacyMsg, "已否定") && !strings.Contains(legacyMsg, "拒绝派发") {
		t.Fatalf("历史无锚点 fact 也应被回填拉黑，got %q", legacyMsg)
	}
}
