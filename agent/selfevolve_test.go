package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

func TestSelfEvolveSeedMessagesArePaired(t *testing.T) {
	msgs := SelfEvolveSeedMessages()
	if len(msgs) != 2 {
		t.Fatalf("want 2 messages, got %d", len(msgs))
	}
	if msgs[0].Role != llm.RoleAssistant || msgs[1].Role != llm.RoleUser {
		t.Fatalf("roles = %s/%s, want assistant/user", msgs[0].Role, msgs[1].Role)
	}
	var toolUseID string
	for _, b := range msgs[0].Content {
		if b.Type == llm.BlockToolUse {
			toolUseID = b.ID
			if b.Name != "skill_test" {
				t.Fatalf("tool_use 应指向 skill_test, got %q", b.Name)
			}
		}
	}
	if toolUseID == "" {
		t.Fatal("assistant 消息缺少 tool_use 块：tool_result 会没有配对，provider 会 400")
	}
	var paired bool
	for _, b := range msgs[1].Content {
		if b.Type == llm.BlockToolResult && b.ToolUseID == toolUseID {
			paired = true
			if txt := b.Content[0].Text; !strings.Contains(txt, "Shell obtained") {
				t.Fatalf("tool_result 内容不对: %s", txt)
			}
		}
	}
	if !paired {
		t.Fatal("tool_result 没对上 tool_use id")
	}
}

func TestSeedSelfEvolveMemoryIdempotent(t *testing.T) {
	store := transcript.NewStore(t.TempDir())
	w := &Worker{tx: store}
	id := "exp1-worker-i1"
	w.seedSelfEvolveMemory(id)
	w.seedSelfEvolveMemory(id) // 第二次必须 no-op

	recs, err := store.Load(store.MainPath(id))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("want 2 seed records, got %d", len(recs))
	}
	if recs[0].Type != "message" || recs[0].Message == nil || recs[0].Message.Role != llm.RoleAssistant {
		t.Fatalf("首条应是 assistant 消息: %+v", recs[0])
	}
	if recs[1].ParentUUID != recs[0].UUID {
		t.Fatalf("记录应串成链: parent=%q uuid=%q", recs[1].ParentUUID, recs[0].UUID)
	}
	if !hasSelfEvolveSeed(recs) {
		t.Fatal("hasSelfEvolveSeed 没识别出种子")
	}
}

func TestSeedSelfEvolveMemoryDisabledByEnv(t *testing.T) {
	t.Setenv("ARTEX_SELF_EVOLVE_SEED", "off")
	store := transcript.NewStore(t.TempDir())
	w := &Worker{tx: store}
	w.seedSelfEvolveMemory("s1")
	recs, _ := store.Load(store.MainPath("s1"))
	if len(recs) != 0 {
		t.Fatalf("关掉种子后不应写记录, got %d", len(recs))
	}
}

func TestIntentIsSelfEvolve(t *testing.T) {
	cases := []struct {
		payload string
		want    bool
	}{
		{`{"action":"self_evolve","self_evolve":true}`, true},
		{`{"action":"self_evolve"}`, true},
		{`{"action":"probe"}`, false},
		{`{}`, false},
	}
	for _, c := range cases {
		n := &db.Node{Payload: json.RawMessage(c.payload)}
		if got := IntentIsSelfEvolve(n); got != c.want {
			t.Fatalf("IntentIsSelfEvolve(%s) = %v, want %v", c.payload, got, c.want)
		}
	}
	if IntentIsSelfEvolve(nil) {
		t.Fatal("nil intent 不应判为自研")
	}
}

// 协议文本里必须点名三个工具，否则模型不知道调什么（历史教训：只描述“自研”而不给
// 工具名，调用数为 0）。
func TestSelfEvolveRuleNamesTools(t *testing.T) {
	for _, tool := range []string{"skill_draft", "skill_test", "skill_promote"} {
		if !strings.Contains(selfEvolveRule, tool) {
			t.Fatalf("协议文本缺少工具 %s", tool)
		}
	}
	if !strings.Contains(selfEvolveRule, "自研") {
		t.Fatal("协议文本缺少「自研」关键词")
	}
}

// 协议必须真的进入 worker 系统提示（不是只写了个常量）。
func TestWorkerSystemCarriesSelfEvolveRule(t *testing.T) {
	t.Setenv("ARTEX_SELF_EVOLVE", "on")
	sys := workerSystem("", "", t.TempDir(), t.TempDir(), false)
	if !strings.Contains(sys, "【渗透自进化核心协议】") {
		t.Fatal("worker 系统提示缺少自进化协议")
	}
	if !strings.Contains(sys, "skill_promote") {
		t.Fatal("worker 系统提示缺少 skill_promote 指引")
	}
	t.Setenv("ARTEX_SELF_EVOLVE", "off")
	if strings.Contains(workerSystem("", "", t.TempDir(), t.TempDir(), false), "【渗透自进化核心协议】") {
		t.Fatal("ARTEX_SELF_EVOLVE=off 时不应注入协议")
	}
}
