package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

func TestJoinSystemTrimsAndSkipsEmpty(t *testing.T) {
	got := joinSystem([]string{"  a  ", "", "   ", "b\n", "c"})
	if got != "a\n\nb\n\nc" {
		t.Fatalf("joinSystem = %q", got)
	}
	if joinSystem(nil) != "" {
		t.Fatal("空输入应为空串")
	}
}

func TestHasNonEmptyKey(t *testing.T) {
	cases := []struct {
		raw  string
		want bool
	}{
		{`null`, false},
		{`""`, false},
		{`   `, false},
		{`"x"`, true},
		{`0`, true},
		{`{"a":1}`, true},
	}
	for _, c := range cases {
		doc := map[string]json.RawMessage{"k": json.RawMessage(c.raw)}
		if got := hasNonEmptyKey(doc, "k"); got != c.want {
			t.Fatalf("hasNonEmptyKey(%s) = %v, want %v", c.raw, got, c.want)
		}
	}
	if hasNonEmptyKey(map[string]json.RawMessage{}, "k") {
		t.Fatal("缺失键应为 false")
	}
}

// 前缀是进程级常量：只构造一次，且 requestMessages 不能修改调用方的消息。
func TestActivationPreambleCachedAndPure(t *testing.T) {
	a := ActivationPreamble(wireKindOpenAI)
	b := ActivationPreamble(wireKindAnthropic)
	if len(a) == 0 || len(b) == 0 {
		t.Fatal("前缀不应为空")
	}
	if &a[0] != &b[0] {
		t.Fatal("前缀应复用同一份切片，而不是每次重建")
	}

	req := llm.CompletionRequest{Messages: []llm.Message{llm.UserText("hi")}}
	out := requestMessages(req, wireKindOpenAI)
	if len(out) != len(a)+1 {
		t.Fatalf("requestMessages 长度 = %d, want %d", len(out), len(a)+1)
	}
	if len(req.Messages) != 1 || req.Messages[0].Content[0].Text != "hi" {
		t.Fatal("requestMessages 不应修改入参")
	}
	// 前缀内容被共享：重复调用不能再追加一份。
	if got := requestMessages(req, wireKindOpenAI); len(got) != len(out) {
		t.Fatalf("重复调用长度变化: %d != %d", len(got), len(out))
	}
}

// rewriteRequestBody 只替换 messages 字段，其余字段（模型/工具/参数）原样保留。
func TestRewriteRequestBodyOpenAI(t *testing.T) {
	SetMessagePreamble(ActivationPreamble)
	t.Cleanup(func() { SetMessagePreamble(ActivationPreamble) })

	body := []byte(`{"model":"gpt-x","temperature":0.2,"messages":[{"role":"user","content":"old"}]}`)
	req := llm.CompletionRequest{
		System:   []string{"sys-a", " ", "sys-b"},
		Messages: []llm.Message{llm.UserText("new")},
	}
	out, changed, err := rewriteRequestBody(wireKindOpenAI, body, req)
	if err != nil || !changed {
		t.Fatalf("rewrite: changed=%v err=%v", changed, err)
	}
	var doc struct {
		Model       string            `json:"model"`
		Temperature float64           `json:"temperature"`
		Messages    []json.RawMessage `json:"messages"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Model != "gpt-x" || doc.Temperature != 0.2 {
		t.Fatalf("非 messages 字段被破坏: %+v", doc)
	}
	if len(doc.Messages) < 2 {
		t.Fatalf("messages 未重建: %s", out)
	}
	raw := string(out)
	if !strings.Contains(raw, "sys-a\\n\\nsys-b") {
		t.Fatalf("system 未合并进 messages: %s", raw)
	}
	if strings.Contains(raw, `"old"`) {
		t.Fatalf("旧 messages 仍然存在: %s", raw)
	}

	// 没有 messages 字段的请求体不重建。
	if _, changed, _ := rewriteRequestBody(wireKindOpenAI, []byte(`{"model":"x"}`), req); changed {
		t.Fatal("无 messages 字段不应改写")
	}
}
