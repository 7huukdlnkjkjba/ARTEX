package agent

import (
	"context"
	"iter"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

func TestSanitizeToolName(t *testing.T) {
	cases := map[string]string{
		"Bash":                    "Bash",
		"  Read  ":                "Read",
		"Bash<|channel|>":         "Bash",
		"LS<|channel|>commentary": "LS",
		"Bash<|tool▁call|>":       "Bash",
		"mcp__srv__list":          "mcp__srv__list",
		"中文":                      "中文", // no ASCII tool chars → keep original
	}
	for in, want := range cases {
		if got := SanitizeToolName(in); got != want {
			t.Errorf("SanitizeToolName(%q) = %q, want %q", in, got, want)
		}
	}
}

// fakeStreamProvider yields a fixed event sequence.
type fakeStreamProvider struct {
	events []llm.StreamEvent
	msg    llm.Message
}

func (f *fakeStreamProvider) Stream(_ context.Context, _ llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		for _, ev := range f.events {
			if !yield(ev, nil) {
				return
			}
		}
	}
}

func (f *fakeStreamProvider) Complete(_ context.Context, _ llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return f.msg, "tool_use", llm.Usage{}, nil
}

func TestSanitizerProviderStream(t *testing.T) {
	inner := &fakeStreamProvider{events: []llm.StreamEvent{
		{Type: llm.SEToolUseStart, ToolID: "1", ToolName: "Bash<|channel|>"},
		{Type: llm.SETextDelta, Text: "hi"},
	}}
	p := withToolNameSanitizer(inner)
	var got []string
	for ev, err := range p.Stream(context.Background(), llm.CompletionRequest{}) {
		if err != nil {
			t.Fatal(err)
		}
		if ev.Type == llm.SEToolUseStart {
			got = append(got, ev.ToolName)
		}
	}
	if len(got) != 1 || got[0] != "Bash" {
		t.Fatalf("stream tool names = %v, want [Bash]", got)
	}
}

func TestSanitizerProviderComplete(t *testing.T) {
	inner := &fakeStreamProvider{msg: llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
		{Type: llm.BlockToolUse, ID: "1", Name: "LS<|channel|>commentary", Input: []byte(`{}`)},
		{Type: llm.BlockText, Text: "ok"},
	}}}
	p := withToolNameSanitizer(inner)
	msg, _, _, err := p.Complete(context.Background(), llm.CompletionRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if msg.Content[0].Name != "LS" {
		t.Fatalf("complete tool name = %q, want LS", msg.Content[0].Name)
	}
}
