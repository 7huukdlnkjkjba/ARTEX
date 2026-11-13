package agent

// Provider 层的工具名清洗。
//
// 实战 transcript(exp473-worker-i3683,2026-11-12)里出现:
//   "name":"Bash<|channel|>"
//   "name":"LS<|channel|>commentary"
// 结果分别是 `Error: unknown tool "Bash<|channel|>"` 和一次无效调用——模型明明
// 选对了工具,却被网关/模型模板漏出的特殊 token 污染了函数名。对 agent 来说这是
// “工具不可靠”的直接反馈,会把它推回手搓路线。
//
// 这里在 Provider 组装处包一层:任何 ToolUseStart / Complete 返回的 tool_use block
// 都把 `<|...` 之后的模板标记切掉。只改名字、不动参数与内容;名字清洗后为空则保持
// 原样(让上层继续报 unknown tool,而不是静默丢调用)。

import (
	"context"
	"iter"
	"log"
	"strings"

	"github.com/Autumn-27/norma/llm"
)

// SanitizeToolName removes leaked chat-template tokens from a model-emitted tool
// name. Examples:
//
//	"Bash<|channel|>"          -> "Bash"
//	"LS<|channel|>commentary"  -> "LS"
//	"  Record  "               -> "Record"
//	"Bash"                     -> "Bash"
func SanitizeToolName(name string) string {
	orig := name
	name = strings.TrimSpace(name)
	if i := strings.Index(name, "<"); i >= 0 {
		name = name[:i]
	}
	// Full-width variants seen in some gateways.
	if i := strings.Index(name, "｜"); i >= 0 {
		name = name[:i]
	}
	name = strings.TrimSpace(name)
	// Tool names are [A-Za-z0-9_-]+ in practice; keep anything else out of the
	// registry lookup path.
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-', r == '.':
			b.WriteRune(r)
		}
	}
	clean := b.String()
	if clean == "" {
		return orig // let the harness surface the unknown tool instead of dropping it
	}
	if clean != orig {
		log.Printf("[llm] 清洗被模板标记污染的工具名: %q -> %q", orig, clean)
	}
	return clean
}

// sanitizingProvider wraps a Provider so every tool_use name is sanitized before
// the harness looks it up in the registry.
type sanitizingProvider struct{ inner llm.Provider }

// withToolNameSanitizer returns inner wrapped with name sanitization; nil passes
// through.
func withToolNameSanitizer(inner llm.Provider) llm.Provider {
	if inner == nil {
		return nil
	}
	return &sanitizingProvider{inner: inner}
}

func (p *sanitizingProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		for ev, err := range p.inner.Stream(ctx, req) {
			if ev.Type == llm.SEToolUseStart {
				ev.ToolName = SanitizeToolName(ev.ToolName)
			}
			if !yield(ev, err) {
				return
			}
			if err != nil {
				return
			}
		}
	}
}

func (p *sanitizingProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	msg, stop, usage, err := p.inner.Complete(ctx, req)
	if err != nil {
		return msg, stop, usage, err
	}
	for i := range msg.Content {
		if msg.Content[i].Type == llm.BlockToolUse {
			msg.Content[i].Name = SanitizeToolName(msg.Content[i].Name)
		}
	}
	return msg, stop, usage, nil
}
