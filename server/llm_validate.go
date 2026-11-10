package server

import (
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/agent"
)

// validateAnthropicEndpoint guards the one configuration trap that silently
// sends traffic to the wrong vendor: an Anthropic-format profile with an empty
// Base URL. Empty means https://api.anthropic.com — correct for Claude, wrong
// for every third-party model that merely speaks the Anthropic wire format.
// Such requests leave for Anthropic and come back as 403 forbidden
// "Request not allowed" (Anthropic's unsupported-region response), which looks
// like a network outage instead of the configuration mistake it is.
//
// Vendors with a published Anthropic-compatible endpoint are auto-mapped by
// agent.ConfigFrom (see DefaultAnthropicBaseURL), so they pass validation; only
// an unrecognized non-Claude model is rejected with an actionable message.
func validateAnthropicEndpoint(format, model, baseURL string) error {
	if !strings.EqualFold(strings.TrimSpace(format), "anthropic") || strings.TrimSpace(baseURL) != "" {
		return nil
	}
	m := strings.TrimSpace(model)
	if m == "" || strings.HasPrefix(strings.ToLower(m), "claude") {
		return nil
	}
	if agent.DefaultAnthropicBaseURL(m) != "" {
		return nil // known vendor: ConfigFrom fills in the official endpoint
	}
	return fmt.Errorf("模型 %q 不是 Claude 模型，但 Base URL 为空：Anthropic 格式在 Base URL 为空时会默认请求 https://api.anthropic.com，第三方模型会被以 403 \"Request not allowed\" 拒绝。请填写服务商的 Anthropic 兼容端点（例如 DeepSeek：https://api.deepseek.com/anthropic，模型 deepseek-chat），或把格式改为 OpenAI 兼容", m)
}
