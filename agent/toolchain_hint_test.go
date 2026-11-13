package agent

import (
	"encoding/json"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

func toolsNamed(names ...string) []actool.CoreTool {
	out := make([]actool.CoreTool, 0, len(names))
	for _, n := range names {
		out = append(out, fakeTool(n, nil))
	}
	return out
}

func TestToolRoutingHintJS(t *testing.T) {
	payload := json.RawMessage(`{"summary":"下载页面引用的 JS 并审计 DOM XSS / eval 用法"}`)
	built := toolsNamed("Bash", "web_audit", "recon_http", "scan_rustscan")
	got := ToolRoutingHint(payload, built)
	if !strings.Contains(got, "web_audit") {
		t.Fatalf("hint should recommend web_audit, got: %s", got)
	}
	if strings.Contains(got, "scan_rustscan") {
		t.Fatalf("hint should not recommend unrelated tools, got: %s", got)
	}
}

func TestToolRoutingHintFiltersUnavailable(t *testing.T) {
	payload := json.RawMessage(`{"summary":"对目标做 SQL 注入检测"}`)
	built := toolsNamed("Bash", "http_diff") // sqlmap_run 未绑定
	got := ToolRoutingHint(payload, built)
	if strings.Contains(got, "- `sqlmap_run`") {
		t.Fatalf("hint must not advertise an unbound tool: %s", got)
	}
	if !strings.Contains(got, "- `http_diff`") {
		t.Fatalf("hint should keep available http_diff: %s", got)
	}
}

func TestToolRoutingHintEmpty(t *testing.T) {
	if got := ToolRoutingHint(json.RawMessage(`{"summary":"做一个普通的只读检查"}`), toolsNamed("Bash")); got != "" {
		t.Fatalf("want empty hint, got: %s", got)
	}
}

func TestToolRoutingHeaderMentionsCoreTools(t *testing.T) {
	for _, want := range []string{"recon_http", "scan_rustscan", "web_audit", "report_finding_gated", "override_reason"} {
		if !strings.Contains(ToolRoutingHeader, want) {
			t.Errorf("ToolRoutingHeader missing %q", want)
		}
	}
}
