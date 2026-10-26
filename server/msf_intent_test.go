package server

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// 自动派发的意图可能被 worker 直接领取、中间没有 planner 轮次，所以 summary 必须
// 自带工具名、目标与失败分支；这里锁住这几项，防止后续改文案时把它改回"只说一句
// 方向"的普通意图。
func TestMSFIntentPayloadIsSelfContained(t *testing.T) {
	f := &db.DBFinding{ID: 42, Name: "Struts2 S2-045 RCE", VulnClass: "rce"}
	p := msfIntentPayload(f, "struts2", "10.0.0.7:8080")

	if got := p["msf_finding_id"]; got != int64(42) {
		t.Fatalf("msf_finding_id = %v, want 42", got)
	}
	if got := p["msf_target"]; got != "10.0.0.7:8080" {
		t.Fatalf("msf_target = %v", got)
	}
	if got := p["action"]; got != "msf_exploit" {
		t.Fatalf("action = %v", got)
	}
	summary, _ := p["summary"].(string)
	for _, want := range []string{"msf_plan", "msf_execute", "msf_next", "10.0.0.7:8080", "Struts2 S2-045 RCE"} {
		if !strings.Contains(summary, want) {
			t.Fatalf("summary 缺少 %q：%s", want, summary)
		}
	}
	// session_post 只是 msf_plan 里的命令清单字段，不是工具；文案不能再让 worker 去找它。
	if strings.Contains(summary, "session_post") {
		t.Fatalf("summary 不应引用不存在的 session_post 工具：%s", summary)
	}
}

func TestMSFIntentPayloadFallsBackToVulnClass(t *testing.T) {
	p := msfIntentPayload(&db.DBFinding{ID: 7, VulnClass: "lfi"}, "lfi", "10.0.0.8")
	summary, _ := p["summary"].(string)
	if !strings.Contains(summary, "「lfi」") {
		t.Fatalf("名称为空时应回退到漏洞类别：%s", summary)
	}
}
