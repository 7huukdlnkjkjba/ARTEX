package agent

import (
	"context"
	"fmt"
)

// SessionBudget is the money left for one vulnerability-hunting session (a task),
// as resolved by the engine right before a planner round / worker run. It rides
// on the run context so the prompt builders can tell the model how much budget is
// left without threading a new parameter through every call site.
//
// LimitCNY <= 0 means "no budget": the note is omitted entirely, preserving the
// pre-budget prompt byte-for-byte.
type SessionBudget struct {
	SpentCNY float64
	LimitCNY float64
}

// Enabled reports whether a budget is configured.
func (b SessionBudget) Enabled() bool { return b.LimitCNY > 0 }

// RemainingCNY is the budget minus spend, floored at 0.
func (b SessionBudget) RemainingCNY() float64 {
	if left := b.LimitCNY - b.SpentCNY; left > 0 {
		return left
	}
	return 0
}

// UsedPct is the integer percentage already spent (0..100).
func (b SessionBudget) UsedPct() int {
	if !b.Enabled() {
		return 0
	}
	pct := int(b.SpentCNY / b.LimitCNY * 100)
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return pct
}

// Note is the compact prompt block injected into the planner/worker input. It is
// deliberately short: it is re-sent with every round, so a verbose warning would
// itself cost tokens. Two lines of Chinese ≈ 60–80 tokens.
func (b SessionBudget) Note() string {
	if !b.Enabled() {
		return ""
	}
	return fmt.Sprintf(
		"【本次会话模型预算】上限 ¥%.2f，已用 ¥%.2f（%d%%），剩余 ¥%.2f。预算用尽后系统会强制停止新的模型调用——优先推进最可能出结果的方向，让 worker 尽早写回，别把预算耗在重复侦察或低价值枚举上。",
		b.LimitCNY, b.SpentCNY, b.UsedPct(), b.RemainingCNY())
}

type sessionBudgetKey struct{}

// WithSessionBudget attaches a resolved budget snapshot to a run context.
func WithSessionBudget(ctx context.Context, b SessionBudget) context.Context {
	if !b.Enabled() {
		return ctx
	}
	return context.WithValue(ctx, sessionBudgetKey{}, b)
}

// sessionBudgetFrom returns the budget snapshot attached by the engine, if any.
func sessionBudgetFrom(ctx context.Context) (SessionBudget, bool) {
	if ctx == nil {
		return SessionBudget{}, false
	}
	b, ok := ctx.Value(sessionBudgetKey{}).(SessionBudget)
	return b, ok && b.Enabled()
}

// sessionBudgetNote renders the note for a run context, or "" when absent.
func sessionBudgetNote(ctx context.Context) string {
	b, ok := sessionBudgetFrom(ctx)
	if !ok {
		return ""
	}
	return b.Note()
}
