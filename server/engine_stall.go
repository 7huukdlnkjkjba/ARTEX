package server

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// plannerStallRounds 是「连续多少轮规划没有任何新进展」后自动暂停任务的阈值。
// 触发条件同时要求：没有在跑的意图、frontier 里没有待领意图、图谱计数与上一轮
// 完全一致。正常的慢任务（worker 还在跑）不会被计入。
const plannerStallRounds = 3

// plannerStall 记录连续无进展的规划轮数。sig 是图谱快照（见 plannerProgressSig），
// 只要 intents/facts/assets/findings 任一计数变化就算有进展并重置。
type plannerStall struct {
	sig string
	n   int
}

// observe 喂入一轮的结果，返回是否达到暂停阈值。
// active=有在跑意图；open=frontier 待领意图数。两者任一非零都视为仍在推进。
func (s *plannerStall) observe(sig string, active bool, open int) bool {
	if active || open > 0 {
		s.sig, s.n = "", 0
		return false
	}
	if sig != s.sig {
		s.sig, s.n = sig, 1
		return false
	}
	s.n++
	return s.n >= plannerStallRounds
}

func (s *plannerStall) reset() { s.sig, s.n = "", 0 }

// plannerProgressSig 把探索图的计数拼成可比较的签名。统计失败返回空串——空串
// 在 observe 里仍会参与比较，但连续失败三轮也可能触发，故失败时返回唯一值更安全。
func plannerProgressSig(store *db.ExplorationStore) string {
	if store == nil {
		return ""
	}
	st, err := store.Stats()
	if err != nil {
		return "stats-error"
	}
	keys := make([]string, 0, len(st))
	for k := range st {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%d;", k, st[k])
	}
	if n, err := store.CountFinishedIntents(); err == nil {
		fmt.Fprintf(&b, "finished=%d", n)
	}
	return b.String()
}
