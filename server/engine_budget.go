package server

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/cost"
	"github.com/Autumn-27/artex/db"
)

// 会话预算(¥)的任务级闸门。与"任务超时"共用同一套优雅收尾语义：
//
//	① 标记 settling → ② planner 不再规划 / worker 不再领新意图
//	③ 等在跑的执行 drain(有上限) → ④ 落 paused(可调高预算后继续)
//
// 已经在跑的 run 不硬杀：它们在下一次模型调用时会被 task_llm 的本地合成回合
// 结束掉（零成本），把已发现的事实/漏洞留在图里。这条路径与超时收尾的区别是：
// 预算耗尽后不再跑"终局规划轮"——那一轮本身也要花钱，会直接击穿上限。

// budgetState resolves the live config and the task's spend. over is true only
// when a budget is configured and spend has reached it.
func (e *Engine) budgetState(taskID string) (cfg cost.Config, spent float64, over bool) {
	if e == nil || e.m == nil || e.m.pg == nil || taskID == "" {
		return cost.Default(), 0, false
	}
	cfg = cost.Load(e.m.pg)
	if !cfg.Enabled() {
		return cfg, 0, false
	}
	totals, err := e.m.pg.TaskTokenTotals(taskID)
	if err != nil {
		log.Printf("[budget] task %s 读取 token 用量失败: %v", taskID, err)
		return cfg, 0, false
	}
	spent = cfg.Spend(totals)
	return cfg, spent, spent >= cfg.BudgetCNY
}

// BudgetReached starts the budget stop sequence exactly once per task. Safe to
// call from any goroutine, including inside an in-flight LLM call: the settle
// work is detached so the caller can finish its (now local) turn.
func (e *Engine) BudgetReached(taskID string) {
	if taskID == "" {
		return
	}
	if _, loaded := e.budgetHold.LoadOrStore(taskID, true); loaded {
		return
	}
	log.Printf("[budget] task %s 会话预算已用尽，进入收尾", taskID)

	e.deleteMu.RLock()
	if e.IsDeleting(taskID) {
		e.deleteMu.RUnlock()
		return
	}
	rt := e.registerTaskRoutines(context.Background(), taskID, 1)
	e.deleteMu.RUnlock()
	runTaskRoutine(rt, func(ctx context.Context) { e.settleBudget(ctx, taskID) })
}

// settleBudget drains in-flight work, then pauses the task. A pause (instead of a
// terminal status) keeps the exploration resumable: raise the budget in settings
// and press 继续, the task picks up from the frontier.
func (e *Engine) settleBudget(ctx context.Context, taskID string) {
	t, ok := e.m.Task(taskID)
	if !ok {
		e.budgetHold.Delete(taskID)
		return
	}
	if isTerminalStatus(t.lifecycleSnapshot().Status) {
		e.budgetHold.Delete(taskID)
		return
	}
	cfg, spent, over := e.budgetState(taskID)
	if !over {
		e.budgetHold.Delete(taskID) // budget was raised between the call and now
		return
	}

	if !e.markSettling(taskID) {
		return // a timeout settle already owns the sequence
	}
	e.emitActivity(t, db.Activity{Worker: "system", Kind: "text", Summary: fmt.Sprintf(
		"本次会话模型花费已达预算上限 ¥%.2f（当前约 ¥%.2f）。不再派发或领取新意图；正在运行的工作会先把已确认的结果写回。",
		cfg.BudgetCNY, spent)})

	// 等在跑的执行自然收尾。它们下一次调用模型时会拿到本地的"预算用尽"回合，
	// 因此 drain 通常只需要一个工具回合的时间。
	deadline := time.Now().Add(settleDrainGrace)
	for e.inflightCount(taskID) > 0 {
		if time.Now().After(deadline) {
			log.Printf("[budget] task %s drain 超时(%s)，硬取消在跑 run", taskID, settleDrainGrace)
			e.cancelExec(taskID, agent.AbortBudgetExceeded)
			break
		}
		select {
		case <-ctx.Done():
			return // 引擎关停/任务删除：不再落暂停态
		case <-time.After(300 * time.Millisecond):
		}
	}

	// drain 期间用户点了「继续」或把预算调高了：本次收尾作废，别再把它按回去。
	if !e.isSettling(taskID) {
		log.Printf("[budget] task %s 收尾期间已被继续，放弃本次暂停", taskID)
		e.budgetHold.Delete(taskID)
		return
	}
	if cfgNow, spentNow, stillOver := e.budgetState(taskID); !stillOver {
		log.Printf("[budget] task %s 预算已调高(当前约 ¥%.2f / 上限 ¥%.2f)，取消暂停",
			taskID, spentNow, cfgNow.BudgetCNY)
		e.settling.Delete(taskID)
		e.budgetHold.Delete(taskID)
		return
	}

	e.paused.Store(taskID, true)
	if err := e.m.ApplyTaskPause(taskID); err != nil {
		// 已被用户暂停/删除时这里会失败，保留原状态即可。
		log.Printf("[budget] task %s 落暂停态失败: %v", taskID, err)
	}
	e.emitActivity(t, db.Activity{Worker: "system", Kind: "text", Summary: fmt.Sprintf(
		"已按预算暂停：本次会话上限 ¥%.2f。调高「单次会话预算」(系统设置或 %s) 后可点继续，任务会从待领队列接着跑。",
		cfg.BudgetCNY, cost.EnvBudgetCNY)})
	log.Printf("[budget] task %s 已按预算暂停(上限 ¥%.2f)", taskID, cfg.BudgetCNY)
}

// clearBudgetHold releases the in-memory stop so a resumed task can run again.
// Called from Resume: if spend is still at the cap, the very first planner wake
// trips the gate again and the task pauses immediately — that is intended, the
// user must raise the budget to actually continue.
func (e *Engine) clearBudgetHold(taskID string) {
	e.budgetHold.Delete(taskID)
	if e.isSettling(taskID) {
		e.settling.Delete(taskID)
	}
}
