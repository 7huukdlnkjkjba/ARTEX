package agent

import (
	"context"
	"fmt"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

type MainAgent struct {
	findingRecorder FindingRecorder
	prov            llm.Provider
	model           string
	tx              *transcript.Store
	window          int
	windowFn        func() int
	maxTurns        int
	proxyAddr       string
	proxyCACert     string
	webSearch       WebSearchOpts
	workDir         string
	steerWork       func(intentID int64, msg string) error
	killWork        func(intentID int64) error
	nonStreamingFn  func() bool
	noaEnabledFn    func() bool
	maxTokensFn     func() int
}

func (m *MainAgent) SetNoaEnabled(fn func() bool) { m.noaEnabledFn = fn }

func (m *MainAgent) SetNonStreaming(fn func() bool) { m.nonStreamingFn = fn }

func (m *MainAgent) nonStreaming() bool { return m.nonStreamingFn != nil && m.nonStreamingFn() }

func (m *MainAgent) SetMaxTokens(fn func() int) { m.maxTokensFn = fn }

func (m *MainAgent) maxTokens() int {
	if m.maxTokensFn == nil {
		return 0
	}
	return m.maxTokensFn()
}

func NewMainAgent(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int) *MainAgent {
	return &MainAgent{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns}
}

func (m *MainAgent) SetCompactionWindowResolver(fn func() int) { m.windowFn = fn }

func (m *MainAgent) compactionWindow() int {
	if m.windowFn != nil {
		return m.windowFn()
	}
	return m.window
}

func (m *MainAgent) SetProxy(addr, caCert string) { m.proxyAddr, m.proxyCACert = addr, caCert }

func (m *MainAgent) SetWebSearch(o WebSearchOpts) { m.webSearch = o }

func (m *MainAgent) SetSteerWork(fn func(intentID int64, msg string) error) { m.steerWork = fn }

func (m *MainAgent) SetKillWork(fn func(intentID int64) error) { m.killWork = fn }

const mainAgentDefaultTmpl = `你是一个骇客渗透测试系统的"主 agent"，是人类操作员的接口。你不亲自探索、也不自主连续生成意图（那是规划者的工作）。你的职责：

1. 观察：用 graph_overview / list_findings / list_facts / list_assets / get_worker_output 回答人关于当前进展的问题。
2. 操舵（把人的意图落到系统）：
   - 人想"改方向/强调某类漏洞/重点某区域" → 用 add_hint 写提示（规划者下次会读到）。
   - 人想"立刻测某个具体目标" → 用 add_intent 直接注入一条高优先级意图（priority 8-10）。系统会自动把已完成的任务拉回运行态、让 worker 领这条意图执行，跑完即回到已完成状态。
     **当任务目标已全部达成时**（graph_overview 里 goals 均为 met）：下发前先判断这条意图背后是否隐含一个"新的、要达成的结果"。若隐含，用一句话把你猜测的目标复述给人，并**反问是否要登记为正式目标**——人要 → 用 set_goals 登记（任务随后进入常规规划、规划者会自主往下推进）；人不要 / 只是想临时探一下 → 只 add_intent 下发这一条，worker 执行完任务即回到已完成状态（不会自主继续）。若这条意图明显只是一次性查证、不隐含新目标，直接 add_intent 即可，不必每次都问。
   - 人想"对某条正在运行的意图(work)实时纠偏（别再走 X、聚焦 Y）" → 用 steer_work（不打断、不丢已有进展，worker 下一步动作前生效）；先用 get_worker_output 看它在干嘛。方向整个错了则改用 add_intent 另下新意图。
   - 人想"新增一个要达成的最终目标" → 用 set_goals 增补目标。系统会把该目标写入任务图并**自动把已完成/暂停的任务拉回运行态继续跑**（规划者随后会据此重新判断是否达成），无需人工再点恢复。
   - 人想"增/改测试约束（允许/禁止某类操作，如『仅测当前端口』『禁止爆破』『只做被动侦察』）" → 用 set_constraints 登记（type=allow 允许 / type=deny 禁止）。约束会在下一轮规划时注入 planner/worker 的提示词以框定探索边界；也可在总览「约束管理」里增删改。
3. 用人话简洁回复，说明你做了什么。

当前任务目标：{{.Goal}}

不要编造发现；只根据工具返回的真实数据回答。`

func mainAgentSystem(goal, dataDir, workDir string) string {
	body := renderSystem("mainagent", mainAgentDefaultTmpl, MainVars{Goal: goal, DataDir: dataDir, Now: nowStr()})
	return body + artifactSpec(workDir)
}

func (m *MainAgent) Chat(ctx context.Context, taskID int64, mainSeg int, as *db.AssetStore, ts *db.ExplorationStore, goal, message string, emit func(db.Activity), notify, resume func(), notifyGoal, notifyHint func([]string)) (string, error) {
	tsx := NewToolSet(ts, "human")
	tsx.SetFindingRecorder(m.findingRecorder)
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetTaskID(taskID)
	tsx.SetScopeEnforcement(false)
	tsx.SetCoverageEnabled(as == nil || as.CoverageEnabled(taskID))
	tsx.SetNotify(notify)
	tsx.SetResumeTask(resume)
	tsx.SetNotifyGoal(notifyGoal)
	tsx.SetNotifyHint(notifyHint)
	tsx.steerWork = m.steerWork
	tsx.killWork = m.killWork
	base := append(tsx.DropCoverageTools(tsx.MainAgentTools()), actool.DefaultTools()...)
	ctx = WithRunInfo(ctx, RunInfo{TaskID: taskID, ExplorationID: explorationID(ts)})
	tools, def, cleanup := AugmentTools(ctx, "mainagent", base)
	defer cleanup()
	mainDir := ensureRunDir(m.workDir, taskID, 0)
	ctx = intercept.WithReviewWorkingDirectory(ctx, mainDir)
	system, boundary := deferredSystem(mainAgentSystem(goal, m.workDir, mainDir), def)
	opts := agentcore.Options{
		Provider:        m.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		EnableWebFetch:  true,
		WebFetchProxy:   m.proxyAddr,
		WebFetchCACert:  m.proxyCACert,
		EnableWebSearch:       m.webSearch.Enabled,
		WebSearchBackend:      m.webSearch.Backend,
		BraveSearchAPIKey:     m.webSearch.BraveKey,
		TavilySearchAPIKey:    m.webSearch.TavilyKey,
		DeepSeekSearchBaseURL: m.webSearch.DeepSeekBaseURL,
		DeepSeekSearchAPIKey:  m.webSearch.DeepSeekAPIKey,
		DeepSeekSearchModel:   m.webSearch.DeepSeekModel,
		WebSearchProxy:        m.webSearch.Proxy,
		BashEnv:               proxyEnv(m.proxyAddr, m.proxyCACert),
		WorkingDir:            mainDir,
		ToolOutputDir:         cmdOutDir(mainDir),
		MaxTurns:              m.maxTurns,
		Compaction:            compactionConfig(m.compactionWindow()),
		Todos:                 actool.NewTodoStore(),
		Settlement:   wrapupSettlement("mainagent", nil),
		NonStreaming: m.nonStreaming(),
		MaxTokens:    m.maxTokens(),
	}
	if m.tx != nil {
		opts.Transcript = m.tx
		opts.SessionID = fmt.Sprintf("exp%d-main", ts.ID())
		if mainSeg > 0 {
			opts.SessionID = fmt.Sprintf("exp%d-main-s%d", ts.ID(), mainSeg)
		}
	}
	noaSession := fmt.Sprintf("exp%d-main", ts.ID())
	if mainSeg > 0 {
		noaSession = fmt.Sprintf("exp%d-main-s%d", ts.ID(), mainSeg)
	}
	enableNoa(&opts, m.noaEnabledFn, m.workDir, noaSession, noaWarn(noaSession))
	ctx = attachSideCapture(ctx, &opts)
	s := agentcore.NewSession(opts)
	defer s.Close()
	if m.tx != nil {
		_ = s.Resume(opts.SessionID)
	}
	seedUnlockFromHistory(s.Messages(), def.UnlockSkill)
	text, _, err := captureRunSession(ctx, s, message, func(r db.Activity) {
		if emit != nil {
			r.Worker = "mainagent"
			emit(r)
		}
	})
	return text, err
}