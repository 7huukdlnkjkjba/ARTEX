package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
)

// Built-in free model pool (FREE POOL).
//
// The pool is a curated list of free OpenAI-compatible sources. Every pool
// member is a normal llm_profiles row (so activation, failover, rate limiting,
// usage accounting and the edit sheet keep working unchanged) linked through
// free_pool_accounts. Enabling the pool probes the members, activates the first
// healthy one and turns on the existing LLM failover chain, so a rate-limited
// free source degrades into the next one instead of failing the task.
//
// Only keyless sources are seeded automatically. Keyed free tiers (OpenRouter
// free models, Groq/Gemini free quota) can be added from the UI with the
// operator's own key — the pool never ships shared credentials.

const settingFreePoolOn = "free_pool_enabled"

// freeSource is one curated free endpoint.
type freeSource struct {
	Key      string   `json:"key"`
	Name     string   `json:"name"`
	BaseURL  string   `json:"base_url"`
	Models   []string `json:"models"`
	Keyless  bool     `json:"keyless"`
	Tools    bool     `json:"tools"`
	DocsURL  string   `json:"docs_url"`
	Note     string   `json:"note"`
	RPS      float64  `json:"rps"` // 建议限速，0=不限
	RPM      float64  `json:"rpm"`
	ContextK int      `json:"context_k"`

	// EnvKey is the environment variable that already carries the operator's key
	// for this source, so an existing key is picked up without a UI round trip.
	EnvKey string `json:"-"`
	// Local marks a loopback endpoint: http is expected, and the source is seeded
	// only when something is actually listening on it.
	Local bool `json:"local,omitempty"`
}

// builtinFreeSources is the catalog. Order = activation preference.
//
// Every keyed entry is a vendor's own free tier: the operator brings their own
// key (or has it exported in the environment), and the pool only stores that
// key in its normal llm_profiles row. No shared or borrowed credentials.
func builtinFreeSources() []freeSource {
	return []freeSource{
		{
			Key:      "ollama",
			Name:     "本地 Ollama",
			BaseURL:  "http://127.0.0.1:11434/v1",
			Models:   []string{"qwen2.5:7b"},
			Keyless:  true,
			Tools:    true,
			DocsURL:  "https://ollama.com",
			Note:     "本机模型，完全免费且不出网；装了 Ollama 并 ollama pull 模型后自动入池",
			RPS:      0,
			RPM:      0,
			ContextK: 32,
			Local:    true,
		},
		{
			Key:      "pollinations",
			Name:     "Pollinations",
			BaseURL:  "https://text.pollinations.ai/openai",
			Models:   []string{"openai-fast"},
			Keyless:  true,
			Tools:    true,
			DocsURL:  "https://github.com/pollinations/pollinations",
			Note:     "匿名免费档，无需 Key；限 1 次/45 秒，填 pollen key 可提额，适合兜底",
			RPS:      0.02,
			RPM:      1.5,
			ContextK: 128,
		},
		{
			Key:      "openrouter",
			Name:     "OpenRouter",
			BaseURL:  "https://openrouter.ai/api/v1",
			Models:   []string{"deepseek/deepseek-r1:free"},
			Keyless:  false,
			Tools:    true,
			DocsURL:  "https://openrouter.ai/docs",
			Note:     "免费档模型带 :free 后缀，需自备 Key；每天有免费额度",
			RPS:      0.5,
			RPM:      30,
			ContextK: 128,
			EnvKey:   "OPENROUTER_API_KEY",
		},
		{
			Key:      "groq",
			Name:     "Groq",
			BaseURL:  "https://api.groq.com/openai/v1",
			Models:   []string{"llama-3.3-70b-versatile"},
			Keyless:  false,
			Tools:    true,
			DocsURL:  "https://console.groq.com/docs",
			Note:     "免费额度，需自备 Key；响应快，适合工具调用密集的步骤",
			RPS:      0.5,
			RPM:      30,
			ContextK: 128,
			EnvKey:   "GROQ_API_KEY",
		},
		{
			Key:      "gemini",
			Name:     "Google Gemini",
			BaseURL:  "https://generativelanguage.googleapis.com/v1beta/openai",
			Models:   []string{"gemini-2.0-flash"},
			Keyless:  false,
			Tools:    true,
			DocsURL:  "https://ai.google.dev/gemini-api/docs",
			Note:     "AI Studio 免费额度，需自备 Key（OpenAI 兼容端点）",
			RPS:      1,
			RPM:      30,
			ContextK: 128,
			EnvKey:   "GEMINI_API_KEY",
		},
		{
			Key:      "cerebras",
			Name:     "Cerebras",
			BaseURL:  "https://api.cerebras.ai/v1",
			Models:   []string{"llama-3.3-70b"},
			Keyless:  false,
			Tools:    true,
			DocsURL:  "https://inference-docs.cerebras.ai",
			Note:     "免费额度，需自备 Key；推理速度极快，适合工具调用回合",
			RPS:      1,
			RPM:      30,
			ContextK: 128,
			EnvKey:   "CEREBRAS_API_KEY",
		},
		{
			Key:      "mistral",
			Name:     "Mistral",
			BaseURL:  "https://api.mistral.ai/v1",
			Models:   []string{"mistral-small-latest"},
			Keyless:  false,
			Tools:    true,
			DocsURL:  "https://docs.mistral.ai",
			Note:     "免费 Experiment 档，需自备 Key；注意免费档的数据使用条款",
			RPS:      1,
			RPM:      60,
			ContextK: 128,
			EnvKey:   "MISTRAL_API_KEY",
		},
		{
			Key:      "nvidia",
			Name:     "NVIDIA NIM",
			BaseURL:  "https://integrate.api.nvidia.com/v1",
			Models:   []string{"meta/llama-3.3-70b-instruct"},
			Keyless:  false,
			Tools:    true,
			DocsURL:  "https://build.nvidia.com",
			Note:     "注册送免费额度，需自备 Key；模型多，适合当第二梯队",
			RPS:      0.5,
			RPM:      30,
			ContextK: 128,
			EnvKey:   "NVIDIA_API_KEY",
		},
		{
			Key:      "github-models",
			Name:     "GitHub Models",
			BaseURL:  "https://models.github.ai/inference",
			Models:   []string{"openai/gpt-4o-mini"},
			Keyless:  false,
			Tools:    true,
			DocsURL:  "https://docs.github.com/en/github-models",
			Note:     "用 GitHub PAT 当 Key，按账号给免费速率；额度小，适合轻量步骤",
			RPS:      0.5,
			RPM:      15,
			ContextK: 128,
			EnvKey:   "GITHUB_TOKEN",
		},
		{
			Key:      "together",
			Name:     "Together AI",
			BaseURL:  "https://api.together.xyz/v1",
			Models:   []string{"meta-llama/Llama-3.3-70B-Instruct-Turbo-Free"},
			Keyless:  false,
			Tools:    true,
			DocsURL:  "https://docs.together.ai",
			Note:     "带 -Free 后缀的模型免费，需自备 Key；并发有限",
			RPS:      0.5,
			RPM:      30,
			ContextK: 128,
			EnvKey:   "TOGETHER_API_KEY",
		},
		{
			Key:      "siliconflow",
			Name:     "硅基流动 SiliconFlow",
			BaseURL:  "https://api.siliconflow.cn/v1",
			Models:   []string{"Qwen/Qwen2.5-7B-Instruct"},
			Keyless:  false,
			Tools:    true,
			DocsURL:  "https://docs.siliconflow.cn",
			Note:     "部分小模型免费，需自备 Key；国内直连，延迟低",
			RPS:      1,
			RPM:      60,
			ContextK: 32,
			EnvKey:   "SILICONFLOW_API_KEY",
		},
		{
			Key:      "zai",
			Name:     "智谱 Z.ai",
			BaseURL:  "https://api.z.ai/api/paas/v4",
			Models:   []string{"glm-4.5-flash"},
			Keyless:  false,
			Tools:    true,
			DocsURL:  "https://docs.z.ai",
			Note:     "GLM Flash 系列免费，需自备 Key；中文场景表现好",
			RPS:      0.5,
			RPM:      30,
			ContextK: 128,
			EnvKey:   "ZAI_API_KEY",
		},
		{
			Key:      "modelscope",
			Name:     "魔搭 ModelScope",
			BaseURL:  "https://api-inference.modelscope.cn/v1",
			Models:   []string{"Qwen/Qwen2.5-7B-Instruct"},
			Keyless:  false,
			Tools:    false,
			DocsURL:  "https://modelscope.cn/docs",
			Note:     "每日免费调用额度，需自备 Key；工具调用支持有限，适合纯推理步骤",
			RPS:      0.5,
			RPM:      30,
			ContextK: 32,
			EnvKey:   "MODELSCOPE_API_KEY",
		},
		{
			Key:      "huggingface",
			Name:     "Hugging Face",
			BaseURL:  "https://router.huggingface.co/v1",
			Models:   []string{"meta-llama/Llama-3.1-8B-Instruct"},
			Keyless:  false,
			Tools:    false,
			DocsURL:  "https://huggingface.co/docs/inference-providers",
			Note:     "每月免费额度，需自备 HF Token；工具调用支持有限",
			RPS:      0.5,
			RPM:      30,
			ContextK: 32,
			EnvKey:   "HF_TOKEN",
		},
	}
}

func freeSourceByKey(key string) (freeSource, bool) {
	for _, s := range builtinFreeSources() {
		if s.Key == key {
			return s, true
		}
	}
	return freeSource{}, false
}

// freePoolAccountJSON is one pool member plus its live probe result.
type freePoolAccountJSON struct {
	db.FreePoolAccount
	SourceName string `json:"source_name"`
	Keyless    bool   `json:"keyless"`
	Tools      bool   `json:"tools"`
	CallsToday int    `json:"calls_today"`
	FailsToday int    `json:"fails_today"`
	Healthy    *bool  `json:"healthy,omitempty"`
	LatencyMS  int64  `json:"latency_ms,omitempty"`
	ProbeError string `json:"probe_error,omitempty"`
}

// probeFreeAccount sends one tiny chat completion at the source to prove it can
// actually answer (a /models 200 does not imply usable chat or tool calling).
func probeFreeAccount(src freeSource, apiKey, model string) (ok bool, latencyMS int64, errMsg string) {
	if model == "" {
		if len(src.Models) > 0 {
			model = src.Models[0]
		} else {
			model = "default"
		}
	}
	endpoint := strings.TrimRight(src.BaseURL, "/") + "/chat/completions"
	payload, _ := json.Marshal(map[string]any{
		"model":      model,
		"messages":   []map[string]string{{"role": "user", "content": "reply with OK"}},
		"max_tokens": 16,
		"stream":     false,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return false, 0, err.Error()
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, 0, "请求失败: " + err.Error()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	latency := time.Since(start).Milliseconds()
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(body))
		if len(msg) > 240 {
			msg = msg[:240]
		}
		return false, latency, fmt.Sprintf("API 返回 %d: %s", resp.StatusCode, msg)
	}
	if !bytes.Contains(body, []byte(`"choices"`)) {
		return false, latency, "响应不是 chat/completion: " + strings.TrimSpace(string(body[:min(len(body), 200)]))
	}
	return true, latency, ""
}

// profileNameForFreeAccount builds a stable, prefixed profile name so pool
// members stay recognizable in the LLM list and the usage ledger.
func profileNameForFreeAccount(src freeSource, existing []*db.LLMProfile, label string) string {
	base := "免费池·" + src.Name
	if label != "" {
		base += "｜" + label
	}
	seen := map[string]bool{}
	for _, p := range existing {
		seen[p.Name] = true
	}
	if !seen[base] {
		return base
	}
	for i := 2; ; i++ {
		cand := fmt.Sprintf("%s #%d", base, i)
		if !seen[cand] {
			return cand
		}
	}
}

// createFreePoolAccount persists the profile + pool link. Caller holds no lock;
// SaveProfile is safe for concurrent use.
func (s *Server) createFreePoolAccount(src freeSource, label, apiKey, model string) (*db.FreePoolAccount, error) {
	if model == "" && len(src.Models) > 0 {
		model = src.Models[0]
	}
	existing, err := s.m.pg.ListProfiles()
	if err != nil {
		return nil, err
	}
	name := profileNameForFreeAccount(src, existing, label)
	hint := "免费端点，无需 Key"
	if !src.Keyless || apiKey != "" {
		hint = "已填 Key"
	}
	// 远端免费端点仍要一个非空占位 Key：ARTEX 对「非本地且无 Key」的配置会
	// 判定为不可用（KeyOptional=false），而 Pollinations 这类端点会忽略
	// Authorization 头。
	storedKey := apiKey
	if storedKey == "" {
		storedKey = "free-pool"
	}
	profileID, err := s.m.pg.SaveProfile(&db.LLMProfile{
		Name:           name,
		Format:         "openai",
		Model:          model,
		BaseURL:        src.BaseURL,
		APIKey:         storedKey,
		APIKeyHint:     hint,
		RatePerSecond:  src.RPS,
		RatePerMinute:  src.RPM,
		ContextWindowK: src.ContextK,
		Streaming:      true,
		PoolExclude:    false,
	})
	if err != nil {
		return nil, err
	}
	if _, err := s.m.pg.AddFreePoolAccount(src.Key, label, profileID); err != nil {
		return nil, err
	}
	accounts, err := s.m.pg.ListFreePoolAccounts()
	if err != nil {
		return nil, err
	}
	for i := range accounts {
		if accounts[i].ProfileID == profileID {
			return &accounts[i], nil
		}
	}
	return nil, fmt.Errorf("free pool account for profile %d not found after insert", profileID)
}

// normalizeBaseURL makes "https://x/v1/" and "https://X/v1" comparable, so a
// pool source can find the operator's existing profile for the same endpoint.
func normalizeBaseURL(raw string) string {
	return strings.ToLower(strings.TrimRight(strings.TrimSpace(raw), "/"))
}

// sourceEnvKey returns the key that is already exported for this source. The
// pool never ships credentials, but re-typing a key that is already in the
// environment is pointless — vendored names are covered as aliases.
func sourceEnvKey(src freeSource) string {
	names := []string{src.EnvKey}
	switch src.Key {
	case "gemini":
		names = append(names, "GOOGLE_API_KEY")
	case "github-models":
		names = append(names, "GITHUB_MODELS_TOKEN")
	case "huggingface":
		names = append(names, "HUGGING_FACE_HUB_TOKEN")
	}
	for _, name := range names {
		if name == "" {
			continue
		}
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			return v
		}
	}
	return ""
}

// localEndpointUp reports whether something is actually listening on a loopback
// source, so a machine without Ollama does not get a permanently dead pool member.
func localEndpointUp(baseURL string) bool {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" {
		return false
	}
	addr := u.Host
	if !strings.Contains(addr, ":") {
		if u.Scheme == "https" {
			addr += ":443"
		} else {
			addr += ":80"
		}
	}
	conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// ensureFreePoolSeed fills the pool once per source: reuse an existing profile
// that already points at the same endpoint (so the operator's key is reused),
// else create the member when the source is keyless or its key is exported.
func (s *Server) ensureFreePoolSeed() {
	if s.m.pg == nil {
		return
	}
	accounts, err := s.m.pg.ListFreePoolAccounts()
	if err != nil {
		log.Printf("[free-pool] seed: list: %v", err)
		return
	}
	have := map[string]bool{}
	for _, a := range accounts {
		have[a.Source] = true
	}

	// 已有配置优先复用：同一个 BaseURL 的普通 LLM 配置往往已经填过 Key，
	// 免费池只补一条成员链接，不再让操作员在池子里重填一遍。
	profiles, err := s.m.pg.ListProfiles()
	if err != nil {
		log.Printf("[free-pool] seed: profiles: %v", err)
		profiles = nil
	}
	byBase := map[string]*db.LLMProfile{}
	for _, p := range profiles {
		if p.BaseURL != "" {
			byBase[normalizeBaseURL(p.BaseURL)] = p
		}
	}

	for _, src := range builtinFreeSources() {
		if have[src.Key] {
			continue
		}
		if src.Local && !localEndpointUp(src.BaseURL) {
			continue
		}
		if p, ok := byBase[normalizeBaseURL(src.BaseURL)]; ok && (src.Keyless || p.APIKey != "") {
			if _, err := s.m.pg.AddFreePoolAccount(src.Key, "", p.ID); err != nil {
				log.Printf("[free-pool] seed %s: link: %v", src.Key, err)
			}
			continue
		}
		key := ""
		if !src.Keyless {
			key = sourceEnvKey(src)
			if key == "" {
				continue // 没有 Key 的付费档不占用池位，等操作员自己添加
			}
		}
		acc, err := s.createFreePoolAccount(src, "", key, "")
		if err != nil {
			log.Printf("[free-pool] seed %s: %v", src.Key, err)
			continue
		}
		log.Printf("[free-pool] 已接入免费来源 %s（%s / %s）", src.Name, src.BaseURL, acc.Model)
	}
}

// loadFreeAccounts returns every pool member with a decoded source + today's usage.
func (s *Server) loadFreeAccounts() ([]freePoolAccountJSON, error) {
	accounts, err := s.m.pg.ListFreePoolAccounts()
	if err != nil {
		return nil, err
	}
	out := make([]freePoolAccountJSON, 0, len(accounts))
	for _, a := range accounts {
		src, ok := freeSourceByKey(a.Source)
		item := freePoolAccountJSON{FreePoolAccount: a}
		if ok {
			item.SourceName = src.Name
			item.Keyless = src.Keyless
			item.Tools = src.Tools
		}
		if calls, fails, err := s.m.pg.FreePoolUsageToday(a.ProfileName); err == nil {
			item.CallsToday, item.FailsToday = calls, fails
		}
		out = append(out, item)
	}
	return out, nil
}

// GET /api/llm/free-pool — catalog + members + toggle state (no probing).
func (s *Server) pgFreePool(w http.ResponseWriter, r *http.Request) {
	if s.m.pg == nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	s.ensureFreePoolSeed()
	accounts, err := s.loadFreeAccounts()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	active := ""
	if p, _ := s.m.pg.ActiveProfile(); p != nil {
		active = fmt.Sprintf("%d", p.ID)
	}
	writeJSON(w, 200, map[string]any{
		"enabled":           s.m.pg.GetBool(settingFreePoolOn, false),
		"active_profile_id": active,
		"sources":           builtinFreeSources(),
		"accounts":          accounts,
	})
}

// POST /api/llm/free-pool/probe — one tiny chat completion per member.
func (s *Server) pgFreePoolProbe(w http.ResponseWriter, r *http.Request) {
	if s.m.pg == nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	accounts, err := s.m.pg.ListFreePoolAccounts()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	results := make([]map[string]any, len(accounts))
	var wg sync.WaitGroup
	for i, a := range accounts {
		src, ok := freeSourceByKey(a.Source)
		if !ok {
			results[i] = map[string]any{"account_id": a.ID, "ok": false, "error": "未知来源: " + a.Source}
			continue
		}
		wg.Add(1)
		go func(i int, a db.FreePoolAccount, src freeSource) {
			defer wg.Done()
			key := ""
			if prof, err := s.m.pg.ProfileByID(a.ProfileID); err == nil && prof != nil {
				key = prof.APIKey
			}
			ok2, ms, msg := probeFreeAccount(src, key, a.Model)
			results[i] = map[string]any{"account_id": a.ID, "ok": ok2, "latency_ms": ms, "error": msg}
		}(i, a, src)
	}
	wg.Wait()
	writeJSON(w, 200, map[string]any{"ok": true, "results": results})
}

// POST /api/llm/free-pool/accounts — add a member (keyless auto-seeded source or a
// keyed free tier with the operator's own key).
func (s *Server) pgFreePoolAdd(w http.ResponseWriter, r *http.Request) {
	if s.m.pg == nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	var req struct {
		Source string `json:"source"`
		Label  string `json:"label"`
		APIKey string `json:"api_key"`
		Model  string `json:"model"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	src, ok := freeSourceByKey(strings.TrimSpace(req.Source))
	if !ok {
		writeErr(w, 400, "未知免费来源: "+req.Source)
		return
	}
	if !src.Keyless && strings.TrimSpace(req.APIKey) == "" {
		writeErr(w, 400, src.Name+" 需要 API Key")
		return
	}
	acc, err := s.createFreePoolAccount(src, strings.TrimSpace(req.Label), strings.TrimSpace(req.APIKey), strings.TrimSpace(req.Model))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "account": acc})
}

// DELETE /api/llm/free-pool/accounts/{id} — remove the member and its profile.
func (s *Server) pgFreePoolDelete(w http.ResponseWriter, r *http.Request) {
	if s.m.pg == nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "无效的账号 id")
		return
	}
	profileID, err := s.m.pg.DeleteFreePoolAccount(id)
	if err != nil {
		writeErr(w, 404, "账号不存在")
		return
	}
	// 池子会复用操作员「同一个端点」的既有配置（例如他早就配好的 OpenRouter），
	// 那种 profile 不是池子建的，移出池子时只摘链接，不能连人家的配置一起删。
	prof, perr := s.m.pg.ProfileByID(profileID)
	if perr != nil || prof == nil {
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}
	if !strings.HasPrefix(prof.Name, "免费池·") {
		writeJSON(w, 200, map[string]any{"ok": true, "profile_kept": true})
		return
	}
	if err := s.m.pg.DeleteProfile(profileID); err != nil {
		// 账号链接已删，profile 留着也只是普通配置；把原因如实回给用户。
		writeErr(w, 409, "已移出池，但删除配置失败: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/llm/free-pool/activate — probe members and activate the first healthy
// one, then switch on the existing failover chain so a throttled source rolls
// over instead of failing the run.
func (s *Server) pgFreePoolActivate(w http.ResponseWriter, r *http.Request) {
	if s.m.pg == nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	var req struct {
		AccountID int64 `json:"account_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	s.ensureFreePoolSeed()
	accounts, err := s.m.pg.ListFreePoolAccounts()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if len(accounts) == 0 {
		writeErr(w, 400, "免费池为空：先添加一个免费来源")
		return
	}
	var candidates []db.FreePoolAccount
	if req.AccountID > 0 {
		for _, a := range accounts {
			if a.ID == req.AccountID {
				candidates = append(candidates, a)
			}
		}
		if len(candidates) == 0 {
			writeErr(w, 404, "账号不存在")
			return
		}
	} else {
		candidates = accounts
		// 目录顺序即优先级：Pollinations(免 Key) → OpenRouter → Groq → Gemini。
		order := map[string]int{}
		for i, src := range builtinFreeSources() {
			order[src.Key] = i
		}
		sort.SliceStable(candidates, func(i, j int) bool {
			return order[candidates[i].Source] < order[candidates[j].Source]
		})
	}

	type probeResult struct {
		acc db.FreePoolAccount
		ok  bool
		ms  int64
		err string
	}
	results := make([]probeResult, len(candidates))
	var wg sync.WaitGroup
	for i, a := range candidates {
		src, ok := freeSourceByKey(a.Source)
		if !ok {
			results[i] = probeResult{acc: a, err: "未知来源"}
			continue
		}
		wg.Add(1)
		go func(i int, a db.FreePoolAccount, src freeSource) {
			defer wg.Done()
			key := ""
			if prof, err := s.m.pg.ProfileByID(a.ProfileID); err == nil && prof != nil {
				key = prof.APIKey
			}
			ok2, ms, msg := probeFreeAccount(src, key, a.Model)
			results[i] = probeResult{acc: a, ok: ok2, ms: ms, err: msg}
		}(i, a, src)
	}
	wg.Wait()

	var chosen *probeResult
	for i := range results {
		if results[i].ok {
			chosen = &results[i]
			break
		}
	}
	if chosen == nil {
		detail := make([]string, 0, len(results))
		for _, res := range results {
			detail = append(detail, fmt.Sprintf("%s: %s", res.acc.ProfileName, res.err))
		}
		writeErr(w, 502, "没有可用的免费来源："+strings.Join(detail, "；"))
		return
	}
	if err := s.m.pg.SetActiveProfile(chosen.acc.ProfileID); err != nil {
		writeErr(w, 500, "激活失败: "+err.Error())
		return
	}
	_ = s.m.pg.SetBool(settingFreePoolOn, true)
	_ = s.m.pg.SetBool(settingLLMPoolOn, true)
	s.reapplyActiveProfile()
	writeJSON(w, 200, map[string]any{
		"ok":          true,
		"activated":   chosen.acc.ProfileName,
		"latency_ms":  chosen.ms,
		"pool_member": true,
	})
}

// POST /api/llm/free-pool/enabled — toggle the pool. Enabling also runs the
// activate path; disabling only clears the flag and leaves the active profile.
func (s *Server) pgFreePoolToggle(w http.ResponseWriter, r *http.Request) {
	if s.m.pg == nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if !req.Enabled {
		if err := s.m.pg.SetBool(settingFreePoolOn, false); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "enabled": false})
		return
	}
	s.pgFreePoolActivate(w, r)
}
