package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
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
}

// builtinFreeSources is the catalog. Order = activation preference.
func builtinFreeSources() []freeSource {
	return []freeSource{
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

// ensureFreePoolSeed creates the keyless default member once per source.
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
	for _, src := range builtinFreeSources() {
		if !src.Keyless || have[src.Key] {
			continue
		}
		// 同名的普通配置（用户手工建的）优先复用，只补一条池链接，避免重复 profile。
		if profs, err := s.m.pg.ListProfiles(); err == nil {
			var reuse *db.LLMProfile
			for _, p := range profs {
				if p.Name == "免费池·"+src.Name && p.BaseURL == src.BaseURL {
					reuse = p
					break
				}
			}
			if reuse != nil {
				if _, err := s.m.pg.AddFreePoolAccount(src.Key, "", reuse.ID); err != nil {
					log.Printf("[free-pool] seed %s: link: %v", src.Key, err)
				}
				continue
			}
		}
		if _, err := s.createFreePoolAccount(src, "", "", ""); err != nil {
			log.Printf("[free-pool] seed %s: %v", src.Key, err)
			continue
		}
		log.Printf("[free-pool] 已内置免费来源 %s（%s / %s）", src.Name, src.BaseURL, src.Models[0])
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
