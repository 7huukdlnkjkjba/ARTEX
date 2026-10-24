// Package cost turns the always-on llm_usage metering ledger into money, and
// defines the per-session budget that bounds one vulnerability-hunting session.
//
// The ledger stores token counts only (input / output / cache read / cache write),
// so this package applies a price table to them. Prices are CNY per 1M tokens and
// default to DeepSeek's public list price; every value can be overridden from the
// settings table (系统设置) or, for headless deployments, an environment variable.
//
// Semantics of the token columns (norma canonical Usage):
//   - InputTokens is the TOTAL prompt size and already includes CacheReadTokens.
//   - CacheReadTokens is the cached subset of that total.
//   - CacheWriteTokens is the cache-creation subset (Anthropic-style providers);
//     DeepSeek reports 0 here because it does not bill cache writes separately.
//
// Therefore the cache-miss part is (InputTokens - CacheReadTokens); charging the
// full InputTokens AND CacheReadTokens would double-bill the cached prefix.
package cost

import (
	"os"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// Settings keys (flat key-value table, see db/settings.go).
const (
	SettingBudgetCNY      = "task_budget_cny"
	SettingPriceInput     = "llm_price_input_cny_per_mtok"
	SettingPriceOutput    = "llm_price_output_cny_per_mtok"
	SettingPriceCacheRead = "llm_price_cache_read_cny_per_mtok"
	// SettingPriceCacheWrite is the *premium* over the normal input price, not the
	// absolute write price: norma counts cache-creation tokens inside InputTokens
	// (at the miss price) and reports them again as CacheWriteTokens. Charging the
	// premium here yields input + premium (e.g. Anthropic's 1.25×) without
	// double-billing. DeepSeek (the default table) reports 0, so the default is 0.
	SettingPriceCacheWrite = "llm_price_cache_write_cny_per_mtok"
)

// Environment overrides, useful for headless/containers. Values use the same unit
// (CNY per 1M tokens); ARTEX_SESSION_BUDGET_CNY=0 disables the cap.
const (
	EnvBudgetCNY       = "ARTEX_SESSION_BUDGET_CNY"
	EnvPriceInput      = "ARTEX_PRICE_INPUT_CNY_PER_MTOK"
	EnvPriceOutput     = "ARTEX_PRICE_OUTPUT_CNY_PER_MTOK"
	EnvPriceCacheRead  = "ARTEX_PRICE_CACHE_READ_CNY_PER_MTOK"
	EnvPriceCacheWrite = "ARTEX_PRICE_CACHE_WRITE_CNY_PER_MTOK"
)

// Defaults: DeepSeek official list price (deepseek-chat), CNY per 1M tokens.
// Cache-miss input ¥2, cache-hit input ¥0.5, output ¥8, cache write not charged.
// The ¥6 session budget is the default the platform ships with.
const (
	DefaultBudgetCNY       = 6.0
	DefaultPriceInput      = 2.0
	DefaultPriceOutput     = 8.0
	DefaultPriceCacheRead  = 0.5
	DefaultPriceCacheWrite = 0.0
)

// Config is a resolved price table plus the per-session budget. BudgetCNY <= 0
// disables enforcement (pure metering).
type Config struct {
	BudgetCNY         float64
	InputPerMTok      float64
	OutputPerMTok     float64
	CacheReadPerMTok  float64
	CacheWritePerMTok float64
}

// Default returns the built-in DeepSeek price table and the ¥6 budget.
func Default() Config {
	return Config{
		BudgetCNY:         DefaultBudgetCNY,
		InputPerMTok:      DefaultPriceInput,
		OutputPerMTok:     DefaultPriceOutput,
		CacheReadPerMTok:  DefaultPriceCacheRead,
		CacheWritePerMTok: DefaultPriceCacheWrite,
	}
}

// Enabled reports whether a budget is configured (>0).
func (c Config) Enabled() bool { return c.BudgetCNY > 0 }

// RemainingCNY is the budget minus the given spend, floored at 0.
func (c Config) RemainingCNY(spent float64) float64 {
	if !c.Enabled() {
		return 0
	}
	if left := c.BudgetCNY - spent; left > 0 {
		return left
	}
	return 0
}

// Spend converts one task's token totals into CNY.
func (c Config) Spend(t db.TaskTokenTotals) float64 {
	miss := t.InputTokens - t.CacheRead
	if miss < 0 {
		miss = 0
	}
	cost := float64(miss)*c.InputPerMTok +
		float64(t.CacheRead)*c.CacheReadPerMTok +
		float64(t.CacheWrite)*c.CacheWritePerMTok +
		float64(t.OutputTokens)*c.OutputPerMTok
	return cost / 1_000_000
}

// Load resolves the effective config: settings table first, environment second
// (so a container can pin the budget without touching the DB). pg may be nil, in
// which case only defaults + environment apply.
func Load(pg *db.DB) Config {
	c := Default()
	if pg != nil {
		c.BudgetCNY = settingFloat(pg, SettingBudgetCNY, c.BudgetCNY, true)
		c.InputPerMTok = settingFloat(pg, SettingPriceInput, c.InputPerMTok, false)
		c.OutputPerMTok = settingFloat(pg, SettingPriceOutput, c.OutputPerMTok, false)
		c.CacheReadPerMTok = settingFloat(pg, SettingPriceCacheRead, c.CacheReadPerMTok, false)
		c.CacheWritePerMTok = settingFloat(pg, SettingPriceCacheWrite, c.CacheWritePerMTok, false)
	}
	c.BudgetCNY = envFloat(EnvBudgetCNY, c.BudgetCNY, true)
	c.InputPerMTok = envFloat(EnvPriceInput, c.InputPerMTok, false)
	c.OutputPerMTok = envFloat(EnvPriceOutput, c.OutputPerMTok, false)
	c.CacheReadPerMTok = envFloat(EnvPriceCacheRead, c.CacheReadPerMTok, false)
	c.CacheWritePerMTok = envFloat(EnvPriceCacheWrite, c.CacheWritePerMTok, false)
	return c
}

// settingFloat reads a numeric setting. zeroAllowed=false rejects 0 (a price of
// 0 would silently hide spend); true is used for the budget where 0 = 不限.
func settingFloat(pg *db.DB, key string, def float64, zeroAllowed bool) float64 {
	raw, ok, err := pg.GetSetting(key)
	if err != nil || !ok {
		return def
	}
	return parseFloat(raw, def, zeroAllowed)
}

func envFloat(key string, def float64, zeroAllowed bool) float64 {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	return parseFloat(raw, def, zeroAllowed)
}

func parseFloat(raw string, def float64, zeroAllowed bool) float64 {
	f, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil || f < 0 || (!zeroAllowed && f == 0) {
		return def
	}
	return f
}
