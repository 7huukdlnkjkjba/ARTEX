package cost

import (
	"math"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestSpendDeepSeekDefaults(t *testing.T) {
	cfg := Default()
	// 1M prompt of which 400k cache hits, 100k output:
	// miss 600k×2 + hit 400k×0.5 + out 100k×8 = 1.2 + 0.2 + 0.8 = ¥2.20
	got := cfg.Spend(db.TaskTokenTotals{
		InputTokens: 1_000_000, CacheRead: 400_000, OutputTokens: 100_000,
	})
	if math.Abs(got-2.2) > 1e-9 {
		t.Fatalf("spend = %v, want 2.2", got)
	}
}

func TestSpendDoesNotDoubleBillCacheRead(t *testing.T) {
	cfg := Default()
	allHit := cfg.Spend(db.TaskTokenTotals{InputTokens: 1_000_000, CacheRead: 1_000_000})
	allMiss := cfg.Spend(db.TaskTokenTotals{InputTokens: 1_000_000})
	if math.Abs(allHit-0.5) > 1e-9 {
		t.Fatalf("all-hit spend = %v, want 0.5", allHit)
	}
	if math.Abs(allMiss-2.0) > 1e-9 {
		t.Fatalf("all-miss spend = %v, want 2.0", allMiss)
	}
	if allHit >= allMiss {
		t.Fatalf("cached prompt must be cheaper: hit=%v miss=%v", allHit, allMiss)
	}
	// A provider that reported more cache reads than total input must not produce a
	// negative miss component.
	if got := cfg.Spend(db.TaskTokenTotals{InputTokens: 100, CacheRead: 500}); got < 0 {
		t.Fatalf("negative spend %v", got)
	}
}

func TestRemainingAndDisabledBudget(t *testing.T) {
	cfg := Default()
	if got := cfg.RemainingCNY(2.5); math.Abs(got-3.5) > 1e-9 {
		t.Fatalf("remaining = %v, want 3.5", got)
	}
	if got := cfg.RemainingCNY(99); got != 0 {
		t.Fatalf("overspent remaining = %v, want 0", got)
	}
	off := Config{BudgetCNY: 0}
	if off.Enabled() || off.RemainingCNY(1) != 0 {
		t.Fatalf("zero budget must be disabled")
	}
}

func TestLoadEnvOverrides(t *testing.T) {
	t.Setenv(EnvBudgetCNY, "12.5")
	t.Setenv(EnvPriceInput, "4")
	t.Setenv(EnvPriceOutput, "16")
	t.Setenv(EnvPriceCacheRead, "1")
	t.Setenv(EnvPriceCacheWrite, "0.25")
	cfg := Load(nil) // no DB: defaults + env
	if cfg.BudgetCNY != 12.5 || cfg.InputPerMTok != 4 || cfg.OutputPerMTok != 16 ||
		cfg.CacheReadPerMTok != 1 || cfg.CacheWritePerMTok != 0.25 {
		t.Fatalf("env overrides not applied: %+v", cfg)
	}
	// Budget 0 is a legitimate "no limit", not a parse failure.
	t.Setenv(EnvBudgetCNY, "0")
	if Load(nil).Enabled() {
		t.Fatalf("ARTEX_SESSION_BUDGET_CNY=0 must disable the cap")
	}
}

func TestLoadRejectsBadValues(t *testing.T) {
	t.Setenv(EnvBudgetCNY, "not-a-number")
	t.Setenv(EnvPriceInput, "-1")
	cfg := Load(nil)
	if cfg.BudgetCNY != DefaultBudgetCNY {
		t.Fatalf("bad budget fell through: %v", cfg.BudgetCNY)
	}
	if cfg.InputPerMTok != DefaultPriceInput {
		t.Fatalf("negative price accepted: %v", cfg.InputPerMTok)
	}
}
