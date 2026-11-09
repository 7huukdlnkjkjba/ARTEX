package db

import "testing"

func TestHashContent(t *testing.T) {
	if a, b := HashContent([]byte("x")), HashContent([]byte("x")); a != b || len(a) != 64 {
		t.Fatalf("hash = %q %q", a, b)
	}
	if HashContent([]byte("x")) == HashContent([]byte("y")) {
		t.Fatal("hash collision")
	}
}

func TestNetBenefitPositive(t *testing.T) {
	if !NetBenefitPositive(0.10, 0.05, 100, 1.0) { // 5.0 saving > 1.0
		t.Error("should be positive")
	}
	if NetBenefitPositive(0.10, 0.09, 10, 1.0) { // 0.1 saving < 1.0
		t.Error("should be negative")
	}
}

func TestCostAwareVerdict(t *testing.T) {
	base := GeneCostProfile{GeneKey: "prompt:x", Revision: 1, AvgCostCNY: 0.10,
		SampleCount: 10, CacheHitRate: 0.8, AvgTurns: 3}
	if v, _ := CostAwareVerdict(base, GeneCostProfile{}, 20, 0); v != "inconclusive" {
		t.Errorf("variant samples = %s", v)
	}
	expensive := base
	expensive.AvgCostCNY = 0.12
	if v, _ := CostAwareVerdict(base, expensive, 20, 0); v != "fail" {
		t.Errorf("expensive = %s", v)
	}
	cacheLoss := base
	cacheLoss.CacheHitRate = 0.5
	if v, _ := CostAwareVerdict(base, cacheLoss, 20, 0); v != "fail" {
		t.Errorf("cache = %s", v)
	}
	turns := base
	turns.AvgTurns = 4
	if v, _ := CostAwareVerdict(base, turns, 20, 0); v != "fail" {
		t.Errorf("turns = %s", v)
	}
	cheap := base
	cheap.AvgCostCNY = 0.05
	if v, net := CostAwareVerdict(base, cheap, 100, 1.0); v != "pass" || net <= 0 {
		t.Errorf("cheap = %s net=%v", v, net)
	}
	if v, _ := CostAwareVerdict(base, cheap, 10, 1.0); v != "inconclusive" {
		t.Errorf("small saving = %s", v)
	}
}

func TestFitnessCacheHitRate(t *testing.T) {
	f := Fitness{InputTokens: 100, CacheReadTokens: 40}
	if got := f.CacheHitRate(); got != 0.4 {
		t.Fatalf("hit = %v", got)
	}
	if (Fitness{}).CacheHitRate() != 0 {
		t.Fatal("zero input should be 0")
	}
}
