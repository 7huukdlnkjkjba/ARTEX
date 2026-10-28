package server

import "testing"

func TestPlannerStallTripsAfterRepeatedNoProgress(t *testing.T) {
	s := &plannerStall{}
	for i := 1; i < plannerStallRounds; i++ {
		if s.observe("a=1;", false, 0) {
			t.Fatalf("第 %d 轮不应触发暂停", i)
		}
	}
	if !s.observe("a=1;", false, 0) {
		t.Fatalf("连续 %d 轮无进展应触发暂停", plannerStallRounds)
	}
}

func TestPlannerStallResetsOnProgress(t *testing.T) {
	s := &plannerStall{}
	s.observe("a=1;", false, 0)
	s.observe("a=1;", false, 0)
	if s.observe("a=2;", false, 0) {
		t.Fatal("图谱计数变化应视为进展，不触发暂停")
	}
	if s.observe("a=2;", false, 0) {
		t.Fatal("重置后第一轮不应触发")
	}
}

func TestPlannerStallIgnoresActiveWork(t *testing.T) {
	s := &plannerStall{}
	for i := 0; i < plannerStallRounds+2; i++ {
		if s.observe("a=1;", true, 0) {
			t.Fatal("有在跑意图时不应暂停")
		}
		if s.observe("a=1;", false, 2) {
			t.Fatal("frontier 有待领意图时不应暂停")
		}
	}
}
