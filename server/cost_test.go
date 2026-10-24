package server

import (
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// The synthetic stop must look like a normal assistant turn: a text delta and a
// clean end_turn. Anything else (an error, or a bare message_stop) would send the
// harness down the retry/blocked path instead of ending the run gracefully.
func TestBudgetStopStreamIsANormalTurn(t *testing.T) {
	const text = "预算已用尽"
	var got []llm.StreamEvent
	for ev, err := range budgetStopStream(text) {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		got = append(got, ev)
	}
	if len(got) != 4 {
		t.Fatalf("events = %d, want 4: %+v", len(got), got)
	}
	if got[0].Type != llm.SEMessageStart {
		t.Fatalf("first event = %q", got[0].Type)
	}
	if got[1].Type != llm.SETextDelta || got[1].Text != text {
		t.Fatalf("text event = %+v", got[1])
	}
	if got[2].Type != llm.SEMessageDelta || got[2].StopReason != "end_turn" {
		t.Fatalf("delta event = %+v", got[2])
	}
	if got[3].Type != llm.SEMessageStop {
		t.Fatalf("last event = %q", got[3].Type)
	}
}

func TestBudgetStopMessageIsANormalReply(t *testing.T) {
	msg, stop, usage, err := budgetStopMessage("stop")
	if err != nil || stop != "end_turn" {
		t.Fatalf("stop=%q err=%v", stop, err)
	}
	if msg.Role != llm.RoleAssistant || msg.Text() != "stop" {
		t.Fatalf("msg = %+v", msg)
	}
	if usage.InputTokens+usage.OutputTokens != 0 {
		t.Fatalf("synthetic stop must be free, got %+v", usage)
	}
}

func TestRoundCNY(t *testing.T) {
	for in, want := range map[float64]float64{5.999999: 6, 5.994: 5.99, 0.005: 0.01} {
		if got := roundCNY(in); got != want {
			t.Fatalf("roundCNY(%v) = %v, want %v", in, got, want)
		}
	}
}
