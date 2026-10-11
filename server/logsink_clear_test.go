package server

import (
	"io"
	"testing"
	"time"
)

func newTestLogSink() *logSinkT {
	return &logSinkT{cap: 16, subs: map[chan LogLine]struct{}{}, out: io.Discard}
}

// Clear must drop the buffered lines, tell live subscribers to empty their view,
// and keep the seq cursor monotonic so an SSE client resuming with ?since=<seq>
// never gets stuck behind a rewind.
func TestLogSinkClearDropsRingAndSignalsSubscribers(t *testing.T) {
	s := newTestLogSink()
	s.Write([]byte("2026/01/01 00:00:00 [planner] task 1 规划中\n"))
	if lines, _ := s.recent(0, 10); len(lines) != 1 {
		t.Fatalf("precondition: want 1 buffered line, got %d", len(lines))
	}
	ch, unsub := s.subscribe()
	defer unsub()

	deleted, err := s.Clear()
	if err != nil {
		t.Fatalf("clear: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("no DB wired: want 0 deleted rows, got %d", deleted)
	}
	if lines, _ := s.recent(0, 10); len(lines) != 0 {
		t.Fatalf("ring not dropped after clear: %+v", lines)
	}

	var marker LogLine
	select {
	case marker = <-ch:
	case <-time.After(time.Second):
		t.Fatal("subscriber received no cleared frame")
	}
	if !marker.Cleared {
		t.Fatalf("want cleared frame, got %+v", marker)
	}

	s.Write([]byte("2026/01/01 00:00:01 [planner] task 1 继续\n"))
	lines, cursor := s.recent(0, 10)
	if len(lines) != 1 {
		t.Fatalf("want 1 line after clear, got %d", len(lines))
	}
	if lines[0].Seq <= marker.Seq {
		t.Fatalf("seq rewound: line seq=%d, marker seq=%d (SSE clients would never see it)", lines[0].Seq, marker.Seq)
	}
	if cursor != lines[0].Seq {
		t.Fatalf("cursor should track the newest seq: got %d, want %d", cursor, lines[0].Seq)
	}
}

// Lines emitted before a Clear must not be written back after the DELETE.
func TestLogSinkClearDropsQueuedWrites(t *testing.T) {
	s := newTestLogSink()
	s.Write([]byte("2026/01/01 00:00:00 [activity] task 1 旧行\n"))
	before, _ := s.recent(0, 10)
	old := before[0].Seq
	if _, err := s.Clear(); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if s.shouldPersist(old) {
		t.Fatal("pre-clear line would be inserted after the DELETE")
	}
	s.Write([]byte("2026/01/01 00:00:02 [activity] task 1 新行\n"))
	after, _ := s.recent(0, 10)
	fresh := after[0].Seq
	if !s.shouldPersist(fresh) {
		t.Fatal("post-clear line must still be persisted")
	}
}

// The auto-clear hook fires on entering a terminal state — done (success) and
// failed / timeout (failure) alike — but never on non-terminal moves or on
// rewrites of a status that is already terminal.
func TestShouldClearLogsOnTerminal(t *testing.T) {
	cases := []struct {
		prev, next string
		want       bool
	}{
		{"running", "done", true},
		{"running", "failed", true},
		{"running", "timeout", true},
		{"queued", "timeout", true},
		{"", "done", true},
		{"running", "running", false},
		{"running", "paused", false},
		{"running", "queued", false},
		{"done", "done", false},
		{"timeout", "done", false},
		{"failed", "timeout", false},
		{"done", "running", false}, // 复活重跑：清空发生在终态，不在这里
	}
	for _, c := range cases {
		if got := shouldClearLogsOnTerminal(c.prev, c.next); got != c.want {
			t.Errorf("shouldClearLogsOnTerminal(%q→%q) = %v, want %v", c.prev, c.next, got, c.want)
		}
	}
}
