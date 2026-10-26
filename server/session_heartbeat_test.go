package server

import (
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// 运行期心跳只探「alive 且空闲超过阈值」的会话：新鲜会话不打扰，dead 行不探，
// 边界值（恰好等于阈值）不算空闲，零值 last_beat 视为陈旧。
func TestSessionNeedsHeartbeat(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		rec  *db.SessionRecord
		want bool
	}{
		{"alive 且空闲", &db.SessionRecord{Status: db.SessionAlive, LastBeat: now.Add(-11 * time.Minute)}, true},
		{"alive 但新鲜", &db.SessionRecord{Status: db.SessionAlive, LastBeat: now.Add(-time.Minute)}, false},
		{"dead 不探", &db.SessionRecord{Status: db.SessionDead, LastBeat: now.Add(-time.Hour)}, false},
		{"恰好边界不探", &db.SessionRecord{Status: db.SessionAlive, LastBeat: now.Add(-sessionHeartbeatIdle)}, false},
		{"零值 last_beat 视为空闲", &db.SessionRecord{Status: db.SessionAlive}, true},
		{"nil 不探", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sessionNeedsHeartbeat(c.rec, now, sessionHeartbeatIdle); got != c.want {
				t.Fatalf("sessionNeedsHeartbeat = %v, want %v", got, c.want)
			}
		})
	}
}
