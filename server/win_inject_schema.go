package server

import "encoding/json"

// winInjectSchemaMap adapts the JSON-schema literal used by the Windows
// implementation to the map shape expected by actool.Spec. The schema text
// itself stays in win_inject_windows.go.
func winInjectSchemaMap(raw json.RawMessage) map[string]any {
	var m map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &m)
	}
	if m == nil {
		m = map[string]any{"type": "object", "properties": map[string]any{}}
	}
	return m
}
