package server

import (
	"strings"
	"testing"
)

func TestWinInjectToolsRegistered(t *testing.T) {
	found := false
	for _, tool := range (&Server{}).winInjectTools() {
		if tool.Name() == "win_inject" {
			found = true
			if !strings.Contains(tool.Description(), "confirm=true") {
				t.Error("description should mention confirm")
			}
		}
	}
	if !found {
		t.Fatal("win_inject not registered")
	}
}

func TestWinInjectSchemaMap(t *testing.T) {
	m := winInjectSchemaMap([]byte(`{"type":"object","properties":{"pid":{"type":"integer"}}}`))
	if m["type"] != "object" {
		t.Fatalf("schema = %+v", m)
	}
}
