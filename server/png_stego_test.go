package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func callPNGStego(t *testing.T, s *Server, payload map[string]any) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(payload)
	res, err := s.toolPNGStego().Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool error: %s", res.Flatten())
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(res.Flatten()), &out); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, res.Flatten())
	}
	return out
}

func writeTestPNG(t *testing.T, path string, w, h int) {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{R: 10, G: 20, B: 30, A: 255})
		}
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		t.Fatal(err)
	}
}

func TestPNGStegoRoundTrip(t *testing.T) {
	dir := t.TempDir()
	carrier := filepath.Join(dir, "carrier.png")
	hidden := filepath.Join(dir, "hidden.png")
	extracted := filepath.Join(dir, "payload.bin")
	writeTestPNG(t, carrier, 128, 128)

	payload := []byte("ARTEX stego round-trip payload\x00\x01\x02")
	s := &Server{}
	hide := callPNGStego(t, s, map[string]any{
		"action": "hide", "image_path": carrier,
		"payload": base64.StdEncoding.EncodeToString(payload), "out_path": hidden,
	})
	if hide["status"] != "success" || hide["bytes_hidden"].(float64) != float64(len(payload)) {
		t.Fatalf("hide = %+v", hide)
	}
	ex := callPNGStego(t, s, map[string]any{
		"action": "extract", "image_path": hidden, "out_path": extracted, "return_payload": true,
	})
	if ex["status"] != "success" || ex["bytes_extracted"].(float64) != float64(len(payload)) {
		t.Fatalf("extract = %+v", ex)
	}
	got, err := os.ReadFile(extracted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: %q != %q", got, payload)
	}
	b64, _ := ex["payload_b64"].(string)
	if b64 == "" {
		t.Error("missing payload_b64")
	}
}

func TestPNGStegoCreatesCarrier(t *testing.T) {
	dir := t.TempDir()
	hidden := filepath.Join(dir, "hidden.png")
	s := &Server{}
	out := callPNGStego(t, s, map[string]any{
		"action": "hide", "image_path": filepath.Join(dir, "missing.png"),
		"payload": base64.StdEncoding.EncodeToString([]byte("hello")), "out_path": hidden,
	})
	if out["status"] != "success" {
		t.Fatalf("out = %+v", out)
	}
	if _, err := os.Stat(hidden); err != nil {
		t.Fatal(err)
	}
}

func TestPNGStegoCapacityError(t *testing.T) {
	dir := t.TempDir()
	carrier := filepath.Join(dir, "small.png")
	writeTestPNG(t, carrier, 10, 10)
	s := &Server{}
	raw, _ := json.Marshal(map[string]any{
		"action": "hide", "image_path": carrier,
		"payload":  base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), 100)),
		"out_path": filepath.Join(dir, "out.png"),
	})
	res, _ := s.toolPNGStego().Call(context.Background(), raw, nil)
	if !res.IsError || !strings.Contains(res.Flatten(), "容量不足") {
		t.Fatalf("res = %v %s", res.IsError, res.Flatten())
	}
}

func TestPNGStegoBadMagic(t *testing.T) {
	dir := t.TempDir()
	carrier := filepath.Join(dir, "plain.png")
	writeTestPNG(t, carrier, 64, 64)
	s := &Server{}
	raw, _ := json.Marshal(map[string]any{
		"action": "extract", "image_path": carrier, "out_path": filepath.Join(dir, "out.bin"),
	})
	res, _ := s.toolPNGStego().Call(context.Background(), raw, nil)
	if !res.IsError || !strings.Contains(res.Flatten(), "ARTX") {
		t.Fatalf("res = %v %s", res.IsError, res.Flatten())
	}
}

func TestPNGStegoToolsRegistered(t *testing.T) {
	found := false
	for _, tool := range (&Server{}).pngStegoTools() {
		if tool.Name() == "png_stego" {
			found = true
		}
	}
	if !found {
		t.Fatal("png_stego not registered")
	}
}
