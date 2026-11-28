package msfrpc

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	long := bytes.Repeat([]byte("x"), 300)
	cases := []struct {
		name string
		in   any
		want any
	}{
		{"nil", nil, nil},
		{"true", true, true},
		{"false", false, false},
		{"zero", 0, int64(0)},
		{"fixint", 42, int64(42)},
		{"negfixint", -32, int64(-32)},
		{"int8", -33, int64(-33)},
		{"int16", -1000, int64(-1000)},
		{"int32", -100000, int64(-100000)},
		{"uint8", 200, int64(200)},
		{"uint16", 40000, int64(40000)},
		{"uint32", 3000000000, int64(3000000000)},
		{"string", "hello", "hello"},
		{"long string", string(long), string(long)},
		{"bin", []byte{1, 2, 3}, []byte{1, 2, 3}},
		{"array", []any{"a", 1, true, nil}, []any{"a", int64(1), true, nil}},
		{"map", map[string]any{"b": 2, "a": "x"}, map[string]any{"a": "x", "b": int64(2)}},
		{"nested", map[string]any{"opts": map[string]any{"RPORT": 80, "SSL": false}}, map[string]any{"opts": map[string]any{"RPORT": int64(80), "SSL": false}}},
		{"array16", bigIntArray(20), bigIntArray(20)},
		{"map16", bigMap(20), bigMap(20)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw, err := encode(c.in)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			got, err := decode(raw)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("roundtrip = %#v, want %#v", got, c.want)
			}
		})
	}
}

func TestEncodeWireBytes(t *testing.T) {
	// A real msfrpcd request body: ["auth.login","msf","pass"] plus a uint16.
	raw, err := encode([]any{"auth.login", "msf", "pass", 70000})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	want := []byte{
		0x94,                     // fixarray(4)
		0xaa, 'a', 'u', 't', 'h', '.', 'l', 'o', 'g', 'i', 'n', // fixstr(10)
		0xa3, 'm', 's', 'f',      // fixstr(3)
		0xa4, 'p', 'a', 's', 's', // fixstr(4)
		0xce, 0x00, 0x01, 0x11, 0x70, // uint32(70000)
	}
	if !bytes.Equal(raw, want) {
		t.Fatalf("wire bytes\n got % x\nwant % x", raw, want)
	}
}

func TestDecodeRejectsBrokenInput(t *testing.T) {
	if _, err := decode([]byte{0xa5, 'a', 'b'}); err == nil {
		t.Fatal("截断的 str 应报错")
	}
	if _, err := decode([]byte{0xc1}); err == nil {
		t.Fatal("0xc1 是保留标记，应报错")
	}
	if _, err := decode([]byte{0x01, 0x02}); err == nil {
		t.Fatal("尾部多余字节应报错")
	}
	if _, err := decode(nil); err == nil {
		t.Fatal("空报文应报错")
	}
}

func TestDecodeMapWithNonStringKey(t *testing.T) {
	// {1: "a"} — msfrpcd never sends this, but decoding must not panic.
	raw := []byte{0x81, 0x01, 0xa1, 'a'}
	got, err := decode(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	m, ok := got.(map[string]any)
	if !ok || m["1"] != "a" {
		t.Fatalf("got %#v", got)
	}
}

// bigIntArray / bigMap produce containers that need the 16-bit header forms,
// which is where a decoder length bug hides (array16/map16 were misread as
// 1-byte lengths before this test existed).
func bigIntArray(n int) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = int64(i)
	}
	return out
}

func bigMap(n int) map[string]any {
	out := make(map[string]any, n)
	for i := 0; i < n; i++ {
		out[fmt.Sprintf("k%02d", i)] = int64(i)
	}
	return out
}

// TestDecodeRealAuthLoginPayload decodes a byte-for-byte capture from msfrpcd
// 6.4 on Windows. Ruby encodes strings as bin (0xc4), so both the map keys and
// the values arrive as []byte — a decoder that only accepts str keys breaks
// every reply.
func TestDecodeRealAuthLoginPayload(t *testing.T) {
	raw, err := hex.DecodeString("82c406726573756c74c40773756363657373c405746f6b656ec42054454d50384c7333724f4a47714c6c744437367142574e716634475134625570")
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	val, err := decode(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	m, ok := val.(map[string]any)
	if !ok {
		t.Fatalf("type=%T", val)
	}
	if got := asString(m["result"]); got != "success" {
		t.Fatalf("result=%q (keys=%v)", got, m)
	}
	if tok := asString(m["token"]); tok == "" {
		t.Fatalf("token 为空：%v", m)
	}
}
