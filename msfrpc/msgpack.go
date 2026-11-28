// Package msfrpc is a dependency-free client for Metasploit's RPC daemon
// (msfrpcd).
//
// ARTEX talks to msfrpcd directly instead of spawning an MCP server: the wire
// protocol is a MessagePack array POSTed to /api/ with Content-Type
// binary/message-pack, which needs neither a Python interpreter nor any pip
// package. Everything the Metasploit closed loop needs (auth, module info and
// execution, consoles, sessions) is implemented here.
package msfrpc

import (
	"encoding/binary"
	"fmt"
	"math"
	"reflect"
	"sort"
)

// encode packs v into MessagePack.
//
// Supported Go values: nil, bool, string, []byte (bin), every int/uint/float
// width, slices and arrays (array), maps with string keys (map), and
// pointers/interfaces (dereferenced, nil becomes nil).
func encode(v any) ([]byte, error) {
	return appendValue(make([]byte, 0, 64), v)
}

func appendValue(b []byte, v any) ([]byte, error) {
	if v == nil {
		return append(b, 0xc0), nil
	}
	rv := reflect.ValueOf(v)
	for rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return append(b, 0xc0), nil
		}
		rv = rv.Elem()
	}
	switch rv.Kind() {
	case reflect.Bool:
		if rv.Bool() {
			return append(b, 0xc3), nil
		}
		return append(b, 0xc2), nil
	case reflect.String:
		return appendString(b, rv.String()), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return appendInt(b, rv.Int()), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return appendUint(b, rv.Uint()), nil
	case reflect.Float32:
		b = append(b, 0xca)
		return binary.BigEndian.AppendUint32(b, math.Float32bits(float32(rv.Float()))), nil
	case reflect.Float64:
		b = append(b, 0xcb)
		return binary.BigEndian.AppendUint64(b, math.Float64bits(rv.Float())), nil
	case reflect.Slice:
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			return appendBin(b, rv.Bytes()), nil
		}
		return appendArray(b, rv)
	case reflect.Array:
		return appendArray(b, rv)
	case reflect.Map:
		return appendMap(b, rv)
	default:
		return nil, fmt.Errorf("msgpack: 不支持的类型 %s", rv.Type())
	}
}

func appendArray(b []byte, rv reflect.Value) ([]byte, error) {
	n := rv.Len()
	switch {
	case n < 16:
		b = append(b, byte(0x90|n))
	case n < 1<<16:
		b = append(b, 0xdc)
		b = binary.BigEndian.AppendUint16(b, uint16(n))
	default:
		b = append(b, 0xdd)
		b = binary.BigEndian.AppendUint32(b, uint32(n))
	}
	var err error
	for i := 0; i < n; i++ {
		if b, err = appendValue(b, rv.Index(i).Interface()); err != nil {
			return nil, err
		}
	}
	return b, nil
}

func appendMap(b []byte, rv reflect.Value) ([]byte, error) {
	keys := make([]string, 0, rv.Len())
	index := map[string]reflect.Value{}
	for _, k := range rv.MapKeys() {
		if k.Kind() != reflect.String {
			return nil, fmt.Errorf("msgpack: map 键必须是字符串，得到 %s", k.Type())
		}
		s := k.String()
		keys = append(keys, s)
		index[s] = rv.MapIndex(k)
	}
	sort.Strings(keys) // deterministic wire bytes for tests and logs
	n := len(keys)
	switch {
	case n < 16:
		b = append(b, byte(0x80|n))
	case n < 1<<16:
		b = append(b, 0xde)
		b = binary.BigEndian.AppendUint16(b, uint16(n))
	default:
		b = append(b, 0xdf)
		b = binary.BigEndian.AppendUint32(b, uint32(n))
	}
	var err error
	for _, k := range keys {
		b = appendString(b, k)
		if b, err = appendValue(b, index[k].Interface()); err != nil {
			return nil, err
		}
	}
	return b, nil
}

func appendString(b []byte, s string) []byte {
	n := len(s)
	switch {
	case n < 32:
		b = append(b, byte(0xa0|n))
	case n < 1<<8:
		b = append(b, 0xd9, byte(n))
	case n < 1<<16:
		b = append(b, 0xda)
		b = binary.BigEndian.AppendUint16(b, uint16(n))
	default:
		b = append(b, 0xdb)
		b = binary.BigEndian.AppendUint32(b, uint32(n))
	}
	return append(b, s...)
}

func appendBin(b []byte, p []byte) []byte {
	n := len(p)
	switch {
	case n < 1<<8:
		b = append(b, 0xc4, byte(n))
	case n < 1<<16:
		b = append(b, 0xc5)
		b = binary.BigEndian.AppendUint16(b, uint16(n))
	default:
		b = append(b, 0xc6)
		b = binary.BigEndian.AppendUint32(b, uint32(n))
	}
	return append(b, p...)
}

func appendInt(b []byte, v int64) []byte {
	switch {
	case v >= 0:
		return appendUint(b, uint64(v))
	case v >= -32: // negative fixint
		return append(b, byte(v))
	case v >= math.MinInt8:
		return append(b, 0xd0, byte(v))
	case v >= math.MinInt16:
		b = append(b, 0xd1)
		return binary.BigEndian.AppendUint16(b, uint16(v))
	case v >= math.MinInt32:
		b = append(b, 0xd2)
		return binary.BigEndian.AppendUint32(b, uint32(v))
	default:
		b = append(b, 0xd3)
		return binary.BigEndian.AppendUint64(b, uint64(v))
	}
}

func appendUint(b []byte, v uint64) []byte {
	switch {
	case v < 0x80:
		return append(b, byte(v))
	case v <= math.MaxUint8:
		return append(b, 0xcc, byte(v))
	case v <= math.MaxUint16:
		b = append(b, 0xcd)
		return binary.BigEndian.AppendUint16(b, uint16(v))
	case v <= math.MaxUint32:
		b = append(b, 0xce)
		return binary.BigEndian.AppendUint32(b, uint32(v))
	default:
		b = append(b, 0xcf)
		return binary.BigEndian.AppendUint64(b, v)
	}
}

// decode unpacks a complete MessagePack document. ints come back as int64,
// floats as float64, maps as map[string]any, arrays as []any, str as string,
// bin as []byte.
func decode(b []byte) (any, error) {
	v, n, err := decodeAt(b, 0)
	if err != nil {
		return nil, err
	}
	if n != len(b) {
		return nil, fmt.Errorf("msgpack: 尾部有 %d 字节多余数据", len(b)-n)
	}
	return v, nil
}

func decodeAt(b []byte, off int) (any, int, error) {
	if off >= len(b) {
		return nil, off, fmt.Errorf("msgpack: 数据提前结束")
	}
	c := b[off]
	switch {
	case c <= 0x7f:
		return int64(c), off + 1, nil
	case c >= 0xe0:
		return int64(int8(c)), off + 1, nil
	case c >= 0xa0 && c <= 0xbf: // fixstr
		return readString(b, off+1, int(c&0x1f))
	case c >= 0x90 && c <= 0x9f: // fixarray
		return readArray(b, off+1, int(c&0x0f))
	case c >= 0x80 && c <= 0x8f: // fixmap
		return readMap(b, off+1, int(c&0x0f))
	}
	switch c {
	case 0xc0:
		return nil, off + 1, nil
	case 0xc2:
		return false, off + 1, nil
	case 0xc3:
		return true, off + 1, nil
	case 0xc4, 0xc5, 0xc6: // bin8/16/32
		size, next, err := readSize(b, off+1, 1<<(c-0xc4))
		if err != nil {
			return nil, off, err
		}
		if next+size > len(b) {
			return nil, off, fmt.Errorf("msgpack: bin 长度越界")
		}
		out := make([]byte, size)
		copy(out, b[next:next+size])
		return out, next + size, nil
	case 0xca:
		v, next, err := readUintN(b, off+1, 4)
		if err != nil {
			return nil, off, err
		}
		return float64(math.Float32frombits(uint32(v))), next, nil
	case 0xcb:
		v, next, err := readUintN(b, off+1, 8)
		if err != nil {
			return nil, off, err
		}
		return math.Float64frombits(v), next, nil
	case 0xcc, 0xcd, 0xce, 0xcf: // uint8/16/32/64
		v, next, err := readUintN(b, off+1, 1<<(c-0xcc))
		if err != nil {
			return nil, off, err
		}
		return int64(v), next, nil // msfrpcd never sends values above MaxInt64
	case 0xd0, 0xd1, 0xd2, 0xd3: // int8/16/32/64
		size := 1 << (c - 0xd0)
		v, next, err := readUintN(b, off+1, size)
		if err != nil {
			return nil, off, err
		}
		switch size {
		case 1:
			return int64(int8(v)), next, nil
		case 2:
			return int64(int16(v)), next, nil
		case 4:
			return int64(int32(v)), next, nil
		default:
			return int64(v), next, nil
		}
	case 0xd4, 0xd5, 0xd6, 0xd7, 0xd8: // fixext 1/2/4/8/16
		size := 1 << (c - 0xd4)
		if off+2+size > len(b) {
			return nil, off, fmt.Errorf("msgpack: ext 长度越界")
		}
		return append([]byte(nil), b[off+2:off+2+size]...), off + 2 + size, nil
	case 0xc7, 0xc8, 0xc9: // ext8/16/32
		size, next, err := readSize(b, off+1, 1<<(c-0xc7))
		if err != nil {
			return nil, off, err
		}
		if next+1+size > len(b) {
			return nil, off, fmt.Errorf("msgpack: ext 长度越界")
		}
		return append([]byte(nil), b[next+1:next+1+size]...), next + 1 + size, nil
	case 0xd9, 0xda, 0xdb: // str8/16/32
		size, next, err := readSize(b, off+1, 1<<(c-0xd9))
		if err != nil {
			return nil, off, err
		}
		return readString(b, next, size)
	case 0xdc, 0xdd: // array16/32
		size, next, err := readSize(b, off+1, 2<<(c-0xdc))
		if err != nil {
			return nil, off, err
		}
		return readArray(b, next, size)
	case 0xde, 0xdf: // map16/32
		size, next, err := readSize(b, off+1, 2<<(c-0xde))
		if err != nil {
			return nil, off, err
		}
		return readMap(b, next, size)
	}
	return nil, off, fmt.Errorf("msgpack: 未知类型标记 0x%02x", c)
}

// readSize reads a 1/2/4-byte big-endian length; width is that byte count.
func readSize(b []byte, off int, width int) (int, int, error) {
	v, next, err := readUintN(b, off, width)
	if err != nil {
		return 0, off, err
	}
	if v > uint64(len(b)) {
		return 0, off, fmt.Errorf("msgpack: 声明长度 %d 超过报文长度 %d", v, len(b))
	}
	return int(v), next, nil
}

func readUintN(b []byte, off, n int) (uint64, int, error) {
	if off+n > len(b) {
		return 0, off, fmt.Errorf("msgpack: 数据提前结束")
	}
	var v uint64
	for i := 0; i < n; i++ {
		v = v<<8 | uint64(b[off+i])
	}
	return v, off + n, nil
}

func readString(b []byte, off, size int) (any, int, error) {
	if off+size > len(b) {
		return nil, off, fmt.Errorf("msgpack: str 长度越界")
	}
	return string(b[off : off+size]), off + size, nil
}

func readArray(b []byte, off, size int) (any, int, error) {
	out := make([]any, 0, size)
	for i := 0; i < size; i++ {
		v, next, err := decodeAt(b, off)
		if err != nil {
			return nil, off, err
		}
		out = append(out, v)
		off = next
	}
	return out, off, nil
}

func readMap(b []byte, off, size int) (any, int, error) {
	out := make(map[string]any, size)
	for i := 0; i < size; i++ {
		k, next, err := decodeAt(b, off)
		if err != nil {
			return nil, off, err
		}
		off = next
		v, next, err := decodeAt(b, off)
		if err != nil {
			return nil, off, err
		}
		off = next
		key, ok := k.(string)
		if !ok {
			// Ruby's msgpack encodes strings as bin, so msfrpcd replies carry
			// []byte keys even though they are field names.
			if b, isBin := k.([]byte); isBin {
				key = string(b)
			} else {
				key = fmt.Sprint(k)
			}
		}
		out[key] = v
	}
	return out, off, nil
}
