package server

// png_stego stores/retrieves a bounded payload in the RGB LSBs of a PNG.
// Format: "ARTX" magic + uint32 little-endian length + payload, bit-packed MSB
// first across R,G,B of each pixel. Alpha is preserved.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"log"
	"os"
	"path/filepath"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

const (
	stegoMagic      = "ARTX"
	stegoMaxPayload = 4 << 20
)

type pngStegoParams struct {
	Action       string `json:"action"`
	ImagePath    string `json:"image_path"`
	Payload      string `json:"payload,omitempty"`
	OutPath      string `json:"out_path"`
	ReturnBase64 bool   `json:"return_payload,omitempty"`
}

func (s *Server) pngStegoTools() []actool.CoreTool {
	return []actool.CoreTool{s.toolPNGStego()}
}

func (s *Server) seedPNGStegoTools() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	workerAgents, _ := json.Marshal([]string{"worker"})
	for _, t := range s.pngStegoTools() {
		schema, _ := json.Marshal(t.InputSchema())
		if err := s.m.PG().SeedTool(t.Name(), t.Description(), schema, workerAgents); err != nil {
			log.Printf("[tools] seed %s 失败: %v", t.Name(), err)
		}
	}
}

func (s *Server) toolPNGStego() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        "png_stego",
		Description: "【PNG LSB 隐写】把 Base64 payload 隐藏到 PNG 的 RGB 最低有效位，或从 PNG 提取。执行归代码：容量校验、位运算、PNG 编解码、SHA-256；不生成/不执行 payload。",
		Schema: objSchema(map[string]any{
			"action":         strParam("hide | extract"),
			"image_path":     strParam("载体 PNG 路径；hide 时不存在则生成 1000x1000 纯色底板"),
			"payload":        strParam("Base64 编码的 payload（hide 用）"),
			"out_path":       strParam("输出文件路径（hide 输出 PNG，extract 输出原始 payload）"),
			"return_payload": map[string]any{"type": "boolean", "description": "extract 时是否在结果里返回 Base64（≤1MB；默认 false）"},
		}, "action", "image_path", "out_path"),
		ReadOnly:    func(json.RawMessage) bool { return false },
		Permissions: sessionPerm,
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var p pngStegoParams
			if err := json.Unmarshal(in, &p); err != nil {
				return actool.Errorf("参数解析失败：" + err.Error()), nil
			}
			p.Action = strings.ToLower(strings.TrimSpace(p.Action))
			p.ImagePath = strings.TrimSpace(p.ImagePath)
			p.OutPath = strings.TrimSpace(p.OutPath)
			if p.ImagePath == "" || p.OutPath == "" {
				return actool.Errorf("image_path/out_path 必填"), nil
			}
			switch p.Action {
			case "hide":
				payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(p.Payload))
				if err != nil {
					return actool.Errorf("payload 需为 Base64: " + err.Error()), nil
				}
				if len(payload) == 0 || len(payload) > stegoMaxPayload {
					return actool.Errorf("payload 长度需在 1..4MB"), nil
				}
				img, err := loadOrCreateStegoImage(p.ImagePath)
				if err != nil {
					return actool.Errorf("载体图片失败: " + err.Error()), nil
				}
				if capacityBytes(img) < 8+len(payload) {
					return actool.Errorf(fmt.Sprintf("载体容量不足：需要 %d 字节，最多 %d", 8+len(payload), capacityBytes(img))), nil
				}
				if err := hidePNG(img, payload, p.OutPath); err != nil {
					return actool.Errorf("隐写失败: " + err.Error()), nil
				}
				sum := sha256.Sum256(payload)
				return jsonResult(map[string]any{
					"status": "success", "action": "hide", "out_path": p.OutPath,
					"bytes_hidden": len(payload), "sha256": hex.EncodeToString(sum[:]),
					"capacity_bytes": capacityBytes(img),
				})
			case "extract":
				img, err := loadPNG(p.ImagePath)
				if err != nil {
					return actool.Errorf("解码图片失败: " + err.Error()), nil
				}
				payload, err := extractPNG(img)
				if err != nil {
					return actool.Errorf("提取失败: " + err.Error()), nil
				}
				if err := os.MkdirAll(filepath.Dir(p.OutPath), 0o755); err != nil {
					return actool.Errorf("创建输出目录失败: " + err.Error()), nil
				}
				if err := os.WriteFile(p.OutPath, payload, 0o600); err != nil {
					return actool.Errorf("写输出失败: " + err.Error()), nil
				}
				sum := sha256.Sum256(payload)
				res := map[string]any{
					"status": "success", "action": "extract", "out_path": p.OutPath,
					"bytes_extracted": len(payload), "sha256": hex.EncodeToString(sum[:]),
				}
				if p.ReturnBase64 && len(payload) <= 1<<20 {
					res["payload_b64"] = base64.StdEncoding.EncodeToString(payload)
				}
				return jsonResult(res)
			}
			return actool.Errorf("action 只支持 hide/extract"), nil
		},
	})
}

func loadPNG(path string) (image.Image, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	img, err := png.Decode(f)
	if err != nil {
		return nil, err
	}
	return img, nil
}

func loadOrCreateStegoImage(path string) (image.Image, error) {
	if _, err := os.Stat(path); err == nil {
		return loadPNG(path)
	}
	return image.NewRGBA(image.Rect(0, 0, 1000, 1000)), nil
}

func capacityBytes(img image.Image) int {
	b := img.Bounds()
	return (b.Dx() * b.Dy() * 3) / 8
}

func hidePNG(img image.Image, payload []byte, outPath string) error {
	bounds := img.Bounds()
	rgba := image.NewRGBA(bounds)
	header := make([]byte, 8)
	copy(header[:4], []byte(stegoMagic))
	binary.LittleEndian.PutUint32(header[4:], uint32(len(payload)))
	full := append(header, payload...)
	totalBits := len(full) * 8
	if totalBits > bounds.Dx()*bounds.Dy()*3 {
		return fmt.Errorf("载体容量不足")
	}
	bitIdx := 0
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			r, g, b, a := img.At(x, y).RGBA()
			outR, outG, outB := uint8(r>>8), uint8(g>>8), uint8(b>>8)
			for c := 0; c < 3 && bitIdx < totalBits; c++ {
				bit := (full[bitIdx/8] >> (7 - (bitIdx % 8))) & 1
				switch c {
				case 0:
					outR = (outR &^ 1) | bit
				case 1:
					outG = (outG &^ 1) | bit
				case 2:
					outB = (outB &^ 1) | bit
				}
				bitIdx++
			}
			rgba.Set(x, y, color.RGBA{R: outR, G: outG, B: outB, A: uint8(a >> 8)})
		}
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return err
	}
	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.DefaultCompression}
	if err := enc.Encode(&buf, rgba); err != nil {
		return err
	}
	return os.WriteFile(outPath, buf.Bytes(), 0o600)
}

func extractPNG(img image.Image) ([]byte, error) {
	header, err := readLSBBytes(img, 8)
	if err != nil {
		return nil, err
	}
	if string(header[:4]) != stegoMagic {
		return nil, fmt.Errorf("未找到 ARTX 隐写头")
	}
	n := int(binary.LittleEndian.Uint32(header[4:]))
	if n <= 0 || n > stegoMaxPayload {
		return nil, fmt.Errorf("长度非法: %d", n)
	}
	if capacityBytes(img) < 8+n {
		return nil, fmt.Errorf("数据长度超过载体容量")
	}
	return readLSBBytesFrom(img, 8, n)
}

func readLSBBytes(img image.Image, n int) ([]byte, error) {
	return readLSBBytesFrom(img, 0, n)
}

func readLSBBytesFrom(img image.Image, skipBytes, n int) ([]byte, error) {
	totalBits := (skipBytes + n) * 8
	b := img.Bounds()
	if totalBits > b.Dx()*b.Dy()*3 {
		return nil, fmt.Errorf("位流不足")
	}
	out := make([]byte, n)
	bitPos := 0
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r, g, bl, _ := img.At(x, y).RGBA()
			ch := []uint8{uint8(r), uint8(g), uint8(bl)}
			for c := 0; c < 3; c++ {
				if bitPos >= totalBits {
					return out, nil
				}
				if bitPos >= skipBytes*8 {
					byteIdx := bitPos/8 - skipBytes
					out[byteIdx] = (out[byteIdx] << 1) | (ch[c] & 1)
				}
				bitPos++
			}
		}
	}
	return out, nil
}
