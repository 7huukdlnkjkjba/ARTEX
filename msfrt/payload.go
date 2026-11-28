// Package msfrt carries Metasploit's portable runtime inside the ARTEX binary.
//
// ARTEX ships as one file: the Go binary plus a runtime archive (portable Ruby +
// the Metasploit framework with its gems) appended as a trailer, or compiled in
// with `-tags embedruntime`. On first use the archive is unpacked under the
// user's local cache and msfrpcd is started from the unpacked tree, so a clean
// machine needs no Ruby, no Metasploit install and no network.
package msfrt

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Trailer layout (see scripts/append-payload.ps1):
//
//	[archive bytes][uint64 little-endian length][8-byte magic]
const (
	trailerMagic  = "ARTEXRT1"
	trailerHeader = 16 // 8 length + 8 magic
)

// Archive is the runtime payload, readable without loading it into memory.
type Archive struct {
	ReaderAt io.ReaderAt
	Size     int64
	Version  string // short hash of the payload; also the extraction dir name
	Source   string // "trailer" or "embed", for logs
	close    func() error
}

// Close releases the underlying file (no-op for the embedded copy).
func (a *Archive) Close() error {
	if a == nil || a.close == nil {
		return nil
	}
	return a.close()
}

// Open resolves the runtime payload: a trailer appended to this executable wins,
// then a build-time embedding (-tags embedruntime), then ARTEX_MSF_RUNTIME_ZIP
// pointing at a local archive (handy for development).
func Open() (*Archive, error) {
	self, err := os.Executable()
	if err == nil {
		if a, tErr := openTrailer(self); tErr == nil {
			return a, nil
		}
	}
	if len(embeddedPayload) > 0 {
		return newArchive(bytes.NewReader(embeddedPayload), int64(len(embeddedPayload)), "embed", nil)
	}
	if p := strings.TrimSpace(os.Getenv("ARTEX_MSF_RUNTIME_ZIP")); p != "" {
		f, fErr := os.Open(p)
		if fErr != nil {
			return nil, fmt.Errorf("ARTEX_MSF_RUNTIME_ZIP 打不开：%w", fErr)
		}
		st, stErr := f.Stat()
		if stErr != nil {
			_ = f.Close()
			return nil, stErr
		}
		return newArchive(f, st.Size(), "file:"+p, f.Close)
	}
	return nil, fmt.Errorf("二进制里没有内置 Metasploit 运行时（既无 trailer 也无 embed）；用 scripts/build-runtime.ps1 + scripts/append-payload.ps1 出单文件，或设 ARTEX_MSF_RUNTIME_ZIP 指向 runtime.zip")
}

// HasPayload reports whether a runtime archive is reachable (no extraction).
func HasPayload() bool {
	a, err := Open()
	if err != nil {
		return false
	}
	_ = a.Close()
	return true
}

// openTrailer looks for the trailer at the end of exe.
func openTrailer(exe string) (*Archive, error) {
	f, err := os.Open(exe)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if st.Size() < trailerHeader {
		_ = f.Close()
		return nil, fmt.Errorf("文件太小，没有 trailer")
	}
	tail := make([]byte, trailerHeader)
	if _, err := f.ReadAt(tail, st.Size()-trailerHeader); err != nil {
		_ = f.Close()
		return nil, err
	}
	if string(tail[8:]) != trailerMagic {
		_ = f.Close()
		return nil, fmt.Errorf("没有 runtime trailer")
	}
	n := int64(binary.LittleEndian.Uint64(tail[:8]))
	start := st.Size() - trailerHeader - n
	if n <= 0 || start < 0 {
		_ = f.Close()
		return nil, fmt.Errorf("trailer 长度非法：%d", n)
	}
	return newArchive(io.NewSectionReader(f, start, n), n, "trailer", f.Close)
}

// newArchive hashes the payload once so extraction is content-addressed: a new
// build lands in a new directory, an identical build reuses the old one.
func newArchive(ra io.ReaderAt, size int64, source string, closeFn func() error) (*Archive, error) {
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(ra, 0, size)); err != nil {
		if closeFn != nil {
			_ = closeFn()
		}
		return nil, fmt.Errorf("读取运行时包失败：%w", err)
	}
	sum := h.Sum(nil)
	return &Archive{
		ReaderAt: ra,
		Size:     size,
		Version:  hex.EncodeToString(sum[:8]),
		Source:   source,
		close:    closeFn,
	}, nil
}

// CacheBase is where runtimes are unpacked: %LOCALAPPDATA%\ARTEX\runtime on
// Windows, $XDG_CACHE_HOME/artex/runtime elsewhere.
func CacheBase() string {
	if v := strings.TrimSpace(os.Getenv("ARTEX_MSF_RUNTIME_DIR")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("LOCALAPPDATA")); v != "" {
		return filepath.Join(v, "ARTEX", "runtime")
	}
	if v := strings.TrimSpace(os.Getenv("XDG_CACHE_HOME")); v != "" {
		return filepath.Join(v, "artex", "runtime")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cache", "artex", "runtime")
}
