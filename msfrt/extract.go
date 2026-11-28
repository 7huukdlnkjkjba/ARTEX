package msfrt

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Runtime is an unpacked runtime tree (contains embedded\..., LICENSES\...).
type Runtime struct {
	Root    string
	Version string
	Fresh   bool // true when this call unpacked it
}

// EnsureExtracted unpacks the archive under the platform cache dir, unless an
// identical build is already there (content-addressed by payload hash).
func (a *Archive) EnsureExtracted() (*Runtime, error) {
	return a.EnsureExtractedAt(CacheBase())
}

// EnsureExtractedAt is EnsureExtracted with an explicit base directory (tests).
func (a *Archive) EnsureExtractedAt(base string) (*Runtime, error) {
	dest := filepath.Join(base, a.Version)
	stamp := filepath.Join(dest, ".ready")
	if _, err := os.Stat(stamp); err == nil {
		return &Runtime{Root: dest, Version: a.Version}, nil
	}
	if err := os.MkdirAll(base, 0o755); err != nil {
		return nil, fmt.Errorf("创建运行时目录 %s 失败：%w", base, err)
	}
	tmp := fmt.Sprintf("%s.tmp-%d", dest, os.Getpid())
	_ = os.RemoveAll(tmp)
	if err := a.extractTo(tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(tmp, ".ready"), []byte(a.Version+"\n"), 0o644); err != nil {
		_ = os.RemoveAll(tmp)
		return nil, fmt.Errorf("写版本戳失败：%w", err)
	}
	_ = os.RemoveAll(dest)
	if err := os.Rename(tmp, dest); err != nil {
		// A concurrent first run may have won the race.
		if _, statErr := os.Stat(stamp); statErr == nil {
			_ = os.RemoveAll(tmp)
			return &Runtime{Root: dest, Version: a.Version}, nil
		}
		_ = os.RemoveAll(tmp)
		return nil, fmt.Errorf("安装运行时到 %s 失败：%w", dest, err)
	}
	return &Runtime{Root: dest, Version: a.Version, Fresh: true}, nil
}

// extractTo unpacks every entry into dir, refusing paths that escape it
// (zip-slip) and preserving the executable bit on unix.
func (a *Archive) extractTo(dir string) error {
	zr, err := zip.NewReader(a.ReaderAt, a.Size)
	if err != nil {
		return fmt.Errorf("打开内置运行时失败：%w", err)
	}
	clean := filepath.Clean(dir)
	for _, f := range zr.File {
		name := strings.ReplaceAll(f.Name, "\\", "/")
		if name == "" || strings.HasSuffix(name, "/") {
			continue
		}
		dst := filepath.Join(clean, filepath.FromSlash(name))
		if dst != clean && !strings.HasPrefix(dst, clean+string(os.PathSeparator)) {
			return fmt.Errorf("内置运行时含非法路径：%s", f.Name)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return fmt.Errorf("创建目录失败（%s）：%w", dst, err)
		}
		mode := os.FileMode(0o644)
		if f.Mode()&0o111 != 0 {
			mode = 0o755
		}
		if err := writeZipEntry(f, dst, mode); err != nil {
			return fmt.Errorf("写入 %s 失败：%w", dst, err)
		}
	}
	return nil
}

func writeZipEntry(f *zip.File, dst string, mode os.FileMode) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()
	// %%?%% prefix: Metasploit's module tree is deep enough to hit MAX_PATH when
	// the runtime lives under %LOCALAPPDATA%.
	out, err := os.OpenFile(LongPath(dst), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, rc); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// LongPath applies the Windows extended-length prefix so extraction does not
// stop at 260 characters. Elsewhere it is the identity.
func LongPath(p string) string {
	if runtime.GOOS != "windows" {
		return p
	}
	if strings.HasPrefix(p, `\\?\`) {
		return p
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return `\\?\` + abs
}
