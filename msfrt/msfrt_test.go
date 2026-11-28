package msfrt

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// buildZip creates an in-memory archive with the given entries.
func buildZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func runtimeFiles() map[string]string {
	ruby := "embedded/bin/ruby.exe"
	if runtime.GOOS != "windows" {
		ruby = "embedded/bin/ruby"
	}
	return map[string]string{
		ruby:                          "#!/bin/sh\nexit 0\n",
		"embedded/framework/msfrpcd":  "#!/usr/bin/env ruby\n",
		"embedded/framework/Gemfile":  "source 'https://rubygems.org'\n",
		"embedded/framework/lib/a.rb": "module A; end\n",
		"LICENSES/LICENSE":            "BSD-3-Clause\n",
	}
}

func TestArchiveExtractAndSpec(t *testing.T) {
	payload := buildZip(t, runtimeFiles())
	a, err := newArchive(bytes.NewReader(payload), int64(len(payload)), "test", nil)
	if err != nil {
		t.Fatalf("newArchive: %v", err)
	}
	if a.Version == "" || len(a.Version) != 16 {
		t.Fatalf("version=%q", a.Version)
	}
	base := t.TempDir()
	rt, err := a.EnsureExtractedAt(base)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if !rt.Fresh {
		t.Fatal("首次解压应标 Fresh")
	}
	if _, err := os.Stat(filepath.Join(rt.Root, ".ready")); err != nil {
		t.Fatalf("缺版本戳：%v", err)
	}
	spec, err := rt.Spec()
	if err != nil {
		t.Fatalf("spec: %v", err)
	}
	if spec.Cmd == "" || len(spec.Args) == 0 || spec.Dir == "" {
		t.Fatalf("spec=%+v", spec)
	}
	if !filepath.IsAbs(spec.Cmd) || filepath.Base(spec.Args[0]) != "msfrpcd" {
		t.Fatalf("spec 路径异常：%+v", spec)
	}
	var hasBundle, hasPath bool
	for _, kv := range spec.Env {
		if len(kv) > len("BUNDLE_GEMFILE=") && kv[:len("BUNDLE_GEMFILE=")] == "BUNDLE_GEMFILE=" {
			hasBundle = true
		}
		if len(kv) > 5 && kv[:5] == "PATH=" {
			hasPath = true
		}
	}
	if !hasBundle || !hasPath {
		t.Fatalf("env 缺 BUNDLE_GEMFILE/PATH：%v", spec.Env)
	}

	// 第二次必须是复用（不重复解压、Fresh=false）。
	again, err := a.EnsureExtractedAt(base)
	if err != nil {
		t.Fatalf("second extract: %v", err)
	}
	if again.Fresh {
		t.Fatal("第二次不应重新解压")
	}
	if again.Root != rt.Root {
		t.Fatalf("root 漂移：%s != %s", again.Root, rt.Root)
	}
}

func TestExtractRejectsZipSlip(t *testing.T) {
	payload := buildZip(t, map[string]string{
		"embedded/framework/msfrpcd": "x",
		"../escaped.txt":             "nope",
	})
	a, err := newArchive(bytes.NewReader(payload), int64(len(payload)), "test", nil)
	if err != nil {
		t.Fatalf("newArchive: %v", err)
	}
	if _, err := a.EnsureExtractedAt(t.TempDir()); err == nil {
		t.Fatal("zip-slip 路径必须被拒绝")
	}
}

func TestOpenTrailer(t *testing.T) {
	payload := buildZip(t, runtimeFiles())
	exe := filepath.Join(t.TempDir(), "fake.exe")
	f, err := os.Create(exe)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("MZ fake exe")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(payload); err != nil {
		t.Fatal(err)
	}
	var lenbuf [8]byte
	binary.LittleEndian.PutUint64(lenbuf[:], uint64(len(payload)))
	if _, err := f.Write(lenbuf[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(trailerMagic)); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	a, err := openTrailer(exe)
	if err != nil {
		t.Fatalf("openTrailer: %v", err)
	}
	defer func() { _ = a.Close() }()
	if a.Size != int64(len(payload)) || a.Source != "trailer" {
		t.Fatalf("size=%d source=%s", a.Size, a.Source)
	}
	rt, err := a.EnsureExtractedAt(t.TempDir())
	if err != nil {
		t.Fatalf("trailer 解压失败：%v", err)
	}
	if _, err := os.Stat(filepath.Join(rt.Root, "embedded", "framework", "msfrpcd")); err != nil {
		t.Fatalf("trailer 内容缺失：%v", err)
	}
}

func TestOpenWithoutPayload(t *testing.T) {
	// 没有 trailer、没有 embed、没设环境变量时必须给出可执行的提示。
	t.Setenv("ARTEX_MSF_RUNTIME_ZIP", "")
	exe := filepath.Join(t.TempDir(), "plain.exe")
	if err := os.WriteFile(exe, []byte("MZ no payload here at all"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := openTrailer(exe); err == nil {
		t.Fatal("无 trailer 时应报错")
	}
}
