// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExecutorBase(t *testing.T) {
	dir := t.TempDir()
	prog := filepath.Join(dir, "merged.syz")
	if err := os.WriteFile(prog, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	// -minimize-* take a program file: stage next to it, i.e. the job root.
	if got := executorBase(prog); got != dir {
		t.Errorf("executorBase(file) = %q, want %q", got, dir)
	}
	// The replay mode takes the ring buffer directory itself.
	if got := executorBase(dir); got != dir {
		t.Errorf("executorBase(dir) = %q, want %q", got, dir)
	}
	// A path that does not exist yet is treated as a file.
	missing := filepath.Join(dir, "sub", "culprit.syz")
	if got, want := executorBase(missing), filepath.Join(dir, "sub"); got != want {
		t.Errorf("executorBase(missing) = %q, want %q", got, want)
	}
}

func TestStageExecutorCopiesAndIsExecutable(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "syz-executor")
	if err := os.WriteFile(src, []byte("ELF-ish"), 0755); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "bluetoothd")
	if err := stageExecutor(src, dst); err != nil {
		t.Fatalf("stageExecutor: %v", err)
	}
	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "ELF-ish" {
		t.Errorf("staged content = %q", data)
	}
	fi, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	// Darwin takes p_comm from the file executed, so the copy has to be runnable.
	if fi.Mode().Perm()&0111 == 0 {
		t.Errorf("staged copy is not executable: %v", fi.Mode())
	}
	// No .tmp left behind by the atomic write.
	if _, err := os.Stat(dst + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file survived: %v", err)
	}
}

func TestStageExecutorRefreshesOnlyWhenStale(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "syz-executor")
	dst := filepath.Join(dir, "bluetoothd")
	if err := os.WriteFile(src, []byte("v1"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := stageExecutor(src, dst); err != nil {
		t.Fatal(err)
	}
	// An up-to-date copy is left alone: re-staging must not rewrite it.
	before, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if err := stageExecutor(src, dst); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Errorf("copy was rewritten though it was current")
	}
	// A rebuilt executor IS picked up, so a stale copy cannot silently outlive a
	// rebuild and run the wrong code under the right name.
	newer := time.Now().Add(2 * time.Second)
	if err := os.WriteFile(src, []byte("v2"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(src, newer, newer); err != nil {
		t.Fatal(err)
	}
	if err := stageExecutor(src, dst); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "v2" {
		t.Errorf("stale copy not refreshed: got %q, want %q", data, "v2")
	}
}

func TestStageExecutorReportsUnwritableDir(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "syz-executor")
	if err := os.WriteFile(src, []byte("x"), 0755); err != nil {
		t.Fatal(err)
	}
	ro := filepath.Join(dir, "ro")
	if err := os.Mkdir(ro, 0555); err != nil {
		t.Fatal(err)
	}
	// Fail loudly rather than fall back to the un-renamed executor: running under
	// the wrong name is exactly the silent no-op this flag exists to prevent.
	if err := stageExecutor(src, filepath.Join(ro, "bluetoothd")); err == nil {
		t.Errorf("staging into an unwritable dir succeeded, want an error")
	}
}

func TestStageExecutorMissingSource(t *testing.T) {
	dir := t.TempDir()
	err := stageExecutor(filepath.Join(dir, "absent"), filepath.Join(dir, "bluetoothd"))
	if err == nil {
		t.Fatalf("staging a missing executor succeeded, want an error")
	}
}
