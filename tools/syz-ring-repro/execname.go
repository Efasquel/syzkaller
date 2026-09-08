// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Running the executor under a different process name.
//
// Some IOKit drivers refuse to hand out a user client unless the calling process
// has an expected name. IOBluetoothHCIControllerUserClient is one: it returns
// kIOReturnUnsupported (0xe00002c7) to every caller whose p_comm is not
// "bluetoothd". Under the wrong name no connection is ever created, so every
// later IOConnectCallMethod is inert and minimization concludes that nothing
// reproduces -- having never reached the driver at all.
//
// That is not hypothetical. Campaign drivers_260902 ran four consecutive
// IOBluetoothFamily minimizations (jobs t4-t7) for 25,461 probes with zero
// reproductions, all four "exhausted", while the three non-Bluetooth jobs in the
// same campaign found a verified culprit in <=39 probes each. Measured on the
// box, same program and flags, only the executed file's name differing:
//
//	executed as `syz-executor`  ->  IOServiceOpen = 0xffffffffe00002c7
//	executed as `bluetoothd`    ->  IOServiceOpen = 0x0
//
// syz-manager's side of this already worked (mgrconfig's executor_name, staged by
// fuzz-session.py); only minimization ran under the wrong name. So the flag here
// exists to make the tool self-sufficient: a hand-run `syz-ring-repro
// -minimize-conn` on a Bluetooth bug has to be able to set the name without a
// manager config, or it silently reproduces the same 25,000-probe no-op.
//
// Darwin takes p_comm from the file that was executed, not from argv[0], so the
// only way to set it is to exec a copy of the executor under that name -- a copy,
// not a symlink, because p_comm comes from the file actually executed.

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/tool"
)

// Darwin stores a process name in two struct proc fields, and which one a kext
// reads decides how much of -executor_name survives (verified on macOS 26.5):
//
//	p_comm     16 bytes -- ps -o ucomm, proc_selfname(), AND the kernel proc_name()
//	                       KPI, which does strlcpy(buf, p->p_comm, MIN(sizeof
//	                       p_comm, size)); the caller's buffer size cannot lift it.
//	p_name    ~31 bytes -- proc_best_name(), and the userspace libproc proc_name().
//	full path           -- proc_pidpath().
//
// 16 is the only bound safe no matter which API the kext calls, so that is where
// we warn. Names of 17-31 are fine *if* the kext uses proc_best_name/libproc.
const (
	maxComLen   = 16
	procNameMax = 31
)

// execBaseDir is the directory the renamed executor copy is staged in: the job
// root, alongside the program being minimized and its conn_state.json/culprit.syz.
// Set by main from the positional argument.
var execBaseDir string

// executorBase picks the staging directory for a positional argument that is
// either a program file (the -minimize-* modes) or a ring buffer directory (the
// replay mode).
func executorBase(dir string) string {
	if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
		return dir
	}
	return filepath.Dir(dir)
}

// resolveExecutor returns the path to exec, honouring -executor_name. Called only
// from the two paths that actually run a program, so the offline modes (-merge,
// -emit-culprit, -emit-json) never stage a copy.
func resolveExecutor() string {
	name := strings.TrimSpace(*flagExecutorName)
	if name == "" {
		return *flagExecutor
	}
	if strings.ContainsRune(name, filepath.Separator) || name == "." || name == ".." {
		tool.Failf("-executor_name must be a bare filename, not a path: %q", name)
	}
	if n := len(name); n > maxComLen {
		log.Logf(0, "warning: -executor_name %q is %d bytes; p_comm keeps only %d, so a kext using "+
			"proc_name()/proc_selfname sees %q. Names of %d-%d survive only if it uses "+
			"proc_best_name/libproc (which keep ~%d).",
			name, n, maxComLen, name[:maxComLen], maxComLen+1, procNameMax, procNameMax)
	}
	base := execBaseDir
	if base == "" {
		base = "."
	}
	// Absolute, because exec.Command does a PATH lookup for any name with no
	// separator in it -- a relative "bluetoothd" would not resolve to the copy we
	// just staged, it would search $PATH and fail.
	dst, err := filepath.Abs(filepath.Join(base, name))
	if err != nil {
		tool.Failf("cannot resolve %s/%s: %v", base, name, err)
	}
	if err := stageExecutor(*flagExecutor, dst); err != nil {
		tool.Failf("cannot stage the executor as %q in %s: %v\n"+
			"The renamed copy must live in a directory this user can write; that is normally the "+
			"job root, next to the program being minimized.", name, base, err)
	}
	log.Logf(0, "executing as %q (copy of %s at %s)", name, *flagExecutor, dst)
	return dst
}

// stageExecutor copies src to dst unless dst already exists and is no older than
// src, so a rebuilt executor is picked up but repeated runs do not re-copy.
func stageExecutor(src, dst string) error {
	si, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("executor %s: %w", src, err)
	}
	if di, err := os.Stat(dst); err == nil && !di.ModTime().Before(si.ModTime()) {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	// Write to a temp name and rename, so a copy interrupted partway cannot leave
	// a truncated binary that later runs would happily exec.
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0755); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
