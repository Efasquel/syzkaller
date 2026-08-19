// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Offline culprit emission. Unlike -minimize-conn this runs no programs and touches
// no device: it reads the checkpoint left by an -minimize-conn run and writes out
// the program for the smallest subset known to crash. It is the automation seam
// — a campaign script runs -minimize-conn until a crash lands the culprit in the
// checkpoint, then calls -emit-culprit to materialize that subset and feed it to
// whatever isolated test the script wants (e.g. syz-execprog on a fresh boot).
//
// It never modifies conn_state.json, so it is safe to call at any point, as
// often as wanted, in parallel with nothing.

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
)

// resolveStatePath returns the checkpoint path: the -state override if set,
// otherwise defaultName alongside the program file. The default differs per
// command (conn_state.json vs call_state.json) so the two stages do not collide
// when run in the same directory.
func resolveStatePath(progFile, defaultName string) string {
	if *flagState != "" {
		return *flagState
	}
	return filepath.Join(filepath.Dir(progFile), defaultName)
}

// resolveCulpritPath returns the reproducer output path: the -culprit override
// if set, otherwise culprit.syz alongside the program file.
func resolveCulpritPath(progFile string) string {
	if *flagCulprit != "" {
		return *flagCulprit
	}
	return filepath.Join(filepath.Dir(progFile), "culprit.syz")
}

// reductionForKind builds the reduction that a checkpoint of the given kind was
// produced by, so its masks can be turned back into programs. An empty or
// unknown kind defaults to connection, which is also what pre-Kind checkpoints
// (older conn_state.json files) record.
func reductionForKind(p *prog.Prog, kind string) (reduction, error) {
	if kind == kindCall {
		return callReduction(p)
	}
	return connReduction(p)
}

// runEmitCulprit loads the program and a checkpoint, picks the smallest known
// crashing subset, and writes the corresponding program to the culprit path. It
// works for either stage: the checkpoint records its Kind, so emission rebuilds
// the matching reduction (connections or method calls). It fails (non-zero exit)
// when no crashing subset has been recorded yet, so a script can branch on the
// exit code: success means "a candidate is ready to test", failure means "keep
// minimizing".
func runEmitCulprit(target *prog.Target, progFile string) error {
	p, err := readProg(target, progFile)
	if err != nil {
		return err
	}
	statePath := resolveStatePath(progFile, "conn_state.json")
	culpritPath := resolveCulpritPath(progFile)

	// Peek at the checkpoint to learn which reduction wrote it, then build that
	// reduction so its masks resolve correctly.
	peek := readDdState(statePath)
	if peek == nil {
		return fmt.Errorf("no checkpoint at %s; run -minimize-conn or -minimize-calls first", statePath)
	}
	red, err := reductionForKind(p, peek.Kind)
	if err != nil {
		return fmt.Errorf("%w in %s", err, progFile)
	}

	// Read-only: load the checkpoint but never save it, so emission cannot
	// disturb a running minimization's state. kind="" accepts whatever the file
	// records. Recovery of a pending Attempting mask happens in memory here
	// (loadDdState is silent), which is what lets emission work immediately after
	// a crash, before the box has been relaunched.
	state := loadDdState(statePath, red.n, progHash(p), "")
	mask, verified, ok := state.bestCulprit()
	if !ok {
		return fmt.Errorf("no crashing subset recorded in %s yet; keep minimizing", statePath)
	}

	sub := red.extract(mask)
	if err := os.WriteFile(culpritPath, sub.Serialize(), 0644); err != nil {
		return fmt.Errorf("write culprit: %w", err)
	}
	if err := syncDir(filepath.Dir(culpritPath)); err != nil {
		return fmt.Errorf("sync culprit dir: %w", err)
	}

	status := "NOT verified (never re-checked on its own)"
	if verified {
		status = "verified (crashes on its own)"
	}
	log.Logf(0, "Culprit so far: %s, %s.", plural(popcount(mask), red.label), status)
	for _, i := range setBits(mask) {
		log.Logf(0, "  [%d] %s", i, red.describe(i))
	}
	log.Logf(0, "Wrote %d-call reproducer to %s", len(sub.Calls), culpritPath)
	return nil
}
