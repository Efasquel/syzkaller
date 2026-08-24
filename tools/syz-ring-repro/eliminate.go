// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// On-device execution loop for connection-elimination. The pure logic lives in
// connection.go (grouping), search.go (strategy) and ddmin.go (halving,
// checkpoint); this file drives them against the real executor via RunLocal.
//
// It supplies the one thing those cannot: a predicate that answers "does this
// subset of connections reproduce the crash?" on a machine the crash reboots.
// The answer is read from the process's own survival. A subset that does not
// reproduce returns in-process, so a single boot clears many of them. A subset
// that does reproduce panics the kernel and kills this process mid-probe — so
// the pending mask is fsync'd to the checkpoint *before* the run, and on the
// next boot loadDdState recovers it as a crash. The search is deterministic, so
// re-running replays every decided probe instantly and continues from there.
// The campaign driver only has to relaunch this command after a reboot.

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpcserver"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
)

// reduction describes a family of subprograms of p indexed by a bitmask over n
// units — bit i keeps unit i. Connection-minimization and call-minimization are
// two instances; everything below (the crash-safe search, the checkpoint, and
// the isolation re-check) is identical for both and lives in minimize.
type reduction struct {
	label    string                       // singular noun for logs: "connection", "call"
	n        int                          // number of reducible units (mask width)
	extract  func(mask uint64) *prog.Prog // self-contained program for the kept units
	describe func(i int) string           // one-line description of unit i, for logs
}

// plural renders a count with its noun, adding an "s" for anything but one,
// e.g. plural(1, "call") == "1 call", plural(3, "connection") == "3 connections".
func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// readProg reads and deserializes a syzkaller program file.
func readProg(target *prog.Target, progFile string) (*prog.Prog, error) {
	data, err := os.ReadFile(progFile)
	if err != nil {
		return nil, fmt.Errorf("read program: %w", err)
	}
	p, err := target.Deserialize(data, prog.NonStrict)
	if err != nil {
		return nil, fmt.Errorf("deserialize program: %w", err)
	}
	return p, nil
}

// reductionKind names the two reduction stages. It is stored in the checkpoint
// (ddState.Kind) so -emit-culprit can rebuild the matching reduction.
const (
	kindConnection = "connection"
	kindCall       = "call"
)

// connReduction builds the connection-level reduction for p: units are
// connections (an open plus every call using its handle).
func connReduction(p *prog.Prog) (reduction, error) {
	conns, orphans := identifyConnections(p)
	if len(conns) == 0 {
		return reduction{}, fmt.Errorf("no connections found")
	}
	if len(orphans) > 0 {
		log.Logf(0, "Note: %s belong to no connection and are dropped.", plural(len(orphans), "call"))
	}
	return reduction{
		label:    kindConnection,
		n:        len(conns),
		extract:  func(mask uint64) *prog.Prog { return extractConnections(p, conns, mask) },
		describe: func(i int) string { return describeConnection(p, conns[i]) },
	}, nil
}

// runConnMinimize reduces the program to its minimal crashing set of
// connections. This runs first, to fix which connections matter before
// -minimize-calls pares down their calls.
func runConnMinimize(target *prog.Target, progFile string) error {
	p, err := readProg(target, progFile)
	if err != nil {
		return err
	}
	red, err := connReduction(p)
	if err != nil {
		return fmt.Errorf("%w in %s", err, progFile)
	}
	culpritPath := resolveCulpritPath(progFile)
	if err := minimize(target, p, resolveStatePath(progFile, "conn_state.json"),
		culpritPath, red); err != nil {
		return err
	}
	// minimize returns only when the culprit is written (a crashing probe reboots
	// the box and kills the process mid-search), so it is safe to translate now.
	return maybeEmitJSON(target, culpritPath)
}

// minimize searches the reduction on device for the smallest subset of units
// that still crashes, checkpointing to statePath (crash-safe across reboots) and
// writing the resulting reproducer to culpritPath. It is the shared engine for
// -minimize-conn and -minimize-calls.
func minimize(target *prog.Target, p *prog.Prog, statePath, culpritPath string, red reduction) error {
	log.Logf(0, "Minimizing %s in this program:", plural(red.n, red.label))
	for i := 0; i < red.n; i++ {
		log.Logf(0, "  [%d] %s", i, red.describe(i))
	}
	log.Logf(0, "Plan: try the smallest subsets first (up to %d at a time, ~%d test runs), "+
		"then bisect if that isn't enough.", *flagMaxK, projectedProbes(red.n, *flagMaxK))
	log.Logf(0, "Checkpoint: %s", statePath)

	// When a target signature + confirm command are supplied, gate the reboot-as-
	// crash recovery on a matching panic report, so a second bug that fires during
	// a probe is not misattributed to that subset (see gate.go).
	var gate *crashGate
	if *flagTargetSig != "" && *flagConfirmCmd != "" {
		gate = &crashGate{targetSig: *flagTargetSig, confirmCmd: strings.Fields(*flagConfirmCmd)}
		log.Logf(0, "Crash gating ON: only reboots confirmed as signature %s count as a repro",
			*flagTargetSig)
	}

	state := loadDdState(statePath, red.n, progHash(p), red.label, gate)
	logDdState(state)
	// culprit.syz is only written when the search completes. Any file left from an
	// earlier run describes a different (or abandoned) reduction, and a stale one
	// is easy to mistake for this run's output — drop it now rather than let it
	// outlive a run that panics before finishing.
	if err := os.Remove(culpritPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale culprit: %w", err)
	}
	// Probes actually run on this boot, as opposed to replayed from the memo.
	// Verification is only fully meaningful when this is zero: a subset re-checked
	// after other probes have run is exposed to the very accumulated kernel state
	// the re-check exists to rule out.
	probesThisBoot := 0
	// The memoized, checkpointed, crash-safe predicate. On a cache hit it replays
	// instantly (no device run); otherwise it fsyncs the pending mask, runs the
	// subset on device, and records the result. A crashing subset reboots the box
	// and kills this process inside runProgramOnce — the campaign relaunches and
	// loadDdState recovers the pending mask as a crash.
	pred := func(mask uint64) bool {
		key := maskKey(mask)
		if r, ok := state.Memo[key]; ok {
			return r
		}
		probesThisBoot++
		probeStart := time.Now()
		// Checkpoint the pending subset before running it: a crashing subset panics
		// the box, and this fsync'd record is the only trace that survives to the
		// next boot, where it is recovered as a crash.
		state.Attempting = key
		state.AttemptingAt = gateNow()
		if err := saveDdState(statePath, state); err != nil {
			tool.Failf("checkpoint: %v", err)
		}
		sub := red.extract(mask)
		log.Logf(0, "Testing %s %v — %d calls ...", plural(popcount(mask), red.label), setBits(mask), len(sub.Calls))
		if err := runProgramOnce(target, sub); err != nil {
			log.Logf(0, "  (executor error, box still up — treating as no crash: %v)", err)
		}
		// Reaching here means no kernel panic: this subset did not reproduce.
		state.Memo[key] = false
		state.Attempting = ""
		state.AttemptingAt = 0
		state.CleanMs += time.Since(probeStart).Milliseconds()
		state.CleanProbes++
		if err := saveDdState(statePath, state); err != nil {
			tool.Failf("checkpoint: %v", err)
		}
		log.Logf(0, "  no crash (%s)", time.Since(probeStart).Round(time.Millisecond))
		return false
	}

	minimal := searchCulprit(red.n, *flagMaxK, pred)
	verified := verifyCulprit(target, state, statePath, red, minimal, probesThisBoot)
	// Persist the terminal state so the on-disk checkpoint reflects the finished
	// run. Two paths otherwise leave it stale: a verification that crashed and was
	// recovered on the next boot sets VerifiedCrash only in memory (loadDdState),
	// and the trivial n<=1 search saves nothing at all — so without this the file
	// would keep showing a pending "verifying" mask after the run has completed.
	if err := saveDdState(statePath, state); err != nil {
		tool.Failf("checkpoint: %v", err)
	}
	return finishMinimize(p, red, minimal, culpritPath, verified)
}

// verifyCulprit re-runs the culprit on its own to confirm it reproduces without
// help from earlier probes. Probes share a kernel boot — only the crashing ones
// reboot the box — so a subset can panic on zone or driver state some previous
// subset left behind, and be blamed for a crash it did not cause.
//
// The check is the same crash-as-signal trick as the search: checkpoint the mask
// under Verifying, run it, and let the panic-reboot be the positive result. A
// re-check that returns is a *negative* result, recorded in VerifyFailed so it
// is attempted once and cannot loop.
func verifyCulprit(target *prog.Target, state *ddState, statePath string, red reduction,
	minimal uint64, probesThisBoot int) bool {
	key := maskKey(minimal)
	units := setBits(minimal)
	if state.VerifiedCrash == key {
		return true
	}
	if slices.Contains(state.VerifyFailed, key) {
		log.Logf(0, "Culprit %v did NOT crash on its own — the crash during the search probably "+
			"needed leftover state from an earlier test on the same boot.", units)
		return false
	}
	if probesThisBoot > 0 {
		log.Logf(0, "Re-checking culprit %v on its own (heads up: %d test(s) already ran this "+
			"boot, so the kernel isn't pristine) ...", units, probesThisBoot)
	} else {
		log.Logf(0, "Re-checking culprit %v on its own, as the first program this boot ...", units)
	}
	state.Verifying = key
	state.VerifyingAt = gateNow()
	if err := saveDdState(statePath, state); err != nil {
		tool.Failf("checkpoint: %v", err)
	}
	if err := runProgramOnce(target, red.extract(minimal)); err != nil {
		log.Logf(0, "  (executor error during re-check: %v)", err)
	}
	// Still here, so the culprit did not reproduce in isolation.
	state.Verifying = ""
	state.VerifyingAt = 0
	state.VerifyFailed = append(state.VerifyFailed, key)
	if err := saveDdState(statePath, state); err != nil {
		tool.Failf("checkpoint: %v", err)
	}
	log.Logf(0, "Culprit %v did NOT crash on its own.", units)
	return false
}

func finishMinimize(p *prog.Prog, red reduction, minimal uint64, culpritPath string,
	verified bool) error {
	sub := red.extract(minimal)
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
	log.Logf(0, "")
	log.Logf(0, "Minimal culprit: %s, %s.", plural(popcount(minimal), red.label), status)
	for _, i := range setBits(minimal) {
		log.Logf(0, "  [%d] %s", i, red.describe(i))
	}
	log.Logf(0, "Wrote %d-call reproducer to %s", len(sub.Calls), culpritPath)
	return nil
}

// runProgramOnce runs a single program once via RunLocal and returns when the box
// is still up (nil on clean completion). A kernel panic reboots the machine and
// kills this process, so a crash never returns here — it is observed out-of-band
// via the checkpoint on the next boot.
func runProgramOnce(target *prog.Target, p *prog.Prog) error {
	sandbox, err := flatrpc.SandboxToFlags(*flagSandbox)
	if err != nil {
		return err
	}
	env := sandbox
	if *flagDebug {
		env |= flatrpc.ExecEnvDebug
	}
	rpcCtx, done := context.WithCancel(context.Background())
	src := &singleProg{
		prog: p,
		done: done,
		opts: flatrpc.ExecOpts{
			EnvFlags:   env,
			ExecFlags:  flatrpc.ExecFlagThreaded | flatrpc.ExecFlagDedupCover,
			SandboxArg: int64(*flagSandboxArg),
		},
	}
	cfg := &rpcserver.LocalConfig{
		Config: rpcserver.Config{
			Config: vminfo.Config{
				Target:     target,
				VMType:     "none",
				Features:   flatrpc.AllFeatures,
				Debug:      *flagDebug,
				Sandbox:    sandbox,
				SandboxArg: int64(*flagSandboxArg),
				KcovDevice: *flagKcovDevice,
			},
			Procs:      1,
			Slowdown:   *flagSlowdown,
			KcovDevice: *flagKcovDevice,
			KextID:     *flagKextID,
		},
		Executor:         *flagExecutor,
		HandleInterrupts: true,
		MachineChecked:   src.machineChecked,
		OutputWriter:     os.Stderr,
	}
	return rpcserver.RunLocal(rpcCtx, cfg)
}

// singleProg is a queue.Source that yields exactly one program and then signals
// RunLocal to stop by cancelling its context in the request's done callback.
type singleProg struct {
	prog *prog.Prog
	opts flatrpc.ExecOpts
	done func()
	mu   sync.Mutex
	sent bool
}

func (s *singleProg) machineChecked(features flatrpc.Feature, _ map[*prog.Syscall]bool) queue.Source {
	s.opts.EnvFlags |= csource.FeaturesToFlags(features, nil)
	return queue.DefaultOpts(s, s.opts)
}

func (s *singleProg) Next() *queue.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sent {
		return nil
	}
	s.sent = true
	req := &queue.Request{Prog: s.prog}
	req.OnDone(func(_ *queue.Request, _ *queue.Result) bool {
		s.done()
		return true
	})
	return req
}
