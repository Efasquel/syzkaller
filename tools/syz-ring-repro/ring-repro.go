// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-ring-repro replays programs saved in a ring buffer directory to reproduce
// a crash that occurred in VM-less (type: "none") mode.
//
// After a kernel panic the ring buffer directory (<workdir>/ring_buffer/) contains
// slot_NNNN.syz files.  Each file starts with an "id=N" header line followed by the
// serialized program.  The slot with the highest id is the program that was about to
// execute when the crash occurred.
//
// Usage: syz-ring-repro [flags] <ring-buffer-dir>
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	stdlog "log"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpcserver"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var (
	flagOS         = flag.String("os", runtime.GOOS, "target os")
	flagArch       = flag.String("arch", runtime.GOARCH, "target arch")
	flagExecutor   = flag.String("executor", "./syz-executor", "path to executor binary")
	flagSandbox    = flag.String("sandbox", "none", "sandbox for execution (none/setuid/namespace/android)")
	flagSandboxArg = flag.Int("sandbox_arg", 0, "argument for sandbox runner")
	flagRepeat     = flag.Int("repeat", 1, "number of times to replay the full sequence (0 = infinite)")
	flagProcs      = flag.Int("procs", 1, "number of parallel executor processes")
	flagDebug      = flag.Bool("debug", false, "debug output from executor")
	flagOutput     = flag.Bool("output", false, "print each program before execution")
	flagUnsafe     = flag.Bool("unsafe", false, "use unsafe program deserialization mode")
	flagSlowdown   = flag.Int("slowdown", 1, "execution slowdown caused by emulation/instrumentation")
	flagFrom       = flag.Int("from", -1, "start of range, as an offset back from the most recent program n "+
		"(e.g. 5 selects from n-5); -1 = oldest available")
	flagTo = flag.Int("to", 0, "end of range, as an offset back from the most recent program n "+
		"(e.g. 1 selects up to n-1); 0 = most recent")
	flagMerge = flag.String("merge", "", "concatenate the selected programs into a single program, write it "+
		"to this file, and exit without executing")
	flagStatic = flag.Bool("static", false, "when merging, statically drop calls that are inert by the "+
		"IOKit/MIG contract (calls on unproduced/closed connections, double closes) before writing; "+
		"this shrinks the trace so the on-device bisection triggers fewer reboots")
	flagMinimizeConn = flag.Bool("minimize-conn", false, "reduce a program to its minimal crashing set of "+
		"connections, on device: the positional arg is a merged/reduced program file (not a ring dir). Test "+
		"subsets of the connections (each an open + its methods + close) to find the smallest that still "+
		"crashes, checkpointing to <dir>/conn_state.json (crash-safe across reboots) and writing the culprit "+
		"reproducer to <dir>/culprit.syz")
	flagMinimizeCalls = flag.Bool("minimize-calls", false, "reduce a program to its minimal crashing set of "+
		"IOConnectCallMethod calls, on device, keeping every open and close (an open produces the handle later "+
		"calls need; a close can be the bug). Meant to run after -minimize-conn on the resulting culprit. "+
		"Checkpoints to <dir>/call_state.json and writes the reduced reproducer to <dir>/culprit.syz")
	flagEmitCulprit = flag.Bool("emit-culprit", false, "offline: read the checkpoint written by a prior "+
		"-minimize-conn run (the positional arg is the same program file) and write the smallest known crashing "+
		"subset to <dir>/culprit.syz, then exit. Runs nothing on device and never modifies conn_state.json. "+
		"Exits non-zero if no crashing subset has been recorded yet, so a campaign can branch on it")
	flagState = flag.String("state", "", "path to the connection-minimization checkpoint used by -minimize-conn "+
		"and -emit-culprit; defaults to conn_state.json alongside the program file. The program file is still "+
		"required (the checkpoint stores only masks; building the culprit needs the program to resolve them)")
	flagCulprit = flag.String("culprit", "", "path to write the minimal reproducer produced by -minimize-conn "+
		"and -emit-culprit; defaults to culprit.syz alongside the program file")
	flagEmitJSON = flag.Bool("emit-json", false, "read a minimized culprit and write the list of "+
		"IOConnectCallMethod syscall names to disable (JSON) to <dir>/syscalls.json. Alone it is an offline mode "+
		"reading the positional culprit; combined with -minimize-conn/-minimize-calls/-emit-culprit it emits the "+
		"list right after that mode writes the culprit, so one command minimizes and translates. Feeds "+
		"syz-manager's disable_syscalls — a name-level list, so it disables a generic call's every selector at "+
		"once (single-selector suppression would need an executor guard, out of scope)")
	flagJSONOut = flag.String("json-out", "", "path to write the -emit-json list; defaults to "+
		"syscalls.json alongside the program file")
	flagTargetSig = flag.String("target_sig", "", "with -minimize-*, the crash signature the predicate must "+
		"confirm before counting a reboot as a repro. Requires -confirm_cmd. When unset, any reboot counts "+
		"(original behavior); when set, a reboot whose panic report fingerprints to a DIFFERENT bug is not "+
		"attributed to the subset — so a second bug firing during a probe cannot misdirect the search")
	flagConfirmCmd = flag.String("confirm_cmd", "", "command that classifies a reboot for -target_sig. Invoked "+
		"as <confirm_cmd> <target_sig> <since_epoch>; it should print 'match' / 'none' (both counted as the "+
		"target crash) or 'other <sig>' (a different bug — not counted). Typically "+
		"'python3 scripts/crash_fingerprint.py match-since --dir <panic-dir>'")
	flagMaxK = flag.Int("max_k", 3, "with -minimize-conn, the largest culprit size searched by enumeration "+
		"before falling back to ddmin halving. Enumeration costs sum(C(n,k)) cheap probes but crashes "+
		"(and so reboots) only once, on the answer; halving crashes on nearly every reduction step. "+
		"Raise it when reboots are slow relative to a probe, lower it when there are many connections")
	flagCoverFile = flag.String("coverfile", "", "append newly seen coverage PCs to this file, fsync'd after "+
		"every program so they survive a kernel panic; PCs are written raw (0x%x), matching syz-manager's cover_log")
	flagKcovDevice = flag.String("kcov_device", "", "Darwin KEXT coverage device for Pishi/KextFuzz (e.g. "+
		"/dev/pishi); required for -coverfile, the executor opens it via ioctl to collect coverage")
	flagKextID = flag.Int("kext_id", 1, "KEXT bundle id passed to Pishi via FUZZER_IOCTL_START (ignored by KextFuzz)")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: syz-ring-repro [flags] <ring-buffer-dir>\n")
		flag.PrintDefaults()
	}
	defer tool.Init()()

	// Drop the "YYYY/MM/DD HH:MM:SS" prefix from log lines: this tool's output is
	// a one-shot triage report (merge / static-reduce / minimize), not a
	// time-series, so the timestamps are noise. pkg/log prints via the stdlib
	// logger, so clearing its flags here suffices without touching pkg/log.
	stdlog.SetFlags(0)

	if len(flag.Args()) != 1 {
		flag.Usage()
		os.Exit(1)
	}
	dir := flag.Args()[0]

	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		tool.Fail(err)
	}

	// Connection-minimization and offline culprit emission both take a single
	// program file, not a ring buffer dir.
	if *flagEmitCulprit {
		if err := runEmitCulprit(target, dir); err != nil {
			tool.Failf("emit-culprit failed: %v", err)
		}
		// -emit-json may ride along: translate the culprit just written.
		if err := maybeEmitJSON(target, resolveCulpritPath(dir)); err != nil {
			tool.Failf("emit-json failed: %v", err)
		}
		return
	}
	// -minimize-* honor -emit-json internally (they emit once the culprit is
	// written), so a single command can minimize and translate.
	if *flagMinimizeConn {
		if err := runConnMinimize(target, dir); err != nil {
			tool.Failf("minimize-conn failed: %v", err)
		}
		return
	}
	if *flagMinimizeCalls {
		if err := runMinimizeCalls(target, dir); err != nil {
			tool.Failf("minimize-calls failed: %v", err)
		}
		return
	}
	// Standalone: -emit-json with no minimize/emit-culprit mode reads the
	// positional culprit directly.
	if *flagEmitJSON {
		if err := runEmitSyscalls(target, dir); err != nil {
			tool.Failf("emit-json failed: %v", err)
		}
		return
	}

	entries, err := loadRingBuffer(target, dir)
	if err != nil {
		tool.Failf("failed to load ring buffer from %s: %v", dir, err)
	}
	if len(entries) == 0 {
		tool.Failf("no valid programs found in %s", dir)
	}

	entries, err = selectRange(entries)
	if err != nil {
		tool.Failf("%v", err)
	}

	log.Logf(0, "loaded %d programs from ring buffer", len(entries))
	for i, e := range entries {
		marker := ""
		if i == len(entries)-1 {
			marker = " <-- most recent (likely culprit)"
		}
		log.Logf(0, "  [order %d] %s id=%d%s", i+1, e.slot, e.id, marker)
	}

	if *flagMerge != "" {
		if err := mergeEntries(target, entries, *flagMerge, *flagStatic); err != nil {
			tool.Failf("merge failed: %v", err)
		}
		return
	}

	sandbox, err := flatrpc.SandboxToFlags(*flagSandbox)
	if err != nil {
		tool.Failf("failed to parse sandbox: %v", err)
	}
	env := sandbox
	if *flagDebug {
		env |= flatrpc.ExecEnvDebug
	}

	rpcCtx, done := context.WithCancel(context.Background())
	ctx := &Context{
		target:  target,
		done:    done,
		entries: entries,
		repeat:  *flagRepeat,
		defaultOpts: flatrpc.ExecOpts{
			EnvFlags:   env,
			ExecFlags:  flatrpc.ExecFlagThreaded | flatrpc.ExecFlagDedupCover,
			SandboxArg: int64(*flagSandboxArg),
		},
	}
	collectCover := *flagCoverFile != ""
	if collectCover {
		if *flagKcovDevice == "" {
			tool.Failf("-coverfile requires -kcov_device (e.g. /dev/pishi) so the executor can collect coverage")
		}
		ctx.defaultOpts.ExecFlags |= flatrpc.ExecFlagCollectCover
		f, err := os.Create(*flagCoverFile)
		if err != nil {
			tool.Failf("failed to create cover file %s: %v", *flagCoverFile, err)
		}
		defer f.Close()
		ctx.coverFile = f
		ctx.coverSeen = make(map[uint64]bool)
		log.Logf(0, "logging coverage PCs from %s (kext id %d) to %s",
			*flagKcovDevice, *flagKextID, *flagCoverFile)
	}

	cfg := &rpcserver.LocalConfig{
		Config: rpcserver.Config{
			Config: vminfo.Config{
				Target:     target,
				VMType:     "none",
				Features:   flatrpc.AllFeatures,
				Debug:      *flagDebug,
				Cover:      collectCover,
				Sandbox:    sandbox,
				SandboxArg: int64(*flagSandboxArg),
				KcovDevice: *flagKcovDevice,
			},
			Procs:      *flagProcs,
			Slowdown:   *flagSlowdown,
			KcovDevice: *flagKcovDevice,
			KextID:     *flagKextID,
		},
		Executor:         *flagExecutor,
		HandleInterrupts: true,
		MachineChecked:   ctx.machineChecked,
		OutputWriter:     os.Stderr,
	}
	if err := rpcserver.RunLocal(rpcCtx, cfg); err != nil {
		tool.Fail(err)
	}
}

type slotEntry struct {
	id   int
	slot string
	prog *prog.Prog
}

type Context struct {
	target      *prog.Target
	done        func()
	entries     []slotEntry
	defaultOpts flatrpc.ExecOpts
	repeat      int
	mu          sync.Mutex
	pos         int
	completed   atomic.Uint64

	// Coverage logging. coverFile is fsync'd after every program so the
	// coverage of the programs that ran just before a kernel panic is not lost
	// (this tool runs VM-less, so a panic takes the whole machine down).
	coverMu   sync.Mutex
	coverFile *os.File
	coverSeen map[uint64]bool
}

func (ctx *Context) machineChecked(features flatrpc.Feature, _ map[*prog.Syscall]bool) queue.Source {
	ctx.defaultOpts.EnvFlags |= csource.FeaturesToFlags(features, nil)
	return queue.DefaultOpts(ctx, ctx.defaultOpts)
}

func (ctx *Context) Next() *queue.Request {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	if ctx.repeat > 0 && ctx.pos >= len(ctx.entries)*ctx.repeat {
		return nil
	}
	idx := ctx.pos % len(ctx.entries)
	ctx.pos++
	e := ctx.entries[idx]
	if *flagOutput {
		log.Logf(0, "executing %s id=%d:\n%s", e.slot, e.id, e.prog.Serialize())
	}
	req := &queue.Request{Prog: e.prog}
	req.OnDone(ctx.onDone)
	return req
}

func (ctx *Context) onDone(_ *queue.Request, res *queue.Result) bool {
	if ctx.coverFile != nil && res != nil && res.Info != nil {
		ctx.writeCover(res.Info)
	}
	completed := int(ctx.completed.Add(1))
	if ctx.repeat > 0 && completed >= len(ctx.entries)*ctx.repeat {
		ctx.done()
	}
	return true
}

// writeCover appends the newly seen coverage PCs from one program to coverFile
// and fsyncs them to stable storage before the next (possibly crashing) program
// runs. PCs are emitted raw (no PreviousInstructionPC adjustment): on Darwin the
// executor already returns full kernel/KEXT PCs from Pishi/KextFuzz, and they are
// canonicalized host-side, so this matches syz-manager's cover_log format.
func (ctx *Context) writeCover(info *flatrpc.ProgInfo) {
	collect := func(call *flatrpc.CallInfo) {
		if call == nil {
			return
		}
		for _, pc := range call.Cover {
			if ctx.coverSeen[pc] {
				continue
			}
			ctx.coverSeen[pc] = true
			fmt.Fprintf(ctx.coverFile, "0x%x\n", pc)
		}
	}
	ctx.coverMu.Lock()
	defer ctx.coverMu.Unlock()
	for _, call := range info.Calls {
		collect(call)
	}
	collect(info.Extra)
	if err := ctx.coverFile.Sync(); err != nil {
		log.Logf(0, "failed to fsync cover file: %v", err)
	}
}

// selectRange narrows entries (sorted oldest -> newest, so the last element is
// the most recent program "n") to the window selected by -from and -to.
// Both flags are offsets counted back from n: 0 == n, k == n-k. -from defaults
// to the oldest available program and -to defaults to n, so an unset range
// selects everything.
func selectRange(entries []slotEntry) ([]slotEntry, error) {
	n := len(entries)
	fromOff, toOff := *flagFrom, *flagTo
	if fromOff < 0 {
		fromOff = n - 1 // oldest available
	}
	if toOff < 0 {
		toOff = 0 // most recent
	}
	if fromOff < toOff {
		return nil, fmt.Errorf("-from (n-%d) is more recent than -to (n-%d); -from must be >= -to",
			*flagFrom, *flagTo)
	}
	if toOff > n-1 {
		return nil, fmt.Errorf("-to selects n-%d but only %d programs are available", toOff, n)
	}
	if fromOff > n-1 {
		fromOff = n - 1 // clamp to oldest available
	}
	lo := n - 1 - fromOff
	hi := n - 1 - toOff
	return entries[lo : hi+1], nil
}

// mergeEntries concatenates the calls of all selected programs (in oldest ->
// newest order) into a single program and writes it to outFile. Resource
// variables are renumbered across the whole sequence by Serialize, so a plain
// append of the calls is sufficient. The result is a self-contained reproducer
// candidate that can be replayed, minimized, or fed to syz-prog2c/syz-repro.
func mergeEntries(target *prog.Target, entries []slotEntry, outFile string, static bool) error {
	merged := &prog.Prog{Target: target}
	start := 0
	for _, e := range entries {
		n := len(e.prog.Calls)
		merged.Calls = append(merged.Calls, e.prog.Calls...)
		// Show where each slot lands in the merged, 0-based call numbering so a
		// dropped "call #N" below can be traced back to its source slot.
		log.Logf(0, "  %s (id=%d): merged calls #%d..#%d", e.slot, e.id, start, start+n-1)
		start += n
	}
	log.Logf(0, "\n")
	// Round-trip to make sure the concatenation produced a valid program.
	if _, err := target.Deserialize(merged.Serialize(), prog.NonStrict); err != nil {
		return fmt.Errorf("merged program is invalid: %v", err)
	}
	total := len(merged.Calls)
	if static {
		// Serialize once (one line per call) so each drop can show the exact
		// call text. Indices are 0-based into this merged (pre-reduction) program.
		lines := strings.Split(string(merged.Serialize()), "\n")
		reduced, removals := staticReduce(merged)
		for _, r := range removals {
			text := ""
			if r.index < len(lines) {
				text = strings.TrimSpace(lines[r.index])
			}
			log.Logf(0, "  static-reduce: DROP call #%d — %s", r.index, r.reason)
			parts := strings.SplitN(text, ",", 3)

			switch len(parts) {
			case 1:
				text = parts[0]
			case 2:
				text = parts[0] + "," + parts[1]
			default:
				text = parts[0] + "," + parts[1] + ", ...)"
			}
			log.Logf(0, "      └─ %s", text)
		}
		log.Logf(0, "\nstatic-reduce: removed %d/%d calls", len(removals), total)
		merged = reduced
	}
	data := merged.Serialize()
	// Validate the final program that is actually written.
	if _, err := target.Deserialize(data, prog.NonStrict); err != nil {
		return fmt.Errorf("reduced program is invalid: %v", err)
	}
	if len(merged.Calls) > prog.MaxCalls {
		log.Logf(0, "warning: merged program has %d calls, exceeding prog.MaxCalls=%d; "+
			"the executor may refuse it until it is minimized", len(merged.Calls), prog.MaxCalls)
	}
	if err := os.WriteFile(outFile, data, 0644); err != nil {
		return err
	}
	log.Logf(0, "merged %d programs (%d calls total) into %s", len(entries), len(merged.Calls), outFile)
	return nil
}

func loadRingBuffer(target *prog.Target, dir string) ([]slotEntry, error) {
	files, err := filepath.Glob(filepath.Join(dir, "slot_*.syz"))
	if err != nil {
		return nil, err
	}
	mode := prog.NonStrict
	if *flagUnsafe {
		mode = prog.NonStrictUnsafe
	}
	var entries []slotEntry
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			log.Logf(0, "skipping %s: %v", f, err)
			continue
		}
		id, progData, ok := parseSlotHeader(data)
		if !ok {
			log.Logf(0, "skipping %s: missing or malformed id header", f)
			continue
		}
		p, err := target.Deserialize(progData, mode)
		if err != nil {
			log.Logf(0, "skipping %s: %v", f, err)
			continue
		}
		entries = append(entries, slotEntry{
			id:   id,
			slot: filepath.Base(f),
			prog: p,
		})
	}
	slices.SortFunc(entries, func(a, b slotEntry) int {
		return a.id - b.id
	})
	return entries, nil
}

// parseSlotHeader extracts the id from the "id=N" first line and returns the
// program bytes that follow.
func parseSlotHeader(data []byte) (id int, progData []byte, ok bool) {
	nl := bytes.IndexByte(data, '\n')
	if nl < 0 {
		return 0, nil, false
	}
	line := data[:nl]
	if !bytes.HasPrefix(line, []byte("id=")) {
		return 0, nil, false
	}
	n, err := strconv.Atoi(string(line[3:]))
	if err != nil {
		return 0, nil, false
	}
	return n, data[nl+1:], true
}
