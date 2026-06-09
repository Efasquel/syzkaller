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
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
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
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: syz-ring-repro [flags] <ring-buffer-dir>\n")
		flag.PrintDefaults()
	}
	defer tool.Init()()

	if len(flag.Args()) != 1 {
		flag.Usage()
		os.Exit(1)
	}
	dir := flag.Args()[0]

	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		tool.Fail(err)
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
		if err := mergeEntries(target, entries, *flagMerge); err != nil {
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

	cfg := &rpcserver.LocalConfig{
		Config: rpcserver.Config{
			Config: vminfo.Config{
				Target:     target,
				VMType:     "none",
				Features:   flatrpc.AllFeatures,
				Debug:      *flagDebug,
				Sandbox:    sandbox,
				SandboxArg: int64(*flagSandboxArg),
			},
			Procs:    *flagProcs,
			Slowdown: *flagSlowdown,
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

func (ctx *Context) onDone(_ *queue.Request, _ *queue.Result) bool {
	completed := int(ctx.completed.Add(1))
	if ctx.repeat > 0 && completed >= len(ctx.entries)*ctx.repeat {
		ctx.done()
	}
	return true
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
func mergeEntries(target *prog.Target, entries []slotEntry, outFile string) error {
	merged := &prog.Prog{Target: target}
	for _, e := range entries {
		merged.Calls = append(merged.Calls, e.prog.Calls...)
	}
	data := merged.Serialize()
	// Round-trip to make sure the concatenation produced a valid program.
	if _, err := target.Deserialize(data, prog.NonStrict); err != nil {
		return fmt.Errorf("merged program is invalid: %v", err)
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
