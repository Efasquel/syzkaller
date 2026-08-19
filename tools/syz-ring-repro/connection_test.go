// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

// Two independent connections plus a null-handle call (an orphan the static pass
// would normally have removed). Calls, by index:
//
//	0 open r0 | 1 call r0 | 2 call r0 | 3 close r0     -> connection 0
//	4 open r1 | 5 call r1 | 6 close r1                 -> connection 1
//	7 call 0x0                                          -> orphan
func TestIdentifyConnections(t *testing.T) {
	tgt, err := prog.GetTarget("darwin", "amd64")
	if err != nil {
		t.Skipf("darwin target unavailable: %v", err)
	}
	src := `syz_IOServiceOpen(&AUTO='AppleSSE\x00', 0x0, &AUTO=<r0=>0x0)
syz_IOConnectCallMethod(r0, ` + cmArgs + `)
syz_IOConnectCallMethod(r0, ` + cmArgs + `)
syz_IOServiceClose(r0)
syz_IOServiceOpen(&AUTO='AppleSSE\x00', 0x0, &AUTO=<r1=>0x0)
syz_IOConnectCallMethod(r1, ` + cmArgs + `)
syz_IOServiceClose(r1)
syz_IOConnectCallMethod(0x0, ` + cmArgs + `)
`
	p, err := tgt.Deserialize([]byte(src), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	conns, orphans := identifyConnections(p)

	if len(conns) != 2 {
		t.Fatalf("expected 2 connections, got %d: %+v", len(conns), conns)
	}
	if got := conns[0].callIdxs; !equalInts(got, []int{0, 1, 2, 3}) || conns[0].openIdx != 0 {
		t.Errorf("connection 0 = open %d calls %v, want open 0 calls [0 1 2 3]", conns[0].openIdx, got)
	}
	if got := conns[1].callIdxs; !equalInts(got, []int{4, 5, 6}) || conns[1].openIdx != 4 {
		t.Errorf("connection 1 = open %d calls %v, want open 4 calls [4 5 6]", conns[1].openIdx, got)
	}
	if !equalInts(orphans, []int{7}) {
		t.Errorf("orphans = %v, want [7]", orphans)
	}

	// Extract connection 1 (mask bit 1): a valid, self-contained 3-call program.
	sub := extractConnections(p, conns, 1<<1)
	if len(sub.Calls) != 3 {
		t.Fatalf("extracted connection 1 has %d calls, want 3", len(sub.Calls))
	}
	wantNames := []string{"syz_IOServiceOpen", "syz_IOConnectCallMethod", "syz_IOServiceClose"}
	for i, want := range wantNames {
		if sub.Calls[i].Meta.Name != want {
			t.Errorf("extracted call %d = %s, want %s", i, sub.Calls[i].Meta.Name, want)
		}
	}
	if _, err := tgt.Deserialize(sub.Serialize(), prog.NonStrict); err != nil {
		t.Fatalf("extracted connection is invalid: %v", err)
	}

	// Extract both connections (mask 0b11): all 7 non-orphan calls, in order.
	both := extractConnections(p, conns, 0b11)
	if len(both.Calls) != 7 {
		t.Fatalf("extracted both connections has %d calls, want 7", len(both.Calls))
	}
	if len(p.Calls) != 8 {
		t.Errorf("original mutated: now %d calls", len(p.Calls))
	}
}

// TestDdminConns checks that delta debugging converges to the minimal crashing
// subset, for single- and (crucially) multi-connection culprits.
func TestDdminConns(t *testing.T) {
	cases := []struct {
		n       int
		culprit uint64
	}{
		{6, 0b000100},   // single connection (#2)
		{6, 0b100001},   // two connections, far apart (#0 and #5)
		{8, 0b00011000}, // two adjacent connections (#3 and #4)
		{7, 0b0100010},  // two connections (#1 and #5)
		{4, 0b1111},     // all needed -> minimal is the full set
		{1, 0b1},        // trivial
	}
	for _, tc := range cases {
		culprit := tc.culprit
		// Oracle: the subset reproduces iff it contains every culprit connection.
		pred := func(mask uint64) bool { return mask&culprit == culprit }
		got := ddminConns(tc.n, pred)
		if got != culprit {
			t.Errorf("ddminConns(n=%d, culprit=0x%x) = 0x%x, want 0x%x", tc.n, culprit, got, culprit)
		}
	}
}

// TestDdminCheckpointReplay drives ddmin the way the on-device loop does: each
// crashing subset test is modeled as a VM-less panic — the pending mask is
// checkpointed and the process "reboots" (panics). The state is reloaded (which
// must recover the pending mask as a crash) and ddmin re-runs, replaying the memo,
// until a boot completes without a crash. It must converge to the same minimal
// culprit as the crash-free run. This exercises the checkpoint round-trip,
// dangling-attempt recovery, and deterministic replay together.
func TestDdminCheckpointReplay(t *testing.T) {
	const n = 7
	const culprit = uint64(0b0100010) // connections #1 and #5
	const hash = "testprog"
	oracle := func(mask uint64) bool { return mask&culprit == culprit }
	path := filepath.Join(t.TempDir(), "conn_state.json")

	type reboot struct{ mask uint64 }
	var result uint64
	for boots := 1; ; boots++ {
		if boots > n*n+20 {
			t.Fatalf("did not converge after %d boots", boots)
		}
		d := loadDdState(path, n, hash, "")
		rebooted := false
		func() {
			defer func() {
				r := recover()
				if r == nil {
					return
				}
				if _, ok := r.(reboot); ok {
					rebooted = true
					return
				}
				panic(r)
			}()
			result = ddminConns(n, func(mask uint64) bool {
				key := maskKey(mask)
				if v, ok := d.Memo[key]; ok {
					return v
				}
				if oracle(mask) {
					// Simulate the box rebooting mid-test: checkpoint the pending
					// mask, then die. On reload it must come back as a crash.
					d.Attempting = key
					if err := saveDdState(path, d); err != nil {
						panic(err)
					}
					panic(reboot{mask})
				}
				d.Memo[key] = false
				d.Attempting = ""
				if err := saveDdState(path, d); err != nil {
					panic(err)
				}
				return false
			})
		}()
		if !rebooted {
			break
		}
	}
	if result != culprit {
		t.Fatalf("replay converged to 0x%x, want 0x%x", result, culprit)
	}
}

// TestCallClassifiers guards the bug where a $variant open (e.g.
// syz_IOServiceOpen$AppleJPEGDriver) was not recognized as an open, orphaning it
// so extractConnections dropped it and every connector serialized as 0x0.
func TestCallClassifiers(t *testing.T) {
	if !isOpenCall("syz_IOServiceOpen") || !isOpenCall("syz_IOServiceOpen$AppleJPEGDriver") {
		t.Error("isOpenCall must match plain and $variant opens")
	}
	if !isCloseCall("syz_IOServiceClose") || !isCloseCall("syz_IOServiceClose$Foo") {
		t.Error("isCloseCall must match plain and $variant closes")
	}
	if !isConnectCall("syz_IOConnectCallMethod$AppleJPEGDriver") ||
		!isConnectCall("syz_IOConnectCallAsyncMethod") {
		t.Error("isConnectCall must match method $variants")
	}
	if isOpenCall("syz_IOServiceClose") || isCloseCall("syz_IOServiceOpen") {
		t.Error("open/close classifiers must not cross-match")
	}
}

// TestDdStateRejectsForeignMemo guards the failure where a conn_state.json left
// over from a different program was replayed against the current one: every
// stale entry answers a device test that was never run for this program.
func TestDdStateRejectsForeignMemo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conn_state.json")
	if err := saveDdState(path, &ddState{
		NUnits:   7,
		ProgHash: "oldprog",
		Memo:     map[string]bool{"1": false, "7e": false, "3e0": false},
	}); err != nil {
		t.Fatal(err)
	}
	// Same connection count, different program.
	if s := loadDdState(path, 7, "newprog", ""); len(s.Memo) != 0 {
		t.Errorf("memo from a different program was kept: %v", s.Memo)
	}
	// Different connection count.
	if s := loadDdState(path, 10, "oldprog", ""); len(s.Memo) != 0 {
		t.Errorf("memo with a different conn count was kept: %v", s.Memo)
	}
	// Matching identity: kept, but a key with bits outside nConns cannot be a
	// configuration of this program and is dropped.
	s := loadDdState(path, 7, "oldprog", "")
	if len(s.Memo) != 2 || s.Memo["3e0"] {
		t.Errorf("memo = %v, want the two 7-bit entries only", s.Memo)
	}
}

// TestDdStateRecoversLostRename models the panic that motivated the parent-dir
// fsync: the checkpoint's contents were fsync'd into <path>.tmp but the rename
// never reached disk, so the crash it recorded must still be recovered.
func TestDdStateRecoversLostRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "conn_state.json")
	committed := &ddState{NUnits: 10, ProgHash: "p", Memo: map[string]bool{"1f": false, "3e0": false}}
	if err := saveDdState(path, committed); err != nil {
		t.Fatal(err)
	}
	// The write whose rename was lost: same state, mask 0x3 pending.
	pending := *committed
	pending.Attempting = "3"
	data, err := json.MarshalIndent(&pending, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".tmp", data, 0644); err != nil {
		t.Fatal(err)
	}

	s := loadDdState(path, 10, "p", "")
	if !s.Memo["3"] {
		t.Fatalf("pending mask 0x3 not recovered as a crash: %v", s.Memo)
	}
	if s.Attempting != "" {
		t.Errorf("Attempting = %q, want cleared after recovery", s.Attempting)
	}
	// A stranded temp file from a *different* program must not be recovered.
	foreign := ddState{NUnits: 10, ProgHash: "other", Memo: map[string]bool{}, Attempting: "1c"}
	data, _ = json.MarshalIndent(&foreign, "", "  ")
	if err := os.WriteFile(path+".tmp", data, 0644); err != nil {
		t.Fatal(err)
	}
	if s := loadDdState(path, 10, "p", ""); s.Memo["1c"] {
		t.Error("recovered a pending mask from another program's temp file")
	}
}

// TestAtomicWriteJSONClearsTemp checks the invariant the recovery above relies
// on: after a successful write no temp file remains, so a surviving <path>.tmp
// always means a lost write rather than normal debris.
func TestAtomicWriteJSONClearsTemp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conn_state.json")
	for i := 0; i < 3; i++ {
		if err := saveDdState(path, &ddState{NUnits: 4, ProgHash: "p", Memo: map[string]bool{}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file survived a successful write (err=%v)", err)
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestDdStateProbeCostSurvivesReboot checks that the measured clean-probe cost
// accumulates across boots. A single boot only ever sees part of the search, so
// the mean is only meaningful if it is carried in the checkpoint.
func TestDdStateProbeCostSurvivesReboot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conn_state.json")
	s := &ddState{NUnits: 5, ProgHash: "p", Memo: map[string]bool{}}
	if got := s.meanProbeMs(); got != 0 {
		t.Errorf("mean with no probes = %d, want 0", got)
	}
	s.CleanMs, s.CleanProbes = 900, 3
	if err := saveDdState(path, s); err != nil {
		t.Fatal(err)
	}
	// "Reboot": reload and add two more probes.
	s = loadDdState(path, 5, "p", "")
	if s.CleanProbes != 3 || s.meanProbeMs() != 300 {
		t.Fatalf("after reload: %d probes, mean %dms; want 3, 300", s.CleanProbes, s.meanProbeMs())
	}
	s.CleanMs += 300
	s.CleanProbes += 2
	if err := saveDdState(path, s); err != nil {
		t.Fatal(err)
	}
	if s := loadDdState(path, 5, "p", ""); s.CleanProbes != 5 || s.meanProbeMs() != 240 {
		t.Errorf("after second boot: %d probes, mean %dms; want 5, 240", s.CleanProbes, s.meanProbeMs())
	}
	// A checkpoint from a different program must not contribute its timings.
	if s := loadDdState(path, 5, "other", ""); s.CleanProbes != 0 || s.CleanMs != 0 {
		t.Errorf("foreign checkpoint leaked timings: %d probes, %dms", s.CleanProbes, s.CleanMs)
	}
}
