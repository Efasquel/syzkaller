// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"strings"
	"testing"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

// IOConnectTrap reaches the kernel through iokit_user_client_trap rather than
// externalMethod, but from this tool's point of view it is the same shape as an
// external method: it consumes an io_connect_t and produces nothing. Every stage
// must treat it as a connect call, or a crashing trap is orphaned from its open
// during minimization and the culprit reduces to "nothing reproduces".
func TestTrapIsAConnectCall(t *testing.T) {
	for _, name := range []string{
		"syz_IOConnectTrap0",
		"syz_IOConnectTrap4",
		"syz_IOConnectTrap2$IOSurfaceRootUserClient_7",
	} {
		if !isConnectCall(name) {
			t.Errorf("isConnectCall(%q) = false, want true", name)
		}
		if !isTrapCall(name) {
			t.Errorf("isTrapCall(%q) = false, want true", name)
		}
		if got := callKind(name); got != "Trap" {
			t.Errorf("callKind(%q) = %q, want Trap", name, got)
		}
	}
	// A method is a connect call but not a trap, and keeps its own label.
	for _, name := range []string{
		"syz_IOConnectCallMethod",
		"syz_IOConnectCallAsyncMethod$Foo_3",
	} {
		if !isConnectCall(name) {
			t.Errorf("isConnectCall(%q) = false, want true", name)
		}
		if isTrapCall(name) {
			t.Errorf("isTrapCall(%q) = true, want false", name)
		}
		if got := callKind(name); got != "Method" {
			t.Errorf("callKind(%q) = %q, want Method", name, got)
		}
	}
	// Opens and closes must not be swept up by the trap prefix.
	if isTrapCall("syz_IOServiceOpen") || isTrapCall("syz_IOServiceClose") {
		t.Error("open/close misclassified as a trap")
	}
}

// A trap on an unproduced handle, and one issued after the connection is closed,
// are inert for the same reasons a method is -- so static reduction removes them.
func TestStaticReduceTraps(t *testing.T) {
	tgt, err := prog.GetTarget("darwin", "amd64")
	if err != nil {
		t.Skipf("darwin target unavailable: %v", err)
	}
	// open r0; trap r0; close r0; trap r0 (after close); trap 0x0 (unproduced).
	// Expected kept: open, trap, close (3). Removed: after-close, null (2).
	src := `syz_IOServiceOpen(&AUTO='IOSurfaceRoot\x00', 0x0, &AUTO=<r0=>0x0)
syz_IOConnectTrap2(r0, 0x0, 0x0, 0x1)
syz_IOServiceClose(r0)
syz_IOConnectTrap2(r0, 0x0, 0x0, 0x1)
syz_IOConnectTrap1(0x0, 0x4, 0x0)
`
	p, err := tgt.Deserialize([]byte(src), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if len(p.Calls) != 5 {
		t.Fatalf("setup: expected 5 calls, got %d", len(p.Calls))
	}
	reduced, removals := staticReduce(p)
	if len(removals) != 2 {
		t.Fatalf("expected 2 removals, got %d: %+v", len(removals), removals)
	}
	if len(reduced.Calls) != 3 {
		t.Fatalf("expected 3 calls kept, got %d", len(reduced.Calls))
	}
}

// The call-minimization stage must offer traps as removable units; if it does
// not, a program whose only connect calls are traps has nothing to pare down.
func TestIdentifyTrapCalls(t *testing.T) {
	tgt, err := prog.GetTarget("darwin", "amd64")
	if err != nil {
		t.Skipf("darwin target unavailable: %v", err)
	}
	src := `syz_IOServiceOpen(&AUTO='IOSurfaceRoot\x00', 0x0, &AUTO=<r0=>0x0)
syz_IOConnectTrap1(r0, 0x4, 0x0)
syz_IOConnectCallMethod(r0, ` + cmArgs + `)
syz_IOConnectTrap4(r0, 0xa, 0x0, 0x0, 0x0, 0x0)
syz_IOServiceClose(r0)
`
	p, err := tgt.Deserialize([]byte(src), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	// Calls 1, 2 and 3 -- the two traps and the method; not the open or close.
	got := identifyMethodCalls(p)
	want := []int{1, 2, 3}
	if len(got) != len(want) {
		t.Fatalf("identifyMethodCalls = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("identifyMethodCalls = %v, want %v", got, want)
		}
	}
	if _, err := callReduction(p); err != nil {
		t.Errorf("callReduction: %v", err)
	}
}

// Traps must reach the disable list, otherwise quarantine can never suppress a
// crashing trap and the campaign re-hits it on every reboot.
func TestEmitSyscallsTraps(t *testing.T) {
	tgt, err := prog.GetTarget("darwin", "amd64")
	if err != nil {
		t.Skipf("darwin target unavailable: %v", err)
	}
	src := `syz_IOServiceOpen(&AUTO='IOSurfaceRoot\x00', 0x0, &AUTO=<r0=>0x0)
syz_IOConnectTrap1(r0, 0x4, 0x0)
syz_IOConnectTrap1(r0, 0x5, 0x0)
syz_IOConnectTrap4(r0, 0xa, 0x0, 0x0, 0x0, 0x0)
syz_IOServiceClose(r0)
`
	p, err := tgt.Deserialize([]byte(src), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	names, warnings := emitSyscalls(p)
	// Two distinct trap syscalls; the repeated Trap1 collapses to one entry.
	if len(names) != 2 {
		t.Fatalf("names = %v, want 2 distinct trap names", names)
	}
	for _, n := range names {
		if !strings.HasPrefix(n, "syz_IOConnectTrap") {
			t.Errorf("names = %v, contains a non-trap entry", names)
		}
	}
	// The bare generic traps have a fuzzable index, so each is flagged wholesale
	// and the warning says "trap index", not "selector".
	if len(warnings) != 2 {
		t.Fatalf("warnings = %v, want one per generic trap", warnings)
	}
	for _, w := range warnings {
		if !strings.Contains(w, "trap index") {
			t.Errorf("warning %q should name the trap index, not a selector", w)
		}
	}
}

// A trap's arg 1 is a trap index, a method's is a selector. They are different
// namespaces -- trap 3 and selector 3 are unrelated code -- so the minimization
// log must not call both "sel".
func TestDescribeCallLabelsTrapIndex(t *testing.T) {
	tgt, err := prog.GetTarget("darwin", "amd64")
	if err != nil {
		t.Skipf("darwin target unavailable: %v", err)
	}
	src := `syz_IOServiceOpen(&AUTO='IOSurfaceRoot\x00', 0x0, &AUTO=<r0=>0x0)
syz_IOConnectTrap1(r0, 0x4, 0x0)
syz_IOConnectCallMethod(r0, 0x5, &AUTO, 0x0, &AUTO, 0x0, &AUTO, &AUTO, &AUTO, &AUTO)
`
	p, err := tgt.Deserialize([]byte(src), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if got := describeCall(p.Calls[1], 1); got != "Trap(idx=0x4) #1" {
		t.Errorf("describeCall(trap) = %q, want %q", got, "Trap(idx=0x4) #1")
	}
	if got := describeCall(p.Calls[2], 2); got != "Method(sel=0x5) #2" {
		t.Errorf("describeCall(method) = %q, want %q", got, "Method(sel=0x5) #2")
	}
}
