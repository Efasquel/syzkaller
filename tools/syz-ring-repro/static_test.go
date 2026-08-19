// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

// method is one IOConnectCallMethod on the given port (r0/r1/0x0).
const cmArgs = "0x0, &AUTO, 0x0, &AUTO, 0x0, &AUTO, &AUTO, &AUTO, &AUTO"

func TestStaticReduce(t *testing.T) {
	tgt, err := prog.GetTarget("darwin", "amd64")
	if err != nil {
		t.Skipf("darwin target unavailable: %v", err)
	}
	// open r0; call r0; close r0; call r0 (after close); close r0 (double);
	// call 0x0 (null); open r1; call r1.
	// Expected kept: open r0, call r0, close r0, open r1, call r1  (5 calls).
	// Expected removed: after-close call, double close, null call    (3 calls).
	src := `syz_IOServiceOpen(&AUTO='AppleSSE\x00', 0x0, &AUTO=<r0=>0x0)
syz_IOConnectCallMethod(r0, ` + cmArgs + `)
syz_IOServiceClose(r0)
syz_IOConnectCallMethod(r0, ` + cmArgs + `)
syz_IOServiceClose(r0)
syz_IOConnectCallMethod(0x0, ` + cmArgs + `)
syz_IOServiceOpen(&AUTO='AppleSSE\x00', 0x0, &AUTO=<r1=>0x0)
syz_IOConnectCallMethod(r1, ` + cmArgs + `)
`
	p, err := tgt.Deserialize([]byte(src), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if len(p.Calls) != 8 {
		t.Fatalf("setup: expected 8 calls, got %d", len(p.Calls))
	}

	reduced, removals := staticReduce(p)

	if len(removals) != 3 {
		t.Fatalf("expected 3 removals, got %d: %+v", len(removals), removals)
	}
	// Removed indices must be exactly the after-close call (3), double close (4),
	// and null-handle call (5) from the original program.
	gotIdx := map[int]string{}
	for _, r := range removals {
		gotIdx[r.index] = r.reason
	}
	for _, i := range []int{3, 4, 5} {
		if _, ok := gotIdx[i]; !ok {
			t.Errorf("expected call %d to be removed; removals=%+v", i, removals)
		}
	}

	if len(reduced.Calls) != 5 {
		t.Fatalf("expected 5 calls after reduction, got %d", len(reduced.Calls))
	}
	wantKept := []string{
		"syz_IOServiceOpen",
		"syz_IOConnectCallMethod",
		"syz_IOServiceClose",
		"syz_IOServiceOpen",
		"syz_IOConnectCallMethod",
	}
	for i, want := range wantKept {
		if reduced.Calls[i].Meta.Name != want {
			t.Errorf("kept call %d = %s, want %s", i, reduced.Calls[i].Meta.Name, want)
		}
	}

	// The reduced program must be a valid, self-contained program.
	if _, err := tgt.Deserialize(reduced.Serialize(), prog.NonStrict); err != nil {
		t.Fatalf("reduced program is invalid: %v", err)
	}
	// Original must be untouched (staticReduce works on a clone).
	if len(p.Calls) != 8 {
		t.Errorf("original program was mutated: now %d calls", len(p.Calls))
	}
}

// A trace with only live calls must be returned unchanged.
func TestStaticReduceNoop(t *testing.T) {
	tgt, err := prog.GetTarget("darwin", "amd64")
	if err != nil {
		t.Skipf("darwin target unavailable: %v", err)
	}
	src := `syz_IOServiceOpen(&AUTO='AppleSSE\x00', 0x0, &AUTO=<r0=>0x0)
syz_IOConnectCallMethod(r0, ` + cmArgs + `)
syz_IOConnectCallMethod(r0, ` + cmArgs + `)
syz_IOServiceClose(r0)
`
	p, err := tgt.Deserialize([]byte(src), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	reduced, removals := staticReduce(p)
	if len(removals) != 0 {
		t.Fatalf("expected no removals, got %+v", removals)
	}
	if len(reduced.Calls) != 4 {
		t.Fatalf("expected 4 calls, got %d", len(reduced.Calls))
	}
}
