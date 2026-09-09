// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

// A culprit's surviving IOConnectCallMethod calls are emitted as syscall names;
// opens and closes are skipped. A generic call (fuzzable selector) is still
// listed by name but flagged with a warning, since disabling it is wholesale.
func TestEmitSyscallsGenericWarns(t *testing.T) {
	tgt, err := prog.GetTarget("darwin", "amd64")
	if err != nil {
		t.Skipf("darwin target unavailable: %v", err)
	}
	src := `syz_IOServiceOpen(&AUTO='AppleSSE\x00', 0x0, &AUTO=<r0=>0x0)
syz_IOConnectCallMethod(r0, 0x5, &AUTO, 0x0, &AUTO, 0x0, &AUTO, &AUTO, &AUTO, &AUTO)
syz_IOServiceClose(r0)
`
	p, err := tgt.Deserialize([]byte(src), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	names, warnings := emitSyscalls(p)
	if len(names) != 1 || names[0] != "syz_IOConnectCallMethod" {
		t.Fatalf("names = %v, want [syz_IOConnectCallMethod]", names)
	}
	if len(warnings) != 1 {
		t.Errorf("warnings = %v, want 1 (generic call is wholesale)", warnings)
	}
}

// Repeated calls to the same syscall collapse to a single name.
func TestEmitSyscallsDedups(t *testing.T) {
	tgt, err := prog.GetTarget("darwin", "amd64")
	if err != nil {
		t.Skipf("darwin target unavailable: %v", err)
	}
	src := `syz_IOServiceOpen(&AUTO='AppleSSE\x00', 0x0, &AUTO=<r0=>0x0)
syz_IOConnectCallMethod(r0, 0x5, &AUTO, 0x0, &AUTO, 0x0, &AUTO, &AUTO, &AUTO, &AUTO)
syz_IOConnectCallMethod(r0, 0x9, &AUTO, 0x0, &AUTO, 0x0, &AUTO, &AUTO, &AUTO, &AUTO)
syz_IOServiceClose(r0)
`
	p, err := tgt.Deserialize([]byte(src), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	names, _ := emitSyscalls(p)
	// Both lines are the same bare generic syscall name, so one entry.
	if len(names) != 1 {
		t.Fatalf("names = %v, want a single deduped entry", names)
	}
}

// freeDispatchArg reports true for a fuzzable dispatch arg; a const[N] one (its
// value fixed in the variant name) returns false and warrants no warning.
func TestFreeSelectorConst(t *testing.T) {
	tgt, err := prog.GetTarget("darwin", "amd64")
	if err != nil {
		t.Skipf("darwin target unavailable: %v", err)
	}
	var constType *prog.ConstType
	for _, s := range tgt.Syscalls {
		for _, f := range s.Args {
			if ct, ok := f.Type.(*prog.ConstType); ok {
				constType = ct
				break
			}
		}
		if constType != nil {
			break
		}
	}
	if constType == nil {
		t.Skip("no ConstType arg in darwin target")
	}
	fixed := prog.MakeConstArg(constType, prog.DirIn, constType.Val)
	call := &prog.Call{Args: []prog.Arg{nil, fixed}}
	if freeDispatchArg(call) {
		t.Errorf("freeDispatchArg(const selector) = true, want false")
	}
}
