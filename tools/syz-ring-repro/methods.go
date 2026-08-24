// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Call-level minimization: the second reduction stage, run after -minimize-conn
// on the connection-minimized culprit. It removes IOConnectCallMethod calls only.
//
// Opens and closes are deliberately never removed. An open produces the
// io_connect_t handle every later call in its connection references, so dropping
// it would break those references; a close is frequently the trigger itself (a
// teardown use-after-free), so dropping it could hide the very bug. That is also
// why connection-minimization runs first: it fixes the set of connections — and
// thus their opens and closes — so this stage only has to decide which method
// calls between them are load-bearing.
//
// Mechanically this is just another reduction (see eliminate.go): the units are
// the method calls, and extract keeps every non-method call plus the selected
// methods. All of the crash-safe search, checkpoint, and verification machinery
// is shared with connection-minimization.

package main

import (
	"fmt"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
)

// identifyMethodCalls returns the indices of the IOConnectCallMethod (and async)
// calls in p, in program order — the only calls this stage removes.
func identifyMethodCalls(p *prog.Prog) []int {
	var m []int
	for i, c := range p.Calls {
		if isConnectCall(c.Meta.Name) {
			m = append(m, i)
		}
	}
	return m
}

// extractMethodCalls returns a self-contained program keeping every non-method
// call plus the method calls selected by mask (bit i = methods[i]). Removing a
// method never breaks a resource link: IOConnectCallMethod consumes the
// connection handle but produces no resource that other calls reference.
func extractMethodCalls(p *prog.Prog, methods []int, mask uint64) *prog.Prog {
	drop := make(map[int]bool, len(methods))
	for i, idx := range methods {
		if mask&(uint64(1)<<uint(i)) == 0 {
			drop[idx] = true
		}
	}
	sub := p.Clone()
	for i := len(p.Calls) - 1; i >= 0; i-- {
		if drop[i] {
			sub.RemoveCall(i)
		}
	}
	return sub
}

// describeMethodCall renders one method call, kind first, e.g.
// "Method(sel=0x5) #4".
func describeMethodCall(p *prog.Prog, idx int) string {
	return describeCall(p.Calls[idx], idx)
}

// callReduction builds the call-level reduction for p: units are the
// IOConnectCallMethod calls, and every open and close is kept.
func callReduction(p *prog.Prog) (reduction, error) {
	methods := identifyMethodCalls(p)
	if len(methods) == 0 {
		return reduction{}, fmt.Errorf("no IOConnectCallMethod calls to minimize")
	}
	return reduction{
		label:    kindCall,
		n:        len(methods),
		extract:  func(mask uint64) *prog.Prog { return extractMethodCalls(p, methods, mask) },
		describe: func(i int) string { return describeMethodCall(p, methods[i]) },
	}, nil
}

// runMinimizeCalls reduces the program to the smallest set of IOConnectCallMethod
// calls that still crashes, keeping all opens and closes. Intended to run after
// -minimize-conn, pointed at the connection-minimized culprit.
func runMinimizeCalls(target *prog.Target, progFile string) error {
	p, err := readProg(target, progFile)
	if err != nil {
		return err
	}
	red, err := callReduction(p)
	if err != nil {
		return fmt.Errorf("%w in %s", err, progFile)
	}
	if red.n == 1 {
		log.Logf(0, "Only one method call here, so there is nothing to pare down — it is "+
			"essential. This run just re-checks it crashes on its own.")
	}
	culpritPath := resolveCulpritPath(progFile)
	if err := minimize(target, p, resolveStatePath(progFile, "call_state.json"),
		culpritPath, red); err != nil {
		return err
	}
	// See runConnMinimize: minimize returns only once the culprit is written.
	return maybeEmitJSON(target, culpritPath)
}
