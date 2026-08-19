// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Static reduction of a joined trace before on-device bisection.
//
// Each on-device test in VM-less mode costs a reboot, so we first delete the
// calls that are provably inert *by the IOKit/MIG contract* — independent of any
// KEXT state. These can never be the culprit (they are rejected before the KEXT
// runs), so removing them cannot change whether the trace reproduces, and it
// shrinks the input the reboot-costly bisection has to work on.
//
// What is safe to delete statically (kernel-contract-inert):
//   - an IOConnectCallMethod on an unproduced connection — a handle that no
//     prior IOServiceOpen in the trace defined (port.Res == nil). This covers a
//     bare 0x0 handle and any hardcoded literal: MIG has no port for it. Note a
//     connection legitimately produced by an open is kept even if its handle
//     value is 0, because it still has a producer (port.Res != nil);
//   - an IOConnectCallMethod on a connection already closed earlier — MIG
//     rejects it at the port lookup, before the user client is reached;
//   - a second IOServiceClose on an already-closed connection.
//
// What is deliberately kept (inertness would depend on KEXT state, so only the
// on-device oracle may drop it):
//   - the *first* IOServiceClose on a connection — it can be load-bearing
//     (e.g. a teardown that double-frees an object a sub-opcode already freed);
//   - every IOServiceOpen — opening instantiates the user client and runs KEXT
//     dispatch setup;
//   - any call on a live, open connection.
//
// Connections are keyed by producer identity (port.Res, the open's out arg), so
// a connection reopened after a close is a different producer and its calls are
// never mistaken for post-close calls.

package main

import (
	"strings"

	"github.com/google/syzkaller/prog"
)

// staticRemoval records one deleted call for logging.
type staticRemoval struct {
	index  int
	call   string
	reason string
}

func isConnectCall(name string) bool {
	return strings.HasPrefix(name, "syz_IOConnectCallMethod") ||
		strings.HasPrefix(name, "syz_IOConnectCallAsyncMethod")
}

// isOpenCall / isCloseCall match IOServiceOpen / IOServiceClose and their
// per-driver specializations (e.g. syz_IOServiceOpen$AppleJPEGDriver). Matching
// by prefix is essential: a bare == would miss the $variant opens, orphaning them
// so their connections are extracted without their producing open.
func isOpenCall(name string) bool {
	return strings.HasPrefix(name, "syz_IOServiceOpen")
}

func isCloseCall(name string) bool {
	return strings.HasPrefix(name, "syz_IOServiceClose")
}

// portArg returns the connection handle (arg 0) of a close/call-method call.
func portArg(c *prog.Call) *prog.ResultArg {
	if len(c.Args) == 0 {
		return nil
	}
	ra, _ := c.Args[0].(*prog.ResultArg)
	return ra
}

// isUnproducedHandle reports whether the port is a connection that no prior
// IOServiceOpen in the trace produced, i.e. a literal (Res == nil) rather than a
// reference to an open's out resource. A nil port (arg 0 is not a ResultArg,
// which should not happen for these calls) is not treated as unproduced — we
// keep what we cannot reason about.
func isUnproducedHandle(port *prog.ResultArg) bool {
	return port != nil && port.Res == nil
}

// staticReduce returns a copy of p with the kernel-contract-inert calls removed,
// plus the list of what was removed. If nothing is removable it returns p
// unchanged and a nil list.
func staticReduce(p *prog.Prog) (*prog.Prog, []staticRemoval) {
	closed := map[*prog.ResultArg]bool{} // producer arg -> already closed
	remove := map[int]bool{}
	var removals []staticRemoval
	add := func(i int, name, reason string) {
		remove[i] = true
		removals = append(removals, staticRemoval{index: i, call: name, reason: reason})
	}
	for i, c := range p.Calls {
		name := c.Meta.Name
		switch {
		case isCloseCall(name):
			port := portArg(c)
			if port == nil {
				continue // cannot identify the handle, keep it
			}
			if isUnproducedHandle(port) {
				add(i, name, "invalid connection") // close on a 0x0/unproduced handle
				continue
			}
			if closed[port.Res] {
				add(i, name, "double close") // 2nd close of an already-closed conn
				continue
			}
			// First close: potentially load-bearing, keep it, mark closed.
			closed[port.Res] = true
		case isConnectCall(name):
			port := portArg(c)
			if port == nil {
				continue // cannot identify the handle, keep it
			}
			if isUnproducedHandle(port) {
				add(i, name, "invalid connection") // 0x0 connector, no prior open
				continue
			}
			if closed[port.Res] {
				add(i, name, "after close") // MIG rejects at port lookup
			}
		}
	}
	if len(remove) == 0 {
		return p, nil
	}
	reduced := p.Clone()
	// Remove in descending index order so earlier indices stay valid. Removed
	// calls (closes and call-methods) produce no resources, so no later call can
	// reference them — removal never orphans a resource.
	for i := len(p.Calls) - 1; i >= 0; i-- {
		if remove[i] {
			reduced.RemoveCall(i)
		}
	}
	return reduced, removals
}
