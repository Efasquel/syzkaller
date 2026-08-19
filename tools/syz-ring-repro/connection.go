// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Connection grouping for the connection-elimination stage (see ddmin.go for the
// delta-debugging search and eliminate.go for the on-device loop).
//
// A *connection* is one IOServiceOpen plus every call that uses the io_connect_t
// it produced (its IOConnectCallMethods and IOServiceClose), grouped by producer
// identity (port.Res). Connection-elimination finds the minimal subset of
// connections that still reproduces the crash. This is also where "unused open"
// and "open+close-only" connections get dropped — safely, once the oracle has
// confirmed they are not part of the culprit set, never by a blind static delete
// (an open+close-only pair is the minimal reproducer for a clientClose/teardown
// double-free, so deleting it statically could remove the very bug).

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/syzkaller/prog"
)

// connection is one IOServiceOpen and every call using the io_connect_t it
// produced. callIdxs are indices into the source program, in original order, and
// include the open itself. openIdx is -1 if a consumer's producing open was not
// found (should not happen after static reduction).
type connection struct {
	openIdx  int
	callIdxs []int
}

// openProducer returns the io_connect_t resource an IOServiceOpen produces via
// its out-pointer (arg 2), or nil if it produces none.
func openProducer(c *prog.Call) *prog.ResultArg {
	if len(c.Args) < 3 {
		return nil
	}
	res, _ := prog.InnerArg(c.Args[2]).(*prog.ResultArg)
	return res
}

// identifyConnections groups the calls of p into connections by producer
// identity, ordered by their open's position (oldest first). Calls belonging to
// no connection — a consumer on an unproduced handle (static reduction should
// already have removed these) or a non-IOKit call — are returned in orphans.
func identifyConnections(p *prog.Prog) (conns []connection, orphans []int) {
	byProducer := map[*prog.ResultArg]int{} // producer -> index into conns
	for i, c := range p.Calls {
		name := c.Meta.Name
		switch {
		case isOpenCall(name):
			prod := openProducer(c)
			if prod == nil {
				orphans = append(orphans, i)
				continue
			}
			ci, ok := byProducer[prod]
			if !ok {
				ci = len(conns)
				conns = append(conns, connection{openIdx: i})
				byProducer[prod] = ci
			} else {
				conns[ci].openIdx = i
			}
			conns[ci].callIdxs = append(conns[ci].callIdxs, i)
		case isCloseCall(name) || isConnectCall(name):
			port := portArg(c)
			if port == nil || port.Res == nil {
				orphans = append(orphans, i)
				continue
			}
			ci, ok := byProducer[port.Res]
			if !ok {
				ci = len(conns)
				conns = append(conns, connection{openIdx: -1})
				byProducer[port.Res] = ci
			}
			conns[ci].callIdxs = append(conns[ci].callIdxs, i)
		default:
			orphans = append(orphans, i)
		}
	}
	return conns, orphans
}

// extractConnections returns a self-contained program containing the calls of the
// connections selected by mask (bit i = conns[i]), in their original order.
// Removing the other calls never breaks a resource link, because a connection's
// consumers reference only its own open.
func extractConnections(p *prog.Prog, conns []connection, mask uint64) *prog.Prog {
	keep := map[int]bool{}
	for i := range conns {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		for _, idx := range conns[i].callIdxs {
			keep[idx] = true
		}
	}
	sub := p.Clone()
	for i := len(p.Calls) - 1; i >= 0; i-- {
		if !keep[i] {
			sub.RemoveCall(i)
		}
	}
	return sub
}

// describeConnection renders one connection as its calls, kind first and the
// source call index after, e.g. "Open #7, Method(sel=0x0) #8, Close #12". The
// indices are not contiguous: a connection's calls are typically interleaved
// with other connections'.
func describeConnection(p *prog.Prog, c connection) string {
	var parts []string
	for _, idx := range c.callIdxs {
		parts = append(parts, describeCall(p.Calls[idx], idx))
	}
	if len(parts) == 0 {
		return "(no calls)"
	}
	return strings.Join(parts, ", ")
}

// describeCall renders one call as "Kind #idx", appending the method selector
// (the driver entry point being hit) for IOConnectCallMethod calls.
func describeCall(call *prog.Call, idx int) string {
	s := callKind(call.Meta.Name)
	if isConnectCall(call.Meta.Name) && len(call.Args) > 1 {
		if sel, ok := call.Args[1].(*prog.ConstArg); ok {
			s += fmt.Sprintf("(sel=0x%x)", sel.Val)
		}
	}
	return fmt.Sprintf("%s #%d", s, idx)
}

func callKind(name string) string {
	switch {
	case isOpenCall(name):
		return "Open"
	case isCloseCall(name):
		return "Close"
	case isConnectCall(name):
		return "Method"
	}
	return name
}

// atomicWriteJSON marshals v and writes it to path durably: a temp file, fsync,
// atomic rename, then an fsync of the parent *directory*.
//
// That last fsync is not optional here. A rename is a directory metadata
// operation: fsyncing the temp file only makes its contents durable, and on APFS
// the new directory entry can still be sitting in the volume's uncommitted state
// when the kernel panics. The observed failure is exactly that — a fsync'd
// <path>.tmp holding the pending checkpoint survives the reboot while <path>
// still shows the previous generation, so the crash that the checkpoint was
// written to record is lost and ddmin re-tests the same mask forever.
func atomicWriteJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// syncDir fsyncs a directory so that renames/creates inside it are durable
// across a kernel panic.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		d.Close()
		return err
	}
	return d.Close()
}
