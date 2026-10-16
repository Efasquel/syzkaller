// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"path/filepath"
	"testing"
)

// A pass found in flight after a reboot crashed the box. The first pass becomes
// the crash slot (a second pass verifies it); the second pass is the verdict.
func TestReplayRecoversACrashedPass(t *testing.T) {
	s := &replayState{Pending: passReplay, PendingAt: 1, PendingSlot: "slot_0007.syz"}
	s.recover(nil)
	if s.CrashSlot != "slot_0007.syz" || s.Result != "" {
		t.Errorf("first pass: crash slot %q result %q, want slot_0007.syz and no result yet",
			s.CrashSlot, s.Result)
	}
	if s.Pending != "" {
		t.Error("recovered pass still pending")
	}
	s.Pending, s.PendingAt = passVerify, 1
	s.recover(nil)
	if s.Result != replayVerified {
		t.Errorf("second pass crashed: result %q, want %q", s.Result, replayVerified)
	}
}

// A pass interrupted without a reboot (the process was killed) proves nothing
// and must simply run again.
func TestReplayInterruptedWithoutRebootRunsAgain(t *testing.T) {
	s := &replayState{Pending: passReplay, PendingAt: gateNow() + 3600, PendingSlot: "slot_0001.syz"}
	s.recover(nil)
	if s.CrashSlot != "" || s.Result != "" || s.Pending != "" {
		t.Errorf("interrupted pass recorded as %+v; want nothing decided", s)
	}
}

// A hang from before the current boot was freed by that reboot.
func TestReplayClearsAHangFromAPreviousBoot(t *testing.T) {
	s := &replayState{Hanging: "slot_0003.syz", HangingAt: 1}
	s.recover(nil)
	if s.Hanging != "" {
		t.Errorf("hang from a previous boot kept: %q", s.Hanging)
	}
}

// A checkpoint for another ring or range is not this replay's.
func TestReplayStateIsDiscardedForAnotherRing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay_state.json")
	if err := atomicWriteJSON(path, &replayState{RingHash: "a", Slots: 3, CrashSlot: "slot_0002.syz"}); err != nil {
		t.Fatal(err)
	}
	if got := loadReplayState(path, "a", 3); got.CrashSlot != "slot_0002.syz" {
		t.Error("checkpoint for the same ring was not loaded")
	}
	if got := loadReplayState(path, "b", 3); got.CrashSlot != "" {
		t.Error("checkpoint for a different ring was reused")
	}
	if got := loadReplayState(path, "a", 4); got.CrashSlot != "" {
		t.Error("checkpoint for a different range was reused")
	}
}

// A pass that panicked with another bug names it and the slot it was running.
func TestReplayRecordsTheOtherBug(t *testing.T) {
	gate := &crashGate{targetSig: "SIG", confirmCmd: []string{"/bin/echo", "other", "beef01"}}
	s := &replayState{Pending: passReplay, PendingAt: 1000, PendingSlot: "slot_0004.syz"}
	s.recover(gate)
	if s.Result != replayOther || s.OtherSig != "beef01" || s.OtherSlot != "slot_0004.syz" {
		t.Errorf("got result %q other %q at %q", s.Result, s.OtherSig, s.OtherSlot)
	}
}
