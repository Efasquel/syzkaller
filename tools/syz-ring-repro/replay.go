// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Ring replay: the last check of a minimization that found no subset which
// reproduces on its own. It runs the ring buffer exactly as it was fuzzed --
// every slot in order, each as its own program, nothing merged or reduced -- and
// asks the one question the subset search cannot answer: does the crash
// reproduce at all?
//
// Merging changes what was fuzzed. Each fuzzer program opened and dropped its
// own connections; the merged program keeps them alive across what used to be
// program boundaries, and the static pass removes calls by contract. A search
// over that program can fail for reasons that have nothing to do with the bug.
// The ring itself has no such excuse.
//
// Like the subset search, the answer is read from the process's survival, with
// the pass in flight fsync'd first. A replay that panics the box is recovered as
// a crash on the next boot, and a second pass then runs as the first thing on
// that boot: it is the verification. The outcomes:
//
//	verified    both passes crashed (with the target signature, when gated)
//	unverified  the first pass crashed, the second did not
//	clean       the first pass ran to the end without crashing
//	other       a pass panicked with a DIFFERENT bug's signature

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
)

const (
	passReplay = "replay"
	passVerify = "verify"

	replayVerified   = "verified"
	replayUnverified = "unverified"
	replayClean      = "clean"
	replayOther      = "other"
)

// replayState is the crash-safe checkpoint of -replay-ring.
type replayState struct {
	// RingHash identifies the slots replayed (ids and programs); a checkpoint for
	// a different ring or range is discarded.
	RingHash string `json:"ring_hash"`
	Slots    int    `json:"slots"`
	// Pending is the pass in flight ("replay" or "verify"), PendingAt when it
	// started and PendingSlot the slot running. Found set at load time after a
	// reboot, it means that pass crashed the box.
	Pending     string  `json:"pending,omitempty"`
	PendingAt   float64 `json:"pending_at,omitempty"`
	PendingSlot string  `json:"pending_slot,omitempty"`
	// CrashSlot is the slot the first pass was running when it crashed.
	CrashSlot string `json:"crash_slot,omitempty"`
	// Result is the final answer, empty until there is one.
	Result string `json:"result,omitempty"`
	// Skipped are slots over the executor's call limit; they cannot run at all.
	Skipped []string `json:"skipped,omitempty"`
	// OtherSig is the bug a pass panicked with instead of the target, and
	// OtherSlot the slot it was running; OtherSaved the program file written.
	OtherSig   string `json:"other_sig,omitempty"`
	OtherSlot  string `json:"other_slot,omitempty"`
	OtherSaved string `json:"other_saved,omitempty"`
	// Hanging is the slot whose program never returned, as in ddState.
	Hanging   string  `json:"hanging,omitempty"`
	HangingAt float64 `json:"hanging_at,omitempty"`
}

func ringHash(entries []slotEntry) string {
	h := sha256.New()
	for _, e := range entries {
		fmt.Fprintf(h, "id=%d\n", e.id)
		h.Write(e.prog.Serialize())
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}

func loadReplayState(path, hash string, slots int) *replayState {
	fresh := &replayState{RingHash: hash, Slots: slots}
	data, err := os.ReadFile(path)
	if err != nil {
		return fresh
	}
	var s replayState
	if err := json.Unmarshal(data, &s); err != nil || s.RingHash != hash || s.Slots != slots {
		log.Logf(0, "checkpoint %s is for a different ring or range: starting fresh", path)
		return fresh
	}
	return &s
}

// recover turns a pass found in flight into its result: the box went down while
// it was running, so it crashed -- unless the box never rebooted (the process
// was killed), in which case the pass simply runs again.
func (s *replayState) recover(gate *crashGate) {
	if s.Hanging != "" && rebootedSince(s.HangingAt) {
		s.Hanging, s.HangingAt = "", 0
	}
	pass, at, slot := s.Pending, s.PendingAt, s.PendingSlot
	s.Pending, s.PendingAt, s.PendingSlot = "", 0, ""
	if pass == "" {
		return
	}
	if !rebootedSince(at) {
		log.Logf(0, "the %s pass was interrupted but the box never rebooted -- running it again", pass)
		return
	}
	if v, other := gate.verdict(at); v == gateOther {
		s.Result = replayOther
		s.OtherSig, s.OtherSlot = other, slot
		log.Logf(0, "crash-gate: the %s pass panicked with a DIFFERENT bug (at %s)", pass, slot)
		return
	}
	switch pass {
	case passReplay:
		s.CrashSlot = slot
		log.Logf(0, "The ring replay crashed the box (at %s). Verifying with a second pass.", slot)
	case passVerify:
		s.Result = replayVerified
	}
}

func newGate() *crashGate {
	if *flagTargetSig == "" || *flagConfirmCmd == "" {
		return nil
	}
	log.Logf(0, "Crash gating ON: only reboots confirmed as signature %s count as a repro", *flagTargetSig)
	return &crashGate{targetSig: *flagTargetSig, confirmCmd: strings.Fields(*flagConfirmCmd)}
}

// runReplayRing replays the ring buffer in dir slot by slot, checkpointing to
// -state, and writes the ring (concatenated, unreduced) to -culprit when it
// crashes, so the caller can name its syscalls.
func runReplayRing(target *prog.Target, dir string) error {
	entries, err := loadRingBuffer(target, dir)
	if err != nil {
		return err
	}
	if entries, err = selectRange(entries); err != nil {
		return err
	}
	if len(entries) == 0 {
		return fmt.Errorf("no valid programs in %s", dir)
	}
	statePath := *flagState
	if statePath == "" {
		statePath = filepath.Join(dir, "replay_state.json")
	}
	culpritPath := *flagCulprit
	if culpritPath == "" {
		culpritPath = filepath.Join(filepath.Dir(statePath), "ring.syz")
	}
	state := loadReplayState(statePath, ringHash(entries), len(entries))
	state.recover(newGate())
	if state.OtherSig != "" && state.OtherSaved == "" {
		for _, e := range entries {
			if e.slot != state.OtherSlot {
				continue
			}
			path := otherPath(culpritPath, state.OtherSig)
			if err := atomicWriteFile(path, e.prog.Serialize()); err != nil {
				log.Logf(0, "could not save the other bug's program to %s: %v", path, err)
			} else {
				state.OtherSaved = path
				log.Logf(0, "%s crashed with a DIFFERENT bug (%s); saved as %s",
					e.slot, state.OtherSig, path)
			}
		}
	}
	if err := atomicWriteJSON(statePath, state); err != nil {
		return fmt.Errorf("checkpoint: %w", err)
	}
	if state.Result == "" {
		pass := passReplay
		if state.CrashSlot != "" {
			pass = passVerify
		}
		if err := replayPass(target, entries, state, statePath, culpritPath, pass); err != nil {
			return err
		}
	}
	return finishReplay(target, entries, state, culpritPath)
}

// replayPass runs every slot once, in order. It returns only if the box
// survived; a crash ends the process and is recovered on the next boot.
func replayPass(target *prog.Target, entries []slotEntry, state *replayState,
	statePath, culpritPath, pass string) error {
	log.Logf(0, "Ring %s pass: %d programs, oldest first, each run on its own.", pass, len(entries))
	state.Pending, state.PendingAt = pass, gateNow()
	errStreak := 0
	for _, e := range entries {
		if len(e.prog.Calls) > maxExecCalls {
			if !slices.Contains(state.Skipped, e.slot) {
				state.Skipped = append(state.Skipped, e.slot)
			}
			log.Logf(0, "  %s: %d calls, over the executor's limit of %d -- cannot run, skipped",
				e.slot, len(e.prog.Calls), maxExecCalls)
			continue
		}
		state.PendingSlot = e.slot
		if err := atomicWriteJSON(statePath, state); err != nil {
			tool.Failf("checkpoint: %v", err)
		}
		err := runProgramOnce(target, e.prog)
		if errors.Is(err, errProgHang) {
			state.Pending, state.PendingAt, state.PendingSlot = "", 0, ""
			state.Hanging, state.HangingAt = e.slot, gateNow()
			saveHang(culpritPath, e.prog)
			if serr := atomicWriteJSON(statePath, state); serr != nil {
				tool.Failf("checkpoint: %v", serr)
			}
			tool.Failf("%s HUNG during the ring %s pass: no result after %ds.\n"+
				"The wedged executor holds the coverage device until the box reboots.\n"+
				"  sudo fuzz-session.py diagnose-hang\n"+
				"then REBOOT; the pass runs again from the start.", e.slot, pass, *flagProgTimeout)
		}
		if err != nil {
			errStreak++
			log.Logf(0, "  %s: executor error (%d in a row): %v", e.slot, errStreak, err)
			if errStreak >= maxExecErrStreak {
				tool.Failf("the executor failed %d programs in a row (last: %v); the replay "+
					"tested nothing, so it cannot conclude anything", errStreak, err)
			}
			continue
		}
		errStreak = 0
	}
	state.Pending, state.PendingAt, state.PendingSlot = "", 0, ""
	if pass == passReplay {
		state.Result = replayClean
	} else {
		state.Result = replayUnverified
	}
	return atomicWriteJSON(statePath, state)
}

func finishReplay(target *prog.Target, entries []slotEntry, state *replayState, culpritPath string) error {
	log.Logf(0, "")
	switch state.Result {
	case replayVerified:
		log.Logf(0, "Ring replay: VERIFIED -- the ring, replayed as fuzzed, crashed the box twice "+
			"(first at %s).", state.CrashSlot)
	case replayUnverified:
		log.Logf(0, "Ring replay: crashed once (at %s) but NOT on the second pass -- a lead, not a proof.",
			state.CrashSlot)
	case replayClean:
		log.Logf(0, "Ring replay: the ring, replayed as fuzzed, does NOT reproduce the crash.")
	case replayOther:
		log.Logf(0, "Ring replay: a DIFFERENT bug panicked the box; the target did not reproduce.")
	}
	if len(state.Skipped) > 0 {
		log.Logf(0, "  %d slot(s) were over the call limit and could not run: %s",
			len(state.Skipped), strings.Join(state.Skipped, " "))
	}
	if state.Result != replayVerified && state.Result != replayUnverified {
		return nil
	}
	merged := &prog.Prog{Target: target}
	for _, e := range entries {
		merged.Calls = append(merged.Calls, e.prog.Clone().Calls...)
	}
	if err := atomicWriteFile(culpritPath, merged.Serialize()); err != nil {
		return fmt.Errorf("write culprit: %w", err)
	}
	log.Logf(0, "Wrote the ring (%d programs, %d calls, concatenated for naming its syscalls -- "+
		"run it slot by slot, not as one program) to %s", len(entries), len(merged.Calls), culpritPath)
	return nil
}
