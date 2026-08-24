// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"slices"
	"testing"
)

// /bin/echo <verdict> stands in for crash_fingerprint.py match-since: the gate
// appends <target_sig> <since> and reads the first token of stdout.
func echoGate(verdict string) *crashGate {
	return &crashGate{targetSig: "SIG", confirmCmd: []string{"/bin/echo", verdict}}
}

// A reboot the gate identifies as a DIFFERENT bug is recorded as a non-repro,
// not attributed to the subset.
func TestGateFiltersOtherBug(t *testing.T) {
	s := &ddState{Memo: map[string]bool{}}
	s.recoverAttempt("3", 1000.0, 4, echoGate("other"))
	if v, ok := s.Memo["3"]; !ok || v {
		t.Fatalf("Memo[3] = %v (present=%v), want false", v, ok)
	}
}

// A reboot the gate confirms as the target (or cannot fingerprint -> "none")
// counts as a repro, as does an ungated (nil) recovery.
func TestGateCountsMatchNoneAndNil(t *testing.T) {
	for _, verdict := range []string{"match", "none"} {
		s := &ddState{Memo: map[string]bool{}}
		s.recoverAttempt("3", 1000.0, 4, echoGate(verdict))
		if !s.Memo["3"] {
			t.Errorf("verdict %q: Memo[3] = false, want true", verdict)
		}
	}
	var nilGate *crashGate
	s := &ddState{Memo: map[string]bool{}}
	s.recoverAttempt("3", 1000.0, 4, nilGate)
	if !s.Memo["3"] {
		t.Errorf("nil gate: Memo[3] = false, want true (original behavior)")
	}
}

// A missing timestamp (pre-gating checkpoint) bypasses the gate: the reboot
// counts, so old checkpoints loaded under gating flags are never dropped.
func TestGateBypassesWithoutTimestamp(t *testing.T) {
	s := &ddState{Memo: map[string]bool{}}
	s.recoverAttempt("3", 0, 4, echoGate("other"))
	if !s.Memo["3"] {
		t.Errorf("at=0: Memo[3] = false, want true (gate bypassed)")
	}
}

// During verification, a different-bug reboot fails the check (VerifyFailed)
// rather than confirming the culprit.
func TestGateVerifyOtherBugFails(t *testing.T) {
	s := &ddState{Memo: map[string]bool{}}
	s.recoverVerify("2", 1000.0, 4, echoGate("other"))
	if s.VerifiedCrash != "" {
		t.Errorf("VerifiedCrash = %q, want empty", s.VerifiedCrash)
	}
	if !slices.Contains(s.VerifyFailed, "2") {
		t.Errorf("VerifyFailed = %v, want it to contain 2", s.VerifyFailed)
	}
}

func TestGateVerifyMatchConfirms(t *testing.T) {
	s := &ddState{Memo: map[string]bool{}}
	s.recoverVerify("2", 1000.0, 4, echoGate("match"))
	if s.VerifiedCrash != "2" {
		t.Errorf("VerifiedCrash = %q, want 2", s.VerifiedCrash)
	}
}
