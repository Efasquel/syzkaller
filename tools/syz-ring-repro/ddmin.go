// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Delta-debugging (ddmin) over connections, and its crash-safe checkpoint.
//
// A configuration is a subset of the connections, represented as a bitmask (bit i
// = conns[i]). pred(mask) runs the program built from those connections on device
// and reports whether it reproduces the crash. ddminConns returns a 1-minimal
// crashing subset: removing any single connection from it stops the crash. This
// finds culprits made of *several* connections (e.g. a use-after-free split
// across two clients), which testing connections one at a time cannot.
//
// Each pred call is a reboot-costly on-device run, so results are memoized on disk
// (ddState) and the in-flight mask is checkpointed before each run. ddmin is
// deterministic, so after a crash-reboot the campaign relaunches, the memo
// recovers the pending mask as a crash, and re-running ddminConns replays every
// decided test instantly and advances past it — one reboot per committed
// reduction, guaranteed progress.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/bits"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
)

// fullMask is the configuration containing all n connections.
func fullMask(n int) uint64 {
	if n >= 64 {
		return ^uint64(0)
	}
	return (uint64(1) << uint(n)) - 1
}

func popcount(mask uint64) int { return bits.OnesCount64(mask) }

func setBits(mask uint64) []int {
	var b []int
	for i := 0; i < 64; i++ {
		if mask&(uint64(1)<<uint(i)) != 0 {
			b = append(b, i)
		}
	}
	return b
}

// partition splits the set bits of mask into gran roughly-equal, contiguous
// sub-masks (empty parts are dropped). Deterministic, so ddmin replays identically.
func partition(mask uint64, gran int) []uint64 {
	b := setBits(mask)
	n := len(b)
	if gran > n {
		gran = n
	}
	if gran < 1 {
		return nil
	}
	var parts []uint64
	for g := 0; g < gran; g++ {
		lo := g * n / gran
		hi := (g + 1) * n / gran
		var part uint64
		for _, bi := range b[lo:hi] {
			part |= uint64(1) << uint(bi)
		}
		if part != 0 {
			parts = append(parts, part)
		}
	}
	return parts
}

// ddminConns runs delta debugging over n connections using pred (pred(mask) =
// does the subprogram of those connections reproduce the crash). It returns a
// 1-minimal crashing subset. The full configuration is assumed to reproduce, so
// pred is only ever called on strict subsets.
func ddminConns(n int, pred func(uint64) bool) uint64 {
	config := fullMask(n)
	if n <= 1 {
		return config
	}
	gran := 2
	for popcount(config) >= 2 {
		parts := partition(config, gran)
		reduced := false
		// Reduce to subset: some part alone still crashes.
		for _, d := range parts {
			if pred(d) {
				config = d
				gran = 2
				reduced = true
				break
			}
		}
		if reduced {
			continue
		}
		// Reduce to complement: removing some part still crashes.
		for _, d := range parts {
			comp := config &^ d
			if comp != 0 && pred(comp) {
				config = comp
				gran = maxInt(gran-1, 2)
				reduced = true
				break
			}
		}
		if reduced {
			continue
		}
		if gran >= popcount(config) {
			break
		}
		gran = minInt(gran*2, popcount(config))
	}
	return config
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ddState is the crash-safe checkpoint of connection ddmin: the memoized result
// of every subset tested so far, and the subset currently in flight. It is
// written (fsync'd) before each on-device test so a panic-reboot loses nothing.
//
// A memo is only meaningful for the exact program and reduction it was measured
// on, so the state carries that identity (Kind + NUnits + ProgHash) and is
// discarded wholesale on any mismatch. Silently reusing another program's results
// is worse than starting over: every stale `false` tells ddmin a subset is
// innocent without a single device run behind it.
type ddState struct {
	// Kind is which reduction wrote this checkpoint: "connection" or "call". It
	// records what a mask bit means, so -emit-culprit can pick the matching
	// extractor and turn a mask back into a program without being told.
	Kind string `json:"kind,omitempty"`
	// NUnits is how many reducible units (connections, or method calls) the masks
	// index — the mask width. Named generically because both reduction stages
	// share this state; a mask with a bit at or above NUnits is not a
	// configuration of this program.
	NUnits int `json:"n_units"`
	// nConnsLegacy loads the pre-rename "n_conns" field so checkpoints written
	// before NUnits existed still resume instead of being discarded. Migrated
	// into NUnits by readDdState and never written back (omitempty, always 0
	// after migration).
	NConnsLegacy int `json:"n_conns,omitempty"`
	// ProgHash identifies the program the memo was measured on (see progHash).
	ProgHash string `json:"prog_hash"`
	// Memo maps a configuration mask (hex) to whether it reproduced the crash.
	Memo map[string]bool `json:"memo"`
	// Attempting is the mask (hex) currently under test, or "" when nothing is in
	// flight. A non-empty value found at load time means the box rebooted while
	// testing it, i.e. that subset crashed.
	Attempting string `json:"attempting"`
	// CleanMs is the cumulative wall time of clean (no-repro) probes across all
	// boots, and CleanProbes how many produced it. Their ratio is the per-probe
	// cost that any search strategy trades against reboot time: a strategy that
	// avoids one reboot is worth it only if it adds fewer than reboot/probe extra
	// probes. Accumulated on disk because a single boot only ever sees a fraction
	// of the search.
	CleanMs     int64 `json:"clean_ms"`
	CleanProbes int   `json:"clean_probes"`
	// Verifying is the mask (hex) being re-checked as the first program of a
	// launch, or "" when nothing is in flight — the same reboot-survives-as-a-
	// crash trick as Attempting, kept separate so a verification never rewrites
	// the search memo.
	Verifying string `json:"verifying,omitempty"`
	// VerifiedCrash is the mask confirmed to reproduce on its own, with no other
	// probe having run first. Probes share a kernel boot, so a subset can crash
	// on state an earlier probe left behind; without this the search would
	// happily blame whichever subset happened to tip it over.
	VerifiedCrash string `json:"verified_crash,omitempty"`
	// VerifyFailed are masks that crashed during the search but did not crash on
	// re-check. Recorded so verification is attempted once and cannot loop.
	VerifyFailed []string `json:"verify_failed,omitempty"`
	// Exhausted marks a finished search whose best candidate has already failed
	// verification: there is nothing left to try, and re-running will produce the
	// same unverified answer forever.
	//
	// Without this the caller cannot tell "not finished yet, relaunch me" from
	// "finished, and the answer is that no subset reproduces alone". Both looked
	// like a clean exit with no VerifiedCrash, so an orchestrator that relaunches
	// until verification succeeds spins until its boot budget runs out. That is
	// not hypothetical: a poisoned checkpoint burned six triage advances in a real
	// campaign and would have consumed all forty.
	Exhausted bool `json:"exhausted,omitempty"`
	// Hanging is the mask whose program never returned, with the wall-clock epoch
	// it started. Recorded separately from Attempting because it is a DIFFERENT
	// outcome: Attempting recovered after a reboot means the subset panicked the
	// box, while this one wedged a kernel thread without panicking. Conflating
	// them would file a hang as a crash and send triage looking for a panic
	// report that does not exist.
	Hanging   string  `json:"hanging,omitempty"`
	HangingAt float64 `json:"hanging_at,omitempty"`
	// AttemptingAt / VerifyingAt are the wall-clock epochs the in-flight
	// Attempting / Verifying subset started running, so a crash gate can scope its
	// panic-report scan to reports produced by that subset's reboot. Zero when
	// nothing is pending, and on pre-gating checkpoints (which then bypass gating).
	AttemptingAt float64 `json:"attempting_at,omitempty"`
	VerifyingAt  float64 `json:"verifying_at,omitempty"`
}

// meanProbeMs is the average clean-probe cost measured so far, or 0 if nothing
// has completed yet.
func (s *ddState) meanProbeMs() int64 {
	if s.CleanProbes == 0 {
		return 0
	}
	return s.CleanMs / int64(s.CleanProbes)
}

func maskKey(mask uint64) string { return strconv.FormatUint(mask, 16) }

// exhaustedFor reports whether the finished search's answer has already been
// re-checked and failed. Called only after searchCulprit returns, so "the search
// wanted nothing more" is implied; this adds "and verification is spent".
func (s *ddState) exhaustedFor(minimal uint64) bool {
	return slices.Contains(s.VerifyFailed, maskKey(minimal))
}

// bestCulprit reports the smallest subset currently known to crash, and whether
// one exists. This is the checkpoint's best answer at any moment, without any
// further device work: a VerifiedCrash if one has been confirmed, otherwise the
// fewest-connection mask the search has recorded as crashing (ties broken by
// mask value, so the choice is deterministic).
//
// The `verified` return distinguishes a mask re-checked in isolation from a
// mere search hit, which may still owe its crash to state an earlier probe left
// behind. Callers that automate on the result should treat unverified as "test
// this candidate", not "this is the answer".
func (s *ddState) bestCulprit() (mask uint64, verified, ok bool) {
	if s.VerifiedCrash != "" {
		if m, err := strconv.ParseUint(s.VerifiedCrash, 16, 64); err == nil {
			return m, true, true
		}
	}
	best, found := uint64(0), false
	for key, crashed := range s.Memo {
		if !crashed {
			continue
		}
		m, err := strconv.ParseUint(key, 16, 64)
		if err != nil {
			continue
		}
		if !found || popcount(m) < popcount(best) || (popcount(m) == popcount(best) && m < best) {
			best, found = m, true
		}
	}
	return best, false, found
}

// progHash identifies a program by its serialization, so a checkpoint can tell
// whether it belongs to the program now being reduced.
func progHash(p *prog.Prog) string {
	sum := sha256.Sum256(p.Serialize())
	return hex.EncodeToString(sum[:8])
}

// loadDdState reads the checkpoint for the reduction identified by (kind,
// nUnits, hash), or initializes a fresh one. kind may be "" to mean "accept
// whatever the file says" — used by -emit-culprit, which reads the kind from the
// file rather than asserting it. Four things are recovered or rejected here:
//
//   - A state belonging to a different program or reduction (Kind, NUnits, or
//     ProgHash mismatch) is discarded; so is any memo key with bits outside
//     nUnits.
//   - A dangling Attempting mask means the box rebooted mid-test, i.e. that
//     subset crashed; it is recorded as such. Recovery is persisted by the next
//     save and is idempotent.
//   - A <path>.tmp newer than path is a checkpoint whose rename was lost to a
//     panic (see atomicWriteJSON). Its Attempting mask is the crash the lost
//     write existed to record, so it is recovered the same way. Without this,
//     any checkpoint written before the fsync-the-directory fix is unreadable.
//
// The optional gate (variadic so existing callers stay 4-arg) filters reboots
// that reproduced a different bug than the target out of the recovered memo; a
// nil/absent gate recovers every reboot as a crash, the original behavior.
func loadDdState(path string, nUnits int, hash, kind string, gates ...*crashGate) *ddState {
	var gate *crashGate
	if len(gates) > 0 {
		gate = gates[0]
	}
	fresh := &ddState{Kind: kind, NUnits: nUnits, ProgHash: hash, Memo: map[string]bool{}}
	s := readDdState(path)
	// A recorded kind that disagrees with a caller-asserted kind is a mismatch;
	// an empty caller kind (emit) accepts whatever was recorded.
	kindClash := s != nil && kind != "" && s.Kind != "" && s.Kind != kind
	if s == nil || s.NUnits != nUnits || s.ProgHash != hash || kindClash {
		if s != nil {
			// The state path is derived from the program's directory, so pointing
			// a stage at a second program in the same directory lands on this
			// branch — and the first probe would then overwrite results that cost
			// reboots to obtain. Move the old checkpoint aside instead.
			backupDdState(path, s)
			log.Logf(0, "checkpoint %s is for a different program/stage (%s, %d units, hash %s; "+
				"now %s, %d/%s): starting fresh", path, s.Kind, s.NUnits, s.ProgHash, kind, nUnits, hash)
		}
		s = fresh
	}
	if kind != "" {
		s.Kind = kind
	}
	// A mask with bits beyond nUnits cannot be a configuration of this program.
	for key := range s.Memo {
		if mask, err := strconv.ParseUint(key, 16, 64); err != nil || mask&^fullMask(nUnits) != 0 {
			delete(s.Memo, key)
		}
	}
	s.recoverAttempt(s.Attempting, s.AttemptingAt, nUnits, gate)
	s.recoverVerify(s.Verifying, s.VerifyingAt, nUnits, gate)
	// A lost rename leaves the pending checkpoint stranded in the temp file.
	if tmp := readDdState(path + ".tmp"); tmp != nil && tmp.NUnits == nUnits && tmp.ProgHash == hash {
		if newer(path+".tmp", path) {
			s.recoverAttempt(tmp.Attempting, tmp.AttemptingAt, nUnits, gate)
			s.recoverVerify(tmp.Verifying, tmp.VerifyingAt, nUnits, gate)
		}
	}
	return s
}

// recoverVerify records an in-flight verification as confirmed: the box went
// down while re-running that subset on its own, which is exactly what the
// re-check was looking for. When gated, a reboot that produced a DIFFERENT bug's
// report means the culprit did not cleanly reproduce the target, so verification
// fails (recorded once) rather than confirming.
func (s *ddState) recoverVerify(key string, at float64, nConns int, gate *crashGate) {
	s.Verifying = ""
	if !validMask(key, nConns) {
		return
	}
	if !rebootedSince(at) {
		log.Logf(0, "interrupted while verifying %s but the box never rebooted "+
			"— verification is inconclusive, not a pass", key)
		return
	}
	if gate.verdict(at) == gateOther {
		if !slices.Contains(s.VerifyFailed, key) {
			s.VerifyFailed = append(s.VerifyFailed, key)
		}
		log.Logf(0, "crash-gate: verification reboot for %s was a DIFFERENT crash than the "+
			"target — verification failed", key)
		return
	}
	s.VerifiedCrash = key
}

// validMask reports whether key is a hex mask that could be a configuration of
// nConns connections.
func validMask(key string, nConns int) bool {
	if key == "" {
		return false
	}
	mask, err := strconv.ParseUint(key, 16, 64)
	return err == nil && mask != 0 && mask&^fullMask(nConns) == 0
}

// recoverAttempt records an in-flight mask as a crash: reaching load time with a
// mask still pending means the box went down while testing it. When gated, a
// reboot whose report fingerprints to a DIFFERENT bug is recorded as a non-repro
// (Memo=false) instead, so the search never minimizes toward the wrong crash.
// It does not log per-mask (loadDdState is also the read path for offline
// -emit-culprit), except when the gate positively filters a reboot.
func (s *ddState) recoverAttempt(key string, at float64, nConns int, gate *crashGate) {
	s.Attempting = ""
	if !validMask(key, nConns) {
		return
	}
	if !rebootedSince(at) {
		// Interrupted, not crashed. Leave it UNMEMOIZED so the subset is probed
		// again rather than recorded as a verdict we never actually observed.
		log.Logf(0, "interrupted while testing %s but the box never rebooted "+
			"— not counting it as a repro; it will be re-probed", key)
		return
	}
	if gate.verdict(at) == gateOther {
		s.Memo[key] = false
		log.Logf(0, "crash-gate: reboot while testing %s was a DIFFERENT crash than the target "+
			"— not counting it as a repro", key)
		return
	}
	s.Memo[key] = true
}

// backupDdState preserves a checkpoint that belongs to another program under a
// name keyed by that program, so returning to it later replays its results
// instead of paying for them again.
//
// It copies rather than renames: loading a checkpoint must not consume the file
// it read, or a second load would see nothing. The original stays in place and
// is overwritten by this run's first save, which is what makes the copy worth
// having. Best-effort — failing to keep a backup must not stop the run.
func backupDdState(path string, s *ddState) {
	id := s.ProgHash
	if id == "" {
		id = "unknown"
	}
	bak := fmt.Sprintf("%s.%s.bak", path, id)
	if err := atomicWriteJSON(bak, s); err != nil {
		log.Logf(0, "could not back up %s: %v", path, err)
		return
	}
	log.Logf(0, "kept previous checkpoint (%d decided) as %s", len(s.Memo), bak)
}

func readDdState(path string) *ddState {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var s ddState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil
	}
	if s.Memo == nil {
		s.Memo = map[string]bool{}
	}
	// Migrate the pre-rename "n_conns" field so old checkpoints still resume.
	if s.NUnits == 0 && s.NConnsLegacy != 0 {
		s.NUnits = s.NConnsLegacy
	}
	s.NConnsLegacy = 0
	return &s
}

// newer reports whether a was modified strictly after b (b missing counts).
func newer(a, b string) bool {
	sa, err := os.Stat(a)
	if err != nil {
		return false
	}
	sb, err := os.Stat(b)
	if err != nil {
		return true
	}
	return sa.ModTime().After(sb.ModTime())
}

func saveDdState(path string, s *ddState) error { return atomicWriteJSON(path, s) }

// logDdState summarizes what a resumed run inherited from the checkpoint. It
// stays silent on a fresh start (nothing to report) and otherwise reports, in
// plain terms, how much has been decided and the confirmed culprit if any.
// Subsets are shown as their unit indices, not raw masks.
func logDdState(s *ddState) {
	if len(s.Memo) == 0 && s.VerifiedCrash == "" && s.CleanProbes == 0 {
		return // fresh run — nothing inherited
	}
	var crashed []string
	clean := 0
	for key, repro := range s.Memo {
		if repro {
			if m, err := strconv.ParseUint(key, 16, 64); err == nil {
				crashed = append(crashed, fmt.Sprintf("%v", setBits(m)))
			}
		} else {
			clean++
		}
	}
	sort.Strings(crashed)
	log.Logf(0, "Resuming from checkpoint: %d subset(s) already tested (%d crashing, %d not).",
		len(s.Memo), len(crashed), clean)
	if len(crashed) > 0 {
		log.Logf(0, "  crashing subsets: %s", strings.Join(crashed, " "))
	}
	if m, err := strconv.ParseUint(s.VerifiedCrash, 16, 64); err == nil {
		log.Logf(0, "  confirmed culprit: %v (crashes on its own)", setBits(m))
	}
	if s.CleanProbes > 0 {
		log.Logf(0, "  average test run: %dms (over %d clean runs)", s.meanProbeMs(), s.CleanProbes)
	}
}
