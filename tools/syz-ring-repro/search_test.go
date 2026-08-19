// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"path/filepath"
	"testing"
)

// TestCombinations checks the enumeration is complete, correctly sized, and in a
// fixed order — replay after a panic-reboot depends on the order never changing.
func TestCombinations(t *testing.T) {
	var got []uint64
	combinations(4, 2, func(m uint64) bool {
		got = append(got, m)
		return false
	})
	want := []uint64{0b0011, 0b0101, 0b1001, 0b0110, 0b1010, 0b1100}
	if len(got) != len(want) {
		t.Fatalf("got %d combinations %v, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("combination %d = 0b%04b, want 0b%04b (order must be stable)", i, got[i], want[i])
		}
	}
	// Sizes and counts across a range of n/k, including the degenerate ones.
	for n := 1; n <= 10; n++ {
		for k := 0; k <= n+1; k++ {
			count := 0
			combinations(n, k, func(m uint64) bool {
				count++
				if popcount(m) != k {
					t.Fatalf("n=%d k=%d: mask 0x%x has %d bits", n, k, m, popcount(m))
				}
				if m&^fullMask(n) != 0 {
					t.Fatalf("n=%d k=%d: mask 0x%x has bits outside n", n, k, m)
				}
				return false
			})
			want := 0
			if k >= 1 && k <= n {
				want = int(binomial(n, k))
			}
			if count != want {
				t.Errorf("n=%d k=%d: %d combinations, want %d", n, k, count, want)
			}
		}
	}
	// Early stop must actually stop.
	seen := 0
	if !combinations(6, 3, func(m uint64) bool { seen++; return seen == 4 }) {
		t.Error("combinations did not report the early stop")
	}
	if seen != 4 {
		t.Errorf("kept going after the stop: %d calls", seen)
	}
}

func binomial(n, k int) int64 {
	r := int64(1)
	for i := 0; i < k; i++ {
		r = r * int64(n-i) / int64(i+1)
	}
	return r
}

// TestSearchCulpritMinimum is the property that motivates enumeration over
// halving: the result is of *minimum cardinality*, not merely 1-minimal. The
// oracle below is deliberately built so ddmin alone would settle for a larger
// answer — connections 6 and 7 are individually inert but are dragged along by
// any halving that keeps the real culprit.
func TestSearchCulpritMinimum(t *testing.T) {
	cases := []struct {
		n, maxK int
		culprit uint64
	}{
		{8, 3, 0b00000100},    // size 1
		{8, 3, 0b10000001},    // size 2, far apart
		{8, 3, 0b00011000},    // size 2, adjacent
		{8, 3, 0b01001001},    // size 3
		{10, 3, 0b1000000001}, // size 2 spanning the halving boundary
		{4, 3, 0b1111},        // needs everything: enumeration exhausts, full set is the answer
		{1, 3, 0b1},           // trivial
	}
	for _, tc := range cases {
		culprit := tc.culprit
		probes, crashes := 0, 0
		pred := func(mask uint64) bool {
			probes++
			if mask&culprit == culprit {
				crashes++
				return true
			}
			return false
		}
		got := searchCulprit(tc.n, tc.maxK, pred)
		if got != culprit {
			t.Errorf("searchCulprit(n=%d, maxK=%d, culprit=0x%x) = 0x%x",
				tc.n, tc.maxK, culprit, got)
			continue
		}
		// The whole point: at most one probe reproduces, because every probe
		// before the answer is a strictly smaller subset and cannot contain it.
		if crashes > 1 {
			t.Errorf("n=%d culprit=0x%x: %d crashing probes, want at most 1 (each is a reboot)",
				tc.n, culprit, crashes)
		}
		t.Logf("n=%d culprit=0x%x: %d probes, %d crash", tc.n, culprit, probes, crashes)
	}
}

// TestSearchCulpritFallback checks that a culprit larger than maxK is still
// found, by handing off to ddmin, and that the clean results enumeration paid
// for are reused by the fallback rather than re-probed on device.
//
// ddmin deliberately re-queries masks (its partition/complement phases revisit
// the same configuration), which is why the real predicate in eliminate.go is
// memoized. Model that here: repeats are free replays, and only first-time
// masks count as device probes.
func TestSearchCulpritFallback(t *testing.T) {
	const n = 8
	const culprit = uint64(0b00111100) // size 4, beyond maxK=2
	memo := map[uint64]bool{}
	devProbes, replays, reusedFromEnum := 0, 0, 0
	enumerated := map[uint64]bool{}
	for k := 1; k <= 2; k++ {
		combinations(n, k, func(m uint64) bool { enumerated[m] = true; return false })
	}
	pred := func(mask uint64) bool {
		if r, ok := memo[mask]; ok {
			replays++
			if enumerated[mask] {
				reusedFromEnum++
			}
			return r
		}
		devProbes++
		r := mask&culprit == culprit
		memo[mask] = r
		return r
	}
	got := searchCulprit(n, 2, pred)
	if got&culprit != culprit {
		t.Fatalf("searchCulprit = 0x%x, does not contain culprit 0x%x", got, culprit)
	}
	// ddmin guarantees 1-minimality, so nothing removable should remain.
	for _, bit := range setBits(got) {
		if sub := got &^ (uint64(1) << uint(bit)); sub&culprit == culprit {
			t.Errorf("result 0x%x is not 1-minimal: 0x%x still reproduces", got, sub)
		}
	}
	// Enumeration alone costs n + C(n,2) = 36 probes; the fallback must not
	// repeat any of them.
	if want := n + n*(n-1)/2; devProbes < want {
		t.Errorf("%d device probes, want at least the %d from enumeration", devProbes, want)
	}
	if reusedFromEnum == 0 {
		t.Error("fallback never reused an enumeration result; the memo is not being shared")
	}
	t.Logf("found 0x%x: %d device probes, %d replays (%d of them enumeration results)",
		got, devProbes, replays, reusedFromEnum)
}

// TestSearchCulpritReplay drives searchCulprit exactly as the on-device loop
// does: a reproducing probe checkpoints its mask and kills the process, and the
// search is re-run from the reloaded state on the "next boot". It must converge
// to the same answer, never re-probe a decided mask, and reboot exactly once.
func TestSearchCulpritReplay(t *testing.T) {
	const n = 8
	const maxK = 3
	const culprit = uint64(0b01000010) // connections 1 and 6
	const hash = "p"
	path := filepath.Join(t.TempDir(), "conn_state.json")

	type reboot struct{}
	var result uint64
	reboots, deviceProbes := 0, 0
	for boots := 1; ; boots++ {
		if boots > 20 {
			t.Fatalf("did not converge after %d boots", boots)
		}
		d := loadDdState(path, n, hash, "")
		rebooted := false
		func() {
			defer func() {
				r := recover()
				if r == nil {
					return
				}
				if _, ok := r.(reboot); !ok {
					panic(r)
				}
				rebooted = true
				reboots++
			}()
			result = searchCulprit(n, maxK, func(mask uint64) bool {
				key := maskKey(mask)
				if v, ok := d.Memo[key]; ok {
					return v
				}
				deviceProbes++
				d.Attempting = key
				if err := saveDdState(path, d); err != nil {
					t.Fatal(err)
				}
				if mask&culprit == culprit {
					panic(reboot{}) // box goes down mid-probe
				}
				d.Memo[key] = false
				d.Attempting = ""
				if err := saveDdState(path, d); err != nil {
					t.Fatal(err)
				}
				return false
			})
		}()
		if !rebooted {
			break
		}
	}
	if result != culprit {
		t.Fatalf("replay converged to 0x%x, want 0x%x", result, culprit)
	}
	if reboots != 1 {
		t.Errorf("%d reboots, want exactly 1", reboots)
	}
	// n singletons + the pairs up to (1,6) inclusive: no mask probed twice.
	crashFree := searchProbeCount(t, n, maxK, culprit)
	if deviceProbes != crashFree {
		t.Errorf("%d device probes across reboots, want %d (no mask may be re-probed)",
			deviceProbes, crashFree)
	}
}

// searchProbeCount is the probe count of an uninterrupted search, for comparison
// against the crash-interrupted one.
func searchProbeCount(t *testing.T, n, maxK int, culprit uint64) int {
	t.Helper()
	probes := 0
	searchCulprit(n, maxK, func(mask uint64) bool {
		probes++
		return mask&culprit == culprit
	})
	return probes
}

// TestProjectedProbes pins the cost estimate logged before a search starts.
func TestProjectedProbes(t *testing.T) {
	cases := []struct{ n, maxK, want int }{
		{10, 3, 10 + 45 + 120},
		{10, 1, 10},
		{5, 3, 5 + 10 + 10},
		{4, 3, 4 + 6 + 4}, // maxK >= n-1: only proper subsets are counted
		{1, 3, 0},         // nothing to probe; the single connection is the answer
	}
	for _, tc := range cases {
		if got := projectedProbes(tc.n, tc.maxK); got != tc.want {
			t.Errorf("projectedProbes(%d, %d) = %d, want %d", tc.n, tc.maxK, got, tc.want)
		}
	}
}

// TestVerifyRecovery covers the verification handshake: a re-check that panics
// must come back as confirmed, and must not be confused with a search probe.
func TestVerifyRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conn_state.json")
	s := &ddState{NUnits: 8, ProgHash: "p", Memo: map[string]bool{"42": true}}
	s.Verifying = "42"
	if err := saveDdState(path, s); err != nil {
		t.Fatal(err)
	}
	// "Reboot" during the re-check: the pending verification is the confirmation.
	got := loadDdState(path, 8, "p", "")
	if got.VerifiedCrash != "42" {
		t.Errorf("VerifiedCrash = %q, want \"42\"", got.VerifiedCrash)
	}
	if got.Verifying != "" {
		t.Errorf("Verifying = %q, want cleared", got.Verifying)
	}
	// The search memo must be untouched by verification.
	if len(got.Memo) != 1 || !got.Memo["42"] {
		t.Errorf("verification altered the search memo: %v", got.Memo)
	}
	// A verification mask outside the connection count is ignored, not trusted.
	s2 := &ddState{NUnits: 4, ProgHash: "p", Memo: map[string]bool{}, Verifying: "3e0"}
	if err := saveDdState(path, s2); err != nil {
		t.Fatal(err)
	}
	if got := loadDdState(path, 4, "p", ""); got.VerifiedCrash != "" {
		t.Errorf("out-of-range verify mask was accepted: %q", got.VerifiedCrash)
	}
}

// TestForeignCheckpointIsBackedUp: pointing -minimize-conn at a second program in a
// directory that already holds a checkpoint must not destroy it. Those results
// cost reboots to obtain, and the state path is derived from the directory, so
// the collision is easy to trigger by accident.
func TestForeignCheckpointIsBackedUp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "conn_state.json")
	orig := &ddState{
		NUnits: 10, ProgHash: "66e2c6c4039e44b5",
		Memo:        map[string]bool{"1f": true, "3": false},
		CleanMs:     1200,
		CleanProbes: 1,
	}
	if err := saveDdState(path, orig); err != nil {
		t.Fatal(err)
	}
	// A different program lands on the same path.
	fresh := loadDdState(path, 4, "otherprog", "")
	if len(fresh.Memo) != 0 {
		t.Errorf("foreign memo was reused: %v", fresh.Memo)
	}
	if err := saveDdState(path, fresh); err != nil {
		t.Fatal(err)
	}
	// The original must still be recoverable, in full.
	bak := path + ".66e2c6c4039e44b5.bak"
	got := readDdState(bak)
	if got == nil {
		t.Fatalf("no backup at %s", bak)
	}
	if !got.Memo["1f"] || got.Memo["3"] || got.NUnits != 10 || got.CleanProbes != 1 {
		t.Errorf("backup lost data: %+v", got)
	}
	// And restoring it must replay: point the original program at the backup.
	if s := loadDdState(bak, 10, "66e2c6c4039e44b5", ""); !s.Memo["1f"] {
		t.Errorf("restored checkpoint does not replay: %+v", s)
	}
}

// TestBestCulprit covers the offline candidate selection used by -emit-culprit:
// prefer a verified crash, else the fewest-connection crashing subset, ties
// broken deterministically, and clean-only or empty memos yield nothing.
func TestBestCulprit(t *testing.T) {
	// Empty: no candidate.
	if _, _, ok := (&ddState{Memo: map[string]bool{}}).bestCulprit(); ok {
		t.Error("empty memo yielded a culprit")
	}
	// Only clean results: still nothing.
	if _, _, ok := (&ddState{Memo: map[string]bool{"1": false, "6": false}}).bestCulprit(); ok {
		t.Error("clean-only memo yielded a culprit")
	}
	// Smallest crashing subset wins over a larger one, regardless of insertion.
	s := &ddState{Memo: map[string]bool{"7": true, "3": true, "1f": true, "4": false}}
	mask, verified, ok := s.bestCulprit()
	if !ok || verified || mask != 0x3 {
		t.Errorf("bestCulprit = 0x%x verified=%v ok=%v; want 0x3 false true", mask, verified, ok)
	}
	// Equal popcount: the smaller mask value is chosen (determinism).
	s = &ddState{Memo: map[string]bool{"6": true, "3": true}}
	if mask, _, _ := s.bestCulprit(); mask != 0x3 {
		t.Errorf("tie broken to 0x%x, want 0x3", mask)
	}
	// A verified crash wins even over a smaller unverified one.
	s = &ddState{Memo: map[string]bool{"1": true}, VerifiedCrash: "6"}
	mask, verified, ok = s.bestCulprit()
	if !ok || !verified || mask != 0x6 {
		t.Errorf("bestCulprit = 0x%x verified=%v ok=%v; want 0x6 true true", mask, verified, ok)
	}
	// A pending Attempting mask, recovered at load, is a crash and so a candidate.
	path := filepath.Join(t.TempDir(), "conn_state.json")
	if err := saveDdState(path, &ddState{NUnits: 4, ProgHash: "p", Memo: map[string]bool{}, Attempting: "2"}); err != nil {
		t.Fatal(err)
	}
	if mask, _, ok := loadDdState(path, 4, "p", "").bestCulprit(); !ok || mask != 0x2 {
		t.Errorf("recovered-attempt culprit = 0x%x ok=%v; want 0x2 true", mask, ok)
	}
}
