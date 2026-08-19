// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Culprit search: increasing-cardinality enumeration, with ddmin halving as the
// fallback (see ddmin.go for the halving itself, eliminate.go for the on-device
// predicate).
//
// The two strategies trade against each other on a strongly asymmetric cost. A
// probe that does *not* reproduce returns in-process and costs one executor run
// (sub-second to a few seconds). A probe that *does* reproduce panics the kernel
// and costs a full reboot plus relaunch (minutes). So the metric to minimize is
// the number of *crashing* probes, not the number of probes.
//
// Standard ddmin is built for cheap symmetric predicates and ignores this: nearly
// every reduction step it takes is a crashing probe, so narrowing n connections
// down costs several reboots. Enumerating subsets by increasing size instead
// crashes exactly once — on the answer — because every probe before it is clean.
// It also returns a *minimum-cardinality* culprit, which is strictly stronger
// than ddmin's 1-minimality: a 1-minimal set of 4 can coexist with a true culprit
// of 2, and ddmin will happily return the 4.
//
// Enumeration is only affordable while k stays small: it costs sum(C(n,i), i<=k)
// probes. maxK caps that, and once exceeded the search falls back to halving,
// which is where ddmin's exponential narrowing earns its keep. Every clean result
// found by enumeration stays in the memo, so the fallback inherits it for free.

package main

import (
	"math/big"
)

// combinations calls fn for every mask with exactly k of the low n bits set, in
// lexicographic order of the chosen indices, stopping early if fn returns true
// (which combinations then also returns).
//
// The order is fixed and must stay that way: after a panic-reboot the search is
// re-run from the checkpoint and has to replay the identical probe sequence to
// land back where it left off.
func combinations(n, k int, fn func(uint64) bool) bool {
	if k < 1 || k > n {
		return false
	}
	idx := make([]int, k)
	for i := range idx {
		idx[i] = i
	}
	for {
		var mask uint64
		for _, i := range idx {
			mask |= uint64(1) << uint(i)
		}
		if fn(mask) {
			return true
		}
		// Advance to the next combination: find the rightmost index that can be
		// incremented, bump it, and repack everything after it.
		i := k - 1
		for i >= 0 && idx[i] == n-k+i {
			i--
		}
		if i < 0 {
			return false
		}
		idx[i]++
		for j := i + 1; j < k; j++ {
			idx[j] = idx[j-1] + 1
		}
	}
}

// projectedProbes is how many probes the enumeration phase runs if it never
// finds a culprit, i.e. its worst case. Logged before the search starts so the
// cost is visible up front rather than discovered halfway through.
func projectedProbes(n, maxK int) int {
	total := 0
	for k := 1; k <= minInt(maxK, n-1); k++ {
		total += int(new(big.Int).Binomial(int64(n), int64(k)).Int64())
	}
	return total
}

// searchCulprit returns a crashing subset of the n connections, minimal in the
// sense described above. pred(mask) reports whether that subset reproduces; the
// full configuration is assumed to reproduce and is never probed.
//
// Sizes 1..maxK are enumerated first, so a culprit found there is of minimum
// cardinality. If none is found and every proper subset has been covered
// (maxK >= n-1), the full set is the answer by elimination. Otherwise the search
// hands off to ddmin.
func searchCulprit(n, maxK int, pred func(uint64) bool) uint64 {
	full := fullMask(n)
	limit := minInt(maxK, n-1)
	for k := 1; k <= limit; k++ {
		var found uint64
		if combinations(n, k, func(mask uint64) bool {
			if !pred(mask) {
				return false
			}
			found = mask
			return true
		}) {
			return found
		}
	}
	if limit >= n-1 {
		// Every proper subset was probed and none reproduced, so the full
		// configuration is itself the minimum crashing one.
		return full
	}
	return ddminConns(n, pred)
}
