// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package targets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGnuCPPPicksNewestVersionedGpp(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"g++-9", "g++-15", "g++-13", "g++-x"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	// Not executable: must be skipped even though it is the highest version.
	if err := os.WriteFile(filepath.Join(dir, "g++-99"), nil, 0644); err != nil {
		t.Fatal(err)
	}
	if got := gnuCPP("g++-does-not-exist-11", dir); got != "g++-15" {
		t.Fatalf("gnuCPP = %q, want g++-15", got)
	}
}

func TestGnuCPPKeepsWantWhenNothingFound(t *testing.T) {
	if got := gnuCPP("g++-does-not-exist-11", t.TempDir()); got != "g++-does-not-exist-11" {
		t.Fatalf("gnuCPP = %q, want the requested name back", got)
	}
}
