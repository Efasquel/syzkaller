// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

// One connection with two method calls between open and close:
//
//	0 open r0 | 1 call r0 | 2 call r0 | 3 close r0
//
// Call-minimization removes only the method calls (1, 2); the open and close
// stay put, so every extracted subset is still a valid, self-contained program.
func TestMethodCalls(t *testing.T) {
	tgt, err := prog.GetTarget("darwin", "amd64")
	if err != nil {
		t.Skipf("darwin target unavailable: %v", err)
	}
	src := `syz_IOServiceOpen(&AUTO='AppleSSE\x00', 0x0, &AUTO=<r0=>0x0)
syz_IOConnectCallMethod(r0, ` + cmArgs + `)
syz_IOConnectCallMethod(r0, ` + cmArgs + `)
syz_IOServiceClose(r0)
`
	p, err := tgt.Deserialize([]byte(src), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}

	methods := identifyMethodCalls(p)
	if !equalInts(methods, []int{1, 2}) {
		t.Fatalf("identifyMethodCalls = %v, want [1 2]", methods)
	}

	// Full mask keeps both methods: the original 4 calls.
	full := extractMethodCalls(p, methods, 0b11)
	if len(full.Calls) != 4 {
		t.Errorf("full mask kept %d calls, want 4", len(full.Calls))
	}
	// Keep only the first method (bit 0): open, one method, close.
	one := extractMethodCalls(p, methods, 0b01)
	if len(one.Calls) != 3 {
		t.Fatalf("mask 0b01 kept %d calls, want 3", len(one.Calls))
	}
	wantNames := []string{"syz_IOServiceOpen", "syz_IOConnectCallMethod", "syz_IOServiceClose"}
	for i, want := range wantNames {
		if one.Calls[i].Meta.Name != want {
			t.Errorf("call %d = %s, want %s", i, one.Calls[i].Meta.Name, want)
		}
	}
	// Drop both methods (mask 0): open + close only, still valid.
	none := extractMethodCalls(p, methods, 0)
	if len(none.Calls) != 2 {
		t.Fatalf("mask 0 kept %d calls, want 2 (open+close)", len(none.Calls))
	}
	if _, err := tgt.Deserialize(none.Serialize(), prog.NonStrict); err != nil {
		t.Errorf("open+close subset is invalid: %v", err)
	}
	// The original program must not be mutated by extraction.
	if len(p.Calls) != 4 {
		t.Errorf("original mutated: now %d calls", len(p.Calls))
	}
}

// TestMethodCallsOnlyMethods guards the invariant the stage depends on: opens
// and closes are never in the removable set, so no extracted subset can drop
// them, whatever the mask.
func TestMethodCallsOnlyMethods(t *testing.T) {
	tgt, err := prog.GetTarget("darwin", "amd64")
	if err != nil {
		t.Skipf("darwin target unavailable: %v", err)
	}
	src := `syz_IOServiceOpen(&AUTO='AppleSSE\x00', 0x0, &AUTO=<r0=>0x0)
syz_IOConnectCallMethod(r0, ` + cmArgs + `)
syz_IOServiceClose(r0)
syz_IOServiceOpen(&AUTO='AppleSSE\x00', 0x0, &AUTO=<r1=>0x0)
syz_IOConnectCallMethod(r1, ` + cmArgs + `)
`
	p, err := tgt.Deserialize([]byte(src), prog.NonStrict)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	methods := identifyMethodCalls(p)
	if !equalInts(methods, []int{1, 4}) {
		t.Fatalf("identifyMethodCalls = %v, want [1 4]", methods)
	}
	// Even with every method dropped, both opens and the close survive.
	sub := extractMethodCalls(p, methods, 0)
	opens, closes := 0, 0
	for _, c := range sub.Calls {
		switch {
		case isOpenCall(c.Meta.Name):
			opens++
		case isCloseCall(c.Meta.Name):
			closes++
		case isConnectCall(c.Meta.Name):
			t.Errorf("a method call survived mask 0: %s", c.Meta.Name)
		}
	}
	if opens != 2 || closes != 1 {
		t.Errorf("kept %d opens / %d closes, want 2 / 1", opens, closes)
	}
}

// TestDdStateLegacyNConns checks a checkpoint written before the NConns->NUnits
// rename (only "n_conns", no "kind") still loads instead of being discarded —
// the user's in-flight crash must survive the upgrade.
func TestDdStateLegacyNConns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conn_state.json")
	legacy := `{"n_conns":5,"prog_hash":"h","memo":{"1":true},"attempting":""}`
	if err := os.WriteFile(path, []byte(legacy), 0644); err != nil {
		t.Fatal(err)
	}
	s := loadDdState(path, 5, "h", kindConnection)
	if s.NUnits != 5 {
		t.Errorf("legacy n_conns not migrated: NUnits=%d", s.NUnits)
	}
	if !s.Memo["1"] {
		t.Errorf("legacy memo dropped: %v", s.Memo)
	}
	if s.Kind != kindConnection {
		t.Errorf("Kind not stamped on load: %q", s.Kind)
	}
	// Re-saving must write n_units and not resurrect n_conns.
	if err := saveDdState(path, s); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !contains(string(data), `"n_units"`) || contains(string(data), `"n_conns"`) {
		t.Errorf("re-saved file has wrong field names:\n%s", data)
	}
}

// TestDdStateKindClash checks a checkpoint from one stage is not reused by the
// other even on the same program (same hash), so call masks never get read as
// connection masks or vice versa.
func TestDdStateKindClash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := saveDdState(path, &ddState{
		Kind: kindConnection, NUnits: 4, ProgHash: "h",
		Memo: map[string]bool{"3": true},
	}); err != nil {
		t.Fatal(err)
	}
	// Same program+size, but the call stage must not inherit connection results.
	if s := loadDdState(path, 4, "h", kindCall); len(s.Memo) != 0 || s.Kind != kindCall {
		t.Errorf("call stage reused connection checkpoint: memo=%v kind=%q", s.Memo, s.Kind)
	}
	// emit (kind="") accepts whatever the file records.
	if s := loadDdState(path, 4, "h", ""); !s.Memo["3"] || s.Kind != kindConnection {
		t.Errorf("emit did not accept recorded kind: memo=%v kind=%q", s.Memo, s.Kind)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestFinalStatePersisted checks the terminal-state save: after a verification
// crash is recovered on the next boot, the on-disk checkpoint must show the
// confirmed culprit (verified_crash set, verifying cleared), not a dangling
// pending verification. Models what minimize does around verifyCulprit.
func TestFinalStatePersisted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "call_state.json")
	// A prior run checkpointed "verifying 1" and then crashed (verified).
	if err := saveDdState(path, &ddState{
		Kind: kindCall, NUnits: 1, ProgHash: "h",
		Memo: map[string]bool{}, Verifying: "1",
	}); err != nil {
		t.Fatal(err)
	}
	// Next boot: load recovers verifying->verified_crash in memory...
	state := loadDdState(path, 1, "h", kindCall)
	if state.VerifiedCrash != "1" || state.Verifying != "" {
		t.Fatalf("recovery in memory wrong: verified=%q verifying=%q", state.VerifiedCrash, state.Verifying)
	}
	// ...and minimize persists that terminal state (the fix).
	if err := saveDdState(path, state); err != nil {
		t.Fatal(err)
	}
	// Re-read from disk: no dangling verification, culprit confirmed.
	on := readDdState(path)
	if on.Verifying != "" {
		t.Errorf("on-disk checkpoint still shows a pending verification: %q", on.Verifying)
	}
	if on.VerifiedCrash != "1" {
		t.Errorf("on-disk checkpoint lost the verified culprit: %q", on.VerifiedCrash)
	}
}
