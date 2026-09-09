// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// -emit-json: translate a minimized culprit into the list of syscall names to
// disable, as JSON. This is an offline projection of what minimization already
// decided — every IOConnectCallMethod that survives in the culprit is
// load-bearing for the crash — into a form syz-manager's disable_syscalls can
// consume. It runs nothing on device (like -emit-culprit).
//
// It lists *names* only. disable_syscalls matches syscall names, never argument
// values, so a per-selector variant (e.g. ...$AppleJPEGDriverUserClient_5, whose
// selector is baked into the name) is disabled exactly, while the generic
// variant (...$AppleJPEGDriver, whose selector is a fuzzable argument) can only
// be disabled *wholesale* — every selector at once. We emit its name anyway and
// warn, rather than pretend to target one selector value: single-selector
// suppression of a generic call would need an executor-side guard, which is
// deliberately out of scope.
//
// Opens/closes are never listed: they carry no selector, and disabling
// IOServiceOpen would disable the whole driver.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
)

// disableList is the emitted document: the culprit's distinct connect-call names
// to disable, plus enough provenance to apply them to the right target's config.
type disableList struct {
	Culprit  string   `json:"culprit"`
	OS       string   `json:"os"`
	Arch     string   `json:"arch"`
	Syscalls []string `json:"syscalls"`
}

// freeDispatchArg reports whether a connect call's dispatch argument (arg 1 --
// a method's selector or a trap's index) is a fuzzable value rather than a
// grammar-fixed const. Disabling such a call by name removes every selector or
// index it can reach, so the caller warns. A call we cannot read is treated as
// free (warn rather than over-promise).
func freeDispatchArg(c *prog.Call) bool {
	if len(c.Args) < 2 {
		return true
	}
	ca, ok := c.Args[1].(*prog.ConstArg)
	if !ok {
		return true
	}
	_, isConst := ca.Type().(*prog.ConstType)
	return !isConst
}

// emitSyscalls returns the culprit's distinct connect-call names -- external
// methods and traps alike (in first-seen order) -- and one warning per generic
// call whose disable is wholesale.
func emitSyscalls(p *prog.Prog) (names, warnings []string) {
	seen := make(map[string]bool)
	for _, c := range p.Calls {
		if !isConnectCall(c.Meta.Name) || seen[c.Meta.Name] {
			continue
		}
		seen[c.Meta.Name] = true
		names = append(names, c.Meta.Name)
		if freeDispatchArg(c) {
			what, plural := "selector", "selectors"
			if isTrapCall(c.Meta.Name) {
				what, plural = "trap index", "trap indices"
			}
			warnings = append(warnings, fmt.Sprintf("%s has a fuzzable %s; disabling "+
				"it drops ALL its %s, not just the crashing one", c.Meta.Name, what, plural))
		}
	}
	return names, warnings
}

// maybeEmitJSON emits the disable list from a freshly written culprit when
// -emit-json is combined with a mode that produces one (a minimize stage or
// -emit-culprit), so a single command minimizes and translates. It is a no-op
// unless -emit-json is set, and must be called only after the culprit at
// culpritPath has been written.
func maybeEmitJSON(target *prog.Target, culpritPath string) error {
	if !*flagEmitJSON {
		return nil
	}
	return runEmitSyscalls(target, culpritPath)
}

// runEmitSyscalls reads the minimized culprit and writes its disable list as
// JSON. Output goes to -json-out, else syscalls.json alongside the program.
func runEmitSyscalls(target *prog.Target, progFile string) error {
	p, err := readProg(target, progFile)
	if err != nil {
		return err
	}
	names, warnings := emitSyscalls(p)
	if len(names) == 0 {
		return fmt.Errorf("no method or trap calls in %s: nothing to disable "+
			"(is this the minimized culprit?)", progFile)
	}
	for _, w := range warnings {
		log.Logf(0, "warning: %s", w)
	}

	doc := disableList{Culprit: progFile, OS: target.OS, Arch: target.Arch, Syscalls: names}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	out := *flagJSONOut
	if out == "" {
		out = filepath.Join(filepath.Dir(progFile), "syscalls.json")
	}
	if err := os.WriteFile(out, data, 0644); err != nil {
		return fmt.Errorf("write disable list: %w", err)
	}
	if err := syncDir(filepath.Dir(out)); err != nil {
		return fmt.Errorf("sync disable-list dir: %w", err)
	}

	log.Logf(0, "Wrote %d syscall name(s) to disable to %s:", len(names), out)
	for _, n := range names {
		log.Logf(0, "  disable_syscalls += %s", n)
	}
	return nil
}
