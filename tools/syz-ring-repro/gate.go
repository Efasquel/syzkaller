// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Crash gating: decide whether a reboot recorded during minimization actually
// reproduced the TARGET crash, rather than tripping a different bug (or a
// non-panic reboot). The minimizer's signal is reboot-as-crash — a subset that
// panics the box is recovered as a repro on the next boot. Without a gate, ANY
// reboot counts, so a second bug that fires during a probe is misattributed to
// that subset and the search minimizes toward the wrong thing.
//
// Signature computation lives in crash_fingerprint.py, so the gate shells out to
// a caller-provided command (the -confirm_cmd flag), appending the target
// signature and the epoch the subset started running. The command inspects the
// panic reports produced since that epoch and prints a verdict: a line starting
// with "other" means a DIFFERENT crash's report appeared; anything else
// ("match", "none", or an outright error) is treated as the target crash. That
// bias is deliberate — a genuine repro whose report we could not read or
// fingerprint must never be dropped, only a positively-identified different bug
// is filtered out.

package main

import (
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/log"
)

// bootEpoch is when this machine last booted, or 0 if it cannot be determined.
//
// The minimizer's crash signal is indirect: a subset that panics the box kills
// this process, and the pending checkpoint is recovered as a repro on the next
// boot. But a process can die WITHOUT the box going down -- an operator
// restarting the launchd agent, a SIGKILL, an OOM. Those recover as a crash too,
// which invents a culprit; and because the memo is checkpointed, the wrong answer
// is permanent. Comparing the boot time against when the attempt started tells
// the two apart. Darwin-only (kern.boottime); elsewhere this returns 0 and
// callers fall back to the old, more permissive behaviour.
func bootEpoch() float64 {
	out, err := exec.Command("sysctl", "-n", "kern.boottime").Output()
	if err != nil {
		return 0
	}
	i := strings.Index(string(out), "sec = ")
	if i < 0 {
		return 0
	}
	rest := string(out)[i+len("sec = "):]
	end := strings.IndexFunc(rest, func(r rune) bool { return r < '0' || r > '9' })
	if end <= 0 {
		return 0
	}
	v, err := strconv.ParseFloat(rest[:end], 64)
	if err != nil {
		return 0
	}
	return v
}

// rebootedSince reports whether the box actually rebooted after `at`. A false
// answer means the process died for some other reason, so a pending attempt must
// NOT be counted as a reproduction.
func rebootedSince(at float64) bool {
	b := bootEpoch()
	if b <= 0 || at <= 0 {
		return true // cannot tell: keep the permissive behaviour
	}
	return b >= at
}

// gateNow is the epoch stamped as a subset starts running, i.e. the "since" a
// crash gate scopes its panic-report scan to. Whole seconds are enough — reports
// land seconds after the reboot — and the Python side applies a small grace
// window for clock skew.
func gateNow() float64 {
	return float64(time.Now().Unix())
}

// crashGate is optional: a nil gate (or one missing its target or command)
// treats every reboot as the target crash, i.e. the original behavior.
type crashGate struct {
	targetSig  string
	confirmCmd []string // argv, split from the -confirm_cmd flag
}

type gateVerdict int

const (
	gateCrash gateVerdict = iota // count the reboot as the target crash
	gateOther                    // a different bug rebooted; not the target
)

// verdict classifies the reboot for a subset that started running at sinceEpoch.
// A nil gate, an unset target, a missing command, or a missing timestamp all
// fall back to gateCrash (so pre-gating checkpoints and ungated runs behave as
// before).
func (g *crashGate) verdict(sinceEpoch float64) gateVerdict {
	if g == nil || g.targetSig == "" || len(g.confirmCmd) == 0 || sinceEpoch <= 0 {
		return gateCrash
	}
	args := append(append([]string{}, g.confirmCmd[1:]...),
		g.targetSig, strconv.FormatFloat(sinceEpoch, 'f', 3, 64))
	out, err := exec.Command(g.confirmCmd[0], args...).Output()
	if err != nil {
		log.Logf(0, "crash-gate: confirm command %v failed (%v); counting the reboot as a crash",
			g.confirmCmd, err)
		return gateCrash
	}
	fields := strings.Fields(string(out))
	if len(fields) > 0 && fields[0] == "other" {
		return gateOther
	}
	return gateCrash
}
