#!/usr/bin/env python3
"""Crash-aware quarantine scheduler for a syzkaller/macOS fuzzing campaign.

See .notes/quarantine-design.md for the full design. In brief: a device that
reboots on every kernel crash must not keep re-hitting known crashes, but must
also never permanently shrink the search space to "everything that ever crashed".

This module is the pure decision core (one JSON state file per manager config);
the fuzz-campaign.py coordinator owns all device I/O (apply config, reboot,
minimize, replay) and calls the functions here at each decision point.

Model (single fixed BKC per campaign, so no probing -- a known crash never stops
crashing until you rebuild, which you don't do mid-campaign):

  - Every new crash starts SUSPECT: recorded but NOT suppressed; the campaign
    resumes with it enabled. It is acted on only when its signature recurs in the
    same config (occurrence_count >= CONFIRM). Nothing is benched on a one-off.
  - On confirmation, classify from the minimized sequence by (distinct selectors
    D, call count N):
      HARD        (D==1, N==1): the selector alone crashes  -> permanent disable.
      REPETITION  (D==1, N>1):  single-selector state buildup -> TOLERATE (stay
                                enabled), escalate to disable only if it recurs
                                TOLERATE_BUDGET times (cost outweighs coverage).
      SOFT        (D>1):        multi-selector sequence -> a rotation group; keep
                                exactly one member disabled (crash can't fire),
                                rotate which one so each keeps most of its coverage.
  - disabled_set = HARD (+escalated) selectors, seeded into a greedy minimal cover
    of the SOFT groups (a group already covered by a HARD selector, or by a shared
    selector another group disabled, contributes nothing).
  - Tolerated crashes are still catalogued (dedup, escalation, and reporting).
  - A crash that fires while we believed it suppressed is an ESCAPE: a new trigger
    path for the same signature -> classify and fold it in (a sig may own several
    groups). No pinning.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import timefmt  # noqa: E402


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
RINGREPRO_BIN = Path(os.environ.get(
    "SYZ_RINGREPRO", REPO_ROOT / "bin/darwin_arm64/syz-ring-repro"))

# Categories / dispositions.
HARD, REPETITION, SOFT, SUSPECT = "HARD", "REPETITION", "SOFT", "SUSPECT"
DISABLED, TOLERATED, ROTATING, SUSPECTED = "disabled", "tolerated", "rotating", "suspect"

# Tunable defaults (persisted per state under "params"; see design §14).
DEFAULT_PARAMS = {
    "confirm": 2,          # occurrences in the same config before we act
    "tolerate_budget": 4,  # tolerated REPETITION reboots before escalating to disable
    "stall_threshold": 20000,    # execs-without-new-coverage that triggers a rotation
    "rotate_cap": 200000,        # absolute execs-per-rotation safety cap
}


def now_iso():
    return timefmt.now_iso()


# --- state io ---------------------------------------------------------------
def init_state(config=None):
    return {
        "config": config,
        "epoch": 0,
        "last_rotation_exec": 0,
        "hard": [],          # permanently disabled selectors (HARD + escalated REP)
        "soft_groups": [],   # [{id, members[], cursor, crash_id, created}]
        "catalog": {},       # {sig: record}
        "params": dict(DEFAULT_PARAMS),
        "_next_group_id": 1,
    }


def load_state(path):
    try:
        with open(path) as f:
            s = json.load(f)
    except (OSError, ValueError):
        return init_state()
    base = init_state()
    for k, v in base.items():
        s.setdefault(k, v)
    for k, v in DEFAULT_PARAMS.items():   # backfill new params
        s["params"].setdefault(k, v)
    return s


def save_state(path, state):
    """Atomic write (temp + rename) so a crash mid-write cannot corrupt the ledger."""
    state["epoch"] = state.get("epoch", 0) + 1
    tmp = "%s.tmp" % path
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _p(state, key):
    return state.get("params", {}).get(key, DEFAULT_PARAMS[key])


# --- pure helpers -----------------------------------------------------------
def distinct_selectors(seq):
    """Sorted distinct selector names in a minimized sequence."""
    return sorted(set(seq))


def max_repeat(seq):
    """Largest number of times any single selector appears (intra-program depth)."""
    return max(Counter(seq).values()) if seq else 0


def classify(dn, n):
    """Category from (distinct selector count, total call count)."""
    if dn <= 1:
        return HARD if n <= 1 else REPETITION
    return SOFT


def disabled_set(state):
    """The selectors to disable right now: the HARD set, seeded into a greedy
    minimal cover of the SOFT groups. Seeding with HARD means a group already
    broken by a permanently-disabled selector (or a rotated member that later
    became HARD) adds nothing. Deterministic given the state."""
    disabled = set(state["hard"])
    for g in state["soft_groups"]:
        members = g["members"]
        if disabled.isdisjoint(members):
            disabled.add(members[g["cursor"] % len(members)])
    return sorted(disabled)


# --- mutations --------------------------------------------------------------
def _add_hard(state, selectors):
    state["hard"] = sorted(set(state["hard"]) | set(selectors))


def add_soft_group(state, members, sig, now):
    """Append a SOFT rotation group, unless one with the same member set exists."""
    members = sorted(set(members))
    for g in state["soft_groups"]:
        if sorted(g["members"]) == members:
            return g
    g = {"id": state["_next_group_id"], "members": members, "cursor": 0,
         "crash_id": sig, "created": now}
    state["_next_group_id"] += 1
    state["soft_groups"].append(g)
    return g


def escalate_repetition(state, rec, now):
    """A tolerated REPETITION crash has cost too many reboots: disable its selector."""
    _add_hard(state, rec["culprit_selectors"][:1])
    rec["category"] = REPETITION
    rec["disposition"] = DISABLED


def add_path(state, rec, distinct, now):
    """Fold an additional trigger path for an existing crash sig (an escape) into
    suppression: a multi-selector path becomes another SOFT group; a single-selector
    path is disabled outright. greedy_cover then covers all of a sig's paths."""
    if len(distinct) > 1:
        add_soft_group(state, distinct, rec["crash_id"], now)
    else:
        _add_hard(state, distinct)
    # Record the path as well as acting on it. culprit_selectors keeps the FIRST
    # minimized sequence and is deliberately not overwritten, so without this the
    # record reads "sel=[A] esc=1" and there is no way to learn that B is the
    # selector that escaped -- exactly what a disclosure needs to say a bug is
    # reachable by more than one method.
    paths = rec.setdefault("escape_paths", [])
    if distinct and not any(p["selectors"] == list(distinct) for p in paths):
        paths.append({"selectors": list(distinct), "at": now})


# --- the core decision tree -------------------------------------------------
def on_crash(state, sig, seq=None, now=None):
    """Record a crash and update quarantine per the design.

    `seq` is the minimized sequence of selector calls. It may be omitted (None)
    for a cheap SUSPECT sighting: a NEW crash is recorded without a sequence and
    the campaign resumes enabled -- the expensive minimize is deferred until the
    crash recurs (§3). The coordinator MUST provide `seq` on the occurrence that
    confirms a suspect or handles an escape (classification needs it); it may omit
    it for a tolerated recurrence (escalation uses the stored culprit).

    Returns {"decision", "category", "disposition", "disabled"} for logging.
    """
    now = now or now_iso()
    have = seq is not None
    distinct = distinct_selectors(seq) if have else []
    dn, n = len(distinct), (len(seq) if have else 0)

    rec = state["catalog"].get(sig)
    if rec is None:
        rec = {
            "crash_id": sig,
            "culprit_selectors": distinct,
            "minimized_sequence": (list(seq) if have else None),
            "category": SUSPECT,
            "disposition": SUSPECTED,
            "occurrence_count": 0,
            "repetition_count": (max_repeat(seq) if have else 0),
            "escaped_count": 0,
            "first_seen": now,
            "last_seen": now,
            "discovery_context": disabled_set(state),
        }
        state["catalog"][sig] = rec
    elif have and not rec.get("minimized_sequence"):
        # First real sequence for a record that was created seq-less (SUSPECT).
        rec["minimized_sequence"] = list(seq)
        rec["culprit_selectors"] = distinct
        rec["repetition_count"] = max_repeat(seq)
    rec["occurrence_count"] += 1
    rec["last_seen"] = now
    disp = rec["disposition"]

    # (1) A crash we believed suppressed fired anyway -> a NEW trigger path.
    if disp in (DISABLED, ROTATING):
        rec["escaped_count"] += 1
        add_path(state, rec, distinct, now)
        decision = "escape"
    # (2) Tolerated REPETITION fired again -> escalate once it costs too much.
    elif disp == TOLERATED:
        if rec["occurrence_count"] >= _p(state, "tolerate_budget"):
            escalate_repetition(state, rec, now)
            decision = "escalated"
        else:
            decision = "tolerated"
    # (3) Still SUSPECT: do not act until confirmed IN THIS CONFIG.
    elif rec["occurrence_count"] < _p(state, "confirm"):
        rec["disposition"] = SUSPECTED
        decision = "suspect"
    # (4) Confirmed -> classify and act.
    else:
        cat = classify(dn, n)
        rec["category"] = cat
        if cat == HARD:
            _add_hard(state, distinct)
            rec["disposition"] = DISABLED
        elif cat == SOFT:
            add_soft_group(state, distinct, sig, now)
            rec["disposition"] = ROTATING
        else:  # REPETITION
            rec["disposition"] = TOLERATED
            if rec["occurrence_count"] >= _p(state, "tolerate_budget"):
                escalate_repetition(state, rec, now)
        decision = "confirmed"

    return {"decision": decision, "category": rec["category"],
            "disposition": rec["disposition"], "disabled": disabled_set(state)}


# --- rotation ---------------------------------------------------------------
def maybe_rotate(state, exec_total, execs_since_cov):
    """Advance every SOFT group's disabled member if a rotation is due: PRIMARY on
    coverage stall (execs since the last new coverage >= stall_threshold), SECONDARY
    on the absolute rotate_cap. Returns True if the disabled set changed (the
    coordinator must then re-apply the config and resume).

    `exec_total` is the CURRENT run's exec count. syz-manager resets it to 0 on
    every (re)start, and a rotation restarts the run, so it doubles as "execs since
    the last rotation" -- no cross-run delta bookkeeping needed.
    """
    if not state["soft_groups"]:
        return False
    due = (execs_since_cov >= _p(state, "stall_threshold")
           or exec_total >= _p(state, "rotate_cap"))
    if not due:
        return False
    for g in state["soft_groups"]:
        g["cursor"] = (g["cursor"] + 1) % len(g["members"])
    state["last_rotation_exec"] = exec_total   # kept for observability only
    return True


# --- culprit -> sequence ----------------------------------------------------
# The one grammar-dependent step: turning a minimized .syz reproducer into the
# selector sequence classify() needs. Offline (no device), but it shells out to
# syz-ring-repro because only the Go side knows the descriptions. Deriving the
# sequence from the file is also the only way to get it *right*: selector names
# contain '$', so hand-typing them into --seq invites the shell to eat the
# variant suffix.
def ringrepro_cmd():
    """argv prefix for syz-ring-repro: the built binary, else a dev `go run`."""
    if RINGREPRO_BIN.exists():
        return [str(RINGREPRO_BIN)]
    return ["go", "run", "./tools/syz-ring-repro"]


def emit_syscalls(culprit, out=None, log=None):
    """The distinct syscall names a minimized culprit needs, via -emit-json.

    Writes syscalls.json next to the culprit unless `out` is given. Raises
    RuntimeError if the tool fails or writes no readable list.
    """
    culprit = Path(culprit)
    if not culprit.exists():
        raise RuntimeError("culprit not found: %s" % culprit)
    out = Path(out) if out else culprit.parent / "syscalls.json"
    cmd = ringrepro_cmd() + ["-emit-json", "-json-out", str(out), str(culprit)]
    if log:
        log("$ %s" % " ".join(cmd))
    rc = subprocess.run(cmd, cwd=str(REPO_ROOT)).returncode
    if rc != 0:
        raise RuntimeError("syz-ring-repro -emit-json exited %d on %s" % (rc, culprit))
    try:
        with open(out) as f:
            doc = json.load(f)
    except (OSError, ValueError):
        doc = None
    if not doc or "syscalls" not in doc:
        raise RuntimeError("no readable syscall list at %s" % out)
    return doc["syscalls"]


def count_calls(text, name):
    """How many times `name` is called in a serialized program.

    Line-anchored and paren-terminated so a return-value binding (`r0 = name(`)
    counts and a longer selector that merely starts with `name` (..._1 vs ..._10)
    does not.
    """
    pat = re.compile(r"^\s*(?:r\d+\s*=\s*)?%s\(" % re.escape(name))
    return sum(1 for line in text.splitlines() if pat.match(line))


def culprit_sequence(culprit, log=None):
    """A minimized culprit as the selector sequence classify() consumes.

    -emit-json gives the distinct connect-call selectors (grammar-accurate). For a
    single-selector culprit we expand to N entries by counting its calls in the
    program text, so HARD (one call) and REPETITION (many calls) are told apart.
    With D>1 the count is irrelevant -- it is SOFT either way.
    """
    names = emit_syscalls(culprit, log=log)
    if len(names) != 1:
        return list(names)
    sel = names[0]
    try:
        n = count_calls(Path(culprit).read_text(errors="replace"), sel)
    except OSError:
        n = 1
    return [sel] * max(n, 1)


# --- cli --------------------------------------------------------------------
def _load(args):
    return load_state(args.state)


def cmd_init(args):
    s = init_state(config=args.config)
    save_state(args.state, s)
    print("initialized %s (config=%s)" % (args.state, args.config))


def _config_path(args, state):
    """The manager config this state governs: --config override, else the one
    recorded at init time."""
    return getattr(args, "config", None) or state.get("config")


def read_config(path):
    with open(path) as f:
        return json.load(f)


def write_disable_syscalls(cfg_path, want):
    """Set the config's disable_syscalls to exactly `want` (atomic). Returns True
    if the file changed.

    Exact, not incremental: a selector that rotated back in must also come *out*
    of the config, so the config always mirrors the scheduler.
    """
    c = read_config(cfg_path)
    if list(c.get("disable_syscalls", [])) == list(want):
        return False
    if want:
        c["disable_syscalls"] = list(want)
    else:
        c.pop("disable_syscalls", None)
    tmp = "%s.tmp" % cfg_path
    with open(tmp, "w") as f:
        json.dump(c, f, indent=4)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, cfg_path)
    return True


def known_selectors(cfg_path):
    """The config's enable_syscalls, or None when it has no explicit list (then
    every name is plausible and we cannot validate)."""
    try:
        c = read_config(cfg_path)
    except (OSError, ValueError, TypeError):
        return None
    names = c.get("enable_syscalls")
    return set(names) if names else None


def check_seq(seq, cfg_path):
    """Reject selector names the config never enables.

    This exists for one specific footgun: selector names contain a '$', so
    --seq "syz_IOConnectCallMethod$Foo_5" in double quotes lets the shell expand
    $Foo_5 to nothing and silently quarantines the bare generic name. Use single
    quotes. Returns a list of unknown names.
    """
    known = known_selectors(cfg_path)
    if known is None:
        return []
    return [n for n in seq if n not in known]


def cmd_apply(args):
    s = _load(args)
    want = disabled_set(s)
    for k in want:
        print(k)
    cfg = _config_path(args, s)
    if args.print_only:
        return
    if not cfg:
        sys.exit("no config recorded in %s; pass --config, or --print to only "
                 "list the set" % args.state)
    try:
        changed = write_disable_syscalls(cfg, want)
    except (OSError, ValueError) as e:
        sys.exit("cannot update %s: %s" % (cfg, e))
    print("%s disable_syscalls (%d) in %s"
          % ("wrote" if changed else "already current:", len(want), cfg))
    if changed:
        print("restart the session for it to take effect "
              "(scripts/fuzz-session.py resume ...)")


def cmd_crash(args):
    s = _load(args)
    if args.culprit:
        try:
            seq = culprit_sequence(args.culprit, log=lambda m: print(m, file=sys.stderr))
        except RuntimeError as e:
            sys.exit(str(e))
        print("culprit %s -> %s" % (args.culprit, ",".join(seq)), file=sys.stderr)
    else:
        seq = [x for x in (args.seq.split(",") if args.seq else []) if x]
    unknown = check_seq(seq, _config_path(args, s))
    if unknown:
        sys.exit("--seq names not in the config's enable_syscalls: %s\n"
                 "selector names contain '$' -- quote them with SINGLE quotes, "
                 "e.g. --seq 'syz_IOConnectCallMethod$Driver_5'" % ", ".join(unknown))
    res = on_crash(s, args.sig, seq)
    save_state(args.state, s)
    print("%-9s %s [%s] disabled=%s" % (
        res["decision"], args.sig, res["category"], res["disabled"]))


def cmd_rotate(args):
    s = _load(args)
    changed = maybe_rotate(s, args.exec_total, args.since_cov)
    if changed:
        save_state(args.state, s)
    print("%s  disabled=%s" % ("rotated" if changed else "no rotation",
                               disabled_set(s)))


def cmd_status(args):
    s = _load(args)
    print("config=%s epoch=%d last_rotation_exec=%d"
          % (s["config"], s["epoch"], s["last_rotation_exec"]))
    print("disabled now: %s" % disabled_set(s))
    if s["hard"]:
        print("hard: %s" % s["hard"])
    for g in s["soft_groups"]:
        cur = g["members"][g["cursor"] % len(g["members"])]
        print("soft group %d (crash %s): %s  disabled->%s"
              % (g["id"], g["crash_id"], g["members"], cur))
    if s["catalog"]:
        print("catalog:")
        for sig, c in s["catalog"].items():
            print("  %s %-10s %-9s occ=%d rep=%d esc=%d culprit=%s"
                  % (sig, c["category"], c["disposition"], c["occurrence_count"],
                     c["repetition_count"], c["escaped_count"], c["culprit_selectors"]))


def cmd_replay_list(args):
    """Print each catalogued crash's minimized sequence (end-of-campaign replay)."""
    s = _load(args)
    for sig, c in s["catalog"].items():
        print("%s\t%s" % (sig, ",".join(c["minimized_sequence"])))


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state", required=True, help="per-config quarantine state JSON")
    sub = ap.add_subparsers(dest="cmd")

    pi = sub.add_parser("init", help="create a fresh state")
    pi.add_argument("--config", help="manager config this state governs")
    pi.set_defaults(func=cmd_init)

    pa = sub.add_parser("apply", help="write the disabled set into the manager config")
    pa.add_argument("--config", help="config to write (default: the one from init)")
    pa.add_argument("--print", dest="print_only", action="store_true",
                    help="only list the set, do not touch the config")
    pa.set_defaults(func=cmd_apply)
    sub.add_parser("status", help="print scheduler state").set_defaults(func=cmd_status)
    sub.add_parser("replay-list", help="print each crash's minimized sequence").set_defaults(func=cmd_replay_list)

    pc = sub.add_parser("crash", help="record a crash (sig + minimized sequence)")
    pc.add_argument("--sig", required=True)
    src = pc.add_mutually_exclusive_group()
    src.add_argument("--culprit", help="minimized .syz reproducer; the sequence is "
                                       "derived from it (preferred over --seq)")
    src.add_argument("--seq", help="minimized sequence, comma-separated selector names "
                                   "(use SINGLE quotes: names contain '$')")
    pc.add_argument("--config", help="config to validate --seq against "
                                     "(default: the one from init)")
    pc.set_defaults(func=cmd_crash)

    pr = sub.add_parser("rotate", help="rotate SOFT groups if due")
    pr.add_argument("--exec-total", type=int, required=True, dest="exec_total")
    pr.add_argument("--since-cov", type=int, required=True, dest="since_cov",
                    help="executed test cases since the last new coverage")
    pr.set_defaults(func=cmd_rotate)

    args = ap.parse_args()
    if not getattr(args, "func", None):
        ap.print_help()
        sys.exit(2)
    args.func(args)


if __name__ == "__main__":
    main()
