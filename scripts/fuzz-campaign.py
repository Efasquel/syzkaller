#!/usr/bin/env python3
"""fuzz-campaign.py -- autonomous, crash-safe driver over fuzz-session.py.

A campaign is an ordered list of configs, each fuzzed for a wall-clock budget.
The driver runs one config to its budget, then advances to the next; on a crash
or hang it collects a reproduction bundle and *restarts the same config* (corpus
and ring buffer intact), so the budget keeps accumulating toward the next bug.

It drives fuzz-session.py as a subprocess and never imports it: the session
script stays the single source of truth, and a driver crash cannot corrupt
session state. Two recovery paths, because a kernel panic reboots the box and
kills the driver:

  * live supervision -- while the driver is up it polls `exec total`; frozen
    with the manager alive is a hang, a dead manager with panic evidence is a
    crash.
  * boot reconciliation -- launchd RunAtLoad restarts the driver after a
    panic-reboot; it finds the in-flight run ended uncollected and, from
    panic_evidence, records the crash before resuming.

A circuit breaker halts the campaign on a crash-storm or low disk (a kernel
core is ~220MB), and cores are pruned to the newest few after each collect.

Commands:
  new <name> <config...> [--budget-hours H] [--loop] ...   author a campaign
  run <name>                     the supervision loop (what launchd invokes)
  status <name>                  campaign runtime state
  list                           all campaigns
  halt <name> / resume <name>    manual stop/continue
  install <name> / uninstall <name>   generate + (un)load the launchd plist
"""
import argparse
import atexit
import fcntl
import signal
import getpass
import json
import os
import pwd
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
SESSION = SCRIPT_DIR / "fuzz-session.py"
TRIAGE = SCRIPT_DIR / "triage.py"
RESULTS = SCRIPT_DIR / "fuzz-results.py"
BUG_REGISTRY = SCRIPT_DIR / "bug_registry.py"
CAMPAIGN_DIR = REPO_ROOT / "campaigns"
STATE_DIR = CAMPAIGN_DIR / ".state"
# The reportable bug inventory (bug_registry dossiers + registry.json). It is
# deliberately NOT under a session's workdir: bug_registry dedups by bug_key
# ("<driver>:<method>:<fault-class>"), and the same bug is re-found by every
# config of that driver, by later campaigns, and after every rebuild. Per-workdir
# storage would restart the counter each time and mint a fresh BUG-000N id for a
# bug already filed -- destroying the dedup that is the point of the tool. (The
# manual campaign's BUG-0001..0004 span seven separate sessions.) Session-scoped
# evidence -- panic bundles, ring buffers, culprits -- does live in the workdir;
# the dossiers cite it by path.
BUGS_DIR = CAMPAIGN_DIR / "bugs"

sys.path.insert(0, str(SCRIPT_DIR))
import crash_fingerprint as cf  # noqa: E402
import quarantine as qm  # noqa: E402
import triage as tri  # noqa: E402  (job outcome constants only; runs as a subprocess)
from lib import bootinfo  # noqa: E402
from lib import cfgutil  # noqa: E402
from lib import timefmt  # noqa: E402
from lib.tablefmt import render, tabulate  # noqa: E402

# `syz-ring-repro -emit-json` translates a minimized culprit into the list of
# IOConnectCallMethod syscall names to disable (JSON). Prefer the built binary;
# fall back to `go run` so the step works in a dev tree with no bin/.
RINGREPRO_BIN = Path(os.environ.get("SYZ_RINGREPRO", REPO_ROOT / "bin/darwin_arm64/syz-ring-repro"))

# Where kernel cores/panics land. These MUST match fuzz-session.py and triage.py
# (same two dirs, same two env overrides), or the driver fingerprints a different
# set of reports than the session that produced them. DiagnosticReports holds the
# *.panic/*.ips; /private/var/tmp/kernel_panics holds the *.kernel.core.gz -- the
# ~220MB space hogs prune_cores reclaims.
PANIC_DIRS = [
    Path(os.environ.get("SYZ_PANIC_DIR", "/Library/Logs/DiagnosticReports")),
    Path(os.environ.get("SYZ_KERNEL_PANIC_DIR", "/private/var/tmp/kernel_panics")),
]
CORE_GLOBS = ("*.kernel.core.gz", "*.kernel.core.log")

DEFAULTS = {
    "budget_hours": 6.0,
    "loop": False,
    "poll_seconds": 600,        # how often to check exec total (10 min)
    "hang_after_seconds": 1800,  # frozen this long with manager alive => hang
    # Incidents (crash + hang) on ONE config before that config is abandoned and
    # the campaign moves to the next. It used to count the whole campaign and
    # halt it, so a crash-heavy first config starved every config after it.
    "max_crashes": 20,
    "min_free_gb": 20.0,        # halt if root disk drops below this
    "keep_cores": 3,            # cores retained after pruning
    # The crash-loop breaker exists to catch a PATHOLOGICAL loop -- a config that
    # cannot fuzz at all (manager dies on startup, corpus poisoned so the very
    # first program re-panics) -- not productive fuzzing. On this target a healthy
    # run panics the box every 30-110s, so the old 120s/5 pairing halted a working
    # campaign within ten minutes of its first real bug.
    #
    # "Never fuzzed anything" is measured as programs executed, not seconds. A
    # time window was tried: both of its ends come from the manager's stat line,
    # written every 10s, so the error (up to 20s) was as large as the window, and
    # a healthy run with a quick real bug read as "fast". At 40-50 execs/s, five
    # seconds of real fuzzing is far past 200; a poisoned corpus panics at 0-30.
    # The count can be up to 10s stale, which only ever undercounts.
    "crashloop_min_execs": 200,   # a crash before this many programs is "fast"
    "crashloop_limit": 15,      # this many consecutive such crashes => halt
    # A manager that dies before executing a single program, with no panic --
    # a held port, a bad config, a missing binary. Not a crash and not a hang:
    # it used to be filed as a "hang" one poll (10 min) later and retried
    # forever; one campaign did that 19 times. Watched closely until the first
    # exec, halted after this many in a row.
    "startup_fail_limit": 3,
    "startup_poll_seconds": 15,     # poll this often until the first exec
    "startup_retry_seconds": 30,    # pause before retrying a failed start
    "triage_max_boots": 40,     # give up (halt) if triage can't reach a culprit in this many advances
    # Pause before re-running a triage advance that returned without finishing.
    # A probe that reproduces reboots the box, so an advance only returns early
    # on an error; this is a breather, not a wait for anything. It used to be
    # poll_seconds (10 min), uninterruptible, and on no clock at all.
    "triage_retry_seconds": 30,
    # Which clock --budget measures.
    #   "wall"  -- everything the campaign occupied the rig for: preparation
    #              PLUS fuzzing PLUS minimization PLUS reboot overhead. "Give this config 24
    #              hours of machine time", which is what a comparison between
    #              configurations needs, and the default for that reason.
    #   "real"  -- elapsed time since the config started, counting EVERYTHING:
    #              halts, reboots, the machine being off. The only clock that
    #              answers "start at 2pm, stop at 4pm", because it is the only
    #              one that keeps running while the campaign is not. Survives the
    #              panic-reboots: the start stamp is persisted, not re-taken on
    #              relaunch, so a crash does not restart the window.
    #   "fuzz"  -- from each run's first executed program to its end, so neither
    #              startup nor a long triage eats the budget. Still not pure
    #              execution time: the manager also re-triages its corpus and
    #              waits on RPC. For that figure use `runstats.py show`, which
    #              reads syz-manager's own counter.
    # wall >= fuzz always, so this default can only end a campaign sooner.
    "budget_clock": "wall",
    # Cap on the launchd-captured log. One real campaign produced 7.0MB across
    # 119,299 lines, of which 33,267 were per-probe minimizer chatter -- the
    # coordinator's own decisions were unreadable inside it, and `tail -f` on the
    # combined stream was useless exactly when it mattered.
    "max_log_mb": 25.0,
    # How often to look for a stop request. Cheap (one stat of a local file), so
    # it is decoupled from poll_seconds, which is expensive (an HTTP round trip
    # to the manager) and therefore rare.
    "stop_check_seconds": 5,
    # One `syz-executor exec` process per program, so a healthy one lives
    # milliseconds. Alive this long means a syscall that never returned -- a
    # direct hang signal, rather than waiting hang_after_seconds to infer one
    # from a stalled counter. Generous, so a legitimately slow program is safe.
    "exec_stuck_seconds": 600,
    # A gap between the driver's last save and the next boot is reboot overhead.
    # Capped, because an unbounded gap is not overhead -- it is the rig sitting
    # idle while you were asleep, and charging that would make the wall clock a
    # measure of your schedule rather than the campaign's.
    "max_boot_gap_seconds": 900.0,
    # Of that gap, the part after the boot is login-to-relaunch, which launchd
    # keeps to a minute or two. Longer means nobody relaunched the driver (a
    # manual start days later), which is idle, not overhead.
    "max_relaunch_seconds": 300.0,
    # Clone of the results repo (fuzz-results.py). Unset: no results commits.
    # Set: a commit before every session (re)start -- before the manager
    # re-triages corpus.db and drops what no longer reproduces -- one per poll
    # when the corpus or coverage moved, one per incident, and one at the end.
    "results_repo": None,
}

BUDGET_CLOCKS = ("fuzz", "wall", "real")


# --- small utilities ---------------------------------------------------------
def now_iso():
    """Stored form: local time with its offset (2026-09-01T14:56:39+02:00).

    Was UTC-with-Z, which read two hours off your wall clock in Paris summer
    time and disagreed with the local stamps used for directory names."""
    return timefmt.now_iso()


# The driver's own decisions, separated from the subprocess output launchd
# captures. Everything log() writes goes to BOTH: stdout (interleaved with
# syz-ring-repro's per-probe chatter, useful for forensics) and this file (the
# coordinator's narrative alone, which is what you actually want to `tail -f`).
_coord_log = None


def open_coord_log(name):
    """Start mirroring log() into <name>.coordinator.log. Best effort."""
    global _coord_log
    path = STATE_DIR / ("%s.coordinator.log" % name)
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        rotate_log(path, DEFAULTS["max_log_mb"], own_fd=True)
        _coord_log = open(path, "a")
        atexit.register(_close_coord_log)
    except OSError:
        _coord_log = None
    return path


def _close_coord_log():
    global _coord_log
    if _coord_log is not None:
        try:
            _coord_log.close()
        except OSError:
            pass
        _coord_log = None


def rotate_log(path, max_mb, own_fd=False):
    """Keep a log under max_mb.

    own_fd=True: we are the only writer, so rename to .1 (one generation kept).
    own_fd=False: launchd holds the descriptor and renaming would leave it
    appending to the rotated file forever, so truncate in place instead -- with
    O_APPEND the next write lands at the new EOF.
    """
    try:
        if not path.exists() or path.stat().st_size <= max_mb * 1024 * 1024:
            return False
        if own_fd:
            path.replace(Path(str(path) + ".1"))
        else:
            os.truncate(str(path), 0)
        return True
    except OSError:
        return False


def log(msg):
    """Timestamped line to stdout -- launchd captures it to the campaign log."""
    line = "%s  %s\n" % (timefmt.stamp(), msg)
    sys.stdout.write(line)
    sys.stdout.flush()
    if _coord_log is not None:
        try:
            _coord_log.write(line)
            _coord_log.flush()
        except OSError:
            pass


# --- the brake ---------------------------------------------------------------
# A file whose existence stops the campaign. It exists because every other stop
# needs something to be working: `halt` needs a shell, the crash-loop breaker
# needs the driver to be running, and neither survives a box that panics its way
# through login. The brake is checked before anything else the driver does, and
# it is a FILE so it can be set from macOS Recovery -- boot ⌘R, open Terminal,
# and touch it on the mounted Data volume. Names are deliberately short and
# uppercase: you may be typing this at 3am on a rescue keyboard.
GLOBAL_BRAKE = REPO_ROOT / "STOP"


def brake_paths(name):
    """(global, per-campaign) brake file paths."""
    return GLOBAL_BRAKE, STATE_DIR / ("%s.brake" % name)


def brake_held(name):
    """(path, reason) if a brake is set, else None. Any content is the reason,
    so `echo "boot loop 03:12" > STOP` leaves a note from your past self."""
    for p in brake_paths(name):
        try:
            if p.exists():
                try:
                    why = p.read_text().strip()[:500]
                except OSError:
                    why = ""
                return str(p), why
        except OSError:
            continue
    return None


def recovery_hint():
    """The brake path as it appears from macOS Recovery, where the Data volume is
    mounted under /Volumes/<name> - Data rather than at /."""
    vol = "Macintosh HD"
    try:
        out = subprocess.run(["diskutil", "info", "/"], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True, timeout=10).stdout
        m = re.search(r"Volume Name:\s*(.+)", out or "")
        if m:
            vol = m.group(1).strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return '/Volumes/%s - Data%s' % (vol, GLOBAL_BRAKE)


def wall_seconds(s):
    """Total time this campaign has been the rig's occupant: preparing each run,
    fuzzing, plus the minimization it took to explain a crash, plus the reboots
    those crashes cost. Excludes time halted or idle -- nothing accrues while no
    driver runs."""
    return (s.get("prep_seconds", 0.0) + s.get("active_seconds", 0.0)
            + s.get("triage_seconds", 0.0) + s.get("overhead_seconds", 0.0))


def real_seconds(s):
    """Elapsed time since the current config started, by the wall clock on the
    wall -- not the campaign's occupancy of the rig.

    Unlike wall_seconds this keeps running while the campaign does not: through a
    halt, a panic-reboot, a crashloop pause, the box being powered off. That is
    the point. It is the only clock that can express a window ("2pm to 4pm"),
    because a window elapses whether or not anything is fuzzing.

    Reads config_started_at, which is stamped once when a config starts and NOT
    re-taken when the coordinator relaunches. That matters here more than
    anywhere: this rig reboots on every panic, so a stamp refreshed on relaunch
    would restart the window at each crash and the budget would never expire.
    """
    t0 = timefmt.to_epoch(s.get("config_started_at"))
    if not t0:
        return 0.0
    return max(0.0, time.time() - t0)


def budget_spent(s, d):
    """The clock --budget is measured against (see DEFAULTS["budget_clock"])."""
    clock = d.get("budget_clock")
    if clock == "real":
        return real_seconds(s)
    return wall_seconds(s) if clock == "wall" else s.get("active_seconds", 0.0)


def fmt_hms(sec):
    sec = int(max(0.0, sec or 0.0))
    return "%dh%02dm" % (sec // 3600, (sec % 3600) // 60)


# The per-config clocks above are a BUDGET, so they reset when a config's budget
# is spent and the campaign advances. The lifetime totals below never reset, so
# "how long did this campaign run?" survives every advance and every wrap. Losing
# that is why a finished 2h run reported active_seconds 0.0.
LIFETIME_CLOCKS = {"prep_seconds": "total_prep_seconds",
                   "active_seconds": "total_active_seconds",
                   "triage_seconds": "total_triage_seconds",
                   "overhead_seconds": "total_overhead_seconds"}


def roll_budget_clocks(s):
    """Bank the current config's clocks into the lifetime totals, then zero them
    for the next config. Call this instead of assigning active_seconds = 0."""
    for cur, tot in LIFETIME_CLOCKS.items():
        s[tot] = s.get(tot, 0.0) + s.get(cur, 0.0)
        s[cur] = 0.0
    s["run_active_base"] = 0.0
    s["run_prep_base"] = 0.0
    s["run_prep_started"] = None
    # The "real" clock's origin is per-config too: dropping it here makes the
    # next config stamp a fresh one when it starts.
    s["config_started_at"] = None


def lifetime(s, key):
    """A clock's campaign-lifetime value: banked totals plus the current config."""
    return s.get(LIFETIME_CLOCKS[key], 0.0) + s.get(key, 0.0)


def lifetime_wall(s):
    return sum(lifetime(s, k) for k in LIFETIME_CLOCKS)


def boot_epoch():
    return bootinfo.boot_epoch()


# --- per-run accounting ------------------------------------------------------
# A run has two stretches. Preparation: the coordinator snapshots the inputs and
# commits results, the manager compiles the grammar and waits for the executor.
# Fuzzing: from the first executed program to the end of the run. They are
# prep_seconds and active_seconds, recomputed from the run's own timestamps
# rather than incremented, so a late or repeated poll cannot skew them;
# run_prep_base / run_active_base hold what earlier runs of this config banked.
#
# The end of a run is its last sign of life, not the moment we noticed. This
# target reboots on every panic, so nearly every crash is noticed on the NEXT
# boot; measuring to then charged the reboot as fuzzing -- and charged it twice,
# since reconcile_gap also counted it as overhead. One campaign was charged
# 68h41m of fuzzing for a box that sat powered off over a weekend.
RUN_ALIVE = "alive"


def run_end_epoch(info, now=None):
    """When a run that is no longer alive ended: its last sign of life (the run
    log's newest line, the cover log's mtime). Never later than the boot that
    followed it, never earlier than its start."""
    now = time.time() if now is None else now
    started = info.get("run_started_epoch")
    end = info.get("last_activity_epoch") or started or now
    boot = info.get("boot_epoch") or boot_epoch()
    if boot and started and boot > started:
        end = min(end, boot)
    end = min(end, now)
    if started:
        end = max(end, started)
    return end


def account_run(s, info, end):
    """Set this config's prep/active clocks for the open run, up to `end`.
    Returns how long the manager lived (end minus its start), or None."""
    started = info.get("run_started_epoch")
    prep_from = s.get("run_prep_started") or started or end
    fuzz_from = info.get("fuzz_started_epoch")
    if fuzz_from is not None and fuzz_from <= end:
        prep = max(0.0, fuzz_from - prep_from)
        active = max(0.0, end - max(fuzz_from, prep_from))
    else:                                   # never executed a program
        prep, active = max(0.0, end - prep_from), 0.0
    s["prep_seconds"] = s.get("run_prep_base", 0.0) + prep
    s["active_seconds"] = s.get("run_active_base", 0.0) + active
    return (end - started) if started else None


def close_run(s, info, end):
    """Account the open run up to `end` and bank it. A no-op when no run is
    open, so every exit path can call it without counting a run twice."""
    if not s.get("run_prep_started"):
        return None
    ran = account_run(s, info, end)
    s["run_prep_base"] = s["prep_seconds"]
    s["run_active_base"] = s["active_seconds"]
    s["run_prep_started"] = None
    # Which run was banked, and up to when: a manager that outlives the close
    # (any halt path that fails to stop it) is re-attached from here, not from
    # its own start, or its time would be counted twice.
    s["run_closed"] = {"started": info.get("run_started_epoch"), "end": end}
    return ran


def die(msg):
    sys.stderr.write("error: %s\n" % msg)
    sys.exit(1)


def read_json(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_json(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2)
    os.replace(tmp, path)


def def_path(name):
    return CAMPAIGN_DIR / ("%s.json" % name)


def state_path(name):
    return STATE_DIR / ("%s.json" % name)


def config_id(cfg):
    """Session id fuzz-session.py derives from a config path (its stem)."""
    return Path(cfg).stem


# --- driving fuzz-session.py -------------------------------------------------
def session(*args, capture=False):
    """Run fuzz-session.py <args>. capture=True returns (rc, stdout)."""
    cmd = [sys.executable, str(SESSION)] + [str(a) for a in args]
    if capture:
        p = subprocess.run(cmd, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True)
        return p.returncode, p.stdout
    log("$ fuzz-session %s" % " ".join(str(a) for a in args))
    return subprocess.run(cmd).returncode, ""


def inspect(sid):
    """fuzz-session.py inspect <sid> as a dict ({found:False} on any failure)."""
    rc, out = session("inspect", sid, capture=True)
    if rc != 0:
        return {"found": False}
    try:
        return json.loads(out)
    except ValueError:
        return {"found": False}


# --- campaign definition + state ---------------------------------------------
def load_def(name):
    d = read_json(def_path(name))
    if d is None:
        die("no campaign %r (looked in %s)" % (name, def_path(name)))
    merged = dict(DEFAULTS)
    merged.update(d)
    # Normalise configs to [{config, budget_seconds}] with per-item override.
    items = []
    for c in merged["configs"]:
        if isinstance(c, str):
            cfg, hours = c, merged["budget_hours"]
        else:
            cfg, hours = c["config"], c.get("budget_hours", merged["budget_hours"])
        cfg_abs = cfg if os.path.isabs(cfg) else str(REPO_ROOT / cfg)
        if not Path(cfg_abs).exists():
            die("campaign %r references missing config: %s" % (name, cfg_abs))
        items.append({"config": cfg_abs, "budget_seconds": float(hours) * 3600})
    merged["items"] = items
    merged["name"] = name
    return merged


def init_state(name):
    return {
        "name": name, "status": "running", "cursor": 0,
        # Four disjoint clocks; wall_seconds() is their sum. Keeping them apart
        # is what lets a writeup say "24h fuzzing, 31h wall, of which 4h
        # minimization" instead of picking one number and hiding the rest.
        "prep_seconds": 0.0,        # snapshot, grammar compile, up to the first exec
        "active_seconds": 0.0,      # first exec -> end of the run
        "triage_seconds": 0.0,      # minimizing a culprit (not fuzzing)
        "overhead_seconds": 0.0,    # observed panic-reboot gaps
        "session_id": None, "current_config": None,
        "run_started": None, "last_exec_total": None,
        "crashes": 0, "hangs": 0, "consec_fast_crashes": 0,
        # Per-config counters, reset when the campaign moves to the next config.
        "config_incidents": 0, "startup_failures": 0,
        "abandoned": [],            # configs max_crashes gave up on
        "incidents": [], "started_at": now_iso(), "updated_at": now_iso(),
        "halt_reason": None,
        # coordinator: fuzzing <-> triaging. On a new crash the campaign hands
        # the box to triage, benches the culprit, then resumes fuzzing.
        "phase": "fuzzing", "triage_job": None, "triage_bug_sig": None,
        "triage_boots": 0, "triage_seq": 0, "suppressed_sigs": [],
        "exhausted_sigs": [],
        # Second bugs a triage job surfaced, waiting for a job of their own, and
        # per-job bookkeeping (panics routed, bugs announced / queued).
        "triage_queue": [], "triage_seen": {},
        # Start the watermark at the newest report that already exists, so the
        # campaign's first crash fingerprints one fresh panic instead of replaying
        # every historical report in the dir (they are ~2MB each).
        "panic_sig_watermark": _newest_report_mtime(),
    }


def _is_dir(p):
    """is_dir() that answers False instead of raising.

    pathlib only swallows "not there" errors (ENOENT/ENOTDIR/...); EACCES
    propagates. doctor probes paths that belong to other users by design, so
    every probe here has to be permission-proof.
    """
    try:
        return Path(p).is_dir()
    except OSError:
        return False


def _exists(p):
    try:
        return Path(p).exists()
    except OSError:
        return False


def _has_any(dpath, globs):
    """Does dpath contain at least one entry matching any of `globs`?

    NOT `any(dpath.glob(g) for g in globs)` -- glob returns a generator, which is
    truthy whether or not it yields anything, so that form answers True for an
    empty directory.
    """
    for g in globs:
        try:
            if next(iter(Path(dpath).glob(g)), None) is not None:
                return True
        except OSError:
            continue
    return False


# Delimited by NON-hex bytes, not by newlines: in a Go binary the -ldflags -X
# string sits between NULs, so line anchors never match.
_REV_RE = re.compile(rb"[^0-9a-f]([0-9a-f]{40}\+?)[^0-9a-f]")


def _binary_revision(path):
    """The git revision the Makefile stamped into a Go binary, or None."""
    try:
        blob = Path(path).read_bytes()
    except OSError:
        return None
    hits = {m.group(1).decode() for m in _REV_RE.finditer(blob)}
    # Other 40-hex strings can occur; the dirty marker is what a locally built
    # tree stamps, so prefer it and only fall back when there is exactly one.
    dirty = sorted(h for h in hits if h.endswith("+"))
    return dirty[0] if dirty else (sorted(hits)[0] if len(hits) == 1 else None)


def _newest_report_mtime():
    newest = 0.0
    for dpath in PANIC_DIRS:
        if not dpath.is_dir():
            continue
        for g in PANIC_REPORT_GLOBS:
            for p in dpath.glob(g):
                try:
                    newest = max(newest, p.stat().st_mtime)
                except OSError:
                    pass
    return newest


# Fields added after a campaign's first run; backfill so old state files load.
COORDINATOR_DEFAULTS = {
    "phase": "fuzzing", "triage_job": None, "triage_bug_sig": None,
    "triage_boots": 0, "triage_seq": 0, "suppressed_sigs": [],
        "exhausted_sigs": [],
    "panic_sig_watermark": 0.0,
    # Clocks added after the first campaigns ran; absent in their state files.
    "triage_seconds": 0.0, "overhead_seconds": 0.0,
    "total_active_seconds": 0.0, "total_triage_seconds": 0.0,
    "total_overhead_seconds": 0.0,
    "prep_seconds": 0.0, "total_prep_seconds": 0.0,
    "config_incidents": 0, "startup_failures": 0, "abandoned": [],
    "triage_queue": [], "triage_seen": {},
}


def load_state(name):
    s = read_json(state_path(name))
    return s if s else init_state(name)


def save_state(s):
    s["updated_at"] = now_iso()
    write_json(state_path(s["name"]), s)


# --- circuit breaker + core pruning ------------------------------------------
def free_gb():
    return shutil.disk_usage(str(REPO_ROOT)).free / 1e9


def breaker(s, d):
    """Reason to halt the campaign, or None. Config-level limits are in
    config_breaker: they move on to the next config instead."""
    fg = free_gb()
    if fg < d["min_free_gb"]:
        return "low disk (%.1fGB free < %.1fGB)" % (fg, d["min_free_gb"])
    if s["consec_fast_crashes"] >= d["crashloop_limit"]:
        return ("crash loop (%d crashes in a row before %d programs executed)"
                % (s["consec_fast_crashes"], d["crashloop_min_execs"]))
    limit = d.get("startup_fail_limit", DEFAULTS["startup_fail_limit"])
    if s.get("startup_failures", 0) >= limit:
        return ("syz-manager failed to start %d times in a row (died before "
                "executing anything); last log line: %s"
                % (s["startup_failures"], s.get("last_startup_error") or "?"))
    return None


def config_breaker(s, d):
    """Reason to abandon the current config and move on, or None."""
    n = s.get("config_incidents", 0)
    if n >= d["max_crashes"]:
        return "reached max_crashes (%d incidents on this config)" % n
    return None


def reset_config_counters(s):
    """Zero what is counted per config. Lifetime totals are left alone."""
    s["config_incidents"] = 0
    s["consec_fast_crashes"] = 0
    s["startup_failures"] = 0


def advance_config(s):
    """Leave the current config: bank its clocks, reset its counters."""
    s["cursor"] += 1
    s["results_started"] = False
    roll_budget_clocks(s)
    s["session_id"] = None
    s["last_exec_total"] = None
    reset_config_counters(s)
    # A queued second bug belongs to the config it crashed in. Its program stays
    # in the triage job that found it, and the quarantine already has it as
    # SUSPECT, so a recurrence later still gets it triaged.
    for item in s.get("triage_queue") or []:
        log("dropping queued triage of %s (config advanced); its program is %s"
            % (item["sig"], item["program"]))
    s["triage_queue"] = []


def run_log_tail(info):
    """The last meaningful line of the run's manager log ('' if none) -- for a
    manager that died at startup, that is the reason."""
    p = info.get("run_log")
    try:
        lines = [ln.strip() for ln in Path(p).read_text(errors="replace").splitlines()
                 if ln.strip()] if p else []
    except OSError:
        return ""
    fatal = [ln for ln in lines if "FATAL" in ln or "SYZFAIL" in ln]
    return (fatal or lines or [""])[-1][:300]


def prune_cores(keep):
    """Keep only the newest <keep> kernel cores; delete the rest to reclaim disk.

    Run only after a collect has copied the relevant core into its bundle, so
    the original is redundant. Skips silently if not permitted (dev, non-root).
    """
    found = []
    for d in PANIC_DIRS:
        if not d.is_dir():
            continue
        for g in CORE_GLOBS:
            for p in d.glob(g):
                if p.name.startswith("."):
                    continue
                try:
                    found.append((p.stat().st_mtime, p))
                except OSError:
                    pass
    found.sort(reverse=True)   # newest first
    for _, p in found[keep:]:
        try:
            p.unlink()
            log("pruned core %s" % p)
        except OSError as e:
            log("could not prune %s: %s" % (p, e))


# --- incident handling -------------------------------------------------------
def record_incident(s, d, kind, info, end=None):
    """Update counters and the crash-loop tracker for one crash/hang, and close
    the run's clocks at `end` (default: its last sign of life)."""
    if end is None:
        end = run_end_epoch(info)
    started = info.get("run_started_epoch")
    ran_for = close_run(s, info, end)
    if ran_for is None and started:
        ran_for = max(0.0, end - started)
    # "Fast" means the run executed almost nothing before the panic (see
    # crashloop_min_execs): independent of how long startup took, and of the
    # 10s granularity of the stat line. No stat line at all reads as zero.
    fuzz_from = info.get("fuzz_started_epoch")
    fuzzed = max(0.0, end - fuzz_from) if fuzz_from and fuzz_from <= end else 0.0
    execs = info.get("exec_total") or 0
    fast = kind == "crash" and execs < d["crashloop_min_execs"]
    s["consec_fast_crashes"] = s["consec_fast_crashes"] + 1 if fast else 0
    if fuzz_from:
        s["startup_failures"] = 0          # this run did start
    s["config_incidents"] = s.get("config_incidents", 0) + 1
    if kind == "crash":
        s["crashes"] += 1
    else:
        s["hangs"] += 1
    target = fuzzed_target(s["current_config"])
    s["incidents"].append({
        "config": s["current_config"], "kind": kind, "at": now_iso(),
        "fuzzed_kext": target["kext"], "kext_id": target["kext_id"],
        "ran_seconds": round(ran_for) if ran_for else None,
        "fuzzed_seconds": round(fuzzed),
        "exec_total": info.get("exec_total"),
        "panic_evidence": info.get("panic_evidence"),
    })
    log("incident: %s on %s after %ss (exec_total=%s, panics=%s)"
        % (kind, config_id(s["current_config"]),
           round(ran_for) if ran_for else "?", info.get("exec_total"),
           info.get("panic_evidence")))


def collect_and_prune(s, d, kind):
    session("collect", s["session_id"], kind)
    prune_cores(d["keep_cores"])
    results_commit(s, d, kind, detach=True)


def results_commit(s, d, event, cfg=None, detach=False):
    """Record the current config's results in the results repo (fuzz-results.py).

    Best effort by construction: a results failure is logged and fuzzing goes
    on. detach=True returns at once (polls and incidents must not stall the
    loop); the synchronous calls are the (re)start, which must capture corpus.db
    before the manager re-triages it, and the end, after which nothing runs."""
    repo = (d or {}).get("results_repo")
    cfg = cfg or s.get("current_config")
    if not repo or not cfg:
        return
    prefix = s["name"] if len(d["items"]) <= 1 else "%s/%s" % (s["name"], config_id(cfg))
    cmd = [sys.executable, str(RESULTS), "--repo", repo, "commit", cfg,
           "--event", event, "--campaign", s["name"], "--tag-prefix", prefix,
           "--campaign-def", str(def_path(s["name"])),
           "--wall-seconds", str(round(lifetime_wall(s))),
           "--push", "detach" if event in ("restart", "corpus", "crash", "hang") else "wait"]
    if event in ("start", "restart"):
        cmd.append("--no-freq")         # fast path: the manager is waiting on us
    out = open(STATE_DIR / ("%s.results.log" % s["name"]), "a")
    try:
        if detach:
            subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=out,
                             stderr=subprocess.STDOUT, start_new_session=True)
        else:
            rc = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=out,
                                stderr=subprocess.STDOUT, timeout=600).returncode
            if rc != 0:
                log("results commit (%s) failed; see %s" % (event, out.name))
    except (OSError, subprocess.SubprocessError) as e:
        log("results commit (%s) failed: %s" % (event, e))
    finally:
        out.close()


# --- coordinator: crash -> triage -> bench -> resume -------------------------
# The campaign is a two-phase machine. In "fuzzing" it runs the config to budget
# as before. On a crash whose signature it has NOT already benched, it flips to
# "triaging": it hands the box to triage.py (itself a reboot-resumable driver),
# and on each boot advances it toward a minimal culprit. When triage reaches
# DONE, the campaign benches the culprit's syscall(s) via -emit-json + exclude,
# records the signature so it never re-triages the same bug, and resumes fuzzing.
# Both phases survive the reboot-on-every-crash target: the one campaign launchd
# agent relaunches cmd_run, which re-enters whichever phase the state file holds.
PANIC_REPORT_GLOBS = ("*.panic", "*.ips", "*.kernel.core.log")


def triage(*args, capture=False):
    """Run triage.py <args>. capture=True returns (rc, stdout)."""
    cmd = [sys.executable, str(TRIAGE)] + [str(a) for a in args]
    if capture:
        p = subprocess.run(cmd, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True)
        return p.returncode, p.stdout
    log("$ triage %s" % " ".join(str(a) for a in args))
    return subprocess.run(cmd).returncode, ""


def triage_state(job):
    """triage.py's state file for a job, or None."""
    return read_json(REPO_ROOT / "triage" / ".state" / ("%s.json" % job))


def _scan_reports(since_epoch):
    """Panic reports across PANIC_DIRS with mtime > since_epoch, oldest first."""
    found = {}
    for dpath in PANIC_DIRS:
        if not dpath.is_dir():
            continue
        for g in PANIC_REPORT_GLOBS:
            for p in dpath.glob(g):
                if p.name.startswith("."):
                    continue
                try:
                    t = p.stat().st_mtime
                except OSError:
                    continue
                if t > since_epoch:
                    found[p] = t
    return sorted(found, key=found.get)


def latest_panic_signature(s):
    """Fingerprint of the newest panic report since the last check, or None.

    Advances panic_sig_watermark so a report is fingerprinted once. Used to tell
    a new bug (worth triaging) from one already benched (just resume).
    """
    reports = _scan_reports(s.get("panic_sig_watermark", 0.0))
    sig = None
    for r in reports:
        try:
            fp = cf.fingerprint(str(r))
        except Exception as e:  # noqa: BLE001 - a bad report must not stall the campaign
            log("could not fingerprint %s: %s" % (r.name, e))
            continue
        sig = fp["signature"]
        # Kept for the incident and for status: the backtrace's crashing kext is
        # how a crash outside the fuzzed driver gets noticed.
        s["last_panic"] = {"signature": sig, "title": fp.get("title"),
                           "crashing_kext": fp.get("crashing_kext"), "report": r.name}
        try:
            s["panic_sig_watermark"] = max(s.get("panic_sig_watermark", 0.0),
                                           r.stat().st_mtime)
        except OSError:
            pass
    return sig


def fuzzed_target(cfg):
    """What a config fuzzes: its Pishi kext_id, the IOKit services it opens
    (from syz_IOServiceOpen$<Service>_<UserClient>) and its workdir's kext
    directory (workdir/<Kext>/<run>). The config names no kext, so this is the
    best there is to compare a backtrace's crashing kext against."""
    try:
        conf = cfgutil.load(cfg) if cfg else {}
    except (OSError, ValueError):
        conf = {}
    services = set()
    for name in conf.get("enable_syscalls") or []:
        if name.startswith("syz_IOServiceOpen$"):
            services.add(name.split("$", 1)[1].rsplit("_", 1)[0])
    workdir = conf.get("workdir")
    return {"kext_id": (conf.get("kext_coverage") or {}).get("kext_id"),
            "kext": Path(workdir).parent.name if workdir else None,
            "services": sorted(services)}


def kext_matches(target, crashing):
    """Whether a backtrace's crashing kext is the one being fuzzed: True, False,
    or None when there is nothing to compare (no kext, or the kernel itself)."""
    if not crashing or crashing == "kernel":
        return None
    names = [n for n in [target.get("kext")] + target.get("services", []) if n]
    if not names:
        return None
    c = crashing.lower()
    return any(c in n.lower() or n.lower() in c for n in names)


def config_triage_flags(cfg):
    """The config's own device settings, as triage flag values.

    Minimization has to run in the SAME environment the crash was found in, or it
    reduces a program that never reaches the driver. Two settings are per-config:

      kext_coverage.{kext_id,kcov_device} -- each driver has its own Pishi id.
      executor_name -- the process name the driver expects. Some IOKit drivers
        gate their user client on p_comm: IOBluetoothHCIControllerUserClient
        refuses every caller not named "bluetoothd" with kIOReturnUnsupported.
        Without it every IOServiceOpen fails, every later call is inert, and the
        search reports that nothing reproduces. That cost campaign drivers_260902
        25,461 probes across four jobs before it was noticed.

    Empty when the config has no such settings, so the campaign-level triage
    defaults still apply.
    """
    conf = read_json(cfg) if cfg else None
    kc = (conf or {}).get("kext_coverage") or {}
    out = {}
    if kc.get("kext_id") is not None:
        out["kext_id"] = kc["kext_id"]
    if kc.get("kcov_device"):
        out["kcov_device"] = kc["kcov_device"]
    name = ((conf or {}).get("executor_name") or "").strip()
    if name:
        out["executor_name"] = name
    return out


def begin_triage(s, d, sig, ring=None):
    """Pause fuzzing and stand up a triage job for a new bug. Returns True on
    success; on any failure the campaign just resumes fuzzing (no phase change).

    `ring` defaults to the session's ring buffer; a queued second bug brings its
    own (a one-slot ring holding the program that crashed with it)."""
    if ring is None:
        info = inspect(s["session_id"]) if s.get("session_id") else {"found": False}
        workdir = info.get("workdir")
        if not workdir:
            log("cannot triage %s: session workdir unknown; resuming fuzzing" % sig)
            return False
        ring = Path(workdir) / "ring_buffer"
    ring = Path(ring)
    if not ring.is_dir():
        log("cannot triage %s: no ring buffer at %s; resuming fuzzing" % (sig, ring))
        return False

    s["triage_seq"] += 1
    job = "%s_t%d" % (s["name"], s["triage_seq"])
    tri = dict(d.get("triage") or {})
    # The coverage device settings belong to the CONFIG, not the campaign: each
    # driver has its own Pishi kext id (a bitmask -- AppleJPEGDriver=1, AppleSSE=4,
    # IOSurface=128 ...), so a campaign spanning several drivers cannot carry one
    # id for all of them. Minimizing an IOSurface crash under AppleJPEGDriver's id
    # would configure coverage for the wrong kext. Take them from the config that
    # actually crashed and fall back to the campaign's block.
    # Fail closed. Triage inherits the crashing config's device settings; if that
    # config cannot be read we would silently fall back to the campaign defaults
    # and minimize in the wrong environment -- which produces a confident "nothing
    # reproduces" from a search that never reached the driver. Refuse instead.
    cfg_path = s.get("current_config")
    if cfg_path and read_json(cfg_path) is None:
        log("cannot triage %s: config %s is unreadable, so triage would run with "
            "unknown device settings (kext_id / executor_name); resuming fuzzing"
            % (sig, cfg_path))
        return False
    tri.update(config_triage_flags(cfg_path))
    # Pin the target signature so triage's crash gate is active from the first
    # subset (a second bug firing during minimization won't misdirect it).
    args = ["new", job, "--ring", str(ring), "--target-sig", sig, "--force",
            "--campaign", s["name"]]
    if cfg_path:
        args += ["--config", config_id(cfg_path)]
        kext = fuzzed_target(cfg_path).get("kext")
        if kext:
            args += ["--fuzzed-kext", kext]
    for flag, key in (("--executor", "executor"), ("--ringrepro", "ringrepro"),
                      ("--kcov-device", "kcov_device"), ("--kext-id", "kext_id"),
                      ("--sandbox", "sandbox"), ("--max-k", "max_k"),
                      ("--executor-name", "executor_name")):
        if tri.get(key) is not None:
            args += [flag, str(tri[key])]
    rc, out = triage(*args, capture=True)
    if rc != 0:
        log("triage new failed for %s (rc=%d): %s; resuming fuzzing"
            % (sig, rc, (out or "").strip()))
        return False
    s["phase"] = "triaging"
    s["triage_job"] = job
    s["triage_bug_sig"] = sig
    s["triage_boots"] = 0
    # Not necessarily new -- the quarantine only sends confirmed recurrences and
    # escapes here, so say what it is rather than implying a first sighting.
    log("triaging %s as job %s (fuzzing paused)" % (sig, job))
    return True


def _bench_culprit(s, culprit):
    """Bench the culprit's syscall(s) in the crashed config (exclude)."""
    cfg = Path(s["current_config"]) if s.get("current_config") else None
    if not cfg or not cfg.exists():
        log("no current config to bench culprit into; skipping")
        return
    try:
        names = emit_syscalls(culprit)
        added, already = exclude_syscalls(names, cfg)
    except RuntimeError as e:
        log("bench failed: %s" % e)
        return
    for n in added:
        log("benched in %s: %s" % (cfg.name, n))
    for n in already:
        log("already benched in %s: %s" % (cfg.name, n))


def bench_lead_program(s, cfg, key, program, why):
    """Bench `program`'s selectors under quarantine key `key` as an UNVERIFIED
    lead. Returns True if anything was benched."""
    try:
        seq = culprit_sequence(program)
    except RuntimeError as e:
        log("  cannot read selectors from %s (%s); nothing benched" % (program, e))
        return False
    qs = load_qstate(cfg)
    res = qm.bench_lead(qs, key, seq, program)
    if res is None:
        log("  %s names no selector; nothing benched" % program)
        return False
    save_qstate(cfg, qs)
    apply_disabled(cfg, qs)
    log("  benched UNVERIFIED lead for %s (%s): %s -> %s/%s; disabled=%s"
        % (key, why, program, res["category"], res["disposition"], res["disabled"]))
    return True


def bench_hang(s, job, cfg, program):
    """A triage job that kept hanging: bench the program that hung. It gets its
    own quarantine key -- a hang has no panic signature, and filing it under the
    crash being minimized would claim it reproduces that crash."""
    if not (cfg and program and Path(program).exists()):
        log("  hang culprit missing (%s); nothing benched" % program)
        return
    bench_lead_program(s, cfg, "hang:%s" % job, program, "hung %d times in triage"
                       % tri.MAX_HANGS)


def newest_ring_program(workdir, dst):
    """Copy the newest program in workdir's ring buffer to dst, without its id
    header. The program running when the box panicked, as far as the ring knows.
    Returns dst, or None."""
    best = None
    for p in (Path(workdir) / "ring_buffer").glob("slot_*.syz"):
        try:
            head, _, body = p.read_text().partition("\n")
            n = int(head[3:]) if head.startswith("id=") else None
        except (OSError, ValueError):
            continue
        if n is not None and (best is None or n > best[0]):
            best = (n, body)
    if best is None:
        return None
    dst = Path(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(best[1])
    return str(dst)


def exhausted_recurrence(s, sig, info):
    """An exhausted signature panicked the box again. Count it in the quarantine,
    and once it has recurred tolerate_budget times, bench the newest ring program
    as an UNVERIFIED lead -- otherwise nothing ever stops it rebooting the box."""
    cfg = s.get("current_config")
    if not cfg:
        return
    qs = load_qstate(cfg)
    n = qm.count_exhausted(qs, sig)
    save_qstate(cfg, qs)
    budget = qm._p(qs, "tolerate_budget")
    why = (s.get("exhausted_why") or {}).get(sig) or "no-repro"
    if not qm.lead_due(qs, n):
        log("crash %s: exhausted (%s), not re-triaged; recurrence %d of %d before a "
            "lead is benched" % (sig, why, n, budget))
        return
    lead = newest_ring_program(info.get("workdir") or "",
                               STATE_DIR / "leads" / ("%s_%s.syz" % (sig, timefmt.now_ts())))
    if not lead:
        log("crash %s: exhausted, %d recurrences, but no ring program to bench" % (sig, n))
        return
    log("crash %s: exhausted (%s) and recurred %d times; benching the newest ring "
        "program as a lead" % (sig, why, n))
    bench_lead_program(s, cfg, sig, lead, "newest ring program, recurrence %d" % n)


def triage_seen(s, job):
    """Per-job bookkeeping: panic reports routed, second bugs announced, and
    second bugs queued. Dropped when the job ends."""
    seen = s.setdefault("triage_seen", {}).setdefault(job, {})
    for k in ("routed", "others", "queued"):
        seen.setdefault(k, [])
    return seen


def route_triage_panics(s, st, job):
    """Catalog the panics a triage job produced, each once.

    A subset that reproduces the bug panics the box, and triage.py files that
    panic in the JOB's ledger -- nothing else routes it to the bug inventory.
    The target's panics are evidence the minimizer caused on purpose (origin
    triage, not a sighting). A DIFFERENT signature is a genuine find nobody was
    looking for (origin fuzz-during-triage): it is announced, and seeded in the
    quarantine. Routing used to repeat every incident on every advance.
    """
    seen = triage_seen(s, job)
    target = (st or {}).get("target_signature")
    for inc in (st or {}).get("incidents", []):
        rep = inc.get("report")
        if not rep or rep in seen["routed"]:
            continue
        seen["routed"].append(rep)       # a report that is gone will not come back
        sig = inc.get("signature")
        other = bool(sig and target and sig != target)
        for dpath in PANIC_DIRS:
            cand = dpath / rep
            if _exists(cand):
                route_bug_registry(str(cand), s.get("name"), s.get("current_config"),
                                   origin="fuzz-during-triage" if other else "triage")
                break
        if other:
            note_second_bug(s, job, inc)


def note_second_bug(s, job, inc):
    """Announce a second bug a triage job tripped over, and seed it SUSPECT."""
    seen = triage_seen(s, job)
    sig = inc["signature"]
    if sig in seen["others"]:
        return
    seen["others"].append(sig)
    log("SECOND BUG during triage %s: %s -- %s (crashing kext %s), not the target "
        "%s; filed as a genuine find" % (job, sig, inc.get("title") or "?",
                                         inc.get("kext") or "?", s.get("triage_bug_sig")))
    cfg = s.get("current_config")
    if not cfg:
        return
    qs = load_qstate(cfg)
    rec = qs["catalog"].get(sig)
    if rec is None:
        qm.on_crash(qs, sig, None)
        save_qstate(cfg, qs)
        log("  quarantine: %s seeded SUSPECT" % sig)
    else:
        log("  quarantine: %s already known (%s)" % (sig, rec.get("disposition")))


def why_not_triage(s, sig):
    """Why a second bug should NOT get a triage of its own, or None."""
    if sig == s.get("triage_bug_sig"):
        return "it is the bug being triaged"
    if sig in (s.get("exhausted_sigs") or []):
        return "it is exhausted"
    cfg = s.get("current_config")
    rec = load_qstate(cfg)["catalog"].get(sig) if cfg else None
    if rec and rec.get("disposition") not in (None, qm.SUSPECTED):
        return "the quarantine already handles it (%s)" % rec["disposition"]
    return None


def queue_second_bugs(s, st, job):
    """Queue a triage for each second bug whose crashing program triage saved."""
    seen = triage_seen(s, job)
    for sig, ob in sorted(((st or {}).get("other_bugs") or {}).items()):
        if sig in seen["queued"] or not Path(ob.get("program") or "").exists():
            continue
        seen["queued"].append(sig)
        why = why_not_triage(s, sig)
        if not why and any(q["sig"] == sig for q in s.get("triage_queue") or []):
            why = "it is already queued"
        if why:
            log("second bug %s: not queued for triage: %s" % (sig, why))
            continue
        s.setdefault("triage_queue", []).append(
            {"sig": sig, "program": ob["program"], "from_job": job,
             "config": s.get("current_config"), "at": now_iso()})
        log("second bug %s: queued for its own triage after %s (program %s)"
            % (sig, job, ob["program"]))


def start_queued_triage(s, d):
    """Start the next queued second-bug triage, if any is still worth it.
    Returns True when the campaign is triaging again."""
    while s.get("triage_queue"):
        item = s["triage_queue"].pop(0)
        sig = item["sig"]
        if item.get("config") != s.get("current_config"):
            log("dropping queued triage of %s: queued under another config" % sig)
            continue
        budget = d["items"][min(s["cursor"], len(d["items"]) - 1)]["budget_seconds"]
        if budget_spent(s, d) >= budget:
            log("dropping queued triage of %s: the budget is spent (program %s; it is "
                "SUSPECT, so a recurrence will still be triaged)" % (sig, item["program"]))
            continue
        why = why_not_triage(s, sig)
        if why:
            log("dropping queued triage of %s: %s" % (sig, why))
            continue
        ring = STATE_DIR / "queued" / ("%s_%s" % (sig, timefmt.now_ts())) / "ring_buffer"
        try:
            ring.mkdir(parents=True, exist_ok=True)
            (ring / "slot_0000.syz").write_text("id=0\n" + Path(item["program"]).read_text())
        except OSError as e:
            log("dropping queued triage of %s: cannot stage its program: %s" % (sig, e))
            continue
        log("starting the queued triage of second bug %s (found by %s)"
            % (sig, item["from_job"]))
        if begin_triage(s, d, sig, ring=ring):
            return True
    return False


def advance_triage(s, d):
    """One boot's worth of triage. On DONE: bench the culprit + resume fuzzing.
    Counts advances and halts the campaign if triage cannot reach a culprit."""
    job = s.get("triage_job")
    if not job:
        s["phase"] = "fuzzing"
        save_state(s)
        return
    # Count the advance BEFORE running triage: a crashing subset reboots the box
    # and kills us mid-run, and the launchd relaunch must not retry forever.
    s["triage_boots"] += 1
    advance_started = time.time()
    if s["triage_boots"] > d["triage_max_boots"]:
        s["status"] = "halted"
        s["halt_reason"] = ("triage stuck on %s after %d boots (job %s)"
                            % (s.get("triage_bug_sig"), s["triage_boots"], job))
        save_state(s)
        log("HALT: %s" % s["halt_reason"])
        return
    # Persisted so the next boot can split this advance at the panic it may end
    # in: up to the crashing probe is minimization, after it is the reboot.
    s["triage_advance_started"] = advance_started
    save_state(s)
    log("triage advance %d/%d for job %s"
        % (s["triage_boots"], d["triage_max_boots"], job))
    triage("run", job, "--reboot-on-hang")
    # Charge this advance to the triage clock. A crashing subset reboots the box
    # mid-run and we never get here -- reconcile_triage_gap does it next boot.
    s["triage_seconds"] = s.get("triage_seconds", 0.0) + (time.time() - advance_started)
    s["triage_advance_started"] = None
    save_state(s)     # or a driver death here re-charges the advance next boot

    st = triage_state(job)
    route_triage_panics(s, st, job)
    queue_second_bugs(s, st, job)
    # A program hung, the executor holds the coverage device, and triage could
    # not reboot the box. Nothing can run until someone does: fuzzing would die
    # at startup and every further advance would fail the same way.
    if st and st.get("needs_reboot"):
        s["status"] = "halted"
        s["halt_reason"] = ("triage job %s hung and the box must be rebooted, but it "
                            "could not reboot itself: %s"
                            % (job, st["needs_reboot"].get("why")))
        save_state(s)
        log("HALT: %s" % s["halt_reason"])
        return
    stage = st.get("stage") if st else "?"
    if not st or stage not in ("DONE", "STUCK"):
        pause = d.get("triage_retry_seconds", DEFAULTS["triage_retry_seconds"])
        log("triage %s at stage %s; will advance again in %ds" % (job, stage, pause))
        save_state(s)
        paused = time.time()
        wait_for_stop(s, d, pause)          # a halt or brake lands within seconds
        s["triage_seconds"] = s.get("triage_seconds", 0.0) + (time.time() - paused)
        return

    # STUCK is a result, not a failure, and its kind says what there is to bench:
    #   unverified  a subset crashed during the search but not again on its own.
    #               Benched as an UNVERIFIED lead -- the smallest sequence seen to
    #               crash is still the best evidence -- and recorded as unproven.
    #   hang        the search kept hanging. The hung program is benched under its
    #               own quarantine key (it is not the target crash), and the target
    #               is exhausted: minimizing it again would hang the same way.
    #   no-repro, ring-*  nothing smaller than the whole ring reproduced. Benching
    #               "the whole program" would disable syscalls on no evidence, so
    #               the signature is recorded as exhausted instead; handle_crash
    #               counts its recurrences and benches a lead after the budget.
    verified = stage == "DONE"
    kind = None if verified else st.get("stuck_kind")
    sig = s.get("triage_bug_sig")
    cfg = s.get("current_config")
    if not verified:
        log("triage %s STUCK (%s): %s"
            % (job, kind, st.get("stuck_reason", "no verified culprit")))
    if kind in tri.NO_CULPRIT_KINDS or kind == "hang":
        if kind == "hang":
            bench_hang(s, job, cfg, st.get("hang_culprit"))
        else:
            log("  NOT benching: there is no culprit smaller than the whole ring")
        if sig and sig not in s.setdefault("exhausted_sigs", []):
            s["exhausted_sigs"].append(sig)
        if sig:
            s.setdefault("exhausted_why", {})[sig] = kind
            log("  %s recorded as exhausted (%s): not re-triaged; after %d more "
                "recurrences its newest ring program is benched as an UNVERIFIED "
                "lead (fuzz-campaign.py forget-exhausted %s to retry)"
                % (sig, kind, qm.DEFAULT_PARAMS["tolerate_budget"], s["name"]))
    else:
        if not verified:
            log("  benching its selectors anyway so fuzzing can continue, but the "
                "reproducer is UNVERIFIED -- it is a lead, not a proof")
        elif st.get("calls_reduced") is False:
            log("  calls could not be reduced; the verified connection culprit is "
                "the reproducer")
        culprit = st.get("final_culprit") or st.get("conn_culprit")
        if culprit and Path(culprit).exists() and sig and cfg:
            quarantine_apply_culprit(s, sig, cfg, culprit)
            # Write the reproducer back into the bug inventory. The quarantine knows
            # the culprit and triage holds the .syz, but the dossier -- the thing
            # that becomes a vendor report -- knew neither, and reported method: None.
            attribute_bug(sig, culprit, job, verified)
        else:
            log("triage %s %s but missing culprit/sig/config; suppression skipped"
                % (job, stage))
    # The quarantine owns the disable/rotate decision, but the campaign still
    # records which signatures it has spent a triage on -- that is what `status`
    # reports and what makes a re-triage of the same bug visible.
    if sig and sig not in s["suppressed_sigs"]:
        s["suppressed_sigs"].append(sig)
    s["phase"] = "fuzzing"
    s["triage_job"] = None
    s["triage_bug_sig"] = None
    s["triage_boots"] = 0
    # Every panic this job caused is filed. Without moving the watermark past
    # them, the next fuzzing crash would fingerprint them all again -- and if its
    # own report were unreadable, would take a triage panic's signature for it.
    s["panic_sig_watermark"] = max(s.get("panic_sig_watermark", 0.0),
                                   _newest_report_mtime())
    (s.get("triage_seen") or {}).pop(job, None)
    save_state(s)
    log("triage %s %s; bug %s %s; resuming fuzzing"
        % (job, "COMPLETE" if verified else "STUCK", sig,
           "benched (verified reproducer)" if verified
           else "exhausted (%s)" % kind if sig in s.get("exhausted_sigs", [])
           else "benched (UNVERIFIED lead)"))
    # A second bug this job (or an earlier one) surfaced goes next, before fuzzing.
    if start_queued_triage(s, d):
        save_state(s)


# --- the loop ----------------------------------------------------------------
def ensure_running(s, cfg, d=None):
    """Make sure a live session exists for cfg; resume if a record exists.

    Returns the inspect dict for the (now running) session. Resets the
    per-run exec-total baseline so the hang detector starts clean.
    """
    # The running config must reflect the current quarantine state (a fresh
    # escalation or a rotation changed disable_syscalls). Apply before start/resume
    # so syz-manager reads it and FilterCandidates prunes the corpus accordingly.
    try:
        apply_disabled(cfg, load_qstate(cfg))
    except RuntimeError as e:
        log("quarantine apply skipped for %s: %s" % (config_id(cfg), e))
    # New run: exec_total resets to 0, so reset the coverage-stall rotation clock.
    s["q_last_cover"] = None
    s["q_cover_exec_mark"] = 0
    sid = config_id(cfg)
    info = inspect(sid)
    if info.get("found") and info.get("status") == "running" and info.get("pid_alive"):
        log("session %s already running (pid %s); attaching supervisor"
            % (sid, info.get("pid")))
        # Attaching continues the open run. Re-basing here used to re-add the
        # run's elapsed time on every reattach. Only a run this state never
        # opened (a manager that outlived its supervisor) is opened now, from
        # the manager's own start.
        if not s.get("run_prep_started"):
            closed = s.get("run_closed") or {}
            if (closed.get("end") and closed.get("started") is not None
                    and closed["started"] == info.get("run_started_epoch")):
                # This very run was already banked up to closed["end"]: continue
                # it from there. account_run then counts only what came after.
                s["run_prep_started"] = closed["end"]
                s["run_prep_base"] = s.get("prep_seconds", 0.0)
                s["run_active_base"] = s.get("active_seconds", 0.0)
            else:
                s["run_prep_started"] = info.get("run_started_epoch") or time.time()
                s["run_prep_base"] = s.get("prep_seconds", 0.0)
                s["run_active_base"] = s.get("run_active_base", s.get("active_seconds", 0.0))
    else:
        # A run left open (rotation, halt) is closed before the next one opens.
        if s.get("run_prep_started") and s.get("session_id") == sid and info.get("found"):
            close_run(s, info, run_end_epoch(info))
        # Open the run before anything slow: preparation starts here, with the
        # snapshot and the results commit, not when the manager is launched.
        s["run_prep_base"] = s.get("prep_seconds", 0.0)
        s["run_active_base"] = s.get("active_seconds", 0.0)
        s["run_prep_started"] = time.time()
        # Name the session BEFORE starting it. It used to be saved only after
        # `session start` returned, so a panic in between (grammar compile,
        # corpus re-triage: the riskiest seconds of a run) left session_id None:
        # the next boot reconciled nothing, and the --force start overwrote the
        # ring buffer that held the crash.
        s["session_id"] = sid
        s["current_config"] = cfg
        save_state(s)
        verb = "resume" if info.get("found") else "start"
        target = sid if verb == "resume" else cfg
        # Before the manager starts: it re-triages corpus.db and silently drops
        # every program that no longer reproduces, which is how a whole corpus
        # was lost once. This commit is the copy that survives that.
        first = not s.get("results_started")
        results_commit(s, d, "start" if first else "restart", cfg=cfg)
        s["results_started"] = True
        rc, _ = session(verb, target, "--force")
        if rc != 0:
            # fall back to a fresh start if resume failed (e.g. no record)
            if verb == "resume":
                rc, _ = session("start", cfg, "--force")
            if rc != 0:
                raise RuntimeError("could not start session for %s" % cfg)
        info = inspect(sid)
    s["session_id"] = sid
    s["current_config"] = cfg
    s["run_started"] = info.get("run_started")
    s["last_exec_total"] = info.get("exec_total")
    save_state(s)
    return info


def handle_crash(s, d, info):
    """The coordinator work owed after a crash, shared by BOTH detection paths.

    This target reboots on every panic, so almost every crash is discovered by
    reconcile_boot on the next boot -- NOT by supervise. Keeping this logic only
    in the supervise branch made it unreachable in practice: a real 2h run took
    10 crashes and produced zero quarantine decisions, no bug-registry entries
    and no triage, because every one of them arrived through reconcile_boot.

    Returns True if the campaign flipped to the triaging phase.
    """
    panics = info.get("panics", [])
    log("crash: %d panic report(s); bug inventory -> %s" % (len(panics), BUGS_DIR))
    # The incident record_incident just wrote for this crash: what is learned
    # here (signature, kexts, bug ids, decision) is written onto it, so status
    # and the state file say what each crash WAS, not only that it happened.
    inc = s["incidents"][-1] if s.get("incidents") else {}
    if inc.get("kind") != "crash":
        inc = {}
    bug_ids = []
    for pth in panics:
        # provenance: which run found it, so one deduped inventory can still be
        # sliced per campaign (bug_registry list --campaign <name>)
        bug_ids += route_bug_registry(pth, s.get("name"), s.get("current_config")) or []
    if bug_ids:
        inc["bug_ids"] = list(dict.fromkeys(bug_ids))
    sig = latest_panic_signature(s)
    if not sig:
        log("crash: no readable panic signature; resuming without a decision")
        inc["decision"] = "unreadable"
        return False
    last = s.get("last_panic") or {}
    inc["signature"] = sig
    if last.get("signature") == sig:
        inc["title"] = last.get("title")
        inc["crashing_kext"] = last.get("crashing_kext")
        match = kext_matches(fuzzed_target(s.get("current_config")), last.get("crashing_kext"))
        inc["kext_match"] = match
        if match is False:
            log("crash %s: the backtrace blames %s, not the fuzzed kext %s"
                % (sig, last.get("crashing_kext"), inc.get("fuzzed_kext") or "?"))
    if sig in (s.get("exhausted_sigs") or []):
        exhausted_recurrence(s, sig, info)
        inc["decision"] = "exhausted (%s)" % ((s.get("exhausted_why") or {}).get(sig)
                                              or "no-repro")
        return False
    if quarantine_decide(s, sig) != "triage":
        rec = (load_qstate(s["current_config"])["catalog"].get(sig) or {}
               if s.get("current_config") else {})
        inc["decision"] = rec.get("disposition") or "resume"
        return False
    started = begin_triage(s, d, sig)
    inc["decision"] = "triage" if started else "triage failed"
    if started:
        inc["triage_job"] = s.get("triage_job")
    return started


def reconcile_gap(s, d, since=None, now=None):
    """Charge the interval from `since` to now to reboot overhead.

    `since` is when the last accounted activity ended: the closed run's last
    sign of life, or the last checkpoint when there is nothing better. The
    driver dies with the box, so the panic-to-login interval is invisible to
    every other clock. Measuring it is the difference between "the campaign ran
    2h" and "the campaign ran 2h and spent 40m rebooting to do it".

    When a boot happened in between, [boot, now] is login to relaunch and gets
    its own small cap (max_relaunch_seconds). The whole gap is capped at
    max_boot_gap_seconds: anything longer is not overhead but the rig sitting
    idle (or off) -- charging it would measure your schedule, not the campaign."""
    now = time.time() if now is None else now
    if since is None:
        since = timefmt.to_epoch(s.get("updated_at"))   # tolerates legacy 'Z'
    if since is None:
        return
    cap = d.get("max_boot_gap_seconds", DEFAULTS["max_boot_gap_seconds"])
    relaunch_cap = d.get("max_relaunch_seconds", DEFAULTS["max_relaunch_seconds"])
    boot = boot_epoch()
    raw = max(0.0, now - since)
    if boot and since < boot <= now:
        gap = max(0.0, boot - since) + min(now - boot, relaunch_cap)
    else:
        gap = raw
    if gap > cap:
        log("gap of %s since the last activity exceeds the %s reboot cap; "
            "counting the cap and treating the rest as idle"
            % (fmt_hms(raw), fmt_hms(cap)))
        gap = cap
    s["overhead_seconds"] = s.get("overhead_seconds", 0.0) + gap


def triage_probe_epoch(job, lo, hi):
    """The last moment a triage job is known to have been probing, in [lo, hi].

    syz-ring-repro fsyncs its checkpoint before and after every probe and stamps
    the probe it is about to run, so the newest of those is within one probe of
    the panic that killed it."""
    st = triage_state(job) if job else None
    if not st or not st.get("dir"):
        return None
    best = None
    # The ring replay rewrites its checkpoint before every slot, like a probe.
    for name in ("conn_state.json", "call_state.json", "replay_state.json"):
        p = Path(st["dir"]) / name
        cands = []
        try:
            cands.append(p.stat().st_mtime)
        except OSError:
            continue
        ck = read_json(p) or {}
        cands += [ck.get(k) for k in ("attempting_at", "verifying_at", "hanging_at",
                                      "pending_at")]
        for t in cands:
            if t and lo <= t <= hi and (best is None or t > best):
                best = t
    return best


def reconcile_triage_gap(s, d, last_save, now=None):
    """Account a triage advance the panic cut short.

    A probe that reproduces panics the box and kills the advance before it can
    charge itself. Up to that probe the box was minimizing; after it, rebooting.
    This used to charge all of it as reboot overhead, capped at 15 minutes, so a
    long minimization boot both vanished from the minimizing clock and was
    labelled as rebooting."""
    now = time.time() if now is None else now
    started = s.get("triage_advance_started")
    s["triage_advance_started"] = None
    if not started:
        reconcile_gap(s, d, since=last_save, now=now)
        return
    boot = boot_epoch()
    if not (boot and started < boot <= now):
        # The driver died without a reboot: no panic to split at.
        reconcile_gap(s, d, since=started, now=now)
        return
    crash = triage_probe_epoch(s.get("triage_job"), started, boot) or started
    s["triage_seconds"] = s.get("triage_seconds", 0.0) + (crash - started)
    reconcile_gap(s, d, since=crash, now=now)


def reconcile_boot(s, d):
    """Handle a run the driver was supervising when it was killed (panic-reboot).

    If the recorded session ended and was never collected, that ended run is an
    incident we owe a bundle. panic_evidence tells crash from hang: a real panic
    leaves a *.kernel.core.log/*.panic; a wedge that took the box down without
    one is treated as a hang. Idempotent -- a collected run has uncollected=None.

    Returns when the run it closed ended (for reconcile_gap), RUN_ALIVE if the
    session survived the driver, or None when there was no open run.
    """
    sid = s.get("session_id")
    if not sid:
        return None
    info = inspect(sid)
    if not info.get("found"):
        return None
    if info.get("status") == "running" and info.get("pid_alive"):
        return RUN_ALIVE             # survived; supervisor will re-attach
    end = run_end_epoch(info) if s.get("run_prep_started") else None
    if end is not None:
        # The record can be the previous run's: the session is named before its
        # manager starts, and the box may have gone down in between.
        end = max(end, s["run_prep_started"])
    if not info.get("uncollected"):
        if end is not None:
            close_run(s, info, end)  # already collected; just stop its clocks
        return end
    if info.get("status") == "stopped" and not info.get("panic_evidence"):
        # Stopped on purpose (halt, stop, rotation) and never collected: not an
        # incident. Filing it as a hang is how a halt-then-resume used to add a
        # phantom hang to the campaign. Snapshot it so its ring is kept and the
        # record reads collected.
        log("boot reconcile: %s was stopped deliberately, not lost; snapshot only" % sid)
        if end is not None:
            close_run(s, info, end)
        session("collect", sid, "snapshot")
        save_state(s)
        return end
    kind = "crash" if info.get("panic_evidence") else "hang"
    log("boot reconcile: %s ended uncollected -> %s" % (sid, kind))
    record_incident(s, d, kind, info, end)
    collect_and_prune(s, d, kind)
    if kind == "crash":
        handle_crash(s, d, info)   # may flip phase to triaging; the loop honours it
    save_state(s)
    return end


def _etime_seconds(text):
    """ps ELAPSED ([[dd-]hh:]mm:ss) -> seconds."""
    text = (text or "").strip()
    if not text:
        return None
    days = 0
    if "-" in text:
        d_, text = text.split("-", 1)
        try:
            days = int(d_)
        except ValueError:
            return None
    parts = text.split(":")
    try:
        parts = [int(x) for x in parts]
    except ValueError:
        return None
    while len(parts) < 3:
        parts.insert(0, 0)
    return days * 86400 + parts[0] * 3600 + parts[1] * 60 + parts[2]


def stuck_executor_seconds(d):
    """Age of the longest-running `syz-executor exec`, if it exceeds the limit.

    syz-executor forks one short-lived `exec` process per program, so a normal one
    lives milliseconds. One alive for minutes means a syscall that never returned:
    the box is wedged, whatever the manager's counters say.
    """
    limit = d.get("exec_stuck_seconds", DEFAULTS["exec_stuck_seconds"])
    if not limit:
        return None
    try:
        out = subprocess.run(["/bin/ps", "-Ao", "etime,command"],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             text=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    worst = 0
    for line in (out or "").splitlines()[1:]:
        line = line.strip()
        if "syz-executor exec" not in line:
            continue
        secs = _etime_seconds(line.split(None, 1)[0])
        if secs and secs > worst:
            worst = secs
    return worst if worst >= limit else None


def wait_for_stop(s, d, seconds):
    """Sleep up to `seconds`, returning early if a stop is requested.

    Returns "halted", "brake", or None if the full interval elapsed quietly.
    The brake is checked here as well as at startup: it is the stop you reach
    for when the box is misbehaving, and having to wait out a poll interval for
    it defeats the purpose.
    """
    step = d.get("stop_check_seconds", DEFAULTS["stop_check_seconds"])
    deadline = time.time() + seconds
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            return None
        time.sleep(min(step, remaining))
        if load_state(s["name"]).get("status") == "halted":
            return "halted"
        held = brake_held(s["name"])
        if held:
            path, why = held
            log("BRAKE while running: %s%s" % (path, " -- %s" % why if why else ""))
            s["status"] = "halted"
            s["halt_reason"] = "brake: %s" % (why or path)
            save_state(s)
            return "brake"


def supervise(s, d, sid, budget):
    """Poll until an incident, budget exhaustion, or manager death.

    Returns one of: "crash", "hang", "budget". exec_total resets to 0 each run,
    so a decrease across a restart reads as progress (never a false hang).
    """
    poll = d["poll_seconds"]
    hang_after = d["hang_after_seconds"]
    fuzzing = False
    last_et = s.get("last_exec_total")
    last_progress = time.time()
    while True:
        # A stop request must not wait on the progress poll. Those are two very
        # different costs: inspect() talks to the manager over HTTP and is
        # deliberately infrequent (poll_seconds, 10 min by default), while
        # noticing a halt is one stat() of a local file. Sleeping the whole poll
        # in one go coupled them, so `halt` took up to ten minutes to be seen --
        # long enough to feel broken and to invite killing the driver instead,
        # which is how a half-stopped campaign gets left behind.
        #
        # Never sleep past the budget either. The polls are phased from when
        # supervision started, not from the deadline, so a check that lands just
        # short of it used to buy a whole extra poll: a 1h campaign checked at
        # 59m06s and ran to 1h09m.
        # Until the first exec, a manager that dies is a startup failure, and
        # it should be noticed in seconds, not at the next 10-minute poll.
        step = poll if fuzzing else min(poll, d.get("startup_poll_seconds",
                                                    DEFAULTS["startup_poll_seconds"]))
        stop = wait_for_stop(s, d, min(step, max(1, budget - budget_spent(s, d))))
        if stop == "halted":
            s["halt_reason"] = s.get("halt_reason") or "halted by user"
            session("stop", sid)
            return "halted"
        if stop == "brake":
            session("stop", sid)
            return "halted"

        s.update(load_state(s["name"]))

        info = inspect(sid)
        now = time.time()
        if not info.get("found") or not info.get("pid_alive"):
            if info.get("panic_evidence"):
                return "crash"
            return "hang" if info.get("fuzz_started_epoch") else "startup"
        if info.get("fuzz_started_epoch") and not fuzzing:
            fuzzing = True
            s["startup_failures"] = 0
        account_run(s, info, now)
        et = info.get("exec_total")
        if et is not None and et != last_et:
            last_et = et
            s["last_exec_total"] = et
            last_progress = now
        elif (now - last_progress) >= hang_after:
            # NOT gated on `et is not None`. It used to be, on both branches, so a
            # manager that stopped reporting exec_total at all -- which is what a
            # bad hang looks like -- could never be declared hung. The detector
            # only caught a wedge mild enough for the manager to keep publishing a
            # frozen number: the worse the hang, the more invisible it was. A box
            # sat 38 minutes on one stuck program with nothing noticing.
            log("hang: %s for %ds"
                % ("exec_total stuck at %s" % et if et is not None
                   else "exec_total UNREADABLE (manager not reporting)",
                   round(now - last_progress)))
            return "hang"
        # A single program wedged in the kernel is a hang, and a far more direct
        # signal than a stalled counter: syz-executor forks one `exec` process per
        # program, so one alive for minutes is a syscall that never returned.
        # Catches in exec_stuck_seconds what the counter takes hang_after to infer.
        stuck = stuck_executor_seconds(d)
        if stuck:
            log("hang: syz-executor has been in one exec for %ds (limit %ds) -- "
                "a program is wedged in the kernel"
                % (round(stuck), d.get("exec_stuck_seconds", DEFAULTS["exec_stuck_seconds"])))
            return "hang"
        # SOFT-group rotation: advancing the disabled set needs a manager restart
        # (it re-reads disable_syscalls), so surface it as an outcome the loop
        # handles by re-applying the config and resuming the same config.
        if quarantine_rotate_due(s):
            return "rotate"
        # Commits only when the corpus or coverage moved (fuzz-results decides).
        results_commit(s, d, "corpus", detach=True)
        if budget_spent(s, d) >= budget:
            return "budget"
        # breaker can trip mid-run (disk), so re-check each poll. Stop the manager
        # like the other halt paths: left running, it fuzzed on unsupervised and
        # held /dev/pishi, and a later resume re-attached to a run already closed.
        reason = breaker(s, d)
        if reason:
            s["status"] = "halted"
            s["halt_reason"] = reason
            save_state(s)
            session("stop", sid)
            return "halted"
        save_state(s)


def cmd_run(name):
    d = load_def(name)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    # single driver per campaign, even if launchd double-starts us
    lock = open(STATE_DIR / ("%s.lock" % name), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        log("another driver for %r is already running; exiting" % name)
        return
    # The brake is checked FIRST, before the state is even read, because its whole
    # purpose is to stop a box that keeps panicking -- including one that panics
    # as soon as fuzzing resumes. Anything we do before this is something the
    # brake failed to prevent.
    held = brake_held(name)
    if held:
        path, why = held
        log("BRAKE: %s" % path)
        if why:
            log("  reason: %s" % why)
        log("  remove the file and run: fuzz-campaign.py resume %s" % name)
        s = load_state(name)
        s["status"] = "halted"
        s["halt_reason"] = "brake: %s" % (why or path)
        save_state(s)
        return                      # exit 0: KeepAlive{SuccessfulExit:false} stays down
    coord_path = open_coord_log(name)
    # The launchd-captured stream is shared with every subprocess, so we cannot
    # rotate it by rename -- truncate it in place when it gets out of hand.
    if rotate_log(STATE_DIR / ("%s.launchd.log" % name), d["max_log_mb"]):
        log("launchd log exceeded %.0fMB and was truncated (decisions are kept "
            "in %s)" % (d["max_log_mb"], coord_path))
    s = load_state(name)
    for k, v in COORDINATOR_DEFAULTS.items():   # backfill for pre-coordinator state
        s.setdefault(k, type(v)(v) if isinstance(v, (list, dict)) else v)   # never share a default
    if s["status"] in ("done", "halted"):
        log("campaign %r is %s (%s); nothing to do"
            % (name, s["status"], s.get("halt_reason") or ""))
        return
    log("campaign %r starting: %d config(s), %.1fh budget each, loop=%s, phase=%s"
        % (name, len(d["items"]), d["budget_hours"], d["loop"], s["phase"]))
    # Where the three ledgers live. They are campaign-scoped, not session-scoped,
    # on purpose -- see the note on BUGS_DIR.
    log("  bug inventory : %s" % BUGS_DIR)
    log("  quarantine    : %s/quarantine_<config-id>.json" % STATE_DIR)
    log("  triage jobs   : %s" % (REPO_ROOT / "triage"))
    log("  decisions log : %s" % coord_path)
    # Printed on every start so the stop path is in the log you will already be
    # reading when the box starts misbehaving -- not only in the setup doc.
    log("  brake (stop)  : touch %s" % GLOBAL_BRAKE)
    # Whatever killed the last driver -- a panic-reboot mid-fuzz or mid-triage --
    # the time since the last thing we accounted is split between the phase that
    # was running and the reboot. Read the checkpoint before anything saves.
    last_save = timefmt.to_epoch(s.get("updated_at"))
    if s["phase"] == "triaging":
        # No fuzzing session to reconcile; the box is (or was) running triage,
        # resumed by the phase branch below.
        reconcile_triage_gap(s, d, last_save)
    else:
        end = reconcile_boot(s, d)
        if end != RUN_ALIVE:          # a live manager was fuzzing all along
            reconcile_gap(s, d, since=end if end is not None else last_save)

    while True:
        # `fuzz-campaign.py halt` writes the status into the state FILE. Only
        # supervise re-read it, so a halt was ignored for as long as the campaign
        # sat in the triaging phase -- and advance_triage's own save_state then
        # overwrote it from stale memory, silently un-halting the campaign.
        persisted = load_state(name)
        if persisted.get("status") == "halted":
            s["status"] = "halted"
            s["halt_reason"] = persisted.get("halt_reason")
            save_state(s)
            log("campaign halted by user%s"
                % (": %s" % s["halt_reason"] if s.get("halt_reason") else ""))
            return
        reason = breaker(s, d)
        if reason:
            s["status"] = "halted"
            s["halt_reason"] = reason
            save_state(s)
            log("HALT: %s" % reason)
            return
        # Coordinator: while a bug is being triaged, drive triage instead of
        # fuzzing. advance_triage flips phase back to "fuzzing" when it benches
        # the culprit, or halts the campaign if triage cannot make progress.
        if s["phase"] == "triaging":
            # The budget is otherwise only tested inside supervise, which does
            # not run in this phase -- so a long minimization would overrun a
            # wall budget without ever noticing. Check before spending another
            # boot on triage. Only the wall clock can expire here; a fuzz-clock
            # budget deliberately does not charge triage at all.
            # A job is not abandoned half-way when the budget runs out: it is
            # finished (still bounded by triage_max_boots), its result benched,
            # and the config advanced after -- see the budget check below.
            item = d["items"][min(s["cursor"], len(d["items"]) - 1)]
            if budget_spent(s, d) >= item["budget_seconds"]:
                log("budget spent (%s clock) while triaging %s; finishing the job, "
                    "then moving on" % (d.get("budget_clock"), s.get("triage_job")))
            advance_triage(s, d)
            if s["status"] == "halted":
                return
            continue
        if s["cursor"] >= len(d["items"]):
            if d["loop"]:
                log("loop: wrapping cursor to 0")
                s["cursor"] = 0
                roll_budget_clocks(s)
                reset_config_counters(s)
            else:
                s["status"] = "done"
                save_state(s)
                log("campaign %r done: prep %s, fuzz %s, triage %s, reboots %s, wall %s"
                    % (name, fmt_hms(lifetime(s, "prep_seconds")),
                       fmt_hms(lifetime(s, "active_seconds")),
                       fmt_hms(lifetime(s, "triage_seconds")),
                       fmt_hms(lifetime(s, "overhead_seconds")),
                       fmt_hms(lifetime_wall(s))))
                return
        item = d["items"][s["cursor"]]
        cfg, budget = item["config"], item["budget_seconds"]
        # A config max_crashes gave up on stays given up for this campaign: a
        # looping campaign skips it, and one with nothing left to run halts.
        gone = {a["config"] for a in s.get("abandoned", [])}
        if cfg in gone:
            if all(it["config"] in gone for it in d["items"]):
                s["status"] = "halted"
                s["halt_reason"] = "every config was abandoned (max_crashes)"
                save_state(s)
                log("HALT: %s" % s["halt_reason"])
                return
            log("skipping %s: abandoned earlier" % config_id(cfg))
            advance_config(s)
            save_state(s)
            continue
        why = config_breaker(s, d)
        if why:
            log("ABANDON %s: %s; moving to the next config" % (config_id(cfg), why))
            s.setdefault("abandoned", []).append(
                {"config": cfg, "reason": why, "at": now_iso()})
            results_commit(s, d, "end", cfg=cfg)
            advance_config(s)
            save_state(s)
            continue
        # Stamp the real clock's origin once per config. Guarded on absence, not
        # overwritten: every panic-reboot relaunches this loop, and re-stamping
        # would restart the window on each crash.
        if not s.get("config_started_at"):
            s["config_started_at"] = now_iso()
            save_state(s)
        remaining = budget - budget_spent(s, d)
        if remaining <= 0:
            # Spent while triaging (the only phase that can overrun it). The
            # manager was stopped at the crash; starting it again only to stop it
            # at the first budget check would cost a whole preparation.
            log("budget spent on %s (during triage); advancing" % config_id(cfg))
            results_commit(s, d, "end", cfg=cfg)
            advance_config(s)
            save_state(s)
            continue
        log("config %d/%d: %s (%.0f min left of %.1fh %s budget; this config so "
            "far: prep %s, fuzz %s, triage %s, reboots %s)"
            % (s["cursor"] + 1, len(d["items"]), config_id(cfg),
               remaining / 60, budget / 3600, d.get("budget_clock", "wall"),
               fmt_hms(s.get("prep_seconds")), fmt_hms(s.get("active_seconds")),
               fmt_hms(s.get("triage_seconds")), fmt_hms(s.get("overhead_seconds"))))
        try:
            ensure_running(s, cfg, d)
        except RuntimeError as e:
            s["status"] = "halted"
            s["halt_reason"] = str(e)
            save_state(s)
            log("HALT: %s" % e)
            return

        outcome = supervise(s, d, s["session_id"], budget)

        if outcome == "halted":
            close_run(s, inspect(s["session_id"]), time.time())
            s["halt_reason"] = s.get("halt_reason") or "halted by user"
            save_state(s)
            log("HALT: %s" % s["halt_reason"])
            results_commit(s, d, "halt", cfg=cfg)
            return
        if outcome == "budget":
            close_run(s, inspect(s["session_id"]), time.time())
            log("budget spent on %s; snapshot + advance" % config_id(cfg))
            session("collect", s["session_id"], "snapshot")
            session("stop", s["session_id"])
            results_commit(s, d, "end", cfg=cfg)
            advance_config(s)
            save_state(s)
            continue
        if outcome == "startup":
            info = inspect(s["session_id"])
            end = run_end_epoch(info)
            started = info.get("run_started_epoch")
            close_run(s, info, end)
            s["startup_failures"] = s.get("startup_failures", 0) + 1
            why = run_log_tail(info)
            s["last_startup_error"] = why
            s["incidents"].append({
                "config": cfg, "kind": "startup", "at": now_iso(),
                "ran_seconds": round(end - started) if started else None,
                "exec_total": None, "panic_evidence": False, "log_tail": why})
            limit = d.get("startup_fail_limit", DEFAULTS["startup_fail_limit"])
            log("startup failure %d/%d on %s: syz-manager died before executing "
                "anything -- %s" % (s["startup_failures"], limit, config_id(cfg),
                                    why or "(empty run log)"))
            session("collect", s["session_id"], "startup")
            save_state(s)
            if s["startup_failures"] < limit:
                wait_for_stop(s, d, d.get("startup_retry_seconds",
                                          DEFAULTS["startup_retry_seconds"]))
            continue                     # the breaker halts at the limit
        if outcome == "rotate":
            # A SOFT group rotated: stop and resume the SAME config (budget kept);
            # ensure_running re-applies the now-rotated disabled set on resume.
            log("SOFT rotation due on %s; restarting to apply" % config_id(cfg))
            info = inspect(s["session_id"])
            close_run(s, info, time.time() if info.get("pid_alive") else run_end_epoch(info))
            if info.get("pid_alive"):
                session("stop", s["session_id"])
            s["session_id"] = None
            save_state(s)
            continue
        # crash or hang: stop if still alive, record, collect. A manager we stop
        # ran until now; a dead one ended at its last sign of life, not at the
        # poll that noticed (up to poll_seconds later).
        info = inspect(s["session_id"])
        end = time.time() if info.get("pid_alive") else run_end_epoch(info)
        if info.get("pid_alive"):
            session("stop", s["session_id"])
            info = inspect(s["session_id"])
        record_incident(s, d, outcome, info, end)
        collect_and_prune(s, d, outcome)
        # Coordinator: the quarantine SUSPECT gate decides whether a crash earns a
        # triage. A NEW signature becomes SUSPECT and just resumes (enabled); a
        # recurrence that needs confirming, or an escape, is triaged; a tolerated
        # recurrence is handled in place. See quarantine_decide.
        if outcome == "crash" and handle_crash(s, d, info):
            save_state(s)
            continue                     # loop re-enters the triaging phase
        save_state(s)
        # policy: restart same config -- loop re-enters ensure_running (resume)


# --- authoring + control -----------------------------------------------------
def cmd_new(name, configs, budget_hours, loop, poll_seconds, hang_after_seconds,
            max_crashes, min_free_gb, keep_cores, force, triage_opts=None,
            breaker_opts=None):
    path = def_path(name)
    if path.exists() and not force:
        die("campaign %r already exists (%s); use --force to overwrite" % (name, path))
    rel = []
    for c in configs:
        cp = Path(c)
        if not cp.exists():
            die("config not found: %s" % c)
        try:
            rel.append(str(cp.resolve().relative_to(REPO_ROOT)))
        except ValueError:
            rel.append(str(cp.resolve()))
    d = {
        "name": name, "configs": rel, "budget_hours": budget_hours, "loop": loop,
        "poll_seconds": poll_seconds, "hang_after_seconds": hang_after_seconds,
        "max_crashes": max_crashes, "min_free_gb": min_free_gb,
        "keep_cores": keep_cores,
    }
    # The device flags begin_triage passes to `triage.py new`. Without them triage
    # falls back to its own defaults (no kcov device, no kext id), which is not
    # what the manual runs used -- so author them here, once, per campaign.
    tri = {k: v for k, v in (triage_opts or {}).items() if v is not None}
    # Device settings belong to the CONFIG, so default them from it rather than
    # making you retype what the config already says. Each driver has its own
    # Pishi kext id (AppleJPEGDriver=1, AppleSSE=4 ... AppleFDEKeyStore=256), and
    # a campaign told the wrong one triages a crash against the wrong kext. An
    # explicit flag still wins, but not typing it is no longer a way to be wrong.
    # Only the FIRST config seeds these: they are the campaign-level fallback, and
    # begin_triage takes the real values per crash via config_triage_flags.
    seeded = config_triage_flags(rel[0] if rel else None)
    for k, v in seeded.items():
        if k != "executor_name" and k not in tri:
            tri[k] = v
    if tri:
        d["triage"] = tri
    # Breaker overrides sit at the top level and are merged over DEFAULTS by
    # load_def, so only the ones actually given are written.
    for k, v in (breaker_opts or {}).items():
        if v is not None:
            d[k] = v
    write_json(path, d)
    log("wrote %s" % path)
    # Show what each config brings, because the two ways to get a sweep wrong are
    # invisible in the flags: configs sharing a workdir (then they share a corpus
    # and the comparison measures nothing), and configs spanning kext ids (fine,
    # but you should know you did it).
    rows, kexts, workdirs = [], set(), []
    for c in rel:
        conf = read_json(c) or {}
        kc = conf.get("kext_coverage") or {}
        wd = (conf.get("workdir") or "").rstrip("/").rsplit("/", 1)[-1] or "-"
        kexts.add(kc.get("kext_id"))
        workdirs.append(wd)
        rows.append([Path(c).name, str(kc.get("kext_id") or "-"),
                     str(len(conf.get("enable_syscalls") or [])),
                     conf.get("executor_name") or "-", wd])
    for ln in render(rows, ["config", "kext", "syscalls", "exec name", "workdir"]):
        print("  " + ln)
    # budget_hours is PER CONFIG. "24" on a three-config sweep is 72 hours, and
    # that is the kind of thing you find out the next morning.
    total = budget_hours * len(rel)
    print("  %d config(s), %.1fh EACH on the %s clock = %.1fh total%s"
          % (len(rel), budget_hours, d.get("budget_clock", DEFAULTS["budget_clock"]),
             total, " per lap, looping" if loop else ""))
    if len(rel) > 1 and len(set(workdirs)) < len(workdirs):
        print("  WARNING: configs share a workdir, so they share a corpus -- a "
              "comparison between them measures nothing")
    if len(kexts) > 1:
        print("  note: configs span %d kext ids; the campaign-level kext_id (%s) is "
              "only a fallback -- triage takes it from the config that crashed"
              % (len(kexts), tri.get("kext_id")))
    if any(r[3] == "-" for r in rows):
        print("  note: a config sets no executor_name. If its driver gates the user "
              "client on p_comm, every IOServiceOpen fails and both fuzzing and "
              "minimization silently do nothing.")
    print("  pre-flight:  ./scripts/fuzz-campaign.py doctor %s" % name)
    print("  run it:      ./scripts/fuzz-campaign.py run %s" % name)
    print("  or install:  sudo ./scripts/fuzz-campaign.py install %s --agent --user fuzz" % name)


def _delta(cur, prev, fmt="%+d"):
    """Render the change since the previous sample, or "" when there is none.

    Watch mode exists to show movement, and an absolute counter does not: 11.2M
    programs looks identical one refresh later whether the box is fuzzing hard or
    wedged. The delta is the part you actually read."""
    if prev is None or cur is None or cur == prev:
        return ""
    try:
        return "  " + (fmt % (cur - prev))
    except (TypeError, ValueError):
        return ""


def corpus_facts(cfg):
    """(inputs, bytes, mtime) for the config's corpus.db, or None.

    Surfaced because a config IS its workdir: re-running a config resumes that
    workdir's corpus rather than starting over, which is right for making
    progress and wrong for measuring "coverage reached from scratch in 24h".
    Whether you are continuing or starting fresh should not be something you have
    to infer from a log line that scrolled past hours ago.
    """
    try:
        conf = read_json(cfg)
        wd = (conf or {}).get("workdir")
        if not wd:
            return None
        db = Path(wd) / "corpus.db"
        st = db.stat()
        return {"path": str(db), "bytes": st.st_size, "mtime": st.st_mtime,
                "workdir": wd}
    except OSError:
        return None


def orphaned_session(s, d):
    """A live fuzzing session with no supervisor updating the campaign state.

    This is what `launchctl bootout` used to leave behind: fuzz-session spawns
    syz-manager detached, so unloading the agent kills the supervisor while the
    manager keeps fuzzing. The campaign still says "running" because nothing is
    left to say otherwise -- the most misleading state the system can be in, so
    it is detected rather than inferred from a stale timestamp by eye.

    Detected by the state going unwritten for well over a poll interval while
    the session is still alive.
    """
    if s.get("status") != "running" or not s.get("session_id"):
        return None
    last = timefmt.to_epoch(s.get("updated_at"))
    if last is None:
        return None
    stale = time.time() - last
    # Two polls plus a margin: one missed write is a slow inspect, not a death.
    if stale < max(2.5 * d["poll_seconds"], 120):
        return None
    info = inspect(s["session_id"])
    if not (info.get("found") and info.get("pid_alive")):
        return None
    return {"sid": s["session_id"], "stale_for": stale, "pid": info.get("pid")}


def status_lines(name, prev=None):
    """The status block as a list of lines, plus a sample dict for the next call.

    prev is the previous call's sample; when given, changed counters are annotated
    with their delta.
    """
    d = load_def(name)
    s = load_state(name)
    prev = prev or {}
    out = []

    def row(label, value, extra=""):
        out.append("  %-12s: %s%s" % (label, value, extra))

    out.append("campaign %s : %s" % (name, s["status"]))
    if s.get("halt_reason"):
        row("halt reason", s["halt_reason"])
    orphan = orphaned_session(s, d)
    if orphan:
        out.append("  !! NO SUPERVISOR: the state has not been written for %s "
                   "(poll is %ds)." % (fmt_hms(orphan["stale_for"]), d["poll_seconds"]))
        out.append("     The manager is still fuzzing, unwatched: no budget is "
                   "enforced, no crash")
        out.append("     is filed, and it holds /dev/pishi against the next "
                   "campaign. Stop it with:")
        out.append("       fuzz-session.py stop %s" % orphan["sid"])
    held = brake_held(name)
    if held:
        row("BRAKE", "%s%s" % (held[0], " -- %s" % held[1] if held[1] else ""))
    row("configs", "%d (loop=%s)" % (len(d["items"]), d["loop"]))
    row("cursor", "%d/%d" % (min(s["cursor"] + 1, len(d["items"])), len(d["items"])))

    cfg = s.get("current_config")
    if cfg:
        item = d["items"][min(s["cursor"], len(d["items"]) - 1)]
        row("current", config_id(cfg))
        row("budget", "%.2f / %.2f h used (%s clock, this config)"
            % (budget_spent(s, d) / 3600, item["budget_seconds"] / 3600,
               d.get("budget_clock", "wall")))
        if s.get("config_started_at"):
            row("config start", timefmt.fmt(s["config_started_at"]))
        # A config is a workdir. Say plainly whether this run inherited a corpus.
        cf_facts = corpus_facts(cfg)
        if cf_facts:
            row("corpus", "%s  (%.0f KB, last grew %s)"
                % (Path(cf_facts["workdir"]).name, cf_facts["bytes"] / 1024.0,
                   timefmt.fmt_epoch(cf_facts["mtime"], short=True)),
                _delta(cf_facts["bytes"], prev.get("corpus_bytes"), "%+d B"))
        else:
            row("corpus", "none yet -- this config starts from scratch")

    # Four clocks, campaign-lifetime (never reset by a config advance). Reported
    # separately because "24h of fuzzing" and "24h of campaign" are different
    # claims, and a writeup that conflates them overstates the fuzzing.
    # "fuzzing" starts at the run's first executed program, so the startup
    # (snapshot, grammar compile, executor handshake) is its own line. It still
    # includes the manager re-triaging its corpus and waiting on RPC; for pure
    # execution time `runstats.py show` reads syz-manager's own counter.
    out.append("  time, whole campaign:")
    row("  preparing", fmt_hms(lifetime(s, "prep_seconds")),
        "  (snapshot, grammar compile, until the first exec)")
    row("  fuzzing", fmt_hms(lifetime(s, "active_seconds")),
        "  (first exec -> end of run; see runstats.py for execution time)")
    row("  minimizing", fmt_hms(lifetime(s, "triage_seconds")), "  (triage)")
    row("  rebooting", fmt_hms(lifetime(s, "overhead_seconds")),
        "  (panic -> back up, and dead time)")
    row("  wall", fmt_hms(lifetime_wall(s)), "  (sum of the four)")

    # What the box actually did, not just how long it was up: on this target a
    # campaign can burn an hour of wall clock and execute very little.
    live = inspect(s["session_id"]) if s.get("session_id") else {}
    execs = live.get("exec_total") if live.get("exec_total") is not None \
        else s.get("last_exec_total")
    cov = live.get("coverage")
    # The manager's UI: coverage browser, corpus, crash list. Only meaningful
    # while the manager is actually serving, so it is shown with that caveat
    # rather than as a link that may quietly not answer.
    if live.get("http"):
        url = live["http"]
        if not url.startswith("http"):
            url = "http://%s" % url
        row("web ui", url if live.get("pid_alive") else "%s  (manager down)" % url)
    row("executed", "%s program(s)%s"
        % ("{:,}".format(int(execs)) if execs not in (None, "") else "-",
           "  (%s/sec)" % live.get("rate") if live.get("rate") else ""),
        _delta(execs, prev.get("execs"), "%+,d".replace(",", "")))
    if cov not in (None, ""):
        row("coverage", "%s basic block(s)" % cov, _delta(_int(cov), prev.get("cov")))
    row("incidents", "%d crash / %d hang  (this config: %d of max_crashes %d)"
        % (s["crashes"], s["hangs"], s.get("config_incidents", 0), d["max_crashes"]),
        _delta(s["crashes"], prev.get("crashes")))
    if s.get("startup_failures"):
        row("startup", "%d failed start(s) in a row (halts at %d): %s"
            % (s["startup_failures"], d.get("startup_fail_limit",
                                            DEFAULTS["startup_fail_limit"]),
               s.get("last_startup_error") or "?"))
    for a in s.get("abandoned", []):
        row("abandoned", "%s  (%s, %s)" % (config_id(a["config"]), a.get("reason"),
                                           timefmt.fmt(a.get("at"), short=True)))
    row("phase", s.get("phase", "fuzzing"))
    if s.get("phase") == "triaging":
        row("triaging", "job %s, bug %s (advance %d/%d)"
            % (s.get("triage_job"), s.get("triage_bug_sig"),
               s.get("triage_boots", 0), d["triage_max_boots"]))
        tst = triage_state(s.get("triage_job")) if s.get("triage_job") else None
        if tst:
            row("  progress", tri.progress_line(tri.progress(tst)))
    if s.get("triage_queue"):
        row("triage queue", "%d second bug(s) waiting: %s"
            % (len(s["triage_queue"]), ", ".join(q["sig"] for q in s["triage_queue"])))
    if s.get("exhausted_sigs"):
        why = s.get("exhausted_why") or {}
        row("exhausted", "%d sig(s) minimization could not reduce, not re-triaged (%s)"
            % (len(s["exhausted_sigs"]),
               ", ".join("%s %s" % (g, why.get(g, "no-repro"))
                         for g in s["exhausted_sigs"][-3:])))
    if s.get("suppressed_sigs"):
        row("benched sigs", "%d (%s)"
            % (len(s["suppressed_sigs"]), ", ".join(s["suppressed_sigs"][-3:])))
    row("disk free", "%.1f GB" % free_gb())
    row("updated", timefmt.fmt(s.get("updated_at")))
    row("started", timefmt.fmt(s.get("started_at")))
    for inc in s["incidents"][-5:]:
        out.append("    - " + incident_line(inc))

    sample = {"execs": execs, "cov": _int(cov), "crashes": s["crashes"],
              "corpus_bytes": (corpus_facts(cfg) or {}).get("bytes") if cfg else None}
    return out, sample


def incident_line(inc):
    """One incident for status: when, what, where, and what it turned out to be."""
    line = "%s  %-7s %s  ran %ss" % (timefmt.fmt(inc["at"]), inc["kind"],
                                     config_id(inc["config"]), inc.get("ran_seconds"))
    if inc.get("signature"):
        line += "  sig %s" % inc["signature"]
    if inc.get("bug_ids"):
        line += " %s" % ",".join(inc["bug_ids"])
    if inc.get("crashing_kext"):
        line += "  in %s" % inc["crashing_kext"]
        if inc.get("kext_match") is False:
            line += " (NOT the fuzzed %s)" % (inc.get("fuzzed_kext") or "kext")
    if inc.get("decision"):
        line += "  -> %s" % inc["decision"]
        if inc.get("triage_job"):
            line += " %s" % inc["triage_job"]
    elif inc["kind"] == "crash" and not inc.get("panic_evidence"):
        line += "  (no panic report)"
    if inc.get("log_tail"):
        line += "  -- %s" % inc["log_tail"][:80]
    return line


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def cmd_status(name, watch=False, interval=10):
    """Campaign dashboard: printed once, or redrawn until Ctrl-C with --watch.

    Watch mode annotates the counters that moved since the last redraw, so a
    wedged manager is visible as "nothing changed" rather than requiring you to
    remember the previous number.
    """
    if not watch:
        lines, _ = status_lines(name)
        print("\n".join(lines))
        return
    prev = None
    try:
        while True:
            lines, sample = status_lines(name, prev)
            head = ("fuzz-campaign status --watch  (every %ds, Ctrl-C to quit)  %s"
                    % (interval, timefmt.stamp()))
            # Clear + home, then repaint, so the block does not scroll away.
            sys.stdout.write("\033[2J\033[H" + "\n".join([head, ""] + lines) + "\n")
            sys.stdout.flush()
            prev = sample
            time.sleep(interval)
    except KeyboardInterrupt:
        sys.stdout.write("\n")


def cmd_doctor(name):
    """Pre-flight a campaign: check the things a supervised run needs before it
    hits its first crash. Exit 0 if nothing is fatal, 1 if any FAIL."""
    d = load_def(name)
    checks = []  # (level, message)

    def add(level, msg):
        checks.append((level, msg))

    # The brake. Reported first because it is the check you need to have read
    # BEFORE the box misbehaves -- afterwards you may not have a usable login.
    held = brake_held(name)
    if held:
        add("FAIL", "BRAKE SET (%s%s) -- this campaign will halt instead of running; "
                    "clear it with `fuzz-campaign.py brake --clear`"
            % (held[0], ": %s" % held[1] if held[1] else ""))
    else:
        add("OK", "brake clear (set it with `touch %s`; from Recovery: `touch \"%s\"`)"
            % (GLOBAL_BRAKE, recovery_hint()))

    # Campaigns share /dev/pishi, so a second one does not queue behind the first,
    # it collides: the new session's executor dies with EBUSY and the run looks
    # broken for no reason anyone would connect to "something else was running".
    busy = box_busy()
    if busy:
        add("FAIL", "something is already using the box -- campaigns share "
                    "/dev/pishi and a second one collides with EBUSY "
                    "(stop it first: fuzz-campaign.py halt <name>)")
        for what, pid, cmd in busy:
            add("FAIL", "  pid %s  %s  %s" % (pid, what, cmd[:80]))
    else:
        add("OK", "nothing else holding /dev/pishi")

    # Coordinator's own binary. A daemon can't use the `go run` fallback (minimal
    # PATH), so the built binary is required there; foreground can go run.
    if RINGREPRO_BIN.exists() or os.environ.get("SYZ_RINGREPRO"):
        add("OK", "syz-ring-repro binary present (%s)" % RINGREPRO_BIN)
    elif shutil.which("go"):
        add("WARN", "syz-ring-repro not built (%s): foreground uses `go run`, but the "
            "daemon cannot -- run `make target`" % RINGREPRO_BIN)
    else:
        add("FAIL", "no syz-ring-repro binary (%s) and no `go` on PATH -- run `make target`"
            % RINGREPRO_BIN)

    # fuzz-session's device binaries. syz-manager itself validates that BOTH
    # syz-execprog and syz-executor sit under <syzkaller>/bin/<arch>/ and exits
    # FATAL at startup if either is absent (pkg/mgrconfig/load.go), so check both
    # here -- a tree missing syz-execprog otherwise fails one second into the run.
    for binname in ("syz-executor", "syz-execprog"):
        bp = REPO_ROOT / "bin/darwin_arm64" / binname
        add("OK" if bp.exists() else "FAIL",
            "%s present" % binname if bp.exists()
            else "%s MISSING (%s) -- syz-manager exits FATAL without it; run `make target`"
                 % (binname, bp))
    mgr = Path(os.environ.get("SYZ_MANAGER_BIN", REPO_ROOT / "bin/syz-manager"))
    add("OK" if mgr.exists() else "FAIL",
        "syz-manager present" if mgr.exists() else "syz-manager MISSING (%s) -- make manager" % mgr)

    # Helper scripts the coordinator shells out to. quarantine.py and
    # bug_registry.py are imported/executed on the crash path, so a tree that
    # published only the two drivers (an old sync) fails here rather than at 3am.
    for p in (SESSION, TRIAGE, SCRIPT_DIR / "crash_fingerprint.py",
              SCRIPT_DIR / "quarantine.py", BUG_REGISTRY):
        add("OK" if p.exists() else "FAIL",
            "%s present" % p.name if p.exists() else "%s MISSING (%s)" % (p.name, p))

    # Everything below is checked AS THE USER THAT WILL RUN THE CAMPAIGN. Under
    # launchd that is the agent's user (e.g. fuzz), not the person running doctor
    # -- so run `doctor` as that user (sudo -u fuzz ...) for a truthful answer.
    add("INFO", "checks below run as uid %d (%s) -- run doctor as the campaign's "
        "launchd user for a truthful answer" % (os.geteuid(), getpass.getuser()))

    # Panic reports drive fingerprint/dedup/new-bug detection AND the crash gate.
    # Existing-but-unreadable is the dangerous case: the driver simply never sees
    # a crash, so it never triages, never quarantines, and fuzzes a dead box.
    readable = []
    for dp in PANIC_DIRS:
        if not _is_dir(dp):
            add("WARN", "panic dir %s absent (ok if unused)" % dp)
        elif os.access(str(dp), os.R_OK | os.X_OK):
            readable.append(dp)
            add("OK", "panic dir %s readable" % dp)
        else:
            add("FAIL", "panic dir %s exists but is NOT readable by this user -- "
                "crashes would be invisible (grant access, e.g. add the user to the "
                "dir's group)" % dp)
    if not readable:
        add("FAIL", "no readable panic dir (%s) -- the driver cannot detect a crash"
            % ", ".join(str(dp) for dp in PANIC_DIRS))

    # Pruning unlinks cores, which needs write on the *directory*, not the file.
    # Failing this doesn't stop fuzzing; it fills the disk until the breaker halts.
    for dp in PANIC_DIRS:
        if _is_dir(dp) and _has_any(dp, CORE_GLOBS):
            add("OK" if os.access(str(dp), os.W_OK) else "WARN",
                "cores in %s are prunable" % dp if os.access(str(dp), os.W_OK)
                else "cores in %s are NOT prunable by this user -- they accumulate "
                     "(~220MB each) until the low-disk breaker halts the campaign" % dp)

    # Each config in the campaign.
    for item in d["items"]:
        cfg = Path(item["config"])
        conf = read_json(cfg)
        if conf is None:
            add("FAIL", "config %s unreadable" % cfg.name)
            continue
        add("OK", "config %s loads" % cfg.name)
        if not conf.get("target"):
            add("WARN", "config %s has no \"target\"" % cfg.name)
        if not conf.get("enable_syscalls"):
            add("WARN", "config %s has empty enable_syscalls" % cfg.name)
        if not conf.get("workdir"):
            add("WARN", "config %s has no \"workdir\"" % cfg.name)
        # The quarantine rewrites disable_syscalls into the config on every
        # decision; a read-only config silently loses every bench.
        add("OK" if os.access(str(cfg), os.W_OK) else "FAIL",
            "config %s writable (quarantine rewrites disable_syscalls)" % cfg.name
            if os.access(str(cfg), os.W_OK)
            else "config %s is NOT writable by this user -- quarantine decisions "
                 "cannot be applied" % cfg.name)
        wd = conf.get("workdir")
        if wd:
            # fuzz-session creates the workdir on first start, so on a fresh tree
            # only its nearest existing ancestor can be tested -- that is what has
            # to be writable for the mkdir to succeed.
            probe = Path(wd)
            while not _is_dir(probe) and probe.parent != probe:
                probe = probe.parent
            ok = os.access(str(probe), os.W_OK)
            here = "" if probe == Path(wd) else " (nearest existing ancestor of %s)" % wd
            add("OK" if ok else "FAIL",
                "workdir %s writable%s" % (probe, here) if ok
                else "workdir %s is NOT writable by this user%s" % (probe, here))

    # Triage device flags (optional; else triage uses its defaults).
    tri = d.get("triage") or {}
    if tri:
        add("OK", "triage flags: %s" % ", ".join("%s=%s" % kv for kv in tri.items()))
        kd = tri.get("kcov_device")
        if kd and not Path(kd).exists():
            add("WARN", "triage.kcov_device %s not present" % kd)
    else:
        add("INFO", "no \"triage\" block -- triage uses each config's kext_coverage")
    # Each config's own kext id wins over the campaign's, so a multi-driver
    # campaign triages every crash against the right kext. Show what each will
    # use, and say plainly when a config cannot supply one.
    seen = []
    for it in d["items"]:
        kc = config_triage_flags(it["config"])
        seen.append((config_id(it["config"]), kc.get("kext_id"), kc.get("kcov_device")))
    if len({k for _, k, _ in seen if k is not None}) > 1:
        add("OK", "multi-driver campaign: kext_id taken per config (%s)"
            % ", ".join("%s=%s" % (n.split("_")[0], k) for n, k, _ in seen))
    for n, k, _ in seen:
        if k is None:
            add("WARN", "%s has no kext_coverage.kext_id -- triage falls back to "
                        "the campaign default, which is wrong for a multi-driver "
                        "run" % n)

    fg = free_gb()
    add("OK" if fg >= d["min_free_gb"] else "FAIL",
        "disk free %.1f GB (min %.1f)" % (fg, d["min_free_gb"]))
    add("OK" if Path("/usr/bin/python3").exists() else "WARN",
        "/usr/bin/python3 present" if Path("/usr/bin/python3").exists()
        else "/usr/bin/python3 missing -- daemon falls back to %s" % sys.executable)
    # syzkaller refuses to pair a manager/executor built from different sources:
    # the RPC handshake aborts with "mismatching manager/executor git revisions".
    # syz-ring-repro is the manager side during minimization, so a binary rebuilt
    # by hand (plain `go build` drops the Makefile's -ldflags -X GitRevision, and
    # stamps nothing) fails every probe. Build with `make`, not `go build`.
    revs = {}
    for binname, bp in (("syz-manager", Path(os.environ.get("SYZ_MANAGER_BIN",
                                                            REPO_ROOT / "bin/syz-manager"))),
                        ("syz-executor", REPO_ROOT / "bin/darwin_arm64/syz-executor"),
                        ("syz-ring-repro", RINGREPRO_BIN)):
        revs[binname] = _binary_revision(bp)
    known = {k: v for k, v in revs.items() if v}
    if len(known) < 3:
        add("WARN", "could not read a git revision from: %s (skipping the match check)"
            % ", ".join(sorted(k for k in revs if not revs[k])))
    elif len(set(known.values())) == 1:
        add("OK", "manager/executor/ring-repro all built from %s"
            % list(known.values())[0][:12])
    else:
        add("FAIL", "binaries built from DIFFERENT revisions -- the RPC handshake "
            "will abort every probe: %s. Rebuild with `make`, not `go build` "
            "(plain go build drops the -ldflags revision stamp)."
            % ", ".join("%s=%s" % (k, v[:12]) for k, v in sorted(known.items())))

    # The git-revision check above cannot see a DESCRIPTIONS mismatch: the executor
    # stores that hash as a C literal, but the Go tools compute it at runtime. The
    # observable proxy is the source: if any sys/<os>/*.txt is newer than the
    # executor binary, the executor was built from older descriptions, and any Go
    # tool rebuilt now will abort every probe with "mismatching manager/executor
    # system call descriptions".
    # Only meaningful where builds happen: in a published runtime tree the binary
    # and the .txt files are both copies stamped with the sync time, so comparing
    # their mtimes says nothing.
    execbin = REPO_ROOT / "bin/darwin_arm64/syz-executor"
    if not _is_dir(REPO_ROOT / ".git"):
        add("INFO", "descriptions-drift check skipped (not a build tree) -- run "
                    "`./scripts/fuzz-campaign.py doctor %s` from the syzkaller repo "
                    "to get this one" % name)
    elif execbin.exists():
        try:
            ebuilt = execbin.stat().st_mtime
            newer = sorted(t.name for t in (REPO_ROOT / "sys").rglob("*.txt")
                           if t.stat().st_mtime > ebuilt)
        except OSError:
            newer = []
        if newer:
            add("WARN", "syscall descriptions edited after syz-executor was built "
                "(%s) -- rebuilding any Go tool now yields a descriptions mismatch. "
                "Rebuild the executor too, or build tools from the committed "
                "descriptions." % ", ".join(newer[:4]))
        else:
            add("OK", "syscall descriptions no newer than the executor binary")

    # launchd sets WorkingDirectory to REPO_ROOT, so it is the cwd inherited by
    # every process the campaign spawns -- including the executor, which creates
    # its shmem file and tmpdir by relative path and dies at startup if it cannot.
    add("OK" if os.access(str(REPO_ROOT), os.W_OK) else "FAIL",
        "tree root %s writable (it is the spawned processes' cwd)" % REPO_ROOT
        if os.access(str(REPO_ROOT), os.W_OK)
        else "tree root %s is NOT writable by this user -- it is the launchd job's "
             "WorkingDirectory, so the executor dies at startup on every run "
             "(\"SYZFAIL: shmem open failed ... errno 13\")" % REPO_ROOT)

    # Everything the driver persists lives under these; unwritable means the
    # campaign cannot record a single incident.
    for dp in (STATE_DIR, BUGS_DIR, REPO_ROOT / "triage" / ".state"):
        exists = _is_dir(dp)
        probe = dp if exists else dp.parent
        ok = _is_dir(probe) and os.access(str(probe), os.W_OK)
        add("OK" if ok else "FAIL",
            "%s writable" % dp if ok else "%s is NOT writable by this user" % dp)
    add("INFO", "launchd daemon %s"
        % ("INSTALLED (%s)" % plist_path(name) if plist_path(name).exists() else "not installed"))
    # The user we are RUNNING as first -- that is the one whose agent matters and
    # the one whose home we can definitely read. SUDO_USER is checked too (that is
    # where a `sudo ./fuzz-campaign.py install --agent` without --user would have
    # put it), but under `sudo -u fuzz` that home belongs to someone else and
    # stat'ing it raises EACCES, so every probe is guarded.
    me = pwd.getpwuid(os.geteuid()).pw_name
    for u in dict.fromkeys(x for x in (me, os.environ.get("SUDO_USER")) if x):
        try:
            home = Path(pwd.getpwnam(u).pw_dir)
        except KeyError:
            continue
        ap = home / "Library" / "LaunchAgents" / ("%s.plist" % plist_label(name))
        if _exists(ap):
            add("INFO", "launchd agent INSTALLED for %s (%s)" % (u, ap))

    # A probe that hangs leaves an executor holding /dev/pishi until a reboot;
    # triage reboots by itself only if sudo lets this user run shutdown.
    if can_reboot():
        add("OK", "triage can reboot after a hang (sudo -n %s)" % " ".join(tri.REBOOT_CMD[2:]))
    else:
        add("WARN", "%s cannot run `%s` without a password: a hang during triage will "
                    "halt the campaign until someone reboots. Add to /etc/sudoers.d/fuzz: "
                    "`%s ALL=(root) NOPASSWD: /sbin/shutdown -r now`"
            % (me, " ".join(tri.REBOOT_CMD[2:]), me))

    fails = sum(1 for lvl, _ in checks if lvl == "FAIL")
    warns = sum(1 for lvl, _ in checks if lvl == "WARN")
    print("doctor: campaign %s" % name)
    marks = {"OK": "ok  ", "WARN": "WARN", "FAIL": "FAIL", "INFO": "--  "}
    for lvl, msg in checks:
        print("  [%s] %s" % (marks[lvl], msg))
    print("summary: %d fail, %d warn" % (fails, warns))
    if fails:
        print("-> NOT ready: fix the FAIL items above")
    elif warns:
        print("-> startable, but review the WARN items (especially panic dirs)")
    else:
        print("-> looks good")
    return 1 if fails else 0


def can_reboot():
    """True when sudo lets this user run triage's reboot command, no password."""
    try:
        return subprocess.run(["/usr/bin/sudo", "-n", "-l"] + tri.REBOOT_CMD[2:],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=10).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def cmd_list():
    CAMPAIGN_DIR.mkdir(parents=True, exist_ok=True)
    defs = sorted(CAMPAIGN_DIR.glob("*.json"))
    if not defs:
        print("no campaigns in %s" % CAMPAIGN_DIR)
        return
    rows = []
    for dp in defs:
        name = dp.stem
        d = load_def(name)
        s = load_state(name)
        status = s["status"]
        if brake_held(name):
            status += " (brake)"
        rows.append((name, status,
                     "%d/%d" % (min(s["cursor"] + 1, len(d["items"])), len(d["items"])),
                     "%d/%d" % (s["crashes"], s["hangs"]),
                     fmt_hms(lifetime(s, "active_seconds")),
                     fmt_hms(lifetime_wall(s))))
    tabulate(rows, ("CAMPAIGN", "STATUS", "CONFIG", "CRASH/HANG", "FUZZED", "WALL"))


def _set_status(name, status, reason=None):
    s = load_state(name)
    s["status"] = status
    if reason:
        s["halt_reason"] = reason
    if status == "running":
        s["halt_reason"] = None
        s["consec_fast_crashes"] = 0
        s["startup_failures"] = 0
    save_state(s)
    log("campaign %r -> %s" % (name, status))


def cmd_halt(name):
    s = load_state(name)
    if s.get("session_id"):
        session("stop", s["session_id"])
    _set_status(name, "halted", reason="halted by user")


def cmd_resume(name):
    # A brake outlives a resume on purpose: the next driver start would re-halt,
    # and silently marking the campaign "running" would look like it worked.
    held = brake_held(name)
    if held:
        die("brake is set (%s%s); clear it first:\n"
            "  ./scripts/fuzz-campaign.py brake %s--clear"
            % (held[0], " -- %s" % held[1] if held[1] else "",
               "" if held[0].endswith("STOP") else "%s " % name)
            + ("--global " if held[0].endswith("STOP") else ""))
    _set_status(name, "running")
    print("marked running; (re)start the driver: sudo ./scripts/fuzz-campaign.py run %s" % name)


# --- launchd -----------------------------------------------------------------
# A LaunchDaemon (system domain, /Library/LaunchDaemons) is the right vehicle:
# it runs at every boot as root with NO user logged in, which a bare-metal crash
# box that reboots itself needs. RunAtLoad fires once per boot — exactly one
# relaunch per crash-reboot — and the coordinator (cmd_run) re-enters whichever
# phase (fuzzing / triaging) the state file holds. It drives triage.py as a
# subprocess, so this is the ONLY launchd job to install; do NOT also install
# triage.py's own agent, which would double-drive the box.
LAUNCHD_DIR = Path("/Library/LaunchDaemons")

# A daemon inherits a minimal PATH, so give it common tool locations (Go, both
# homebrew prefixes) — though the coordinator prefers the built binary and does
# not rely on `go` at runtime. SYZ_* overrides set at install time are carried in.
DAEMON_PATH = "/usr/local/go/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
DAEMON_ENV_PASSTHROUGH = ("SYZ_PANIC_DIR", "SYZ_KERNEL_PANIC_DIR", "SYZ_RINGREPRO", "SYZ_FILTER")


def plist_label(name):
    return "com.fuzz-campaign.%s" % name


def plist_path(name):
    return LAUNCHD_DIR / ("%s.plist" % plist_label(name))


def _daemon_env():
    env = {"PATH": DAEMON_PATH}
    for k in DAEMON_ENV_PASSTHROUGH:
        v = os.environ.get(k)
        if v:
            env[k] = v
    return env


def _plist_xml(name, user=None):
    logf = STATE_DIR / ("%s.launchd.log" % name)
    # Prefer Apple's stable system python3 for a long-lived daemon; env python3
    # (e.g. Xcode's) can move or vanish across an Xcode update.
    py = "/usr/bin/python3" if Path("/usr/bin/python3").exists() else sys.executable
    args = [py, str(SESSION.parent / "fuzz-campaign.py"), "run", name]
    arg_xml = "\n".join("    <string>%s</string>" % a for a in args)
    env_xml = "\n".join("    <key>%s</key><string>%s</string>" % (k, v)
                        for k, v in _daemon_env().items())
    # A system LaunchDaemon runs as root unless pinned to a user. Pin it to the
    # dedicated fuzzing user so IOKit/coverage access and file ownership match the
    # interactive setup and the auto-login-after-panic user.
    user_xml = ("  <key>UserName</key><string>%s</string>\n" % user) if user else ""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0">\n<dict>\n'
        '  <key>Label</key><string>%s</string>\n'
        '  <key>ProgramArguments</key>\n  <array>\n%s\n  </array>\n'
        '  <key>EnvironmentVariables</key>\n  <dict>\n%s\n  </dict>\n'
        '%s'
        '  <key>WorkingDirectory</key><string>%s</string>\n'
        # Without this launchd may class a long-running agent as Background and
        # throttle its CPU/IO -- which on a fuzzer is a silent throughput cut.
        '  <key>ProcessType</key><string>Standard</string>\n'
        # umask 002 (decimal 2): everything the campaign creates under the shared
        # tree stays group-writable, so the build account can still inspect, clean
        # and re-sync workdirs that the fuzz account made. Without it fuzz creates
        # 0755/0644 and the two accounts fence each other out of their own tree.
        '  <key>Umask</key><integer>2</integer>\n'
        '  <key>RunAtLoad</key><true/>\n'
        '  <key>KeepAlive</key>\n  <dict>\n'
        '    <key>SuccessfulExit</key><false/>\n  </dict>\n'
        # Don't hot-loop if the driver exits nonzero immediately (e.g. a bug):
        # wait 30s between relaunches. A crash-reboot resets this anyway.
        '  <key>ThrottleInterval</key><integer>30</integer>\n'
        '  <key>StandardOutPath</key><string>%s</string>\n'
        '  <key>StandardErrorPath</key><string>%s</string>\n'
        '</dict>\n</plist>\n'
        % (plist_label(name), arg_xml, env_xml, user_xml, REPO_ROOT, logf, logf)
    )


def _user_can_read(user, path):
    """Can `user` actually reach `path`? None when we cannot tell.

    The plist bakes in THIS tree's paths, so installing the agent from a tree the
    fuzz user cannot traverse (the dev repo under a 0700 home) produces a job that
    launchd starts and python immediately kills -- with the failure buried in a log
    the user never opens. Fork + setuid so the check uses the target's real rights,
    supplementary groups included.
    """
    try:
        pw = pwd.getpwnam(user)
    except KeyError:
        return None
    if os.geteuid() != 0:
        return os.access(str(path), os.R_OK) if pw.pw_uid == os.geteuid() else None
    pid = os.fork()
    if pid == 0:                                  # child: drop to the target user
        try:
            os.setgroups(os.getgrouplist(user, pw.pw_gid))
            os.setgid(pw.pw_gid)
            os.setuid(pw.pw_uid)
            os._exit(0 if os.access(str(path), os.R_OK) else 1)
        except Exception:                         # noqa: BLE001
            os._exit(2)
    _, status = os.waitpid(pid, 0)
    code = os.WEXITSTATUS(status)
    return None if code == 2 else code == 0


def _check_tree_reachable(user):
    """Fail the install if `user` cannot read the tree the plist will point at."""
    probe = SCRIPT_DIR / "fuzz-campaign.py"
    ok = _user_can_read(user, probe)
    if ok is False:
        die("%s cannot read %s -- the agent would start and die immediately.\n"
            "The plist bakes in THIS tree's paths, so install from a tree %s can "
            "reach: publish with scripts/sync-fuzz-run.sh, then run `install` from "
            "there (e.g. /Users/Shared/fuzz-run/scripts/fuzz-campaign.py)."
            % (user, probe, user))
    if ok is None:
        log("could not verify %s can read %s -- check it before relying on the agent"
            % (user, probe))


def _chown_state_dirs(user):
    """Hand the campaign's own state dirs to the daemon/agent user."""
    for dpath in (STATE_DIR, CAMPAIGN_DIR, BUGS_DIR):
        try:
            dpath.mkdir(parents=True, exist_ok=True)
            shutil.chown(dpath, user=user)
        except (LookupError, PermissionError, OSError) as e:
            log("could not chown %s to %s: %s (ensure it is writable by %s)"
                % (dpath, user, e, user))


def cmd_install_agent(name, user=None):
    """Install a per-user LaunchAgent that runs the campaign inside the user's
    login (GUI) session -- needed when the fuzzed IOKit driver requires the console
    session. With auto-login enabled for that user, RunAtLoad fires at every boot
    (including a panic-reboot), so the campaign resumes unattended.

    Runnable as the user itself (no sudo) or as root (chowns to the user). Loads
    now if that user has an active GUI session; otherwise it loads at next login.
    """
    load_def(name)
    user = user or os.environ.get("SUDO_USER") or getpass.getuser()
    try:
        pw = pwd.getpwnam(user)
    except KeyError:
        die("no such user %r" % user)
    if not RINGREPRO_BIN.exists() and not os.environ.get("SYZ_RINGREPRO"):
        die("built binary %s is missing; a headless agent can't use `go run`. "
            "Build it (make target) or set SYZ_RINGREPRO." % RINGREPRO_BIN)
    _check_tree_reachable(user)
    agents = Path(pw.pw_dir) / "Library" / "LaunchAgents"
    agents.mkdir(parents=True, exist_ok=True)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    path = agents / ("%s.plist" % plist_label(name))
    path.write_text(_plist_xml(name, user=None))   # agent runs as the session user
    os.chmod(path, 0o644)
    if os.geteuid() == 0:                           # installed via sudo -> fix ownership
        try:
            shutil.chown(path, user=user)
            shutil.chown(agents, user=user)
        except (LookupError, PermissionError, OSError) as e:
            log("could not chown agent plist to %s: %s" % (user, e))
        _chown_state_dirs(user)
    log("wrote LaunchAgent %s" % path)
    dom = "gui/%d" % pw.pw_uid
    subprocess.run(["launchctl", "bootout", dom, str(path)], stderr=subprocess.DEVNULL)
    rc = subprocess.run(["launchctl", "bootstrap", dom, str(path)]).returncode
    if rc != 0:
        log("agent will load at %s's next login (auto-login); immediate bootstrap "
            "into %s failed rc=%d -- run it from within %s's session to start now."
            % (user, dom, rc, user))
    else:
        log("loaded LaunchAgent for %s in %s -- RunAtLoad + KeepAlive" % (user, dom))
        startup_hint(name)


def startup_hint(name):
    """What to expect in the first minutes, printed where you will read it.

    syz-manager compiles every enabled syscall before it serves rpc, so a large
    grammar leaves the box apparently idle for a couple of minutes at the start
    of each config. That silence is indistinguishable from a hang, and mistaking
    one for the other is how a missed rpc port cost a config an hour of budget.
    """
    try:
        d = load_def(name)
    except SystemExit:
        return
    counts = []
    for it in d["items"]:
        conf = read_json(it["config"]) or {}
        counts.append((config_id(it["config"]),
                       len(conf.get("enable_syscalls") or [])))
    big = max((n for _, n in counts), default=0)
    log("first minutes of each config are a GRAMMAR COMPILE, not a stall:")
    for cid, n in counts:
        log("  %-46s %3d syscall(s)%s"
            % (cid, n, "  (~2 min to serve rpc)" if n >= 60 else ""))
    if big >= 60:
        log("  the largest takes roughly two minutes before syz-executor appears")
    log("  a real stall is a manager with NO executor and no corpus growth after")
    log("  that; check with: /bin/ps -Ao command | grep syz-executor")


def cmd_install(name, user=None, agent=False):
    if agent:
        return cmd_install_agent(name, user)
    load_def(name)   # validate it exists
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    if os.geteuid() != 0:
        die("install writes to %s and loads a system LaunchDaemon; run with sudo" % LAUNCHD_DIR)
    # A daemon runs with a minimal PATH and cannot use the coordinator's `go run`
    # fallback, so the built binary must exist (or SYZ_RINGREPRO must point at one).
    if not RINGREPRO_BIN.exists() and not os.environ.get("SYZ_RINGREPRO"):
        die("built binary %s is missing; a daemon can't use the `go run` fallback. "
            "Build it first: make target   (or set SYZ_RINGREPRO)" % RINGREPRO_BIN)
    if user:
        _check_tree_reachable(user)
        _chown_state_dirs(user)   # daemon runs as this user; let it persist state
    path = plist_path(name)
    path.write_text(_plist_xml(name, user))
    os.chmod(path, 0o644)
    log("wrote %s" % path)
    subprocess.run(["launchctl", "bootout", "system", str(path)],
                   stderr=subprocess.DEVNULL)
    rc = subprocess.run(["launchctl", "bootstrap", "system", str(path)]).returncode
    if rc != 0:
        die("launchctl bootstrap failed (rc=%d)" % rc)
    log("loaded %s -- RunAtLoad + KeepAlive; survives reboots and runs headless" % plist_label(name))
    startup_hint(name)
    print("  logs: %s" % (STATE_DIR / ("%s.launchd.log" % name)))
    print("  note: this is the ONLY job to install -- it drives triage.py itself; "
          "do not also `triage.py install`.")


def stop_campaign_session(name):
    """Stop whatever fuzzing session this campaign has running, if any."""
    s = load_state(name)
    sid = s.get("session_id")
    if not sid:
        return
    info = inspect(sid)
    if not info.get("found"):
        return
    if info.get("status") == "running" or info.get("pid_alive"):
        log("stopping fuzzing session %s (pid %s) before unloading the job"
            % (sid, info.get("pid")))
        session("stop", sid)
    else:
        log("session %s already stopped" % sid)


# --- the reliable stop ------------------------------------------------------
def box_busy():
    """[(what, pid, cmd)] of processes actually driving the box.

    running_processes() substring-matches the whole command line. That is right
    for the stop paths, which filter again by binary path, and wrong here: a shell
    whose argv merely mentions "syz-manager" reads as a live campaign. Match the
    EXECUTED program instead (argv[0]'s basename) and skip our own process tree.
    """
    mine = {os.getpid(), os.getppid()}
    out = []
    for pid, cmd in running_processes(""):
        if pid in mine:
            continue
        parts = cmd.split()
        base = Path(parts[0]).name if parts else ""
        if base == "syz-manager":
            out.append(("syz-manager", pid, cmd))
            continue
        # A supervisor is an interpreter (or the shebang'd script) running THIS
        # script's `run` subcommand. Requiring argv[0] to be one of those keeps a
        # `zsh -c "... fuzz-campaign.py run ..."` -- whose real supervisor shows up
        # as its own process anyway -- from being counted twice, and keeps `status`
        # and `doctor` from being counted at all.
        if not (base.lower().startswith("python") or base == "fuzz-campaign.py"):
            continue
        for i, tok in enumerate(parts[:-1]):
            if tok.endswith("fuzz-campaign.py") and parts[i + 1] == "run":
                out.append(("supervisor", pid, cmd))
                break
    return out


def running_processes(pattern):
    """[(pid, command)] of live processes whose command contains `pattern`.

    Deliberately reads the process table rather than any state file. Every stop
    path used to trust the session record, and the record can be wrong in the
    worst direction: pid_alive() returned False for a manager that had been
    running for twenty hours, so stop_one() refused to touch it and the thing
    kept fuzzing. Reality is what `ps` says.
    """
    try:
        out = subprocess.run(["/bin/ps", "-Ao", "pid,command"],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             text=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    found = []
    for line in (out or "").splitlines()[1:]:
        line = line.strip()
        if not line or pattern not in line:
            continue
        pid, _, cmd = line.partition(" ")
        try:
            found.append((int(pid), cmd.strip()))
        except ValueError:
            continue
    return found


def campaign_processes(s):
    """(managers, executors) belonging to this campaign, from the process table.

    Managers are matched on the config path so a stop cannot reach into an
    unrelated session. Executors carry no config, so they are matched by the
    session's scratch directory, and otherwise left alone.
    """
    cfg = s.get("current_config") or ""
    managers = [p for p in running_processes("syz-manager") if cfg and cfg in p[1]]
    # Executors are matched on OUR executor binary, not on the session id: a
    # session id never appears in an executor's argv (it is only the cwd), so
    # matching on it found nothing and stop reported "all processes gone" while
    # two executors were still running -- one of them unkillable and holding the
    # coverage device. Only one campaign runs at a time (they share /dev/pishi),
    # so every executor under our tree belongs to it.
    exe = str(REPO_ROOT / "bin" / "darwin_arm64" / "syz-executor")
    executors = [p for p in running_processes("syz-executor") if exe in p[1]]
    return managers, executors


def proc_stat(pid):
    """ps STAT for a pid, or "". 'U' is uninterruptible sleep -- unkillable."""
    try:
        out = subprocess.run(["/bin/ps", "-o", "stat=", "-p", str(int(pid))],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             text=True, timeout=5).stdout.strip()
        return out.split()[0] if out else ""
    except (OSError, ValueError, subprocess.SubprocessError):
        return ""


def _signal(pid, sig, what):
    try:
        os.kill(pid, sig)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        log("  cannot signal %s pid %d (owned by another user -- re-run with sudo)"
            % (what, pid))
        return False
    except OSError as e:
        log("  could not signal %s pid %d: %s" % (what, pid, e))
        return False


def agent_domains(name):
    """launchd domains this campaign's agent may be loaded in: gui/<uid> of each
    user with its plist in ~/Library/LaunchAgents, and of the state file's
    owner (install chowns it to the agent user)."""
    label = plist_label(name)
    uids = []
    try:
        uids.append(state_path(name).stat().st_uid)
    except OSError:
        pass
    for pw in pwd.getpwall():
        if pw.pw_uid >= 500 and _exists(
                Path(pw.pw_dir) / "Library" / "LaunchAgents" / ("%s.plist" % label)):
            uids.append(pw.pw_uid)
    return ["gui/%d" % u for u in dict.fromkeys(uids) if u != 0]


def cmd_stop(name, grace=30, keep_agent=False):
    """End a campaign's fuzzing for good, whether or not a supervisor is alive.

    The other stop paths all assume the supervisor is running: `halt` writes a
    flag it has to read, and the brake is checked in its loop. When the
    supervisor is gone -- killed by a `launchctl bootout`, say -- syz-manager
    keeps fuzzing detached, the campaign still reports "running" because nothing
    updates it, and the orphan holds /dev/pishi against the next campaign. This
    is the path that does not care.

    Order matters: stop the relaunch first, or launchd restarts the supervisor
    in the middle of the teardown.
    """
    s = load_state(name)
    log("stopping campaign %r" % name)

    # 1. Nothing may bring it back while we work.
    if not keep_agent:
        label = plist_label(name)
        for dom in agent_domains(name) + ["system"]:
            subprocess.run(["launchctl", "bootout", "%s/%s" % (dom, label)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log("  launchd job %s booted out (if it was loaded)" % label)
    s["status"] = "halted"
    s["halt_reason"] = s.get("halt_reason") or "stopped by user"
    save_state(s)

    # 2. Graceful: let fuzz-session close the session down properly, so the
    #    registry, the scratch cleanup and the final state are all consistent.
    #    Bounded, because a graceful step that can hang forever defeats the whole
    #    purpose of this command -- and one did: a scratch retire that could not
    #    rename fell back to walking 65,000 directories it had no permission to
    #    delete. Whatever survives the timeout is handled by the escalation below.
    if s.get("session_id"):
        try:
            subprocess.run([sys.executable, str(SESSION), "stop", s["session_id"]],
                           timeout=max(grace, 30))
        except subprocess.TimeoutExpired:
            log("  fuzz-session stop did not return in %ds; escalating"
                % max(grace, 30))
        except OSError as e:
            log("  could not run fuzz-session stop: %s" % e)

    # 3. Verify against the process table, and escalate only against what
    #    survived. A graceful stop that silently did nothing is the failure
    #    this whole command exists to prevent.
    deadline = time.time() + grace
    while time.time() < deadline:
        managers, executors = campaign_processes(s)
        if not managers and not executors:
            log("  all processes gone")
            break
        time.sleep(1)
    managers, executors = campaign_processes(s)
    for pid, cmd in managers + executors:
        if proc_stat(pid).startswith("U"):
            log("  pid %d is wedged in the kernel (STAT U); signalling is futile"
                % pid)
            continue
        log("  still alive after %ds: pid %d  %s" % (grace, pid, cmd[:70]))
        _signal(pid, signal.SIGINT, "process")
    if managers or executors:
        time.sleep(3)
        for pid, cmd in campaign_processes(s)[0] + campaign_processes(s)[1]:
            if proc_stat(pid).startswith("U"):
                continue        # unreachable by any signal; reported below
            log("  SIGKILL pid %d (did not exit on SIGINT)" % pid)
            _signal(pid, signal.SIGKILL, "process")

    # 4. Say what is true now, and fail loudly if anything is left: a stop that
    #    reports success while a manager still holds /dev/pishi is worse than
    #    one that reports failure.
    managers, executors = campaign_processes(s)
    if managers or executors:
        wedged = [(pid, cmd) for pid, cmd in managers + executors
                  if proc_stat(pid).startswith("U")]
        log("STOP INCOMPLETE: %d manager(s), %d executor(s) still running"
            % (len(managers), len(executors)))
        for pid, cmd in managers + executors:
            log("  pid %d [%s]  %s" % (pid, proc_stat(pid) or "?", cmd[:70]))
        if wedged:
            log("  pid(s) %s are in uninterruptible sleep: wedged inside a kernel "
                "call that never returns. SIGKILL cannot reach them and they hold "
                "the coverage device until the machine REBOOTS."
                % ", ".join(str(p) for p, _ in wedged))
            log("  capture the stack first -- it names the blocked call:")
            log("    sudo %s diagnose-hang" % SESSION)
        else:
            log("  they are probably owned by another user -- re-run with sudo")
        return 1
    log("campaign %r stopped: no manager, no executor, nothing holding the "
        "coverage device" % name)
    return 0


def cmd_uninstall(name, user=None, agent=False):
    """Stop the daemon/agent now and prevent it from ever restarting.

    bootout unloads the job and kills its running instance; removing the plist
    means RunAtLoad cannot fire again on the next boot/login. (`halt` only pauses
    the campaign and leaves the job installed.)

    The fuzzing SESSION is stopped first, and that is not optional. fuzz-session
    spawns syz-manager detached, so it is not part of the launchd job's process
    tree: booting out the agent kills the supervisor and leaves the manager
    fuzzing on with nobody watching it. The campaign then still reports
    "running" -- nothing is left to update its state -- while the orphan holds
    /dev/pishi and blocks the next campaign.
    """
    stop_campaign_session(name)
    label = plist_label(name)
    if agent:
        user = user or os.environ.get("SUDO_USER") or getpass.getuser()
        try:
            pw = pwd.getpwnam(user)
        except KeyError:
            die("no such user %r" % user)
        apath = Path(pw.pw_dir) / "Library" / "LaunchAgents" / ("%s.plist" % label)
        dom = "gui/%d" % pw.pw_uid
        subprocess.run(["launchctl", "bootout", "%s/%s" % (dom, label)], stderr=subprocess.DEVNULL)
        subprocess.run(["launchctl", "bootout", dom, str(apath)], stderr=subprocess.DEVNULL)
        if apath.exists():
            apath.unlink()
            log("removed %s" % apath)
        else:
            log("no agent plist at %s" % apath)
        log("agent %s unloaded; it will NOT restart at %s's next login" % (label, user))
        return
    if os.geteuid() != 0:
        die("uninstall unloads a system LaunchDaemon; run with sudo")
    path = plist_path(name)
    # Boot out by label and by path, so it works whether or not the file is still
    # on disk; both unload the job and terminate the running instance.
    subprocess.run(["launchctl", "bootout", "system/%s" % label], stderr=subprocess.DEVNULL)
    subprocess.run(["launchctl", "bootout", "system", str(path)], stderr=subprocess.DEVNULL)
    if path.exists():
        path.unlink()
        log("removed %s" % path)
    else:
        log("no plist at %s" % path)
    log("daemon %s unloaded; it will NOT restart, including across reboots" % label)


# --- exclude / include: bench a syscall, then rotate it back -----------------
# Excluding is not permanent suppression: it benches the syscall that is
# crash-dominating so coverage on the rest can build, and `include` rotates it
# back in later (typically once coverage plateaus, then another is benched). The
# campaign owns the *strategy* (which config, when, how to resume); it delegates
# the one grammar-dependent step — reading the culprit and listing its surviving
# syscall names — to `syz-ring-repro -emit-json`, then edits the config here.
# The names go into disable_syscalls, which syz-manager applies AFTER
# enable_syscalls and subtracts, so a name is benched whether the config enabled
# it explicitly or via a `*` glob — no recompile. `include` reverses it.
def ringrepro_cmd():
    """argv prefix for syz-ring-repro: the built binary, else a dev `go run`."""
    if RINGREPRO_BIN.exists():
        return [str(RINGREPRO_BIN)]
    log("syz-ring-repro binary not at %s; falling back to `go run`" % RINGREPRO_BIN)
    return ["go", "run", "./tools/syz-ring-repro"]


def emit_syscalls(culprit, out=None):
    """Translate a minimized culprit into the list of syscall names to disable.

    Runs `syz-ring-repro -emit-json`, which writes syscalls.json next to the
    culprit (unless out is given), and returns the names. Raises RuntimeError if
    the tool fails or writes no readable list.

    Lives in quarantine.py so the coordinator and the standalone `quarantine.py
    crash --culprit` path cannot drift; this wrapper only adds campaign logging.
    """
    return qm.emit_syscalls(culprit, out, log=log)


def write_config(path, cfg):
    """Rewrite a syzkaller .cfg atomically, keeping its 4-space JSON style."""
    path = Path(path)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w") as f:
        json.dump(cfg, f, indent=4)
        f.write("\n")
    os.replace(tmp, path)


def exclude_syscalls(names, cfg_path, dry_run=False):
    """Bench syscalls: add names to cfg_path's disable_syscalls, idempotently.

    In place. Returns (added, already): names newly benched, and names that were
    already benched. With dry_run, computes the result without touching the file.
    """
    cfg_path = Path(cfg_path)
    cfg = read_json(cfg_path)
    if cfg is None:
        raise RuntimeError("cannot read config %s" % cfg_path)
    disabled = list(cfg.get("disable_syscalls", []))
    present = set(disabled)
    added, already = [], []
    for n in names:
        if n in present:
            already.append(n)
            continue
        disabled.append(n)
        present.add(n)
        added.append(n)
    if added and not dry_run:
        cfg["disable_syscalls"] = disabled
        write_config(cfg_path, cfg)
    return added, already


def include_syscalls(names, cfg_path, all_=False, dry_run=False):
    """Rotate benched syscalls back in: remove names from disable_syscalls.

    The inverse of exclude_syscalls — a pure config edit by name, no grammar or
    culprit needed. all_ empties the whole benched set.
    Returns (removed, absent): names taken out, and names that were not benched.
    """
    cfg_path = Path(cfg_path)
    cfg = read_json(cfg_path)
    if cfg is None:
        raise RuntimeError("cannot read config %s" % cfg_path)
    disabled = list(cfg.get("disable_syscalls", []))
    if all_:
        removed, absent, disabled = disabled[:], [], []
    else:
        present = set(disabled)
        wanted = set(names)
        removed = [n for n in names if n in present]
        absent = [n for n in names if n not in present]
        disabled = [d for d in disabled if d not in wanted]
    if removed and not dry_run:
        cfg["disable_syscalls"] = disabled
        write_config(cfg_path, cfg)
    return removed, absent


# --- quarantine adapter: crash-aware temporary suppression -------------------
# The coordinator's automatic path uses quarantine.py (per-config state) instead
# of a permanent blacklist: a NEW crash is SUSPECT (resume enabled, no bench); a
# confirmed one is classified HARD/REPETITION/SOFT and the whole disabled set is
# written into the config. exclude/include stay as manual tools.
def qstate_path(cfg):
    return STATE_DIR / ("quarantine_%s.json" % config_id(cfg))


def load_qstate(cfg):
    qs = qm.load_state(str(qstate_path(cfg)))
    if not qs.get("config"):
        qs["config"] = str(cfg)
    return qs


def save_qstate(cfg, qs):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    qm.save_state(str(qstate_path(cfg)), qs)


def apply_disabled(cfg, qs):
    """Write disable_syscalls = the quarantine's full disabled set into cfg.

    Unlike exclude (incremental), this makes the config exactly match the
    scheduler: benched selectors that became ACTIVE/rotated out are also removed.
    Returns True if the file changed.
    """
    cfg = Path(cfg)
    c = read_json(cfg)
    if c is None:
        raise RuntimeError("cannot read config %s" % cfg)
    want = qm.disabled_set(qs)
    if list(c.get("disable_syscalls", [])) == want:
        return False
    c["disable_syscalls"] = want
    write_config(cfg, c)
    log("quarantine: disable_syscalls=%s in %s" % (want, cfg.name))
    return True


def culprit_sequence(culprit):
    """The minimized culprit as a selector sequence for classification.

    See qm.culprit_sequence: -emit-json for the distinct selectors, expanded to N
    entries when there is only one so HARD (one call) and REPETITION (many calls)
    are told apart.
    """
    return qm.culprit_sequence(culprit, log=log)


def quarantine_decide(s, sig):
    """On a crash (before triage), apply the SUSPECT gate and decide whether to
    spend a triage on this signature. Returns "triage" or "resume".

    - NEW signature      -> record SUSPECT (resume enabled), no triage.
    - tolerated recurrence-> increment/escalate in place, no triage.
    - suspect recurrence  -> "triage" (confirm it, classify at DONE).
    - disabled/rotating   -> "triage" (an escape: learn the new path at DONE).
    """
    cfg = s.get("current_config")
    if not cfg:
        return "resume"
    qs = load_qstate(cfg)
    rec = qs["catalog"].get(sig)
    if rec is None:
        qm.on_crash(qs, sig, None)             # SUSPECT, occ 1, seq deferred
        save_qstate(cfg, qs)
        log("crash %s: NEW -> SUSPECT (occ 1); resuming enabled" % sig)
        return "resume"
    if rec["disposition"] == qm.TOLERATED:
        res = qm.on_crash(qs, sig, None)       # increment; escalate if over budget
        save_qstate(cfg, qs)
        if res["disposition"] == qm.DISABLED:
            apply_disabled(cfg, qs)
            log("crash %s: tolerated REPETITION escalated -> disabled" % sig)
        else:
            log("crash %s: tolerated (occ %d); resuming"
                % (sig, rec["occurrence_count"]))
        return "resume"
    # qm.SUSPECTED ("suspect") is the DISPOSITION; qm.SUSPECT ("SUSPECT") is the
    # CATEGORY. Two letters apart and both live on the same record -- comparing a
    # disposition against the category constant silently never matches, which is
    # how every ordinary confirmation came out labelled "ESCAPED".
    why = ("CONFIRMED (occ %d) -- minimizing to a culprit"
           % (rec["occurrence_count"] + 1) if rec["disposition"] == qm.SUSPECTED
           else "ESCAPED a %s bench -- re-minimizing to learn the new path"
                % rec["disposition"])
    log("crash %s: %s" % (sig, why))
    return "triage"                            # suspect-confirm or escape


def quarantine_apply_culprit(s, sig, cfg, culprit):
    """At triage DONE: classify the culprit and write the config's disabled set."""
    qs = load_qstate(cfg)
    try:
        seq = culprit_sequence(culprit)
    except RuntimeError as e:
        log("quarantine: cannot read culprit selectors (%s); suppression skipped" % e)
        return
    res = qm.on_crash(qs, sig, seq)
    # Keep the culprit program path on the record so `replay` can verify it later.
    rec = qs["catalog"].get(sig)
    if rec is not None:
        rec["culprit"] = str(culprit)
    save_qstate(cfg, qs)
    apply_disabled(cfg, qs)
    log("quarantine: %s -> %s/%s; disabled=%s"
        % (sig, res["category"], res["disposition"], res["disabled"]))


def attribute_bug(sig, culprit, job, verified):
    """Record the minimized reproducer against the bug the signature identifies.

    Best-effort: a campaign must not stall because the inventory is unavailable.
    The quarantine decision has already been applied by the time we get here."""
    if not BUG_REGISTRY.exists():
        return
    try:
        selectors = culprit_sequence(culprit)
    except RuntimeError as e:
        log("bug_registry attribute: cannot read culprit selectors (%s)" % e)
        selectors = []
    cmd = [sys.executable, str(BUG_REGISTRY), "--bugs", str(BUGS_DIR),
           "attribute", "--sig", sig, "--culprit", str(culprit), "--job", job]
    for sel in dict.fromkeys(selectors):        # de-dup, keep order
        cmd += ["--selector", sel]
    if verified:
        cmd.append("--verified")
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True)
    except OSError as e:
        log("bug_registry attribute failed: %s" % e)
        return
    for line in (p.stdout or "").splitlines():
        if line.strip():
            log("bug_registry: %s" % line.strip())


def route_bug_registry(panic_path, campaign=None, config=None, origin="fuzz"):
    """Best-effort: catalog a panic in the bug registry (the reportable inventory
    that end-of-campaign replay iterates). Tolerated crashes are catalogued too."""
    if not BUG_REGISTRY.exists():
        return []
    ids = []
    try:
        BUGS_DIR.mkdir(parents=True, exist_ok=True)
        p = subprocess.run(
            [sys.executable, str(BUG_REGISTRY), "--bugs", str(BUGS_DIR),
             "route", str(panic_path), "--origin", origin]
            + (["--campaign", campaign] if campaign else [])
            + (["--config", config_id(config)] if config else []),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if p.returncode != 0:
            log("bug_registry route rc=%d for %s: %s"
                % (p.returncode, Path(panic_path).name, (p.stdout or "").strip()))
            return ids
        # Echo the routing decision (NEW BUG / new crash / dup + the bug id and
        # key). Silently succeeding here is what made the bug inventory feel like
        # it was not being written at all.
        for line in (p.stdout or "").splitlines():
            if line.strip():
                log("bug_registry: %s  <- %s" % (line.strip(), Path(panic_path).name))
                ids += re.findall(r"\bBUG-\d+\b", line)
    except Exception as e:  # noqa: BLE001 - cataloguing must never stall the campaign
        log("bug_registry route failed for %s: %s" % (panic_path, e))
    return ids


def cmd_replay(name, as_json=False):
    """End-of-campaign verification manifest: every catalogued crash with its
    culprit and expected signature, so each can be replayed to confirm it still
    reproduces after the whole campaign.

    Building the authoritative list is done here; re-executing a saved culprit
    needs the device (syz-ring-repro replays the ring buffer, not a saved .syz),
    so this emits the list + the confirm command rather than faking a replay.
    """
    d = load_def(name)
    rows, seen = [], []
    for item in d["items"]:
        cfg = item["config"]
        if cfg in seen:
            continue
        seen.append(cfg)
        qs = load_qstate(cfg)
        for sig, rec in qs.get("catalog", {}).items():
            culprit = rec.get("culprit")
            rows.append({
                "config": config_id(cfg), "crash_id": sig,
                "category": rec.get("category"), "disposition": rec.get("disposition"),
                "occurrences": rec.get("occurrence_count"),
                "culprit": culprit,
                "minimized_sequence": rec.get("minimized_sequence"),
                "replayable": bool(culprit and Path(culprit).exists()),
            })
    if as_json:
        json.dump(rows, sys.stdout, indent=2)
        print()
        return 0
    if not rows:
        print("no catalogued crashes for campaign %r" % name)
        return 0
    print("%-10s %-18s %-11s %-4s %-7s %s"
          % ("category", "crash_id", "disposition", "occ", "replay?", "culprit"))
    for r in rows:
        print("%-10s %-18s %-11s %-4s %-7s %s"
              % (r["category"] or "?", (r["crash_id"] or "?")[:18],
                 r["disposition"] or "?", r["occurrences"] or 0,
                 "yes" if r["replayable"] else "NO",
                 r["culprit"] or "(no culprit stored)"))
    n_ok = sum(1 for r in rows if r["replayable"])
    print("\n%d crash(es); %d with a stored culprit to replay." % (len(rows), n_ok))
    print("Verify one on-device: replay its culprit through the executor, then\n"
          "  crash_fingerprint.py match-since <crash_id> <since_epoch>")
    return 0


def quarantine_rotate_due(s):
    """If a SOFT group's rotation is due, advance it, persist, and signal the
    coordinator to re-apply the config + resume. Coverage-stall telemetry is used
    when the session exposes it; otherwise the absolute rotate_cap drives it."""
    cfg = s.get("current_config")
    if not cfg:
        return False
    qs = load_qstate(cfg)
    if not qs["soft_groups"]:
        return False
    info = inspect(s.get("session_id")) if s.get("session_id") else {}
    exec_total = info.get("exec_total") or 0     # per run: resets to 0 each (re)start
    cover = info.get("coverage")
    # Track executions since the last coverage bump, within this run.
    if cover is not None and cover != s.get("q_last_cover"):
        s["q_last_cover"] = cover
        s["q_cover_exec_mark"] = exec_total
    mark = s.get("q_cover_exec_mark")
    since_cov = (exec_total - mark) if mark is not None else 0
    if qm.maybe_rotate(qs, exec_total, since_cov):
        save_qstate(cfg, qs)
        return True
    return False


def _target_config(name, config):
    """The config a command should edit: --config, else the crashed config."""
    s = load_state(name)
    cfg = config or s.get("current_config")
    if not cfg:
        die("no config to edit: campaign %r has no current config; pass --config" % name)
    cfg = Path(cfg)
    if not cfg.exists():
        die("config not found: %s" % cfg)
    return cfg


def cmd_exclude(name, culprit, config=None, dry_run=False):
    """Bench a minimized culprit's syscall(s) so fuzzing can resume on the rest.

    Not permanent: `include` rotates them back in later. Translates the culprit
    to a syscall-name list via syz-ring-repro, then benches those names in the
    config. Targets the campaign's crashed config (state.current_config) unless
    --config. Always exit 0 (nothing to fail on beyond a bad culprit/config).
    """
    cfg = _target_config(name, config)
    try:
        names = emit_syscalls(culprit)
        added, already = exclude_syscalls(names, cfg, dry_run=dry_run)
    except RuntimeError as e:
        die(str(e))

    verb = "would bench" if dry_run else "benched"
    for n in added:
        log("%s in %s: %s" % (verb, cfg.name, n))
    for n in already:
        log("already benched in %s: %s" % (cfg.name, n))
    if not added and not already:
        log("nothing to bench from %s" % culprit)
    return 0


def cmd_include(name, syscalls, config=None, all_=False, dry_run=False):
    """Rotate benched syscalls back into the config (inverse of exclude).

    Names one or more syscalls to re-enable, or --all to clear the benched set.
    A pure config edit; exit 0 always (nothing to fail on beyond a bad config).
    """
    cfg = _target_config(name, config)
    if not syscalls and not all_:
        die("give one or more syscall names to re-include, or --all")
    try:
        removed, absent = include_syscalls(syscalls, cfg, all_=all_, dry_run=dry_run)
    except RuntimeError as e:
        die(str(e))

    verb = "would re-include" if dry_run else "re-included"
    for n in removed:
        log("%s in %s: %s" % (verb, cfg.name, n))
    for n in absent:
        log("not benched in %s: %s" % (cfg.name, n))
    if not removed:
        log("nothing to re-include in %s" % cfg.name)
    return 0


def cmd_forget_exhausted(name, sig=None):
    """Clear signatures recorded as exhausted so they can be triaged again.

    A signature lands there when minimization found nothing smaller than the
    whole ring to blame: nothing reproduced at all (often the environment -- a
    missing executor_name), only the unmerged ring did, or the search kept
    hanging. Once the cause is fixed, the bug is worth another pass -- but only
    then, which is why this is a deliberate command and not automatic.
    """
    s = load_state(name)
    if not s:
        die("no campaign '%s'" % name)
    have = s.get("exhausted_sigs") or []
    if not have:
        print("campaign %s has no exhausted signatures" % name)
        return 0
    if sig:
        if sig not in have:
            die("%s is not recorded as exhausted for %s (have: %s)"
                % (sig, name, ", ".join(have)))
        have.remove(sig)
        (s.get("exhausted_why") or {}).pop(sig, None)
        print("forgot %s; it will be triaged again on its next crash" % sig)
    else:
        print("forgot %d signature(s): %s" % (len(have), ", ".join(have)))
        have = []
        s["exhausted_why"] = {}
    s["exhausted_sigs"] = have
    save_state(s)
    return 0


def cmd_brake(name, global_=False, reason=None, clear=False, where=False):
    """Set or clear the brake. Setting one does not stop a running driver by
    itself -- it stops the NEXT one, which is the case a running driver cannot
    cover: the box panicking its way through every relaunch."""
    g, per = brake_paths(name) if name else (GLOBAL_BRAKE, None)
    target = g if (global_ or not name) else per
    if where:
        print("global      : %s" % g)
        if per:
            print("per-campaign: %s" % per)
        print("from Recovery: touch \"%s\"" % recovery_hint())
        held = brake_held(name) if name else (
            (str(g), g.read_text().strip()) if g.exists() else None)
        print("currently   : %s" % ("SET -- %s" % held[0] if held else "not set"))
        return 0
    if clear:
        try:
            target.unlink()
            log("brake cleared: %s" % target)
        except FileNotFoundError:
            log("no brake at %s" % target)
        except OSError as e:
            die("cannot clear brake %s: %s" % (target, e))
        if name:
            log("the campaign stays halted until: fuzz-campaign.py resume %s" % name)
        return 0
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((reason or "set by %s at %s" % (getpass.getuser(), now_iso())) + "\n")
    except OSError as e:
        die("cannot set brake %s: %s" % (target, e))
    log("BRAKE SET: %s" % target)
    log("  the next driver start will halt instead of fuzzing")
    log("  clear with: fuzz-campaign.py brake %s--clear"
        % ("%s " % name if name and not global_ else "--global "))
    return 0


# --- cli ---------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(description="autonomous campaign driver over fuzz-session.py")
    sub = p.add_subparsers(dest="cmd")

    sp = sub.add_parser("new", help="author a campaign definition")
    sp.add_argument("name")
    sp.add_argument("configs", nargs="+", help="config paths, fuzzed in this order")
    sp.add_argument("--budget-hours", type=float, default=DEFAULTS["budget_hours"])
    sp.add_argument("--loop", action="store_true", help="restart the list when done")
    sp.add_argument("--poll-seconds", type=int, default=DEFAULTS["poll_seconds"])
    sp.add_argument("--hang-after-seconds", type=int, default=DEFAULTS["hang_after_seconds"])
    sp.add_argument("--max-crashes", type=int, default=DEFAULTS["max_crashes"])
    sp.add_argument("--min-free-gb", type=float, default=DEFAULTS["min_free_gb"])
    sp.add_argument("--keep-cores", type=int, default=DEFAULTS["keep_cores"])
    sp.add_argument("--force", action="store_true")
    # Baked into the def's "triage" block and replayed to `triage.py new` on every
    # bug the coordinator decides to minimize. Mirror what the manual runs used.
    sp.add_argument("--kcov-device", help="coverage device passed to triage (e.g. /dev/pishi)")
    sp.add_argument("--kext-id", type=int, help="Pishi kext id passed to triage")
    sp.add_argument("--executor", help="syz-executor for triage (default: bin/darwin_arm64/syz-executor)")
    sp.add_argument("--ringrepro", help="syz-ring-repro for triage (default: bin/darwin_arm64/syz-ring-repro)")
    sp.add_argument("--sandbox", help="sandbox mode passed to triage")
    sp.add_argument("--max-k", type=int, help="triage minimization width cap")
    # Circuit-breaker overrides. A crash-heavy target needs these loosened, or the
    # breaker halts the campaign before any bug reaches its second occurrence.
    sp.add_argument("--crashloop-limit", type=int,
                    help="consecutive fast crashes before halting (default %d)"
                         % DEFAULTS["crashloop_limit"])
    sp.add_argument("--crashloop-min-execs", type=int,
                    help="a crash before this many programs executed counts as "
                         "fast (default %d)" % DEFAULTS["crashloop_min_execs"])
    sp.add_argument("--triage-max-boots", type=int,
                    help="advances before giving up on a triage (default %d)"
                         % DEFAULTS["triage_max_boots"])
    sp.add_argument("--budget-clock", choices=BUDGET_CLOCKS,
                    help="what --budget-hours measures: 'fuzz' charges time from "
                         "each run's first executed program (startup excluded; "
                         "still not pure execution time), 'wall' also charges "
                         "startup, minimization and reboots, "
                         "'real' is elapsed time since the config started and "
                         "keeps running through halts, reboots and downtime -- "
                         "the one that means 'stop 2h from now' "
                         "(default %s)" % DEFAULTS["budget_clock"])

    sp = sub.add_parser("stop",
                        help="end a campaign's fuzzing for good, whether or not "
                             "a supervisor is alive (verifies against the "
                             "process table)")
    sp.add_argument("name")
    sp.add_argument("--grace", type=int, default=30,
                    help="seconds to wait for a graceful exit before escalating "
                         "to SIGINT/SIGKILL (default 30)")
    sp.add_argument("--keep-agent", action="store_true",
                    help="leave the launchd job loaded (it will relaunch the "
                         "supervisor, which then sees the halt and exits)")
    sp.set_defaults(func=None)

    sp = sub.add_parser("forget-exhausted",
                        help="allow re-triage of bugs whose minimization reproduced "
                             "nothing (do this after fixing the environment)")
    sp.add_argument("name")
    sp.add_argument("--sig", help="one signature to forget (default: all)")

    sp = sub.add_parser("brake",
                        help="set/clear the file brake that stops a campaign even "
                             "from Recovery")
    sp.add_argument("name", nargs="?", help="campaign to brake (omit for --global)")
    sp.add_argument("--global", dest="global_", action="store_true",
                    help="brake every campaign, not just one")
    sp.add_argument("--reason", help="note stored in the file and logged on halt")
    sp.add_argument("--clear", action="store_true", help="remove the brake file")
    sp.add_argument("--where", action="store_true",
                    help="print the brake paths (including the Recovery form) and exit")

    sp = sub.add_parser("status", help="show campaign runtime state")
    sp.add_argument("name")
    sp.add_argument("-w", "--watch", action="store_true",
                    help="redraw until Ctrl-C, annotating what changed since the "
                         "last refresh")
    sp.add_argument("--interval", type=int, default=10,
                    help="seconds between redraws with --watch (default 10)")

    for _n, _h in (("run", "supervision loop (launchd entry point)"),
                   ("doctor", "pre-flight checks before a run"),
                   ("halt", "soft-pause the campaign (leaves the daemon installed)"),
                   ("resume", "clear halt and mark running")):
        s2 = sub.add_parser(_n, help=_h)
        s2.add_argument("name")

    for _n, _h in (("install", "generate + load a launchd job that resumes across reboots"),
                   ("uninstall", "stop the daemon/agent now + prevent restart (removes the plist)")):
        sp = sub.add_parser(_n, help=_h)
        sp.add_argument("name")
        sp.add_argument("--user", help="the user the job runs as (e.g. fuzz, the auto-login user)")
        sp.add_argument("--agent", action="store_true",
                        help="per-user LaunchAgent (runs in the login/GUI session) instead of a "
                             "system LaunchDaemon -- use when the driver needs the console session")
    sub.add_parser("list", help="table of all campaigns")

    sp = sub.add_parser("replay",
                        help="verification manifest: every catalogued crash + its culprit to re-confirm")
    sp.add_argument("name")
    sp.add_argument("--json", action="store_true")

    sp = sub.add_parser("exclude",
                        help="bench a culprit's syscall (remove it from the config) so fuzzing can resume")
    sp.add_argument("name")
    sp.add_argument("culprit", help="minimized culprit.syz from triage")
    sp.add_argument("--config", help="config to update (default: the campaign's current config)")
    sp.add_argument("--dry-run", action="store_true", help="report what would change without writing")

    sp = sub.add_parser("include",
                        help="rotate benched syscalls back into the config (inverse of exclude)")
    sp.add_argument("name")
    sp.add_argument("syscalls", nargs="*", help="syscall names to re-enable")
    sp.add_argument("--config", help="config to update (default: the campaign's current config)")
    sp.add_argument("--all", action="store_true", help="re-include every benched syscall")
    sp.add_argument("--dry-run", action="store_true", help="report what would change without writing")

    args = p.parse_args()
    if not args.cmd:
        p.print_help()
        sys.exit(1)
    if args.cmd == "new":
        cmd_new(args.name, args.configs, args.budget_hours, args.loop,
                args.poll_seconds, args.hang_after_seconds, args.max_crashes,
                args.min_free_gb, args.keep_cores, args.force,
                {"executor": args.executor, "ringrepro": args.ringrepro,
                 "kcov_device": args.kcov_device, "kext_id": args.kext_id,
                 "sandbox": args.sandbox, "max_k": args.max_k},
                {"crashloop_limit": args.crashloop_limit,
                 "crashloop_min_execs": args.crashloop_min_execs,
                 "triage_max_boots": args.triage_max_boots,
                 "budget_clock": args.budget_clock})
    elif args.cmd == "stop":
        sys.exit(cmd_stop(args.name, args.grace, args.keep_agent))
    elif args.cmd == "brake":
        sys.exit(cmd_brake(args.name, args.global_, args.reason, args.clear, args.where))
    elif args.cmd == "run":
        cmd_run(args.name)
    elif args.cmd == "status":
        cmd_status(args.name, args.watch, args.interval)
    elif args.cmd == "doctor":
        sys.exit(cmd_doctor(args.name))
    elif args.cmd == "list":
        cmd_list()
    elif args.cmd == "replay":
        sys.exit(cmd_replay(args.name, args.json))
    elif args.cmd == "halt":
        cmd_halt(args.name)
    elif args.cmd == "resume":
        cmd_resume(args.name)
    elif args.cmd == "forget-exhausted":
        sys.exit(cmd_forget_exhausted(args.name, args.sig))
    elif args.cmd == "install":
        cmd_install(args.name, args.user, args.agent)
    elif args.cmd == "uninstall":
        cmd_uninstall(args.name, args.user, args.agent)
    elif args.cmd == "exclude":
        sys.exit(cmd_exclude(args.name, args.culprit, args.config, args.dry_run))
    elif args.cmd == "include":
        sys.exit(cmd_include(args.name, args.syscalls, args.config, args.all, args.dry_run))


if __name__ == "__main__":
    main()
