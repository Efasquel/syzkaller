#!/usr/bin/env python3
"""Manage syz-manager fuzzing sessions.

A "session" is one ``syz-manager -config <cfg>`` run. All of its persistent
state (corpus.db, results/, ring_buffer/, crashes/) lives in the config's
``workdir``, so syz-manager auto-resumes from corpus.db whenever it is
relaunched with the same config. This script wraps that lifecycle and keeps a
small registry so sessions can be started, stopped, resumed, and compared.

  session id  = the config's basename without ".cfg".
  registry    = sessions/<id>.json at the repo root (git-ignored).
  per run     = a fresh results/bench-<ts>.json (periodic stats, for compare)
                and results/run-<ts>.log (syz-manager stdout/stderr).

Usage:
  scripts/fuzz-session.py config new <Kext>_<variant> [--like <id>]  # generate a config
  scripts/fuzz-session.py config lint                     # check configs for drift
  scripts/fuzz-session.py start   <config.cfg>            # manager + 1 executor
  scripts/fuzz-session.py start   <config.cfg> --no-executor   # manager only, print runner cmd
  scripts/fuzz-session.py start   <config.cfg> -e N       # manager + N executors
  scripts/fuzz-session.py stop    <id|config|all>
  scripts/fuzz-session.py resume  <id|config> [-e N]
  scripts/fuzz-session.py restart <id|config> [-e N]
  scripts/fuzz-session.py exec-start <id> [-n N]          # add executors to a live session
  scripts/fuzz-session.py exec-stop  <id>                 # stop executors, keep manager
  scripts/fuzz-session.py list
  scripts/fuzz-session.py status  <id> [-w] [-i SEC] [--tail N]   # -w = live redraw
  scripts/fuzz-session.py watch   <id>                    # alias for 'status --watch'
  scripts/fuzz-session.py collect <id> crash|hang|snapshot  # save repro material
  scripts/fuzz-session.py compare <id... | all>
  scripts/fuzz-session.py bench   <id|config|bench.json> [--last] [--jsonl] [--keys k,k]
  scripts/fuzz-session.py grammar list    <id> [--all]   # show enabled/disabled syscalls
  scripts/fuzz-session.py grammar disable <id> <pat>...  # blacklist syscall(s)/glob(s)
  scripts/fuzz-session.py grammar enable  <id> <pat>...  # un-blacklist
  scripts/fuzz-session.py grammar clear   <id>           # empty the blacklist
  scripts/fuzz-session.py grammar save    <id>           # copy sys/<os>/*.txt defining the enabled syscalls
  scripts/fuzz-session.py snapshot  <id> [-l label]      # save corpus+ring_buffer+config
  scripts/fuzz-session.py snapshots <id>                 # list snapshots
  scripts/fuzz-session.py restore   <id> <snapshot>      # restore a saved state
  scripts/fuzz-session.py logs    <id> [-f]
  scripts/fuzz-session.py clean   <id>                   # wipe stopped session scratch dirs
  scripts/fuzz-session.py rm      <id>

Bare metal means one device: only one session may run at a time (two managers
would contend for the kcov device and the http port), so start/resume refuse
while another session is live -- override with --allow-concurrent.

Executors run from /tmp/syz-exec-<id>-<n>/ so their ./syzkaller.XXXXXX sandbox
dirs land there (not in the repo) and are wiped on stop. start/resume auto-save
the pre-run corpus.db + ring_buffer + config to workdir/snapshots/<ts>_auto/
(skipped when the corpus is unchanged); nothing is ever auto-deleted.
"""
import argparse
import collections
import errno
import fnmatch
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cfgutil  # noqa: E402
import timefmt  # noqa: E402
from fsutil import hardlink_or_copy  # noqa: E402

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
CONFIG_DIR = REPO_ROOT / "config"
WORKDIR_ROOT = REPO_ROOT / "workdir"
# Optional kext -> coverage id map (authoritative; e.g. exported from Pishi).
KEXT_MAP_PATH = Path(os.environ.get("SYZ_KEXT_MAP", CONFIG_DIR / "kext_ids.json"))
MANAGER_BIN = Path(os.environ.get("SYZ_MANAGER_BIN", REPO_ROOT / "bin" / "syz-manager"))
EXECUTOR_BIN = Path(os.environ.get(
    "SYZ_EXECUTOR_BIN", REPO_ROOT / "bin" / "darwin_arm64" / "syz-executor"))
REGISTRY_DIR = REPO_ROOT / "sessions"
# Executor scratch dirs: the executor does mkdtemp("./syzkaller.XXXXXX") relative
# to its cwd for per-program sandboxing, so we run it from here to keep those
# dirs out of the repo, and wipe this on stop.
EXEC_SCRATCH_BASE = Path(os.environ.get("SYZ_EXEC_SCRATCH", "/tmp"))
# Where kernel-panic / spin reports land after a bare-metal crash+reboot.
# DiagnosticReports has the macOS .ips/.diag; kernel_panics has the full
# panic-full-*.panic dumps. Both are searched; override the paths via env.
PANIC_DIRS = (
    Path(os.environ.get("SYZ_PANIC_DIR", "/Library/Logs/DiagnosticReports")),
    Path(os.environ.get("SYZ_KERNEL_PANIC_DIR", "/private/var/tmp/kernel_panics")),
)
# .panic/.ips/.diag from DiagnosticReports; *.kernel.core.log is the readable
# full panic log in kernel_panics (the sibling *.kernel.core.gz cores are
# 200MB+ each, so they are left out of the bundle by default).
PANIC_GLOBS = ("*.panic", "*.ips", "syz-manager*.diag", "*.kernel.core.log")
# Where `collect` bundles land. One bundle == one incident, so this doubles as
# the session's crash/hang ledger (see crash_events). Default is per-session and
# inside the workdir, so bundles move with it on a rename; --artifacts-dir
# overrides and is remembered in the registry record.
SECTION_WIDTH = 46      # lint check titles are dot-padded to this column
ARTIFACTS_SUBDIR = "artifacts"
# One folder per kind, one dated dir per incident inside it. These live under
# <workdir>/artifacts/ rather than <workdir>/crashes/, which is syzkaller's own
# (it writes crashes/<hash>/ there) -- we must not mix our bundles into it.
INCIDENT_DIRS = {"crash": "crashes", "hang": "hangs", "snapshot": "snapshots"}
EVENT_KINDS = tuple(INCIDENT_DIRS)
STOP_TIMEOUT = 30       # seconds to wait for a graceful (SIGINT) shutdown
# Seconds to wait for the manager to log its rpc port. Generous on purpose: the
# manager compiles the whole enabled grammar before it starts serving, so this
# scales with the config. A 12-syscall AppleJPEGDriver config gets there in
# seconds; a 91-syscall IOSurface config took 96s on a cold workdir and blew a
# 60s limit -- which cost that config an hour of its budget sitting idle with no
# executor. Waiting costs nothing when the port appears early (polled every
# 0.5s), and wait_for_rpc_port gives up immediately if the manager dies.
RPC_PORT_TIMEOUT = 300
DEFAULT_EXECUTORS = 1   # single device == single executor; override with -e/--no-executor

# Metrics pulled from the last bench record. Keys are syz-manager stat names.
BENCH_KEYS = ("coverage", "corpus", "exec total", "crashes", "crash types", "uptime")


# ---- terminal colouring ----------------------------------------------------
class _Style:
    """ANSI colouring that switches itself off when output is not a terminal.

    Piping lint into grep/a file must stay plain text, so escape codes are only
    emitted on a real tty. Honours the NO_COLOR convention and TERM=dumb.
    """
    CODES = {"red": "31", "green": "32", "yellow": "33",
             "cyan": "36", "grey": "90", "bold": "1"}

    def __init__(self, enabled):
        self.enabled = enabled

    def __call__(self, text, *names):
        if not self.enabled or not names:
            return text
        return "\033[%sm%s\033[0m" % (";".join(self.CODES[n] for n in names), text)


style = _Style(
    os.environ.get("NO_COLOR") is None
    and os.environ.get("TERM") != "dumb"
    and hasattr(sys.stdout, "isatty") and sys.stdout.isatty())

# Tick/cross read better than ASCII, but a non-UTF-8 stdout would raise on
# print, so fall back rather than risk crashing the lint over decoration.
if (getattr(sys.stdout, "encoding", "") or "").lower().replace("-", "") == "utf8":
    GLYPH = {"ok": "✓", "error": "✗", "warn": "!", "note": "·"}
else:
    GLYPH = {"ok": "*", "error": "x", "warn": "!", "note": "-"}


# ---- small helpers ---------------------------------------------------------
def die(msg):
    print("error: %s" % msg, file=sys.stderr)
    sys.exit(1)


def warn(msg):
    print("warning: %s" % msg, file=sys.stderr)


# now_iso and now_ts used to be two different clocks -- UTC-with-Z and local --
# so one event was logged at 15:41:48Z and filed under 20260831-174148. They now
# share timefmt's local clock and can no longer drift apart.
def now_iso():
    return timefmt.now_iso()


def now_ts():
    return timefmt.now_ts()


def _iso_epoch(iso):
    """A registry timestamp -> epoch, or None. Tolerant of the legacy UTC 'Z'
    form still present in older session records."""
    return timefmt.to_epoch(iso)


def _epoch_iso(epoch):
    return timefmt.fmt_epoch(epoch, default="unknown")


_BOOT_EPOCH = None


def boot_epoch():
    """Seconds-since-epoch of the current boot, or None if it can't be read.

    Used to invalidate pids recorded before a reboot. On a box that panics and
    reboots constantly, pid reuse is not a corner case: a session record written
    before the panic names a pid the OS has since handed to something else.
    """
    global _BOOT_EPOCH
    if _BOOT_EPOCH is None:
        try:
            out = subprocess.run(["sysctl", "-n", "kern.boottime"],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 text=True, timeout=5).stdout
            m = re.search(r"sec\s*=\s*(\d+)", out)
            _BOOT_EPOCH = int(m.group(1)) if m else False
        except (OSError, ValueError, subprocess.SubprocessError):
            _BOOT_EPOCH = False
    return _BOOT_EPOCH or None


def pid_alive(pid, rec_boot=None):
    """Is `pid` live AND the same process we recorded?

    `rec_boot` is the boot epoch stored alongside the pid. If it disagrees with
    the current boot, the recorded process died in the panic and this pid now
    belongs to someone else -- report it dead. Without that guard a stale record
    reads as "running" after every panic-reboot, and the stop path would signal
    (and killpg) whatever unrelated process inherited the number.
    """
    if not pid:
        return False
    if rec_boot is not None:
        cur = boot_epoch()
        if cur is not None and int(rec_boot) != cur:
            return False
    try:
        os.kill(int(pid), 0)
        return True
    except PermissionError:
        # EPERM means the process EXISTS but belongs to another user, which is
        # proof of life, not death. This is the normal case here: the campaign
        # runs as `fuzz` and is routinely inspected from an admin account, so
        # treating EPERM as dead made every cross-user check lie. It reported a
        # manager with twenty hours of uptime as "crashed", and stop_one() --
        # which refuses to signal a pid it believes is dead -- then declined to
        # stop it, leaving it fuzzing unsupervised.
        return True
    except (OSError, ValueError):
        return False


def pid_start_epoch(pid):
    """When `pid`'s process actually started, or None if it can't be read."""
    try:
        out = subprocess.run(["ps", "-o", "lstart=", "-p", str(int(pid))],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             text=True, timeout=5).stdout.strip()
        if not out:
            return None
        return datetime.strptime(out, "%a %b %d %H:%M:%S %Y").timestamp()
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def state_pid_alive(state):
    """pid_alive for a session record, with two identity guards.

    boot_epoch catches the common case (the box panicked, rebooted, and the pid
    was handed to something else). Records written before that field existed fall
    back to comparing the process's real start time against the session's --
    which also catches pid reuse *within* one boot, e.g. a long-lived registry
    entry whose manager died hours ago.
    """
    state = state or {}
    pid = state.get("pid")
    if not pid_alive(pid, state.get("boot_epoch")):
        return False
    if state.get("boot_epoch") is not None:
        return True
    started = state.get("started_at")
    proc_started = pid_start_epoch(pid)
    if not started or proc_started is None:
        return True                      # can't tell; don't invent a death
    rec = timefmt.to_epoch(started)
    if rec is None:
        return True
    # The record is written right after the spawn, so our manager's start time and
    # started_at agree to within seconds. Compare in BOTH directions: pid reuse
    # after a panic-reboot produces a process NEWER than the record, not older, so
    # a one-sided ">= rec" test would wave it straight through.
    return abs(proc_started - rec) <= 120


def state_file(sid):
    return REGISTRY_DIR / ("%s.json" % sid)


def load_state(sid):
    sf = state_file(sid)
    if not sf.exists():
        return None
    with sf.open() as f:
        return json.load(f)


def save_state(state):
    REGISTRY_DIR.mkdir(exist_ok=True)
    sf = state_file(state["id"])
    tmp = sf.with_suffix(".json.tmp")
    with tmp.open("w") as f:
        json.dump(state, f, indent=2)
    tmp.replace(sf)


def resolve_id(arg):
    """A user argument is either a session id or a path to a .cfg."""
    if arg.endswith(".cfg") or os.path.isfile(arg):
        return Path(arg).name[:-4] if arg.endswith(".cfg") else Path(arg).stem
    return arg


def config_for_id(sid):
    """Config for an id: the registry record, else config/<id>.cfg."""
    state = load_state(sid)
    if state and state.get("config"):
        return Path(state["config"])
    fallback = REPO_ROOT / "config" / ("%s.cfg" % sid)
    return fallback if fallback.exists() else None


def load_config(path):
    """Parse a syzkaller JSON config, tolerating the '#' comments syz-manager
    tolerates. See cfgutil for why this matches the Go rule exactly rather than
    accepting every comment style."""
    return cfgutil.load(path)


def latest_bench(workdir):
    results = Path(workdir) / "results"
    benches = sorted(results.glob("bench-*.json"), key=lambda p: p.stat().st_mtime)
    return benches[-1] if benches else None


def latest_run_log(workdir):
    results = Path(workdir) / "results"
    logs = sorted(results.glob("run-*.log"), key=lambda p: p.stat().st_mtime)
    return logs[-1] if logs else None


def tail_text(path, nbytes=8192):
    """Last nbytes of a file as text (cheap on multi-hour logs)."""
    try:
        size = path.stat().st_size
        with path.open("rb") as f:
            f.seek(max(0, size - nbytes))
            return f.read().decode("utf-8", "replace")
    except OSError:
        return ""


# syz-manager logs a stat line every ~10s, e.g.:
#   "... candidates=0 corpus=127 coverage=480 exec total=669974 (135/sec)"
# These are fresher than bench (~10s vs 60s) and present even before the first
# 60s bench write, so for the live headline metrics we prefer this line.
_STAT_FIELD_RE = {
    "corpus": re.compile(r"\bcorpus=(\d+)"),
    "coverage": re.compile(r"\bcoverage=(\d+)"),
    "exec total": re.compile(r"\bexec total=(\d+)"),
    "rate": re.compile(r"\((\d+)/sec\)"),
}


def run_log_stats(workdir):
    """Parse the newest run log's last stat line ('' for any missing field).

    exec total resets to 0 on every run (a fresh syz-manager process), so this
    is the CURRENT run's count, not the session lifetime -- see
    session_exec_lifetime for the cross-run sum.
    """
    out = {k: "" for k in _STAT_FIELD_RE}
    log = latest_run_log(workdir)
    if not log or not log.exists():
        return out
    line = ""
    for ln in tail_text(log).splitlines():
        if "exec total=" in ln:
            line = ln
    if not line:
        return out
    for k, rx in _STAT_FIELD_RE.items():
        m = rx.search(line)
        if m:
            out[k] = int(m.group(1))
    return out


def exec_rate(workdir):
    """Latest exec/sec from the newest run log ('' if none)."""
    return run_log_stats(workdir).get("rate", "")


def session_exec_lifetime(workdir):
    """Sum of each run's final exec total across all run logs of a session.

    exec total resets per run, so lifetime effort is the sum of every
    run-*.log's last count. Runs that crashed before their first stat line
    contribute 0. Returns '' if no run log carries a stat line.
    """
    results = Path(workdir) / "results"
    total, seen = 0, False
    for log in sorted(results.glob("run-*.log")):
        last = None
        for m in _STAT_FIELD_RE["exec total"].finditer(tail_text(log)):
            last = m
        if last:
            total += int(last.group(1))
            seen = True
    return total if seen else ""


# ---- panic report intake ----------------------------------------------------
# A panic report is written by the OS into a directory the OS also rotates, and
# it is evidence three different consumers want: the run's snapshot, the crash
# bundle, and the bug dossier that becomes a vendor report. Copying it into each
# triples ~1.5MB per report; referencing it from each leaves every consumer
# pointing at a file macOS is free to delete.
#
# So: copy ONCE into workdir/reports/ (the intake), and hardlink from everywhere
# else. A hardlink has no owner -- every name is equal and the data survives
# until the last one goes -- so pruning or rotating any single location cannot
# break the others, and the extra names cost no blocks.
#
# The one thing never linked is a kernel core (*.kernel.core.gz, ~220MB): those
# exist to be reclaimed by prune_cores, and a link would keep the blocks alive
# while the prune reported success. Cores stay referenced by path in manifests.
# hardlink_or_copy lives in fsutil, shared with the bug registry.
REPORTS_SUBDIR = "reports"


def reports_intake(workdir):
    return Path(workdir) / REPORTS_SUBDIR


def intake_report(workdir, src):
    """Bring one panic report under the workdir, out of the OS-rotated directory.

    Idempotent, and read-only once taken: annotating a report in place would
    retroactively change every snapshot that links it, so notes belong in a
    sidecar. Returns the intake path (the copy every other consumer links to).
    """
    src = Path(src)
    dst = reports_intake(workdir) / src.name
    if not dst.exists():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        try:
            os.chmod(dst, 0o444)
        except OSError:
            pass                     # read-only is a guard rail, not a requirement
    return dst


def artifacts_root(state):
    """Root holding this session's collect bundles, i.e. its incident ledger."""
    d = state.get("artifacts_dir")
    return Path(d) if d else Path(state["workdir"]) / ARTIFACTS_SUBDIR


def last_collect_epoch(state):
    """When this session was last collected, or None if it never was."""
    root = artifacts_root(state)
    best = None
    for sub in INCIDENT_DIRS.values():
        for ev in (root / sub).glob("*/event.json"):
            try:
                with ev.open() as f:
                    t = _iso_epoch(json.load(f).get("collected_at"))
            except (OSError, ValueError):
                continue
            if t and (best is None or t > best):
                best = t
    return best


def uncollected_run(state):
    """Describe the previous run if it ended without a collect, else None.

    Restarting overwrites ring_buffer/slot_NNNN.syz in place, and those slots
    are the last programs executed before the crash -- the repro material. So a
    previous run that was never collected is a real loss risk, not a nag.
    """
    workdir = Path(state["workdir"])
    started = run_start_epoch(workdir)
    if started is None:
        return None                         # never run: nothing to lose
    ring = workdir / "ring_buffer"
    if not ring.is_dir() or not any(ring.glob("slot_*.syz")):
        return None                         # nothing to overwrite
    last = last_collect_epoch(state)
    if last is not None and last >= started:
        return None                         # already collected since that run
    return {"run_started": _epoch_iso(started),
            "last_collect": _epoch_iso(last) if last else "never",
            "slots": sum(1 for _ in ring.glob("slot_*.syz"))}


def crash_events(state):
    """Incidents recorded for a session as {kind: count}, one dir per incident.

    syz-manager cannot witness a bare-metal panic -- type:none has no VM and no
    console, so the machine dies under it and workdir/crashes is never written.
    The collect bundles are the only record, so we count those: each `collect
    <id> crash|hang` drops one dated dir under artifacts/crashes or
    artifacts/hangs. Snapshots are deliberately not incidents and are not
    counted here.
    """
    root = artifacts_root(state)
    counts = {}
    for kind, sub in INCIDENT_DIRS.items():
        d = root / sub
        if d.is_dir():
            counts[kind] = sum(1 for p in d.iterdir() if p.is_dir())
    return counts


def run_start_epoch(workdir):
    """Epoch of the latest run's start, from its run-<ts>.log filename."""
    log = latest_run_log(workdir)
    if not log:
        return None
    m = re.search(r"run-(\d{8})-(\d{6})\.log$", log.name)
    if m:
        try:
            return datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S").timestamp()
        except ValueError:
            pass
    return log.stat().st_mtime


# Reports embed the incident time in their name (local time, like our run logs):
#   panic-full-2026-07-18-093748.0002.panic  ->  2026-07-18 09:37:48
# mtime is unreliable here (macOS rewrites some reports days later), so prefer
# the filename timestamp and fall back to mtime only when the name has none.
_REPORT_TS_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})-(\d{6})")


def report_time(path):
    m = _REPORT_TS_RE.search(path.name)
    if m:
        try:
            return datetime.strptime("".join(m.groups()), "%Y%m%d%H%M%S").timestamp()
        except ValueError:
            pass
    try:
        return path.stat().st_mtime
    except OSError:
        return 0


def collect_reports(since_epoch, until_epoch, pad=300):
    """Panic/diag reports whose incident time falls in the session's window.

    Searches every PANIC_DIRS entry (DiagnosticReports + kernel_panics), bounded
    on both ends -- [run_start - pad, stopped + pad] -- so reports from earlier
    or later runs don't leak in. Dotfiles (e.g. .contents.panic) are skipped.
    Returns paths sorted oldest first.
    """
    lo = (since_epoch - pad) if since_epoch else 0
    hi = (until_epoch + pad) if until_epoch else float("inf")
    found = {}
    for d in PANIC_DIRS:
        if not d.is_dir():
            continue
        for g in PANIC_GLOBS:
            for p in d.glob(g):
                if p.name.startswith("."):
                    continue
                t = report_time(p)
                if lo <= t <= hi:
                    found[p] = t
    return sorted(found, key=found.get)


# --- basic-block coverage (kext_coverage.cover_log) --------------------------
# syz-manager appends every newly-covered BB PC as "0x%x\n", fsync'd per program
# so it survives a panic. os.Create truncates on start, so the live file holds
# THIS run's BBs; start archives the prior run to results/cover-<ts>.log.
def cover_log_path(state):
    """The cover_log path from the session's config, or the default convention.

    A relative cover_log is joined with the workdir (matching how mgrconfig
    resolves it), so both absolute and workdir-relative configs work.
    """
    workdir = Path(state["workdir"])
    cfg = state.get("config")
    if cfg and Path(cfg).exists():
        cl = (load_config(cfg).get("kext_coverage") or {}).get("cover_log")
        if cl:
            return Path(cl) if os.path.isabs(cl) else workdir / cl
    return workdir / "cover.log"


def cover_log_archives(workdir):
    return sorted((Path(workdir) / "results").glob("cover-*.log"))


def bb_unique(paths):
    """Count distinct coverage PCs across one or more cover-log files."""
    seen = set()
    for p in paths:
        p = Path(p)
        if not p.exists():
            continue
        try:
            for line in p.read_text(errors="replace").splitlines():
                line = line.strip()
                if line:
                    seen.add(line)
        except OSError:
            pass
    return len(seen)


def rawcover_text(http, timeout=3):
    """Body of the manager's /rawcover endpoint, or None if down/unreachable.

    /rawcover returns the full deduped set of covered PCs across the corpus,
    one "0x%x" per line -- the authoritative live coverage. Only reachable while
    the manager is running; callers fall back to the on-disk cover_log.
    """
    if not http:
        return None
    try:
        with urllib.request.urlopen("http://%s/rawcover" % http, timeout=timeout) as r:
            if r.status != 200:
                return None
            return r.read().decode("utf-8", "replace")
    except Exception:
        return None


def rawcover_count(http, timeout=3):
    """Live BB count from /rawcover, or None if the manager is down."""
    text = rawcover_text(http, timeout)
    if text is None:
        return None
    return sum(1 for line in text.splitlines() if line.strip())


def bench_records(bench):
    """Yield every record from a bench file, oldest first.

    A syz-manager bench file is NOT a single JSON document: it is an
    append-only stream of pretty-printed JSON objects, one per minute, with no
    enclosing array (so a kill mid-run never invalidates the records already on
    disk). Decode it greedily; a trailing partial record from an in-progress
    write is silently dropped.
    """
    if not bench or not Path(bench).exists():
        return
    text = Path(bench).read_text()
    dec, i, n = json.JSONDecoder(), 0, len(text)
    while i < n:
        while i < n and text[i] in " \t\r\n":
            i += 1
        if i >= n:
            break
        try:
            obj, i = dec.raw_decode(text, i)
        except ValueError:
            break
        yield obj


def fmt_uptime(secs):
    """Bench uptime (seconds) as 1h 02m 03s; passes through junk/empty as "-"."""
    try:
        s = int(float(secs))
    except (TypeError, ValueError):
        return secs or "-"
    h, rem = divmod(s, 3600)
    m, s = divmod(rem, 60)
    if h:
        return "%dh %02dm %02ds" % (h, m, s)
    if m:
        return "%dm %02ds" % (m, s)
    return "%ds" % s


def bench_metrics(bench):
    """Return {key: value} from the LAST record of a bench file."""
    last = None
    for last in bench_records(bench):
        pass
    if not last:
        return {k: "" for k in BENCH_KEYS}
    return {k: last.get(k, "") for k in BENCH_KEYS}


def refresh_status(sid):
    """A dead pid on a "running" record becomes "crashed"."""
    state = load_state(sid)
    if not state:
        return None
    if state.get("status") == "running" and not state_pid_alive(state):
        state["status"] = "crashed"
        state["stopped_at"] = now_iso()
        save_state(state)
    return state


def cmd_inspect(target):
    """Emit one session's status as JSON, for machine consumers (fuzz-campaign).

    Keeps all status derivation here -- dead-pid reclassification, exec-total
    parsing, panic-window scanning -- so a driver never re-implements it. The
    one fact a supervisor needs and cannot see post-reboot is panic_evidence:
    a *.kernel.core.log/*.panic in the run window proves a real crash, which
    is how crash is told apart from a hang (which leaves no panic file).
    """
    sid = resolve_id(target)
    state = refresh_status(sid)
    if not state:
        print(json.dumps({"id": sid, "found": False}))
        return
    workdir = state["workdir"]
    started = run_start_epoch(workdir)
    stats = run_log_stats(workdir)
    until = _iso_epoch(state.get("stopped_at")) or time.time()
    reports = collect_reports(started, until) if started else []
    panics = [str(p) for p in reports
              if p.name.endswith((".kernel.core.log", ".panic"))]
    et = stats.get("exec total")
    out = {
        "id": sid, "found": True,
        "status": state.get("status"),
        "pid": state.get("pid"), "pid_alive": state_pid_alive(state),
        "config": state.get("config"), "workdir": workdir,
        # The manager's web UI. Recorded per session because the port is taken
        # from the config, so a driver supervising several configs cannot guess
        # it -- and it is the first thing you want when a run looks wrong.
        "http": state.get("http"),
        "run_started": _epoch_iso(started) if started else None,
        "run_started_epoch": started,
        "exec_total": et if et != "" else None,
        "coverage": int(stats["coverage"]) if stats.get("coverage") not in ("", None) else None,
        "rate": stats.get("rate") if stats.get("rate") != "" else None,
        "reports": [str(p) for p in reports],
        "panic_evidence": bool(panics),
        "panics": panics,
        "incidents": crash_events(state),
        "uncollected": uncollected_run(state),
        "run_count": state.get("run_count"),
    }
    print(json.dumps(out, indent=2))


def all_ids():
    if not REGISTRY_DIR.is_dir():
        return []
    return sorted(p.stem for p in REGISTRY_DIR.glob("*.json"))


def fmt_row(cols, widths):
    return "  ".join(str(c).ljust(w) for c, w in zip(cols, widths))


# ---- executor management ---------------------------------------------------
_RPC_RE = re.compile(r"serving rpc on tcp://(\d+)")


def wait_for_rpc_port(logf, timeout=RPC_PORT_TIMEOUT, pid=None):
    """Poll a manager run log for 'serving rpc on tcp://<port>'.

    pid, when given, is the manager: if it dies there is no port coming, so stop
    waiting rather than burning the whole timeout on a corpse.
    """
    deadline = time.time() + timeout
    waited, announced = 0.0, 0.0
    while time.time() < deadline:
        try:
            for line in Path(logf).read_text(errors="replace").splitlines():
                m = _RPC_RE.search(line)
                if m:
                    if waited > 20:
                        print("    ... rpc ready after %.0fs" % waited)
                    return int(m.group(1))
        except OSError:
            pass
        if pid is not None and waited > 5 and not pid_alive(pid):
            warn("manager pid %s exited before serving rpc; see the run log" % pid)
            return None
        # A heartbeat, so a long compile reads as progress rather than a stall.
        if waited - announced >= 30:
            announced = waited
            print("    ... still compiling (%.0fs of %ds)" % (waited, timeout))
            sys.stdout.flush()
        time.sleep(0.5)
        waited += 0.5
    return None


def exec_scratch(sid, index):
    return EXEC_SCRATCH_BASE / ("syz-exec-%s-%d" % (sid, index))


# Darwin stores a process name in two struct proc fields, and which one a kext
# reads decides how much of executor_name survives (verified on macOS 26.5):
#   p_comm  16 bytes -- ps -o ucomm, proc_selfname(), AND the kernel proc_name()
#                       KPI, which does strlcpy(buf, p->p_comm, MIN(sizeof p_comm,
#                       size)) -- the caller's buffer size cannot lift this.
#   p_name  ~31 bytes -- proc_best_name(), and the *userspace* libproc proc_name().
#   full path -- proc_pidpath().
# 16 is the only bound that is safe no matter which API the kext calls (the
# kernel proc_name() KPI, the common IOKit choice, reads p_comm), so we warn
# above it. Names of 17-31 are fine *if* the kext uses proc_best_name/libproc.
MAXCOMLEN = 16
PROC_NAME_MAX = 31


def executor_binary(state, scratch):
    """Path to the binary to exec, honouring the config's executor_name.

    Some IOKit drivers only talk to a client with an expected process name, so
    we run a renamed copy of syz-executor. A copy, not a symlink: p_comm comes
    from the file that was actually executed. The copy is refreshed whenever
    the real executor is newer, so rebuilds are picked up.
    """
    cfg = state.get("config")
    name = ""
    if cfg and Path(cfg).exists():
        name = (load_config(cfg).get("executor_name") or "").strip()
    if not name:
        return EXECUTOR_BIN
    if "/" in name:
        die("executor_name must be a bare filename, not a path: %r" % name)
    # Warn above the conservative 16-byte p_comm bound: the kernel proc_name()
    # KPI (the usual IOKit access check) reads p_comm, so a longer name only
    # survives if the kext happens to use proc_best_name/libproc (~31). Between
    # 17 and 31 that is a legitimate choice -- launch_executor shows the p_comm
    # form so the truncated name is visible.
    n = len(name.encode())
    if n > MAXCOMLEN:
        warn("executor_name %r is %d bytes; p_comm keeps only %d, so a kext using "
             "proc_name()/proc_selfname sees %r. Names of %d-%d survive only if it "
             "uses proc_best_name/libproc (which keep ~%d)."
             % (name, n, MAXCOMLEN, name[:MAXCOMLEN],
                MAXCOMLEN + 1, PROC_NAME_MAX, PROC_NAME_MAX))
    dest = Path(scratch) / name
    if not dest.exists() or dest.stat().st_mtime < EXECUTOR_BIN.stat().st_mtime:
        shutil.copy2(EXECUTOR_BIN, dest)
        dest.chmod(dest.stat().st_mode | 0o111)
    return dest


def launch_executor(state, index, port):
    """Start one 'syz-executor runner <index> 127.0.0.1 <port>' from a scratch dir."""
    if not EXECUTOR_BIN.exists() or not os.access(EXECUTOR_BIN, os.X_OK):
        die("syz-executor not found at %s (build it, or set SYZ_EXECUTOR_BIN)" % EXECUTOR_BIN)
    scratch = exec_scratch(state["id"], index)
    scratch.mkdir(parents=True, exist_ok=True)
    binary = executor_binary(state, scratch)
    logf = str(Path(state["workdir"]) / "results" / ("executor-%d.log" % index))
    log_fh = open(logf, "w")
    proc = subprocess.Popen(
        [str(binary), "runner", str(index), "127.0.0.1", str(port)],
        stdout=log_fh, stderr=subprocess.STDOUT,
        cwd=str(scratch), start_new_session=True,
    )
    time.sleep(0.5)
    if proc.poll() is not None:
        warn("executor %d exited immediately; last log lines:" % index)
        sys.stderr.write("".join(open(logf).readlines()[-10:]))
        die("failed to start executor %d" % index)
    state.setdefault("executors", []).append(
        {"pid": proc.pid, "boot_epoch": boot_epoch(), "index": index,
         "scratch": str(scratch), "log": logf})
    named = ""
    if binary != EXECUTOR_BIN:
        named = " as '%s'" % binary.name
        if len(binary.name.encode()) > MAXCOMLEN:   # p_comm is the short one
            named += " (p_comm: '%s')" % binary.name[:MAXCOMLEN]
    print("  executor %d: pid %s%s (cwd %s)" % (index, proc.pid, named, scratch))
    return proc.pid


def start_executors(state, count):
    """Bring the session up to <count> LIVE executors total, resolving rpc port first."""
    need = count - len(live_executors(state))
    if need <= 0:
        return
    # Say what the silence is. syz-manager compiles every enabled syscall before
    # it serves rpc, and that scales with the grammar: ~2 minutes for a
    # 91-syscall config on this box, seconds for a 12-syscall one. Without this
    # line the wait is indistinguishable from a hang -- which is exactly how a
    # missed rpc port went unnoticed for an hour of budget.
    n = 0
    try:
        conf = json.loads(Path(state["config"]).read_text())
        n = len(conf.get("enable_syscalls") or [])
    except (OSError, ValueError, KeyError):
        pass
    print("  waiting for syz-manager to serve rpc%s -- it compiles the enabled"
          % (" (%d syscall(s) to compile)" % n if n else ""))
    print("    grammar first, so expect ~2 min for a large one. Up to %ds."
          % RPC_PORT_TIMEOUT)
    port = wait_for_rpc_port(state["stdout"], pid=state.get("pid"))
    if not port:
        warn("could not read rpc port from manager log within %ds; "
             "start executors later with: %s exec-start %s"
             % (RPC_PORT_TIMEOUT, sys.argv[0], state["id"]))
        return
    state["rpc_port"] = port
    print("  rpc port: %s" % port)
    existing = {e["index"] for e in state.get("executors", [])}
    idx = 0
    started = 0
    while started < need:
        if idx not in existing:
            launch_executor(state, idx, port)
            started += 1
        idx += 1
    save_state(state)


def orphan_executors(state=None):
    """Our syz-executor processes NOT tracked by `state` -- leftovers from a
    wedged or half-stopped run.

    They matter because the executor holds the coverage device EXCLUSIVELY. One
    program wedged in the kernel leaves an executor alive forever, and every
    subsequent manager then dies at startup with "open of kcov device failed
    (errno 16)" -- EBUSY. No restart can succeed until the orphan is gone, so a
    campaign that only knows how to restart halts instead of recovering.

    Matched on our own executor path, so nothing outside this tree is ever
    touched. Returns [(pid, command)].
    """
    tracked = {int(e["pid"]) for e in (state or {}).get("executors", [])
               if e.get("pid")}
    try:
        out = subprocess.run(["/bin/ps", "-Ao", "pid,command"],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             text=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    mine = str(EXECUTOR_BIN) if "EXECUTOR_BIN" in globals() else "syz-executor"
    found = []
    for line in (out or "").splitlines()[1:]:
        line = line.strip()
        if "syz-executor" not in line or mine not in line:
            continue
        pid_s, _, cmd = line.partition(" ")
        try:
            pid = int(pid_s)
        except ValueError:
            continue
        if pid not in tracked and pid != os.getpid():
            found.append((pid, cmd.strip()))
    return found


def proc_state(pid):
    """ps STAT for a pid, or "" -- 'U' is uninterruptible sleep."""
    try:
        out = subprocess.run(["/bin/ps", "-o", "stat=", "-p", str(int(pid))],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             text=True, timeout=5).stdout.strip()
        return out.split()[0] if out else ""
    except (OSError, ValueError, subprocess.SubprocessError):
        return ""


def unkillable(pid):
    """True when pid is wedged in the kernel and cannot be signalled away.

    STAT 'U' is uninterruptible sleep: the thread is inside a kernel call that
    never returns and never checks for signals, so SIGKILL is merely QUEUED --
    it is delivered if the call returns, which by definition it will not. This
    is what a real driver hang looks like from userspace, and it is the one
    condition where the honest answer is "only a reboot clears this".
    """
    return proc_state(pid).startswith("U")


def reap_orphan_executors(state=None):
    """Free the coverage device by killing orphaned executors.

    Returns (freed, wedged): how many died, and the pids that cannot be killed
    at all. A non-empty `wedged` means no restart on this boot can succeed --
    the device stays held until the machine reboots.
    """
    orphans = orphan_executors(state)
    if not orphans:
        return 0, []
    for pid, cmd in orphans:
        if unkillable(pid):
            continue          # signalling it is pointless; reported below
        warn("orphaned executor pid %d holds the coverage device -- killing it "
             "(%s)" % (pid, cmd[:60]))
        try:
            os.kill(pid, signal.SIGKILL)
        except PermissionError:
            warn("  cannot kill pid %d (owned by another user); run as that "
                 "user or with sudo" % pid)
        except OSError:
            pass
    time.sleep(1)
    left = orphan_executors(state)
    wedged = [pid for pid, _ in left if unkillable(pid)]
    for pid in wedged:
        warn("executor pid %d is in uninterruptible sleep (STAT U): wedged inside "
             "a kernel call that never returns. SIGKILL cannot reach it, so it "
             "will hold the coverage device until the machine REBOOTS." % pid)
    other = [pid for pid, _ in left if pid not in wedged]
    if other:
        warn("%d orphaned executor(s) survived the kill: %s"
             % (len(other), ", ".join(str(p) for p in other)))
    return len(orphans) - len(left), wedged


def _run_capture(cmd, timeout=90):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True, timeout=timeout)
        return p.returncode, p.stdout or ""
    except subprocess.TimeoutExpired:
        return 1, "(timed out after %ds)" % timeout
    except OSError as e:
        return 1, str(e)


# Frames worth pulling out of a stack dump. A wedged executor is blocked in ONE
# call, so unlike a crash -- where the fault is state-dependent and you need the
# whole sequence -- the stack IS the answer.
_HANG_FRAMES = re.compile(
    r"IOConnect|IOService|IOKit|io_connect|mach_msg|semaphore|_sleep|"
    r"msleep|thread_block|lck_|IOLock|AVB|IOAVB", re.I)


def diagnose_hang(pids=None, out_dir=None):
    """Capture what a wedged executor is blocked in, with sample and spindump.

    Seconds, no reboots, and it names the kernel call directly -- which is why
    it is the first thing to try, ahead of any minimization. Minimizing a hang
    costs a reboot per positive probe; this costs nothing and often ends the
    investigation.

    Returns [(pid, path, interesting_frames)].
    """
    if pids is None:
        pids = [pid for pid, _ in orphan_executors(None) if unkillable(pid)]
        pids += [pid for pid, _ in orphan_executors(None) if pid not in pids]
    if not pids:
        print("no wedged executor found")
        return []
    out_dir = Path(out_dir or ".")
    out_dir.mkdir(parents=True, exist_ok=True)
    results = []
    for pid in pids:
        stamp = now_ts()
        print("  pid %d (STAT %s)" % (pid, proc_state(pid) or "?"))
        text = ""
        for label, cmd in (("sample", ["/usr/bin/sample", str(pid), "3", "-mayDie"]),
                           ("spindump", ["/usr/sbin/spindump", str(pid), "3",
                                         "-stdout"])):
            rc, body = _run_capture(cmd)
            if rc == 0 and body.strip():
                text += "\n===== %s =====\n%s" % (label, body)
                print("    %s: captured %d lines" % (label, body.count("\n")))
            else:
                # Both need root for another user's process; say so once, plainly.
                first = (body or "").strip().splitlines()[:1]
                print("    %s: unavailable%s"
                      % (label, " -- %s" % first[0][:90] if first else ""))
        if not text.strip():
            warn("no stack captured for pid %d -- both sample and spindump need "
                 "root for another user's process: sudo is required" % pid)
            results.append((pid, None, []))
            continue
        path = out_dir / ("hang-%d-%s.txt" % (pid, stamp))
        path.write_text(text)
        frames = []
        for line in text.splitlines():
            if _HANG_FRAMES.search(line) and line.strip() not in frames:
                frames.append(line.strip())
        print("    saved %s" % path)
        if frames:
            print("    frames naming the blocked call:")
            for f in frames[:12]:
                print("      %s" % f[:110])
        else:
            print("    no IOKit/driver frames matched -- read the full dump")
        results.append((pid, str(path), frames))
    return results


def stop_executors(state):
    """Kill all executors of a session and wipe their scratch dirs."""
    execs = state.get("executors", [])
    for e in execs:
        pid = e.get("pid")
        if pid_alive(pid, e.get("boot_epoch")):
            try:
                os.killpg(os.getpgid(int(pid)), signal.SIGINT)
            except OSError:
                try:
                    os.kill(int(pid), signal.SIGKILL)
                except OSError:
                    pass
    time.sleep(1)
    for e in execs:
        pid = e.get("pid")
        if pid_alive(pid, e.get("boot_epoch")):
            try:
                os.kill(int(pid), signal.SIGKILL)
            except OSError:
                pass
        scratch = e.get("scratch")
        if scratch:
            retire_scratch(scratch)   # rename now, delete out of band
    if execs:
        print("  stopped %d executor(s)" % len(execs))
    state["executors"] = []


def live_executors(state):
    return [e for e in state.get("executors", [])
            if pid_alive(e.get("pid"), e.get("boot_epoch"))]


# A scratch dir holds one `syzkaller.XXXXXX` subdir PER EXECUTED PROGRAM, so a
# long run leaves millions of them. Deleting that inline made `stop` take minutes
# -- during which the manager was still running and the state file still said
# "running", which reads as a hung stop. So retire by rename (O(1)) and delete
# out of band.
TRASH_PREFIX = "syz-trash-"


def retire_scratch(path):
    """Move a scratch dir aside instantly; return its trash path (or None).

    os.rename within one filesystem is O(1) no matter how many entries are
    inside, so the caller can update state and move on. Falls back to a blocking
    delete only if the rename is impossible (e.g. cross-device).
    """
    path = Path(path)
    if not path.is_dir():
        return None
    trash = EXEC_SCRATCH_BASE / ("%s%s-%d" % (TRASH_PREFIX, path.name, int(time.time() * 1000)))
    try:
        os.rename(str(path), str(trash))
        return trash
    except OSError as e:
        # EXDEV is the one case where a blocking delete is the right answer: the
        # rename is impossible but the removal is not.
        if e.errno == errno.EXDEV:
            shutil.rmtree(path, ignore_errors=True)
            return None
        # Anything else -- and in practice this is EPERM -- must NOT fall back to
        # a walk. These dirs live in /tmp, which is sticky, so only their owner
        # can rename or unlink them: a stop run by the wrong user cannot touch a
        # scratch tree the fuzz user created. shutil.rmtree(ignore_errors=True)
        # then walks every one of ~65,000 subdirectories, fails on each, swallows
        # the error and keeps going -- minutes of work that deletes nothing while
        # looking exactly like a hung stop. Leave it for whoever owns it; the next
        # stop or `clean` by that user picks it up.
        warn("cannot retire scratch %s (%s) -- leaving it for its owner; "
             "run stop as that user, or: sudo rm -rf %s"
             % (path, e.strerror or e, path))
        return None


def reap_trash(background=True):
    """Delete retired scratch dirs. Returns the number of trees handed off.

    The speed win is the rename in retire_scratch, not this: measured on 20k
    entries, `rm -rf` and shutil.rmtree are within a second of each other. `rm` is
    used because it can be detached (start_new_session) and outlive this process,
    which is what lets `stop` return immediately. An interrupted reap is harmless
    -- the leftover trash dir is picked up by the next stop/clean.
    """
    trees = [d for d in EXEC_SCRATCH_BASE.glob("%s*" % TRASH_PREFIX) if d.is_dir()]
    if not trees:
        return 0
    cmd = ["/bin/rm", "-rf"] + [str(d) for d in trees]
    try:
        if background:
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True)
        else:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        for d in trees:
            shutil.rmtree(d, ignore_errors=True)
    return len(trees)


def clean_scratch(sid):
    """Retire every executor scratch dir for a session id (glob on the id).

    Catches orphans left behind when executors are killed or a run is superseded
    without a clean stop. The trailing '-' in the glob keeps it from matching a
    different session whose id is a prefix of this one. Caller must ensure no
    tracked executor of this session is still using one of these dirs.

    Renames rather than deletes; call reap_trash() to do the actual removal.
    """
    removed = 0
    for d in sorted(EXEC_SCRATCH_BASE.glob("syz-exec-%s-*" % sid)):
        if d.is_dir():
            retire_scratch(d)
            removed += 1
    return removed


# ---- snapshots (reusable corpus/ring_buffer "inputs") ----------------------
def snapshot_root(workdir):
    return Path(workdir) / "snapshots"


def _file_sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _ring_sha(ring):
    """Hash of the ring buffer's slot contents, or '' when there is none.

    The manager overwrites slot_NNNN.syz in place, so these files are the last
    programs executed before a crash -- the repro material. They change on
    almost every exec, while corpus.db only changes when new coverage is found,
    so the corpus hash alone is not a safe proxy for "nothing new to save".
    """
    if not Path(ring).is_dir():
        return ""
    h = hashlib.sha256()
    for slot in sorted(Path(ring).glob("slot_*.syz")):
        h.update(slot.name.encode())
        h.update(slot.read_bytes())
    return h.hexdigest()


def latest_bundle(state):
    """Newest collect bundle dir for a session, or None if never collected."""
    root = artifacts_root(state)
    best, best_t = None, None
    for sub in INCIDENT_DIRS.values():
        for ev in (root / sub).glob("*/event.json"):
            try:
                with ev.open() as f:
                    t = _iso_epoch(json.load(f).get("collected_at"))
            except (OSError, ValueError):
                continue
            if t and (best_t is None or t > best_t):
                best, best_t = ev.parent, t
    return best


def bundle_covers_inputs(state, corpus_sha, ring_sha):
    """True when the newest collect bundle already holds these exact inputs.

    `collect` saves corpus.db + ring_buffer + config, so once you have collected
    an incident, the next start's auto-snapshot would copy identical bytes under
    a second name. Compared against the newest bundle only: the workflow is
    collect-then-restart, so that is the one that can match.
    """
    bundle = latest_bundle(state)
    if bundle is None:
        return False
    corpus = bundle / "corpus.db"
    have_corpus = _file_sha(corpus) if corpus.exists() else ""
    return have_corpus == corpus_sha and _ring_sha(bundle / "ring_buffer") == ring_sha


def list_snapshots(workdir):
    """Return snapshot manifests under a workdir, oldest first."""
    root = snapshot_root(workdir)
    if not root.is_dir():
        return []
    out = []
    for d in sorted(root.iterdir()):
        mf = d / "manifest.json"
        if d.is_dir() and mf.exists():
            try:
                m = json.load(open(mf))
            except ValueError:
                m = {}
            m["name"] = d.name
            m["_dir"] = str(d)
            out.append(m)
    return out


def make_snapshot(sid, workdir, config, label=None, metrics=None, dedupe=False):
    """Copy corpus.db + ring_buffer + config into workdir/snapshots/<ts>[_label]/.

    Nothing is ever deleted. With dedupe=True, skips (returns None) when these
    exact inputs are already saved -- either by the most recent snapshot or by
    the most recent collect bundle, which stores the same three things.
    Returns the snapshot name, or None if there was nothing (new) to save.
    """
    wd = Path(workdir)
    corpus, ring = wd / "corpus.db", wd / "ring_buffer"
    if not corpus.exists() and not ring.is_dir():
        return None  # brand-new session, nothing to preserve yet

    corpus_sha = _file_sha(corpus) if corpus.exists() else ""
    ring_sha = _ring_sha(ring)
    if dedupe and (corpus_sha or ring_sha):
        prev = list_snapshots(workdir)
        # Skip only when *both* are unchanged. Gating on the corpus alone lost
        # the ring buffer after any crash that found no new coverage.
        if (prev and prev[-1].get("corpus_sha") == corpus_sha
                and prev[-1].get("ring_sha") == ring_sha):
            return None
        # A collect bundle holds corpus.db + ring_buffer + config too, so
        # snapshotting identical bytes right after a collect just duplicates it.
        # The start guard means a collect is the normal path into a restart.
        if bundle_covers_inputs(load_state(sid) or {"workdir": workdir},
                                corpus_sha, ring_sha):
            return None

    ts = now_ts()
    name = ts + ("_" + label if label else "")
    dest = snapshot_root(workdir) / name
    while dest.exists():                       # avoid clobber on sub-second retries
        name += "x"
        dest = snapshot_root(workdir) / name
    dest.mkdir(parents=True)
    if corpus.exists():
        shutil.copy2(corpus, dest / "corpus.db")
    if ring.is_dir():
        shutil.copytree(ring, dest / "ring_buffer")
    if config and Path(config).exists():
        shutil.copy2(config, dest / "config.cfg")
    manifest = {
        "id": sid, "name": name, "created_at": now_iso(), "label": label or "",
        "corpus_bytes": corpus.stat().st_size if corpus.exists() else 0,
        "corpus_sha": corpus_sha, "ring_sha": ring_sha, "metrics": metrics or {},
    }
    with open(dest / "manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)
    return name


# ---- grammar capture (preserve the descriptions a run used) ----------------
# The syscall descriptions (sys/<os>/*.txt) are compiled into syz-manager at
# build time and are untracked, so a run's exact grammar is otherwise lost the
# next time they are edited or regenerated. Before each start we copy the files
# that DEFINE the config's enable_syscalls into workdir/grammar/<ts>/, keeping a
# session reproducible with the values it actually fuzzed.
def _desc_dir(conf):
    os_name = (conf.get("target") or "darwin/arm64").split("/")[0]
    return REPO_ROOT / "sys" / os_name


def _index_defs(desc_dir):
    """Map each sys/<os>/*.txt to the set of top-level syscalls it defines.

    A syscall definition is a column-0 line whose text before '(' is a single
    token (the name, e.g. syz_IOConnectCallMethod$AppleSSEUserClient_0_v0).
    Struct fields are indented and resources/types use '['/'{', so they do not
    match; exact membership against enable_syscalls makes any stray head harmless.
    """
    idx = {}
    for p in sorted(desc_dir.glob("*.txt")):
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        names = set()
        for line in text.splitlines():
            if not line or line[0].isspace():        # only column-0 declarations
                continue
            paren = line.find("(")
            if paren <= 0:
                continue
            head = line[:paren]
            if " " not in head and "\t" not in head:
                names.add(head)
        idx[p] = names
    return idx


def grammar_files_for(conf):
    """sys/<os>/*.txt files that DEFINE the config's enable_syscalls.

    Returns (files_sorted, mapping{call: [Path,...]}, missing[call,...]). Glob
    patterns in enable_syscalls are matched against the defined names.
    """
    desc_dir = _desc_dir(conf)
    calls = conf.get("enable_syscalls", []) or []
    idx = _index_defs(desc_dir)
    mapping, need, missing = {}, set(), []
    for c in calls:
        if any(ch in c for ch in "*?["):
            hit = [p for p, names in idx.items()
                   if any(fnmatch.fnmatchcase(n, c) for n in names)]
        else:
            hit = [p for p, names in idx.items() if c in names]
        mapping[c] = sorted(hit)
        if hit:
            need.update(hit)
        else:
            missing.append(c)
    return sorted(need), mapping, missing


def _grammar_fingerprint(files):
    """sha256 over (name,bytes) of the defining files: identity of a grammar set."""
    h = hashlib.sha256()
    for p in sorted(files):
        h.update(p.name.encode())
        h.update(b"\0")
        try:
            h.update(p.read_bytes())
        except OSError:
            pass
        h.update(b"\0")
    return h.hexdigest()


def _git_head():
    try:
        out = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"],
                                      cwd=str(REPO_ROOT), stderr=subprocess.DEVNULL)
        return out.decode().strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def save_grammar(workdir, conf, stamp, dedupe=True):
    """Copy the description files defining enable_syscalls into
    workdir/grammar/<stamp>/, with a manifest (call -> file, sha256, git HEAD).

    dedupe: reuse the newest saved set when it is byte-identical. Returns a dict
    {name, n, missing, os, skipped} (name=None when nothing defines the calls),
    or None when there is nothing to record at all.
    """
    files, mapping, missing = grammar_files_for(conf)
    os_name = (conf.get("target") or "darwin/arm64").split("/")[0]
    if not files:
        return ({"name": None, "n": 0, "missing": missing, "os": os_name,
                 "skipped": False} if missing else None)
    root = Path(workdir) / "grammar"
    fp = _grammar_fingerprint(files)
    if dedupe and root.is_dir():
        prev = sorted(d for d in root.iterdir() if (d / "manifest.json").is_file())
        if prev:
            try:
                last = json.load(open(prev[-1] / "manifest.json"))
            except (OSError, ValueError):
                last = {}
            if last.get("fingerprint") == fp:
                return {"name": prev[-1].name, "n": len(files),
                        "missing": missing, "os": os_name, "skipped": True}
    dest = root / stamp
    while dest.exists():                       # avoid clobber on sub-second retries
        stamp += "x"
        dest = root / stamp
    dest.mkdir(parents=True)
    fileinfo = []
    for p in files:
        shutil.copy2(p, dest / p.name)
        fileinfo.append({"name": p.name, "src": str(p), "sha256": _file_sha(p)})
    manifest = {
        "created_at": now_iso(), "stamp": stamp, "os": os_name, "fingerprint": fp,
        "syscalls": conf.get("enable_syscalls", []) or [],
        "defines": {c: [x.name for x in mapping[c]] for c in mapping},
        "missing": missing, "files": fileinfo, "git_head": _git_head(),
    }
    with open(dest / "manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)
    return {"name": dest.name, "n": len(files), "missing": missing,
            "os": os_name, "skipped": False}


# ---- commands --------------------------------------------------------------
def cmd_start(cfg_arg, executors=None, allow_concurrent=False, force=False):
    if not MANAGER_BIN.exists() or not os.access(MANAGER_BIN, os.X_OK):
        die("syz-manager not built at %s (run: make manager)" % MANAGER_BIN)
    # The coverage device is exclusive, and a wedged executor holds it forever.
    # Without this the manager dies at startup with "open of kcov device failed
    # (errno 16)" and no restart can ever succeed -- which is how a single hung
    # program turned into a halted campaign rather than a recovered one.
    _, wedged = reap_orphan_executors(None)
    if wedged:
        die("cannot start: executor pid(s) %s are wedged in the kernel "
            "(uninterruptible sleep) and still hold the coverage device. "
            "syz-manager would die with \"open of kcov device failed "
            "(errno 16)\". Nothing on this boot can free it -- REBOOT the machine."
            % ", ".join(str(p) for p in wedged))
    cfg = Path(cfg_arg)
    if not cfg.is_file():
        die("config not found: %s" % cfg_arg)
    cfg = cfg.resolve()
    sid = cfg.name[:-4] if cfg.name.endswith(".cfg") else cfg.stem

    conf = load_config(cfg)
    workdir = conf.get("workdir")
    http = conf.get("http", "")
    if not workdir:
        die('config has no "workdir": %s' % cfg)

    prev = refresh_status(sid)
    if prev and prev.get("status") == "running":
        die("session '%s' is already running (pid %s). Use restart or stop first."
            % (sid, prev.get("pid")))

    # Bare metal: a single device means a single /dev/pishi and a single http port,
    # so two managers would fight over both. Refuse to start a second session.
    if not allow_concurrent:
        for other in all_ids():
            if other == sid:
                continue
            st = refresh_status(other)
            if st and st.get("status") == "running" and state_pid_alive(st):
                die("session '%s' is already running (pid %s).\n"
                    "Only one session can run at a time: they would contend for the "
                    "kcov device (%s) and http %s.\n"
                    "Stop it first (%s stop %s), or pass --allow-concurrent if this "
                    "session really targets separate hardware."
                    % (other, st.get("pid"), (conf.get("kext_coverage") or {})
                       .get("kcov_device", "/dev/pishi"), st.get("http", ""),
                       sys.argv[0], other))

    # The previous run's ring buffer is about to be overwritten in place. If it
    # was never collected, that crash/hang is unreproducible afterwards.
    if prev and not force:
        pending = uncollected_run(prev)
        if pending:
            die("'%s' ran on %s and was never collected; its %d ring-buffer "
                "slot(s) hold the last programs from that run and starting "
                "again overwrites them.\n"
                "  last collect: %s\n"
                "  save it first : %s collect %s crash|hang\n"
                "  or skip        : %s start %s --force"
                % (sid, pending["run_started"], pending["slots"],
                   pending["last_collect"], sys.argv[0], sid, sys.argv[0], cfg_arg))

    # Session isn't running, so any leftover scratch dirs are stale — clear them
    # so executor indices restart at 0 instead of climbing across runs.
    stale = clean_scratch(sid)
    if stale:
        print("  cleaned %d stale executor scratch dir(s)" % stale)

    # Preserve the pre-run corpus/ring_buffer as reusable inputs. This is the
    # safe moment to copy corpus.db (the manager isn't writing it yet). Dedupe
    # skips it when the corpus is unchanged since the last snapshot.
    snap = make_snapshot(sid, workdir, cfg, label="auto", dedupe=True)
    if snap:
        print("  snapshot: saved pre-run inputs -> snapshots/%s" % snap)
    else:
        print("  snapshot: skipped, these inputs are already saved")

    (Path(workdir) / "results").mkdir(parents=True, exist_ok=True)
    ts = now_ts()
    bench = str(Path(workdir) / "results" / ("bench-%s.json" % ts))
    logf = str(Path(workdir) / "results" / ("run-%s.log" % ts))

    # Preserve the grammar this run uses: the sys/<os>/*.txt files that define
    # the enabled syscalls. They are compiled into syz-manager and untracked, so
    # without this the exact descriptions are unrecoverable once they change.
    g = save_grammar(workdir, conf, ts)
    if g and g.get("name") and not g.get("skipped"):
        print("  grammar : saved %d description file(s) -> grammar/%s"
              % (g["n"], g["name"]))
    elif g and g.get("skipped"):
        print("  grammar : unchanged since grammar/%s" % g["name"])
    if g and g.get("missing"):
        warn("grammar: %d enabled syscall(s) not defined in sys/%s/*.txt: %s"
             % (len(g["missing"]), g["os"], ", ".join(g["missing"])))

    # syz-manager truncates cover_log on start (os.Create), so archive the prior
    # run's basic-block log first -- named by its own mtime, matching results/.
    cl = (conf.get("kext_coverage") or {}).get("cover_log")
    if cl:
        cl = Path(cl) if os.path.isabs(cl) else Path(workdir) / cl
    else:
        cl = Path(workdir) / "cover.log"
    if cl.exists() and cl.stat().st_size > 0:
        arch = Path(workdir) / "results" / ("cover-%s.log" % datetime.fromtimestamp(
            cl.stat().st_mtime).strftime("%Y%m%d-%H%M%S"))
        if not arch.exists():
            shutil.copy2(cl, arch)
            print("  cover  : archived prior BB log -> results/%s" % arch.name)

    print("starting '%s'" % sid)
    print("  config : %s" % cfg)
    print("  workdir: %s" % workdir)
    if (Path(workdir) / "corpus.db").exists():
        print("  corpus : resuming from existing corpus.db")

    log_fh = open(logf, "w")
    proc = subprocess.Popen(
        [str(MANAGER_BIN), "-config", str(cfg), "-bench", bench],
        stdout=log_fh, stderr=subprocess.STDOUT,
        cwd=str(REPO_ROOT), start_new_session=True,
    )
    time.sleep(1)
    if proc.poll() is not None:
        warn("syz-manager exited immediately; last log lines:")
        sys.stderr.write("".join(open(logf).readlines()[-20:]))
        die("failed to start '%s'" % sid)

    run_count = (prev.get("run_count", 0) if prev else 0) + 1
    # exec_count: how many executors this session wants; remembered so resume/
    # restart bring the same number back up against the new (random) rpc port.
    # Default is 1 (single device == single executor); -e / --no-executor override.
    exec_count = executors if executors is not None else DEFAULT_EXECUTORS
    state = {
        "id": sid, "config": str(cfg), "workdir": workdir, "http": http,
        "status": "running", "pid": proc.pid, "boot_epoch": boot_epoch(),
        "bench": bench, "stdout": logf,
        "started_at": now_iso(), "stopped_at": None, "run_count": run_count,
        "exec_count": exec_count, "executors": [],
    }
    save_state(state)
    print("  pid    : %s" % proc.pid)
    if http:
        print("  http   : http://%s" % http)
    print("  log    : %s" % logf)

    if exec_count > 0:
        start_executors(state, exec_count)
    else:
        # No auto executor: surface the rpc port + a copy-paste runner command.
        port = wait_for_rpc_port(logf)
        if port:
            state["rpc_port"] = port
            save_state(state)
            print("  rpc    : %s" % port)
            # Materialise the renamed copy now so the command below is runnable
            # as printed -- a kext matching on process name rejects the other.
            scratch = exec_scratch(sid, 0)
            scratch.mkdir(parents=True, exist_ok=True)
            print("  attach : (cd %s && %s runner 0 127.0.0.1 %s)"
                  % (scratch, executor_binary(state, scratch), port))
        else:
            warn("rpc port not seen in manager log yet; check: %s logs %s"
                 % (sys.argv[0], sid))


def stop_one(sid):
    state = load_state(sid)
    if not state:
        die("no such session: %s" % sid)
    pid = state.get("pid")
    boot = state.get("boot_epoch")   # a pid from a previous boot is not ours to kill
    if not pid_alive(pid, boot):
        print("'%s' is not running" % sid)
        stop_executors(state)  # reap any orphaned executors + scratch dirs
        if state.get("status") == "running":
            state["status"] = "crashed"
        save_state(state)
        clean_scratch(sid)
        reap_trash()
        return
    # Stop executors first so they detach cleanly before the manager goes away.
    stop_executors(state)
    save_state(state)
    print("stopping '%s' (pid %s, graceful SIGINT, up to %ds)..." % (sid, pid, STOP_TIMEOUT))
    try:
        os.kill(int(pid), signal.SIGINT)
    except OSError:
        pass
    waited = 0
    while pid_alive(pid, boot) and waited < STOP_TIMEOUT:
        time.sleep(1)
        waited += 1
    if pid_alive(pid, boot):
        warn("still alive after %ds; sending SIGTERM" % STOP_TIMEOUT)
        try:
            os.kill(int(pid), signal.SIGTERM)
        except OSError:
            pass
        time.sleep(2)
    if pid_alive(pid, boot):
        warn("still alive; sending SIGKILL")
        try:
            os.kill(int(pid), signal.SIGKILL)
        except OSError:
            pass
    # Record the stop BEFORE any cleanup: the scratch trees are millions of
    # entries, and a state file that still says "running" while a delete grinds
    # away is exactly what makes a stop look hung.
    state["status"] = "stopped"
    state["stopped_at"] = now_iso()
    save_state(state)
    # Manager + tracked executors are down; sweep any orphaned scratch dirs.
    orphans = clean_scratch(sid)
    if orphans:
        print("  cleaned %d orphaned executor scratch dir(s)" % orphans)
    trees = reap_trash()
    if trees:
        print("  deleting %d retired scratch tree(s) in the background" % trees)
    print("  stopped '%s'" % sid)


def cmd_stop(target):
    if target == "all":
        stopped = False
        for sid in all_ids():
            state = refresh_status(sid)
            if state and state.get("status") == "running":
                stop_one(sid)
                stopped = True
        if not stopped:
            print("no running sessions")
        return
    stop_one(resolve_id(target))


def cmd_resume(target, executors=None, allow_concurrent=False, force=False):
    sid = resolve_id(target)
    state = refresh_status(sid)
    if state and state.get("status") == "running":
        die("session '%s' is already running (pid %s)." % (sid, state.get("pid")))
    # Free the coverage device before trying: this session's own executors are
    # tracked and left alone, but a leftover from a wedged run would make the
    # manager die at startup with EBUSY (see reap_orphan_executors).
    _, wedged = reap_orphan_executors(state)
    if wedged:
        die("cannot resume: executor pid(s) %s are wedged in the kernel and hold "
            "the coverage device; only a reboot frees it."
            % ", ".join(str(p) for p in wedged))
    cfg = config_for_id(sid)
    if not cfg:
        die("cannot find config for '%s' (looked in registry and config/%s.cfg)" % (sid, sid))
    # Default to however many executors this session last ran with.
    if executors is None:
        executors = state.get("exec_count", DEFAULT_EXECUTORS) if state else DEFAULT_EXECUTORS
    cmd_start(str(cfg), executors=executors, allow_concurrent=allow_concurrent,
              force=force)


def cmd_restart(target, executors=None, allow_concurrent=False, force=False):
    sid = resolve_id(target)
    state = load_state(sid)
    if state and state_pid_alive(state):
        stop_one(sid)
    cmd_resume(sid, executors=executors, allow_concurrent=allow_concurrent,
               force=force)


def cmd_exec_start(target, count):
    sid = resolve_id(target)
    state = refresh_status(sid)
    if not state:
        die("no such session: %s" % sid)
    if state.get("status") != "running" or not state_pid_alive(state):
        die("session '%s' is not running; start it first" % sid)
    before = len(live_executors(state))
    start_executors(state, before + count)
    # Remember the new desired count so resume/restart keep it.
    state["exec_count"] = len(live_executors(state))
    save_state(state)
    print("executors now running: %d" % state["exec_count"])


def cmd_exec_stop(target):
    sid = resolve_id(target)
    state = load_state(sid)
    if not state:
        die("no such session: %s" % sid)
    stop_executors(state)
    state["exec_count"] = 0
    save_state(state)
    print("stopped executors for '%s' (manager left running)" % sid)


def cmd_list():
    ids = all_ids()
    if not ids:
        print("no sessions yet - start one with: %s start config/<name>.cfg" % sys.argv[0])
        return
    widths = (37, 8, 6, 6, 11, 7, 5, 8, 6, 24)
    print(fmt_row(("SESSION", "STATUS", "PID", "EXECS", "EXEC_TOTAL", "RATE/s",
                   "COV", "CRASHES", "HANGS", "HTTP"), widths))
    for sid in ids:
        state = refresh_status(sid)
        pid = state.get("pid")
        workdir = state["workdir"]
        m = bench_metrics(latest_bench(workdir))
        rl = run_log_stats(workdir)          # current-run count + rate, fresher than bench
        ev = crash_events(state)             # from collect bundles, not workdir/crashes
        http = state.get("http", "")
        print(fmt_row((
            sid, state.get("status", "?"),
            pid if state_pid_alive(state) else "-",
            len(live_executors(state)),
            rl["exec total"] or m["exec total"] or "-", rl["rate"] or "-",
            rl["coverage"] or m["coverage"] or "-",
            ev.get("crash", 0), ev.get("hang", 0),
            ("http://%s" % http) if http else "-",
        ), widths))


def status_lines(sid, rawcover=False):
    """Build the status dashboard for one session as a list of lines.

    Shared by 'status' (print once) and 'watch' (redraw on an interval).
    Headline live metrics (coverage/corpus/exec total/rate) come from the run
    log (~10s fresh); the rest come from the latest bench record. Basic blocks
    come from the cheap on-disk cover_log unless rawcover=True, which queries the
    live /rawcover (authoritative but triggers manager-side coverage init).
    """
    state = refresh_status(sid)
    if not state:
        return None
    workdir = state["workdir"]
    bench = latest_bench(workdir)
    m = bench_metrics(bench)
    rl = run_log_stats(workdir)
    lifetime = session_exec_lifetime(workdir)
    ev = crash_events(state)
    http = state.get("http", "")
    execs = live_executors(state)
    L = [
        "session   : %s" % sid,
        "status    : %s" % state.get("status"),
        "config    : %s" % state.get("config"),
        "workdir   : %s" % workdir,
        "http      : %s" % (("http://%s" % http) if http else "-"),
        "pid       : %s" % state.get("pid"),
        "runs      : %s" % state.get("run_count"),
        "started   : %s" % state.get("started_at"),
        "stopped   : %s" % state.get("stopped_at"),
        "log       : %s" % state.get("stdout"),
    ]
    if state.get("rpc_port"):
        L.append("rpc port  : %s" % state.get("rpc_port"))
    L.append("executors : %d live%s" % (
        len(execs),
        (" (pids " + ", ".join(str(e["pid"]) for e in execs) + ")") if execs else ""))
    # Basic blocks: default to the cheap on-disk cover_log (no manager
    # interaction). Only query the live /rawcover when explicitly asked, since
    # its first hit triggers manager-side coverage init (logs + symbolization).
    bb = None
    if rawcover and state.get("status") == "running" and state_pid_alive(state):
        n = rawcover_count(state.get("http"))
        if n is not None:
            bb = "%s (rawcover, live -- triggered manager cover init)" % n
    if bb is None:
        cl = cover_log_path(state)
        archives = cover_log_archives(workdir)
        configured = bool((load_config(state["config"]).get("kext_coverage") or {}
                           ).get("cover_log")) if state.get("config") else False
        if cl.exists() or archives:
            bb = "%s (this run) / %s (all runs, cover_log)" % (
                bb_unique([cl]), bb_unique([cl] + archives))
        elif configured:
            bb = "- (cover_log configured, no data yet -- run to populate)"
        else:
            bb = "- (cover_log not set; add kext_coverage.cover_log, or --rawcover)"
    L += [
        "-- metrics (run log = live ~10s; bench = ~60s) --",
        "coverage   : %s (syz signal)" % (rl["coverage"] or m["coverage"] or "-"),
        "basic blks : %s" % bb,
        "corpus     : %s" % (rl["corpus"] or m["corpus"] or "-"),
        "exec total : %s (this run) / %s (all runs)" % (
            rl["exec total"] or m["exec total"] or "-", lifetime or "-"),
        "exec rate  : %s/sec" % (rl["rate"] or "-"),
        "incidents  : %s crash / %s hang (+%s snapshot) collected" % (
            ev.get("crash", 0), ev.get("hang", 0), ev.get("snapshot", 0)),
        "crash types: %s" % (m["crash types"] or "-"),
        "uptime     : %s%s" % (
            fmt_uptime(m["uptime"]),
            " (%s sec)" % m["uptime"] if m["uptime"] else ""),
    ]
    return L


def _status_block(sid, tail, rawcover=False):
    """status_lines for sid plus an optional N-line raw run-log tail."""
    lines = status_lines(sid, rawcover=rawcover)
    if lines is None:
        return None
    if tail:
        log = latest_run_log(load_state(sid)["workdir"])
        if log:
            lines = lines + ["", "-- run log tail --"] + tail_text(log).splitlines()[-tail:]
    return lines


def cmd_status(target, watch=False, interval=10, tail=None, rawcover=False):
    """Single-session dashboard: static once, or --watch to redraw until Ctrl-C.

    tail defaults to 0 lines when static and 8 when watching; --tail overrides.
    Basic blocks come from the on-disk cover_log; --rawcover instead queries the
    live manager (authoritative, but triggers its coverage init). For the raw,
    pipe-friendly log stream, use 'logs' instead.
    """
    sid = resolve_id(target)
    if status_lines(sid) is None:
        die("no such session: %s" % sid)
    tail = (8 if watch else 0) if tail is None else tail
    if not watch:
        print("\n".join(_status_block(sid, tail, rawcover)))
        return
    try:
        while True:
            block = _status_block(sid, tail, rawcover)
            if block is None:
                die("session vanished: %s" % sid)
            out = ["fuzz-session status --watch  (every %ds, Ctrl-C to quit)  %s" % (
                       interval, now_iso()), ""] + block
            # Clear screen + home, then repaint (atomic-ish, no flicker scroll).
            sys.stdout.write("\033[2J\033[H" + "\n".join(out) + "\n")
            sys.stdout.flush()
            time.sleep(interval)
    except KeyboardInterrupt:
        sys.stdout.write("\n")


def cmd_collect(target, kind="snapshot", out=None, pad=300, since=None,
                artifacts_dir=None):
    """Bundle everything needed to reproduce one incident, before you restart.

    You say which kind it was -- we do not try to infer it, because a hang and a
    clean stop leave identical traces on disk. The kind picks the folder:
    artifacts/{crashes,hangs,snapshots}/<ts>/.

    Content is the same reproduction set in every case (config, all logs, bench,
    cover logs, ring_buffer, corpus.db, registry record) plus any panic reports
    from PANIC_DIRS inside the run's time window. Panic reports only exist for a
    real kernel panic, so a crash without them, or a hang with them, is flagged
    rather than silently accepted. Read-only w.r.t. the workdir.
    """
    sid = resolve_id(target)
    state = refresh_status(sid)
    if not state:
        die("no such session: %s" % sid)
    workdir = Path(state["workdir"])
    results = workdir / "results"

    # Remember an explicit --artifacts-dir so later collects and the ls/status
    # counters all agree on where this session's ledger lives.
    if artifacts_dir:
        state["artifacts_dir"] = str(Path(artifacts_dir).expanduser().resolve())
        save_state(state)

    # Panic reports in this run's window [start - pad, stopped + pad]; a running
    # or unknown session uses now as the upper bound.
    since_epoch = since if since is not None else run_start_epoch(workdir)
    until_epoch = _iso_epoch(state.get("stopped_at")) or time.time()
    reports = collect_reports(since_epoch, until_epoch, pad=pad)

    # Only a kernel-panic artifact proves the kernel died. A syz-manager*.diag
    # does not: those are Microstackshots reports, which macOS writes for
    # sustained CPU use -- normal fuzzer behaviour, not evidence of anything.
    panics = [Path(r).name for r in reports
              if Path(r).name.endswith((".kernel.core.log", ".panic"))]

    if out:                                         # explicit -o wins
        dest = Path(out)
    else:
        # now_ts() is second-granularity, so two collects in the same second
        # would land in one dir and silently merge into a single incident.
        base = artifacts_root(state) / INCIDENT_DIRS[kind] / now_ts()
        dest, n = base, 1
        while dest.exists():
            dest = Path("%s.%d" % (base, n))
            n += 1
    dest.mkdir(parents=True, exist_ok=True)

    copied, skipped = [], []

    def grab(src, subdir="", link=False):
        if not src:
            return
        src = Path(src)
        if not src.exists():
            skipped.append(str(src))
            return
        d = dest / subdir
        d.mkdir(parents=True, exist_ok=True)
        try:
            if src.is_dir():
                shutil.copytree(src, d / src.name, dirs_exist_ok=True)
            elif link:
                hardlink_or_copy(src, d / src.name)
            else:
                shutil.copy2(src, d / src.name)
            copied.append(str(src))
        except OSError as e:
            skipped.append("%s (%s)" % (src, e))

    # Session's own artifacts.
    grab(state.get("config"))
    grab(latest_run_log(workdir), "logs")
    grab(results / "manager.log", "logs")
    for exe in sorted(results.glob("executor-*.log")):
        grab(exe, "logs")
    grab(latest_bench(workdir), "logs")
    grab(state_file(sid))                       # the registry record
    # Basic-block coverage: the crashing run's cover_log (fsync'd, survives the
    # panic) plus any archived per-run logs. If the manager is still up, also
    # snapshot the live full set from /rawcover.
    grab(cover_log_path(state), "cover")
    for arch in cover_log_archives(workdir):
        grab(arch, "cover")
    if state.get("status") == "running" and state_pid_alive(state):
        rc = rawcover_text(state.get("http"))
        if rc is not None:
            (dest / "cover").mkdir(parents=True, exist_ok=True)
            (dest / "cover" / "rawcover.txt").write_text(rc)
            copied.append("/rawcover @ %s (%d PCs)" % (
                state.get("http"), sum(1 for x in rc.splitlines() if x.strip())))
    # Self-contained replay material (user opted in; may be large).
    grab(workdir / "corpus.db")
    grab(workdir / "ring_buffer")
    # The grammar tree is already deduplicated by fingerprint (save_grammar keeps
    # one directory per distinct description set), so linking it costs nothing
    # and keeps the bundle self-contained.
    grab(workdir / "grammar")               # descriptions the run used (save_grammar)

    # Panic reports: take them under the workdir once, then link. Previously each
    # snapshot copied every report in its window -- 5.7MB of the 6.6MB bundle in a
    # real run -- and cited files in an OS-rotated directory.
    linked = 0
    for r in reports:
        try:
            kept = intake_report(workdir, r)
        except OSError as e:
            skipped.append("%s (%s)" % (r, e))
            continue
        d = dest / "reports"
        d.mkdir(parents=True, exist_ok=True)
        try:
            if hardlink_or_copy(kept, d / kept.name):
                linked += 1
            copied.append(str(r))
        except OSError as e:
            skipped.append("%s (%s)" % (r, e))

    # Manifest: status snapshot + what was gathered + a run-log tail.
    log = latest_run_log(workdir)
    tail = tail_text(log).splitlines()[-15:] if log else []
    since_str = _epoch_iso(since_epoch)
    until_str = _epoch_iso(until_epoch)

    # What you said happened vs what the machine left behind. Neither case is
    # fatal -- a panic can fail to write its log, and a hang can follow an
    # earlier unnoticed panic -- but you should know before you restart.
    notes = []
    if kind == "crash" and not panics:
        notes.append("no kernel panic log found in the window -- if the machine "
                     "did reboot, widen --pad or check the panic dirs")
    if kind == "hang" and panics:
        notes.append("kernel panic log present (%s) -- this may have been a crash"
                     % ", ".join(panics))

    with (dest / "event.json").open("w") as f:
        json.dump({"session": sid, "kind": kind, "collected_at": now_iso(),
                   "window": [since_str, until_str],
                   "panics": panics,
                   "reports": [Path(r).name for r in reports],
                   "notes": notes}, f, indent=2)

    manifest = ["collected : %s" % now_iso(),
                "kind      : %s" % kind,
                "panic logs: %s" % (", ".join(panics) if panics else "none"),
                "window    : incident time in [%s, %s] (pad %ds)" % (
                    since_str, until_str, pad),
                "panic dirs: %s" % ", ".join(str(d) for d in PANIC_DIRS),
                ""]
    manifest += (status_lines(sid) or [])
    manifest += ["", "-- collected files (%d) --" % len(copied)]
    manifest += ["  %s" % c for c in copied]
    if skipped:
        manifest += ["", "-- missing / skipped --"] + ["  %s" % s for s in skipped]
    if tail:
        manifest += ["", "-- run log tail --"] + tail
    (dest / "manifest.txt").write_text("\n".join(manifest) + "\n")

    print("%s  %s" % (style(kind, "bold"), dest))
    print("  gathered  : %d item(s)%s"
          % (len(copied),
             "  (%d report(s) hardlinked, no extra disk)" % linked if linked else ""))
    print("  panic logs: %s" % (", ".join(panics) if panics else "none"))
    if reports and not panics:
        print("  other     : %s (context only, not panic evidence)"
              % ", ".join(Path(r).name for r in reports))
    for n in notes:
        warn(n)
    if skipped:
        warn("%d item(s) missing/skipped (see manifest.txt)" % len(skipped))


def cmd_compare(targets):
    ids = all_ids() if targets == ["all"] else [resolve_id(t) for t in targets]
    if not ids:
        die("no sessions to compare")
    widths = (45, 8, 9, 9, 12, 7, 7, 10)
    print(fmt_row(("SESSION", "STATUS", "COVERAGE", "CORPUS", "EXEC_TOTAL",
                   "CRASHES", "CTYPES", "UPTIME"), widths))
    for sid in ids:
        state = refresh_status(sid)
        if not state:
            warn("skipping unknown session: %s" % sid)
            continue
        m = bench_metrics(latest_bench(state["workdir"]))
        print(fmt_row((
            sid, state.get("status", "?"),
            m["coverage"] or "-", m["corpus"] or "-", m["exec total"] or "-",
            m["crashes"] or "-", m["crash types"] or "-", fmt_uptime(m["uptime"]),
        ), widths))


def resolve_bench(target):
    """Locate a bench file from a session id, a .cfg, or a direct path.

    A direct path may be a bench-*.json file or a workdir/results dir; a
    session id or config resolves through the registry (else config/<id>.cfg's
    derived workdir) to its newest bench file.
    """
    if target:
        p = Path(target)
        if p.is_file():
            return p
        if p.is_dir():
            return latest_bench(p.parent if p.name == "results" else p)
    sid = resolve_id(target)
    state = load_state(sid)
    if state:
        return latest_bench(state["workdir"])
    cfg = config_for_id(sid)
    if cfg:
        workdir = load_config(cfg).get("workdir")
        if workdir:
            return latest_bench(workdir)
    return None


def cmd_bench(target, last=False, jsonl=False, keys=None, indent=2):
    """Convert a bench stream to valid JSON on stdout (never touches the file).

    Default: a single JSON array of every snapshot. --last: only the final
    snapshot (a JSON object). --jsonl: one compact object per line (JSON Lines).
    """
    bench = resolve_bench(target)
    if not bench:
        die("no bench file for: %s" % target)
    records = list(bench_records(bench))
    if not records:
        die("bench file has no complete records yet: %s" % bench)
    if keys:
        records = [{k: r.get(k, None) for k in keys} for r in records]
    if last:
        print(json.dumps(records[-1], indent=None if jsonl else indent))
    elif jsonl:
        for r in records:
            print(json.dumps(r))
    else:
        print(json.dumps(records, indent=indent))


def cmd_logs(target, follow):
    sid = resolve_id(target)
    state = load_state(sid)
    if not state:
        die("no such session: %s" % sid)
    logf = state.get("stdout")
    if not logf or not Path(logf).exists():
        die("no log file for '%s'" % sid)
    args = ["tail", "-f", logf] if follow else ["tail", "-n", "40", logf]
    subprocess.call(args)


def cmd_rm(target):
    sid = resolve_id(target)
    state = refresh_status(sid)
    if not state:
        die("no such session: %s" % sid)
    if state.get("status") == "running":
        die("'%s' is running; stop it first" % sid)
    state_file(sid).unlink()
    print("removed session record '%s' (workdir left intact)" % sid)


# ---- config naming convention ----------------------------------------------
# <Kext>_<YYMMDD>_<cov-token>_<label...>
#   cov-token : cov | nocov | cov-<backend>   (bare 'cov' == pishi)
#   label     : free-form (grammar tier + modifiers + seq); may contain anything,
#               which is exactly why the binary cov field must precede it.
COV_TOKEN_RE = re.compile(r"^(cov|nocov)(?:-([a-z0-9]+))?$")
BACKEND_DEVICE = {"pishi": "/dev/pishi", "kextfuzz": "/dev/kextfuzz", "ksancov": ""}


def parse_config_name(basename):
    """Split a config basename per the convention.

    Returns a dict, or None when it does not follow the convention. Because the
    cov token sits at a fixed slot before the free-form label, this is a plain
    positional split -- no regex over the whole name.
    """
    parts = basename.split("_")
    if len(parts) < 3:
        return None
    m = COV_TOKEN_RE.match(parts[2])
    if not m:
        return None
    cover = m.group(1) == "cov"
    backend = m.group(2) or ("pishi" if cover else None)
    return {
        "kext": parts[0], "date": parts[1], "cov_token": parts[2],
        "cover": cover, "backend": backend,
        "label": "_".join(parts[3:]), "label_tokens": parts[3:],
    }


def build_config_name(kext, date, cover, backend, label):
    """Inverse of parse_config_name: the name is an OUTPUT of the selections."""
    tok = "cov" if cover else "nocov"
    if cover and backend and backend != "pishi":
        tok += "-" + backend
    return "_".join([kext, date, tok] + ([label] if label else []))


# ---- config lint (drift doctor) --------------------------------------------
def _section(title, items, is_error=False, info=False):
    """Print one check's result. Returns the number of findings.

    info=True marks a check that reports a state worth seeing but which is not
    drift (e.g. a config you have not run yet). Those print as 'note' and the
    caller does not add them to the warning count, so they never imply
    something needs fixing.
    """
    n = len(items)
    if n == 0:
        glyph, tag, col = GLYPH["ok"], "ok", "green"
    elif is_error:
        glyph, tag, col = GLYPH["error"], "ERROR (%d)" % n, "red"
    elif info:
        glyph, tag, col = GLYPH["note"], "note (%d)" % n, "cyan"
    else:
        glyph, tag, col = GLYPH["warn"], "WARN (%d)" % n, "yellow"
    dots = "." * max(2, SECTION_WIDTH - len(title))
    print("  %s %s %s %s" % (style(glyph, col, "bold"), title,
                             style(dots, "grey"), style(tag, col)))
    for it in items:
        print("      %s %s" % (style("-", "grey"), it))
    return n


def _group(title):
    """Header separating the lint's check groups."""
    print("\n%s" % style(title, "bold"))


def cmd_lint():
    """Read-only lint of configs, workdirs and the session registry.

    Reports drift that manual editing introduces; never modifies anything.
    Exits 1 if any ERROR-level finding is present.
    """
    cfgs, parse_errs = {}, []
    for f in sorted(CONFIG_DIR.glob("*.cfg")):
        try:
            cfgs[f.name[:-4]] = load_config(f)
        except Exception as e:
            parse_errs.append("%s: %s" % (f.name, e))

    print("%s  %s config(s) in %s" % (style("lint", "bold"),
                                      len(cfgs) + len(parse_errs), CONFIG_DIR))
    errors = warns = notes = 0

    _group("config files")
    errors += _section("config parse errors", parse_errs, is_error=True)

    # --- configs vs workdirs ---
    mism, orphaned, neverrun, nokobj, nocoverlog = [], [], [], [], []
    by_workdir = collections.defaultdict(list)
    for b, d in sorted(cfgs.items()):
        wd = d.get("workdir", "")
        if "_" in b:
            kext, variant = b.split("_", 1)
            expect = str(WORKDIR_ROOT / kext / variant)
            if wd != expect:
                mism.append("%s -> %s (name implies %s)" % (b, wd, Path(expect).name))
        if wd:
            by_workdir[wd].append(b)
            if not Path(wd).is_dir():
                # A missing workdir means two very different things. With a
                # registry record the session ran and its data has since gone
                # -- real drift. Without one it was simply never started, which
                # is normal for the unrun arm of a cov/nocov pair.
                if state_file(b).exists():
                    orphaned.append("%s -> %s (ran; workdir gone)" % (b, Path(wd).name))
                else:
                    neverrun.append("%s -> %s" % (b, Path(wd).name))
        if d.get("cover") and not d.get("kernel_obj"):
            nokobj.append(b)
        if d.get("cover") and not (d.get("kext_coverage") or {}).get("cover_log"):
            nocoverlog.append(b)

    _group("configs vs workdirs")
    errors += _section("name<->workdir mismatch", mism, is_error=True)
    errors += _section("workdir shared by 2+ configs",
                       ["%s <- %s" % (Path(w).name, ", ".join(c))
                        for w, c in sorted(by_workdir.items()) if len(c) > 1],
                       is_error=True)
    warns += _section("workdir gone after run (orphaned)", orphaned)
    notes += _section("never run (no workdir, no record)", neverrun, info=True)

    _group("coverage setup")
    warns += _section("cover:true without kernel_obj", nokobj)
    warns += _section("cover:true without cover_log (BBs unlogged)", nocoverlog)

    _group("naming, ids and syscalls")
    # --- kext ids: internal agreement, and agreement with the map ---
    per = collections.defaultdict(lambda: collections.defaultdict(list))
    for b, d in sorted(cfgs.items()):
        kid = (d.get("kext_coverage") or {}).get("kext_id")
        if kid is not None and "_" in b:
            per[b.split("_", 1)[0]][kid].append(b)
    kid_issues = []
    for kext, ids in sorted(per.items()):
        if len(ids) > 1:
            kid_issues.append("%s: configs disagree -> %s"
                              % (kext, {k: len(v) for k, v in sorted(ids.items())}))
    kmap = load_kext_map()
    for kext, ids in sorted(per.items()):
        if kext in kmap:
            for kid, names in sorted(ids.items()):
                if kid != kmap[kext]:
                    kid_issues.append("%s: map says %s, but %s use %s"
                                      % (kext, kmap[kext], ", ".join(names), kid))
    warns += _section("kext_id consistency%s" % (" (vs map)" if kmap else ""), kid_issues)

    # --- naming convention ---
    # Convention: <Kext>_<YYMMDD>_<coverage>[-<mod>...]_<grammar>[_<seq>]
    #   coverage: cov | nocov
    #   grammar: nogram | gramsel | gramsel-extended | gram   ('nogrammar' retired)
    # Configs with a 'test' token are scratch experiments and are exempt.
    lint = []
    for b in sorted(cfgs):
        if "_" not in b:
            lint.append("%s: no <Kext>_<variant> split" % b)
            continue
        variant = b.split("_", 1)[1]
        toks = variant.split("_")
        if "test" in toks:
            continue                       # scratch config, convention does not apply
        issues = []
        if re.search(r"(^|[_-])nogrammar([_-]|$)", variant):
            issues.append("uses 'nogrammar' (prefer 'nogram')")

        covi = [i for i, t in enumerate(toks) if re.fullmatch(r"(no)?cov", t)]
        if covi:
            second = 1
            # cov must be the second token
            if not (covi[-1] == second):
                issues.append("cov token not after date (instead: %s)"
                              % toks[second])
            
            if len(covi) > 1:
                issues.append("cov token appears %dx" % len(covi))
        else:
            issues.append("no cov/nocov token")
        if issues:
            lint.append("%s: %s" % (b, "; ".join(issues)))
    warns += _section("naming convention", lint)

    # --- grammar token vs the syscalls it claims ---
    # nogram == 1 syz_IOServiceOpen + 1 syz_IOConnectCallMethod per UserClient,
    # plus a single generic syz_IOServiceClose (which accepts any connection).
    # So #open must equal #call. A mismatch means the syscall list does not match
    # the name (e.g. per-selector call variants pasted into a 'nogram' config).
    grammar_issues = []
    for b, d in sorted(cfgs.items()):
        toks = b.split("_", 1)[1].split("_") if "_" in b else []
        if "test" in toks:
            continue
        if not re.search(r"(^|_)nogram([_-]|$)", b.split("_", 1)[1] if "_" in b else ""):
            continue
        s = d.get("enable_syscalls", [])
        n_open = sum(1 for x in s if "IOServiceOpen" in x)
        n_call = sum(1 for x in s if "IOConnectCallMethod" in x)
        if n_open != n_call:
            grammar_issues.append("%s: 'nogram' implies 1 call per UC, but open=%d call=%d"
                                  % (b, n_open, n_call))
    warns += _section("grammar token vs syscalls", grammar_issues)

    # --- syscalls target the kext the config is named for ---
    # Catches a config whose enable_syscalls were pasted from another kext.
    wrong_kext = []
    kext_tokens = {k.replace("Family", "") for k in load_kext_map()} or None
    for b, d in sorted(cfgs.items()):
        if "_" not in b:
            continue
        kext = b.split("_", 1)[0]
        stem = kext.replace("Family", "")
        s = [x for x in d.get("enable_syscalls", []) if "$" in x]
        if not s:
            continue
        foreign = [x for x in s if stem.lower() not in x.lower()]
        if len(foreign) == len(s):     # not one syscall mentions this kext
            other = ""
            if kext_tokens:
                hits = [t for t in kext_tokens
                        if t != stem and any(t.lower() in x.lower() for x in s)]
                other = " (they look like %s)" % ", ".join(sorted(hits)) if hits else ""
            wrong_kext.append("%s: none of its %d syscalls mention '%s'%s"
                              % (b, len(s), stem, other))
    warns += _section("syscalls match config's kext", wrong_kext)

    _group("runtime state")
    # --- session registry (read-only: never rewrites state) ---
    stale = []
    live = set()
    for sid in all_ids():
        st = load_state(sid)
        if not st:
            continue
        running = st.get("status") == "running"
        alive = state_pid_alive(st)
        if running and alive:
            live.add(sid)
        elif running and not alive:
            stale.append("%s: recorded running (pid %s) but the process is gone"
                         % (sid, st.get("pid")))
        cfgp = st.get("config")
        if cfgp and not Path(cfgp).exists():
            stale.append("%s: config no longer exists: %s" % (sid, cfgp))
    warns += _section("session registry", stale)

    # --- executor scratch dirs left behind ---
    orphans = []
    for d in sorted(EXEC_SCRATCH_BASE.glob("syz-exec-*")):
        if not d.is_dir():
            continue
        sid = d.name[len("syz-exec-"):].rsplit("-", 1)[0]
        if sid not in live:
            try:
                n = sum(1 for _ in d.iterdir())
            except OSError:
                n = -1
            orphans.append("%s (%d top-level entries) -- '%s clean %s' removes it"
                           % (d, n, sys.argv[0], sid))
    warns += _section("orphaned executor scratch", orphans)

    if errors:
        verdict = style("%d error(s)" % errors, "red", "bold")
    elif warns:
        verdict = style("%d warning(s)" % warns, "yellow", "bold")
    else:
        verdict = style("all clean", "green", "bold")
    detail = "%s, %s" % (style("%d error(s)" % errors, "red" if errors else "grey"),
                         style("%d warning(s)" % warns, "yellow" if warns else "grey"))
    if notes:
        detail += ", %s" % style("%d note(s)" % notes, "cyan")
    print("\n%s  %s" % (verdict, style("(%s)" % detail, "grey")))
    if errors:
        print(style("errors indicate a run would write to the wrong place "
                    "-- fix before fuzzing", "red"))
    sys.exit(1 if errors else 0)


def cmd_clean(target):
    sid = resolve_id(target)
    state = refresh_status(sid)
    if state and state.get("status") == "running":
        die("'%s' is running; its executor scratch is in use. Stop it first." % sid)
    n = clean_scratch(sid)
    # An explicit `clean` should not return until the space is actually back, so
    # reap in the foreground here (still `rm -rf`, not a Python walk).
    reap_trash(background=False)
    print("removed %d executor scratch dir(s) for '%s'" % (n, sid))


def cmd_snapshot(target, label):
    sid = resolve_id(target)
    state = load_state(sid)
    if not state:
        die("no such session: %s" % sid)
    if state.get("status") == "running" and state_pid_alive(state):
        warn("session is running; corpus.db may be captured mid-write. "
             "Stop it first for a guaranteed-consistent snapshot.")
    m = bench_metrics(latest_bench(state["workdir"]))
    name = make_snapshot(sid, state["workdir"], state.get("config"),
                         label=label or "manual", metrics=m)
    if name:
        print("saved snapshot: %s/snapshots/%s" % (state["workdir"], name))
    else:
        print("nothing to snapshot yet (no corpus.db / ring_buffer)")


def cmd_snapshots(target):
    sid = resolve_id(target)
    state = load_state(sid)
    if not state:
        die("no such session: %s" % sid)
    snaps = list_snapshots(state["workdir"])
    if not snaps:
        print("no snapshots for '%s'" % sid)
        return
    widths = (28, 22, 10, 9)
    print(fmt_row(("SNAPSHOT", "CREATED", "CORPUS_B", "COVERAGE"), widths))
    for m in snaps:
        cov = (m.get("metrics") or {}).get("coverage", "")
        print(fmt_row((m["name"], m.get("created_at", "?"),
                       m.get("corpus_bytes", "?"), cov or "-"), widths))


def cmd_restore(target, name):
    sid = resolve_id(target)
    state = refresh_status(sid)
    if not state:
        die("no such session: %s" % sid)
    if state.get("status") == "running" and state_pid_alive(state):
        die("'%s' is running; stop it before restoring" % sid)
    workdir = state["workdir"]
    src = snapshot_root(workdir) / name
    if not src.is_dir():
        names = [m["name"] for m in list_snapshots(workdir)]
        die("no snapshot '%s'. Available: %s" % (name, ", ".join(names) or "(none)"))
    # Back up the current state first so a restore is itself reversible.
    backup = make_snapshot(sid, workdir, state.get("config"), label="pre-restore")
    if backup:
        print("backed up current state -> snapshots/%s" % backup)
    if (src / "corpus.db").exists():
        shutil.copy2(src / "corpus.db", Path(workdir) / "corpus.db")
        print("restored corpus.db")
    else:
        warn("snapshot '%s' contains no corpus.db (it was taken before the session "
             "had a corpus); current corpus.db left unchanged" % name)
    if (src / "ring_buffer").is_dir():
        dst_ring = Path(workdir) / "ring_buffer"
        if dst_ring.exists():
            shutil.rmtree(dst_ring, ignore_errors=True)
        shutil.copytree(src / "ring_buffer", dst_ring)
        print("restored ring_buffer")
    else:
        warn("snapshot '%s' contains no ring_buffer; left unchanged" % name)
    print("restored '%s' from snapshot %s (resume to fuzz from this state)" % (sid, name))


# ---- grammar (enable/disable syscalls) -------------------------------------
def _load_config_editable(path):
    """Load a config for editing, preserving key order. Returns (data, lossy)."""
    raw = Path(path).read_text()
    try:
        return json.loads(raw), False       # plain JSON: order preserved, lossless
    except ValueError:
        return load_config(path), True       # had comments: they will be dropped


def _save_config(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
        f.write("\n")


def cmd_grammar(action, target, patterns, dump_all=False):
    # target may be a session id or a direct path to a .cfg.
    if target.endswith(".cfg") and os.path.isfile(target):
        cfg = Path(target).resolve()
        sid = resolve_id(target)
    else:
        sid = resolve_id(target)
        cfg = config_for_id(sid)
    if not cfg:
        die("cannot find config for '%s'" % sid)
    data, lossy = _load_config_editable(cfg)
    enabled = data.get("enable_syscalls", []) or []
    disabled = data.get("disable_syscalls", []) or []

    if action == "list":
        print("config  : %s" % cfg)
        print("enabled : %d syscall pattern(s)" % len(enabled))
        print("disabled: %d syscall pattern(s) (blacklist)" % len(disabled))
        for s in disabled:
            print("  - %s" % s)
        if dump_all:
            print("-- enabled --")
            for s in enabled:
                print("  %s" % s)
        elif enabled:
            print("(use --all to dump the %d enabled patterns)" % len(enabled))
        return

    if action == "save":
        workdir = data.get("workdir")
        if not workdir:
            die('config has no "workdir": %s' % cfg)
        g = save_grammar(workdir, data, now_ts(), dedupe=False)
        print("config  : %s" % cfg)
        if g and g.get("name"):
            print("saved %d description file(s) -> %s"
                  % (g["n"], Path(workdir) / "grammar" / g["name"]))
        else:
            warn("no sys/*/*.txt defines the enabled syscalls")
        if g and g.get("missing"):
            warn("%d enabled syscall(s) not defined in sys/%s/*.txt: %s"
                 % (len(g["missing"]), g["os"], ", ".join(g["missing"])))
        return

    if not patterns:
        die("usage: grammar %s <id> <syscall-pattern>..." % action)

    if lossy:
        warn("config %s contains comments; they will be dropped on rewrite" % cfg)

    if action == "disable":
        added = [p for p in patterns if p not in disabled]
        disabled += added
        data["disable_syscalls"] = disabled
        print("blacklisted %d new pattern(s) (disable_syscalls now %d):"
              % (len(added), len(disabled)))
        for p in added:
            print("  + %s" % p)
    elif action == "enable":
        removed = [p for p in patterns if p in disabled]
        disabled = [s for s in disabled if s not in patterns]
        data["disable_syscalls"] = disabled
        print("un-blacklisted %d pattern(s) (disable_syscalls now %d)"
              % (len(removed), len(disabled)))
        not_in_enable = [p for p in patterns if enabled and p not in enabled]
        if not_in_enable:
            warn("these are not in enable_syscalls, so still won't run: %s"
                 % ", ".join(not_in_enable))
    elif action == "clear":
        print("cleared %d blacklisted pattern(s)" % len(disabled))
        data["disable_syscalls"] = []

    _save_config(cfg, data)
    state = load_state(sid)
    if state and state.get("status") == "running":
        print("note: '%s' is running the old grammar; apply with: %s restart %s"
              % (sid, sys.argv[0], sid))


# ---- config generation -----------------------------------------------------
# Fields that are pure boilerplate across every config; inherited from a template
# config rather than hardcoded here, so changing e.g. the BKC in one config and
# using it as the template propagates to new ones.
BOILERPLATE_KEYS = ("target", "syzkaller", "procs", "type", "log_file",
                    "kernel_obj", "kernel_obj_file", "sandbox", "reproduce")
# Written in this order to match the existing configs' layout.
CONFIG_KEY_ORDER = ("target", "http", "workdir", "syzkaller", "procs", "type", "cover",
                    "kext_coverage", "ring_buffer_size", "log_file", "kernel_obj",
                    "kernel_obj_file", "sandbox", "reproduce",
                    "enable_syscalls", "disable_syscalls")


def _configs_by_mtime(pattern):
    return sorted(CONFIG_DIR.glob(pattern), key=lambda p: p.stat().st_mtime)


_ALL_CONFIGS = None


def all_configs():
    """[(path, dict)] for every parseable config, newest first. Parsed once."""
    global _ALL_CONFIGS
    if _ALL_CONFIGS is None:
        _ALL_CONFIGS = []
        for f in reversed(_configs_by_mtime("*.cfg")):
            try:
                _ALL_CONFIGS.append((f, load_config(f)))
            except Exception:
                continue
    return _ALL_CONFIGS


def boilerplate_fallback(key):
    """Value of `key` from the newest config that defines it, else (None, None).

    Many older configs omit kernel_obj/kernel_obj_file; without this, generating
    from such a template would silently drop the BKC path and break coverage
    symbolization.
    """
    for path, d in all_configs():
        if key in d:
            return d[key], path
    return None, None


def load_kext_map():
    """Optional authoritative kext -> coverage id map (e.g. exported from Pishi).

    Looked up at $SYZ_KEXT_MAP or config/kext_ids.json. Accepts either
    {"IOSurface": 128, ...} or [{"name": "IOSurface", "id": 128}, ...].
    Bundle ids ("com.apple.iokit.IOSurface") also match on their last component.
    """
    if not KEXT_MAP_PATH.exists():
        return {}
    try:
        data = json.loads(KEXT_MAP_PATH.read_text())
    except ValueError as e:
        warn("ignoring malformed kext map %s: %s" % (KEXT_MAP_PATH, e))
        return {}
    pairs = []
    if isinstance(data, dict):
        pairs = list(data.items())
    elif isinstance(data, list):
        for e in data:
            if isinstance(e, dict):
                name = e.get("name", e.get("kext", e.get("bundle_id")))
                kid = e.get("id", e.get("kext_id"))
                if name is not None and kid is not None:
                    pairs.append((name, kid))
    out = {}
    for name, kid in pairs:
        try:
            kid = int(kid)
        except (TypeError, ValueError):
            continue
        name = str(name)
        out[name] = kid
        if "." in name:                       # com.apple.iokit.IOSurface -> IOSurface
            out.setdefault(name.rsplit(".", 1)[-1], kid)
    return out


def infer_kext_id(kext):
    """Infer a kext's coverage id from existing configs. Returns (id, all_distinct)."""
    found = []
    for f in _configs_by_mtime("%s_*.cfg" % kext):
        try:
            kc = (load_config(f) or {}).get("kext_coverage") or {}
        except Exception:
            continue
        if "kext_id" in kc:
            found.append(kc["kext_id"])
    if not found:
        return None, []
    return found[-1], sorted(set(found))   # newest config wins


def infer_cover(variant):
    """Derive the 'cover' flag from the variant name (…_nocov… vs …_cov…)."""
    if re.search(r"(^|[_-])nocov([_-]|$)", variant):
        return False
    if re.search(r"(^|[_-])cov([_-]|$)", variant):
        return True
    return None


def cmd_new(name, like=None, kext_id=None, cover=None, ring=None, http=None, force=False):
    if name.endswith(".cfg"):
        name = name[:-4]
    if "_" not in name:
        die("name must look like <Kext>_<variant>, e.g. IOSurface_260717_gram_cov")
    kext, variant = name.split("_", 1)

    dest = CONFIG_DIR / ("%s.cfg" % name)
    if dest.exists() and not force:
        die("config already exists: %s (use --force to overwrite)" % dest)

    # Template: explicit --like, else newest config for this kext, else newest overall.
    if like:
        tpl_path = Path(like) if like.endswith(".cfg") and os.path.isfile(like) \
            else config_for_id(resolve_id(like))
        if not tpl_path or not Path(tpl_path).is_file():
            die("cannot find --like config: %s" % like)
    else:
        same = _configs_by_mtime("%s_*.cfg" % kext)
        tpl_path = same[-1] if same else (_configs_by_mtime("*.cfg") or [None])[-1]
        if not tpl_path:
            die("no existing config to use as a template; pass --like <config.cfg>")
    tpl = load_config(tpl_path)

    # kext_id: explicit > kext map (authoritative) > --like template > inference.
    distinct, id_src = [], "--kext-id"
    if kext_id is None:
        kmap = load_kext_map()
        if kext in kmap:
            kext_id, id_src = kmap[kext], "kext map (%s)" % KEXT_MAP_PATH.name
        elif like:
            kext_id, id_src = (tpl.get("kext_coverage") or {}).get("kext_id"), "--like template"
        else:
            kext_id, distinct = infer_kext_id(kext)
            id_src = "inferred from existing %s configs" % kext
    if kext_id is None:
        die("cannot determine kext_id for '%s'. Pass --kext-id N, or add it to a "
            "kext map at %s (e.g. {\"%s\": 128})" % (kext, KEXT_MAP_PATH, kext))
    if len(distinct) > 1:
        warn("configs for %s disagree on kext_id %s; using %s (newest). Override with "
             "--kext-id, or add a kext map at %s to settle it."
             % (kext, distinct, kext_id, KEXT_MAP_PATH))

    if cover is None:
        cover = infer_cover(variant)
        if cover is None:
            cover = True   # configs are overwhelmingly cover:true

    cfg = {}
    borrowed = []
    for k in CONFIG_KEY_ORDER:
        if k in BOILERPLATE_KEYS:
            if k in tpl:
                cfg[k] = tpl[k]
            else:
                # Template omits it (many older configs lack kernel_obj*): take it
                # from the newest config that has it rather than dropping it.
                val, src = boilerplate_fallback(k)
                if val is not None:
                    cfg[k] = val
                    borrowed.append((k, src.name))
        elif k == "http":
            cfg[k] = http or tpl.get("http", "127.0.0.1:56741")
        elif k == "workdir":
            cfg[k] = str(WORKDIR_ROOT / kext / variant)   # derived from the name
        elif k == "cover":
            cfg[k] = cover
        elif k == "kext_coverage":
            kc = dict(tpl.get("kext_coverage") or {})
            kc["kext_id"] = kext_id
            kc.setdefault("kcov_device", "/dev/pishi")
            cfg[k] = {"kcov_device": kc["kcov_device"], "kext_id": kc["kext_id"]}
            # Log each newly-covered basic-block PC (fsync'd per program, so it
            # survives a kernel panic). syz-manager truncates it on start, so it
            # holds THIS run's BBs; start/collect archive it for history. Path is
            # workdir-relative (mgrconfig joins it with workdir at load).
            if cover:
                cfg[k]["cover_log"] = "cover.log"
        elif k == "ring_buffer_size":
            cfg[k] = ring if ring is not None else tpl.get("ring_buffer_size", 5)
        elif k == "enable_syscalls":
            # Only inherit the syscall list on an explicit --like; otherwise leave
            # it empty to paste into (a silently inherited grammar would be worse).
            cfg[k] = list(tpl.get("enable_syscalls", [])) if like else []
        elif k == "disable_syscalls":
            if like and tpl.get("disable_syscalls"):
                cfg[k] = list(tpl["disable_syscalls"])

    _save_config(dest, cfg)
    print("created %s" % dest)
    print("  template : %s" % tpl_path)
    for k, src in borrowed:
        print("  borrowed : %s (missing from template; took it from %s)" % (k, src))
    print("  workdir  : %s" % cfg["workdir"])
    print("  cover    : %s%s" % (cfg["cover"], "" if cover is not None else " (default)"))
    print("  kext_id  : %s  [%s]" % (kext_id, id_src))
    print("  syscalls : %d enabled%s"
          % (len(cfg["enable_syscalls"]),
             " (copied from --like)" if like else " -- paste yours into enable_syscalls"))
    if cfg.get("cover") and not cfg.get("kernel_obj"):
        warn("cover:true but no kernel_obj (BKC path) -- coverage PCs will not symbolize")
    wd = Path(cfg["workdir"])
    if (wd / "corpus.db").exists():
        warn("workdir already has a corpus.db; a run will RESUME from it, not start fresh")
    print("next: %s grammar list %s   |   %s start config/%s.cfg"
          % (sys.argv[0], name, sys.argv[0], name))


# ---- dispatch --------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(
        prog="fuzz-session.py", description="Manage syz-manager fuzzing sessions.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd")

    # "config" groups everything that authors or validates a .cfg.
    cfg_p = sub.add_parser("config", help="author/validate configs (new, lint)")
    cfg_sub = cfg_p.add_subparsers(dest="config_cmd")

    sp = cfg_sub.add_parser("new", help="generate a config from the naming convention")
    sp.add_argument("name", help="<Kext>_<variant>, e.g. IOSurface_260717_gram_cov")
    sp.add_argument("--like", default=None, metavar="ID|CFG",
                    help="copy boilerplate AND enable_syscalls from this config")
    sp.add_argument("--kext-id", dest="kext_id", type=int, default=None,
                    help="kext coverage id (default: kext map, then this kext's configs)")
    sp.add_argument("--cover", dest="cover", action="store_const", const=True, default=None,
                    help="force cover:true (default: inferred from _cov/_nocov in the name)")
    sp.add_argument("--no-cover", dest="cover", action="store_const", const=False,
                    help="force cover:false")
    sp.add_argument("--ring", type=int, default=None, metavar="N", help="ring_buffer_size")
    sp.add_argument("--http", default=None, metavar="HOST:PORT")
    sp.add_argument("--force", action="store_true", help="overwrite an existing config")

    cfg_sub.add_parser("lint", help="check configs/workdirs/registry for drift (read-only)")

    sp = sub.add_parser("start", help="launch a run from a config (+1 executor by default)")
    sp.add_argument("config")
    sp.add_argument("-e", "--executors", type=int, default=None, metavar="N",
                    help="number of local executors to start (default 1)")
    sp.add_argument("--no-executor", dest="executors", action="store_const", const=0,
                    help="don't auto-start an executor; print the runner command instead")
    sp.add_argument("--allow-concurrent", action="store_true",
                    help="permit starting while another session runs (separate hardware only)")
    sp.add_argument("--force", action="store_true",
                    help="start even if the previous run was never collected "
                         "(its ring buffer will be overwritten)")
    sp = sub.add_parser("stop", help="graceful stop (id|config|all)")
    sp.add_argument("target")
    sp = sub.add_parser("resume", help="relaunch from the recorded config")
    sp.add_argument("target")
    sp.add_argument("-e", "--executors", type=int, default=None, metavar="N",
                    help="executor count (default: same as last run)")
    sp.add_argument("--allow-concurrent", action="store_true")
    sp.add_argument("--force", action="store_true",
                    help="start even if the previous run was never collected")
    sp = sub.add_parser("restart", help="stop then resume")
    sp.add_argument("target")
    sp.add_argument("-e", "--executors", type=int, default=None, metavar="N")
    sp.add_argument("--allow-concurrent", action="store_true")
    sp.add_argument("--force", action="store_true",
                    help="start even if the previous run was never collected")
    sp = sub.add_parser("exec-start", help="add executor(s) to a running session")
    sp.add_argument("target")
    sp.add_argument("-n", type=int, default=1, metavar="N", help="how many to add (default 1)")
    sp = sub.add_parser("exec-stop", help="stop a session's executors (manager stays up)")
    sp.add_argument("target")
    sub.add_parser("list", help="table of all sessions")
    sub.add_parser("ls", help="alias for list")
    sp = sub.add_parser("diagnose-hang",
                        help="capture what a wedged executor is blocked in "
                             "(sample + spindump); needs sudo for another "
                             "user's process")
    sp.add_argument("pid", nargs="*", type=int,
                    help="pids to sample (default: every wedged executor found)")
    sp.add_argument("--out", help="directory for the dumps (default: cwd)")

    sp = sub.add_parser("inspect", help="machine-readable JSON status (for fuzz-campaign)")
    sp.add_argument("target")
    for _name, _help in (("status", "dashboard for one session (--watch to redraw)"),
                         ("watch", "alias for 'status --watch'")):
        sp = sub.add_parser(_name, help=_help)
        sp.add_argument("target")
        sp.add_argument("-w", "--watch", action="store_true",
                        help="redraw the dashboard until Ctrl-C")
        sp.add_argument("-i", "--interval", type=int, default=10, metavar="SEC",
                        help="redraw interval when watching (default 10, matching the log cadence)")
        sp.add_argument("--tail", type=int, default=None, metavar="N",
                        help="append N raw run-log lines (default 0 static, 8 watching)")
        sp.add_argument("--rawcover", action="store_true",
                        help="BB count from live /rawcover (authoritative; triggers "
                             "manager coverage init) instead of the on-disk cover_log")
    sp = sub.add_parser("collect", help="save reproduction material for a crash/hang")
    sp.add_argument("target")
    sp.add_argument("kind", nargs="?", choices=EVENT_KINDS, default="snapshot",
                    help="what happened: crash (kernel panicked, machine "
                         "rebooted), hang (wedged, no panic), or snapshot "
                         "(nothing wrong -- just save state). Default snapshot; "
                         "picks artifacts/{crashes,hangs,snapshots}/<ts>/")
    sp.add_argument("--artifacts-dir", metavar="DIR",
                    help="where this session's bundles live; remembered in the "
                         "registry (default <workdir>/%s)" % ARTIFACTS_SUBDIR)
    sp.add_argument("-o", "--out", help="write this one bundle here instead "
                    "(not counted as an incident unless under the artifacts dir)")
    sp.add_argument("--pad", type=int, default=300, metavar="SEC",
                    help="include reports modified this many sec before run start (default 300)")
    sp = sub.add_parser("compare", help="metrics across sessions (id... | all)")
    sp.add_argument("targets", nargs="+")
    sp = sub.add_parser("bench", help="dump a bench stream as valid JSON (id|config|path)")
    sp.add_argument("target", help="session id, config, results dir, or bench-*.json path")
    sp.add_argument("--last", action="store_true",
                    help="emit only the final snapshot (a JSON object)")
    sp.add_argument("--jsonl", action="store_true",
                    help="one compact object per line (JSON Lines) instead of an array")
    sp.add_argument("--keys", help="comma-separated keys to keep (default: all)")
    sp = sub.add_parser("grammar",
                        help="view/edit enabled+disabled syscalls; save the defining descriptions")
    sp.add_argument("action", choices=("list", "disable", "enable", "clear", "save"))
    sp.add_argument("target")
    sp.add_argument("patterns", nargs="*", help="syscall name(s)/glob(s) for disable/enable")
    sp.add_argument("--all", dest="dump_all", action="store_true",
                    help="with 'list', also print all enabled patterns")
    sp = sub.add_parser("logs", help="show a session's log")
    sp.add_argument("target")
    sp.add_argument("-f", "--follow", action="store_true")
    sp = sub.add_parser("rm", help="drop a stopped session from the registry")
    sp.add_argument("target")
    sp = sub.add_parser("clean", help="remove a stopped session's executor scratch dirs")
    sp.add_argument("target")
    sp = sub.add_parser("snapshot", help="save corpus.db + ring_buffer + config now")
    sp.add_argument("target")
    sp.add_argument("-l", "--label", default=None, help="name tag for the snapshot")
    sp = sub.add_parser("snapshots", help="list a session's snapshots")
    sp.add_argument("target")
    sp = sub.add_parser("restore", help="restore corpus+ring_buffer from a snapshot")
    sp.add_argument("target")
    sp.add_argument("name", help="snapshot name (see 'snapshots')")

    args = p.parse_args()
    if not args.cmd:
        p.print_help()
        sys.exit(1)

    if args.cmd == "config":
        if args.config_cmd == "new":
            cmd_new(args.name, like=args.like, kext_id=args.kext_id, cover=args.cover,
                    ring=args.ring, http=args.http, force=args.force)
        elif args.config_cmd == "lint":
            cmd_lint()
        else:
            cfg_p.print_help()
            sys.exit(1)
    elif args.cmd == "start":
        cmd_start(args.config, executors=args.executors,
                  allow_concurrent=args.allow_concurrent, force=args.force)
    elif args.cmd == "stop":
        cmd_stop(args.target)
    elif args.cmd == "resume":
        cmd_resume(args.target, executors=args.executors,
                   allow_concurrent=args.allow_concurrent, force=args.force)
    elif args.cmd == "restart":
        cmd_restart(args.target, executors=args.executors,
                    allow_concurrent=args.allow_concurrent, force=args.force)
    elif args.cmd == "exec-start":
        cmd_exec_start(args.target, args.n)
    elif args.cmd == "exec-stop":
        cmd_exec_stop(args.target)
    elif args.cmd in ("list", "ls"):
        cmd_list()
    elif args.cmd == "diagnose-hang":
        diagnose_hang(args.pid or None, args.out)
    elif args.cmd == "inspect":
        cmd_inspect(args.target)
    elif args.cmd in ("status", "watch"):
        cmd_status(args.target, watch=args.watch or args.cmd == "watch",
                   interval=args.interval, tail=args.tail, rawcover=args.rawcover)
    elif args.cmd == "collect":
        cmd_collect(args.target, args.kind, out=args.out, pad=args.pad,
                    artifacts_dir=args.artifacts_dir)
    elif args.cmd == "compare":
        cmd_compare(args.targets)
    elif args.cmd == "bench":
        keys = [k.strip() for k in args.keys.split(",")] if args.keys else None
        cmd_bench(args.target, last=args.last, jsonl=args.jsonl, keys=keys)
    elif args.cmd == "grammar":
        cmd_grammar(args.action, args.target, args.patterns, dump_all=args.dump_all)
    elif args.cmd == "logs":
        cmd_logs(args.target, args.follow)
    elif args.cmd == "rm":
        cmd_rm(args.target)
    elif args.cmd == "clean":
        cmd_clean(args.target)
    elif args.cmd == "snapshot":
        cmd_snapshot(args.target, args.label)
    elif args.cmd == "snapshots":
        cmd_snapshots(args.target)
    elif args.cmd == "restore":
        cmd_restore(args.target, args.name)


if __name__ == "__main__":
    main()
