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
import fcntl
import json
import os
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
CAMPAIGN_DIR = REPO_ROOT / "campaigns"
STATE_DIR = CAMPAIGN_DIR / ".state"

sys.path.insert(0, str(SCRIPT_DIR))
import crash_fingerprint as cf  # noqa: E402

# `syz-ring-repro -emit-json` translates a minimized culprit into the list of
# IOConnectCallMethod syscall names to disable (JSON). Prefer the built binary;
# fall back to `go run` so the step works in a dev tree with no bin/.
RINGREPRO_BIN = Path(os.environ.get("SYZ_RINGREPRO", REPO_ROOT / "bin/darwin_arm64/syz-ring-repro"))

# Where kernel cores/panics land; SYZ_PANIC_DIR mirrors fuzz-session.py so the
# two agree. The *.gz cores are the ~220MB space hogs we prune.
PANIC_DIRS = [
    Path(os.environ.get("SYZ_PANIC_DIR", "/Library/Logs/DiagnosticReports")),
    Path("/Library/Logs/DiagnosticReports/kernel_panics"),
]
CORE_GLOBS = ("*.kernel.core.gz", "*.kernel.core.log")

DEFAULTS = {
    "budget_hours": 6.0,
    "loop": False,
    "poll_seconds": 600,        # how often to check exec total (10 min)
    "hang_after_seconds": 1800,  # frozen this long with manager alive => hang
    "max_crashes": 20,          # total incidents before the breaker halts
    "min_free_gb": 20.0,        # halt if root disk drops below this
    "keep_cores": 3,            # cores retained after pruning
    "crashloop_window_seconds": 120,   # a run shorter than this is a "fast" crash
    "crashloop_limit": 5,       # this many consecutive fast crashes => halt
    "triage_max_boots": 40,     # give up (halt) if triage can't reach a culprit in this many advances
}


# --- small utilities ---------------------------------------------------------
def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg):
    """Timestamped line to stdout -- launchd captures it to the campaign log."""
    sys.stdout.write("%s  %s\n" % (now_iso(), msg))
    sys.stdout.flush()


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
        "active_seconds": 0.0, "session_id": None, "current_config": None,
        "run_started": None, "last_exec_total": None,
        "crashes": 0, "hangs": 0, "consec_fast_crashes": 0,
        "incidents": [], "started_at": now_iso(), "updated_at": now_iso(),
        "halt_reason": None,
        # coordinator: fuzzing <-> triaging. On a new crash the campaign hands
        # the box to triage, benches the culprit, then resumes fuzzing.
        "phase": "fuzzing", "triage_job": None, "triage_bug_sig": None,
        "triage_boots": 0, "triage_seq": 0, "suppressed_sigs": [],
        "panic_sig_watermark": 0.0,
    }


# Fields added after a campaign's first run; backfill so old state files load.
COORDINATOR_DEFAULTS = {
    "phase": "fuzzing", "triage_job": None, "triage_bug_sig": None,
    "triage_boots": 0, "triage_seq": 0, "suppressed_sigs": [],
    "panic_sig_watermark": 0.0,
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
    """Reason to halt the campaign, or None."""
    total = s["crashes"] + s["hangs"]
    if total >= d["max_crashes"]:
        return "reached max_crashes (%d incidents)" % total
    fg = free_gb()
    if fg < d["min_free_gb"]:
        return "low disk (%.1fGB free < %.1fGB)" % (fg, d["min_free_gb"])
    if s["consec_fast_crashes"] >= d["crashloop_limit"]:
        return ("crash loop (%d crashes under %ds of runtime)"
                % (s["consec_fast_crashes"], d["crashloop_window_seconds"]))
    return None


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
def record_incident(s, d, kind, info):
    """Update counters and the crash-loop tracker for one crash/hang."""
    started = info.get("run_started_epoch")
    ran_for = (time.time() - started) if started else None
    fast = (kind == "crash" and ran_for is not None
            and ran_for < d["crashloop_window_seconds"])
    s["consec_fast_crashes"] = s["consec_fast_crashes"] + 1 if fast else 0
    if kind == "crash":
        s["crashes"] += 1
    else:
        s["hangs"] += 1
    s["incidents"].append({
        "config": s["current_config"], "kind": kind, "at": now_iso(),
        "ran_seconds": round(ran_for) if ran_for else None,
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
        try:
            s["panic_sig_watermark"] = max(s.get("panic_sig_watermark", 0.0),
                                           r.stat().st_mtime)
        except OSError:
            pass
    return sig


def begin_triage(s, d, sig):
    """Pause fuzzing and stand up a triage job for a new bug. Returns True on
    success; on any failure the campaign just resumes fuzzing (no phase change)."""
    info = inspect(s["session_id"]) if s.get("session_id") else {"found": False}
    workdir = info.get("workdir")
    if not workdir:
        log("cannot triage %s: session workdir unknown; resuming fuzzing" % sig)
        return False
    ring = Path(workdir) / "ring_buffer"
    if not ring.is_dir():
        log("cannot triage %s: no ring buffer at %s; resuming fuzzing" % (sig, ring))
        return False

    s["triage_seq"] += 1
    job = "%s_t%d" % (s["name"], s["triage_seq"])
    tri = d.get("triage") or {}
    # Pin the target signature so triage's crash gate is active from the first
    # subset (a second bug firing during minimization won't misdirect it).
    args = ["new", job, "--ring", str(ring), "--target-sig", sig, "--force"]
    for flag, key in (("--executor", "executor"), ("--ringrepro", "ringrepro"),
                      ("--kcov-device", "kcov_device"), ("--kext-id", "kext_id"),
                      ("--sandbox", "sandbox"), ("--max-k", "max_k")):
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
    log("NEW bug %s -> triaging as job %s (fuzzing paused)" % (sig, job))
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
    if s["triage_boots"] > d["triage_max_boots"]:
        s["status"] = "halted"
        s["halt_reason"] = ("triage stuck on %s after %d boots (job %s)"
                            % (s.get("triage_bug_sig"), s["triage_boots"], job))
        save_state(s)
        log("HALT: %s" % s["halt_reason"])
        return
    save_state(s)
    log("triage advance %d/%d for job %s"
        % (s["triage_boots"], d["triage_max_boots"], job))
    triage("run", job)

    st = triage_state(job)
    if not st or st.get("stage") != "DONE":
        stage = st.get("stage") if st else "?"
        log("triage %s at stage %s; will advance again" % (job, stage))
        time.sleep(d["poll_seconds"])
        return

    culprit = st.get("final_culprit")
    if culprit and Path(culprit).exists():
        _bench_culprit(s, culprit)
    else:
        log("triage %s DONE but no culprit file; benching skipped" % job)
    sig = s.get("triage_bug_sig")
    if sig and sig not in s["suppressed_sigs"]:
        s["suppressed_sigs"].append(sig)
    s["phase"] = "fuzzing"
    s["triage_job"] = None
    s["triage_bug_sig"] = None
    s["triage_boots"] = 0
    save_state(s)
    log("triage %s COMPLETE; bug %s benched; resuming fuzzing" % (job, sig))


# --- the loop ----------------------------------------------------------------
def ensure_running(s, cfg):
    """Make sure a live session exists for cfg; resume if a record exists.

    Returns the inspect dict for the (now running) session. Resets the
    per-run exec-total baseline so the hang detector starts clean.
    """
    sid = config_id(cfg)
    info = inspect(sid)
    if info.get("found") and info.get("status") == "running" and info.get("pid_alive"):
        log("session %s already running (pid %s); attaching supervisor"
            % (sid, info.get("pid")))
    else:
        verb = "resume" if info.get("found") else "start"
        target = sid if verb == "resume" else cfg
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


def reconcile_boot(s, d):
    """Handle a run the driver was supervising when it was killed (panic-reboot).

    If the recorded session ended and was never collected, that ended run is an
    incident we owe a bundle. panic_evidence tells crash from hang: a real panic
    leaves a *.kernel.core.log/*.panic; a wedge that took the box down without
    one is treated as a hang. Idempotent -- a collected run has uncollected=None.
    """
    sid = s.get("session_id")
    if not sid:
        return
    info = inspect(sid)
    if not info.get("found"):
        return
    if info.get("status") == "running" and info.get("pid_alive"):
        return                       # survived; supervisor will re-attach
    if not info.get("uncollected"):
        return                       # already collected, nothing owed
    kind = "crash" if info.get("panic_evidence") else "hang"
    log("boot reconcile: %s ended uncollected -> %s" % (sid, kind))
    record_incident(s, d, kind, info)
    collect_and_prune(s, d, kind)
    save_state(s)


def supervise(s, d, sid, budget):
    """Poll until an incident, budget exhaustion, or manager death.

    Returns one of: "crash", "hang", "budget". exec_total resets to 0 each run,
    so a decrease across a restart reads as progress (never a false hang).
    """
    poll = d["poll_seconds"]
    hang_after = d["hang_after_seconds"]
    last_et = s.get("last_exec_total")
    last_progress = time.time()
    while True:
        time.sleep(poll)
        latest_state = load_state(s["name"])
        if latest_state["status"] == "halted":
            log("campaign halted by user")
            session("stop", sid)
            return "halted"

        s.update(latest_state)

        info = inspect(sid)
        now = time.time()
        if not info.get("found") or not info.get("pid_alive"):
            return "crash" if info.get("panic_evidence") else "hang"
        s["active_seconds"] += poll
        et = info.get("exec_total")
        if et is not None and et != last_et:
            last_et = et
            s["last_exec_total"] = et
            last_progress = now
        elif et is not None and (now - last_progress) >= hang_after:
            log("hang: exec_total stuck at %s for %ds" % (et, round(now - last_progress)))
            return "hang"
        if s["active_seconds"] >= budget:
            return "budget"
        # breaker can trip mid-run (disk), so re-check each poll
        reason = breaker(s, d)
        if reason:
            s["status"] = "halted"
            s["halt_reason"] = reason
            save_state(s)
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
    s = load_state(name)
    for k, v in COORDINATOR_DEFAULTS.items():   # backfill for pre-coordinator state
        s.setdefault(k, v)
    if s["status"] in ("done", "halted"):
        log("campaign %r is %s (%s); nothing to do"
            % (name, s["status"], s.get("halt_reason") or ""))
        return
    log("campaign %r starting: %d config(s), %.1fh budget each, loop=%s, phase=%s"
        % (name, len(d["items"]), d["budget_hours"], d["loop"], s["phase"]))
    # In triaging phase there is no fuzzing session to reconcile; the box is
    # (or was) running triage, resumed by the phase branch below.
    if s["phase"] != "triaging":
        reconcile_boot(s, d)

    while True:
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
            advance_triage(s, d)
            if s["status"] == "halted":
                return
            continue
        if s["cursor"] >= len(d["items"]):
            if d["loop"]:
                log("loop: wrapping cursor to 0")
                s["cursor"] = 0
                s["active_seconds"] = 0.0
            else:
                s["status"] = "done"
                save_state(s)
                log("campaign %r done" % name)
                return
        item = d["items"][s["cursor"]]
        cfg, budget = item["config"], item["budget_seconds"]
        remaining = budget - s["active_seconds"]
        log("config %d/%d: %s (%.0f min left of %.1fh budget)"
            % (s["cursor"] + 1, len(d["items"]), config_id(cfg),
               remaining / 60, budget / 3600))
        try:
            ensure_running(s, cfg)
        except RuntimeError as e:
            s["status"] = "halted"
            s["halt_reason"] = str(e)
            save_state(s)
            log("HALT: %s" % e)
            return

        outcome = supervise(s, d, s["session_id"], budget)

        if outcome == "halted":
            log("HALT: %s" % s.get("halt_reason"))
            return
        if outcome == "budget":
            log("budget spent on %s; snapshot + advance" % config_id(cfg))
            session("collect", s["session_id"], "snapshot")
            session("stop", s["session_id"])
            s["cursor"] += 1
            s["active_seconds"] = 0.0
            s["session_id"] = None
            s["last_exec_total"] = None
            save_state(s)
            continue
        # crash or hang: stop if still alive, record, collect.
        info = inspect(s["session_id"])
        if info.get("pid_alive"):
            session("stop", s["session_id"])
            info = inspect(s["session_id"])
        record_incident(s, d, outcome, info)
        collect_and_prune(s, d, outcome)
        # Coordinator: a crash with a not-yet-benched signature is a new bug ->
        # triage it before resuming. A known (already benched) signature, or a
        # hang, just restarts the same config as before.
        if outcome == "crash":
            sig = latest_panic_signature(s)
            if sig and sig in s["suppressed_sigs"]:
                log("crash signature %s already benched; resuming fuzzing" % sig)
            elif sig and begin_triage(s, d, sig):
                save_state(s)
                continue                 # loop re-enters the triaging phase
        save_state(s)
        # policy: restart same config -- loop re-enters ensure_running (resume)


# --- authoring + control -----------------------------------------------------
def cmd_new(name, configs, budget_hours, loop, poll_seconds, hang_after_seconds,
            max_crashes, min_free_gb, keep_cores, force):
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
    write_json(path, d)
    log("wrote %s (%d config(s), %.1fh each, loop=%s)"
        % (path, len(rel), budget_hours, loop))
    print("  run it:      sudo ./scripts/fuzz-campaign.py run %s" % name)
    print("  or install:  sudo ./scripts/fuzz-campaign.py install %s" % name)


def cmd_status(name):
    d = load_def(name)
    s = load_state(name)
    print("campaign %s : %s" % (name, s["status"]))
    if s.get("halt_reason"):
        print("  halt reason : %s" % s["halt_reason"])
    print("  configs     : %d (loop=%s)" % (len(d["items"]), d["loop"]))
    print("  cursor      : %d/%d" % (min(s["cursor"] + 1, len(d["items"])), len(d["items"])))
    if s.get("current_config"):
        item = d["items"][min(s["cursor"], len(d["items"]) - 1)]
        print("  current     : %s" % config_id(s["current_config"]))
        print("  budget      : %.2f / %.2f h used"
              % (s["active_seconds"] / 3600, item["budget_seconds"] / 3600))
    print("  incidents   : %d crash / %d hang" % (s["crashes"], s["hangs"]))
    print("  phase       : %s" % s.get("phase", "fuzzing"))
    if s.get("phase") == "triaging":
        print("  triaging    : job %s, bug %s (advance %d/%d)"
              % (s.get("triage_job"), s.get("triage_bug_sig"),
                 s.get("triage_boots", 0), d["triage_max_boots"]))
    if s.get("suppressed_sigs"):
        print("  benched sigs: %d (%s)"
              % (len(s["suppressed_sigs"]), ", ".join(s["suppressed_sigs"][-3:])))
    print("  disk free   : %.1f GB" % free_gb())
    print("  updated     : %s" % s.get("updated_at"))
    for inc in s["incidents"][-5:]:
        print("    - %s  %-6s %s  (ran %ss, panic=%s)"
              % (inc["at"], inc["kind"], config_id(inc["config"]),
                 inc.get("ran_seconds"), inc.get("panic_evidence")))


def cmd_list():
    CAMPAIGN_DIR.mkdir(parents=True, exist_ok=True)
    defs = sorted(CAMPAIGN_DIR.glob("*.json"))
    if not defs:
        print("no campaigns in %s" % CAMPAIGN_DIR)
        return
    print("%-24s %-9s %-8s %s" % ("CAMPAIGN", "STATUS", "CURSOR", "INCIDENTS"))
    for dp in defs:
        name = dp.stem
        d = load_def(name)
        s = load_state(name)
        print("%-24s %-9s %-8s %d/%d"
              % (name, s["status"],
                 "%d/%d" % (min(s["cursor"] + 1, len(d["items"])), len(d["items"])),
                 s["crashes"], s["hangs"]))


def _set_status(name, status):
    s = load_state(name)
    s["status"] = status
    if status == "running":
        s["halt_reason"] = None
        s["consec_fast_crashes"] = 0
    save_state(s)
    log("campaign %r -> %s" % (name, status))


def cmd_halt(name):
    s = load_state(name)
    if s.get("session_id"):
        session("stop", s["session_id"])
    _set_status(name, "halted")


def cmd_resume(name):
    _set_status(name, "running")
    print("marked running; (re)start the driver: sudo ./scripts/fuzz-campaign.py run %s" % name)


# --- launchd -----------------------------------------------------------------
LAUNCHD_DIR = Path.home() / "/Library" / "LaunchAgents"


def plist_label(name):
    return "com.fuzz-campaign.%s" % name


def plist_path(name):
    return LAUNCHD_DIR / ("%s.plist" % plist_label(name))


def _plist_xml(name):
    logf = STATE_DIR / ("%s.launchd.log" % name)
    # Prefer Apple's stable system python3 for a long-lived daemon; env python3
    # (e.g. Xcode's) can move or vanish across an Xcode update.
    py = "/usr/bin/python3" if Path("/usr/bin/python3").exists() else sys.executable
    args = [py, str(SESSION.parent / "fuzz-campaign.py"), "run", name]
    arg_xml = "\n".join("    <string>%s</string>" % a for a in args)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0">\n<dict>\n'
        '  <key>Label</key><string>%s</string>\n'
        '  <key>ProgramArguments</key>\n  <array>\n%s\n  </array>\n'
        '  <key>WorkingDirectory</key><string>%s</string>\n'
        '  <key>RunAtLoad</key><true/>\n'
        '  <key>KeepAlive</key>\n  <dict>\n'
        '    <key>SuccessfulExit</key><false/>\n  </dict>\n'
        '  <key>StandardOutPath</key><string>%s</string>\n'
        '  <key>StandardErrorPath</key><string>%s</string>\n'
        '</dict>\n</plist>\n'
        % (plist_label(name), arg_xml, REPO_ROOT, logf, logf)
    )


def cmd_install(name):
    load_def(name)   # validate it exists
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    if os.geteuid() != 0:
        die("install writes to %s and loads a system daemon; run with sudo" % LAUNCHD_DIR)
    path = plist_path(name)
    path.write_text(_plist_xml(name))
    os.chmod(path, 0o644)
    log("wrote %s" % path)
    subprocess.run(["launchctl", "bootout", "system", str(path)],
                   stderr=subprocess.DEVNULL)
    rc = subprocess.run(["launchctl", "bootstrap", "system", str(path)]).returncode
    if rc != 0:
        die("launchctl bootstrap failed (rc=%d)" % rc)
    log("loaded %s -- RunAtLoad + KeepAlive; it survives reboots" % plist_label(name))
    print("  logs: %s" % (STATE_DIR / ("%s.launchd.log" % name)))


def cmd_uninstall(name):
    if os.geteuid() != 0:
        die("uninstall unloads a system daemon; run with sudo")
    path = plist_path(name)
    subprocess.run(["launchctl", "bootout", "system", str(path)],
                   stderr=subprocess.DEVNULL)
    if path.exists():
        path.unlink()
        log("removed %s" % path)
    else:
        log("no plist at %s" % path)


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
    """
    culprit = Path(culprit)
    if not culprit.exists():
        raise RuntimeError("culprit not found: %s" % culprit)
    out = Path(out) if out else culprit.parent / "syscalls.json"
    cmd = ringrepro_cmd() + ["-emit-json", "-json-out", str(out), str(culprit)]
    log("$ %s" % " ".join(cmd))
    rc = subprocess.run(cmd, cwd=str(REPO_ROOT)).returncode
    if rc != 0:
        raise RuntimeError("syz-ring-repro -emit-json exited %d on %s" % (rc, culprit))
    doc = read_json(out)
    if not doc or "syscalls" not in doc:
        raise RuntimeError("no readable syscall list at %s" % out)
    return doc["syscalls"]


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

    for _n, _h in (("run", "supervision loop (launchd entry point)"),
                   ("status", "show campaign runtime state"),
                   ("halt", "mark the campaign halted"),
                   ("resume", "clear halt and mark running"),
                   ("install", "generate + load the launchd daemon (sudo)"),
                   ("uninstall", "unload + remove the launchd daemon (sudo)")):
        s2 = sub.add_parser(_n, help=_h)
        s2.add_argument("name")
    sub.add_parser("list", help="table of all campaigns")

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
                args.min_free_gb, args.keep_cores, args.force)
    elif args.cmd == "run":
        cmd_run(args.name)
    elif args.cmd == "status":
        cmd_status(args.name)
    elif args.cmd == "list":
        cmd_list()
    elif args.cmd == "halt":
        cmd_halt(args.name)
    elif args.cmd == "resume":
        cmd_resume(args.name)
    elif args.cmd == "install":
        cmd_install(args.name)
    elif args.cmd == "uninstall":
        cmd_uninstall(args.name)
    elif args.cmd == "exclude":
        sys.exit(cmd_exclude(args.name, args.culprit, args.config, args.dry_run))
    elif args.cmd == "include":
        sys.exit(cmd_include(args.name, args.syscalls, args.config, args.all, args.dry_run))


if __name__ == "__main__":
    main()
