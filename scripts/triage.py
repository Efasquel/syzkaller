#!/usr/bin/env python3
"""Autonomous crash-minimization driver over syz-ring-repro + crash_fingerprint.

Takes a ring buffer of crashing programs and reduces it to a minimal, verified
reproducer, capturing and deduplicating every panic along the way. It is a
resumable state machine because the work reboots the box: each minimization
subset that reproduces panics the kernel, which kills this driver. So the driver
is written to advance as far as one boot allows and resume on the next launch,
with a launchd agent (install) relaunching it after every reboot.

Stages:
  MERGE          syz-ring-repro -merge -static   (offline: no device, no reboot)
  MINIMIZE_CONN  syz-ring-repro -minimize-conn    (device; reboots on each crash)
  MINIMIZE_CALLS syz-ring-repro -minimize-calls   (device; reboots on each crash)
  DONE           minimal culprit.syz verified

Each launch: (1) reconcile — scan the panic dirs for reports that appeared since
last time, fingerprint + dedup them into signatures.json, archive the report;
(2) run the current stage to completion this boot; (3) advance when its checkpoint
shows a verified culprit. syz-ring-repro owns the per-subset checkpoint
(conn_state/call_state.json), so a reboot mid-stage loses nothing; this driver
owns the cross-stage state and the crash ledger.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import crash_fingerprint as cf  # noqa: E402
import timefmt  # noqa: E402
from tablefmt import tabulate  # noqa: E402

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
TRIAGE_ROOT = REPO_ROOT / "triage"
STATE_DIR = TRIAGE_ROOT / ".state"
LAUNCHD_DIR = Path.home() / "Library" / "LaunchAgents"

# Panic reports land here after a bare-metal crash+reboot. Mirrors fuzz-session.
PANIC_DIRS = [
    Path(os.environ.get("SYZ_PANIC_DIR", "/Library/Logs/DiagnosticReports")),
    Path(os.environ.get("SYZ_KERNEL_PANIC_DIR", "/private/var/tmp/kernel_panics")),
]
PANIC_GLOBS = ("*.panic", "*.ips", "*.kernel.core.log")

# Ordered stages. Each names the artifact it consumes and the checkpoint it
# writes; MERGE is offline, the two MINIMIZE stages drive the device.
STAGES = ("MERGE", "MINIMIZE_CONN", "MINIMIZE_CALLS", "DONE")

# STUCK is terminal but is NOT in STAGES: it is not a step on the way to DONE,
# it is where a job stops when minimization has proved it cannot do better. A
# stage that can no longer make progress must SAY so -- returning "not finished,
# relaunch me" forever is what burned six triage advances on a real campaign and
# would have consumed all forty before halting.
STUCK = "STUCK"
TERMINAL = ("DONE", STUCK)


# --- small utilities ---------------------------------------------------------
def now_iso():
    return timefmt.now_iso()


def log(msg):
    sys.stdout.write("%s  %s\n" % (timefmt.stamp(), msg))
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
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


# --- job definition + state --------------------------------------------------
# A job's state lives in one JSON file under .state/<name>.json. It is both the
# definition (paths, device flags) and the live state (stage, watermark,
# ledger), so a single durable write advances everything atomically.
def state_path(name):
    return STATE_DIR / ("%s.json" % name)


def load_job(name):
    st = read_json(state_path(name))
    if st is None:
        die("no such triage job: %s (see: triage.py list)" % name)
    return st


def save_job(st):
    st["updated_at"] = now_iso()
    write_json(state_path(st["name"]), st)


def job_dir(st):
    return Path(st["dir"])


def exec_scratch(st):
    """A writable cwd for the executor that syz-ring-repro spawns.

    The executor creates its shmem file and per-program tmpdir RELATIVE TO ITS
    CWD (`syz.XXXXXX`, `./syzkaller.XXXXXX` in executor/common.h). It inherits
    our cwd, which under launchd is the job's WorkingDirectory -- the shared tree
    root, which the fuzzing user can read but not write. The executor then dies at
    startup with "SYZFAIL: shmem open failed ... errno 13", every probe reads as
    an executor error, and minimization concludes nothing reproduces having never
    executed a single program. Give it the job dir, which the running user owns.
    """
    d = job_dir(st) / "exec"
    d.mkdir(parents=True, exist_ok=True)
    return d


def ringrepro_cmd(st, *args):
    """Base syz-ring-repro argv with the job's device flags, plus args."""
    cmd = [st["ringrepro"], "-executor", st["executor"]]
    for k, v in (st.get("flags") or {}).items():
        cmd.append("-%s" % k)
        if v is not True:            # bool flags are bare
            cmd.append(str(v))
    return cmd + list(args)


# --- panic reconcile (capture + fingerprint + dedup) -------------------------
def report_mtime(p):
    try:
        return p.stat().st_mtime
    except OSError:
        return 0


def scan_reports(since_epoch):
    """Panic reports across PANIC_DIRS with mtime strictly after since_epoch,
    oldest first. Dotfiles (.contents.panic etc.) are skipped."""
    found = {}
    for d in PANIC_DIRS:
        if not d.is_dir():
            continue
        for g in PANIC_GLOBS:
            for p in d.glob(g):
                if p.name.startswith("."):
                    continue
                t = report_mtime(p)
                if t > since_epoch:
                    found[p] = t
    return sorted(found, key=found.get)


def reconcile_panics(st):
    """Fingerprint and record every panic that appeared since the last launch.

    Returns the list of newly-recorded incidents. The first panic seen fixes the
    job's target signature (the bug being minimized); a later panic with a
    DIFFERENT signature is flagged — it means minimization tripped a second bug,
    which the operator should know about before trusting the reproducer.
    """
    watermark = st.get("panic_watermark", 0)
    reports = scan_reports(watermark)
    if not reports:
        return []

    sig_store = cf.load_store(job_dir(st) / "signatures.json")
    reports_dir = job_dir(st) / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    new_incidents = []

    for r in reports:
        try:
            fp = cf.fingerprint(str(r))
        except Exception as e:  # noqa: BLE001 - a bad report must not stall triage
            log("could not fingerprint %s: %s" % (r.name, e))
            continue
        status = cf.classify(fp, sig_store, report_name=r.name)
        # Archive the report next to the ledger so the incident is reproducible.
        try:
            shutil.copy2(r, reports_dir / r.name)
        except OSError as e:
            log("could not archive %s: %s" % (r.name, e))

        incident = {"at": now_iso(), "report": r.name,
                    "signature": fp["signature"], "title": fp["title"],
                    "kext": fp["crashing_kext"], "status": status}
        st.setdefault("incidents", []).append(incident)
        new_incidents.append(incident)

        if st.get("target_signature") is None:
            st["target_signature"] = fp["signature"]
            log("target signature set: %s  %s  %s"
                % (fp["signature"], fp["crashing_kext"], fp["title"]))
        elif fp["signature"] != st["target_signature"]:
            log("WARNING: new signature %s (%s) differs from target %s -- a "
                "second bug surfaced during minimization"
                % (fp["signature"], fp["title"], st["target_signature"]))
        else:
            log("panic %s matches target signature %s (%s)"
                % (r.name, fp["signature"], status))

        st["panic_watermark"] = max(st.get("panic_watermark", 0), report_mtime(r))

    cf.save_store(job_dir(st) / "signatures.json", sig_store)
    save_job(st)
    return new_incidents


# --- stage runners -----------------------------------------------------------
def stage_verified(state_json):
    """True when a syz-ring-repro checkpoint records a verified culprit."""
    s = read_json(state_json)
    return bool(s and s.get("verified_crash"))


def stage_exhausted(state_json):
    """True when the checkpoint says the search is finished and its answer has
    already failed re-check -- relaunching cannot change the outcome."""
    s = read_json(state_json)
    return bool(s and s.get("exhausted"))


def stage_no_repro(state_json):
    """True when NOT ONE probe in the whole search reproduced the crash.

    This separates two outcomes that both end in STUCK and used to be reported
    identically:

      hits > 0, verification failed -- a real result about the bug: subsets DO
        crash, but only on state an earlier probe left behind.
      hits == 0 -- nothing was ever reproduced, which for a bug that demonstrably
        panicked the box during fuzzing means the minimization environment cannot
        reach the driver at all. The measured instance: syz-ring-repro ran without
        the executor_name the config sets, IOBluetoothHCIControllerUserClient
        refused every IOServiceOpen with kIOReturnUnsupported, and four jobs
        burned 25,461 probes concluding "the bug needs accumulated state" when the
        truth was "we never opened a connection".

    Free to compute: the memo is already on disk, so this costs no device run.
    """
    s = read_json(state_json)
    if not s:
        return False
    return not any((s.get("memo") or {}).values())


def run_merge(st):
    """Offline: concatenate + statically reduce the ring buffer into merged.syz.
    No device, so this never reboots; it either succeeds or fails outright."""
    merged = job_dir(st) / "merged.syz"
    cmd = ringrepro_cmd(st, "-merge", str(merged), "-static",
                        "-from", str(st.get("from", -1)), "-to", str(st.get("to", 0)),
                        st["ring_buffer"])
    log("MERGE: %s" % " ".join(cmd))
    rc = subprocess.run(cmd, cwd=str(exec_scratch(st))).returncode
    if rc != 0 or not merged.exists():
        die("merge failed (rc=%d); see output above" % rc)
    log("MERGE done -> %s" % merged)
    st["merged"] = str(merged)
    st["stage"] = "MINIMIZE_CONN"
    save_job(st)


def gate_args(st):
    """syz-ring-repro crash-gate flags, when a target signature is known.

    Gating requires the target signature, set either at job creation (--target-sig
    from the coordinator) or by the first reconciled panic. Until then minimize
    runs ungated (any reboot counts) — correct for the very first crash, which is
    what establishes the target. The gate makes syz-ring-repro confirm each later
    reboot against that signature (via crash_fingerprint.py match-since) so a
    second bug firing during a probe cannot misdirect the search.
    """
    sig = st.get("target_signature")
    if not sig:
        return []
    dirs = []
    for d in PANIC_DIRS:
        dirs += ["--dir", str(d)]
    confirm = "%s %s match-since %s" % (
        sys.executable, SCRIPT_DIR / "crash_fingerprint.py", " ".join(dirs))
    return ["-target_sig", sig, "-confirm_cmd", confirm]


def _stabilize(culprit, dst):
    """Durably copy syz-ring-repro's ephemeral culprit.syz to a stage-specific file
    and fsync it. Two reasons: the NEXT stage must read a different file than the
    one it writes its own -culprit into (both are `culprit.syz` otherwise, so a
    stage clobbers its own input); and the tool does not fsync `culprit.syz`, so an
    unclean panic-reboot can lose it -- a stage-named, fsync'd copy survives and
    lets the next stage (or an -emit-culprit recovery) proceed. Returns dst's path.
    """
    dst = Path(dst)
    shutil.copyfile(culprit, dst)
    fd = os.open(str(dst), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return str(dst)


def run_minimize(st, stage, flag, prog_key, out_key, state_name):
    """Drive one on-device minimization stage to completion for this boot.

    syz-ring-repro resumes from its own checkpoint, so re-running after a reboot
    continues where it left off. When it exits 0 AND its checkpoint shows a
    verified culprit, the stage is done and we advance. A reboot mid-run kills
    this process; the launchd agent relaunches us and we re-enter here.
    """
    prog = Path(st[prog_key])
    state_json = job_dir(st) / state_name
    culprit = job_dir(st) / "culprit.syz"
    cmd = ringrepro_cmd(st, flag, "-state", str(state_json),
                        "-culprit", str(culprit), *gate_args(st), str(prog))
    log("%s: %s" % (stage, " ".join(cmd)))
    rc = subprocess.run(cmd, cwd=str(exec_scratch(st))).returncode
    # Reconcile any panic this run produced (it may have rebooted us on a prior
    # invocation; on this one it returned, but earlier subsets still left logs).
    reconcile_panics(st)
    if rc != 0:
        log("%s: syz-ring-repro exited %d (not complete this boot); will resume"
            % (stage, rc))
        return
    if not stage_verified(state_json):
        if stage_exhausted(state_json):
            # The search is spent: its best candidate was re-checked in isolation
            # and did not crash. That is a RESULT about the bug -- it needs state
            # an earlier program leaves behind -- not a reason to try again.
            st[out_key] = _stabilize(culprit, job_dir(st) / ("%s.syz" % out_key))
            st["stage"] = STUCK
            st["stuck_at"] = stage
            unit = "connection" if "CONN" in stage else "call"
            if stage_no_repro(state_json):
                st["stuck_kind"] = "no-repro"
                st["stuck_reason"] = (
                    "NOT ONE probe reproduced the crash -- not a single %s subset, "
                    "ever. For a bug that panicked the box during fuzzing that is "
                    "evidence about the ENVIRONMENT, not about the bug: the "
                    "minimization run cannot reach the driver. Check that this job "
                    "carries the same executor_name, kext_id, kcov_device and "
                    "sandbox the config fuzzed under -- a missing executor_name "
                    "makes every IOServiceOpen return kIOReturnUnsupported and "
                    "every later call inert. The saved culprit is meaningless "
                    "here: it is the whole program, by elimination." % unit)
            else:
                st["stuck_kind"] = "unverified"
                st["stuck_reason"] = (
                    "no %s subset reproduces in isolation; the bug needs accumulated "
                    "state. The saved culprit is the smallest sequence seen to crash "
                    "DURING the search, so treat it as a lead, not a proof." % unit)
            save_job(st)
            log("%s: STUCK -- %s" % (stage, st["stuck_reason"]))
            log("%s: unverified culprit preserved at %s" % (stage, st[out_key]))
            return
        # Exited cleanly but nothing verified: no crashing subset yet. For a real
        # crasher this means it still needs a boot that reproduces; relaunch.
        log("%s: run finished without a verified culprit yet; will resume" % stage)
        return
    # Preserve this stage's result under a durable, stage-specific name so the next
    # stage reads it (not its own live culprit.syz) and it survives a panic-reboot.
    st[out_key] = _stabilize(culprit, job_dir(st) / ("%s.syz" % out_key))
    st["stage"] = STAGES[STAGES.index(stage) + 1]
    save_job(st)
    log("%s done -> %s (verified)" % (stage, st[out_key]))


# --- the orchestrator --------------------------------------------------------
def advance(st):
    """Do one boot's worth of work: reconcile panics, run the current stage."""
    reconcile_panics(st)
    stage = st["stage"]
    if stage == "MERGE":
        run_merge(st)
    elif stage == "MINIMIZE_CONN":
        run_minimize(st, "MINIMIZE_CONN", "-minimize-conn",
                     "merged", "conn_culprit", "conn_state.json")
    elif stage == "MINIMIZE_CALLS":
        run_minimize(st, "MINIMIZE_CALLS", "-minimize-calls",
                     "conn_culprit", "final_culprit", "call_state.json")
    elif stage in TERMINAL:
        return
    else:
        die("unknown stage: %s" % stage)


def cmd_run(name):
    """One launch of the driver: advance until DONE or a reboot kills us."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    st = load_job(name)
    if st["stage"] in TERMINAL:
        log("%s already %s: %s"
            % (name, st["stage"], st.get("final_culprit") or st.get("conn_culprit") or "?"))
        if st["stage"] == STUCK:
            log("  %s" % st.get("stuck_reason", ""))
        return
    log("triage %s: stage=%s dir=%s" % (name, st["stage"], st["dir"]))
    # Advance repeatedly within this boot: offline stages (MERGE) fall straight
    # through, and a device stage that finishes without rebooting lets the next
    # begin immediately. A reboot simply kills us mid-loop; relaunch resumes.
    last = None
    while st["stage"] not in TERMINAL and st["stage"] != last:
        last = st["stage"]
        advance(st)
        st = load_job(name)          # advance persisted; reload the fresh state
    if st["stage"] == STUCK:
        log("triage %s STUCK at %s -> %s"
            % (name, st.get("stuck_at"), st.get("conn_culprit") or st.get("final_culprit")))
        log("  %s" % st.get("stuck_reason", ""))
        _print_summary(st)
        return
    if st["stage"] == "DONE":
        log("triage %s COMPLETE -> %s" % (name, st.get("final_culprit")))
        _print_summary(st)


def _print_summary(st):
    sigs = cf.load_store(job_dir(st) / "signatures.json").get("signatures", {})
    print("\n== triage %s ==" % st["name"])
    print("final reproducer : %s" % st.get("final_culprit", "(none)"))
    print("target signature : %s" % st.get("target_signature", "(none)"))
    print("distinct crashes : %d" % len(sigs))
    for sig, rec in sigs.items():
        mark = " <- target" if sig == st.get("target_signature") else ""
        print("  %s  x%-3d %s  %s%s"
              % (sig, rec.get("count", 0), rec.get("crashing_kext") or "?",
                 rec.get("title") or "?", mark))


# --- job authoring + inspection ----------------------------------------------
def cmd_new(name, ring_buffer, executor, ringrepro, kcov_device, kext_id,
            sandbox, max_k, os_name, arch, from_off, to_off, force,
            target_sig=None, executor_name=None):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    if state_path(name).exists() and not force:
        die("triage job %s already exists (use --force to overwrite)" % name)
    ring = Path(ring_buffer).expanduser().resolve()
    if not ring.exists():
        die("ring buffer not found: %s" % ring)
    jdir = (TRIAGE_ROOT / name).resolve()
    jdir.mkdir(parents=True, exist_ok=True)

    flags = {}
    if os_name:
        flags["os"] = os_name
    if arch:
        flags["arch"] = arch
    if kcov_device:
        flags["kcov_device"] = kcov_device
    if kext_id is not None:
        flags["kext_id"] = kext_id
    if sandbox:
        flags["sandbox"] = sandbox
    # The process name the driver expects. Without it a name-gated user client
    # refuses every open and the whole search is a no-op -- see stage_no_repro.
    if executor_name:
        flags["executor_name"] = executor_name
    if max_k is not None:
        flags["max_k"] = max_k

    st = {
        "name": name,
        "dir": str(jdir),
        "ring_buffer": str(ring),
        "ringrepro": str(Path(ringrepro).expanduser().resolve()),
        "executor": str(Path(executor).expanduser().resolve()),
        "flags": flags,
        "from": from_off,
        "to": to_off,
        "stage": "MERGE",
        "panic_watermark": time.time(),   # ignore panics from before the job
        # A caller (the coordinator) can pin the target signature up front so the
        # crash gate is active from the first subset; otherwise the first
        # reconciled panic sets it.
        "target_signature": target_sig,
        "incidents": [],
        "created_at": now_iso(),
    }
    save_job(st)
    log("created triage job %s (stage MERGE) at %s" % (name, jdir))
    print("  run it:     scripts/triage.py run %s" % name)
    print("  autonomous: sudo scripts/triage.py install %s" % name)


def cmd_status(name):
    st = load_job(name)
    print("job     : %s" % st["name"])
    print("stage   : %s" % st["stage"])
    print("dir     : %s" % st["dir"])
    print("ring    : %s" % st["ring_buffer"])
    for k in ("merged", "conn_culprit", "final_culprit"):
        if st.get(k):
            print("%-8s: %s" % (k, st[k]))
    _print_summary(st)


def cmd_list():
    if not STATE_DIR.is_dir():
        print("no triage jobs")
        return
    rows = []
    for sf in sorted(STATE_DIR.glob("*.json")):
        st = read_json(sf)
        if not st:
            continue
        # A finished job's worth is its reproducer, and whether it is proven.
        if st["stage"] == "DONE":
            repro = "verified"
        elif st["stage"] == STUCK:
            repro = "UNVERIFIED"
        else:
            repro = "-"
        rows.append((st["name"], st["stage"], repro,
                     st.get("target_signature") or "-",
                     len(st.get("incidents", []))))
    if not rows:
        print("no triage jobs")
        return
    tabulate(rows, ("NAME", "STAGE", "REPRO", "TARGET SIG", "PANICS"))


# --- launchd (survive reboots) ----------------------------------------------
def plist_label(name):
    return "com.syz-triage.%s" % name


def plist_path(name):
    return LAUNCHD_DIR / ("%s.plist" % plist_label(name))


def _plist_xml(name):
    logf = STATE_DIR / ("%s.launchd.log" % name)
    py = "/usr/bin/python3" if Path("/usr/bin/python3").exists() else sys.executable
    args = [py, str(SCRIPT_DIR / "triage.py"), "run", name]
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
        '  <key>StandardOutPath</key><string>%s</string>\n'
        '  <key>StandardErrorPath</key><string>%s</string>\n'
        '</dict>\n</plist>\n'
        % (plist_label(name), arg_xml, REPO_ROOT, logf, logf)
    )


def cmd_install(name):
    load_job(name)   # validate it exists
    LAUNCHD_DIR.mkdir(parents=True, exist_ok=True)
    path = plist_path(name)
    path.write_text(_plist_xml(name))
    os.chmod(path, 0o644)
    log("wrote %s" % path)
    uid = os.getuid()
    subprocess.run(["launchctl", "bootout", "gui/%d" % uid, str(path)],
                   stderr=subprocess.DEVNULL)
    rc = subprocess.run(["launchctl", "bootstrap", "gui/%d" % uid, str(path)]).returncode
    if rc != 0:
        die("launchctl bootstrap failed (rc=%d)" % rc)
    log("loaded %s -- RunAtLoad; relaunches after each reboot" % plist_label(name))
    print("  logs: %s" % (STATE_DIR / ("%s.launchd.log" % name)))
    print("  note: RunAtLoad fires once per boot; that is exactly one relaunch "
          "per crash-reboot, which is what triage needs.")


def cmd_uninstall(name):
    path = plist_path(name)
    uid = os.getuid()
    subprocess.run(["launchctl", "bootout", "gui/%d" % uid, str(path)],
                   stderr=subprocess.DEVNULL)
    if path.exists():
        path.unlink()
        log("removed %s" % path)
    else:
        log("no plist at %s" % path)


# --- cli ---------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(
        description="autonomous crash-minimization driver over syz-ring-repro",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd")

    n = sub.add_parser("new", help="author a triage job")
    n.add_argument("name")
    n.add_argument("--ring", required=True, help="ring buffer dir (crashing programs)")
    n.add_argument("--executor", default=str(REPO_ROOT / "bin/darwin_arm64/syz-executor"))
    n.add_argument("--executor-name", default=None,
                   help="process name to run the executor under, matching the manager "
                        "config's executor_name (e.g. bluetoothd). Required whenever the "
                        "driver gates its user client on p_comm")
    n.add_argument("--ringrepro", default=str(REPO_ROOT / "bin/darwin_arm64/syz-ring-repro"))
    n.add_argument("--kcov-device", default=None)
    n.add_argument("--kext-id", type=int, default=None)
    n.add_argument("--sandbox", default=None)
    n.add_argument("--max-k", type=int, default=None)
    n.add_argument("--os", dest="os_name", default=None)
    n.add_argument("--arch", default=None)
    n.add_argument("--from", dest="from_off", type=int, default=-1,
                   help="ring range start (offset back from newest); -1 = oldest")
    n.add_argument("--to", dest="to_off", type=int, default=0,
                   help="ring range end (offset back from newest); 0 = newest")
    n.add_argument("--target-sig", dest="target_sig", default=None,
                   help="pin the crash signature to gate minimization on (else the first panic sets it)")
    n.add_argument("--force", action="store_true")

    for cmd, helptext in (("run", "advance the job as far as this boot allows"),
                          ("status", "show a job's stage + crash ledger"),
                          ("install", "load a launchd agent (relaunch after reboot)"),
                          ("uninstall", "unload the launchd agent")):
        s = sub.add_parser(cmd, help=helptext)
        s.add_argument("name")
    sub.add_parser("list", help="table of all triage jobs")

    args = p.parse_args()
    if args.cmd == "new":
        cmd_new(args.name, args.ring, args.executor, args.ringrepro,
                args.kcov_device, args.kext_id, args.sandbox, args.max_k,
                args.os_name, args.arch, args.from_off, args.to_off, args.force,
                args.target_sig, executor_name=args.executor_name)
    elif args.cmd == "run":
        cmd_run(args.name)
    elif args.cmd == "status":
        cmd_status(args.name)
    elif args.cmd == "list":
        cmd_list()
    elif args.cmd == "install":
        cmd_install(args.name)
    elif args.cmd == "uninstall":
        cmd_uninstall(args.name)
    else:
        p.print_help()
        sys.exit(2)


if __name__ == "__main__":
    main()
