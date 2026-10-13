#!/usr/bin/env python3
"""Replay corpus programs under a before/after clock measurement.

The live campaign cannot say which program moved the clock: several programs are
in flight, DVFS reacts over tens of milliseconds, and the fuzzer's own load
raises the clock anyway. So attribution happens here, offline, on a QUIET box:
every program is run alone by `binfreq --fuzzer-loop`, which measures an active
channel before and after the call and keeps a passive witness sampling
throughout. A control program (getpid) is interleaved with the candidates and
run the same way, so process spawn and executor start-up -- which do raise the
clock -- land in the noise floor rather than in the effect.

  replay dir = progs/<hash>         programs unpacked from corpus.db
               control.prog         the control program
               <phase>.schedule.json  fixed, seeded trial order (resumable)
               <phase>.jsonl        one binfreq record per trial, fsynced
               suspects.jsonl       trials that never returned (kernel panic)
               failures.jsonl       trials binfreq could not estimate (skipped)
               freq-corpus/<hash>/  confirmed programs + their trials

Phases, in order:
  calibrate   controls only: the noise floor and its false-positive rate at k
  screen      every corpus program once, alternating with controls
  confirm     each screen hit `--reps` times (default 10), alternating

A trial is a hit when the PASSIVE witness moved by more than k scaled-MADs of the
controls' distribution. Requiring the witness to move is what rejects
`active_only` responses -- the active channel reacting to its own program's load.
A program is confirmed when at least m of its confirm reps hit in the same
direction.

Usage:
  scripts/freq-replay.py prepare <corpus.db> <dir> [--control FILE]
  scripts/freq-replay.py run     <dir> calibrate|screen|confirm [--channels p,p]
  scripts/freq-replay.py status  <dir>
  scripts/freq-replay.py report  <dir> [--k 4] [--m 7] [--write-corpus]
"""

import argparse
import json
import os
import random
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import timefmt  # noqa: E402
from lib.tablefmt import tabulate  # noqa: E402

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
BIN_DIR = REPO_ROOT / "bin" / "darwin_arm64"
SYZ_DB = Path(os.environ.get("SYZ_DB_BIN", REPO_ROOT / "bin" / "syz-db"))
EXECPROG = Path(os.environ.get("SYZ_EXECPROG_BIN", BIN_DIR / "syz-execprog"))
EXECUTOR = Path(os.environ.get("SYZ_EXECUTOR_BIN", BIN_DIR / "syz-executor"))
RUNNER = SCRIPT_DIR / "freq-runner.sh"
# Same resolution order as fuzz-session: override, the copy synced into this
# tree, then a sibling fthM2 checkout.
_tree_binfreq = REPO_ROOT / "bin" / "binfreq"
BINFREQ_BIN = Path(os.environ.get(
    "SYZ_BINFREQ_BIN",
    _tree_binfreq if _tree_binfreq.exists()
    else REPO_ROOT.parent / "fthM2" / "binfreq"))

PHASES = ("calibrate", "screen", "confirm")
CONTROL = "control"
CONTROL_PROG = "getpid()\n"
# MAD * 1.4826 estimates sigma for a normal distribution, so k reads as "sigmas".
MAD_SCALE = 1.4826
# One counter tick of quantization is ~0.17% of a reading; a floor narrower than
# this is an artefact of a few identical controls, not a real precision.
MIN_MAD_GHZ = 0.002
# Below this many controls, a phase borrows the calibrate floor instead.
MIN_CONTROLS = 20
# binfreq refuses (rather than wraps) once its passive buffer is full, so each
# binfreq process gets a bounded batch of trials and a buffer sized for it.
PASSIVE_SAMPLES_PER_TRIAL = 400
# binfreq ends its whole loop when one trial cannot be estimated ("too few
# uncontended gates"). That trial is recorded as failed and the run goes on; only
# this many consecutive batches with no progress at all stop it.
MAX_FAILED_BATCHES = 3
# Processes whose presence means the box is not quiet.
BUSY_PROCS = ("syz-manager", "syz-executor", "syz-execprog")


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


def read_jsonl(path):
    """Records of a results file. A torn last line (panic mid-write) is skipped."""
    out = []
    try:
        with open(path) as f:
            for line in f:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
    except OSError:
        pass
    return out


def measured(recs):
    """Trials whose program actually ran. A runner that failed (bad path, missing
    binary, executor refused) still gets a binfreq record -- a PRE and POST around
    nothing -- and judging those as measurements reads silence as "no effect"."""
    return [r for r in recs if r.get("call_status", 0) == 0]


def append_jsonl(path, rec):
    with open(path, "a") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())


# --- schedules -----------------------------------------------------------------
def interleave(names, seed):
    """Shuffle the candidates and put a control before each one.

    Alternating keeps the controls spread evenly through the run, so the floor
    they define tracks thermal and background drift over a long night instead of
    describing only the first few minutes."""
    names = list(names)
    random.Random(seed).shuffle(names)
    out = []
    for n in names:
        out.append(CONTROL)
        out.append(n)
    return out


def make_schedule(names):
    return [{"idx": i, "name": n} for i, n in enumerate(names)]


def prog_path(d, name):
    return Path(d) / ("control.prog" if name == CONTROL else "progs/%s" % name)


# --- analysis ------------------------------------------------------------------
def _median(v):
    v = sorted(v)
    n = len(v)
    if not n:
        return 0.0
    return v[n // 2] if n & 1 else 0.5 * (v[n // 2 - 1] + v[n // 2])


def delta(rec, chan):
    return float(rec.get(chan, {}).get("delta_ghz", 0.0))


def floor_of(controls):
    """Noise floor of each channel: median and scaled MAD of the control deltas."""
    fl = {}
    for chan in ("active", "passive"):
        ds = [delta(r, chan) for r in controls]
        med = _median(ds)
        mad = _median([abs(x - med) for x in ds])
        fl[chan] = {"median": med, "sigma": max(mad, MIN_MAD_GHZ) * MAD_SCALE,
                    "n": len(ds)}
    return fl


def zscore(rec, fl, chan):
    return (delta(rec, chan) - fl[chan]["median"]) / fl[chan]["sigma"]


def is_hit(rec, fl, k):
    return abs(zscore(rec, fl, "passive")) > k


def phase_floor(d, phase):
    """The floor a phase is judged against: its own interleaved controls when
    there are enough of them (they share the run's drift), else calibrate's."""
    recs = measured(read_jsonl(Path(d) / ("%s.jsonl" % phase)))
    ctl = [r for r in recs if r.get("name") == CONTROL]
    if len(ctl) < MIN_CONTROLS and phase != "calibrate":
        ctl = [r for r in measured(read_jsonl(Path(d) / "calibrate.jsonl"))
               if r.get("name") == CONTROL]
    if len(ctl) < MIN_CONTROLS:
        return None
    return floor_of(ctl)


def screen_hits(recs, fl, k):
    return sorted({r["name"] for r in recs
                   if r.get("name") != CONTROL and is_hit(r, fl, k)})


def confirm_verdicts(recs, fl, k, m):
    """Per program: reps, hits in the majority direction, verdict.

    Direction matters: a program whose reps hit +5 sigma and -5 sigma alternately
    is noise that happens to be loud, not a frequency effect."""
    by = {}
    for r in recs:
        if r.get("name") != CONTROL:
            by.setdefault(r["name"], []).append(r)
    out = []
    for name, rs in sorted(by.items()):
        zs = [zscore(r, fl, "passive") for r in rs]
        sign = 1 if _median(zs) >= 0 else -1
        hits = sum(1 for z in zs if abs(z) > k and (z > 0) == (sign > 0))
        out.append({
            "name": name, "reps": len(rs), "hits": hits,
            "confirmed": hits >= m,
            "median_z_passive": _median(zs),
            "median_z_active": _median([zscore(r, fl, "active") for r in rs]),
            "median_delta_passive_ghz": _median([delta(r, "passive") for r in rs]),
            "median_delta_active_ghz": _median([delta(r, "active") for r in rs]),
            "classes": sorted({r.get("response_class", "?") for r in rs}),
        })
    return out


# --- commands ------------------------------------------------------------------
def cmd_prepare(corpus, d, control=None):
    d = Path(d)
    if (d / "progs").exists():
        die("%s already prepared (progs/ exists)" % d)
    if not Path(corpus).is_file():
        die("no corpus at %s" % corpus)
    d.mkdir(parents=True, exist_ok=True)
    r = subprocess.run([str(SYZ_DB), "-os", "darwin", "-arch", "arm64",
                        "unpack", str(corpus), str(d / "progs")],
                       capture_output=True, text=True)
    if r.returncode != 0:
        die("syz-db unpack failed:\n%s" % (r.stderr or r.stdout))
    if control:
        shutil.copyfile(control, d / "control.prog")
    else:
        (d / "control.prog").write_text(CONTROL_PROG)
    n = len(list((d / "progs").iterdir()))
    write_json(d / "meta.json", {"corpus": str(Path(corpus).resolve()),
                                 "prepared_at": timefmt.now_iso(),
                                 "programs": n})
    log("prepared %d program(s) in %s" % (n, d / "progs"))


def busy_procs():
    found = []
    for p in BUSY_PROCS:
        if subprocess.run(["pgrep", "-x", p], capture_output=True).returncode == 0:
            found.append(p)
    return found


def build_schedule(d, phase, seed, calib_trials, reps, k):
    d = Path(d)
    if phase == "calibrate":
        names = [CONTROL] * calib_trials
    elif phase == "screen":
        names = interleave(sorted(p.name for p in (d / "progs").iterdir()), seed)
    else:
        fl = phase_floor(d, "screen")
        if fl is None:
            die("confirm needs a screen run with >= %d controls" % MIN_CONTROLS)
        hits = screen_hits(measured(read_jsonl(d / "screen.jsonl")), fl, k)
        if not hits:
            die("screen has no hits at k=%g; nothing to confirm" % k)
        log("confirm: %d screen hit(s) x %d reps" % (len(hits), reps))
        names = interleave([h for h in hits for _ in range(reps)], seed)
    return make_schedule(names)


def note_suspect(d, phase, sched_by_idx, done):
    """A started-marker naming a trial with no result means the box went down
    while that program ran. Record it once; it is skipped from then on."""
    mark = Path(d) / ("%s.mark" % phase)
    try:
        idx = int(mark.read_text().strip())
    except (OSError, ValueError):
        return None
    failed = {f["idx"] for f in read_jsonl(Path(d) / "failures.jsonl")
              if f.get("phase") == phase}
    if idx in done or idx in failed or idx not in sched_by_idx:
        return None
    sus = Path(d) / "suspects.jsonl"
    if any(s.get("phase") == phase and s.get("idx") == idx for s in read_jsonl(sus)):
        return idx
    rec = {"phase": phase, "idx": idx, "name": sched_by_idx[idx]["name"],
           "noted_at": timefmt.now_iso()}
    append_jsonl(sus, rec)
    log("SUSPECT: trial %d (%s) never returned -- likely a panic; skipping it"
        % (idx, rec["name"]))
    return idx


def run_batch(d, phase, trials, channels, active_sweeps, sandbox):
    # Absolute: the runner cd's into exec/ before it writes the log and marker,
    # so a relative replay dir would point them nowhere and every trial would fail.
    d = Path(d).resolve()
    scratch = d / "exec"
    scratch.mkdir(exist_ok=True)
    env = dict(os.environ,
               FREQ_MARK=str(d / ("%s.mark" % phase)), FREQ_SCRATCH=str(scratch),
               FREQ_EXECPROG=str(EXECPROG), FREQ_EXECUTOR=str(EXECUTOR),
               FREQ_LOG=str(d / "runner.log"), FREQ_SANDBOX=sandbox)
    cap = max(100000, PASSIVE_SAMPLES_PER_TRIAL * len(trials))
    cmd = [str(BINFREQ_BIN), "--fuzzer-loop", "-j", "--channels", channels,
           "--active-sweeps", str(active_sweeps), "--passive-capacity", str(cap),
           "--", "/bin/sh", str(RUNNER)]
    by_tok = {}
    lines = []
    for t in trials:
        tok = "%d:%s" % (t["idx"], prog_path(d, t["name"]).resolve())
        by_tok[tok] = t
        lines.append(tok + "\n")
    results = d / ("%s.jsonl" % phase)
    with open(d / "binfreq.log", "a") as errf, \
            subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=errf, env=env, text=True, bufsize=1) as proc:
        proc.stdin.write("".join(lines))
        proc.stdin.close()
        got = ok = 0
        for line in proc.stdout:
            if not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            t = by_tok.get(rec.get("input"))
            if t is None:
                continue
            rec.update(idx=t["idx"], name=t["name"], phase=phase)
            append_jsonl(results, rec)
            got += 1
            ok += rec.get("call_status", 0) == 0
        rc = proc.wait()
    return got, ok, rc


def last_line(path):
    try:
        lines = Path(path).read_text().strip().splitlines()
    except OSError:
        return ""
    return lines[-1] if lines else ""


def note_failure(d, phase, sched_by_idx, rc):
    """binfreq gave up on the in-flight trial and exited. Record that trial as
    failed -- not as a panic suspect: the box is still up -- so it is skipped."""
    d = Path(d)
    try:
        idx = int((d / ("%s.mark" % phase)).read_text().strip())
    except (OSError, ValueError):
        return None
    done = {r["idx"] for r in read_jsonl(d / ("%s.jsonl" % phase)) if "idx" in r}
    if idx in done or idx not in sched_by_idx:
        return None
    rec = {"phase": phase, "idx": idx, "name": sched_by_idx[idx]["name"], "rc": rc,
           "error": last_line(d / "binfreq.log"), "noted_at": timefmt.now_iso()}
    append_jsonl(d / "failures.jsonl", rec)
    log("FAILED: trial %d (%s): %s" % (idx, rec["name"], rec["error"]))
    return idx


def cmd_run(d, phase, channels, batch, seed, calib_trials, reps, k,
            active_sweeps, sandbox, force):
    d = Path(d).resolve()
    if not (d / "progs").is_dir():
        die("%s is not prepared (run: freq-replay.py prepare)" % d)
    for b in (BINFREQ_BIN, EXECPROG, EXECUTOR):
        if not os.access(b, os.X_OK):
            die("missing executable %s" % b)
    busy = busy_procs()
    if busy and not force:
        die("box is not quiet (%s running); stop the campaign or pass --force"
            % ", ".join(busy))
    sp = d / ("%s.schedule.json" % phase)
    sched = read_json(sp)
    if sched is None:
        sched = build_schedule(d, phase, seed, calib_trials, reps, k)
        write_json(sp, sched)
    by_idx = {t["idx"]: t for t in sched}

    def pending():
        done = {r["idx"] for r in read_jsonl(d / ("%s.jsonl" % phase)) if "idx" in r}
        skip = {s["idx"] for f in ("suspects.jsonl", "failures.jsonl")
                for s in read_jsonl(d / f) if s.get("phase") == phase}
        return done, skip, [t for t in sched
                            if t["idx"] not in done and t["idx"] not in skip]

    done, _, _ = pending()
    note_suspect(d, phase, by_idx, done)
    done, skip, todo = pending()
    log("%s: %d trial(s) scheduled, %d done, %d skipped, %d to run"
        % (phase, len(sched), len(done), len(skip), len(todo)))
    stalled = 0
    while todo:
        chunk = todo[:batch]
        got, ok, rc = run_batch(d, phase, chunk, channels, active_sweeps, sandbox)
        if got and not ok:
            die("the runner failed on all %d trial(s) of this batch -- no program "
                "ran, so nothing was measured; see %s and %s"
                % (got, d / "runner.log", d / "binfreq.log"))
        log("%s: batch from %d -> %d record(s)%s"
            % (phase, chunk[0]["idx"], got, "" if rc == 0 else ", binfreq rc=%d" % rc))
        if rc < 0:
            # Killed by a signal: not binfreq's own verdict on one trial. Stop and
            # leave the marker, so a resume treats the trial as a suspect.
            die("binfreq killed by signal %d; see %s" % (-rc, d / "binfreq.log"))
        if rc > 0 and note_failure(d, phase, by_idx, rc) is None:
            # It gave up in the PRE window, before the runner marked the trial:
            # the program never ran, so the trial is simply retried.
            log("binfreq gave up before the call (%s); retrying"
                % last_line(d / "binfreq.log"))
        stalled = stalled + 1 if (rc and not got) else 0
        if stalled >= MAX_FAILED_BATCHES:
            die("binfreq failed %d batches in a row with no results; see %s"
                % (stalled, d / "binfreq.log"))
        _, _, todo = pending()
    log("%s: complete" % phase)


def cmd_status(d):
    d = Path(d)
    rows = []
    sus = read_jsonl(d / "suspects.jsonl")
    fails = read_jsonl(d / "failures.jsonl")
    for ph in PHASES:
        sched = read_json(d / ("%s.schedule.json" % ph))
        if sched is None:
            continue
        n = len(read_jsonl(d / ("%s.jsonl" % ph)))
        rows.append([ph, len(sched), n,
                     sum(1 for s in sus if s.get("phase") == ph),
                     sum(1 for f in fails if f.get("phase") == ph)])
    if not rows:
        print("no phase started in %s" % d)
        return
    tabulate(rows, ["phase", "trials", "done", "suspect", "failed"])


def cmd_report(d, k, m, write_corpus, corpus_out):
    d = Path(d)
    cal = phase_floor(d, "calibrate")
    if cal:
        ctl = [r for r in measured(read_jsonl(d / "calibrate.jsonl")) if r.get("name") == CONTROL]
        fp = sum(1 for r in ctl if is_hit(r, cal, k))
        print("calibrate  n=%d  passive floor %.4f +/- %.4f GHz  active %.4f +/- %.4f"
              % (cal["passive"]["n"], cal["passive"]["median"], cal["passive"]["sigma"],
                 cal["active"]["median"], cal["active"]["sigma"]))
        print("           false positives at k=%g: %d/%d controls" % (k, fp, len(ctl)))
    fl = phase_floor(d, "screen") if (d / "screen.jsonl").exists() else None
    if fl:
        recs = measured(read_jsonl(d / "screen.jsonl"))
        hits = screen_hits(recs, fl, k)
        ncand = sum(1 for r in recs if r.get("name") != CONTROL)
        print("screen     %d program(s) measured, %d hit(s) at k=%g" % (ncand, len(hits), k))
    fl = phase_floor(d, "confirm") if (d / "confirm.jsonl").exists() else None
    if not fl:
        return
    verdicts = confirm_verdicts(measured(read_jsonl(d / "confirm.jsonl")), fl, k, m)
    rows = [[v["name"][:16], v["reps"], v["hits"], "yes" if v["confirmed"] else "",
             "%+.1f" % v["median_z_passive"], "%+.4f" % v["median_delta_passive_ghz"],
             "%+.4f" % v["median_delta_active_ghz"], ",".join(v["classes"])]
            for v in sorted(verdicts, key=lambda v: -abs(v["median_z_passive"]))]
    tabulate(rows, ["program", "reps", "hits", "ok", "z_pas", "d_pas GHz",
                    "d_act GHz", "classes"])
    if write_corpus:
        out = Path(corpus_out) if corpus_out else d / "freq-corpus"
        recs = measured(read_jsonl(d / "confirm.jsonl"))
        n = 0
        for v in verdicts:
            if not v["confirmed"]:
                continue
            pd = out / v["name"]
            pd.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(prog_path(d, v["name"]), pd / "prog")
            with open(pd / "trials.jsonl", "w") as f:
                for r in recs:
                    if r.get("name") == v["name"]:
                        f.write(json.dumps(r, sort_keys=True) + "\n")
            write_json(pd / "summary.json", dict(v, k=k, m=m, floor=fl,
                                                 written_at=timefmt.now_iso()))
            n += 1
        log("wrote %d confirmed program(s) to %s" % (n, out))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("corpus")
    p.add_argument("dir")
    p.add_argument("--control", help="control program file (default: getpid())")
    p = sub.add_parser("run")
    p.add_argument("dir")
    p.add_argument("phase", choices=PHASES)
    p.add_argument("--channels", default="p,p", help="binfreq active,passive clusters")
    p.add_argument("--batch", type=int, default=500, help="trials per binfreq process")
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--trials", type=int, default=200, help="calibrate: control trials")
    p.add_argument("--reps", type=int, default=10, help="confirm: reps per hit")
    p.add_argument("--k", type=float, default=4.0, help="confirm: screen-hit threshold")
    p.add_argument("--active-sweeps", type=int, default=256)
    p.add_argument("--sandbox", default="none")
    p.add_argument("--force", action="store_true", help="run even if the box is busy")
    p = sub.add_parser("status")
    p.add_argument("dir")
    p = sub.add_parser("report")
    p.add_argument("dir")
    p.add_argument("--k", type=float, default=4.0)
    p.add_argument("--m", type=int, default=7)
    p.add_argument("--write-corpus", action="store_true")
    p.add_argument("--corpus-out")
    a = ap.parse_args()
    if a.cmd == "prepare":
        cmd_prepare(a.corpus, a.dir, a.control)
    elif a.cmd == "run":
        cmd_run(a.dir, a.phase, a.channels, a.batch, a.seed, a.trials, a.reps,
                a.k, a.active_sweeps, a.sandbox, a.force)
    elif a.cmd == "status":
        cmd_status(a.dir)
    else:
        cmd_report(a.dir, a.k, a.m, a.write_corpus, a.corpus_out)


if __name__ == "__main__":
    main()
