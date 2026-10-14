#!/usr/bin/env python3
"""Replay a freq_lab campaign's programs in shuffled order, several times.

A campaign measures each program once, at one moment, amid whatever the fuzzer
did just before. Replaying every unique program in a fresh random order per
pass separates an effect that follows the INPUT from one that follows its
POSITION in time: a real effect repeats in every pass; drift does not.

Each pass runs the same freq_lab path as the campaign (syz-execprog
-freq_lab_dir), so it writes the same files: progs/<id>.syz, records.jsonl
(pre/post P+E, per-call results) and outputs.jsonl (IOKit outputs). Programs
are matched across campaign and passes by the SHA-1 of their text.

  out/unique/<sha>.syz        each unique program once
  out/unique.json             sha -> campaign request ids that ran it
  out/pass<N>/order.json      that pass's shuffled sha order (fixed seed)
  out/pass<N>/records.jsonl   freq_lab records   } written by syz-execprog
  out/pass<N>/outputs.jsonl   IOKit outputs      }
  out/pass<N>/suspects.json   programs that never returned (panic) -- skipped

Resumable: a pass restarts after the last recorded program. A program whose
text was saved but has no record took the box down; it is noted and skipped.

Usage:
  scripts/freq-lab-replay.py prepare <campaign>/freqlab <out> [--passes 4] [--seed 1]
  scripts/freq-lab-replay.py run     <out> [--pass N] [--force]
  scripts/freq-lab-replay.py status  <out>
"""

import argparse
import hashlib
import json
import os
import random
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import timefmt  # noqa: E402
from lib.tablefmt import tabulate  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
BIN_DIR = REPO_ROOT / "bin" / "darwin_arm64"
EXECPROG = Path(os.environ.get("SYZ_EXECPROG_BIN", BIN_DIR / "syz-execprog"))
EXECUTOR = Path(os.environ.get("SYZ_EXECUTOR_BIN", BIN_DIR / "syz-executor"))
_tree_binfreq = REPO_ROOT / "bin" / "binfreq"
BINFREQ_BIN = Path(os.environ.get(
    "SYZ_BINFREQ_BIN",
    _tree_binfreq if _tree_binfreq.exists() else REPO_ROOT.parent / "fthM2" / "binfreq"))
BUSY_PROCS = ("syz-manager", "syz-executor", "syz-execprog")


def log(msg):
    sys.stdout.write("%s  %s\n" % (timefmt.stamp(), msg))
    sys.stdout.flush()


def die(msg):
    sys.stderr.write("error: %s\n" % msg)
    sys.exit(1)


def sha(text):
    return hashlib.sha1(text).hexdigest()


def read_json(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_json(path, obj):
    path = Path(path)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=1)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def read_jsonl(path):
    out = []
    try:
        with open(path) as f:
            for line in f:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass            # torn last line after a panic
    except OSError:
        pass
    return out


def cmd_prepare(freqlab, out, passes, seed):
    freqlab, out = Path(freqlab), Path(out)
    progs = freqlab / "progs"
    if not progs.is_dir():
        die("no progs/ in %s" % freqlab)
    if (out / "unique.json").exists():
        die("%s already prepared" % out)
    (out / "unique").mkdir(parents=True, exist_ok=True)
    seen = {}
    for p in sorted(progs.glob("*.syz"), key=lambda p: int(p.stem)):
        text = p.read_bytes()
        h = sha(text)
        if h not in seen:
            (out / "unique" / ("%s.syz" % h)).write_bytes(text)
            seen[h] = []
        seen[h].append(int(p.stem))
    write_json(out / "unique.json", seen)
    shas = sorted(seen)
    for n in range(1, passes + 1):
        order = list(shas)
        random.Random(seed * 1000 + n).shuffle(order)
        d = out / ("pass%d" % n)
        d.mkdir(exist_ok=True)
        write_json(d / "order.json", order)
    write_json(out / "meta.json", {"campaign_freqlab": str(freqlab.resolve()),
                                   "prepared_at": timefmt.now_iso(),
                                   "saved_programs": sum(len(v) for v in seen.values()),
                                   "unique_programs": len(shas),
                                   "passes": passes, "seed": seed})
    log("prepared %d unique program(s) (from %d saved) x %d pass(es) in %s"
        % (len(shas), sum(len(v) for v in seen.values()), passes, out))


def pass_progress(d):
    """(done shas, suspect shas): recorded programs, and programs that were
    saved but never got a record -- they took the box down."""
    recorded = {r["id"] for r in read_jsonl(d / "records.jsonl")}
    done, started = set(), {}
    for p in (d / "progs").glob("*.syz") if (d / "progs").is_dir() else []:
        h = sha(p.read_bytes())
        if int(p.stem) in recorded:
            done.add(h)
        else:
            started[h] = int(p.stem)
    sus = set(read_json(d / "suspects.json", []))
    # Only a saved-but-unrecorded program at the END of the run is a suspect;
    # its id is the highest one saved (one program is in flight at a time).
    if started:
        last_h = max(started, key=started.get)
        if last_h not in done and last_h not in sus:
            sus.add(last_h)
            write_json(d / "suspects.json", sorted(sus))
            log("SUSPECT %s: saved but never recorded -- likely a panic; skipping it" % last_h[:12])
    return done, sus


def busy_procs():
    return [p for p in BUSY_PROCS
            if subprocess.run(["pgrep", "-x", p], capture_output=True).returncode == 0]


def run_pass(out, n):
    d = out / ("pass%d" % n)
    order = read_json(d / "order.json")
    if order is None:
        die("%s has no order.json (run prepare)" % d)
    done, sus = pass_progress(d)
    todo = [h for h in order if h not in done and h not in sus]
    log("pass %d: %d program(s), %d done, %d suspect, %d to run"
        % (n, len(order), len(done), len(sus), len(todo)))
    if not todo:
        return
    batch = d / "batch.syz"
    with open(batch, "wb") as f:
        for i, h in enumerate(todo):
            f.write(b"executing program 0 id=%d\n" % i)
            f.write((out / "unique" / ("%s.syz" % h)).read_bytes())
            f.write(b"\n")
    scratch = d / "exec"
    scratch.mkdir(exist_ok=True)
    env = dict(os.environ, SYZ_IOKIT_OUTPUT_LOG=str((d / "outputs.jsonl").resolve()))
    cmd = [str(EXECPROG), "-executor", str(EXECUTOR), "-procs", "1", "-repeat", "1",
           "-cover=false", "-sandbox", "none",
           "-freq_lab_dir", str(d.resolve()), "-freq_lab_binfreq", str(BINFREQ_BIN),
           str(batch.resolve())]
    with open(d / "execprog.log", "a") as logf:
        rc = subprocess.run(cmd, cwd=str(scratch), env=env, stdout=logf,
                            stderr=subprocess.STDOUT).returncode
    done, sus = pass_progress(d)
    log("pass %d: syz-execprog exited %d; %d/%d recorded" % (n, rc, len(done), len(order)))
    if rc != 0:
        die("syz-execprog failed; see %s" % (d / "execprog.log"))


def cmd_run(out, only, force):
    out = Path(out).resolve()
    meta = read_json(out / "meta.json")
    if meta is None:
        die("%s is not prepared" % out)
    for b in (EXECPROG, EXECUTOR, BINFREQ_BIN):
        if not os.access(b, os.X_OK):
            die("missing executable %s" % b)
    busy = busy_procs()
    if busy and not force:
        die("box is not quiet (%s running); stop the campaign or pass --force" % ", ".join(busy))
    for n in ([only] if only else range(1, meta["passes"] + 1)):
        run_pass(out, n)
    log("complete")


def cmd_status(out):
    out = Path(out)
    meta = read_json(out / "meta.json")
    if meta is None:
        die("%s is not prepared" % out)
    rows = []
    for n in range(1, meta["passes"] + 1):
        d = out / ("pass%d" % n)
        order = read_json(d / "order.json", [])
        recorded = {r["id"] for r in read_jsonl(d / "records.jsonl")}
        done = sum(1 for p in (d / "progs").glob("*.syz")
                   if int(p.stem) in recorded) if (d / "progs").is_dir() else 0
        rows.append([n, len(order), done, len(read_json(d / "suspects.json", []))])
    print("%d unique program(s) from %d saved" % (meta["unique_programs"], meta["saved_programs"]))
    tabulate(rows, ["pass", "programs", "recorded", "suspect"])


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("freqlab")
    p.add_argument("out")
    p.add_argument("--passes", type=int, default=4)
    p.add_argument("--seed", type=int, default=1)
    p = sub.add_parser("run")
    p.add_argument("out")
    p.add_argument("--pass", dest="only", type=int)
    p.add_argument("--force", action="store_true")
    p = sub.add_parser("status")
    p.add_argument("out")
    a = ap.parse_args()
    if a.cmd == "prepare":
        cmd_prepare(a.freqlab, a.out, a.passes, a.seed)
    elif a.cmd == "run":
        cmd_run(a.out, a.only, a.force)
    else:
        cmd_status(a.out)


if __name__ == "__main__":
    main()
