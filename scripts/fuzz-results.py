#!/usr/bin/env python3
"""fuzz-results.py -- mirror campaign results into a git repo, commit, push.

A workdir is not a record. The manager re-triages corpus.db on every start and
drops whatever does not reproduce its coverage, so a corpus that reached 462
basic blocks on 2 Oct was gone by 9 Oct with nothing on disk saying it had ever
existed. The results repo is the record: every session start, corpus change,
incident and campaign end becomes a commit, pushed off the box.

Layout (one directory per workdir, mirroring workdir/<kext>/<name>):

  <kext>/<name>/STATE.json          latest metrics (also in each commit's trailers)
  <kext>/<name>/corpus.db           byte copy, plus corpus/<hash>.syz unpacked
  <kext>/<name>/cover.log, manager.log, results/, ring_buffer/, grammar/,
                snapshots/, reports/, config/, campaign/
  <kext>/<name>/artifacts/<kind>/<ts>/   incident bundles, without freq/ copies
                                        and without kernel cores (cores.json
                                        lists path, size and sha256 instead)
  <kext>/<name>/freqlab/records.NNNN.jsonl.xz   append-only chunks: each holds
  <kext>/<name>/freqlab/outputs.NNNN.jsonl.xz   the lines added since the last
  <kext>/<name>/freqlab/progs.NNNN.tar.xz       commit, so old chunks are never
  <kext>/<name>/freq/<p|e>.NNNN.csv.xz          rewritten; chunks.json tracks it

Commit subject: "<campaign>: <event> corpus N (+d), cov C, E execs", followed by
trailers (Campaign, Session, Event, Corpus, Coverage, Signal, Exec-Total, Wall,
Syzkaller-Rev, BKC, Kext-Id, Boot-Epoch) so `git log --grep` finds any state.
Coverage is distinct basic blocks over every run (cover.log + archives): the
number a corpus loss makes go backwards. Signal is the manager's own figure.

Tags (annotated): <prefix>/start, <prefix>/<crash|hang>-N, <prefix>/end, and at
the end at most one <kext>/record-cov-N on the commit where this campaign first
reached its maximum -- only when that beats every earlier record for the kext.

Every git failure is reported and swallowed: results must never stop fuzzing.
A failed push is retried by the next commit's push.

Usage:
  fuzz-results.py commit  <config> --event E [--campaign NAME] [--tag-prefix P]
                          [--wall-seconds S] [--no-freq] [--push wait|detach|no]
  fuzz-results.py push
  fuzz-results.py backfill <config> [--campaign NAME] [--push ...]
  fuzz-results.py import  <src-dir> <repo-path> -m MESSAGE
  fuzz-results.py restore <kext>/<name> <dest> [--at REV]
"""

import argparse
import fcntl
import hashlib
import io
import json
import lzma
import os
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))
from lib import timefmt  # noqa: E402

DEFAULT_REPO = Path(os.environ.get("SYZ_RESULTS_REPO", "/Users/Shared/fuzz-results"))
EVENTS = ("start", "restart", "corpus", "crash", "hang", "halt", "end", "backfill")
PUSH_TIMEOUT = 30
LOCK_WAIT = 300
XZ_PRESET = 3            # 30MB of freq_lab outputs: preset 3 = 0.16s, 6 = 0.7s, ~same size
BIG_FILE = 20 << 20      # anything larger is stored as <name>.xz
CORE_GLOBS = ("*.kernel.core.gz", "*.core")
_REV_RE = re.compile(rb"[^0-9a-f]([0-9a-f]{40}\+?)[^0-9a-f]")
_COVERAGE_RE = re.compile(r"\bcoverage=(\d+)")
_EXEC_RE = re.compile(r"\bexec total=(\d+)")
_BB_RE = re.compile(r"basic blks\s*:\s*\S+ \(this run\) / (\d+) \(all runs")


def log(msg):
    sys.stdout.write("%s  results: %s\n" % (timefmt.stamp(), msg))
    sys.stdout.flush()


class GitError(Exception):
    pass


# --- git ---------------------------------------------------------------------
def git(repo, *args, check=True, env=None, timeout=120, input=None):
    e = dict(os.environ)
    e.update(env or {})
    try:
        p = subprocess.run(["git", "-C", str(repo)] + [str(a) for a in args],
                           capture_output=True, text=True, env=e,
                           timeout=timeout, input=input)
    except subprocess.TimeoutExpired:
        raise GitError("git %s: timed out after %ss" % (args[0], timeout))
    if check and p.returncode != 0:
        raise GitError("git %s: %s" % (" ".join(map(str, args[:3])),
                                       (p.stderr or p.stdout).strip()))
    return p.stdout


def prepare_repo(repo):
    if not (repo / ".git").is_dir():
        raise GitError("%s is not a git clone (clone the results project there)" % repo)
    # A panic can land mid-commit. Without fsync a reboot can leave a ref
    # pointing at an object that never reached the disk: a corrupt repo, on
    # the box whose crashes are the whole point.
    if git(repo, "config", "--get", "core.fsync", check=False).strip() != "committed,index":
        git(repo, "config", "core.fsync", "committed,index")
    # The repo is shared by wan and fuzz (group staff), so new .git files must
    # stay group-writable whoever wrote them.
    if git(repo, "config", "--get", "core.sharedRepository", check=False).strip() != "group":
        git(repo, "config", "core.sharedRepository", "group")
    host = socket.gethostname().split(".")[0]
    who = os.environ.get("USER") or "fuzz"
    for k, v in (("user.name", "%s@%s" % (who, host)),
                 ("user.email", "%s@%s.local" % (who, host))):
        if not git(repo, "config", "--get", k, check=False).strip():
            git(repo, "config", k, v)


class RepoLock:
    """One writer at a time. Commits arrive from detached children of the
    campaign driver, so two can overlap; flock is released by the kernel when a
    holder dies, which also makes a leftover .git/index.lock provably stale."""

    def __init__(self, repo, wait=LOCK_WAIT):
        self.repo, self.wait, self.f = repo, wait, None

    def __enter__(self):
        self.f = open(self.repo / ".git" / "fuzz-results.lock", "a")
        deadline = time.time() + self.wait
        while True:
            try:
                fcntl.flock(self.f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.time() >= deadline:
                    raise GitError("repo busy for %ss; giving up" % self.wait)
                time.sleep(1)
        stale = self.repo / ".git" / "index.lock"
        if stale.exists():
            log("removing stale %s (left by a killed writer)" % stale)
            stale.unlink()
        return self

    def __exit__(self, *exc):
        self.f.close()


def push(repo, timeout=PUSH_TIMEOUT):
    """Push branch and tags. Never raises: an offline push is retried next time."""
    try:
        branch = git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip()
        git(repo, "push", "--quiet", "--follow-tags", "origin", branch, timeout=timeout)
        log("pushed %s" % branch)
        return True
    except GitError as e:
        log("push failed (will retry on the next commit): %s" % e)
        return False


def push_detached(repo):
    """Push from a detached child so a slow network never holds up fuzzing."""
    subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "push",
                      "--repo", str(repo)],
                     stdin=subprocess.DEVNULL, start_new_session=True)


# --- small file helpers ------------------------------------------------------
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
        json.dump(obj, f, indent=1, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def same_file(a, b):
    try:
        sa, sb = a.stat(), b.stat()
    except OSError:
        return False
    return sa.st_size == sb.st_size and int(sa.st_mtime) == int(sb.st_mtime)


def copy_file(src, dst):
    """Copy src to dst (as dst.xz if large). Returns the path written."""
    src, dst = Path(src), Path(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    if src.stat().st_size > BIG_FILE:
        dst = dst.with_name(dst.name + ".xz")
        if not same_file(src, dst):
            with open(src, "rb") as f, lzma.open(dst, "wb", preset=XZ_PRESET) as out:
                shutil.copyfileobj(f, out, 1 << 20)
            shutil.copystat(src, dst)
        return dst
    if not same_file(src, dst):
        shutil.copy2(src, dst)
    return dst


def is_core(p):
    return any(p.match(g) for g in CORE_GLOBS)


def mirror_tree(src, dst, skip_dirs=(), cores=None):
    """Make dst a copy of src (files removed from src are removed from dst).
    Kernel cores are not copied; when `cores` is a list they are appended to it."""
    src, dst = Path(src), Path(dst)
    if not src.is_dir():
        return
    want = set()
    for root, dirs, files in os.walk(src):
        dirs[:] = sorted(d for d in dirs if d not in skip_dirs)
        rel = Path(root).relative_to(src)
        for name in sorted(files):
            p = Path(root) / name
            if name.startswith(".") or p.is_symlink() and not p.exists():
                continue
            if is_core(p):
                if cores is not None:
                    cores.append(p)
                continue
            want.add(copy_file(p, dst / rel / name))
    if dst.is_dir():
        for p in sorted(dst.rglob("*"), reverse=True):
            if p.is_file() and p not in want:
                p.unlink()
            elif p.is_dir() and not any(p.iterdir()):
                p.rmdir()


# --- what a workdir says about itself ----------------------------------------
def load_config(path):
    cfg = read_json(path)
    if cfg is None:
        raise SystemExit("error: cannot read config %s" % path)
    return cfg


def unit_of(workdir):
    """Repo directory for a workdir: <kext>/<name>, as under fuzz-run/workdir."""
    workdir = Path(workdir)
    return Path(workdir.parent.name) / workdir.name


def run_logs(workdir):
    return sorted((Path(workdir) / "results").glob("run-*.log"))


def tail(path, n=65536):
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - n))
            return f.read().decode("utf-8", "replace")
    except OSError:
        return ""


def bb_coverage(workdir):
    seen = set()
    for p in [Path(workdir) / "cover.log"] + sorted((Path(workdir) / "results").glob("cover-*.log")):
        try:
            seen.update(ln.strip() for ln in p.read_text(errors="replace").splitlines() if ln.strip())
        except OSError:
            pass
    return len(seen)


def signal_and_execs(workdir):
    """(signal coverage of the newest run, exec total summed over all runs)."""
    signal, total = None, 0
    for lg in run_logs(workdir):
        text = tail(lg)
        execs = _EXEC_RE.findall(text)
        if execs:
            total += int(execs[-1])
        cov = _COVERAGE_RE.findall(text)
        if cov:
            signal = int(cov[-1])
    return signal, total


def session_stamp(workdir):
    logs = run_logs(workdir)
    m = re.search(r"run-(\d{8}-\d{6})\.log$", logs[-1].name) if logs else None
    return m.group(1) if m else "-"


def binary_revision(path):
    try:
        blob = Path(path).read_bytes()
    except OSError:
        return None
    hits = {m.group(1).decode() for m in _REV_RE.finditer(blob)}
    dirty = sorted(h for h in hits if h.endswith("+"))
    return dirty[0] if dirty else (sorted(hits)[0] if len(hits) == 1 else None)


def syzkaller_rev():
    for b in (REPO_ROOT / "bin" / "syz-manager",
              REPO_ROOT / "bin" / "darwin_arm64" / "syz-manager"):
        rev = binary_revision(b)
        if rev:
            return rev[:12] + ("+" if rev.endswith("+") else "")
    return "-"


def boot_epoch():
    try:
        out = subprocess.run(["sysctl", "-n", "kern.boottime"], capture_output=True,
                             text=True, timeout=5).stdout
        m = re.search(r"sec = (\d+)", out)
        return int(m.group(1)) if m else None
    except (OSError, subprocess.SubprocessError):
        return None


def syz_db():
    for b in (os.environ.get("SYZ_DB_BIN"), REPO_ROOT / "bin" / "syz-db",
              REPO_ROOT / "bin" / "darwin_arm64" / "syz-db"):
        if b and os.access(b, os.X_OK):
            return str(b)
    return None


def unpack_corpus(db, dst):
    """Mirror corpus.db's programs into dst/<hash>. Returns the count, or None.

    syz-db rewrites any database it can open for writing, so it only ever sees
    a private copy -- never the workdir file, never a snapshot."""
    tool = syz_db()
    if not tool or not Path(db).exists():
        return None
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / "corpus.db"
        shutil.copyfile(db, copy)
        out = Path(tmp) / "progs"
        p = subprocess.run([tool, "unpack", str(copy), str(out)],
                           capture_output=True, text=True, timeout=120)
        if p.returncode != 0:
            log("syz-db unpack failed: %s" % (p.stderr or p.stdout).strip())
            return None
        mirror_tree(out, dst)
        return sum(1 for _ in out.iterdir()) if out.is_dir() else 0


# --- append-only freq chunks -------------------------------------------------
def _head_sig(path, n=4096):
    with open(path, "rb") as f:
        return hashlib.sha1(f.read(n)).hexdigest()


def chunk_lines(src, dst_dir, stem, ext, st):
    """Write src's lines added since the last chunk as dst_dir/stem.NNNN.ext.xz.

    st (per-source, persisted in chunks.json) holds the byte offset reached and
    a signature of the file's head; a file that shrank or whose head changed
    was recreated, and is chunked again from 0 under the next number."""
    src = Path(src)
    size = src.stat().st_size
    sig = _head_sig(src) if size >= 4096 else None
    off = st.get("offset", 0)
    if size < off or (st.get("head") and sig and st["head"] != sig):
        log("%s was recreated; chunking it again from the start" % src.name)
        off = 0
    if size <= off:
        return None
    with open(src, "rb") as f:
        f.seek(off)
        data = f.read(size - off)
    cut = data.rfind(b"\n") + 1           # never split a line being written
    if cut == 0:
        return None
    n = st.get("next", 1)
    dst = Path(dst_dir) / ("%s.%04d.%s.xz" % (stem, n, ext))
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(lzma.compress(data[:cut], preset=XZ_PRESET))
    st.update(offset=off + cut, next=n + 1, head=sig or st.get("head"))
    return dst


def chunk_files(src_dir, dst_dir, stem, st):
    """tar.xz of the files in src_dir modified since the last chunk."""
    src_dir = Path(src_dir)
    mark = st.get("mtime_ns", 0)
    new = sorted((p for p in src_dir.iterdir() if p.is_file()
                  and p.stat().st_mtime_ns > mark), key=lambda p: p.stat().st_mtime_ns)
    if not new:
        return None
    n = st.get("next", 1)
    dst = Path(dst_dir) / ("%s.%04d.tar.xz" % (stem, n))
    dst.parent.mkdir(parents=True, exist_ok=True)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for p in new:
            tar.add(str(p), arcname=p.name)
    dst.write_bytes(lzma.compress(buf.getvalue(), preset=XZ_PRESET))
    st.update(next=n + 1, mtime_ns=new[-1].stat().st_mtime_ns)
    return dst


def chunk_freq(workdir, unit_dir):
    state_path = unit_dir / "chunks.json"
    state = read_json(state_path, {})
    wrote = []
    fl = Path(workdir) / "freqlab"
    for name in ("records", "outputs"):
        if (fl / ("%s.jsonl" % name)).is_file():
            r = chunk_lines(fl / ("%s.jsonl" % name), unit_dir / "freqlab", name, "jsonl",
                            state.setdefault("freqlab/%s.jsonl" % name, {}))
            wrote += [r] if r else []
    if (fl / "progs").is_dir():
        r = chunk_files(fl / "progs", unit_dir / "freqlab", "progs",
                        state.setdefault("freqlab/progs", {}))
        wrote += [r] if r else []
    fq = Path(workdir) / "freq"
    if fq.is_dir():
        for csv in sorted(fq.glob("*.csv")):
            r = chunk_lines(csv, unit_dir / "freq", csv.stem, "csv",
                            state.setdefault("freq/%s" % csv.name, {}))
            wrote += [r] if r else []
    if wrote:
        write_json(state_path, state)
    return wrote


# --- one sync ----------------------------------------------------------------
def sync_bundles(workdir, unit_dir):
    """Copy incident bundles not yet in the repo. Bundles never change once
    collected, so an existing one is skipped. freq/ copies are dropped (the
    chunks already hold that data) and cores are listed, not copied."""
    root = Path(workdir) / "artifacts"
    if not root.is_dir():
        return
    for kind in sorted(p for p in root.iterdir() if p.is_dir()):
        for b in sorted(p for p in kind.iterdir() if p.is_dir()):
            dst = unit_dir / "artifacts" / kind.name / b.name
            if dst.is_dir():
                continue
            cores = []
            mirror_tree(b, dst, skip_dirs=("freq", "freqlab"), cores=cores)
            if cores:
                write_json(dst / "cores.json", [
                    {"path": str(c), "size": c.stat().st_size, "sha256": sha256(c)}
                    for c in cores])


def sync_workdir(workdir, config_path, unit_dir, campaign_def=None, freq=True):
    workdir = Path(workdir)
    unit_dir.mkdir(parents=True, exist_ok=True)
    for name in ("corpus.db", "cover.log", "manager.log"):
        if (workdir / name).is_file():
            copy_file(workdir / name, unit_dir / name)
    corpus = unpack_corpus(workdir / "corpus.db", unit_dir / "corpus")
    for sub in ("results", "ring_buffer", "grammar", "snapshots", "reports"):
        mirror_tree(workdir / sub, unit_dir / sub)
    sync_bundles(workdir, unit_dir)
    if config_path and Path(config_path).is_file():
        copy_file(config_path, unit_dir / "config" / Path(config_path).name)
    if campaign_def and Path(campaign_def).is_file():
        copy_file(campaign_def, unit_dir / "campaign" / Path(campaign_def).name)
    if freq:
        chunk_freq(workdir, unit_dir)
    return corpus


def metrics(workdir, cfg, corpus, wall=None):
    signal, execs = signal_and_execs(workdir)
    kc = cfg.get("kext_coverage") or {}
    db = Path(workdir) / "corpus.db"
    return {
        "session": session_stamp(workdir),
        "corpus": corpus,
        "corpus_sha256": sha256(db) if db.exists() else None,
        "coverage": bb_coverage(workdir),
        "signal": signal,
        "exec_total": execs,
        "wall_seconds": int(wall) if wall is not None else None,
        "syzkaller_rev": syzkaller_rev(),
        "bkc": cfg.get("kernel_obj") or "-",
        "kext_id": kc.get("kext_id"),
        "boot_epoch": boot_epoch(),
    }


def _v(x):
    return "-" if x is None else x


def message(campaign, event, m, prev):
    pc = (prev or {}).get("corpus")
    delta = (" (%+d)" % (m["corpus"] - pc)) if m["corpus"] is not None and pc is not None else ""
    subject = "%s: %s corpus %s%s, cov %s, %s execs" % (
        campaign, event, _v(m["corpus"]), delta, m["coverage"], m["exec_total"])
    trailers = [
        ("Campaign", campaign), ("Session", m["session"]), ("Event", event),
        ("Corpus", _v(m["corpus"])), ("Coverage", m["coverage"]),
        ("Signal", _v(m["signal"])), ("Exec-Total", m["exec_total"]),
        ("Wall", "%ss" % m["wall_seconds"] if m["wall_seconds"] is not None else "-"),
        ("Syzkaller-Rev", m["syzkaller_rev"]), ("BKC", m["bkc"]),
        ("Kext-Id", _v(m["kext_id"])), ("Boot-Epoch", _v(m["boot_epoch"])),
    ]
    return subject + "\n\n" + "\n".join("%s: %s" % kv for kv in trailers) + "\n"


def changed(m, prev):
    keys = ("corpus_sha256", "coverage", "signal")
    return prev is None or any(m.get(k) != prev.get(k) for k in keys)


def commit(repo, unit, msg, allow_empty, date=None):
    git(repo, "add", "-A", "--", str(unit))
    dirty = subprocess.run(["git", "-C", str(repo), "diff", "--cached", "--quiet"]).returncode != 0
    if not dirty and not allow_empty:
        return None
    env = {"GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date} if date else None
    args = ["commit", "--quiet", "--no-verify", "-F", "-"]
    if allow_empty:
        args.insert(1, "--allow-empty")
    git(repo, *args, env=env, input=msg)
    return git(repo, "rev-parse", "HEAD").strip()


def tag(repo, name, msg, rev="HEAD"):
    if git(repo, "tag", "-l", name).strip():
        log("tag %s already exists; left alone" % name)
        return False
    git(repo, "tag", "-a", name, "-m", msg, rev)
    log("tagged %s" % name)
    return True


def next_incident_tag(repo, prefix, kind):
    n = len(git(repo, "tag", "-l", "%s/%s-*" % (prefix, kind)).split())
    return "%s/%s-%d" % (prefix, kind, n + 1)


def trailer_rows(repo, unit, rev_range=None):
    """[(commit, {trailer: value})] for commits touching unit, oldest first."""
    args = ["log", "--reverse", "--format=%H%x00%B%x01"]
    if rev_range:
        args.append(rev_range)
    out = git(repo, *(args + ["--", str(unit)]), check=False)
    rows = []
    for rec in out.split("\x01"):
        if "\x00" not in rec:
            continue
        h, body = rec.strip().split("\x00", 1)
        tr = dict(re.findall(r"^([A-Za-z-]+): (.*)$", body, re.M))
        rows.append((h, tr))
    return rows


def record_tag(repo, kext, unit, since=None):
    """Tag <kext>/record-cov-N where this run first hit its max, if N beats the
    kext's previous record. One tag per campaign at most, set at its end."""
    best, at = 0, None
    for h, tr in trailer_rows(repo, unit, "%s..HEAD" % since if since else None):
        try:
            cov = int(tr.get("Coverage", ""))
        except ValueError:
            continue
        if cov > best:
            best, at = cov, h
    prev = 0
    for t in git(repo, "tag", "-l", "%s/record-cov-*" % kext).split():
        m = re.search(r"record-cov-(\d+)$", t)
        if m:
            prev = max(prev, int(m.group(1)))
    if at and best > prev:
        tag(repo, "%s/record-cov-%d" % (kext, best),
            "%s: new %s coverage record, %d basic blocks (previous %d)"
            % (unit, kext, best, prev), at)
        return best
    return None


def cmd_commit(a):
    repo = Path(a.repo)
    cfg = load_config(a.config)
    workdir = Path(cfg["workdir"])
    unit = unit_of(workdir)
    campaign = a.campaign or workdir.name
    prefix = a.tag_prefix or campaign
    try:
        prepare_repo(repo)
        with RepoLock(repo, a.lock_wait):
            unit_dir = repo / unit
            prev = read_json(unit_dir / "STATE.json")
            corpus = sync_workdir(workdir, a.config, unit_dir,
                                  campaign_def=a.campaign_def, freq=not a.no_freq)
            m = metrics(workdir, cfg, corpus, a.wall_seconds)
            if a.event == "corpus" and not changed(m, prev):
                # Freq chunks written above ride along on the next real commit.
                log("%s: corpus and coverage unchanged; no commit" % unit)
                return 0
            st = dict(m, campaign=campaign, event=a.event, updated_at=timefmt.now_iso())
            write_json(unit_dir / "STATE.json", st)
            rev = commit(repo, unit, message(campaign, a.event, m, prev),
                         allow_empty=a.event != "corpus")
            log("%s: committed %s (%s)" % (unit, (rev or "-")[:12], a.event))
            if a.event == "start":
                tag(repo, "%s/start" % prefix, "%s started on %s" % (campaign, unit))
            elif a.event in ("crash", "hang"):
                tag(repo, next_incident_tag(repo, prefix, a.event),
                    "%s: %s collected on %s" % (campaign, a.event, unit))
            elif a.event == "end":
                tag(repo, "%s/end" % prefix, "%s ended on %s" % (campaign, unit))
                start = "%s/start" % prefix
                since = start if git(repo, "tag", "-l", start).strip() else None
                record_tag(repo, unit.parts[0], unit, since)
    except GitError as e:
        log("commit failed: %s" % e)
        return 1
    do_push(repo, a.push)
    return 0


def do_push(repo, mode):
    if mode == "wait":
        push(repo)
    elif mode == "detach":
        push_detached(repo)


def cmd_push(a):
    with RepoLock(Path(a.repo), a.lock_wait):
        return 0 if push(Path(a.repo)) else 1


# --- backfill ----------------------------------------------------------------
def _backfill_events(workdir):
    """Past recovery points in time order: workdir snapshots and incident bundles."""
    ev = []
    for s in (Path(workdir) / "snapshots").glob("*/manifest.json"):
        t = timefmt.to_epoch((read_json(s) or {}).get("created_at"))
        if t:
            ev.append((t, "snapshot", s.parent))
    for e in (Path(workdir) / "artifacts").glob("*/*/event.json"):
        j = read_json(e) or {}
        t = timefmt.to_epoch(j.get("collected_at"))
        if t:
            ev.append((t, j.get("kind") or e.parent.parent.name, e.parent))
    return sorted(ev, key=lambda x: (x[0], str(x[2])))


def cmd_backfill(a):
    """Rebuild a workdir's history: one commit per snapshot or incident bundle,
    dated when it was taken, each restoring that point's corpus.db at the top;
    then one commit of the workdir as it is now (freq data included)."""
    repo = Path(a.repo)
    cfg = load_config(a.config)
    workdir = Path(cfg["workdir"])
    unit = unit_of(workdir)
    campaign = a.campaign or workdir.name
    try:
        prepare_repo(repo)
        with RepoLock(repo, a.lock_wait):
            unit_dir = repo / unit
            prev = read_json(unit_dir / "STATE.json")
            for t, kind, src in _backfill_events(workdir):
                rel = src.relative_to(workdir)
                if (unit_dir / rel).is_dir():
                    continue                      # already backfilled
                cores = []
                mirror_tree(src, unit_dir / rel, skip_dirs=("freq", "freqlab"), cores=cores)
                if cores:
                    write_json(unit_dir / rel / "cores.json", [
                        {"path": str(c), "size": c.stat().st_size, "sha256": sha256(c)}
                        for c in cores])
                corpus = None
                if (src / "corpus.db").is_file():
                    copy_file(src / "corpus.db", unit_dir / "corpus.db")
                    corpus = unpack_corpus(src / "corpus.db", unit_dir / "corpus")
                man = (src / "manifest.txt")
                bb = _BB_RE.search(man.read_text(errors="replace")) if man.is_file() else None
                m = {"session": src.name, "corpus": corpus,
                     "corpus_sha256": sha256(src / "corpus.db") if (src / "corpus.db").is_file() else None,
                     "coverage": int(bb.group(1)) if bb else "-", "signal": None,
                     "exec_total": "-", "wall_seconds": None, "syzkaller_rev": "-",
                     "bkc": cfg.get("kernel_obj") or "-",
                     "kext_id": (cfg.get("kext_coverage") or {}).get("kext_id"),
                     "boot_epoch": None}
                date = time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(t))
                write_json(unit_dir / "STATE.json",
                           dict(m, campaign=campaign, event="backfill", source=str(rel)))
                msg = message(campaign, "backfill", m, prev).replace(
                    "Event: backfill", "Event: backfill\nSource: %s" % rel)
                rev = commit(repo, unit, msg, allow_empty=False, date=date)
                log("%s: %s %s -> %s" % (unit, kind, rel, (rev or "-")[:12]))
                prev = m
            corpus = sync_workdir(workdir, a.config, unit_dir, campaign_def=a.campaign_def)
            m = metrics(workdir, cfg, corpus)
            write_json(unit_dir / "STATE.json",
                       dict(m, campaign=campaign, event="backfill", updated_at=timefmt.now_iso()))
            rev = commit(repo, unit, message(campaign, "backfill", m, prev), allow_empty=True)
            log("%s: current state -> %s" % (unit, (rev or "-")[:12]))
            record_tag(repo, unit.parts[0], unit)
    except GitError as e:
        log("backfill failed: %s" % e)
        return 1
    do_push(repo, a.push)
    return 0


def cmd_import(a):
    """Commit an arbitrary results directory (an experiment, a recovered corpus)."""
    repo, src = Path(a.repo), Path(a.src)
    if not src.is_dir():
        raise SystemExit("error: %s is not a directory" % src)
    try:
        prepare_repo(repo)
        with RepoLock(repo, a.lock_wait):
            mirror_tree(src, repo / a.dest)
            rev = commit(repo, Path(a.dest), "%s\n\nEvent: import\nSource: %s\n"
                         % (a.message, src.resolve()), allow_empty=False)
            log("%s: %s" % (a.dest, (rev or "nothing new")[:12]))
    except GitError as e:
        log("import failed: %s" % e)
        return 1
    do_push(repo, a.push)
    return 0


# --- restore -----------------------------------------------------------------
def cmd_restore(a):
    """Rebuild a workdir's results from the repo into a NEW directory.

    Never writes into an existing non-empty directory: restoring over a live
    workdir is exactly how the next corpus would get lost."""
    repo, dest = Path(a.repo), Path(a.dest)
    if dest.exists() and any(dest.iterdir()):
        raise SystemExit("error: %s exists and is not empty" % dest)
    dest.mkdir(parents=True, exist_ok=True)
    unit = a.unit.strip("/")
    arch = subprocess.run(["git", "-C", str(repo), "archive", a.at, unit],
                          capture_output=True)
    if arch.returncode != 0:
        raise SystemExit("error: %s" % arch.stderr.decode().strip())
    depth = len(Path(unit).parts)
    with tarfile.open(fileobj=io.BytesIO(arch.stdout)) as tar:
        for mem in tar.getmembers():
            parts = Path(mem.name).parts[depth:]
            if not parts:
                continue
            mem.name = str(Path(*parts))
            tar.extract(mem, dest)
    for big in dest.rglob("*.xz"):
        if re.search(r"\.\d{4}\.", big.name):
            continue                                  # chunks: joined below
        with lzma.open(big) as f, open(big.with_suffix(""), "wb") as out:
            shutil.copyfileobj(f, out)
        big.unlink()
    for sub, out_ext in (("freqlab", "jsonl"), ("freq", "csv")):
        groups = {}
        for c in sorted((dest / sub).glob("*.[0-9][0-9][0-9][0-9].%s.xz" % out_ext)):
            groups.setdefault(c.name.split(".")[0], []).append(c)
        for stem, chunks in groups.items():
            with open(dest / sub / ("%s.%s" % (stem, out_ext)), "wb") as out:
                for c in chunks:
                    out.write(lzma.decompress(c.read_bytes()))
                    c.unlink()
    for c in sorted((dest / "freqlab").glob("progs.*.tar.xz")):
        (dest / "freqlab" / "progs").mkdir(parents=True, exist_ok=True)
        with tarfile.open(c, "r:xz") as tar:
            tar.extractall(dest / "freqlab" / "progs")
        c.unlink()
    print("restored %s@%s into %s" % (unit, a.at, dest))
    print("corpus: %s/corpus.db (%d programs unpacked in corpus/)"
          % (dest, sum(1 for _ in (dest / "corpus").glob("*")) if (dest / "corpus").is_dir() else 0))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--repo", default=str(DEFAULT_REPO))
    ap.add_argument("--lock-wait", type=int, default=LOCK_WAIT)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_common(p):
        p.add_argument("--repo", default=argparse.SUPPRESS)
        p.add_argument("--lock-wait", type=int, default=argparse.SUPPRESS)
        p.add_argument("--push", choices=("wait", "detach", "no"), default="wait")

    p = sub.add_parser("commit")
    p.add_argument("config")
    p.add_argument("--event", required=True, choices=EVENTS)
    p.add_argument("--campaign")
    p.add_argument("--campaign-def")
    p.add_argument("--tag-prefix")
    p.add_argument("--wall-seconds", type=float)
    p.add_argument("--no-freq", action="store_true")
    add_common(p)
    p = sub.add_parser("push")
    p.add_argument("--repo", default=argparse.SUPPRESS)
    p.add_argument("--lock-wait", type=int, default=argparse.SUPPRESS)
    p = sub.add_parser("backfill")
    p.add_argument("config")
    p.add_argument("--campaign")
    p.add_argument("--campaign-def")
    add_common(p)
    p = sub.add_parser("import")
    p.add_argument("src")
    p.add_argument("dest")
    p.add_argument("-m", "--message", required=True)
    add_common(p)
    p = sub.add_parser("restore")
    p.add_argument("unit")
    p.add_argument("dest")
    p.add_argument("--at", default="HEAD")
    p.add_argument("--repo", default=argparse.SUPPRESS)
    a = ap.parse_args()
    return {"commit": cmd_commit, "push": cmd_push, "backfill": cmd_backfill,
            "import": cmd_import, "restore": cmd_restore}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
