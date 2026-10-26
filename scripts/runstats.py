#!/usr/bin/env python3
"""Extract comparable metrics from fuzzing runs, so experiments can be compared.

The unit of analysis is a RUN: one workdir, which is one config, which is one
experiment. Everything a run produced is already on disk -- syz-manager's bench
series, the coverage log, the corpus, the campaign's clocks, the bug inventory --
but scattered across five formats, and none of it is directly comparable between
runs. This normalizes it.

Three things make naive comparison wrong, and this tool exists mostly to get them
right:

  1. `exec total` RESETS on every manager restart. On a target that panics every
     40s a run is dozens of restarts, so reading the last bench sample
     under-reports execution by an order of magnitude. Totals are summed across
     restarts; `coverage` is NOT summed, because it is recomputed from corpus.db
     and therefore already cumulative -- summing it would multiply-count.

  2. Effort must be measured in FUZZING time, not wall clock. A run that spent
     five hours minimizing a bug and one hour fuzzing is not a six-hour run, and
     comparing it against one that fuzzed for six would be meaningless.
     syz-manager reports its own `fuzzing` counter, which is authoritative and
     independent of the campaign driver's accounting.

  3. Time-to-first-bug likewise. A bug found after 40 minutes of wall clock, 30
     of which were reboots, was found in 10 minutes of fuzzing. Wall-clock
     time-to-find measures how crashy the target is, not how fast the fuzzer is.
     Discovery times are mapped back onto the fuzzing clock by interpolating the
     bench series.

Usage:
  runstats.py list                      # one row per run
  runstats.py show <run>                # everything known about one run
  runstats.py compare --by grammar      # group and aggregate (grammar|cov|driver|kext|config)
  runstats.py curve <run>               # coverage vs fuzz-hours, TSV for plotting
  runstats.py export --format csv|json  # the full table, for a notebook or paper

A run is one workdir. Legacy runs are named <Driver>/<variant>, e.g.
AppleSSE/260804_cov_gram. Plan-layout runs (campaign-planning.md §4) are named
<campaign>/<config-id>/<item-id>, one sample of one config under its campaign;
`compare --by config` groups the samples of a config and reports mean ± spread.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib import timefmt  # noqa: E402
from lib.tablefmt import tabulate  # noqa: E402

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
# Rebindable: the runs worth comparing usually live in the PUBLISHED tree
# (/Users/Shared/fuzz-run), not the build tree, because that is where the fuzz
# user actually runs. --root points the whole tool at either.
WORKDIR_ROOT = REPO_ROOT / "workdir"
CONFIG_DIR = REPO_ROOT / "config"
STATE_DIR = REPO_ROOT / "campaigns" / ".state"


def bugs_dir(root):
    """The bug ledger: <root>/bugs, or campaigns/bugs on a tree `migrate` has
    not moved yet -- the same rule as fuzz-campaign.py and bug_registry.py."""
    new, old = Path(root) / "bugs", Path(root) / "campaigns" / "bugs"
    return old if (old.is_dir() and not new.is_dir()) else new


BUGS_DIR = bugs_dir(REPO_ROOT)


def set_root(root):
    global WORKDIR_ROOT, CONFIG_DIR, STATE_DIR, BUGS_DIR
    root = Path(root).expanduser().resolve()
    WORKDIR_ROOT = root / "workdir"
    CONFIG_DIR = root / "config"
    STATE_DIR = root / "campaigns" / ".state"
    BUGS_DIR = bugs_dir(root)

# Counters syz-manager resets when the manager restarts. A run is many restarts
# on this target, so these are summed across bench files; anything not listed is
# read as already-cumulative and taken at its maximum.
RESETTING = ("exec total", "exec fuzz", "exec gen", "exec minimize", "exec smash",
             "exec triage", "exec collide", "executor restarts", "crashes")

# Rebuilt from corpus.db at startup, hence already cumulative across restarts.
CUMULATIVE = ("coverage", "corpus", "signal", "max signal", "syscalls",
              "new inputs", "crash types")


# --- bench series ------------------------------------------------------------
def parse_bench(path):
    """syz-manager writes pretty-printed JSON objects back to back, not JSONL,
    so the file is one concatenated stream rather than one document per line."""
    dec = json.JSONDecoder()
    try:
        text = Path(path).read_text()
    except OSError:
        return []
    out, i, n = [], 0, len(text)
    while i < n:
        while i < n and text[i] in " \t\r\n":
            i += 1
        if i >= n:
            break
        try:
            obj, i = dec.raw_decode(text, i)
        except ValueError:
            break                      # truncated tail: a panic cut the last write
        out.append(obj)
    return out


_BENCH_RE = re.compile(r"bench-(\d{8}-\d{6})\.json$")


def bench_files(workdir):
    """The run's bench files with their start epochs, oldest first."""
    results = Path(workdir) / "results"
    found = []
    for p in sorted(results.glob("bench-*.json")):
        m = _BENCH_RE.search(p.name)
        if not m:
            continue
        start = timefmt.to_epoch(m.group(1))
        if start is None:
            continue
        found.append((start, p))
    return sorted(found)


def merge_bench(workdir, since=None, until=None):
    """Fold every restart of this run into one record plus a fuzz-time series.

    since/until bound which segments count, by segment start time. This matters
    because a config IS a workdir: re-running a config as a NEW campaign appends
    its segments to the same directory, and folding them together silently
    reports one experiment's numbers as another's. Bounding by the campaign's
    lifetime separates them again.

    Returns {segments, fuzz_seconds, uptime_seconds, execs, <cumulative maxima>,
    series: [...], segment_rows: [...]}.
    """
    total = {k: 0 for k in RESETTING}
    peak = {k: 0 for k in CUMULATIVE}
    fuzz_ns, uptime, segments, series = 0, 0, 0, []
    seg_rows = []
    for start, path in bench_files(workdir):
        if since is not None and start < since:
            continue
        if until is not None and start > until:
            continue
        rows = parse_bench(path)
        if not rows:
            seg_rows.append({"name": path.name, "start": start, "empty": True})
            continue                   # a 0-byte bench: manager died before its first tick
        segments += 1
        base_fuzz = fuzz_ns
        for r in rows:
            # Cumulative-within-a-segment: the fuzz clock is base + this sample.
            series.append((base_fuzz + r.get("fuzzing", 0),
                           start + r.get("uptime", 0), r))
            for k in CUMULATIVE:
                if r.get(k) is not None:
                    peak[k] = max(peak[k], r[k])
        last = rows[-1]
        seg_rows.append({"name": path.name, "start": start, "empty": False,
                         "fuzz_seconds": (last.get("fuzzing", 0) or 0) / 1e9,
                         "uptime_seconds": last.get("uptime", 0) or 0,
                         "execs": last.get("exec total", 0) or 0,
                         "coverage": last.get("coverage", 0) or 0})
        for k in RESETTING:
            total[k] += last.get(k, 0) or 0
        fuzz_ns += last.get("fuzzing", 0) or 0
        uptime += last.get("uptime", 0) or 0
    out = {"segments": segments,
           "fuzz_seconds": fuzz_ns / 1e9,
           "uptime_seconds": float(uptime),
           "series": series, "segment_rows": seg_rows}
    out.update({k.replace(" ", "_"): v for k, v in total.items()})
    out.update({k.replace(" ", "_"): v for k, v in peak.items()})
    return out


def fuzz_seconds_at(series, wall_epoch):
    """Fuzzing seconds elapsed when the wall clock read wall_epoch.

    This is the mapping that makes time-to-find comparable: a bug found 40
    minutes into a run that spent 30 of them rebooting was found after 10 minutes
    of fuzzing, and the second number is the one that says anything about the
    fuzzer. Linear within a bench interval, which is a ~60s tick.
    """
    if not series or wall_epoch is None:
        return None
    prev = None
    for fuzz_ns, wall, _ in series:
        if wall >= wall_epoch:
            if prev is None:
                return fuzz_ns / 1e9
            pf, pw = prev
            span = wall - pw
            frac = 0.0 if span <= 0 else (wall_epoch - pw) / span
            return (pf + (fuzz_ns - pf) * frac) / 1e9
        prev = (fuzz_ns, wall)
    return series[-1][0] / 1e9         # after the last sample: all of it


# --- run identity ------------------------------------------------------------
def parse_variant(variant):
    """Decompose <YYMMDD>_<coverage>[-<mod>...]_<grammar>[_<seq>].

    The naming convention is the experiment matrix, so it is also the comparison
    axis: grouping by 'grammar' or 'cov' is just reading these back out.
    """
    toks = variant.split("_")
    out = {"date": None, "cov": None, "grammar": None, "mods": [],
           "seq": None, "test": "test" in toks}
    for t in toks:
        base = t.split("-")[0]
        if re.fullmatch(r"\d{6}", t) and out["date"] is None:
            out["date"] = t
        elif re.fullmatch(r"(no)?cov", base):
            out["cov"] = base
            out["mods"] += t.split("-")[1:]
        elif re.fullmatch(r"(nogram|nogrammar|gramsel|gram)", base):
            out["grammar"] = "nogram" if base == "nogrammar" else base
            out["mods"] += t.split("-")[1:]
        elif re.fullmatch(r"\d+", t):
            out["seq"] = t
        elif t != "test":
            out["mods"].append(t)
    return out


def campaigns_root(root=None):
    """campaigns/ sits beside workdir/ under the tree root (see set_root), so it
    is the sibling of whichever workdir root we were pointed at."""
    return Path(root or WORKDIR_ROOT).parent / "campaigns"


def item_info(workdir):
    """For a plan-layout item workdir, item.json beside it; None for legacy.

    A plan-layout run lives at campaigns/<name>/<config-id>/<item-id>/workdir,
    and item.json one level up records {campaign, item, config, workdir} -- the
    AUTHORED config path among them. We read it rather than parse the path
    because the authored config is the comparison key (§4) and item.json is the
    item's own record of it; the <config-id> folder is merely derived from the
    same stem. `dir` is the on-disk item folder, trusted over item.json's stored
    workdir string because the tree may have been published to another path.
    """
    wd = Path(workdir)
    if wd.name != "workdir":
        return None
    meta = read_json(wd.parent / "item.json")
    if not isinstance(meta, dict) or not meta.get("config"):
        return None
    info = dict(meta)
    info["dir"] = wd.parent
    info["cid"] = Path(meta["config"]).stem
    return info


def discover_runs(root=None):
    """Every run as a workdir, across both layouts.

    Legacy runs are workdir/<Driver>/<variant>/. Plan-layout runs are item
    workdirs at campaigns/<name>/<config-id>/<item-id>/workdir (§4): one workdir
    is still one run, just nested under its campaign and config so a config's
    samples sit side by side. The item.json guard keeps non-run folders (bugs/,
    .state/) from matching the glob."""
    root = Path(root or WORKDIR_ROOT)
    runs = []
    if root.is_dir():
        for driver in sorted(p for p in root.iterdir() if p.is_dir()):
            for wd in sorted(p for p in driver.iterdir() if p.is_dir()):
                runs.append(wd)
    camps = campaigns_root(root)
    if camps.is_dir():
        for wd in sorted(camps.glob("*/*/*/workdir")):
            if wd.is_dir() and (wd.parent / "item.json").exists():
                runs.append(wd)
    return runs


def run_name(workdir):
    """<Driver>/<variant> for a legacy run, <campaign>/<config-id>/<item-id> for
    a plan-layout item -- the three folders that locate the sample under §4."""
    wd = Path(workdir)
    if item_info(wd) is not None:
        return "%s/%s/%s" % (wd.parent.parent.parent.name,
                             wd.parent.parent.name, wd.parent.name)
    return "%s/%s" % (wd.parent.name, wd.name)


def run_path(name, root=None):
    """The workdir a run name points at, for `show`/`curve`. A 3-component name
    is a plan-layout item under campaigns/; otherwise it is legacy under
    workdir/."""
    parts = name.split("/")
    if len(parts) == 3:
        camp, cfg, item = parts
        return campaigns_root(root) / camp / cfg / item / "workdir"
    return Path(root or WORKDIR_ROOT) / name


def config_id_for(workdir):
    """The config whose run this is, as a stem. Legacy: <Driver>_<variant> from
    the path. Plan layout: the AUTHORED config's stem from item.json -- NOT the
    parent folder plus name, because the authored config is what runs of this
    config across campaigns have in common."""
    info = item_info(workdir)
    if info is not None:
        return info["cid"]
    wd = Path(workdir)
    return "%s_%s" % (wd.parent.name, wd.name)


# --- the other sources -------------------------------------------------------
def read_json(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def cover_blocks(workdir):
    """Distinct basic-block PCs in the coverage logs.

    cover.log is the live run's; cover-<ts>.log are archived earlier runs. The
    union across them is what the run actually reached, since a restart begins a
    fresh log while the corpus that produced those blocks persists.
    """
    wd = Path(workdir)
    pcs = set()
    for p in [wd / "cover.log"] + sorted((wd / "results").glob("cover-*.log")):
        try:
            with open(p) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("0x"):
                        pcs.add(line.split()[0])   # '0x<pc>' or '0x<pc> <unix>'
        except OSError:
            continue
    return len(pcs)


def corpus_bytes(workdir):
    """Size of corpus.db. NOT a program count: the file is syzkaller's own
    format (magic db ad 0b 00), not SQLite. The program count comes from the
    bench series' `corpus` field, which the manager reports directly."""
    try:
        return (Path(workdir) / "corpus.db").stat().st_size
    except OSError:
        return None


def grammar_of(workdir):
    """The description set the run used, from save_grammar's manifests.

    Returns (fingerprint, n_files, n_versions). n_versions > 1 means the grammar
    CHANGED mid-run, which makes the run a poor comparison subject -- worth
    seeing rather than silently averaging over.
    """
    gdir = Path(workdir) / "grammar"
    if not gdir.is_dir():
        return None, 0, 0
    manifests = sorted(gdir.glob("*/manifest.json"))
    if not manifests:
        return None, 0, 0
    last = read_json(manifests[-1], {})
    return (last.get("fingerprint", "")[:12] or None,
            len(last.get("files", [])), len(manifests))


def campaign_state_path(campaign):
    """campaigns/<name>/state.json -- the plan-layout campaign's state (§4)."""
    return campaigns_root() / campaign / "state.json"


def config_facts(config_id, config_path=None):
    """Enabled/benched syscall counts for the config this run used. Legacy reads
    config/<id>.cfg by id; an item reads the authored path item.json recorded,
    since a plan-layout config is not under config/<id>.cfg at all."""
    cfg = Path(config_path) if config_path else CONFIG_DIR / ("%s.cfg" % config_id)
    conf = read_json(cfg)
    if not conf:
        return {}
    return {"enabled": len(conf.get("enable_syscalls", []) or []),
            "disabled": len(conf.get("disable_syscalls", []) or []),
            "config_path": str(cfg)}


def campaign_windows(config_id, item=None):
    """Every campaign that drove this config, with the window it owned.

    A LEGACY workdir accumulates segments from every campaign that ever used the
    config, so "this run" is ambiguous unless you say which campaign you mean. A
    plan-layout item workdir holds exactly one sample of one campaign, so the
    item IS the scope: one unbounded window (the whole directory), no time
    bounds to disentangle one experiment's segments from another's."""
    if item is not None:
        st = read_json(campaign_state_path(item["campaign"]), {}) or {}
        if not isinstance(st, dict) or not st:
            return []
        return [{"name": st.get("name") or item["campaign"], "state": st,
                 "start": None, "end": None, "status": st.get("status")}]
    out = []
    if not STATE_DIR.is_dir():
        return out
    for p in sorted(STATE_DIR.glob("*.json")):
        if p.name.startswith("quarantine_") or p.name.endswith(".requests.json"):
            continue
        st = read_json(p, {}) or {}
        if not isinstance(st, dict):          # a request list, not a state
            continue
        cur = st.get("current_config") or ""
        hit = Path(cur).stem == config_id if cur else False
        if not hit:
            hit = any(Path(i.get("config") or "").stem == config_id
                      for i in st.get("incidents", []))
        if not hit:
            continue
        start = timefmt.to_epoch(st.get("started_at"))
        end = timefmt.to_epoch(st.get("updated_at"))
        if st.get("status") == "running":
            end = None                 # still accruing
        out.append({"name": st.get("name") or p.stem, "state": st,
                    "start": start, "end": end,
                    "status": st.get("status")})
    out.sort(key=lambda c: c["start"] or 0)
    return out


def campaign_for(config_id, item=None):
    """The campaign state that drove this config, if any, plus its clocks. For a
    plan-layout item that is campaigns/<name>/state.json directly; for legacy it
    is the one .state/<name>.json that names this config."""
    if item is not None:
        return read_json(campaign_state_path(item["campaign"]))
    if not STATE_DIR.is_dir():
        return None
    for p in sorted(STATE_DIR.glob("*.json")):
        if p.name.startswith("quarantine_") or p.name.endswith(".requests.json"):
            continue
        st = read_json(p, {})
        if not isinstance(st, dict):
            continue
        cur = st.get("current_config") or ""
        hit = Path(cur).stem == config_id if cur else False
        if not hit:
            hit = any(Path(i.get("config") or "").stem == config_id
                      for i in st.get("incidents", []))
        if hit:
            return st
    return None


def _lifetime(st, key):
    total = {"prep_seconds": "total_prep_seconds",
             "active_seconds": "total_active_seconds",
             "triage_seconds": "total_triage_seconds",
             "overhead_seconds": "total_overhead_seconds"}[key]
    return (st.get(total, 0.0) or 0.0) + (st.get(key, 0.0) or 0.0)


_CLOCK_KEYS = ("prep_seconds", "active_seconds", "triage_seconds", "overhead_seconds")


def item_clocks(camp_state, item_id):
    """The four clocks for ONE item. When the item ended, the runner banked them
    onto its record (state.items[id].clocks); while it is the running item they
    are the campaign's live top-level counters, which only that item is accruing.
    This is the per-item answer the shared legacy clocks (_lifetime) cannot give,
    because a plan campaign runs many items against the same counters in turn."""
    rec = ((camp_state or {}).get("items") or {}).get(item_id) or {}
    src = rec.get("clocks") or (camp_state or {})
    return {k: (src.get(k) or 0.0) for k in _CLOCK_KEYS}


def quarantine_for(config_id, item=None):
    """Benched selectors / catalogued signatures. A plan-layout item keeps its
    quarantine next to its corpus (<item>/quarantine.json, §4); legacy shares
    one keyed by config under .state."""
    if item is not None:
        st = read_json(item["dir"] / "quarantine.json", {})
    else:
        st = read_json(STATE_DIR / ("quarantine_%s.json" % config_id), {})
    cat = (st or {}).get("catalog", {})
    return {"benched": len((st or {}).get("hard", []) or []),
            "catalogued": len(cat)}


_PANIC_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})-(\d{6})")


def crash_epoch(crash):
    """When the panic HAPPENED, not when it was filed.

    first_seen is the moment bug_registry routed the report, which can be an hour
    or a session later -- fine for an audit trail, wrong for asking which run was
    running at the time. The report basename carries the real local timestamp
    (panic-full-YYYY-MM-DD-HHMMSS), so prefer it and fall back to first_seen.
    """
    m = _PANIC_RE.search(crash.get("report") or "")
    if m:
        e = timefmt.to_epoch("%s%s%s-%s" % m.groups())
        if e:
            return e
    return timefmt.to_epoch(crash.get("first_seen"))


def run_window(series):
    """(first, last) wall epochs this run was alive, or None."""
    if not series:
        return None
    walls = [w for _, w, _ in series]
    return min(walls), max(walls)


def bugs_for(config_id, series, infer=True, item=None):
    """Bugs the inventory attributes to this run.

    Only fuzz-origin crashes count as discoveries: a panic the minimizer caused
    on purpose is evidence, not a find, and counting it would make investigating
    a bug look like finding more of them.

    For a plan-layout item the attribution is exact: each crash records its
    campaign and item, so a sample owns precisely the crashes tagged with it.
    The item IS the scope -- the time window exists only because legacy workdirs
    were shared between campaigns -- so the window fallback is skipped once the
    campaign+item filter has spoken.

    Otherwise attribution is by the crash row's recorded config where present.
    That field is recent, so most historical crashes carry config=None and would
    otherwise be attributable to nothing -- making every older run report zero
    bugs, which reads as "found nothing" rather than "cannot tell". For those,
    fall back to the run's wall-clock window: a panic that happened while this
    run was the only thing alive belongs to it. Inferred attributions are counted
    separately so the difference between measured and reconstructed stays visible.
    """
    reg = read_json(BUGS_DIR / "registry.json", {}) or {}
    win = run_window(series)
    found = []
    for rec in (reg.get("bugs") or {}).values():
        crashes = [c for c in rec.get("crashes", [])
                   if (c.get("origin") or "fuzz") == "fuzz"]
        inferred = False
        if item is not None:
            firsts = [c for c in crashes
                      if c.get("campaign") == item["campaign"]
                      and c.get("item") == item["item"]]
        else:
            firsts = [c for c in crashes if c.get("config") == config_id]
        if not firsts and infer and win:
            firsts = [c for c in crashes
                      if not c.get("config")
                      and win[0] <= (crash_epoch(c) or 0) <= win[1]]
            inferred = bool(firsts)
        if not firsts:
            continue
        walls = sorted(w for w in (crash_epoch(c) for c in firsts) if w)
        found.append({
            "id": rec.get("id"), "key": rec.get("bug_key"),
            "first_wall": walls[0] if walls else None,
            "first_fuzz_s": fuzz_seconds_at(series, walls[0]) if walls else None,
            "crashes": len(firsts),
            "verified": bool((rec.get("reproducer") or {}).get("verified")),
            "inferred": inferred,
        })
    found.sort(key=lambda b: (b["first_fuzz_s"] is None, b["first_fuzz_s"] or 0))
    return found


# --- the record --------------------------------------------------------------
def collect(workdir, campaign=None):
    """Metrics for one run. For a LEGACY run, `campaign` scopes the bench segments
    to that campaign's lifetime; without it, EVERY campaign that used this config
    is folded in. A plan-layout item workdir needs no such scoping -- it holds one
    sample of one campaign, so the item is the scope -- and its clocks, bugs,
    config and quarantine are read per item rather than per shared config."""
    wd = Path(workdir)
    item = item_info(wd)
    cid = config_id_for(wd)
    scope = None
    if item is not None:
        # The item IS the scope: one workdir, one sample, so fold the whole dir
        # with no window and read everything from the item's own records.
        bench = merge_bench(wd)
        wins = campaign_windows(cid, item=item)
        camp = campaign_for(cid, item=item)
        driver, _, variant = cid.partition("_")
        ident = parse_variant(variant)
        bugs = bugs_for(cid, bench["series"], item=item)
    else:
        wins = campaign_windows(cid)
        if campaign:
            scope = next((c for c in wins if c["name"] == campaign), None)
            if scope is None:
                bench = {"segments": 0, "fuzz_seconds": 0.0, "uptime_seconds": 0.0,
                         "series": [], "segment_rows": []}
            else:
                bench = merge_bench(wd, scope["start"], scope["end"])
        else:
            bench = merge_bench(wd)
        driver = wd.parent.name
        ident = parse_variant(wd.name)
        camp = (scope or {}).get("state") if scope else campaign_for(cid)
        bugs = bugs_for(cid, bench["series"])
    fuzz_s = bench["fuzz_seconds"]
    cbytes = corpus_bytes(wd)
    gfp, gfiles, gversions = grammar_of(wd)

    # Coverage: the bench counter and the cover log are independent measurements
    # (manager-side vs the kext's own log), so keep both rather than picking one.
    blocks_log = cover_blocks(wd)
    blocks = bench.get("coverage") or 0

    rec = {
        "run": run_name(wd), "config": cid, "driver": driver,
        "layout": "plan" if item is not None else "legacy",
        # More than one campaign in this workdir means the unscoped numbers mix
        # experiments. Surfaced rather than silently summed.
        "campaigns_here": [c["name"] for c in wins],
        "scoped_to": campaign,
        "segment_rows": bench.get("segment_rows", []),
        "date": ident["date"], "cov": ident["cov"], "grammar": ident["grammar"],
        "mods": ",".join(ident["mods"]) or "", "seq": ident["seq"],
        "test": ident["test"],
        "segments": bench["segments"],
        "fuzz_seconds": fuzz_s, "uptime_seconds": bench["uptime_seconds"],
        "execs": bench.get("exec_total", 0),
        "crashes": bench.get("crashes", 0),
        "blocks": blocks, "blocks_coverlog": blocks_log,
        "corpus_progs": bench.get("corpus") or None, "corpus_bytes": cbytes,
        "grammar_fp": gfp, "grammar_files": gfiles, "grammar_versions": gversions,
        "bugs": len(bugs), "bugs_verified": sum(1 for b in bugs if b["verified"]),
        "bugs_inferred": sum(1 for b in bugs if b["inferred"]),
        "bug_ids": ",".join(b["id"] for b in bugs if b["id"]),
        # A run whose manager died before its first bench tick left a 0-byte
        # series. That is "no measurement", not "measured zero", and the two must
        # never be averaged together -- a handful of dead runs would drag a
        # variant's mean to nothing and look like a real result.
        "has_data": bench["segments"] > 0,
        "ttfb_fuzz_seconds": bugs[0]["first_fuzz_s"] if bugs else None,
        "_bugs": bugs,
    }
    rec.update(config_facts(cid, item["config"] if item is not None else None))
    rec.update(quarantine_for(cid, item=item))

    if camp:
        rec["campaign"] = camp.get("name")
        if item is not None:
            # Per-item clocks: this sample's banked record, or the live counters
            # while it is the running item -- NOT the campaign-wide lifetime sum,
            # which would credit one sample with every sample's effort.
            clk = item_clocks(camp, item["item"])
            rec["prep_s"] = clk["prep_seconds"]
            rec["campaign_fuzz_s"] = clk["active_seconds"]
            rec["minimize_s"] = clk["triage_seconds"]
            rec["reboot_s"] = clk["overhead_seconds"]
        else:
            rec["prep_s"] = _lifetime(camp, "prep_seconds")
            rec["campaign_fuzz_s"] = _lifetime(camp, "active_seconds")
            rec["minimize_s"] = _lifetime(camp, "triage_seconds")
            rec["reboot_s"] = _lifetime(camp, "overhead_seconds")
    else:
        rec["campaign"] = None
        rec["campaign_fuzz_s"] = rec["minimize_s"] = rec["reboot_s"] = None
        rec["prep_s"] = None

    # --- rates, all per FUZZING hour, never per wall hour ---
    h = fuzz_s / 3600.0
    rec["fuzz_hours"] = h
    rec["exec_rate"] = (rec["execs"] / fuzz_s) if fuzz_s else None
    rec["blocks_per_h"] = (blocks / h) if h else None
    rec["execs_per_h"] = (rec["execs"] / h) if h else None
    rec["bugs_per_h"] = (rec["bugs"] / h) if h else None
    # What fraction of the campaign's effort went to explaining bugs rather than
    # finding them. High is not automatically bad -- it means bugs were found --
    # but it is the number that says why a run's coverage looks thin.
    mn, fz = rec["minimize_s"], rec["campaign_fuzz_s"]
    rec["minimize_ratio"] = (mn / (mn + fz)) if (mn is not None and fz) else None
    return rec


def collect_all(include_test=False, root=None):
    out = []
    for wd in discover_runs(root):
        rec = collect(wd)
        if rec["test"] and not include_test:
            continue
        out.append(rec)
    return out


# --- rendering ---------------------------------------------------------------
def _h(v):
    return "-" if v is None else "%.1f" % (v / 3600.0)


def _n(v, fmt="%.0f"):
    return "-" if v in (None, "") else fmt % v


def _int(v):
    return "-" if v in (None, "") else "{:,}".format(int(v))


def cmd_list(args):
    everything = collect_all(True)
    runs = collect_all(args.all)
    if args.driver:
        runs = [r for r in runs if r["driver"] == args.driver]
        everything = [r for r in everything if r["driver"] == args.driver]
    if not runs:
        if everything:
            print("no non-test runs under %s\n"
                  "  (%d run(s) are marked 'test'; pass --all to include them)"
                  % (WORKDIR_ROOT, len(everything)))
        else:
            print("no runs under %s" % WORKDIR_ROOT)
        return
    runs.sort(key=lambda r: (r["driver"], r["date"] or "", r["run"]))
    if not args.empty:
        runs = [r for r in runs if r["has_data"]]
    rows = []
    for r in runs:
        # Plan-layout runs carry their campaign; legacy runs show '-'.
        camp = r["campaign"] if r.get("layout") == "plan" else "-"
        if not r["has_data"]:
            rows.append((r["run"], camp or "-", r["cov"] or "-", r["grammar"] or "-",
                         "no data", "-", "-", "-", "-", "-", "-", 0))
            continue
        rows.append((r["run"], camp or "-", r["cov"] or "-", r["grammar"] or "-",
                     _h(r["fuzz_seconds"]), _int(r["execs"]), _n(r["exec_rate"]),
                     _int(r["blocks"]), _n(r["blocks_per_h"], "%.1f"),
                     r["bugs"] or 0, _h(r["ttfb_fuzz_seconds"]), r["segments"]))
    if not rows:
        print("no runs with data (use --empty to list runs that never ticked)")
        return
    tabulate(rows, ("RUN", "CAMPAIGN", "COV", "GRAMMAR", "FUZZ_H", "EXECS", "EX/s",
                    "BLOCKS", "BLK/H", "BUGS", "TTFB_H", "RESTARTS"))
    dead = sum(1 for r in collect_all(args.all) if not r["has_data"]
               and (not args.driver or r["driver"] == args.driver))
    print("\nFUZZ_H/TTFB_H are FUZZING hours, not wall clock. RESTARTS is how "
          "many\nmanager segments were folded together (exec counters reset on "
          "each).")
    if dead and not args.empty:
        print("%d run(s) hidden: their manager died before the first bench tick, "
              "so\nthey hold no measurement (--empty to show them)." % dead)


def cmd_show(args):
    wd = run_path(args.run) if "/" in args.run else None
    if wd is None or not wd.is_dir():
        cands = [r for r in discover_runs() if args.run in run_name(r)]
        if len(cands) != 1:
            print("no unique run matching %r (try: runstats.py list)" % args.run,
                  file=sys.stderr)
            sys.exit(1)
        wd = cands[0]
    r = collect(wd, getattr(args, "campaign", None))
    print("run          : %s%s"
          % (r["run"], "   [campaign %s]" % r["scoped_to"] if r["scoped_to"] else ""))
    print("  config     : %s  (%s enabled, %s benched)"
          % (r["config"], r.get("enabled", "?"), r.get("disabled", "?")))
    print("  axes       : cov=%s grammar=%s mods=%s"
          % (r["cov"], r["grammar"], r["mods"] or "-"))
    if r["grammar_versions"] > 1:
        print("  WARNING    : grammar changed %d times mid-run -- this run is a "
              "poor comparison subject" % r["grammar_versions"])
    print("  grammar    : %s (%d file(s))" % (r["grammar_fp"] or "-", r["grammar_files"]))
    print()
    if len(r["campaigns_here"]) > 1 and not r["scoped_to"]:
        print("  !! %d campaigns used this config, so the numbers below MIX them:"
              "\n     %s\n     Scope with --campaign <name>."
              % (len(r["campaigns_here"]), ", ".join(r["campaigns_here"])))
        print()
    if r["segment_rows"]:
        print("  segments   :")
        for sr in r["segment_rows"]:
            if sr.get("empty"):
                print("    %-30s %s  (no data: died before its first tick)"
                      % (sr["name"], timefmt.fmt_epoch(sr["start"], short=True)))
            else:
                print("    %-30s %s  %5.2f fuzz-h  %12s execs"
                      % (sr["name"], timefmt.fmt_epoch(sr["start"], short=True),
                         sr["fuzz_seconds"] / 3600.0, "{:,}".format(sr["execs"])))
        print()
    print("  fuzzing    : %s h  over %d manager restart(s)  [syz-manager's own "
          "counter: time executing programs]" % (_h(r["fuzz_seconds"]), r["segments"]))
    print("  uptime     : %s h  (manager alive, fuzzing or not)" % _h(r["uptime_seconds"]))
    if r["fuzz_seconds"] and r["uptime_seconds"]:
        print("  efficiency : %.0f%% of uptime was spent executing programs"
              % (100.0 * r["fuzz_seconds"] / r["uptime_seconds"]))
    if r["campaign"]:
        print("  campaign   : %s" % r["campaign"])
        print("    preparing: %s h  (startup, until the first exec)" % _h(r.get("prep_s")))
        print("    fuzzing  : %s h  (the campaign's fuzz clock -- first exec to end "
              "of run, NOT pure execution)" % _h(r["campaign_fuzz_s"]))
        print("    minimize : %s h  (%s of effort)"
              % (_h(r["minimize_s"]),
                 "-" if r["minimize_ratio"] is None else "%.0f%%" % (100 * r["minimize_ratio"])))
        print("    reboots  : %s h" % _h(r["reboot_s"]))
    print()
    print("  executed   : %s program(s)  (%s/sec)" % (_int(r["execs"]), _n(r["exec_rate"])))
    print("  coverage   : %s basic block(s)  (%s from cover.log)"
          % (_int(r["blocks"]), _int(r["blocks_coverlog"])))
    print("  corpus     : %s program(s), %s KB"
          % (_int(r["corpus_progs"]),
             "-" if r["corpus_bytes"] is None else "%.0f" % (r["corpus_bytes"] / 1024)))
    print("  blocks/h   : %s" % _n(r["blocks_per_h"], "%.1f"))
    print()
    print("  bugs       : %d (%d verified reproducer, %d attributed by time "
          "window)" % (r["bugs"], r["bugs_verified"], r["bugs_inferred"]))
    for b in r["_bugs"]:
        print("    - %-9s %-44s found after %s h of fuzzing%s%s"
              % (b["id"] or "?", b["key"] or "?", _h(b["first_fuzz_s"]),
                 "  [verified]" if b["verified"] else "",
                 "  [inferred]" if b["inferred"] else ""))
    print("  benched    : %d selector(s), %d signature(s) catalogued"
          % (r.get("benched", 0), r.get("catalogued", 0)))


AXES = {"grammar": "grammar", "cov": "cov", "driver": "driver", "kext": "driver",
        "config": "config"}


def _stats(vals):
    """n, mean, min, max and SAMPLE stddev for a metric over a config's samples.

    The sample (n-1) stddev, not population, because the samples are a draw from
    the runs this config COULD produce, not the whole of them -- the spread we
    report is an estimate of that variability. None below two samples, where a
    spread is undefined and a single number is an anecdote (see the note)."""
    vals = [v for v in vals if v is not None]
    n = len(vals)
    if n == 0:
        return {"n": 0, "mean": None, "min": None, "max": None, "sd": None}
    mean = sum(vals) / n
    sd = None
    if n >= 2:
        sd = (sum((v - mean) ** 2 for v in vals) / (n - 1)) ** 0.5
    return {"n": n, "mean": mean, "min": min(vals), "max": max(vals), "sd": sd}


def _cell(st, fmt="%.0f"):
    """mean (min..max ±sd) for a stats dict; mean alone for one sample; '-' for
    none. The spread is what makes 3 samples a measurement rather than a point."""
    if st["n"] == 0:
        return "-"
    mean = fmt % st["mean"]
    if st["n"] < 2:
        return mean
    rng = "%s..%s" % (fmt % st["min"], fmt % st["max"])
    sd = (" ±" + fmt % st["sd"]) if st["sd"] is not None else ""
    return "%s (%s%s)" % (mean, rng, sd)


def _compare_by_config(runs):
    """Group runs by authored config id and report mean ± spread over the
    config's samples -- the comparison §4 asks for: 3 repeats of one config give
    a mean with a spread directly, instead of one run's number read as fact."""
    skipped = sum(1 for r in runs if not r["has_data"])
    runs = [r for r in runs if r["has_data"]]
    groups = {}
    for r in runs:
        groups.setdefault(r["config"] or "(unset)", []).append(r)
    if not groups:
        print("nothing to compare")
        return
    rows = []
    for name, rs in sorted(groups.items()):
        rows.append((
            name, len(rs),
            _cell(_stats([r["blocks"] for r in rs]), "%.0f"),
            _cell(_stats([r["blocks_per_h"] for r in rs]), "%.1f"),
            _cell(_stats([r["execs"] for r in rs]), "%.0f"),
            _cell(_stats([r["exec_rate"] for r in rs]), "%.1f"),
            _cell(_stats([r["bugs"] for r in rs]), "%.1f"),
        ))
    tabulate(rows, ("CONFIG", "N", "BLOCKS", "BLK/H", "EXECS", "EX/s", "BUGS"))
    print("\nEach cell is mean (min..max ±sample sd) over the config's "
          "samples; the\nsd appears only with 2+ samples. BLOCKS are a per-run "
          "maximum, never\nsummed: repeat samples of one target rediscover the "
          "same blocks.")
    if skipped:
        print("%d run(s) excluded: no bench data, which is not the same as a "
              "measured zero." % skipped)
    thin = [n for n, rs in groups.items() if len(rs) < 2]
    if thin:
        print("Note: %s has a single run, so its numbers are an anecdote, not a "
              "measurement." % ", ".join(sorted(thin)))


def cmd_compare(args):
    runs = collect_all(args.all)
    if args.driver:
        runs = [r for r in runs if r["driver"] == args.driver]
    if args.by == "config":
        return _compare_by_config(runs)
    key = AXES[args.by]
    skipped = sum(1 for r in runs if not r["has_data"])
    runs = [r for r in runs if r["has_data"]]
    groups = {}
    for r in runs:
        groups.setdefault(r[key] or "(unset)", []).append(r)
    if not groups:
        print("nothing to compare")
        return
    rows = []
    for name, rs in sorted(groups.items()):
        fuzz = sum(r["fuzz_seconds"] for r in rs)
        execs = sum(r["execs"] for r in rs)
        bugs = sum(r["bugs"] for r in rs)
        h = fuzz / 3600.0
        # Blocks are a per-run maximum, not a sum: two runs of the same target
        # rediscover the same blocks, so adding them would be meaningless. The
        # mean is what "how much does this variant reach" means.
        blocks = [r["blocks"] for r in rs if r["blocks"]]
        ttfb = [r["ttfb_fuzz_seconds"] for r in rs if r["ttfb_fuzz_seconds"]]
        mexec = execs / 1e6
        # Per-run yield normalised by that run's own effort, then averaged. NOT
        # mean(blocks)/total(hours): a variant whose runs were left going longer
        # would otherwise look worse purely for having been given more time.
        per_h = [r["blocks"] / (r["fuzz_seconds"] / 3600.0)
                 for r in rs if r["blocks"] and r["fuzz_seconds"]]
        per_me = [r["blocks"] / (r["execs"] / 1e6)
                  for r in rs if r["blocks"] and r["execs"]]
        rows.append((name, len(rs), "%.1f" % h, _int(execs),
                     _n(execs / fuzz if fuzz else None),
                     _n(sum(blocks) / len(blocks) if blocks else None),
                     _n(max(blocks) if blocks else None),
                     _n(sum(per_h) / len(per_h) if per_h else None, "%.1f"),
                     _n(sum(per_me) / len(per_me) if per_me else None, "%.1f"),
                     bugs, _n(bugs / h if h else None, "%.2f"),
                     _n(bugs / mexec if mexec else None, "%.2f"),
                     _h(sum(ttfb) / len(ttfb) if ttfb else None)))
    tabulate(rows, (args.by.upper(), "RUNS", "FUZZ_H", "EXECS", "EX/s",
                    "BLK_MEAN", "BLK_MAX", "BLK/H", "BLK/Me", "BUGS",
                    "BUGS/H", "BUGS/Me", "TTFB_H"))
    print("\nBLOCKS are averaged, never summed: repeat runs of one target "
          "rediscover\nthe same blocks. /H is per FUZZING hour, /Me is per "
          "million executions --\nthe second is the fairer one when exec rates "
          "differ between variants.")
    # The comparison only means something WITHIN one target. Averaging a 844-block
    # driver against a 0-block one measures which drivers were fuzzed, not which
    # grammar works -- and the resulting table looks perfectly reasonable.
    if key != "driver":
        spans = {n: sorted({r["driver"] for r in rs}) for n, rs in groups.items()}
        wide = {n: d for n, d in spans.items() if len(d) > 1}
        if wide:
            print()
            print("!! These groups span multiple drivers, so the averages above "
                  "compare\n   targets, not %s:" % args.by)
            for n, d in sorted(wide.items()):
                print("     %-10s %s" % (n, ", ".join(d)))
            print("   Re-run with --driver <kext> for a comparison that means "
                  "something.")
            usable = [dv for dv in {r["driver"] for r in runs}
                      if len({r[key] for r in runs if r["driver"] == dv}) > 1]
            if usable:
                print("   Drivers with more than one %s to compare: %s"
                      % (args.by, ", ".join(sorted(usable))))
    if skipped:
        print("%d run(s) excluded: no bench data, which is not the same as a "
              "measured zero." % skipped)
    thin = [n for n, rs in groups.items() if len(rs) < 2]
    if thin:
        print("Note: %s has a single run, so its numbers are an anecdote, not a "
              "measurement." % ", ".join(sorted(thin)))


def progress_series(workdir):
    """The campaign driver's samples (results/progress.jsonl): one per poll,
    with the config's fuzzing clock, programs and blocks over all runs. The
    only time axis for blocks, since the cover log carries none."""
    out = []
    try:
        for ln in (Path(workdir) / "results" / "progress.jsonl").read_text().splitlines():
            try:
                out.append(json.loads(ln))
            except ValueError:
                continue
    except OSError:
        pass
    return out


def curve_rows(workdir, field):
    """[(fuzz_seconds, value, wall_epoch)] for `field`: 'blocks' and 'exec'
    from the sampled series; anything else from the bench series, where a
    resetting counter (exec total...) is accumulated across restarts instead
    of falling back to zero at each one."""
    if field in ("blocks", "exec"):
        return [(x["fuzz_s"], x[field], x["at"]) for x in progress_series(workdir)
                if x.get(field) is not None]
    rows, base, prev = [], 0, None
    for fuzz_ns, wall, sample in merge_bench(workdir)["series"]:
        v = sample.get(field)
        if v is None:
            continue
        if field in RESETTING:
            if prev is not None and v < prev:      # a new manager: counter restarted
                base += prev
            prev = v
            v += base
        rows.append((fuzz_ns / 1e9, v, wall))
    return rows


def cmd_curve(args):
    wd = run_path(args.run)
    if not wd.is_dir():
        print("no such run: %s" % args.run, file=sys.stderr)
        sys.exit(1)
    field = args.field
    print("fuzz_hours\t%s\twall" % field)
    for fuzz_s, v, wall in curve_rows(wd, field):
        print("%.4f\t%s\t%s" % (fuzz_s / 3600.0, v, timefmt.fmt_epoch(wall)))


CSV_FIELDS = ("run", "driver", "date", "cov", "grammar", "mods", "segments",
              "fuzz_seconds", "uptime_seconds", "execs", "exec_rate", "blocks",
              "blocks_coverlog", "blocks_per_h", "corpus_progs", "bugs",
              "bugs_verified", "bug_ids", "ttfb_fuzz_seconds", "bugs_per_h",
              "campaign", "prep_s", "campaign_fuzz_s", "minimize_s", "reboot_s",
              "minimize_ratio", "enabled", "disabled", "benched",
              "grammar_fp", "grammar_versions")


def cmd_export(args):
    runs = collect_all(args.all)
    runs.sort(key=lambda r: (r["driver"], r["date"] or "", r["run"]))
    if args.format == "json":
        json.dump([{k: v for k, v in r.items() if not k.startswith("_")}
                   for r in runs], sys.stdout, indent=2, default=str)
        print()
        return
    import csv
    w = csv.DictWriter(sys.stdout, fieldnames=CSV_FIELDS, extrasaction="ignore")
    w.writeheader()
    for r in runs:
        w.writerow(r)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", help="tree to read (default: this checkout; the "
                                   "published tree is /Users/Shared/fuzz-run)")
    sub = ap.add_subparsers(dest="cmd")

    def common(p):
        p.add_argument("--all", action="store_true",
                       help="include configs marked 'test' (excluded by default: "
                            "they are scratch experiments)")
        p.add_argument("--driver", help="restrict to one kext")
        p.add_argument("--empty", action="store_true",
                       help="also show runs that produced no bench data at all")
        return p

    common(sub.add_parser("list", help="one row per run")).set_defaults(func=cmd_list)

    p = sub.add_parser("show", help="everything known about one run")
    p.add_argument("run", help="<Driver>/<variant> or <campaign>/<config-id>/"
                               "<item-id>, or a unique substring")
    p.add_argument("--campaign", help="scope to one campaign's segments; without "
                                      "it, every campaign that used this config "
                                      "is folded together")
    p.set_defaults(func=cmd_show)

    p = common(sub.add_parser("compare", help="group runs and aggregate"))
    p.add_argument("--by", choices=sorted(AXES), default="grammar",
                   help="grouping axis; 'config' reports mean +/- spread over a "
                        "config's repeated samples")
    p.set_defaults(func=cmd_compare)

    p = sub.add_parser("curve", help="a metric against fuzzing hours (TSV)")
    p.add_argument("run")
    p.add_argument("--field", default="coverage",
                   help="what to plot: blocks or exec (the driver's sampled series, "
                        "exact across restarts), or a bench field (default coverage; "
                        "try corpus, exec total, signal -- resetting counters are "
                        "accumulated across restarts)")
    p.set_defaults(func=cmd_curve)

    p = common(sub.add_parser("export", help="the full table for a notebook"))
    p.add_argument("--format", choices=("csv", "json"), default="csv")
    p.set_defaults(func=cmd_export)

    args = ap.parse_args()
    if args.root:
        set_root(args.root)
    if not getattr(args, "func", None):
        ap.print_help()
        sys.exit(2)
    args.func(args)


if __name__ == "__main__":
    main()
