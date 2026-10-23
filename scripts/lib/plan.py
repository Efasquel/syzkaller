#!/usr/bin/env python3
"""Plans, and the effective config each of their items runs with.

A plan (plans/<name>.json, campaign-planning.md §3) is a list of items, each one
run of one hand-written config/<id>.cfg. The config holds the experiment: the
syscall lists, the kext under coverage, the ring buffer. Two other kinds of field
end up in the file syz-manager actually reads, and they have other owners:

  - BOX fields (target, syzkaller, http, procs ...) belong to the machine and
    live once in config/box.json, so the dev tree and the box differ only there;
  - RUNTIME fields (workdir, kext_coverage.cover_log) belong to the runner and
    are different for every item.

This module is where those three are put together:

    effective = box.json ⊕ config ⊕ runtime

and where a plan is turned from what the operator wrote into what the driver
runs: defaults filled, item ids derived, config paths resolved and checked. It
is pure over the dicts and paths it is handed. The only file reads are the two
loaders, `load_plan` and `load_box` (plus `cfgutil.load` for the configs that
`check_table` has to open to count their syscalls), so everything else can be
table-tested without a tree on disk, and the driver stays the one place that
decides *which* files to read.

Existing configs still carry box fields -- they were generated from a template
and left to diverge. Rendering lets them win over box.json and reports the
difference as drift, so every config keeps running unchanged while `plan check`
shows which ones to strip. A config that sets a runtime field is not rejected
either: the field is replaced and noted, because the runner must own it for the
grouped campaign tree to hold.
"""

import copy
import json
import re
from pathlib import Path

from lib import cfgutil, schedule

# The three ownerships of §3. Nested pairs are (parent, child) inside a
# one-level-deep object, which today is only kext_coverage.
BOX_KEYS = ("target", "syzkaller", "http", "procs", "type", "log_file",
            "kernel_obj", "kernel_obj_file", "sandbox", "reproduce")
BOX_NESTED = (("kext_coverage", "kcov_device"),)
RUNTIME_KEYS = ("workdir",)
RUNTIME_NESTED = (("kext_coverage", "cover_log"),)

# Campaign names and item ids are folder names and halves of the session id
# "<campaign>.<item-id>", which splits at its one dot only if neither half can
# contain one.
ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")

CLOCKS = ("wall", "fuzz", "real")

# What a plan means when it does not say. Kept as data so `plan check` and the
# driver cannot disagree about them.
DEFAULTS = {
    "max_hours": 6,
    "max_plateau_hours": None,
    "reuse_known_culprits": False,
}
LIMITS = {
    "max_crashes": 20,
    "min_free_gb": 20.0,
    "crashloop_limit": 15,
}
DEFAULT_CLOCK = "fuzz"

# The one runtime value that is not a path: the cover log always sits in the
# item's workdir under this name, so the per-run tools can find it.
COVER_LOG = "cover.log"


class PlanError(ValueError):
    """A plan that cannot run, with every reason at once.

    Fixing a plan one rejected field per attempt is slow when the box is an
    ssh hop away, so `normalize` collects everything it finds and raises once.
    The list is kept on `.problems` for a CLI that wants to print them itself;
    the message is the same list, one per line.
    """

    def __init__(self, problems):
        self.problems = list(problems)
        n = len(self.problems)
        head = "plan has %d problem%s:" % (n, "" if n == 1 else "s")
        super().__init__("\n".join([head] + ["  - " + p for p in self.problems]))


# --- loaders -------------------------------------------------------------------

def load_plan(path):
    """Read a plan file, allowing the whole-line '#' comments configs allow.

    Plans and configs are read by the same comment rule (cfgutil) so an operator
    does not have to remember two syntaxes. A parse failure says which file and
    where, because json's own message names neither.
    """
    path = Path(path)
    try:
        return json.loads(cfgutil.strip_comments(path.read_text()))
    except json.JSONDecodeError as e:
        raise ValueError("plan %s: bad JSON: %s" % (path, e)) from None


def load_box(path):
    """Read config/box.json, or {} when the machine has none yet.

    A missing box is a valid state -- every config still carrying its own box
    fields runs without one -- so it is not an error, only an empty overlay. A
    present but unreadable box IS an error: silently rendering without it would
    hide exactly the per-machine paths it exists to supply.
    """
    path = Path(path)
    if not path.exists():
        return {}
    try:
        return json.loads(cfgutil.strip_comments(path.read_text()))
    except json.JSONDecodeError as e:
        raise ValueError("box %s: bad JSON: %s" % (path, e)) from None


# --- normalizing a plan --------------------------------------------------------

def _is_number(v):
    """True for int/float, not bool: JSON `true` must not pass as hours."""
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _problem_hours(where, key, value, optional):
    """The problem with an hours value, or None when it is acceptable."""
    if value is None:
        return None if optional else "%s: %s is missing" % (where, key)
    if not _is_number(value) or value <= 0:
        return "%s: %s must be a positive number, got %r" % (where, key, value)
    return None


def normalize(plan, root):
    """Return a new plan with defaults filled, ids assigned and configs resolved.

    This is the one place the plan format's implicit parts become explicit, so
    that everything downstream (`plan_to_def`, `item_dir`, `check_table`) reads
    a complete plan and never defaults anything itself. Relative config paths
    are relative to `root`, the tree the plan lives in, and are made absolute
    here so the driver can hand them to syz-manager from any directory.

    Ids are derived with `schedule.item_ids` over the items that have none, so
    `<stem>-1, -2` numbering follows the order of the id-less items and never
    skips a number for an item that was named explicitly. An explicit id is
    validated like a campaign name and must be unique; a derived id colliding
    with an explicit one is reported as a duplicate like any other.

    Every problem found is reported together in one PlanError (a ValueError).
    The input plan is not mutated.
    """
    if not isinstance(plan, dict):
        raise PlanError(["plan must be a JSON object, got %s" % type(plan).__name__])
    root = Path(root)
    out = copy.deepcopy(plan)
    problems = []

    name = out.get("name")
    if name is None:
        problems.append("name is missing")
    elif not isinstance(name, str) or not ID_RE.match(name):
        problems.append("name %r: allowed characters are [A-Za-z0-9_-]" % (name,))

    clock = out.setdefault("clock", DEFAULT_CLOCK)
    if clock not in CLOCKS:
        problems.append("clock %r: one of %s" % (clock, ", ".join(CLOCKS)))

    defaults = out.setdefault("defaults", {})
    if not isinstance(defaults, dict):
        problems.append("defaults must be an object")
        defaults = out["defaults"] = {}
    for key, value in DEFAULTS.items():
        defaults.setdefault(key, value)
    for key, optional in (("max_hours", False), ("max_plateau_hours", True)):
        p = _problem_hours("defaults", key, defaults[key], optional)
        if p:
            problems.append(p)

    limits = out.setdefault("limits", {})
    if not isinstance(limits, dict):
        problems.append("limits must be an object")
        limits = out["limits"] = {}
    for key, value in LIMITS.items():
        limits.setdefault(key, value)

    items = out.get("items")
    if not isinstance(items, list) or not items:
        problems.append("items must be a non-empty list")
        items = out["items"] = []

    # Pass 1: configs and per-item hours, so every item is well-formed before
    # ids are derived from the config stems.
    for i, item in enumerate(items):
        where = "item %d" % (i + 1)
        if not isinstance(item, dict):
            problems.append("%s: must be an object" % where)
            continue
        config = item.get("config")
        if not isinstance(config, str) or not config:
            problems.append("%s: config is missing" % where)
        else:
            path = Path(config)
            if not path.is_absolute():
                path = root / path
            item["config"] = str(path)
            if not path.exists():
                problems.append("%s: config not found: %s" % (where, path))
        item.setdefault("max_hours", defaults["max_hours"])
        item.setdefault("max_plateau_hours", defaults["max_plateau_hours"])
        for key, optional in (("max_hours", False), ("max_plateau_hours", True)):
            p = _problem_hours(where, key, item[key], optional)
            if p:
                problems.append(p)

    # Pass 2: ids. Derived ones number only the id-less items, in order.
    unnamed = [it for it in items if isinstance(it, dict) and not it.get("id")
               and isinstance(it.get("config"), str) and it["config"]]
    derived = schedule.item_ids([it["config"] for it in unnamed])
    for item, iid in zip(unnamed, derived):
        item["id"] = iid
    seen = set()
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        iid = item.get("id")
        if iid is None:
            # No config either; already reported above, nothing to name it by.
            continue
        if not isinstance(iid, str) or not ID_RE.match(iid):
            problems.append("item %d: id %r: allowed characters are [A-Za-z0-9_-]"
                            % (i + 1, iid))
            continue
        if iid in seen:
            problems.append("duplicate item id %r" % iid)
        seen.add(iid)

    if problems:
        raise PlanError(problems)
    return out


# --- names and places ----------------------------------------------------------

def item_dir(root, campaign, item):
    """Where one sample lives: root/campaigns/<campaign>/<config-stem>/<item-id>.

    Grouping by config stem is what makes `ls <config-stem>/` show a config's
    samples side by side, which is the comparison an evaluation makes (§4).
    """
    return Path(root) / "campaigns" / campaign / Path(item["config"]).stem / item["id"]


def session_id(campaign, item_id):
    """The fuzz-session id of one item, "<campaign>.<item-id>".

    Both halves are [A-Za-z0-9_-], so the id splits at its one dot and items
    from different campaigns never collide in sessions/.
    """
    return "%s.%s" % (campaign, item_id)


def effective_name(campaign, item_id):
    """The rendered config's file name: the session id plus '.cfg'.

    fuzz-session.py derives its session id from the config's stem, so naming the
    file after the session id is what ties the two together.
    """
    return session_id(campaign, item_id) + ".cfg"


# --- rendering -----------------------------------------------------------------

def _show(value):
    """A value as it reads in the file, so a drift note matches what grep finds."""
    return json.dumps(value, sort_keys=True)


def _drift_pairs(cfg, box):
    """(key, cfg value, box value) for every box field the config overrides.

    Only a field present in BOTH with different values is drift: a config that
    carries a box field the box does not know has nothing to be compared with,
    and an equal value is harmless redundancy that `config lint --strip-box`
    removes without changing anything.
    """
    pairs = []
    for key in BOX_KEYS:
        if key in cfg and key in box and cfg[key] != box[key]:
            pairs.append((key, cfg[key], box[key]))
    for parent, child in BOX_NESTED:
        c = cfg.get(parent) or {}
        b = box.get(parent) or {}
        if isinstance(c, dict) and isinstance(b, dict) \
                and child in c and child in b and c[child] != b[child]:
            pairs.append(("%s.%s" % (parent, child), c[child], b[child]))
    return pairs


def _drift_text(key, cfg_value, box_value):
    return "%s: config says %s, box.json says %s" % (key, _show(cfg_value), _show(box_value))


def render(cfg, box, workdir, benched=()):
    """The effective config for one item, and notes on what rendering decided.

    effective = box ⊕ cfg ⊕ runtime, with:

      - the config winning over the box wherever both set a box field, so a
        config that still carries its own paths runs exactly as authored. The
        difference is noted as drift, not corrected, because correcting it
        silently would make the rendered file disagree with the tracked one;
      - kext_coverage merged one level deep, so kext_id can come from the
        config and kcov_device from the box;
      - the runtime fields set by the runner no matter what the config says:
        workdir is this item's, cover.log sits in it. A config that set one is
        noted so `plan check` can show the authored value being ignored;
      - disable_syscalls the union of the authored list and `benched`, the
        quarantine's additions, sorted. The authored exclusions are what the
        experiment meant; benching adds to them and never replaces them.

    Neither `cfg` nor `box` is touched; the result shares no structure with
    either.
    """
    effective = copy.deepcopy(box)
    notes = []

    for key, cfg_value, box_value in _drift_pairs(cfg, box):
        notes.append("drift: " + _drift_text(key, cfg_value, box_value))

    for key, value in cfg.items():
        if key == "kext_coverage" and isinstance(value, dict) \
                and isinstance(effective.get(key), dict):
            effective[key].update(copy.deepcopy(value))
        else:
            effective[key] = copy.deepcopy(value)

    for key in RUNTIME_KEYS:
        if key in cfg:
            notes.append("ignored: %s (rendered per item)" % key)
    for parent, child in RUNTIME_NESTED:
        if isinstance(cfg.get(parent), dict) and child in cfg[parent]:
            notes.append("ignored: %s.%s (rendered per item)" % (parent, child))

    effective["workdir"] = str(workdir)
    # Only a config that uses kext coverage gets a cover log: inventing the
    # object for one that does not would switch the feature on.
    if isinstance(effective.get("kext_coverage"), dict):
        effective["kext_coverage"]["cover_log"] = COVER_LOG

    authored = cfg.get("disable_syscalls") or []
    effective["disable_syscalls"] = sorted(set(authored) | set(benched))
    return effective, notes


def drift(cfg, box):
    """Just the drift notes `render` would make, for `plan check`."""
    return ["drift: " + _drift_text(*pair) for pair in _drift_pairs(cfg, box)]


# --- for the driver and for `plan check` ----------------------------------------

def plan_to_def(plan):
    """The driver's definition dict from a normalized plan.

    The driver's breaker and budget code reads a flat dict (`d["max_crashes"]`,
    `d["budget_clock"]`, `item["budget_seconds"]`) and the plan format nests
    the same values under defaults/limits in hours. This is the adapter, so
    that code reads a plan without changing. `loop` is always False (a hunt is
    a long max_hours or the plan queued again) and `watch_window` always True.
    """
    defaults = plan["defaults"]
    d = {
        "name": plan["name"],
        "items": [
            {
                "id": item["id"],
                "config": item["config"],
                "budget_seconds": float(item["max_hours"]) * 3600,
                "max_plateau_hours": item["max_plateau_hours"],
            }
            for item in plan["items"]
        ],
        "budget_clock": plan["clock"],
        "loop": False,
        "watch_window": True,
        "reuse_known_culprits": defaults["reuse_known_culprits"],
        "max_hours": defaults["max_hours"],
        "max_plateau_hours": defaults["max_plateau_hours"],
    }
    d.update(plan["limits"])
    return d


def _hours_text(hours):
    """6 rather than 6.0 in a table column, 1.5 when it is not whole."""
    if _is_number(hours) and float(hours).is_integer():
        return str(int(hours))
    return str(hours)


def _relative(path, root):
    """The path as the plan would write it: relative to root when under it."""
    path, root = Path(path), Path(root)
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def check_table(plan, box, root):
    """Rows for `plan check`: [id, config, max_hours, n_enable_syscalls, drift].

    One row per item of a normalized plan. The syscall count comes from the
    config itself, read as syz-manager reads it, so an annotated config that
    lints as empty shows up here as 0. The drift column lists every box field
    the config overrides, or '-' when it is clean.
    """
    rows = []
    for item in plan["items"]:
        cfg = cfgutil.load(item["config"])
        pairs = _drift_pairs(cfg, box)
        rows.append([
            item["id"],
            _relative(item["config"], root),
            _hours_text(item["max_hours"]),
            str(len(cfg.get("enable_syscalls") or [])),
            "; ".join(_drift_text(*p) for p in pairs) if pairs else "-",
        ])
    return rows
