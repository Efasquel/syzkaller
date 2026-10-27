#!/usr/bin/env python3
"""The box's campaign queue, campaigns/queue.json (campaign-planning.md §7).

One box runs one campaign at a time -- a panic reboots everything -- so the box,
not each campaign, owns the launchd agent, and that agent runs the campaigns
listed here in order. The head of `queue` is the campaign the box is on (or is
about to start); when it ends it moves to `history` with how it ended, and the
next one starts without anybody logging in.

    {"queue":   ["fde_eval", "bt_sweep"],
     "history": [{"name": "smoke", "ended": "...", "status": "done", "reason": null}]}

Every change is a read-modify-write under the same advisory lock and atomic
replace as the operator's request list (lib/requests), for the same reasons: a
`queue add` from the shell can land while the runner is moving a campaign to
history, and neither may lose the other's change. A file that cannot be read is
an empty queue rather than an error, so a damaged queue never wedges the box --
the next change rewrites it whole.
"""

import json

# Same lock and atomic write as the request list; _write_atomic takes any JSON.
from lib.requests import _locked, _write_atomic


def _read_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _empty():
    return {"queue": [], "history": []}


def _load_unlocked(path):
    data = _read_json(path)
    if not isinstance(data, dict):
        return _empty()
    queue = data.get("queue")
    history = data.get("history")
    return {"queue": [n for n in queue if isinstance(n, str)] if isinstance(queue, list) else [],
            "history": [h for h in history if isinstance(h, dict)] if isinstance(history, list) else []}


def load(path):
    """The queue as {"queue": [names], "history": [records]}; empty when missing
    or unreadable. No lock: os.replace guarantees a whole file."""
    return _load_unlocked(path)


def head(path):
    """The campaign the box is on, or None when the queue is empty."""
    q = load(path)["queue"]
    return q[0] if q else None


def _change(path, fn):
    with _locked(path):
        q = _load_unlocked(path)
        out = fn(q)
        _write_atomic(path, q)
    return out


def add(path, name, at=None):
    """Queue `name` at position `at` (0 is the head; None appends). A name
    already queued is not queued twice: ValueError, so the operator learns it
    is already there rather than running it twice."""
    def fn(q):
        if name in q["queue"]:
            raise ValueError("%s is already queued (position %d)"
                             % (name, q["queue"].index(name)))
        pos = len(q["queue"]) if at is None else max(0, min(int(at), len(q["queue"])))
        q["queue"].insert(pos, name)
        return pos
    return _change(path, fn)


def remove(path, name):
    """Take `name` out of the queue; False when it was not queued."""
    def fn(q):
        if name not in q["queue"]:
            return False
        q["queue"].remove(name)
        return True
    return _change(path, fn)


def move(path, name, at):
    """Move a queued `name` to position `at`; ValueError when not queued."""
    def fn(q):
        if name not in q["queue"]:
            raise ValueError("%s is not queued" % name)
        q["queue"].remove(name)
        pos = max(0, min(int(at), len(q["queue"])))
        q["queue"].insert(pos, name)
        return pos
    return _change(path, fn)


def finish(path, name, status, reason, ended):
    """`name` ended: take it out of the queue and record how in history."""
    def fn(q):
        if name in q["queue"]:
            q["queue"].remove(name)
        q["history"].append({"name": name, "ended": ended, "status": status,
                             "reason": reason})
    return _change(path, fn)
