#!/usr/bin/env python3
"""Operator verbs (next, skip, unskip, halt) as REQUESTS, not direct edits.

The campaign runner is the one writer of its state file. If the CLI also wrote
state directly, two hands would be editing the same file and a verb issued while
the runner was mid-poll could be lost or half-applied. So instead a verb is
*appended* here, to an ordered JSON list, and the runner drains it at its next
poll (every stop_check_seconds) and applies the requests in order. One writer of
state, a queue in front of it.

Ordering matters to the operator: `skip B` then `next` within a single poll must
both land, in that order, so the runner skips B and then ends the current item.
That is why this is an append-only list and not a last-writer-wins field.

Two concerns, two mechanisms:

  - A concurrent READER (the runner calling pending()) must never see a
    half-written file. We write a temp file in the same directory and os.replace
    it, so the reader sees either the old list or the new one, never a splice of
    both. A list that still comes back torn -- a crash between create and replace,
    say -- is treated as empty rather than as an error: a damaged request file
    must not be able to stop the runner, and the next append repairs it.

  - Two concurrent WRITERS (two CLI invocations appending at once) could both
    read the list, both append, and both replace -- losing one record. We take an
    advisory lock (fcntl.flock) for the whole read-modify-write. The lock lives
    on a sibling ".lock" file rather than on the JSON itself: the JSON is
    replaced out from under any open handle by os.replace, so a lock held on it
    would protect the wrong inode. The sidecar is never replaced, so the lock is
    stable. flock is advisory and local to one host, which is all we need -- every
    writer is a process on the same box.
"""

import fcntl
import json
import os
import tempfile
import time


def _lock_path(path):
    """The sibling lock file for path -- a stable inode to flock, since the JSON
    itself is replaced (and so re-inoded) on every write."""
    return str(path) + ".lock"


class _locked:
    """Hold an exclusive advisory lock across a read-modify-write of path.

    The lock file is created if missing and left in place afterwards; it carries
    no data, it only exists to be flock()ed.
    """

    def __init__(self, path):
        self._lockfile = _lock_path(path)
        os.makedirs(os.path.dirname(os.path.abspath(self._lockfile)), exist_ok=True)
        self._fd = None

    def __enter__(self):
        self._fd = os.open(self._lockfile, os.O_RDWR | os.O_CREAT, 0o644)
        fcntl.flock(self._fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        # Releasing the lock and closing the handle are the same event here;
        # flock is released implicitly on close, we do both to be explicit.
        fcntl.flock(self._fd, fcntl.LOCK_UN)
        os.close(self._fd)
        self._fd = None


def _read(path):
    """The list on disk, or [] for anything we can't make sense of.

    Missing file, unreadable file, non-JSON, or valid JSON that isn't a list all
    collapse to [] -- see the module docstring: a bad request file must not stop
    the runner.
    """
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []
    return data if isinstance(data, list) else []


def _write_atomic(path, records):
    """Replace path with records as a JSON list, atomically for any reader.

    The temp file is created in the same directory so os.replace is a rename
    within one filesystem (atomic) rather than a cross-device copy.
    """
    path = str(path)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)),
                               prefix=".requests-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(records, f, indent=2)
            f.write("\n")
        os.replace(tmp, path)
    except BaseException:
        # Leave no partial temp file behind on failure.
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def append(path, verb, item=None, now=None):
    """Append {"verb": verb, "item": item, "at": <epoch seconds>} to path.

    `at` is the given `now` when provided, else time.time(). Creates the file
    (and parent dirs) if missing, and repairs a corrupt one by starting from an
    empty list. The whole read-append-write runs under the advisory lock so two
    simultaneous appends can't lose a record. Returns the appended record.
    """
    record = {"verb": verb, "item": item,
              "at": time.time() if now is None else now}
    with _locked(path):
        records = _read(path)
        records.append(record)
        _write_atomic(path, records)
    return record


def pending(path):
    """The pending requests, oldest first; [] when missing, unreadable or torn.

    No lock: a reader only needs the atomicity of os.replace, which guarantees it
    sees one whole list or another, never a splice.
    """
    return _read(path)


def take(path):
    """Return the pending requests and clear the file -- the runner's once-a-poll
    drain. Clearing is the same atomic replace, under the same lock as append so
    a drain and an append can't interleave and drop a record. [] when empty.
    """
    with _locked(path):
        records = _read(path)
        if records:
            _write_atomic(path, [])
    return records


def describe(requests):
    """One short line for status displays: 'next, skip AppleSMC_gram-2'.

    Each request becomes its verb, plus a space and the item when it has one,
    comma-separated and oldest first. '' for an empty list.
    """
    parts = []
    for r in requests:
        verb = r.get("verb", "")
        item = r.get("item")
        parts.append(f"{verb} {item}" if item else verb)
    return ", ".join(parts)
