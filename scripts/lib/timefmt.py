#!/usr/bin/env python3
"""One clock for every tool in the pipeline.

There were two, and they disagreed. now_iso() stamped UTC with a Z suffix while
directory stamps used local time, so a single event appeared in the log as
15:41:48Z and on disk as 20260831-174148 -- a two-hour gap between two records of
the same moment, in Paris summer time. Correlating a panic report against a
campaign log meant doing the arithmetic in your head, every time.

The rule here:

  - STORED timestamps are ISO 8601 **with a real UTC offset**
    (2026-09-01T11:42:03+02:00). Machine-readable, unambiguous across DST, and
    already local -- so a state file reads the way your wall clock does. A bare
    "Z" was neither: it looked precise and read as the wrong hour.
  - DISPLAYED timestamps use the local convention: 01/09/2026 11:42:03.
    Day first, as everywhere outside the US.
  - PARSING is tolerant. State files, registries and dossiers written before
    this change carry the Z form, and they must keep resolving to the same
    instant rather than silently shifting by the offset.

Sorting: never sort these as strings. Rows carrying mixed Z and +02:00 forms
compare wrong lexically. Sort on to_epoch() instead.
"""

from datetime import datetime, timezone

# Stored form. %z renders as "+0200", which we reshape to "+02:00" so the string
# is valid ISO 8601 for any consumer, including datetime.fromisoformat.
_STORE = "%Y-%m-%dT%H:%M:%S%z"

# Display forms, French convention: day/month/year.
_SHOW = "%d/%m/%Y %H:%M:%S"
_SHOW_SHORT = "%d/%m %H:%M:%S"


def _colon_offset(text):
    """+0200 -> +02:00, so what we store is ISO 8601 rather than merely close."""
    if len(text) >= 5 and text[-5] in "+-" and text[-3] != ":":
        return text[:-2] + ":" + text[-2:]
    return text


def now():
    """Timezone-aware 'now' in the machine's local zone."""
    return datetime.now().astimezone()


def now_iso():
    """The stored form: local time carrying its offset."""
    return _colon_offset(now().strftime(_STORE))


def now_ts():
    """Compact local stamp for directory names: 20260901-114203.

    Local on purpose, and now provably the same clock as now_iso() -- these two
    disagreeing is the bug this module exists to prevent.
    """
    return now().strftime("%Y%m%d-%H%M%S")


def parse_iso(text):
    """Parse any timestamp this project has ever written; None if unparseable.

    Handles the current offset form, the legacy UTC 'Z' form, and a naive string
    with no zone at all (read as local, which is what it meant when written).
    """
    if not text:
        return None
    s = str(text).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y%m%d-%H%M%S"):
            try:
                dt = datetime.strptime(s, fmt)
                break
            except ValueError:
                continue
        else:
            return None
    # A naive value predates the offset form and was written in local time.
    return dt.astimezone() if dt.tzinfo is None else dt


def to_epoch(text):
    """Seconds since the epoch, or None. Use this to sort or subtract."""
    dt = parse_iso(text)
    return dt.timestamp() if dt else None


def fmt(text, short=False, default="-"):
    """Render a stored timestamp for a human: 01/09/2026 11:42:03."""
    dt = parse_iso(text)
    if not dt:
        return default
    return dt.astimezone().strftime(_SHOW_SHORT if short else _SHOW)


def fmt_epoch(epoch, short=False, default="-"):
    if not epoch:
        return default
    return datetime.fromtimestamp(epoch).strftime(_SHOW_SHORT if short else _SHOW)


def stamp(short=True):
    """'Now', formatted for a log line prefix."""
    return now().strftime(_SHOW_SHORT if short else _SHOW)
