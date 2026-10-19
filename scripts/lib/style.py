#!/usr/bin/env python3
"""Terminal colouring shared by the campaign and session status views.

One instance, decided once at import: colour goes to a real tty and nowhere
else, so a status piped into grep or a log stays plain text. Honours the
NO_COLOR convention and TERM=dumb.
"""

import os
import sys


class _Style:
    """ANSI colouring that switches itself off when output is not a terminal."""
    CODES = {"red": "31", "green": "32", "yellow": "33",
             "cyan": "36", "grey": "90", "bold": "1"}

    def __init__(self, enabled):
        self.enabled = enabled

    def __call__(self, text, *names):
        if not self.enabled or not names:
            return text
        return "\033[%sm%s\033[0m" % (";".join(self.CODES[n] for n in names), text)


style = _Style(
    os.environ.get("NO_COLOR") is None
    and os.environ.get("TERM") != "dumb"
    and hasattr(sys.stdout, "isatty") and sys.stdout.isatty())

# Tick/cross read better than ASCII, but a non-UTF-8 stdout would raise on
# print, so fall back rather than risk crashing a listing over decoration.
if (getattr(sys.stdout, "encoding", "") or "").lower().replace("-", "") == "utf8":
    GLYPH = {"ok": "✓", "error": "✗", "warn": "!", "note": "·"}
else:
    GLYPH = {"ok": "*", "error": "x", "warn": "!", "note": "-"}
