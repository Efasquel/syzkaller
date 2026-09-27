#!/usr/bin/env python3
"""Column formatting shared by the campaign, triage and bug-registry listings.

Every one of those tools printed its table with hand-tuned "%-24s" widths, and
every one of them eventually met a name longer than its column -- at which point
the row silently runs into the next field and the listing becomes unreadable
exactly when you have the most campaigns to look at. Measuring the content costs
a few lines and cannot go stale.
"""

from __future__ import print_function


def render(rows, headers, gap=2):
    """Return the table as a list of lines, columns sized to their contents."""
    ncols = len(headers)
    width = [len(str(h)) for h in headers]
    for r in rows:
        for i in range(ncols):
            width[i] = max(width[i], len(str(r[i])))
    sep = " " * gap

    def line(vals):
        # The last column is never padded: trailing whitespace on every line
        # makes copy-paste, diffs and terminal wrapping worse for no gain.
        return sep.join(str(v).ljust(width[i]) if i < ncols - 1 else str(v)
                        for i, v in enumerate(vals))

    return [line(headers)] + [line(r) for r in rows]


def tabulate(rows, headers, gap=2):
    for ln in render(rows, headers, gap):
        print(ln)
