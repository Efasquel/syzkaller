#!/usr/bin/env python3
"""Filesystem helpers shared by the session, campaign and bug-registry tools.

The one thing here worth explaining is why hardlinks: a panic report is evidence
that three different consumers want (the run's snapshot, the crash bundle, the
bug dossier). Copying it into each triples ~1.5MB per report. Referencing it from
each leaves every consumer pointing into /Library/Logs/DiagnosticReports, which
macOS rotates on its own schedule -- so the citation rots without anyone deleting
anything deliberately.

A hardlink is a second name for the same inode, with no owner: the data lives
until the last name is unlinked. So each consumer holds a real, openable file,
the extra names cost no blocks, and pruning any one location cannot break the
others.

The exception is anything you actually want reclaimed -- kernel cores are ~220MB
and exist to be deleted by a prune. A link there would keep the blocks alive
while the prune reported success, so cores are referenced by path, never linked.
"""

import os
import shutil
from pathlib import Path


def hardlink_or_copy(src, dst):
    """Link src to dst; fall back to a copy across volumes or on any refusal.

    Returns True if a link was made, False if it fell back to a copy (or dst
    already existed). The fallback is deliberate: an archive tree may live on
    another filesystem, and a bundle that silently failed to capture its evidence
    would be worse than a duplicated one.
    """
    src, dst = Path(src), Path(dst)
    if dst.exists():
        return False
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.link(src, dst)
        return True
    except OSError:
        shutil.copy2(src, dst)
        return False


def link_count(path):
    """How many names refer to this file -- a free refcount of the contexts
    citing a piece of evidence."""
    try:
        return os.stat(path).st_nlink
    except OSError:
        return 0
