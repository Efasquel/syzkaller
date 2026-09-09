#!/usr/bin/env python3
"""Reading a syzkaller manager config the way syz-manager itself reads it.

syz-manager strips whole-line '#' comments and nothing else, in
pkg/config/config.go (LoadData):

    data = regexp.MustCompile(`(^|\n)\s*#[^\n]*`).ReplaceAll(data, nil)

The campaign configs use those comments to record what an experiment excluded --
see config/IOAVBFamily_260709_*-no23.cfg, where the commented-out entries ARE the
'-no23' in the name. So every tool here has to understand them.

Matching the Go rule exactly, rather than being merely permissive, is the point.
A looser reader (trailing '#' comments, '//', '/* */') accepts configs that
syz-manager will then reject at launch, so the mistake surfaces as a campaign
that will not start rather than as a lint failure. Being stricter than the Go
rule is just as bad in the other direction: it makes an annotated config read as
having no enable_syscalls, which silently turns off --seq validation.

A '#' can only begin a line in valid JSON if it opens a comment -- no JSON token
starts with '#' -- so the line-anchored rule never eats string content, and this
needs no string-aware scanner to be safe.
"""

import json
import re
from pathlib import Path

_COMMENT_RE = re.compile(r"(^|\n)\s*#[^\n]*")


def strip_comments(text):
    """Remove whole-line '#' comments, exactly as pkg/config does."""
    return _COMMENT_RE.sub("", text)


def load(path):
    """Parse a syzkaller manager config the way syz-manager does."""
    return json.loads(strip_comments(Path(path).read_text()))
