---
name: kernel-bug-triage
description: Turning a macOS kernel panic from the fuzzer into a reportable bug - fingerprinting and deduplicating panics, filing them in the bug registry, minimizing to a verified reproducer, reading what the quarantine decided, and writing the dossier for disclosure to Apple. Use when a panic needs analyzing, a crash needs attributing to a bug, a triage job needs interpreting (DONE vs STUCK), or a bug is being written up.
---

# From panic to reportable bug

Panic reports land in two places, and both matter:

- `/Library/Logs/DiagnosticReports` — `*.panic`, `*.ips` (the text report)
- `/private/var/tmp/kernel_panics` — `*.kernel.core.gz` (~220MB cores)

The three tools that speak about a crash use **three different names for it**.
Knowing the join keys is most of the job:

| tool | keyed by |
|---|---|
| `crash_fingerprint`, `quarantine`, `triage` | **signature** (`bd9b9121af542594`) |
| `bug_registry` | **bug_key** (`AppleJPEGDriver:r+0xb108:NULL-WRITE`) |

`bug_registry list` prints both, and `find_bug` resolves a bug by id, bug_key, or
any signature filed under it.

## Analyze and file

```sh
/usr/bin/python3 scripts/crash_fingerprint.py analyze <report>   # fault class, culprit site, bug_key
/usr/bin/python3 scripts/bug_registry.py route <report>...       # file under its bug
/usr/bin/python3 scripts/bug_registry.py list                    # the board
```

The signature is **KASLR-stable**: addresses are de-slid so it means the same
thing across reboots. `bug_key` is deliberately coarser than signature — one
root cause can crash as an OOB read one run and a null-write the next. More than
one signature under a bug is worth looking at: it means the fingerprint is
splitting what `bug_key` considers one bug.

### Crash origin is not decoration

```sh
bug_registry.py route --origin triage <report>
```

`origin=triage` marks a panic the **minimizer caused on purpose** while re-running
a known-crashing subset. Listings show these as `6 (+4)`: six genuine sightings,
four self-inflicted. Only fuzz-origin crashes count as sightings, because crash
frequency is a prioritization signal and investigating a bug must not inflate its
own rank. Never read the `(+N)` as evidence a bug is common.

## Minimizing

```sh
/usr/bin/python3 scripts/triage.py list
/usr/bin/python3 scripts/triage.py status <job>
```

Stages: `MERGE` → `MINIMIZE_CONN` → `MINIMIZE_CALLS` → `DONE`, or terminal
`STUCK`. Each crashing subset panics the box, so the job advances one boot at a
time and resumes from its own checkpoint.

**`DONE` vs `STUCK` is the distinction that matters for a report:**

- **DONE** — the culprit was re-run *in isolation, as the first program of a
  boot,* and crashed. That is a verified reproducer. Report it.
- **STUCK** — the subset crashed during the search but not on isolated re-check,
  so the bug needs state an earlier program left behind. **This is a result, not
  a failure.** Re-running will not improve it. The saved sequence is a lead, not
  a proof, and the dossier says so.

Probes share a kernel boot, so an unverified culprit may simply be whichever
subset happened to tip the kernel over. Never present one as a reproducer.

## What the quarantine decided

```sh
/usr/bin/python3 scripts/quarantine.py --state campaigns/.state/quarantine_<config-id>.json status
```

- A signature seen **once** is recorded but never benched (the SUSPECT gate) — a
  one-off crash must not cost a selector its coverage.
- Classification on confirmation: `HARD` (one selector, one call) disables
  permanently; `REPETITION` tolerates then escalates; `SOFT` (several selectors)
  rotates.
- A crash while already disabled or rotating is an **ESCAPE**: it bypasses the
  gate and records the new path, because a benched selector still crashing means
  the attribution was incomplete, not that the bug went away.

Beware the constant trap in code: `qm.SUSPECT` is the *category* `'SUSPECT'`;
`qm.SUSPECTED` is the *disposition* `'suspect'`.

## Attributing the reproducer

```sh
/usr/bin/python3 scripts/bug_registry.py attribute \
    --sig <signature> --culprit <final_culprit.syz> \
    --selector 'syz_IOConnectCallMethod$...' --job <triage-job> --verified
```

Omit `--verified` for a STUCK result. A verified reproducer is never replaced by
a later unverified one. This is what stops a dossier reporting `method: None` —
the selector *is* the method for an IOKit external method, and the symbol map
usually cannot supply it.

## The dossier

`campaigns/bugs/BUG-000N-<slug>.md`. The prose sections (Summary, Root cause,
Reproduce, Impact, Apple report) are **yours** and are never rewritten. Only the
delimited `AUTO-EVIDENCE` block is regenerated — reproducer first, then the
evidence log. Panic reports are hardlinked under `campaigns/bugs/<BUG-id>/reports/`
so the evidence survives macOS rotating `DiagnosticReports`; never chmod or
annotate them in place, since that would rewrite every snapshot linking the same
inode. Notes go in a sidecar.

Before writing up, have: the fault class and faulting offset, a **verified**
minimal reproducer with its selector, the impact (read vs write, what is
controlled), and the crash count with self-inflicted panics excluded.

## Context

This is authorized security research on the user's own dedicated bare-metal test
box (Mac16,10, macOS 26.5, arm64e, xnu-12377), with their own syzkaller + Pishi
coverage setup, for responsible disclosure to Apple.
