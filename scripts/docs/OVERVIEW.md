# scripts/ — a map

Everything that runs a campaign lives here. This file is the index: what each
piece is, and how the directory is laid out. Operational runbooks are linked at
the bottom.

## Layout

```
scripts/
  <driver>.py        CLI tools; each computes REPO_ROOT = its parent's parent,
                     so drivers MUST stay directly in scripts/
  lib/               shared library package, imported as `from lib import ...`
  tests/             unit tests (python3 -m unittest discover -s tests)
  docs/              this map and any design notes
  *.sh               shell entry points (publish, run)
  *.md               operational runbooks
```

Why the split: drivers, libraries, and tests were previously one flat pile.
Drivers can't move (they anchor the repo root off their own location), so the
libraries and tests moved out around them instead.

## Drivers (CLI tools)

| script | what it does |
|--------|--------------|
| `fuzz-campaign.py` | The autonomous coordinator: fuzz → crash → triage → quarantine → resume, reboot-resumable, driven by one launchd agent. Shells out to the drivers below. |
| `fuzz-session.py` | One `syz-manager` run: start/stop/resume, collect repro bundles, snapshot corpus+ring_buffer, save the grammar a run compiled. |
| `triage.py` | Minimizes a crashing program to a verified reproducer, one boot at a time (MERGE → MINIMIZE_CONN → MINIMIZE_CALLS → DONE/STUCK). |
| `quarantine.py` | Decides which syscalls to bench when a signature keeps crashing (HARD / REPETITION / SOFT), and writes `disable_syscalls` back into the live config. |
| `crash_fingerprint.py` | KASLR-stable signature + fault class + culprit site for a panic report. Imported by the coordinator and usable standalone. |
| `bug_registry.py` | Groups signatures into bugs (`bug_key`), tracks disclosure, and holds the dossiers under `campaigns/bugs/`. |
| `runstats.py` | Normalizes runs so experiments can be compared (real execution time vs wall time). |

## Library package (`lib/`)

Pure helpers, no CLI, no repo-root anchoring — imported as `from lib import X`.

| module | what it provides |
|--------|------------------|
| `cfgutil.py` | Parse a manager config exactly as syz-manager parses it (whole-line `#` comments and nothing else). |
| `timefmt.py` | One clock for every tool: stored timestamps with a real UTC offset, local display, tolerant parsing, `now_ts()` directory stamps. |
| `fsutil.py` | `hardlink_or_copy` (share evidence across consumers without duplicating blocks) and a link-count refcount. |
| `tablefmt.py` | `render` / `tabulate` for the aligned tables the CLIs print. |

## Shell

| file | purpose |
|------|---------|
| `sync-fuzz-run.sh` | Publish the dev tree into the fuzz-user runtime tree (`/Users/Shared/fuzz-run`). |

## Tests

```sh
cd scripts && python3 -m unittest discover -s tests      # all
cd scripts && python3 -m unittest tests.test_triage      # one module
```

`tests/__init__.py` puts `scripts/` on the path, so tests import drivers
(`import quarantine`) and libraries (`from lib import cfgutil`) regardless of where
unittest is invoked. The two hyphenated drivers (`fuzz-campaign.py`,
`fuzz-session.py`) can't be `import`ed by name, so their tests load them by path.

## Runbooks

- [../README.md](../README.md) — running a campaign
- [../README-triage.md](../README-triage.md) — crash → reportable bug
- [../fuzz-run-setup.md](../fuzz-run-setup.md) — first-time fuzz-user setup
