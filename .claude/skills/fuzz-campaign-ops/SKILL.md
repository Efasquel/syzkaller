---
name: fuzz-campaign-ops
description: Operating autonomous syzkaller campaigns on the bare-metal macOS test box under the fuzz user - publishing the runtime tree, pre-flight, installing the launchd agent, watching a run, and stopping a box that will not stay up. Use for starting, restarting, observing, halting or debugging a fuzzing campaign, or when a campaign behaves unexpectedly (no crashes filed, budget not moving, agent not relaunching, executor errors).
---

# Operating a campaign

The campaign driver runs unattended as user `fuzz` (uid 502) on a box that
**reboots on every kernel panic**. Almost everything surprising here follows from
those two facts.

## The runtime tree is not the repo

The build tree (`~/Documents/syzkaller`) is `0700`, so `fuzz` cannot even
traverse it. Campaigns run from a published copy at `/Users/Shared/fuzz-run`.

```sh
./scripts/sync-fuzz-run.sh          # repo -> /Users/Shared/fuzz-run
```

Publish **before** every run after any edit. Scripts anchor to
`SCRIPT_DIR.parent`, so a published script reads published state — running the
repo's copy against the published tree silently looks at the wrong campaigns.

Two properties of that tree that are load-bearing:

- **The root is `775`, not `755`.** It is the launchd job's `WorkingDirectory`,
  therefore the cwd of everything the campaign spawns. `syz-executor` creates its
  shmem file and tmpdir *relative to cwd*; a read-only root makes every probe die
  with `SYZFAIL: shmem open failed ... errno 13`, and minimization then reports
  that nothing reproduces having never executed a program.
- **Hardlinked panic evidence under `bugs/*/reports/` is never
  chmod'd or chgrp'd.** Those are second names for the OS's own files; changing
  a link's mode rewrites the original in `/Library/Logs/DiagnosticReports`.

## Pre-flight — as `fuzz`, not as you

```sh
cd /Users/Shared/fuzz-run    # cd FIRST: sudo -u fuzz inherits cwd and cannot
                             # getcwd() inside the 0700 build tree
sudo -u fuzz /usr/bin/python3 scripts/fuzz-campaign.py doctor <campaign>
```

Doctor's permission checks are only meaningful as the user launchd will actually
run as. Run as yourself they are noise — it says so in its own output.

## Authoring and installing

```sh
/usr/bin/python3 scripts/fuzz-campaign.py new <name> config/<x>.cfg [config/<y>.cfg] \
    --repeat 3 --max-hours 6 -m "why"       # creates campaigns/<name>/ (plan.json, state, README) + checks it
/usr/bin/python3 scripts/fuzz-campaign.py new <name2> --copy <name>    # same experiment, new name; flags given alongside override
/usr/bin/python3 scripts/fuzz-campaign.py plan check <name> [--strict]
sudo ./scripts/fuzz-campaign.py install <name> --agent --user fuzz
```

A campaign's plan references hand-written configs; listing a config N times
(or `--repeat N`) runs it N times from scratch as items `<config-id>-1..N`.
`config/box.json` holds the machine's keys once and is never overwritten by
sync; a config's own box key wins and shows as drift in `plan check`. The
runner renders each item's effective config under
`campaigns/<name>/<config-id>/<item-id>/` and never writes `config/`. The
plan and README of each campaign are tracked in git; the rest of its folder
is runtime. Campaigns authored as `campaigns/<name>.json` are read-only now.

`--agent` (a LaunchAgent in `gui/502`), never a LaunchDaemon: the driver needs
the login session. `RunAtLoad` gives exactly one relaunch per panic-reboot, and
`KeepAlive{SuccessfulExit:false}` means **a clean exit leaves it down** — that is
how the brake works.

**Only ever one campaign at a time.** They share `/dev/pishi`.

## A config *is* a workdir

`workdir` is a key in the `.cfg`, so re-running a config resumes that workdir's
`corpus.db` and coverage. Right for making progress, wrong for measuring
"coverage reached from scratch in 24h" — that needs a new config with a new
`workdir` path. The classic mistake is copying a config, changing
`disable_syscalls`, and forgetting `workdir`. `status` reports which it is.

## Watching

```sh
tail -f campaigns/.state/<name>.coordinator.log   # decisions only — use this
tail -f campaigns/.state/<name>.launchd.log       # + minimizer probe chatter
/usr/bin/python3 scripts/fuzz-campaign.py status <name> -w
/usr/bin/python3 scripts/fuzz-campaign.py quarantine <name> [--all]   # what is benched, and why
/usr/bin/python3 scripts/runstats.py curve <campaign>/<config-id>/<item-id> --field blocks|exec   # over fuzz-hours
/usr/bin/python3 scripts/runstats.py compare --by config                            # mean ± spread over a config's items
```

`runstats` addresses one sample as `<campaign>/<config-id>/<item-id>`; the
legacy `<Driver>/<variant>` form still names a run under the top-level
`workdir/`.

`status -w` annotates what moved since the last refresh. A blank delta column
means nothing moved, which is the signal you are watching for — an absolute
counter looks identical whether the box is fuzzing hard or wedged. `exec total`
and `basic blocks` also carry `+N / 1h00m`, the growth over the last hour from
the progress series the driver samples each poll (`results/progress.jsonl`).

The `status` row of `status` (and the STATUS column of `list`) is the **activity**,
finer than the phase and stamped with its duration — `HALTED`/`DONE` are
activity words, any other word means running: `BOOTING` → `PREPARING` →
`FUZZING` → `COLLECTING` → `TRIAGING bug …` (job, stage, advance N/M and progress in the `triage` block) →
`HALTED/<kind>` (`BRAKE`, `USER`, `CRASH-LOOP`, `DISK`, `STARTUP`, `TRIAGE`,
`MAX_CRASHES`, `ERROR`) or `DONE`, plus `WAITING` after a `resume` until the
agent relaunches. It
is what tells "fuzzing restarted" from "still minimizing" between two panics.
The driver opens a Terminal running `status -w` at every start (so it is on
screen right after a panic-reboot; `new --no-watch-window` disables it) and
posts a macOS notification on fuzzing start, each triage advance, each decided
crash, and halt. `FUZZ_NO_GUI=1` silences both, e.g. from an ssh shell.

Four clocks are reported separately: **preparing** (snapshot, grammar compile,
until the first exec), **fuzzing** (first exec to the run's last sign of life),
**minimizing** (triage), **rebooting** (panic to back up, and dead time).
`--clock` picks what `--max-hours` measures: the default `real` is the elapsed
time since the item started, through halts and reboots, so an item asked for 6h
ends 6h after it started and you know when the box frees up; `wall` charges the
four clocks above but not idle time; `fuzz` only fuzzing (so neither startup
nor minimizing a bug eats the budget). Never quote wall time as fuzzing time.

## Stopping a box that will not stay up

Four rungs. Each works when the one above it does not.

| situation | action |
|---|---|
| end only the current item, keep the campaign going | `fuzz-campaign.py next <name>`; `skip <name> <item>` leaves a pending item out (requests, applied at the driver's next poll) |
| running, box usable | `fuzz-campaign.py halt <name>` |
| stop it *before* it fuzzes again after the next reboot | `fuzz-campaign.py brake <name> --reason "why"` |
| panics through login, no usable session | Recovery (⌘R) → Terminal → `touch "/Volumes/Macintosh HD - Data/Users/Shared/fuzz-run/STOP"` |
| panics before the agent runs | Safe Mode (hold ⇧) — no third-party kexts, so Pishi is not loaded |

The brake is a file checked before the driver reads state, before reconcile,
before any session starts. Anything written into it becomes the halt reason.
`resume` refuses while a brake is set. `brake --where` prints the Recovery path.

## When something looks wrong

- **Crashes happen but nothing is filed / nothing quarantined** — check the
  coordinator log, not the launchd log. Every crash on this target arrives via
  `reconcile_boot` on the next boot, not via `supervise`.
- **Executor errors on every probe** — cwd permissions (see 775 above).
- **`[FATAL] bad config syzkaller param` / handshake failure** — the RPC
  handshake requires the manager side and executor to agree on *both* git
  revision and descriptions hash. Rebuild with
  `make ring-repro REV=<rev>`; a plain `go build` drops
  `-ldflags -X prog.GitRevision` and the revision reads `unknown`. If
  `sys/darwin/*.txt` has uncommitted changes, the descriptions hash moves too.
- **Budget seems not to advance** — the per-item clock resets when the campaign
  moves to the next item by design; the lifetime totals in `status` are the
  ones that never do.
- **An item ended early as `abandoned`** — it reached `max_crashes` incidents
  (the limit is per item) and the campaign moved on to the next item; one
  abandoned item is still a sample. `skipped` is different: that is the status
  the `skip` verb sets. When *every* item ended abandoned the campaign halts
  as `HALTED/MAX_CRASHES` ("every item reached max_crashes").
- **Halted with "... hung and the box must be rebooted"** — a triage probe
  wedged the executor (it holds `/dev/pishi`) and `sudo -n /sbin/shutdown -r
  now` was refused. Reboot by hand, `resume`, and add the sudoers rule from
  `fuzz-run-setup.md` (doctor warns when it is missing).
- **A signature keeps crashing but is never triaged** — `status` lists it under
  `exhausted` with the kind (`no-repro`, `ring-only`, `hang`, ...). Recurrences
  are counted; after 4 the newest ring program is benched as an unverified lead.
  `forget-exhausted` re-allows triage once the cause is fixed.
- **An incident says "NOT the fuzzed <kext>"** — the backtrace blames a kext
  other than the one this config targets (a shared IOKit family, the kernel's
  own zone code reached through the driver, or a genuinely different driver).
  Worth a look before attributing the bug to the target.
- **Halted with "failed to start N times"** — the manager died before its first
  exec; the reason quotes the run log. Look in
  `<workdir>/artifacts/startup-failures/`. A held http port is the usual cause.

## Sequence for a fresh run

```sh
./scripts/sync-fuzz-run.sh
cd /Users/Shared/fuzz-run
sudo -u fuzz /usr/bin/python3 scripts/fuzz-campaign.py doctor <name>
sudo ./scripts/fuzz-campaign.py install <name> --agent --user fuzz
tail -f campaigns/.state/<name>.coordinator.log
```
