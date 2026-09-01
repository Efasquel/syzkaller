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
- **Hardlinked panic evidence under `campaigns/bugs/*/reports/` is never
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
/usr/bin/python3 scripts/fuzz-campaign.py new <name> config/<x>.cfg \
    --budget-hours 24 --budget-clock fuzz \
    --kcov-device /dev/pishi --kext-id 1 --sandbox none
sudo ./scripts/fuzz-campaign.py install <name> --agent --user fuzz
```

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
```

`status -w` annotates what moved since the last refresh. A blank delta column
means nothing moved, which is the signal you are watching for — an absolute
counter looks identical whether the box is fuzzing hard or wedged.

Three clocks are reported separately: **fuzzing** (manager executing),
**minimizing** (triage), **rebooting**. `--budget-clock` picks which one
`--budget-hours` measures; the default `fuzz` means minimizing a bug never eats
the fuzzing budget. Never quote wall time as fuzzing time.

## Stopping a box that will not stay up

Four rungs. Each works when the one above it does not.

| situation | action |
|---|---|
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
- **Budget seems not to advance** — the per-config clock resets on a config
  advance by design; the lifetime totals in `status` are the ones that never do.

## Sequence for a fresh run

```sh
./scripts/sync-fuzz-run.sh
cd /Users/Shared/fuzz-run
sudo -u fuzz /usr/bin/python3 scripts/fuzz-campaign.py doctor <name>
sudo ./scripts/fuzz-campaign.py install <name> --agent --user fuzz
tail -f campaigns/.state/<name>.coordinator.log
```
