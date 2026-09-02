# Autonomous campaign under the `fuzz` user (LaunchAgent setup)

Run the whole loop the runbook walks through by hand — **fuzz → crash → collect →
fingerprint → triage/minimize → quarantine → apply → resume** — unattended, as the
dedicated `fuzz` user, surviving panic-reboots and logouts.

- **Build/dev account:** `wan` (uid 501) — owns the repo, rebuilds binaries.
- **Fuzzing account:** `fuzz` (uid 502) — auto-logs-in, runs the campaign.
  Both users are in group `staff`.

One launchd job drives everything: `fuzz-campaign.py run <name>`. It shells out to
`fuzz-session.py`, `triage.py` and `bug_registry.py`, and imports
`crash_fingerprint.py` and `quarantine.py`. **Do not also install `triage.py`'s own
agent** — two drivers would fight over the box.

---

## Why a separate runtime tree

The repo lives at `/Users/wan/Documents/syzkaller`, but **`/Users/wan/Documents` is
`0700`** — `fuzz` cannot traverse into it at all, so it can't read the scripts or
binaries. Symlinks don't help (the block is on traversal). Every script also anchors
its paths to `SCRIPT_DIR.parent` (`config/`, `campaigns/.state`, `sessions/`,
`workdir/`, `triage/`), so `fuzz` needs its own writable repo root.

Solution: a fuzz-accessible runtime root at **`/Users/Shared/fuzz-run`**
(`/Users/Shared` is world-traversable; both users share `staff`).

### What is / isn't copied

| Item | Handling | Why |
|------|----------|-----|
| `scripts/{fuzz-campaign,fuzz-session,triage,quarantine,crash_fingerprint,bug_registry}.py` | **copied** (ro) | the full coordinator, not just the two drivers |
| `bin/syz-manager`, `bin/darwin_arm64/{syz-executor,syz-ring-repro}` | **copied** (ro) | a headless agent has a minimal PATH and cannot fall back to `go run` |
| `config/*.cfg`, `config/kext_ids.json` | **copied + rewritten, group-writable** | `workdir`+`syzkaller` repointed into the tree; the quarantine *writes* `disable_syscalls` back into the live config |
| `campaigns/*.json` | **copied** (defs only) | `.state/` is fuzz-owned runtime |
| `kernel_obj` = `/Users/wan/KernelCollections/` | **left in place** | already `0755`/`0644`, fuzz-readable — avoids a 120 MB copy |
| `bluetoothd` (repo root) | **not copied** | a renamed `syz-executor`; `executor_binary()` derives it at runtime |

No root is needed at runtime: `/dev/pishi` is `0666`, so `fuzz` opens the coverage
device fine.

---

## Two privileged prerequisites (one-time, `sudo`)

There is really only one, and it fails **silently** — the campaign keeps fuzzing and
just never notices a crash — so `doctor` checks it explicitly. The second item is here
because `doctor` warns about it and the obvious "fix" is a bad one.

### 1. Panic reports must be readable by `fuzz`

`/Library/Logs/DiagnosticReports` is `0770 root:_analyticsusers`, and `fuzz` is not a
member. Without it `latest_panic_signature()` returns `None` on every crash, so the
campaign never fingerprints, never triages, never quarantines.

```sh
sudo dseditgroup -o edit -a fuzz -t user _analyticsusers
dsmemberutil checkmembership -U fuzz -G _analyticsusers   # -> is a member
```

This grants read of the diagnostic reports and nothing else — it is not `admin`, so
the fuzzing account still has no privilege escalation path.

### 2. Nothing — do NOT widen `/private/var/tmp/kernel_panics`

`fuzz-campaign.py doctor` warns that `fuzz` cannot prune the `*.kernel.core.gz`
cores in `/private/var/tmp/kernel_panics` (`0755 root:wheel` — unlinking needs write
on the *directory*). **Do not fix that by making the directory group-writable.** Four
reasons:

- On macOS `staff` (gid 20) is the default primary group of *every* local account, so
  `chgrp staff` shares the directory with every user who can log in, not just `fuzz`.
- The sticky bit can't help. `/private/var/tmp` is `1777` precisely so users can't
  delete each other's files; but `1775` here would stop `fuzz` deleting root-owned
  cores, which is the whole point. It would have to be non-sticky `775` — any member
  free to delete or rename root's files.
- Root writes into that directory under predictable filenames
  (`YYYY-MM-DD-HHMMSS.kernel.core.gz`). A directory that unprivileged users can
  create entries in, which root then writes into by name, is the classic symlink-
  redirect setup for an arbitrary root write.
- `fuzz` is the account deliberately executing attacker-shaped syscall sequences
  against the kernel. Granting it write access to a directory root writes into is the
  wrong direction.

**And it is not actually needed.** As of 2026-08-31 the box has not produced a kernel
core since 2026-07-18: 50 August panics, zero cores. The 664 MB sitting there is three
frozen July files. Reclaim them once, by hand, and the warning stops firing (doctor
only warns when cores are actually present):

```sh
sudo rm /private/var/tmp/kernel_panics/*.kernel.core.gz     # ~664MB, all from July
```

The panics that *are* being written go to `/Library/Logs/DiagnosticReports` — ~2 MB
each, 107 MB for 50 of them — and that directory is `0770` with group write, so
prerequisite 1 gives `fuzz` pruning there for free. `collect` also deliberately
excludes `*.kernel.core.gz` from incident bundles (`PANIC_GLOBS` takes only the
`.kernel.core.log`), so a core is never duplicated into the workdir.

If core dumping is ever re-enabled and the cores start accumulating again, prune them
from a small root-owned periodic LaunchDaemon rather than widening the directory.

---

## Publishing / re-syncing after a rebuild

`wan` builds in the real repo, then pushes into the fuzz tree:

```sh
./scripts/sync-fuzz-run.sh                  # defaults to /Users/Shared/fuzz-run
./scripts/sync-fuzz-run.sh /some/other/root
FUZZ_GROUP=otherstaff ./scripts/sync-fuzz-run.sh
```

Safe to re-run mid-campaign:

- every copy is **atomic** (temp + rename), so a running `syz-manager` keeps its old
  inode and is never truncated under it;
- a destination config's **`disable_syscalls` is carried across**, so a re-sync does
  not throw away the quarantine decisions the campaign has accumulated;
- the tree's group is forced to `staff` every sync (under `/Users/Shared` the default
  is `wheel`, which would leave `fuzz` with `r-x` and no way to write state);
- a config that no longer parses as JSON is skipped with a warning rather than
  aborting the publish.

### Seeding the campaign's memory (first publish only)

`.state/` is runtime and deliberately **not** synced. To carry the manual campaign's
knowledge over — so already-known bugs are not re-discovered and re-triaged from
scratch — copy the quarantine ledger and the bug registry once, repointing the
ledger's `config` at the published copy:

```sh
DST=/Users/Shared/fuzz-run
for q in campaigns/.state/quarantine_*.json; do
  /usr/bin/python3 - "$q" "$DST/campaigns/.state/$(basename "$q")" "$DST" <<'PY'
import json, os, sys
src, dst, root = sys.argv[1:4]
q = json.load(open(src))
if q.get("config"):
    q["config"] = os.path.join(root, "config", os.path.basename(q["config"]))
json.dump(q, open(dst, "w"), indent=2); open(dst, "a").write("\n")
PY
done
cp -R campaigns/bugs/. "$DST/campaigns/bugs/"
chgrp -R staff "$DST/campaigns" && chmod -R g+rw "$DST/campaigns/.state" "$DST/campaigns/bugs"
```

---

## Authoring the campaign

The `triage` block is what the coordinator replays to `triage.py new` on every bug it
decides to minimize. **Author it** — without it triage falls back to no coverage
device and no kext id, which is not what the manual runs used:

```sh
./scripts/fuzz-campaign.py new jpeg config/AppleJPEGDriver_260827_cov_gram_test.cfg \
    --budget-hours 12 --loop --kcov-device /dev/pishi --kext-id 1 --sandbox none
```

`--loop` with a single config means it never finishes: at each budget expiry it
snapshots, restarts, and keeps going. Leave `--executor`/`--ringrepro` unset —
`triage.py`'s own defaults are anchored at its repo root, which is correct in both
the dev tree and the published tree, whereas a relative path here would resolve
against launchd's working directory.

---

## Pre-flight — as `fuzz`, not as you

`doctor` checks binaries, scripts, panic-dir **readability**, core **prunability**,
config and workdir **writability**, and the state dirs. Permissions are checked as
whoever runs it, so run it as the user launchd will use:

```sh
cd /Users/Shared/fuzz-run
sudo -u fuzz /usr/bin/python3 scripts/fuzz-campaign.py doctor jpeg
```

**`cd` out of the repo first.** `sudo -u fuzz` inherits your working directory, and
`fuzz` cannot traverse the `0700` build tree — running it from there gives
`shell-init: error retrieving current directory: getcwd: cannot access parent
directories: Permission denied` before anything useful happens.

Expect `0 fail` before installing. A FAIL on a panic dir means crashes would be
invisible; a WARN on prunability means the disk fills.

---

## Install the agent — from the published tree

```sh
cd /Users/Shared/fuzz-run
sudo ./scripts/fuzz-campaign.py install jpeg --agent --user fuzz
```

**Run `install` from `/Users/Shared/fuzz-run`, never from the repo.** The plist bakes
in *the installing tree's* paths, so installing from `/Users/wan/Documents/syzkaller`
produces a job launchd starts and python instantly kills, with the failure buried in
a log nobody opens. `install` now refuses this: it forks, drops to the target user,
and checks it can actually read the tree.

Key plist settings and rationale:

- **`~fuzz/Library/LaunchAgents`, not `/Library/LaunchAgents`** — loads only in
  fuzz's login session. System-wide it would also load in `wan`'s Aqua session and
  spawn a second campaign fighting over `/dev/pishi`.
- **`RunAtLoad` + `KeepAlive{SuccessfulExit:false}`** — starts on fuzz's auto-login
  and after a panic-reboot; restarts on a crash but not on a clean exit (the driver
  exits 0 when the campaign is done or the breaker halts it). Dovetails with
  `reconcile_boot`, which records the in-flight incident and resumes.
- **`ThrottleInterval 30`** — don't hot-loop if the driver exits nonzero at once.

Confirm it is live:

```sh
sudo launchctl print gui/502/com.fuzz-campaign.jpeg | head -30
```

---

## Operating it

```sh
# what the coordinator decided -- crashes, quarantine, triage, budget.
# This is the one to `tail -f`: minimizer probe chatter does NOT go here.
tail -f /Users/Shared/fuzz-run/campaigns/.state/jpeg.coordinator.log

# everything, including syz-ring-repro's per-probe output (forensics; large)
tail -f /Users/Shared/fuzz-run/campaigns/.state/jpeg.launchd.log

# campaign state (phase: fuzzing | triaging, incidents, benched sigs)
cd /Users/Shared/fuzz-run && /usr/bin/python3 scripts/fuzz-campaign.py status jpeg
/usr/bin/python3 scripts/fuzz-campaign.py list

# what the quarantine has decided
/usr/bin/python3 scripts/quarantine.py \
    --state campaigns/.state/quarantine_<config-id>.json status

# the reportable bug inventory
cat campaigns/bugs/INDEX.md
/usr/bin/python3 scripts/fuzz-campaign.py replay jpeg

# pause / resume (the driver polls state and stops the session)
/usr/bin/python3 scripts/fuzz-campaign.py halt jpeg
/usr/bin/python3 scripts/fuzz-campaign.py resume jpeg

# stop the agent entirely (and prevent restart at next login)
sudo ./scripts/fuzz-campaign.py uninstall jpeg --agent --user fuzz
```

### Stopping a runaway box

Four rungs, in order of how broken the machine is. Each works when the one above
it does not.

| situation | what to do |
|---|---|
| campaign is running, you can use the box | `fuzz-campaign.py halt jpeg` |
| you want it stopped *before* it fuzzes again after the next reboot | `fuzz-campaign.py brake jpeg --reason "why"` |
| box panics its way through login; you cannot get a usable session | boot to Recovery (⌘R), Terminal, `touch "/Volumes/Macintosh HD - Data/Users/Shared/fuzz-run/STOP"` |
| it panics before the agent even runs | Safe Mode (hold ⇧ at boot) — no third-party kexts, so Pishi is not loaded |

The **brake** is a file. Its existence is checked before the driver reads state,
before it reconciles the last boot, before any session starts — so it is the only
stop that works on a box that panics as soon as fuzzing resumes. The driver then
exits 0, which is what keeps launchd (`KeepAlive{SuccessfulExit:false}`) from
relaunching it.

```sh
# set / clear / inspect
/usr/bin/python3 scripts/fuzz-campaign.py brake jpeg --reason "boot loop 03:12"
/usr/bin/python3 scripts/fuzz-campaign.py brake jpeg --clear
/usr/bin/python3 scripts/fuzz-campaign.py brake --where   # prints the Recovery path
```

Anything you write into the file becomes the halt reason in the log, so
`echo "suspect _9" > STOP` leaves a note for whoever reads it next (you, tired).
`resume` refuses while a brake is set, rather than marking the campaign running
and letting the next start silently re-halt it.

> **Test the Recovery path once, deliberately, while the box is healthy.** A brake
> you have never exercised is not a brake. (With FileVault on you must unlock the
> volume in Recovery before it mounts; FileVault is currently disabled on this rig.)

### What the breaker will do

The campaign **halts itself** on any of: `max_crashes` total incidents (default 20),
free disk under `min_free_gb` (20), `crashloop_limit` consecutive crashes that
never fuzzed anything (15 runs shorter than `crashloop_window_seconds`, 20s), or
triage failing to reach a culprit in `triage_max_boots` advances (40). The window
is deliberately below anything that managed to execute programs: a healthy run on
this target panics every 30-110s, and the old 120s/5 pairing halted a working
campaign within ten minutes of its first real bug. A halt is a safe stop, not a failure — `resume` clears it. For a multi-day
unattended run, raise `max_crashes` in `campaigns/jpeg.json`.

### A config **is** a workdir

`workdir` is a key in the `.cfg`, so re-running a config resumes **that
workdir's** `corpus.db`, ring buffer and coverage — it continues the previous
experiment rather than starting a new one. That is why a resumed run logs:

```
corpus : resuming from existing corpus.db
```

Which you want depends on the question you are asking:

| you want | do this |
|---|---|
| keep making progress on a target | re-use the config — inherited corpus is the point |
| measure "coverage reached from scratch in 24h" | **new config with a new `workdir` path** |

There is no flag for this and deliberately so: the workdir path in the config is
the single source of truth. But it does mean the classic mistake is copying a
config, changing `disable_syscalls`, and forgetting `workdir` — the "new"
experiment then silently inherits the old corpus and its coverage baseline.

`status` now says which it is, so you never have to infer it from a log line that
scrolled past hours ago:

```
corpus      : 260831_cov_gram_no7_test  (26 KB, last grew 01/09 14:55:31)
corpus      : none yet -- this config starts from scratch
```

### Watching a campaign

```sh
/usr/bin/python3 scripts/fuzz-campaign.py status jpeg -w            # every 10s
/usr/bin/python3 scripts/fuzz-campaign.py status jpeg -w --interval 30
```

Redraws in place until Ctrl-C, annotating what moved since the last refresh:

```
executed    : 11,214,880 program(s)  (78/sec)   +4,213
coverage    : 317 basic block(s)                    +2
incidents   : 4 crash / 0 hang                      +1
corpus      : 260831_cov_gram_no7_test  ...     +1408 B
```

The deltas are the point. An absolute counter looks identical one refresh later
whether the box is fuzzing hard or wedged; a blank delta column means nothing
moved, which is exactly the signal you are watching for.

### Dates

Stored timestamps are ISO 8601 **with a real offset** — `2026-09-01T14:56:39+02:00`
— so a state file reads the way your wall clock does while staying machine-
parseable across DST. Displayed timestamps use the local convention,
`01/09/2026 14:56:39`; log lines use the short form, `01/09 14:56:39`.

This used to be two clocks that disagreed: timestamps were stamped UTC with a `Z`
while directory names used local time, so one event appeared in the log as
`15:41:48Z` and on disk as `20260831-174148`. Reading a state file written before
this change still resolves to the same instant — the `Z` form is parsed, not
reinterpreted — it simply now *displays* as the hour it actually happened.

> Never sort these as strings. A mix of `Z` and `+02:00` rows compares wrong
> lexically; sort on `timefmt.to_epoch()`.

### Reading the clocks

`status` reports three disjoint clocks plus their sum:

```
fuzzing     : 4h12m  (manager executing)
minimizing  : 0h51m  (triage)
rebooting   : 0h23m  (panic -> back up)
wall        : 5h26m  (sum of the three)
```

`--budget-hours` measures **wall** by default: session uptime plus minimization
plus reboot overhead. That is "give this config 24 hours of machine time", which
is what comparing one configuration against another needs. `--budget-clock fuzz`
charges session uptime only, so a stubborn bug's minimization cannot eat the
budget — useful when you care about fuzzing throughput rather than a fixed
envelope. `wall >= fuzz` always, so the default can only end a campaign sooner.

> **`fuzzing` in `status` is session uptime, not time executing programs.** The
> manager also starts up, triages the corpus and waits on RPC; on a measured run
> only **56%** of uptime was execution (18.9 h alive → 10.7 h executing). For the
> real figure, `runstats.py show <run>` reads syz-manager's own counter and
> prints an `efficiency` line. Budget in wall hours, report in fuzzing hours. Both totals are always kept, so a writeup can
say "24h fuzzing, 31h wall, of which 4h minimization" rather than picking one
number and hiding the rest. Nothing accrues while the campaign is halted or idle,
and a reboot gap longer than `max_boot_gap_seconds` (15 min) is treated as idle
rather than overhead — otherwise the wall clock would measure your sleep schedule.

### When triage gets STUCK

Minimization can finish without a verified reproducer: the culprit crashed during
the search but not when re-run on its own, which means the bug needs state an
earlier program left behind. That is a **result**, not a failure. The job stops at
`STUCK`, the campaign benches the selectors anyway so fuzzing continues, and the
bug dossier records the sequence as an *unverified lead* rather than a
reproducer. Re-running will not improve it.

### Switching which campaign runs

Author another def, then install its own agent (each campaign gets its own label).
Only ever run **one** at a time — they share `/dev/pishi`.
