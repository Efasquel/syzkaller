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

## Privileged prerequisites (one-time, `sudo`)

The first fails **silently** — the campaign keeps fuzzing and just never notices a
crash — so `doctor` checks it explicitly. The second is here because `doctor` warns
about it and the obvious "fix" is a bad one. The third lets triage recover from a hang
on its own.

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

### 3. Let triage reboot the box after a hang

A minimization probe that hangs leaves its executor wedged in the kernel (STAT `U`),
holding `/dev/pishi` until the machine reboots: SIGKILL cannot reach it, and nothing
else can run on that boot. Triage captures the stack (`diagnose-hang`) and then
reboots with `sudo -n /sbin/shutdown -r now`. Allow exactly that command:

```sh
echo 'fuzz ALL=(root) NOPASSWD: /sbin/shutdown -r now' | sudo tee /etc/sudoers.d/fuzz-reboot
sudo chmod 0440 /etc/sudoers.d/fuzz-reboot
sudo visudo -cf /etc/sudoers.d/fuzz-reboot                     # -> parsed OK
sudo -u fuzz sudo -n -l /sbin/shutdown -r now                  # -> prints the command
```

Without it a hang **halts** the campaign with the reason, and someone has to reboot
by hand. `doctor` warns when the rule is missing.

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

# what the quarantine has benched for the current config, and why (the
# disabled set, HARD calls, SOFT rotation groups, the catalog); --all for every
# config of the campaign. `status` carries a one-line summary of the same.
/usr/bin/python3 scripts/fuzz-campaign.py quarantine jpeg

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

The campaign **halts itself** on any of: free disk under `min_free_gb` (20),
`crashloop_limit` consecutive kernel panics that hit before the run fuzzed
anything (15 in a row, each before `crashloop_min_execs`, 200, programs ran),
`startup_fail_limit` managers in a row that died before executing a single
program (3), or triage failing to reach a culprit in `triage_max_boots` advances
(40). "Fuzzed anything" is counted in programs, not seconds: a poisoned corpus
panics at 0-30 execs, while even five seconds of real fuzzing is over 200 at
40-50 execs/s. A time window was tried and could not tell them apart -- the
manager's stat line comes every 10s, so its error was as large as the window,
and a healthy run with a quick real bug read as a crash loop. Only fuzzing runs
count: panics caused on purpose during minimization never do. A halt is a safe stop, not a
failure — `resume` clears it.

`max_crashes` (20) is **per config** and does not halt: a config that reaches
it is **abandoned** — recorded in `status`, skipped if the campaign loops — and
the campaign moves on to the next one. Only when every config is abandoned does
it halt. For a multi-day unattended run on a crash-heavy driver, raise
`max_crashes` in the campaign definition.

A manager that dies before its first exec without a panic (a held http port, a
bad config, a missing binary) is a **startup failure**: noticed within
`startup_poll_seconds` (15s), collected under `artifacts/startup-failures/`,
retried after 30s, and the third in a row halts with the run log's last
`FATAL` line as the reason.

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

A full `status`, here mid-minimization (the figures are from a demo state):

```
campaign demo_triaging : TRIAGING bug 3f2a9c01  for 0h31m
  updated       : 19/10/2026 14:47:22  (0h19m ago)

  triage (job demo_triaging_t1, boot 7 / 40):
    stage       : MINIMIZE_CALLS
    progress    : 12 subsets tested for 40 calls, 3 crashing

  session (1/1 - no loop):
    config      : AppleSMC_demo_cov
    stop        : 17h18m / 24h00m (fuzzing)
    manager     : down
    started     : 19/10/2026 06:06:22
    corpus      : workdir  (412 KB, last grew 19/10 14:47:22)
    quarantine  : 2 / 10 disabled (1 hard, 1 soft), 1 suspect

  time breakdown (whole campaign):
    preparing   : 0h12m  (until first exec)
    fuzzing     : 6h41m  (first exec -> end of run)
    minimizing  : 1h03m  (triage)
    rebooting   : 0h44m  (panic -> back up)
    total       : 8h41m

  stats:
    executed    : 11,214,880 program(s)
    basic blocks: 317 (total: 1,304)
    disk free   : 574.9 GB

  incidents (this config: 2 / 20):
    crashes     : 4
    hangs       : 0
    benched     : 2  (77ab10c3, 3f2a9c01)
    triage queue: 1 second bug(s) waiting: 9c1e55d2

  last 4 incident(s):
    when            kind   ran  sig       bug       kext                    decision
    19/10 09:47:22  crash  84s  77ab10c3  BUG-0004  AppleSMC                suspect
    19/10 11:37:22  crash  84s  77ab10c3  BUG-0004  AppleSMC                triage demo_triaging_t0
    19/10 13:12:22  crash  84s  1c2e8800  BUG-0009  IOSurface (NOT fuzzed)  suspect
    19/10 14:33:22  crash  84s  3f2a9c01  BUG-0007  AppleSMC                triage demo_triaging_t1
```

Top to bottom: what the box is doing and for how long; how fresh this screen
is; the triage job while one runs; the session (which config, how much of its
budget is left on which clock, where the manager's UI is, what the quarantine
has benched); the campaign's time split four ways; the numbers; the incidents.

Redraws in place until Ctrl-C, annotating what moved since the last refresh:

```
stats:
  executed    : 11,214,880 program(s)  (78/sec)   +4,213
  basic blocks: 317 (total: 1,204)                    +2
incidents (this config: 2 / 20):
  crashes     : 4   +1
  hangs       : 0
  benched     : 2  (77ab10c3, 3f2a9c01)
corpus      : 260831_cov_gram_no7_test  ...     +1408 B
```

The deltas are the point. An absolute counter looks identical one refresh later
whether the box is fuzzing hard or wedged; a blank delta column means nothing
moved, which is exactly the signal you are watching for.

#### Between two crashes: what the box is doing, without typing

The headline of `status` is the **activity** — finer than the phase, with how
long it has been going. It is also the campaign's status: `HALTED`/`DONE` are
activity words, and any other word means running, so nothing else repeats it:

```
campaign jpeg : TRIAGING bug 3f2a  for 0h12m
campaign fde  : HALTED/CRASH-LOOP crash loop (15 crashes in a row before 50 programs executed)  for 2h03m
```

| activity | meaning |
|---|---|
| `BOOTING` | driver just relaunched, reconciling what the last boot left |
| `PREPARING` | manager starting: snapshot, grammar compile, corpus re-triage — nothing executed yet |
| `FUZZING` | first program executed; the box is fuzzing |
| `COLLECTING` | a crash/hang is being recorded and bundled |
| `TRIAGING` | a bug is being minimized; the `triage` block has the job and its boot count in the header, then the stage and how far its search has got |
| `WAITING` | `resume` was issued; nothing runs until the agent relaunches the driver |
| `HALTED/<kind>` / `DONE` | the driver exited; the kind says who stopped it — `BRAKE`, `USER`, `CRASH-LOOP`, `DISK`, `STARTUP` (the breaker's three), `TRIAGE` (stuck or unrebootable hang), `ABANDONED` (every config gave up), `ERROR` — and the reason follows |

The word is green for fuzzing, red for halted, yellow for everything in between,
and only on a tty. The `STATUS` column of `list` is the same word with its
duration.

The `stop` row in the session block is what is left of the current config's
budget -- not the campaign's end; the session header says whether more configs
or a loop follow -- shown
as left / budget with its clock: `17h18m / 24h00m (fuzzing)`, `3h00m / 8h00m
(total)`, or `at 19/10 16:00 (2h00m, real)` (the real clock is the only one
that names a moment). `list` has the same in its
`STOP` column. A fuzz-clock budget does not move while triaging, so that row
can read the same for the whole of a minimization; that is the budget working
as designed, not a stuck counter.

Two things bring it to you with no command typed, because on this box there is
often no time for one between two panics:

- **A Terminal window running `status -w`**, opened by the driver at every start
  — i.e. after every panic-reboot, the moment auto-login lands — and also when
  the driver is about to exit on a brake or a halt, which is exactly the status
  you want to see. A launchd relaunch with a watch already on screen does not
  stack a second one. Author with `new ... --no-watch-window` to turn it off.
- **A macOS notification** when fuzzing starts, on each triage advance, on every
  crash once the coordinator has decided what it was (signature, BUG id, kext,
  decision), and on halt/done. Booting and preparing stay quiet: they happen on
  every reboot. The first notification may make macOS ask, once, whether
  `osascript` may notify in the fuzz session — allow it.

Both are skipped off macOS and under `FUZZ_NO_GUI=1` (set it when driving a
campaign from an ssh shell you do not want windows popping out of). Only the
driver's own `cmd_run` opens the window; `status` run by hand never does.

Each recent incident says what the crash turned out to be: its signature, its
BUG id in the registry, the kext the backtrace blames, and what the coordinator
decided. A crash in a kext other than the fuzzed one is called out — the config
names no kext, so "fuzzed" means the workdir's kext directory and the services
the config opens:

```
  last 4 incident(s):
    when            kind   ran  sig       bug       kext                    decision
    19/10 09:47:22  crash  84s  77ab10c3  BUG-0004  AppleSMC                suspect
    19/10 11:37:22  crash  84s  77ab10c3  BUG-0004  AppleSMC                triage demo_triaging_t0
    19/10 13:12:22  crash  84s  1c2e8800  BUG-0009  IOSurface (NOT fuzzed)  suspect
    19/10 14:33:22  crash  84s  3f2a9c01  BUG-0007  AppleSMC                triage demo_triaging_t1
```

While triaging, the `triage` block reads the job's checkpoint: subsets tested and
crashed, the subset under test, panics from other bugs, hangs — or, during the
ring replay, the pass and slot.

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

`status` reports four disjoint clocks plus their sum, for the whole campaign:

```
  time breakdown (whole campaign):
    preparing   : 0h06m  (until first exec)
    fuzzing     : 4h12m  (first exec -> end of run)
    minimizing  : 0h51m  (triage)
    rebooting   : 0h23m  (panic -> back up)
    total       : 5h32m
```

`total` is what `--budget-clock wall` measures; `fuzzing` is what the `fuzz`
clock measures, and is still not pure execution time — `runstats.py show` reads
syz-manager's own counter for that.

A run's **preparing** stretch is everything from the coordinator opening it
(snapshot, results commit, manager launch, grammar compile, executor handshake)
to the first stat line with `exec total > 0`. **fuzzing** runs from there to the
run's last sign of life — the newest run-log line or cover-log write — not to
the moment the death was noticed. That matters on this target: nearly every
crash is noticed on the next boot, and measuring to then charged the reboot as
fuzzing. A triage advance cut short by its own crashing probe is split the same
way: minimizing up to the last probe, rebooting after it.

`--budget-hours` measures **wall** by default: preparing plus fuzzing plus
minimization plus reboot overhead. That is "give this config 24 hours of machine
time", which is what comparing one configuration against another needs.
`--budget-clock fuzz` charges the fuzzing line only, so neither startup nor a
stubborn bug's minimization can eat the budget. `--budget-clock real` is elapsed
time since the config started, startup included: ask for 1h and it stops 1h
later. `wall >= fuzz` always, so the default can only end a campaign sooner.

> **`fuzzing` in `status` is still not time executing programs.** The manager
> also re-triages its corpus and waits on RPC; on a measured run only **56%** of
> uptime was execution (18.9 h alive → 10.7 h executing). For the real figure,
> `runstats.py show <run>` reads syz-manager's own counter and prints an
> `efficiency` line.

Budget in wall hours, report in fuzzing hours. Both totals are always kept, so a writeup can
say "24h fuzzing, 31h wall, of which 4h minimization" rather than picking one
number and hiding the rest. Nothing accrues while the campaign is halted or idle,
and a reboot gap is charged at most `max_boot_gap_seconds` (15 min), of which at
most `max_relaunch_seconds` (5 min) for boot-to-relaunch; the rest is treated as
idle rather than overhead — otherwise the wall clock would measure your sleep
schedule.

### When triage gets STUCK

Minimization can finish without a verified reproducer. That is a **result**, not a
failure, and re-running will not improve it. The job's `stuck_kind` says which:

| kind | what happened | what the campaign does |
|---|---|---|
| `unverified` | a connection subset crashed during the search but not when re-run on its own: the bug needs state an earlier program left behind | benches the selectors anyway; the dossier records an *unverified lead* |
| `no-repro` | no subset reproduced, **and** the ring replayed exactly as fuzzed did not crash either | benches nothing; the signature is *exhausted* |
| `ring-only` | no subset of the merged program reproduced, but the ring replayed as fuzzed crashed twice: merging loses what the bug needs. The ring is kept in the job as `ring/` | benches nothing; *exhausted* |
| `ring-unverified` / `ring-other` | the ring crashed once only / panicked with a different bug | benches nothing; *exhausted* |
| `hang` | the job hung 3 times (each hang costs a reboot) | benches the hung program under its own quarantine key `hang:<job>`; the target is *exhausted* |

When the connection culprit was verified but the call stage cannot reduce it, the job
still ends `DONE`, with the connection culprit as the reproducer.

An **exhausted** signature is not triaged again (that would repeat the same answer).
Its recurrences are counted in the quarantine, and after `tolerate_budget` (4) of them
the newest program in the ring buffer is benched as an *unverified lead* so it stops
costing a reboot each time. `fuzz-campaign.py forget-exhausted <campaign> [sig]`
allows a new triage once the cause is fixed.

If the budget runs out while a job is in progress, the job is finished first, its
result benched, and then the campaign moves to the next config.

### A second bug during triage

A probe that panics the box with a **different** signature is not counted for the
bug being minimized (the crash gate filters it), but it is not lost either. The
coordinator log says `SECOND BUG during triage`, the panic is filed in the bug
registry as `fuzz-during-triage` (a genuine sighting), the quarantine records it as
SUSPECT, and the subset that crashed is saved as `other_<sig>.syz` in the job. A
triage for it is queued (`status` shows `triage queue`) and starts when the current
job ends, from that one program. The queue is dropped when the config's budget is
spent or the campaign moves to another config; the bug stays SUSPECT, so its next
recurrence while fuzzing is triaged as usual.

### Switching which campaign runs

Author another def, then install its own agent (each campaign gets its own label).
Only ever run **one** at a time — they share `/dev/pishi`.
