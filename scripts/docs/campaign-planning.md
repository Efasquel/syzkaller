# Campaign planning — redesign

Status: revision 5, 2026-10-22, being implemented. Phases 1, 2a and 2b are in
the code (2026-10-23/26); phases 3, 4 and 5 are not -- see §11 for what each
covers and §12 for the decisions taken on the way. A simulator of the whole
model lives in `playground/` (§13).

What drives it:

1. **The box goes idle between campaigns.** One launchd agent runs one
   campaign; when it ends nothing starts the next.
2. **Evaluation needs repeated runs from scratch.** A config must be run
   several times (3×) on a fresh corpus, a fresh quarantine and fresh triage,
   so that the samples are independent. Today the corpus, the session and the
   quarantine are keyed by config id and shared by every campaign that fuzzes
   that config: a "rerun" silently continues the previous one.
3. **A campaign's files are spread over six places**, keyed three ways, some
   hidden, and a campaign writes into the authored configs.
4. **Too many log files, and the wrong things in them** (§6).
5. **The operator verbs are too coarse.** You can't end the current config
   early, skip a pending one, or halt one campaign without stopping the box.
6. **Optionally, a too-long plateau should move on** to the next config. This
   is opt-in, never the default.

Underneath all of these: **scheduling is not a thing in the code.** It is the
~250-line `while True` in `cmd_run`, interleaved with supervision, triage and
halting, and testable only by driving the whole loop.

---

## 1. Today

### Files

```
<tree>/
  STOP                                    global brake
  config/<id>.cfg                         authored config -- REWRITTEN by the campaign; git-ignored
  campaigns/
    <name>.json                           definition
    bugs/                                 global bug ledger (not a campaign)
    .state/
      <name>.json                         runtime state
      <name>.lock .brake .watch.command
      <name>.coordinator.log .launchd.log .results.log
      quarantine_<config-id>.json         keyed by CONFIG: shared by every campaign
      leads/  queued/                     evidence, no campaign in the path
  sessions/<config-id>.json               keyed by CONFIG
  workdir/<Driver>/<variant>/             keyed by CONFIG: corpus, ring, artifacts, results/
  triage/<name>_t<N>/  triage/.state/     campaign only in the job name
```

- **Nothing about a campaign is fresh except its state file.** A second
  campaign on the same config resumes the first one's corpus, ring buffer,
  quarantine and session, and appends to the same `progress.jsonl` with a clock
  that restarted (its x-axis goes backwards).
- **The authored config is mutable state.** `apply_disabled` rewrites
  `config/<id>.cfg`, which is why `sync-fuzz-run.sh` has to work around it and
  republish without overwriting the box's `disable_syscalls`.
- **The experiment is not in git.** `*.cfg` is ignored, so the definition of
  what was fuzzed lives only on disk, and only until the quarantine rewrites it.
- **`.state/` is not ephemeral.** It holds quarantine decisions and evidence
  next to lock files.

### Scheduling

- A flat ordered list of configs, each with one budget. `new` sets the same
  budget for all of them, and one clock applies to the whole campaign.
- Progress is `cursor`, an **index** into that list. Edit the definition
  mid-campaign and the cursor silently lands on a different config.
- The only stop conditions are budget spent, `max_crashes` reached and the
  breakers. Operator control is `halt`, `resume`, `stop` and the brake.

---

## 2. Principles

1. **An item owns everything it produces.** Corpus, quarantine, ring buffer,
   triage jobs and progress curve all live under the item. Nothing is reused
   across items or campaigns, apart from the global bug ledger, which exists to
   dedup across them.
2. **Inputs are read-only.** `config/` is never written by a run.
3. **No hidden directories hold data.** Ephemeral files live in `run/` and can
   be deleted whenever nothing is running.
4. **Plan items have a stable identity.** State is keyed by item id, never by
   position.
5. **Scheduling is a pure function**: `(plan, state, observations) -> step`.
6. **One writer per file.** Only the runner writes `state.json`. Operator
   commands are *requests* the runner applies (§5). That removes the race the
   code already works around, where `halt` was overwritten by a stale save.
7. **One box, one agent.** A panic reboots everything, so only one campaign
   ever runs; the agent belongs to the box.
8. **Hand-write the experiment, generate the rest.** What an evaluation varies
   is written by hand in a config; what must be identical across the configs
   compared (the machine) is written once and merged in by the runner, so a
   comparison cannot be broken by a stray key.

---

## 3. The plan references configs; the box is an overlay

A syzkaller config mixes three kinds of field with different owners:

| kind | fields | owner |
|---|---|---|
| **box** | `target`, `syzkaller`, `type`, `procs`, `sandbox`, `reproduce`, `kernel_obj`, `kernel_obj_file`, `http`, `kext_coverage.kcov_device` | the machine; identical for every campaign on it |
| **experiment** | `enable_syscalls`, authored `disable_syscalls`, `cover`, `kext_coverage.kext_id`, `ring_buffer_size`, `executor_name` | the config, written by hand: this is what an evaluation varies |
| **runtime** | `workdir`, `kext_coverage.cover_log`, quarantine additions to `disable_syscalls` | the runner, per item |

(The box set is `BOILERPLATE_KEYS` in `fuzz-session.py`, which already treats
those fields as boilerplate copied from a template — generated once, then free
to diverge, which is what `config lint` exists to catch.)

So:

- **`config/<id>.cfg` stays the unit you author**, with `fuzz-session.py config
  new`, globs, whole-line `#` comments and the `-no23` style exclusions, as
  today. It holds the experiment fields. It *may* still carry box fields.
- **`config/box.json` holds the box fields, once per machine.** On the dev tree
  and on the box it differs only in two paths.
- **The runner renders each item's effective config** as

  ```
  effective = box.json  ⊕  config  ⊕  runtime
  ```

  A box key set explicitly in the config **wins**, and `plan check` reports it
  as drift from `box.json`. That keeps every existing config running unchanged
  and lets you strip them when you touch them (`config lint --strip-box`).
  Runtime keys a config still carries (`workdir`, `cover_log`) are **replaced**
  and listed as `ignored: … (rendered per item)` -- every config written by
  `config new` before this carried them, so rejecting them would reject all of
  them.

- **`config/*.cfg` and `campaigns/<name>/campaign.json` are tracked in git.**
  Once nothing writes into configs they stop churning, so an experiment
  (campaign + configs) is reproducible from a commit. The box's copies are produced by sync and stay
  untracked there.

### Format

```json
{
  "name": "fde_eval",
  "clock": "fuzz",
  "defaults": {
    "max_hours": 6,
    "max_plateau_hours": null,
    "reuse_known_culprits": false
  },
  "items": [
    {"config": "config/AppleFDEKeyStore_gram.cfg"},
    {"config": "config/AppleFDEKeyStore_gram.cfg"},
    {"config": "config/AppleFDEKeyStore_gram.cfg"},
    {"config": "config/AppleFDEKeyStore_gramsel.cfg", "max_hours": 12},
    {"config": "config/AppleFDEKeyStore_gramsel.cfg", "max_hours": 12},
    {"config": "config/AppleFDEKeyStore_gramsel.cfg", "max_hours": 12}
  ],
  "limits": {"max_crashes": 20, "min_free_gb": 20, "crashloop_limit": 15}
}
```

- **An item is one run of one config, from scratch.** Running a config three
  times is listing it three times; the list order is the run order. There is no
  `trials` knob and no `order` knob: you choose both by writing the list.
  `new … --repeat 3` is sugar that writes the entries out, so the plan always
  shows them.
- **`id`** is optional. Omitted, `new` derives it and **writes it into
  `campaign.json`**: `<config-id>-1`, `-2`, `-3` — always suffixed, so a config
  run once is `AppleFDEKeyStore_gram-1`, and the first sample's folder never
  repeats the config's name. Written down, an id stays put when entries are
  inserted later; a derived one is the entry's position among those of its
  config, so an insertion would hand a finished sample's record to another
  entry. (An entry you add by hand without an id is still derived, the same
  way, when the campaign is read.) Ids are `[A-Za-z0-9_-]` (they are folder
  names and part of the session id) and unique within the campaign.
- **An item's `config` must be a `.cfg`** whose `enable_syscalls` is not
  empty: `new`, `plan check` and `doctor` refuse otherwise. `box.json` is not a
  config, and an empty list is read by syz-manager as every syscall.
- **`max_hours`** replaces `budget_hours`, with the same clocks (`wall` /
  `fuzz` / `real`; `real` by default, see §12). `new --item id=…,max=…` gives per-item values from the CLI.
- **`reuse_known_culprits`** (default `false`): when a crash's signature maps
  to a bug whose reproducer is already **verified** in the global ledger, the
  item's quarantine benches that culprit at the **first sighting**, with no
  triage job, and the sighting is recorded with campaign and item. The one-off
  rule (nothing benched on a single crash) guards against a crash that would
  not reproduce; a verified reproducer answers that already. Off by default
  because a strict evaluation of time-to-reproducer wants every sample to pay
  its own minimization; on, it saves tens of boots per known bug per sample.
- **`loop` is dropped.** A hunt is a plan with a long `max_hours`; "run
  forever" is queueing the plan again (§7).
- **Whole-line `#` comments are allowed** in plans, read by the same `cfgutil`
  rule as configs.
- **`fuzz-campaign.py plan check <name>`** renders every effective config
  without running anything: the item table (id, config, hours, enabled
  syscalls, drift from `box.json`), `items × hours = total`, and the lint `new`
  does today (shared workdirs can no longer happen; it still flags a missing
  `executor_name`).
- `fuzz-session.py config new` and manual sessions on `config/*.cfg` are
  unchanged.

### One kind of thing: the campaign

`new <name> <configs…>` creates `campaigns/<name>/` with `campaign.json`,
`state.json` (status `new`) and `README.md`; `install <name>` runs it. There is
no separate plan object: a campaign's definition lives where it runs, and
`campaign.json` and `README.md` are the two tracked files of a campaign folder
(the experiment and its write-up), everything else in it being runtime. The
driver reads the normalized `campaign.json` as it is -- there is no second,
flat shape of it. `new <name2> --copy <name>` copies another campaign's
definition into a new one, with any flag given alongside overriding -- that is
how an experiment is run again. (A campaign created before the rename has
`plan.json`, which is read in its place.)

The runner reads `campaign.json` when it starts, so today an edit takes effect
at the next driver start (on this box, the next panic-reboot). Re-reading it at
every scheduling step is the intent -- append or remove pending items, change
their limits -- and is not implemented yet; it must keep the last good
definition when an edit does not parse. Removing a running item is rejected;
use `next`.

### State

```json
"cursor": "AppleFDEKeyStore_gramsel-2",
"items": {
  "AppleFDEKeyStore_gram-1":    {"status": "done",    "reason": "max_hours", "clocks": {…}, …},
  "AppleFDEKeyStore_gram-2":    {"status": "done",    "reason": "next", …},
  "AppleFDEKeyStore_gram-3":    {"status": "skipped", "reason": "skip", …},
  "AppleFDEKeyStore_gramsel-1": {"status": "running", …},
  …
}
```

`cursor` holds an *id*, and the runner derives it from the statuses. It is
stored only so `status` can show it.

An item's `status` is one of `pending | running | done | abandoned | skipped`.
Its `reason` always says why it ended: `max_hours`, `plateau`, `next` (all
`done` — an item cut short by `next` is still a sample, and the reason is
visible), `max_crashes` (`abandoned`), or `skip` (`skipped`). An item that
ran keeps its clocks, crash counts and bug ids whatever the reason, so a
running item cut by `skip` is left out of the samples but not out of the
record.

---

## 4. Folder layout

```
<tree>/                                    (/Users/Shared/fuzz-run on the box)
  config/box.json                          INPUT: this machine's box fields; never overwritten by sync
  config/kext_ids.json                     INPUT
  config/<id>.cfg                          INPUT, tracked: the experiments

  campaigns/                               runs; only campaign.json and README.md are tracked
    queue.json                             what the box runs (§7) -- phase 3, not yet present
    <name>/                                created by `new`; `install` runs it
      campaign.json                        INPUT, tracked in git (§3)
      README.md                            tracked: the write-up
      state.json
      campaign.log                         the one log to read (§6) -- phase 4; until then
                                           the logs stay in campaigns/.state/<name>.*.log
      <config-id>/                         one folder per config in the plan
        <item-id>/                         one sample of it, from scratch
          <name>.<item-id>.cfg             EFFECTIVE config, rendered (§3): exactly
                                           what syz-manager ran, kept as the record
          item.json                        what the item is: config, paths, session id
          quarantine.json
          workdir/                         syz-manager's workdir
            corpus.db ring_buffer/ grammar/ snapshots/ artifacts/
            results/  run-<ts>.log  executor-<ts>-<n>.log  progress.jsonl  cover-*.log
          triage/t<N>/                     jobs born in this item
          leads/  queued/

  bugs/                                    global ledger (moved up from campaigns/bugs)
  sessions/                                fuzz-session registry (unchanged format)
  workdir/  triage/                        manual, non-campaign use only

  run/                                     EPHEMERAL, one set per campaign
    <name>.lock  <name>.brake  <name>.requests.json  <name>.watch.command
    box.out                                launchd's stdout -- phase 4, not yet present
  STOP
```

- **`campaigns/<name>/` is the whole campaign, grouped by config**, and
  `<config-id>/<item-id>/` is one sample of it. `ls <config-id>/` shows a
  config's samples side by side (`AppleFDEKeyStore_gram-1 -2 -3`), which is the
  comparison an evaluation makes. Archiving a campaign is a single `mv`.
- **Triage job numbers `t<N>` are unique across the whole campaign**, even
  though each job lives under its item. That way `t7` in `campaign.log` names
  exactly one folder.
- **The session id is `<name>.<item-id>`**, which is also the effective
  config's file stem. Campaign names and item ids are `[A-Za-z0-9_-]`, so the
  id splits unambiguously at its one dot. `fuzz-session.py` derives the session
  id from that stem, so items never collide in `sessions/`.
- **`config/` stays as authored, and `sync-fuzz-run.sh` simplifies.** No
  campaign writes into configs any more, so there is no `disable_syscalls` to
  carry over. Configs are copied verbatim; the path rewriting remains only for
  configs that still carry box keys. **`config/box.json` is created on the box
  once and never overwritten by sync** (sync warns when the repo's copy
  differs).
- **The quarantine sits next to the corpus it filters**, both per item.
  syz-manager prunes `corpus.db` against `disable_syscalls`, so they belong
  together.
- **The bug ledger stays global**, because dedup across items is its job. Each
  `crashes[]` entry records `campaign` and `item`, so "how many samples found
  BUG-0007" is a query, and `reuse_known_culprits` reads the verified
  reproducer from it.
- **`runstats.py` / `fuzz-results.py`** keep their unit, "one workdir = one
  run". They learn to discover workdirs under `campaigns/*/*/*/workdir` and to
  group them by the config they reference. That gives mean ± spread over 3
  samples directly.
- **Optional seed corpus:** an item may set `"seed": "<snapshot dir>"` to start
  from the same corpus instead of empty. Off by default: "from scratch" means
  an empty corpus.

---

## 5. Operator verbs

| verb | effect |
|---|---|
| `next <name>` | End the running item now (`reason: next`) and move to the next one. |
| `skip <name> <item>` | Mark a pending item `skipped`. If the item is the one running, it ends now like `next`, but as `skipped` (reason `skip`) with its clocks and counts kept: the operator left it out of the samples. `unskip` reverts it for items that haven't run yet. |
| `halt <name>` | Halt **this campaign**: stop its manager, keep its state, and let the box move to the next campaign in the queue. |
| `resume <name>` | Put a halted campaign back at the **front** of the queue; it continues where it stopped. |
| `stop` / `STOP` / brake | Box-level, unchanged: stop everything, and start nothing. |

**Mechanics.**
- While a runner is up, each verb appends to `run/<name>.requests.json`, an ordered
  list `[{verb, campaign, item, at}]`. The runner already polls for a stop every
  `stop_check_seconds` (5 s), and now applies the pending requests, in order, at
  that point, then clears the file. Two verbs issued within one poll are both
  honoured (`skip B` then `next`: B is skipped and the current item ends).
- `status` shows the pending requests until they are applied.
- With no runner up, the request simply waits: whichever runner comes next
  (after a reboot, after `resume`) applies it. Verbs never edit the state
  themselves, so the file keeps exactly one writer. (Phase 1 ships this;
  `halt`/`resume` keep today's direct path until the queue gives `halt` its new
  meaning.)

**`next` / `halt` during triage.** The running triage job is left `stopped`
rather than abandoned: it remains resumable by hand with `triage.py`. Its
benches stay in that item's quarantine. (`next --finish-triage` lets the job
finish first.)

---

## 6. Logs

### Today, per campaign

| file | contents | problem |
|---|---|---|
| `.state/<name>.coordinator.log` (+`.1`) | coordinator decisions | readable, but duplicated into the next one |
| `.state/<name>.launchd.log` | **everything**: decisions again, plus the stdout of every subprocess, including triage's per-probe chatter (33k of 119k lines in one campaign) | catch-all; **truncated in place at 25 MB**, so evidence is lost exactly on the long, crash-heavy runs |
| `.state/<name>.results.log` | fuzz-results commit output | rarely read; a failure is already logged as a pointer |
| `workdir/…/results/run-<ts>.log` | syz-manager stdout, one per run | fine |
| `workdir/…/results/executor-<n>.log` | executor stdout | **opened `"w"` on every start**: overwritten by the next run unless an incident happened to collect it |
| `triage/.state/<job>.launchd.log` | standalone triage only | campaign-born jobs have no log of their own; they go into the catch-all |

### Proposed

The rule is **every process writes to its own file, in the directory of what it
is working on.** Nothing inherits the runner's stdout.

| file | contents |
|---|---|
| `campaigns/<name>/campaign.log` | **The one log to read.** Every coordinator decision, one line each, tagged with the item: `14:02:11 [AppleFDEKeyStore_gram-2] crash → triage t3`. It holds the runner's lifecycle, item start/end with reason, incidents, triage start and outcome, operator requests applied, and a one-line result for each results commit (plus a tail on failure). Rotated by rename, never truncated. |
| `<config>/<item>/workdir/results/run-<ts>.log` | syz-manager, per run (unchanged) |
| `<config>/<item>/workdir/results/executor-<ts>-<n>.log` | executor, **per run**, no longer overwritten |
| `<config>/<item>/triage/t<N>/triage.log` | the job's own decisions (merge, minimize steps, outcome) |
| `<config>/<item>/triage/t<N>/probes.log` | per-probe chatter, kept for forensics (you cannot know in advance which job ends STUCK); **capped per job**, rotated by rename at ~20 MB, and never anywhere else |
| `run/box.out` | launchd's stdout/stderr for the runner. Expected to be **near-empty**: only an interpreter traceback or a launchd-level failure. |

This removes the launchd catch-all, `results.log` and the duplicated decision
stream: each campaign has **one** log file instead of three. Per-run and
per-job files exist because their content belongs to that run or job.

One reader for all of them: `fuzz-campaign.py log <name> [-f] [--item ID]
[--triage tN] [--manager|--executor|--probes]` picks the right file or files.
You never need to remember paths. `log <name> -f` is the `tail -f` you watch
during a run.

All of our own logs use the same timestamp format (`timefmt.stamp()`).
syz-manager's format is left alone.

---

## 7. Campaign queue

- One launchd agent for the box (`install --box --user fuzz`). It runs
  `fuzz-campaign.py run` with no name, which drains `campaigns/queue.json`.
  The per-campaign agent goes away.

  ```json
  {"queue": ["fde_eval", "bt_sweep"],
   "history": [{"name": "drivers_260902", "ended": "…", "status": "done"}]}
  ```

- When the head campaign ends, it moves to `history` and the next one starts,
  with no login or reboot needed.
- Commands: `queue add <plan> [--as <name>] [--at N]`, `queue rm`, `queue mv
  <name> N`, `queue ls`. The runner re-reads the queue only between campaigns.
- How a campaign's end affects the box:

  | campaign ends because | box |
  |---|---|
  | done, every item abandoned or skipped, `halt <name>` | next campaign |
  | low disk, crash loop, repeated startup failures | **stops**: the fault is the box, and the next campaign would hit it too |
  | `stop`, `STOP`, brake | stops |

- `status` with no name shows the box: the running campaign and its item, the
  pending requests, and what is queued next.

---

## 8. Plateau (opt-in)

`max_plateau_hours: H` (per item or in `defaults`; `null` by default): if no
new basic block was found in the last **H hours of fuzzing**, end the item with
`reason: plateau` and move on.

- **Signal:** `blocks` in the item's `progress.jsonl`, the union of the cover
  logs. It is cumulative and survives restarts.
- **Axis:** the fuzz clock (`fuzz_s`), whatever budget clock the plan uses.
  Triage and reboots aren't stagnation.
- **Restart:** the window restarts whenever the effective `disable_syscalls`
  set changes, because a re-enabled or newly benched syscall changes the attack
  surface.
- **Validation:** `new` and `doctor` reject an `H` shorter than 6 samples
  (`poll_seconds` is 10 min).
- **Fair comparisons:** `plan check` **warns** when a config is listed more
  than once and a plateau is set. Samples then end at different fuzz times, so
  they no longer compare equal budgets.
- `status` shows the item's time since its last new block, so you can see a
  plateau coming before it ends the item.

---

## 9. Code structure

New module `scripts/lib/schedule.py`, pure, with no I/O:

```python
def stop_reason(item, istate, plan, requests, obs) -> str | None
    # max_hours / plateau / max_crashes / pending operator request
def next_step(plan, state, requests, obs) -> Step
    # Run(item) | End(item, reason) | Done() | Halt(reason)
```

`cmd_run` becomes the box runner. It picks a campaign from the queue, then
loops `next_step` → execute → persist. `supervise` asks `stop_reason` on each
poll instead of comparing against a budget. Triage, supervision, accounting and
reconciliation are unchanged. They execute steps; they don't choose them.

---

## 10. Compatibility

Only finished campaigns need to survive.

- `fuzz-campaign.py migrate` moves each finished legacy campaign into
  `campaigns/<name>/`:
  - its definition becomes `campaign.json`, one item per config, and every
    runner setting it overrode becomes a `limits` override;
  - its state and coordinator log are moved there;
  - it is marked `legacy: true`, so `run` refuses to resume it.
- Its `workdir/`, `triage/` jobs and quarantine file stay where they are, and
  the state records their paths, so dossier links keep working.
- `migrate` refuses while anything runs. `migrate --strip-disable-syscalls`
  (opt-in) strips `disable_syscalls` from the box's `config/*.cfg` so the next
  `sync` makes box and repo identical; by default the configs are left alone.

---

## 11. Phasing

Each phase ships alone and leaves the box working.

1. **Scheduler and verbs** -- done 2026-10-23:
   - `lib/schedule.py` and item-keyed state, with no behaviour change, covered
     by table tests of `next_step`;
   - the request list, plus `next`, `skip`/`unskip`; `halt`/`resume` keep
     today's meaning until phase 3.
2. **Plan, box.json, layout and repeats:**
   - (2a, done 2026-10-23) the plan format, `box.json` as an overlay with
     drift reporting, rendering effective configs, `plan check`, `config lint
     --strip-box`, and tracking `campaigns/<name>/campaign.json` (named
     `plan.json` until 2026-10-27) and `config/*.cfg` in git;
   - (2a) the campaign directory grouped by config, items from scratch,
     per-item quarantine and triage, `reuse_known_culprits`;
   - (2b, done 2026-10-26) `bugs/` moved up, `run/`, and `migrate`;
   - (2b) `sync-fuzz-run.sh` simplified (verbatim configs, `box.json` left
     alone);
   - (2b) `runstats.py` / `fuzz-results.py` grouping samples by config.
3. **Queue** -- pending: the box agent, `queue add --as`, the `queue` verbs,
   `halt` meaning "the box moves on", and box-level `status`. The idle box is
   driver #1, and phase 2 already puts new files in their final place, so this
   does not wait for the log work.
4. **Logs** -- pending: subprocess output redirected to the per-run and
   per-job files, `campaign.log`, the `log` command, per-run executor logs,
   and the capped `probes.log`.
5. **Plateau** -- pending: opt-in `max_plateau_hours` (`new` already stores
   it; nothing enforces it yet).

---

## 12. Decisions (formerly open questions)

- **Q1 — syscall lists** stay in hand-written configs; the plan references
  them (§3). No inline lists, no file references.
- **Q2 — starting point:** "from scratch" is an empty corpus. `seed` is an
  opt-in per item.
- **Q3 — order:** there is no `trials`/`order`; the item list is the order,
  and repeats are entries in it.
- **Q4 — `next`/`halt` during triage:** the job is stopped and stays
  resumable; `--finish-triage` waits.
- **Q5 — probe chatter:** kept, capped per job.
- Known bugs across samples: `reuse_known_culprits`, off by default, benches
  at first sighting when on.
- Requests are an ordered list; ids and names are `[A-Za-z0-9_-]`; `loop` is
  dropped; `box.json` is an overlay with drift reporting; configs and plans
  are tracked; a plan can be queued many times under different campaign names.
- **Default clock is `real`**: an item asked for 6h ends 6h after it started,
  through halts and reboots, so the operator knows when the box frees up.
  `wall` and `fuzz` are opt-in via `--clock`.
- **`max_crashes` is per item.** One abandoned item is a sample outcome and
  the campaign moves on; only when *every* item ended abandoned does the
  campaign halt, as `HALTED/MAX_CRASHES`. There is no `ABANDONED` halt kind.
- **No `plans/` directory, no freeze.** `new` creates `campaigns/<name>/`
  directly, with the plan where it runs; `new --copy <other>` reuses a plan,
  and `install` only installs the agent.
- **Triage jobs have short names** (`t1`) in `status`, in the notifications
  and in the hang quarantine key; the job is addressed by its directory
  under the item.

---

## 13. Simulator

`playground/sim.py` is this model in miniature, driven by a fake box (a clock
you advance, random crashes, fake triage). `python3 playground/sim.py demo`
plays a full evaluation end to end — plans, `box.json` drift, repeats, the
grouped tree, `skip`/`next`, the queue draining into a second
campaign that benches known bugs without triage — and `sim.py tree` shows the
folders it produced. It is the reference for the layout and the verbs until
the real thing exists; `playground/README.md` has the step-by-step commands.
