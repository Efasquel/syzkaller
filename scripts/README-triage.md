# Crash-minimization & triage

After the fuzzer finds a crash, this pipeline turns the ring buffer of crashing
programs into a **minimal, verified reproducer** and deduplicates every panic it
sees along the way. It is built for a bare-metal Darwin target that **reboots on
every crash**, so each stage is crash-safe and resumable across reboots.

Two ways to use it:

- **Automated** — `triage.py` drives the whole thing as a resumable state
  machine (recommended). Jump to [Automated](#automated-triagepy).
- **Manual** — run the `syz-ring-repro` stages yourself, one at a time. Jump to
  [Manual](#manual-syz-ring-repro-stages) to understand what each stage does.

The tools:

| tool | role |
|---|---|
| `bin/darwin_arm64/syz-ring-repro` | merge + minimize a ring buffer to `culprit.syz` |
| `bin/darwin_arm64/syz-ring-repro -emit-json` | translate a `culprit.syz` into a `syscalls.json` list of names to disable |
| `scripts/crash_fingerprint.py` | fingerprint a panic report; dedup across reboots |
| `scripts/triage.py` | orchestrate merge → minimize → done, capturing panics |
| `scripts/fuzz-campaign.py exclude` | bench the culprit's syscall(s) in the crashed config |
| `scripts/fuzz-campaign.py include` | rotate benched syscalls back into the config (inverse of exclude) |

---

## The pipeline

```
ring_buffer/            (N crashing programs from the fuzzer)
   │  merge + static reduce           syz-ring-repro -merge -static
   ▼
merged.syz              (one program, inert calls dropped)
   │  minimize connections            syz-ring-repro -minimize-conn
   ▼
culprit.syz             (minimal crashing set of IOKit connections)
   │  minimize method calls           syz-ring-repro -minimize-calls
   ▼
culprit.syz             (also minimal in IOConnectCallMethod calls) ✓ verified
```

Each `-minimize-*` stage tests subsets on the device. A subset that reproduces
**panics the box and reboots it**, killing the driver; the stage checkpoints to
`conn_state.json` / `call_state.json` first, so on the next boot it resumes
exactly where it left off. The minimal culprit is re-run **alone on a fresh
boot** to confirm it reproduces in isolation before it is accepted.

---

## Automated (`triage.py`)

### 1. Author a job

```sh
scripts/triage.py new mybug \
    --ring    workdir/AppleJPEGDriver/<run>/ring_buffer \
    --kext-id 1
    # optional device flags, passed through to syz-ring-repro:
    #   --kcov-device /dev/pishi   --sandbox none   --max-k 3
    #   --executor <path>          --ringrepro <path>
    #   --from -1 --to 0           (ring range: oldest..newest)
```

This creates `triage/mybug/` for artifacts and `triage/.state/mybug.json` for
state. Nothing runs on the device yet.

### 2. Run it

Each `run` advances the job as far as **one boot** allows, then exits (or is
killed by a reboot). Because a crashing subset reboots the box, you relaunch
after each reboot — either by hand:

```sh
scripts/triage.py run mybug      # repeat after every reboot until DONE
```

…or autonomously, with a launchd agent that relaunches it on every boot:

```sh
scripts/triage.py install mybug     # RunAtLoad → one relaunch per crash-reboot
scripts/triage.py uninstall mybug   # when done
```

### 3. Watch / collect

```sh
scripts/triage.py status mybug      # stage, final reproducer, crash ledger
scripts/triage.py list              # all jobs
```

When the job reaches **DONE**, the minimal reproducer is at
`triage/mybug/culprit.syz` and every distinct panic seen is in
`triage/mybug/signatures.json` (reports archived under `triage/mybug/reports/`).

### What it captures at every crash

On each launch, before advancing, `triage.py` scans the panic dirs for reports
newer than its watermark, fingerprints each, and dedups them:

- the **first** panic fixes the job's **target signature** (the bug being
  minimized);
- a later panic with the **same** signature is expected (recorded as `known`);
- a panic with a **different** signature is **flagged** — minimization tripped a
  *second* bug, which you should know about before trusting the reproducer.

---

## Manual (`syz-ring-repro` stages)

Run the stages yourself when you want to inspect intermediate output. Paths
default next to the program file; override with `-state` / `-culprit`.

```sh
RR="bin/darwin_arm64/syz-ring-repro -executor bin/darwin_arm64/syz-executor -kext_id 1"
D=workdir/AppleJPEGDriver/<run>

# 1. Merge the ring buffer into one program, dropping IOKit-inert calls.
#    Offline (no device, no reboot).
$RR -merge $D/merged.syz -static $D/ring_buffer

# 2. Minimize to the smallest crashing set of connections. On device; reboots
#    on each crash. Re-run after every reboot until it completes — it resumes
#    from $D/conn_state.json and writes $D/culprit.syz.
$RR -minimize-conn $D/merged.syz

# 3. Minimize the method calls (keeps every open/close). On device; same
#    resume-after-reboot loop. Point it at the connection-minimized culprit.
$RR -minimize-calls $D/culprit.syz
```

### Peek at the current best culprit mid-run (offline)

While a `-minimize-*` stage is between reboots, you can materialize the smallest
crashing subset found so far without touching the device:

```sh
$RR -emit-culprit -state $D/conn_state.json -culprit $D/candidate.syz $D/merged.syz
#   exit 0 = a candidate was written · exit 1 = no crashing subset recorded yet
```

The state file stores only bitmasks, so the **program file is still required**
(it resolves a mask back into calls). Use the same program the stage ran on.

### Crash gating (don't minimize toward the wrong bug)

The minimizer's crash signal is **reboot-as-crash**: a subset that panics the box
is recovered as a repro on the next boot. On its own that counts *any* reboot —
so a *second* bug that fires during a probe would be misattributed to that subset
and the search would minimize toward the wrong crash.

Gating fixes this. Give `syz-ring-repro` the target signature and a confirm
command; after each reboot it checks whether a fresh panic report actually
fingerprints to the target before counting it:

```sh
$RR -minimize-conn \
    -target_sig <sig> \
    -confirm_cmd "python3 scripts/crash_fingerprint.py match-since --dir /Library/Logs/DiagnosticReports" \
    $D/merged.syz
```

`syz-ring-repro` appends `<target_sig> <since_epoch>` and reads the verdict:
`match`/`none` count as the target crash (a genuine repro whose report we can't
read is never dropped); `other <sig>` means a **different** bug rebooted, so that
subset is recorded as a non-repro instead. Unset `-target_sig` = original
behavior (any reboot counts). `triage.py` and the campaign coordinator pass these
flags automatically once the target signature is known — the coordinator pins it
up front (`--target-sig`), so gating is active from the first subset.

### Bench the culprit's syscall, then rotate it back

This is **not** permanent suppression. When one syscall is crash-dominating, you
bench it (`exclude`) so coverage on the rest can build; once that coverage
plateaus you rotate it back in (`include`) and bench the next one. Two steps:

- **Translate** — `syz-ring-repro -emit-json` reads the culprit and writes a
  `syscalls.json` list of the surviving `IOConnectCallMethod` names to disable
  (an offline mode next to `-emit-culprit`; runs nothing on device). It lists
  *names*: a per-selector variant (`...UserClient_5`) is disabled exactly, while
  the generic variant (`...$AppleJPEGDriver`, whose selector is a fuzzable
  argument) can only be disabled wholesale — it warns when that happens.
- **Apply** — `fuzz-campaign.py exclude` / `include` own the *strategy* (which
  config, when, how to resume) and edit `disable_syscalls`.

```sh
# bench the culprit's syscall so fuzzing can proceed on the rest:
scripts/fuzz-campaign.py exclude <campaign> $D/culprit.syz [--config <cfg>] [--dry-run]
#   runs syz-ring-repro -emit-json, then adds each name to disable_syscalls
#   (no recompile). Exit 0. A generic call is disabled wholesale, with a warning.

# rotate benched syscalls back in once their absence has paid off:
scripts/fuzz-campaign.py include <campaign> <syscall...>   [--config <cfg>] [--dry-run]
scripts/fuzz-campaign.py include <campaign> --all          # un-bench everything
```

To just produce the list without touching a config, run the mode directly:
`bin/darwin_arm64/syz-ring-repro -emit-json $D/culprit.syz` (writes `$D/syscalls.json`).
`-emit-json` also composes onto a minimize stage, so one command minimizes **and**
translates — it emits the list the moment the culprit is written:

```sh
$RR -minimize-calls -emit-json $D/culprit.syz   # → culprit.syz + syscalls.json
```

`disable_syscalls` is applied by syz-manager *after* `enable_syscalls` and
subtracts, so a name added there is benched whether the config enabled it by
name or via a `*` glob.

### Autonomous: the campaign drives the whole loop

`fuzz-campaign.py` ties the stages together so the pipeline runs hands-off across
reboots. It is a two-phase machine — **fuzzing** and **triaging** — both durable
via its single launchd agent (one relaunch per crash-reboot):

```
fuzzing ──crash──▶ fingerprint the panic
                     │ already-benched signature → resume fuzzing (same config)
                     │ new signature ▼
                  triaging ─── drive triage.py across reboots ──▶ culprit.syz
                     │  bench it: -emit-json → exclude (disable_syscalls)
                     │  record the signature so it is never re-triaged
                     ▼
                  resume fuzzing
```

On a new bug the campaign pauses fuzzing, stands up a triage job from the
session's ring buffer, and on each boot advances it (`triage.py run`) until DONE;
then it benches the culprit's syscall(s) in the crashed config and resumes. If
triage can't reach a culprit within `triage_max_boots` advances, the campaign
halts with a reason for a human to look. `status` shows the phase:

```sh
scripts/fuzz-campaign.py status <campaign>   # phase, triage job, benched sigs
```

Triage device flags (executor, ringrepro, kcov_device, kext_id, sandbox, max_k)
come from an optional `"triage": { … }` object in the campaign definition JSON;
omit it and triage uses its own defaults. **Rotation** (`include` a benched
syscall back once coverage plateaus) is still manual — plateau detection is not
wired yet.

### Fingerprint a panic by hand

```sh
scripts/crash_fingerprint.py print   /Library/Logs/DiagnosticReports/*.panic
scripts/crash_fingerprint.py classify --store sig.json <report>   # exit 0 iff new bug
```

---

## Files a job produces

Under `triage/<name>/`:

| file | what |
|---|---|
| `merged.syz` | ring buffer merged + statically reduced |
| `conn_state.json` / `call_state.json` | per-stage crash-safe checkpoints (bitmasks) |
| `culprit.syz` | the minimal, verified reproducer |
| `syscalls.json` | list of syscall names to disable, from the culprit (`-emit-json`) |
| `signatures.json` | dedup ledger: one entry per distinct panic signature |
| `reports/` | archived panic reports |

Job state (stage, artifact paths, panic watermark, incident log) lives in
`triage/.state/<name>.json`.

---

## How dedup survives KASLR

A panic report's raw backtrace addresses move every boot, so they can't be
compared directly. `crash_fingerprint.py` builds the signature from:

1. the **panic title**, with addresses and volatile counts scrubbed (e.g. a
   watchdog's "in 91 seconds (998 checkins)" → "in N seconds (N checkins)");
2. the **crashing kext** (first entry under "Kernel Extensions in backtrace:");
3. the **de-slid backtrace** — each frame attributed to a listed module's
   runtime range (kernel text, or a named kext) and expressed as
   `module+0xoffset`. A frame that lands in no module range (a stack/garbage
   value that would otherwise vary with KASLR) collapses to a bare `?`.

Same bug → same signature across reboots and sessions; different bugs differ.
```
