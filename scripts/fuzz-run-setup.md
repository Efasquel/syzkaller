# Autonomous fuzzing under the `fuzz` user (LaunchAgent setup)

Run the syzkaller kernel-fuzzing campaign driver (`fuzz-campaign.py` →
`fuzz-session.py`) autonomously as the dedicated `fuzz` user, surviving crashes,
panic-reboots, and logouts.

- **Build/dev account:** `wan` (uid 501) — owns the repo, rebuilds binaries.
- **Fuzzing account:** `fuzz` (uid 502) — auto-logs-in, auto-restarts, runs the
  campaign. Both users are in group `staff`.

---

## Why a separate runtime tree

The repo lives at `/Users/wan/Documents/syzkaller`, but **`/Users/wan/Documents`
is `0700`** — `fuzz` cannot traverse into it at all, so it can't read the
scripts/binaries or write campaign state. Symlinks don't help (the block is on
traversal). Both scripts also anchor *everything* to `SCRIPT_DIR.parent`
(`config/`, `campaigns/.state`, `sessions/`, `workdir/`), so `fuzz` needs its own
writable repo root.

Solution: a minimal, fuzz-accessible runtime root at **`/Users/Shared/fuzz-run`**
(`/Users/Shared` is world-accessible; both users share `staff`). Only the binary
+ scripts + configs are copied in; large read-only assets stay where they are.

### What is / isn't copied

| Item | Handling | Why |
|------|----------|-----|
| `scripts/*.py`, `bin/syz-manager`, `bin/darwin_arm64/syz-executor` | **copied** (read-only) | fuzz can't read `/Users/wan/Documents` |
| `config/*.cfg`, `config/kext_ids.json` | **copied + rewritten** | `workdir` + `syzkaller` paths repointed into the tree |
| `campaigns/*.json` | **copied** (defs only) | `.state` is fuzz-owned runtime |
| `kernel_obj` = `/Users/wan/KernelCollections/` | **left in place** | already `0755`/`0644`, fuzz-readable — avoids a 120 MB copy |
| `bluetoothd` (repo root) | **not copied** | it's a renamed `syz-executor`; `executor_binary()` derives it at runtime into the exec scratch dir |

No root is needed at runtime: `/dev/pishi` is `0666`, so `fuzz` opens the
coverage device fine.

---

## Runtime tree layout (`/Users/Shared/fuzz-run/`)

```
scripts/                 fuzz-campaign.py, fuzz-session.py   (ro, staff-readable)
bin/syz-manager                                              (ro)
bin/darwin_arm64/syz-executor                                (ro)
config/*.cfg, kext_ids.json   workdir+syzkaller repointed    (ro)
campaigns/*.json         campaign definitions                (ro)
campaigns/.state/        driver state + launchd log          (775, group staff, fuzz-writable)
sessions/                session registry                    (775)
workdir/                 syz-manager workdirs, corpus, cores (775)
launchd/com.fuzz-campaign.bt.plist   the LaunchAgent
```

The writable dirs are `775` group-`staff` (no setgid — macOS refuses it on this
volume, and BSD group-inheritance already gives new files the parent dir's group
`staff`, which both users share).

---

## Publishing / re-syncing after a rebuild

`wan` builds in the real repo, then pushes into the fuzz tree:

```sh
./scripts/sync-fuzz-run.sh            # defaults to /Users/Shared/fuzz-run
./scripts/sync-fuzz-run.sh /some/other/root
```

`sync-fuzz-run.sh` copies scripts/binaries/configs, repoints the config paths,
and fixes permissions. Binary swaps are **atomic** (temp file + rename), so a
`syz-manager` running mid-sync keeps its old inode and is not corrupted.

---

## The LaunchAgent

`launchd/com.fuzz-campaign.bt.plist` runs:

```
/usr/bin/python3 /Users/Shared/fuzz-run/scripts/fuzz-campaign.py run bt
```

Key settings and rationale:

- **Installed in `~fuzz/Library/LaunchAgents`, not `/Library/LaunchAgents`** — so
  it loads *only* in fuzz's login session. If it were system-wide it would also
  load in `wan`'s Aqua session and spawn a second campaign fighting over
  `/dev/pishi`.
- **`RunAtLoad` + `KeepAlive{SuccessfulExit:false}`** — starts on fuzz's
  auto-login and after a panic-reboot; restarts on a crash but *not* on a clean
  exit (the driver exits 0 when the campaign is done or the circuit breaker
  halts it, so this avoids thrashing). Dovetails with the driver's
  `reconcile_boot`, which records the in-flight incident and resumes.
- **`ProcessType Standard`** — don't let macOS throttle the fuzzer to background
  priority.
- Runs as uid 502 (`fuzz`) because it's bootstrapped into `gui/502`.

---

## Install (needs `sudo` — touches fuzz's home + live session)

```sh
# 1. install into fuzz's home and load into fuzz's live GUI session
sudo install -d -o fuzz -g staff -m 700 /Users/fuzz/Library/LaunchAgents
sudo install -o fuzz -g staff -m 644 \
  /Users/Shared/fuzz-run/launchd/com.fuzz-campaign.bt.plist \
  /Users/fuzz/Library/LaunchAgents/com.fuzz-campaign.bt.plist
sudo launchctl bootout   gui/502/com.fuzz-campaign.bt 2>/dev/null   # idempotent
sudo launchctl bootstrap gui/502 \
  /Users/fuzz/Library/LaunchAgents/com.fuzz-campaign.bt.plist

# 2. confirm it's running as fuzz
sudo launchctl print gui/502/com.fuzz-campaign.bt | head -30
```

It also auto-loads on every future fuzz login (the machine auto-logs-in as
`fuzz`), so this manual bootstrap is only needed to start it *now*.

---

## Operating it

```sh
# live log (staff-readable, no sudo)
tail -f /Users/Shared/fuzz-run/campaigns/.state/bt.launchd.log

# campaign state
cd /Users/Shared/fuzz-run && /usr/bin/python3 scripts/fuzz-campaign.py status bt
/usr/bin/python3 scripts/fuzz-campaign.py list

# pause / resume the campaign (the driver polls state and stops the session)
/usr/bin/python3 scripts/fuzz-campaign.py halt bt
/usr/bin/python3 scripts/fuzz-campaign.py resume bt

# stop the agent entirely
sudo launchctl bootout gui/502/com.fuzz-campaign.bt
```

### Switching which campaign runs

Edit the last `<string>bt</string>` in the plist to another campaign name (e.g.
`test` for a short, non-looping smoke test), then re-run the install block. Or
edit `campaigns/<name>.json` to change configs/budgets.

---

## Caveat: the built-in `install` subcommand

`fuzz-campaign.py install <name>` is **not** what set this up. It writes a
*system LaunchDaemon* (`launchctl bootstrap system`, runs as root) and its
`LAUNCHD_DIR` is a buggy `Path.home() / "/Library"` (resolves to
`/Library/LaunchAgents` via a pathlib quirk). Don't use it for the fuzz-user
setup; use the manual `sudo` block above (or fix that subcommand to emit this
agent).
