# Run a campaign

Last updated: 09/09/2026

This document aims at providing all commands useful to run a campaign.

## Create a campaign

1. Create it. Configs are fuzzed in the order given.

        $ python3 scripts/fuzz-campaign.py new fde_2h \
            config/AppleFDEKeyStore_260908_cov_gram.cfg \
            config/AppleFDEKeyStore_260908_cov_gramsel.cfg \
            --budget-hours 1 --budget-clock real

   **`--budget-hours` is charged per config, not per campaign.** Two configs at
   `1` is a two-hour campaign. `new` echoes the arithmetic back — read that line
   rather than assuming:

        2 config(s), 1.0h EACH on the real clock = 2.0h total

   **Do not pass `--kext-id` or `--kcov-device`.** `new` already reads them from
   each config's `kext_coverage`, and when a crash fires triage re-reads them
   from the config that was running, so a campaign-level value is overridden
   anyway. They exist only as a fallback for a config with no `kext_coverage`
   block. Same for `executor_name`.

   Pick the clock for what you actually want to bound:

   | `--budget-clock` | charges | use when |
   |---|---|---|
   | `real` | elapsed time, including halts, reboots and downtime | you want a window — start at 2pm, stopped by 4pm |
   | `wall` (default) | fuzzing + minimization + reboot overhead | you want N hours of *machine time* per config |
   | `fuzz` | session uptime only | you want N hours of *fuzzing*, however long triage takes |

   `real` is the only one that keeps running while the campaign does not, so it
   is the only one that can express a deadline. Note it charges downtime: if a
   panic-reboot takes 20 minutes, that is 20 minutes of the window.

2. Publish the runtime tree. The build tree is `0700`, so the `fuzz` user cannot
   read it; this copies the scripts, binaries and configs into
   `/Users/Shared/fuzz-run` and repoints the configs' absolute paths. **Re-run
   after every rebuild** — it is safe mid-campaign and preserves the quarantine
   decisions already in the published configs.

        $ ./scripts/sync-fuzz-run.sh

3. Pre-flight **as the fuzz user**. Its permission checks only mean anything when
   run as the user launchd will run the campaign as. `cd` out of the repo first:
   `sudo -u fuzz` inherits your cwd and `fuzz` cannot `getcwd()` inside it.

        $ cd /Users/Shared/fuzz-run
        $ sudo -u fuzz /usr/bin/python3 scripts/fuzz-campaign.py doctor fde_2h

4. Start it. The agent has `RunAtLoad`, so the campaign resumes by itself after
   each panic-reboot.

        $ sudo python3 scripts/fuzz-campaign.py install fde_2h --agent --user fuzz

5. Watch it.

        $ python3 scripts/fuzz-campaign.py status fde_2h
        $ python3 scripts/fuzz-campaign.py list

   When it is done, remove the agent:

        $ sudo python3 scripts/fuzz-campaign.py uninstall fde_2h

## Worth knowing

- **A config that sets no `executor_name`** will silently fuzz nothing if its
  driver gates the user client on `p_comm` — every `IOServiceOpen` fails and
  every later call is inert. `new` warns about this. It cost campaign
  `drivers_260902` 25,461 minimization probes across four Bluetooth jobs.
- **Budget spent ≠ time executing programs.** Even on the `fuzz` clock the
  manager also starts up, triages the corpus and waits on RPC; a measured run
  was 56% execution. For the real figure use `runstats.py show`, which reads
  syz-manager's own counter.
- **Crashes pause fuzzing.** The campaign stands up a triage job, minimizes to a
  reproducer, and quarantine benches the offending syscall so fuzzing can
  continue. See [README-triage.md](README-triage.md).
- First-time setup of the `fuzz` user and its tree is in
  [fuzz-run-setup.md](fuzz-run-setup.md).
