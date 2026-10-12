#!/bin/sh
# One replay trial, invoked by `binfreq --fuzzer-loop` between its PRE and POST
# windows. binfreq appends the schedule token "<idx>:<prog path>" as the last
# argument; everything else comes from the environment freq-replay.py sets up.
#
# Nothing may reach stdout: binfreq shares it for its JSONL results, so a stray
# line from syz-execprog corrupts the record stream. All output goes to the log.
#
# The started-marker is written and synced BEFORE the program runs. A program
# that panics the kernel never returns, so after the reboot the marker names it
# and freq-replay.py records it as a suspect instead of replaying it forever.
# The sync falls inside the measured window, but controls pay it identically.
tok="$1"
idx="${tok%%:*}"
prog="${tok#*:}"
printf '%s\n' "$idx" > "$FREQ_MARK" && /bin/sync
cd "$FREQ_SCRATCH" || exit 2
exec "$FREQ_EXECPROG" -executor "$FREQ_EXECUTOR" -procs 1 -repeat 1 \
    -cover=false -sandbox "${FREQ_SANDBOX:-none}" "$prog" >> "$FREQ_LOG" 2>&1
