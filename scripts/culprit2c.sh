#!/bin/sh
# culprit2c.sh -- turn a triage job's minimized culprit into a standalone C
# reproducer, for a vendor report (Apple will not run syzkaller).
#
#   scripts/culprit2c.sh <triage job dir | job name> [prog file]
#
# Writes repro.c and the compiled repro next to the culprit, in the job dir.
# Nothing is executed: running repro is up to you (it is expected to crash).
#
# Requirements:
#   - syz-prog2c built from a tree whose descriptions match the run that found
#     the culprit (`make prog2c`, or set SYZ_PROG2C). A tree without the run's
#     syscalls fails with "unknown syscall ...".
#   - GNU cpp: pkg/csource preprocesses with -fdirectives-only, which clang does
#     not support. `brew install gcc`; any g++-N on PATH is picked up, or set
#     SYZ_CPP.
set -eu

die() { echo "culprit2c: $*" >&2; exit 1; }

[ $# -ge 1 ] || die "usage: $0 <triage job dir | job name> [prog file]"
repo=$(cd "$(dirname "$0")/.." && pwd)
job="$1"
if [ ! -d "$job" ]; then
  job="${SYZ_TRIAGE_DIR:-/Users/Shared/fuzz-run/triage}/$1"
fi
[ -d "$job" ] || die "no triage job at $1"
prog="${2:-$job/final_culprit.syz}"
[ -f "$prog" ] || die "no culprit program at $prog"

prog2c="${SYZ_PROG2C:-$repo/bin/syz-prog2c}"
[ -x "$prog2c" ] || die "no syz-prog2c at $prog2c (run: make prog2c, or set SYZ_PROG2C)"

out="$job/repro.c"
# Threaded mode honours (async) call properties, which minimized culprits keep.
# sandbox none matches how the campaigns run the executor.
"$prog2c" -prog "$prog" -os darwin -arch arm64 -sandbox none -threaded \
  -repeat 1 -procs 1 > "$out.tmp" 2> "$job/repro.prog2c.log" ||
  { rm -f "$out.tmp"; die "syz-prog2c failed: $(head -3 "$job/repro.prog2c.log")"; }
mv "$out.tmp" "$out"

clang -O1 -Wno-deprecated-declarations -o "$job/repro" "$out" \
  -framework IOKit -framework CoreFoundation 2> "$job/repro.build.log" ||
  die "compile failed, see $job/repro.build.log"

echo "culprit : $prog"
echo "source  : $out ($(wc -l < "$out" | tr -d ' ') lines)"
echo "binary  : $job/repro"
echo "run it as a standard user, on a machine you can afford to crash:"
echo "  $job/repro"
