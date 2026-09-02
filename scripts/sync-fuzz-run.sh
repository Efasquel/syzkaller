#!/bin/bash
# sync-fuzz-run.sh -- publish the fuzzing runtime into a fuzz-user-accessible tree.
#
# wan builds in /Users/wan/Documents/syzkaller, which is 0700 -- the "fuzz" user
# (uid 502) cannot even traverse into it. This copies everything fuzz needs to run
# a campaign *end to end* -- not just fuzz, but the whole coordinator loop:
#
#   fuzz -> crash -> collect -> fingerprint -> triage/minimize -> quarantine -> resume
#
# so the script set is the six drivers, and the binaries are the three the loop
# shells out to (syz-manager, syz-executor, syz-ring-repro).
#
# The configs bake absolute paths; workdir + syzkaller are repointed into
# FUZZ_ROOT. kernel_obj (/Users/wan/KernelCollections) is left as-is because it
# is 0755/0644 and already fuzz-readable, so the 120MB BKC is not copied.
#
# Re-run after every rebuild. Two things make a re-sync safe mid-campaign:
#   * every copy is atomic (temp + rename), so a running syz-manager keeps its
#     old inode and is never truncated under it;
#   * a destination config's "disable_syscalls" is carried across, so re-syncing
#     does not throw away the quarantine decisions the campaign has accumulated.
#
# Output is colour-coded by phase (==> section, OK done, SKIP not done, KEPT a
# decision made on your behalf). Colour is suppressed when stdout is not a
# terminal or NO_COLOR is set, since this is routinely redirected into a log.
#
# Usage: ./scripts/sync-fuzz-run.sh [FUZZ_ROOT]   (default /Users/Shared/fuzz-run)
#        NO_COLOR=1 ./scripts/sync-fuzz-run.sh
set -euo pipefail

# --- colour ------------------------------------------------------------------
# Only when stdout is a terminal, and never when NO_COLOR is set: this script is
# routinely redirected into a log and run from other scripts, where escape codes
# are noise at best and confuse a grep at worst.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
  C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'; C_CYAN=$'\033[36m'
else
  C_RESET=; C_BOLD=; C_DIM=; C_RED=; C_GREEN=; C_YELLOW=; C_BLUE=; C_CYAN=
fi

# A section header, so the phases of a publish are distinguishable at a glance.
step()  { printf '%s==>%s %s%s%s\n' "$C_BLUE" "$C_RESET" "$C_BOLD" "$*" "$C_RESET"; }
# Something was done. The count belongs here: "9 scripts" is verifiable, "ok" is not.
ok()    { printf '    %s%s%s %s\n' "$C_GREEN" "OK" "$C_RESET" "$*"; }
# Something was deliberately not done, and you may need to care.
skip()  { printf '    %s%s%s %s\n' "$C_YELLOW" "SKIP" "$C_RESET" "$*"; }
# A decision the sync made on your behalf that changes what will run.
note()  { printf '    %s%s%s %s\n' "$C_CYAN" "KEPT" "$C_RESET" "$*"; }
info()  { printf '    %s%s%s\n' "$C_DIM" "$*" "$C_RESET"; }
fail()  { printf '%sERROR%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

SRC="$(cd "$(dirname "$0")/.." && pwd)"
DST="${1:-/Users/Shared/fuzz-run}"
OLD_PREFIX="$SRC/"
NEW_PREFIX="$DST/"
# The group both accounts share. Group-write is what lets the fuzz user own the
# runtime state in a tree the build user created -- if the tree ends up group
# `wheel` (the default under /Users/Shared) fuzz gets r-x only and the campaign
# cannot write a single byte of state, so set it explicitly every sync.
FUZZ_GROUP="${FUZZ_GROUP:-staff}"

# The whole coordinator, not just the two drivers: fuzz-campaign shells out to
# triage.py and bug_registry.py and imports crash_fingerprint + quarantine, so a
# tree missing any one of them dies on the first crash instead of at sync time.
# tablefmt.py, fsutil.py and timefmt.py are imported by the CLIs above; omitting
# any of them makes every published script fail at import with ModuleNotFoundError.
SCRIPTS=(fuzz-campaign.py fuzz-session.py triage.py quarantine.py
         crash_fingerprint.py bug_registry.py tablefmt.py fsutil.py timefmt.py)
# syz-manager itself validates that <syzkaller>/bin/<arch>/ holds BOTH syz-execprog
# and syz-executor (pkg/mgrconfig/load.go:346-370) and exits FATAL at startup if
# either is missing -- so syz-execprog belongs here even though nothing in these
# scripts calls it directly. syz-ring-repro is the minimizer triage drives; a
# headless agent cannot fall back to `go run`, so it must be published too.
BINS=(bin/syz-manager
      bin/darwin_arm64/syz-executor
      bin/darwin_arm64/syz-execprog
      bin/darwin_arm64/syz-ring-repro)
# Runtime state the campaign writes. config/ is here too: the quarantine rewrites
# disable_syscalls into the live config on every decision.
WRITABLE=(campaigns campaigns/.state campaigns/bugs sessions workdir
          triage triage/.state config)

# atomic copy: never truncate a file a running process may have mapped, and never
# need write permission on the destination file itself (only on its directory) --
# which matters because fuzz-owned files land here once the campaign is running.
cp_atomic() {
  local s="$1" d="$2"
  cp "$s" "$d.tmp.$$"
  chmod g+rX "$d.tmp.$$"
  mv -f "$d.tmp.$$" "$d"
}

printf '%s%s%s %s\n  %s->%s %s\n' \
  "$C_BOLD" "publish" "$C_RESET" "$SRC" "$C_DIM" "$C_RESET" "$DST"
mkdir -p "$DST"/scripts "$DST"/bin/darwin_arm64
for d in "${WRITABLE[@]}"; do mkdir -p "$DST/$d"; done

# --- scripts + binaries (read-only artifacts) --------------------------------
step "scripts"
for f in "${SCRIPTS[@]}"; do
  [ -f "$SRC/scripts/$f" ] || fail "missing $SRC/scripts/$f"
  cp_atomic "$SRC/scripts/$f" "$DST/scripts/$f"
  chmod +x "$DST/scripts/$f"
done
ok "${#SCRIPTS[@]} script(s): ${SCRIPTS[*]}"

step "binaries"
for b in "${BINS[@]}"; do
  [ -f "$SRC/$b" ] || fail "missing $SRC/$b -- run \`make target\` / \`make manager\`"
  cp_atomic "$SRC/$b" "$DST/$b"
  chmod +x "$DST/$b"
  info "$(basename "$b")  $(/usr/bin/stat -f '%z bytes, built %Sm' -t '%d/%m %H:%M' "$SRC/$b" 2>/dev/null)"
done
ok "${#BINS[@]} binary/binaries"

# --- configs (repoint paths; keep the destination's quarantine decisions) -----
step "configs"
cfg_n=0
for c in "$SRC"/config/*.cfg; do
  cfg_n=$((cfg_n + 1))
  base="$(basename "$c")"
  /usr/bin/python3 - "$c" "$DST/config/$base" "$OLD_PREFIX" "$NEW_PREFIX" "${C_CYAN:+1}" <<'PY'
import json, os, sys
src, dst, old, new = sys.argv[1:5]
# Colour is decided once, by the shell, from isatty + NO_COLOR. Deciding it again
# here would emit escapes into a redirected log.
_c = len(sys.argv) > 5 and sys.argv[5] == "1"
YEL = "\033[33m" if _c else ""
CYN = "\033[36m" if _c else ""
RST = "\033[0m" if _c else ""
try:
    cfg = json.load(open(src))
except ValueError as e:
    # A hand-edited config that no longer parses can't be loaded by syz-manager
    # either. Warn and skip it rather than aborting the whole publish.
    sys.stderr.write("    %sSKIP%s %s: not valid JSON (%s)\n"
                     % (YEL, RST, os.path.basename(src), e))
    raise SystemExit(0)
for k, v in list(cfg.items()):
    if isinstance(v, str) and v.startswith(old):
        cfg[k] = new + v[len(old):]
# Carry the live quarantine set across a re-sync. The authored config in the repo
# has no idea which selectors the campaign has benched since; clobbering it would
# silently re-enable every crasher the loop already paid a reboot to find.
try:
    prev = json.load(open(dst)).get("disable_syscalls")
except (OSError, ValueError):
    prev = None
if prev:
    cfg["disable_syscalls"] = prev
    print("    %sKEPT%s %s: disable_syscalls=%s (the campaign's quarantine "
          "decisions)" % (CYN, RST, os.path.basename(dst), ", ".join(prev)))
tmp = dst + ".tmp.%d" % os.getpid()
with open(tmp, "w") as f:
    json.dump(cfg, f, indent=4); f.write("\n")
os.chmod(tmp, 0o664)
os.replace(tmp, dst)
PY
done
[ -f "$SRC/config/kext_ids.json" ] && cp_atomic "$SRC/config/kext_ids.json" "$DST/config/kext_ids.json"
ok "$cfg_n config(s) repointed into $DST"

# --- syscall descriptions ----------------------------------------------------
# syz-manager has the grammar compiled in, so it does not read these. fuzz-session's
# pre-flight lint does: without them it reports every enabled syscall as "not
# defined in sys/<os>/*.txt", a false alarm that buries the real warnings.
step "syscall descriptions"
mkdir -p "$DST/sys/darwin"
desc_n=0
for t in "$SRC"/sys/darwin/*.txt; do
  [ -e "$t" ] || break
  cp_atomic "$t" "$DST/sys/darwin/$(basename "$t")"
  desc_n=$((desc_n + 1))
done
ok "$desc_n description file(s) (for fuzz-session's lint; the manager has the grammar compiled in)"

# --- campaign definitions (defs only; .state is fuzz-owned runtime) ----------
# Defs reference configs by repo-relative path, which resolves against the fuzz
# tree's own root -- so no rewriting is needed here.
step "campaign definitions"
camp_n=0
for j in "$SRC"/campaigns/*.json; do
  [ -e "$j" ] || break
  cp_atomic "$j" "$DST/campaigns/$(basename "$j")"
  camp_n=$((camp_n + 1))
done
ok "$camp_n definition(s); .state left alone (it is fuzz-owned runtime)"

step "permissions"
# --- permissions: read-only artifacts group-readable; state group-writable ---
# No setgid: macOS refuses it on this volume, and BSD group inheritance already
# gives new files the parent dir's group (staff), which both wan and fuzz share.
# Panic reports are HARDLINKED into the bug inventory, not copied (one inode,
# many names -- see fsutil). chgrp/chmod act on the inode, so touching a link
# would rewrite the OS's own file in /Library/Logs/DiagnosticReports, and fails
# anyway because those files are root-owned. Prune those paths from the walk;
# they are evidence, and nothing needs to write them.
find "$DST" -path "$DST/campaigns/bugs/*/reports" -prune -o \
     -exec chgrp "$FUZZ_GROUP" {} + 2>/dev/null || true
chmod -R g+rX "$DST"/scripts "$DST"/bin "$DST"/sys
# 775, not 755: this is the launchd job's WorkingDirectory, so it is the cwd of
# everything the campaign spawns. A read-only root makes any relative-path write
# fail with EACCES -- which is how the executor came to die on every single
# minimization probe ("SYZFAIL: shmem open failed ... errno 13").
chmod 775 "$DST"
for d in "${WRITABLE[@]}"; do chmod 775 "$DST/$d"; done
chmod g+rw "$DST"/config/*.cfg 2>/dev/null || true

# The state the campaign has already written belongs to whoever wrote it; keep it
# group-writable so a later sync (or the other account) can still touch it.
find "$DST/campaigns" "$DST/sessions" "$DST/workdir" "$DST/triage" \
     -type d -exec chmod g+w {} + 2>/dev/null || true
find "$DST/campaigns" "$DST/sessions" "$DST/triage" \
     -path "$DST/campaigns/bugs/*/reports" -prune -o \
     -type f -exec chmod g+rw {} + 2>/dev/null || true

ok "tree root 775 (it is the launchd job's cwd), state dirs group-writable"
info "kernel_obj left in place -- already fuzz-readable, so the 120MB BKC is not copied"

printf '\n%s%s%s\n' "$C_GREEN$C_BOLD" "published." "$C_RESET"
printf '%snext: pre-flight AS THE FUZZ USER.%s doctor'"'"'s permission checks only mean\n' \
  "$C_BOLD" "$C_RESET"
printf '      something when run as the user launchd will run the campaign as.\n'
printf '      %scd out of the repo first: sudo -u fuzz inherits your cwd, and fuzz\n' "$C_DIM"
printf '      cannot getcwd() inside the 0700 build tree.%s\n' "$C_RESET"
printf '  %scd %s && sudo -u fuzz /usr/bin/python3 scripts/fuzz-campaign.py doctor <campaign>%s\n' \
  "$C_CYAN" "$DST" "$C_RESET"
