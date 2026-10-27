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
# The model (campaign-planning.md §3-4): config/*.cfg and plans/*.json are
# read-only INPUTS the campaign never writes back to, so they are copied verbatim
# (comments and all). The machine's own box fields live in config/box.json, which
# is this box's property: sync seeds it once and never overwrites it. Only a
# legacy config that still bakes absolute paths under the build tree is rewritten,
# to repoint those into FUZZ_ROOT; kernel_obj (/Users/wan/KernelCollections) is
# left as-is because it is 0755/0644 and already fuzz-readable, so the 120MB BKC
# is not copied. The bug ledger lives in bugs/ (moved up from campaigns/bugs) and
# the ephemeral box files live in run/.
#
# Re-run after every rebuild. Every copy is atomic (temp + rename), so a running
# syz-manager keeps its old inode and is never truncated under it, which is what
# makes a re-sync safe mid-campaign.
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
warn()  { printf '    %s%s%s %s\n' "$C_YELLOW" "WARN" "$C_RESET" "$*"; }
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
# A missing driver is not a degraded feature -- the tool dies at startup with
# ModuleNotFoundError for the fuzz user, and the campaign stops at its first
# quarantine or session call.
SCRIPTS=(fuzz-campaign.py fuzz-session.py triage.py quarantine.py
         crash_fingerprint.py bug_registry.py)
# fuzz-campaign.py runs it to commit results when the campaign sets results_repo.
SCRIPTS+=(fuzz-results.py)
# The shared-library package the drivers import as `from lib import ...`. It is
# copied as a package (with __init__.py) into $DST/scripts/lib/ so the published
# drivers resolve it the same way the dev tree does; omitting any member makes
# every published driver fail at import with ModuleNotFoundError.
# Every module in lib/: listed by hand this went stale (bootinfo, style, schedule
# and requests were missing), and a missing one fails every published driver.
LIBS=()
for _f in "$SRC"/scripts/lib/*.py; do LIBS+=("$(basename "$_f")"); done
# syz-manager itself validates that <syzkaller>/bin/<arch>/ holds BOTH syz-execprog
# and syz-executor (pkg/mgrconfig/load.go:346-370) and exits FATAL at startup if
# either is missing -- so syz-execprog belongs here even though nothing in these
# scripts calls it directly. syz-ring-repro is the minimizer triage drives; a
# headless agent cannot fall back to `go run`, so it must be published too.
BINS=(bin/syz-manager
      bin/darwin_arm64/syz-executor
      bin/darwin_arm64/syz-execprog
      bin/darwin_arm64/syz-ring-repro)
# fuzz-results.py unpacks corpus.db into per-program files with syz-db.
BINS+=(bin/syz-db)
# The dirs the campaign writes into at runtime, all made group-writable so the
# fuzz user owns its state in a tree the build user created. bugs/ is the ledger's
# new home (moved up from campaigns/bugs). run/ holds the ephemeral box files
# (box.lock box.out requests.json watch.command brake). plans/ is an INPUT, but
# sync copies into it so it must exist. campaigns/ and campaigns/.state stay for
# the legacy state and the logs that still live there until the log phase.
# config/ is NOT here: configs are read-only inputs now, so the directory needs
# group-write only as config/box.json's parent (the box seeds and edits its own
# box.json there) -- handled on its own below, not as a general runtime dir.
WRITABLE=(bugs campaigns campaigns/.state run sessions workdir
          triage triage/.state)

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
mkdir -p "$DST"/scripts "$DST"/bin/darwin_arm64 "$DST"/config
for d in "${WRITABLE[@]}"; do mkdir -p "$DST/$d"; done

# --- scripts + binaries (read-only artifacts) --------------------------------
step "scripts"
for f in "${SCRIPTS[@]}"; do
  [ -f "$SRC/scripts/$f" ] || fail "missing $SRC/scripts/$f"
  cp_atomic "$SRC/scripts/$f" "$DST/scripts/$f"
  chmod +x "$DST/scripts/$f"
done
ok "${#SCRIPTS[@]} script(s): ${SCRIPTS[*]}"

mkdir -p "$DST/scripts/lib"
for f in "${LIBS[@]}"; do
  [ -f "$SRC/scripts/lib/$f" ] || fail "missing $SRC/scripts/lib/$f"
  cp_atomic "$SRC/scripts/lib/$f" "$DST/scripts/lib/$f"
done
ok "${#LIBS[@]} lib module(s): ${LIBS[*]}"

step "binaries"
for b in "${BINS[@]}"; do
  [ -f "$SRC/$b" ] || fail "missing $SRC/$b -- run \`make target\` / \`make manager\`"
  cp_atomic "$SRC/$b" "$DST/$b"
  chmod +x "$DST/$b"
  info "$(basename "$b")  $(/usr/bin/stat -f '%z bytes, built %Sm' -t '%d/%m %H:%M' "$SRC/$b" 2>/dev/null)"
done
ok "${#BINS[@]} binary/binaries"

# --- configs (INPUTS: copied verbatim; legacy path-bakers repointed) ----------
# Configs are read-only inputs now -- no campaign writes a config back -- so each
# one is copied byte for byte, keeping the whole-line '#' comments the experiment
# uses to record what it excluded. The only exception is a legacy config that
# still bakes absolute paths under the build tree: those keys are repointed into
# the fuzz tree so the config keeps resolving, and the file says so.
step "configs"
cfg_n=0
for c in "$SRC"/config/*.cfg; do
  [ -e "$c" ] || break        # no configs: the glob stays literal
  cfg_n=$((cfg_n + 1))
  base="$(basename "$c")"
  /usr/bin/python3 - "$c" "$DST/config/$base" "$OLD_PREFIX" "$NEW_PREFIX" "${C_CYAN:+1}" "$SRC/scripts" <<'PY'
import json, os, sys
src, dst, old, new = sys.argv[1:5]
# cfgutil reads configs exactly as syz-manager does -- stripping whole-line '#'
# comments (pkg/config/config.go) -- so we can INSPECT a config for baked paths
# without a '#'-commented one tripping the parse. It is used only to decide; the
# verbatim copy below goes through the raw bytes so the comments survive.
sys.path.insert(0, sys.argv[6])
from lib import cfgutil
# Colour is decided once, by the shell, from isatty + NO_COLOR. Deciding it again
# here would emit escapes into a redirected log.
_c = len(sys.argv) > 5 and sys.argv[5] == "1"
YEL = "\033[33m" if _c else ""
GRN = "\033[32m" if _c else ""
CYN = "\033[36m" if _c else ""
RST = "\033[0m" if _c else ""

def atomic_write(text):
    # Never truncate a config a running syz-manager has open; write a temp and
    # rename it over the old inode.
    tmp = dst + ".tmp.%d" % os.getpid()
    with open(tmp, "w") as f:
        f.write(text)
    os.chmod(tmp, 0o644)   # an input: nothing writes it at runtime (see the chmod notes)
    os.replace(tmp, dst)

try:
    cfg = cfgutil.load(src)
except ValueError as e:
    # Genuinely malformed -- syz-manager could not load it either. Warn and skip
    # rather than aborting the whole publish.
    sys.stderr.write("    %sSKIP%s %s: not valid JSON (%s)\n"
                     % (YEL, RST, os.path.basename(src), e))
    raise SystemExit(0)
# Which keys still bake an absolute path under the build tree? Only those force a
# rewrite; box fields belong in box.json now (campaign-planning.md §3), but a
# legacy config that still carries them must keep running until it is stripped.
box_paths = [k for k, v in cfg.items()
             if isinstance(v, str) and v.startswith(old)]
if not box_paths:
    # A plain input: copy the raw bytes so the '#' comments reach the published
    # tree. No rewrite, no reformat -- what you authored is what runs.
    with open(src) as f:
        atomic_write(f.read())
    print("    %sOK%s %s: copied verbatim (comments kept)"
          % (GRN, RST, os.path.basename(dst)))
    raise SystemExit(0)
# Legacy config: repoint the build-tree paths into the fuzz tree. This reformats
# the file (comments are lost), which is acceptable because such a config is on
# its way out -- strip its box keys and it becomes a verbatim input.
for k in box_paths:
    cfg[k] = new + cfg[k][len(old):]
atomic_write(json.dumps(cfg, indent=4) + "\n")
print("    %sKEPT%s %s: box keys repointed into the fuzz tree (%s)"
      % (CYN, RST, os.path.basename(dst), ", ".join(sorted(box_paths))))
PY
done
[ -f "$SRC/config/kext_ids.json" ] && cp_atomic "$SRC/config/kext_ids.json" "$DST/config/kext_ids.json"
ok "$cfg_n config(s) published to $DST/config"

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
  # queue.json is the box's own queue, written by its runner: never published
  # (a dev tree's copy overwrote it and re-queued whatever it held).
  [ "$(basename "$j")" = "queue.json" ] && continue
  cp_atomic "$j" "$DST/campaigns/$(basename "$j")"
  camp_n=$((camp_n + 1))
done
ok "$camp_n legacy definition(s); campaigns/<name>/ and .state left alone (fuzz-owned runtime)"

# --- plans: the inputs of the new layout (plans reference configs by repo-relative
# path, which resolves against the fuzz tree's own root -- no rewriting) --------
step "campaigns"
# A campaign's campaign.json and README.md are tracked inputs; the rest of its
# folder is the box's runtime. Publish only campaigns the box does not have yet
# (the box's state, logs and README edits are never overwritten). plan.json is
# the name before the rename: a box campaign that has one already exists, so a
# campaign.json beside it -- which the driver would prefer -- is never added.
camp_new=0
for pj in "$SRC"/campaigns/*/campaign.json "$SRC"/campaigns/*/plan.json; do
  [ -e "$pj" ] || continue
  cname="$(basename "$(dirname "$pj")")"
  if [ ! -e "$DST/campaigns/$cname/campaign.json" ] && [ ! -e "$DST/campaigns/$cname/plan.json" ]; then
    mkdir -p "$DST/campaigns/$cname"
    cp_atomic "$pj" "$DST/campaigns/$cname/$(basename "$pj")"
    [ -f "$SRC/campaigns/$cname/README.md" ] && cp_atomic "$SRC/campaigns/$cname/README.md" "$DST/campaigns/$cname/README.md"
    camp_new=$((camp_new + 1))
  fi
done
ok "$camp_new new campaign(s) published; existing ones left alone"
# config/box.json is THIS machine's: created on the box once, never overwritten
# (sync only says when the repo's copy differs, so a drift is a decision, not an
# accident).
if [ -f "$SRC/config/box.json" ]; then
  if [ ! -f "$DST/config/box.json" ]; then
    cp_atomic "$SRC/config/box.json" "$DST/config/box.json"
    ok "config/box.json seeded from the repo -- edit the box's copy for its own paths"
  elif ! cmp -s "$SRC/config/box.json" "$DST/config/box.json"; then
    warn "config/box.json differs between repo and box; the box's copy is kept"
  fi
fi

step "permissions"
# --- permissions: read-only artifacts group-readable; state group-writable ---
# No setgid: macOS refuses it on this volume, and BSD group inheritance already
# gives new files the parent dir's group (staff), which both wan and fuzz share.
# Panic reports are HARDLINKED into the bug inventory, not copied (one inode,
# many names -- see fsutil). chgrp/chmod act on the inode, so touching a link
# would rewrite the OS's own file in /Library/Logs/DiagnosticReports, and fails
# anyway because those files are root-owned. Prune those paths from the walk;
# they are evidence, and nothing needs to write them. The reports live under
# bugs/*/reports now (the ledger moved up); campaigns/bugs/*/reports is kept so a
# legacy, un-migrated tree is still protected.
# The exec scratch is pruned for cost, not correctness: it holds one empty
# syzkaller.XXXXXX per minimization probe and nothing ever reads it, but it was
# 92% of this tree's 444k files -- three walks over it dominated every publish.
# triage.py clears it when a job finishes; this keeps an in-flight job cheap. The
# new layout keeps it per item (campaigns/<name>/<config>/<item>/triage/*/exec);
# triage/*/exec is the legacy and manual-job location.
find "$DST" \( -path "$DST/bugs/*/reports" \
            -o -path "$DST/campaigns/bugs/*/reports" \
            -o -path "$DST/triage/*/exec" \
            -o -path "$DST/campaigns/*/*/*/triage/*/exec" \) -prune -o \
     -exec chgrp "$FUZZ_GROUP" {} + 2>/dev/null || true
chmod -R g+rX "$DST"/scripts "$DST"/bin "$DST"/sys
# 775, not 755: this is the launchd job's WorkingDirectory, so it is the cwd of
# everything the campaign spawns. A read-only root makes any relative-path write
# fail with EACCES -- which is how the executor came to die on every single
# minimization probe ("SYZFAIL: shmem open failed ... errno 13").
chmod 775 "$DST"
for d in "${WRITABLE[@]}"; do chmod 775 "$DST/$d"; done
# config/ is group-writable only as config/box.json's parent: the box seeds and
# then edits its own box.json in place, which needs write on the directory. The
# .cfg inputs are deliberately NOT made group-writable any more -- nothing writes
# them at runtime, so read-only is the correct, and safer, posture for an input.
chmod 775 "$DST"/config

# The state the campaign has already written belongs to whoever wrote it; keep it
# group-writable so a later sync (or the other account) can still touch it. bugs/
# is included: the ledger (and its dossiers) is written by the campaign and must
# stay editable. Reports and exec scratch are pruned as above.
find "$DST/bugs" "$DST/campaigns" "$DST/sessions" "$DST/workdir" "$DST/triage" \
     \( -path "$DST/bugs/*/reports" -o -path "$DST/campaigns/bugs/*/reports" \
        -o -path "$DST/triage/*/exec" \
        -o -path "$DST/campaigns/*/*/*/triage/*/exec" \) -prune -o \
     -type d -exec chmod g+w {} + 2>/dev/null || true
find "$DST/bugs" "$DST/campaigns" "$DST/sessions" "$DST/triage" \
     \( -path "$DST/bugs/*/reports" -o -path "$DST/campaigns/bugs/*/reports" \
        -o -path "$DST/triage/*/exec" \
        -o -path "$DST/campaigns/*/*/*/triage/*/exec" \) -prune -o \
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
