#!/bin/bash
# sync-fuzz-run.sh -- publish the fuzzing runtime into a fuzz-user-accessible tree.
#
# wan builds in /Users/wan/Documents/syzkaller, which is 0700 -- the "fuzz" user
# (uid 502) cannot read it. This copies only what fuzz needs to *run* a campaign
# (the two scripts, the syz-manager + syz-executor binaries, the configs, and the
# campaign definitions) into FUZZ_ROOT, and leaves the writable runtime state
# (workdir/, sessions/, campaigns/.state) group-writable so fuzz can own it.
#
# The configs bake absolute paths; workdir + syzkaller are repointed into
# FUZZ_ROOT. kernel_obj (/Users/wan/KernelCollections) is left as-is because it
# is 0755/0644 and already fuzz-readable, so the 120MB BKC is not copied.
#
# Re-run after every rebuild. Binary swaps are atomic (temp + rename), so a
# running syz-manager keeps its old inode and is not corrupted mid-run.
#
# Usage: ./scripts/sync-fuzz-run.sh [FUZZ_ROOT]   (default /Users/Shared/fuzz-run)
set -euo pipefail

SRC="$(cd "$(dirname "$0")/.." && pwd)"
DST="${1:-/Users/Shared/fuzz-run}"
OLD_PREFIX="$SRC/"
NEW_PREFIX="$DST/"

# atomic copy: never truncate a file a running process may have mapped.
cp_atomic() {
  local s="$1" d="$2"
  cp "$s" "$d.tmp.$$"
  chmod g+rX "$d.tmp.$$"
  mv -f "$d.tmp.$$" "$d"
}

echo "sync $SRC -> $DST"
mkdir -p "$DST"/scripts "$DST"/bin/darwin_arm64 "$DST"/config \
         "$DST"/campaigns/.state "$DST"/sessions "$DST"/workdir

# --- scripts + binaries (read-only artifacts) --------------------------------
cp_atomic "$SRC/scripts/fuzz-campaign.py" "$DST/scripts/fuzz-campaign.py"
cp_atomic "$SRC/scripts/fuzz-session.py"  "$DST/scripts/fuzz-session.py"
chmod +x "$DST"/scripts/*.py
cp_atomic "$SRC/bin/syz-manager"                  "$DST/bin/syz-manager"
cp_atomic "$SRC/bin/darwin_arm64/syz-executor"    "$DST/bin/darwin_arm64/syz-executor"
chmod +x "$DST/bin/syz-manager" "$DST/bin/darwin_arm64/syz-executor"

# --- configs (repoint workdir + syzkaller into FUZZ_ROOT) --------------------
cp "$SRC"/config/*.cfg "$DST/config/"
[ -f "$SRC/config/kext_ids.json" ] && cp "$SRC/config/kext_ids.json" "$DST/config/"
/usr/bin/sed -i '' "s#${OLD_PREFIX}#${NEW_PREFIX}#g" "$DST"/config/*.cfg

# --- campaign definitions (defs only; .state is fuzz-owned runtime) ----------
cp "$SRC"/campaigns/*.json "$DST/campaigns/" 2>/dev/null || true

# --- permissions: read-only artifacts group-readable; state group-writable ---
# No setgid: macOS refuses it on this volume, and BSD group inheritance already
# gives new files the parent dir's group (staff), which both wan and fuzz share.
chmod -R g+rX "$DST"/scripts "$DST"/bin "$DST"/config
chmod 775 "$DST" "$DST"/campaigns "$DST"/campaigns/.state "$DST"/sessions "$DST"/workdir

echo "done. configs repointed: workdir + syzkaller -> $DST (kernel_obj left in place)"
echo "verify: grep -h workdir \"$DST\"/config/IOBluetoothFamily_260710_cov_gram-14.6.cfg"
