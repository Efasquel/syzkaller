#!/usr/bin/env bash
#
# Remove all directories matching "syzkaller.XXXXXX" where XXXXXX is exactly
# six alphanumeric characters (a-z, A-Z, 0-9).
#
# To stay fast, deletion is done in batches: one glob per leading character
# ("syzkaller.a*", "syzkaller.b*", ... "syzkaller.0*", ...), so each rm call
# handles a whole bucket of directories at once instead of one find per dir.
#
# Usage:
#   ./remove_syzkaller_tmp.sh [-n] [DIR]
#
#   -n    Dry run: only print the directories that would be removed.
#   DIR   Directory to search in (default: current directory).

set -euo pipefail
shopt -s nullglob

dry_run=0
if [[ "${1:-}" == "-n" ]]; then
    dry_run=1
    shift
fi

search_dir="${1:-.}"

if [[ ! -d "$search_dir" ]]; then
    echo "Error: '$search_dir' is not a directory" >&2
    exit 1
fi

# Leading characters to batch over: a-z, A-Z, 0-9.
chars=( {a..z} {A..Z} {0..9} )

for c in "${chars[@]}"; do
    # All directories whose name starts with "syzkaller.<c>".
    # nullglob means this is empty when nothing matches; the ${arr[@]+...}
    # guard keeps that safe under `set -u` on bash 3.2 (macOS).
    batch=( "$search_dir"/syzkaller."$c"* )

    # Keep only real directories whose suffix is exactly 6 alphanumeric chars.
    matches=()
    for dir in ${batch[@]+"${batch[@]}"}; do
        [[ -d "$dir" ]] || continue
        suffix="${dir##*/syzkaller.}"
        [[ "$suffix" =~ ^[A-Za-z0-9]{6}$ ]] || continue
        matches+=( "$dir" )
    done

    [[ ${#matches[@]} -eq 0 ]] && continue

    if [[ "$dry_run" -eq 1 ]]; then
        printf '[dry-run] would remove: %s\n' "${matches[@]}"
    else
        printf 'removing batch syzkaller.%s* (%d dirs)\n' "$c" "${#matches[@]}"
        rm -rf -- "${matches[@]}"
    fi
done
