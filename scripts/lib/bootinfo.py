"""When this machine last booted.

Two tools need it for different reasons. fuzz-session uses it to tell a pid
recorded before a panic-reboot from a live one. fuzz-campaign uses it to split
the interval since its last checkpoint at the reboot: what came before the boot
was the phase that was running (fuzzing or minimizing), what came after is the
cost of getting back up. Without that split, a crash discovered on the next boot
was charged as fuzzing right through the reboot.
"""

import re
import subprocess

_BOOT_EPOCH = None


def boot_epoch():
    """Seconds-since-epoch of the current boot (kern.boottime), or None.

    Cached: it does not change within a process's life, and the callers ask
    often. Note macOS derives it as wall clock minus uptime, so NTP corrections
    move it by a second or so; compare with slack, never for equality.
    """
    global _BOOT_EPOCH
    if _BOOT_EPOCH is None:
        try:
            out = subprocess.run(["sysctl", "-n", "kern.boottime"],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 text=True, timeout=5).stdout
            m = re.search(r"sec\s*=\s*(\d+)", out)
            _BOOT_EPOCH = int(m.group(1)) if m else False
        except (OSError, ValueError, subprocess.SubprocessError):
            _BOOT_EPOCH = False
    return _BOOT_EPOCH or None
