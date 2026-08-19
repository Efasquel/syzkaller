#!/usr/bin/env python3
"""Fingerprint a macOS kernel panic so the same bug dedups across reboots.

A panic report (a .ips/.panic 2-line JSON with a "panicString" payload, or a
plain-text *.kernel.core.log) names the crash three ways that, taken together,
identify a bug independently of where the kernel happened to be loaded:

  - a *title* (the panic reason, e.g. "Kernel data abort"),
  - the *crashing kext* (first entry under "Kernel Extensions in backtrace:"),
  - a *backtrace* of return addresses.

Raw addresses move every boot (KASLR), so they cannot be compared directly. We
de-slide each frame to an offset within its module (a listed kext, or the kernel
text) — that offset is load-invariant — and hash the ordered (module, offset)
list together with the title and crashing kext. Two panics of the same bug then
produce the same signature; different bugs do not.
"""

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

# --- PAC canonicalization ---------------------------------------------------
CANONICAL_MASK = (1 << 56) - 1
CANONICAL_PREFIX = 0xFFFFFE0000000000

# Kernel text is bounded; the panic log gives its base but not its end. An
# address more than this far above the base is not a text address — it is a
# stack/zone/heap pointer that leaked into a frame — and must NOT be attributed
# to the kernel, because its "offset" would then move with KASLR and split one
# bug into many signatures. 1 GiB is far above any real kernel text span and far
# below the zone map (which sits tens of GiB up), so it separates them cleanly.
KERNEL_TEXT_MAX = 0x40000000


def canonicalize(addr):
    """Strip arm64e PAC bits from a kernel pointer."""
    if (addr >> 56) == 0xFF:
        return addr
    low = addr & CANONICAL_MASK
    if (low >> 48) == 0xFE:
        return low | 0xFFFF000000000000
    return low | CANONICAL_PREFIX


# --- report loading ---------------------------------------------------------
def load_panic_text(path):
    """Return the panic text from a report, whatever its container.

    .ips/.panic are two lines: a header JSON, then a payload JSON carrying the
    panic under "panicString". A *.kernel.core.log is already that text. We
    sniff the first non-space byte: '{' means the JSON container.
    """
    with open(path, "r", errors="replace") as f:
        raw = f.read()
    if raw.lstrip().startswith("{"):
        # Header line, then the payload object (which may span many lines).
        parts = raw.split("\n", 1)
        if len(parts) == 2:
            try:
                payload = json.loads(parts[1])
                ps = payload.get("panicString")
                if ps:
                    return ps
            except ValueError:
                pass
    return raw


# --- parsing ----------------------------------------------------------------
_MODULE_RE = re.compile(
    r'([\w.]+)\([^)]*\)\[[0-9A-Fa-f-]+\]@(0x[0-9a-fA-F]+)->(0x[0-9a-fA-F]+)')
_KTEXT_RE = re.compile(r'Kernel text exec base:\s*(0x[0-9a-fA-F]+)')
_LR_RE = re.compile(r'\blr:\s*(0x[0-9a-fA-F]+)')


def parse_title(text):
    """The panic reason from the first line, normalized so the same bug titles
    identically across occurrences.

    Takes the text after "):" up to the first sentence stop, then scrubs the
    parts that vary run to run: hex addresses, and any standalone numbers (a
    watchdog title embeds elapsed seconds and a checkin count, e.g. "... in 91
    seconds (998 total checkins ...)", which would otherwise split one bug into
    many signatures). Each scrubbed run becomes a single "N"/"0x" placeholder so
    the shape of the title is kept.
    """
    first = text.splitlines()[0] if text else ""
    m = re.search(r'\):\s*(.+)', first)
    reason = m.group(1) if m else first
    reason = reason.split(".")[0].split(" at pc")[0].strip()
    reason = re.sub(r'0x[0-9a-fA-F]+', "0x", reason)
    reason = re.sub(r'\b\d+\b', "N", reason)
    reason = re.sub(r'\s+', " ", reason).strip()
    return reason or "unknown"


def short_kext(name):
    """Last dotted component, e.g. com.apple.iokit.IOBluetoothFamily ->
    IOBluetoothFamily."""
    return name.rsplit(".", 1)[-1] if name else name


def parse_modules(text):
    """Parse the loaded modules that frames can be attributed to.

    Returns (crashing_kext, ranges) where ranges is a list of
    (name, base, end) covering every kext listed under "Kernel Extensions in
    backtrace:" plus a synthetic "kernel" range from the kernel text base to
    infinity. crashing_kext is the first non-dependency entry (the extension the
    backtrace is attributed to), or None.
    """
    ranges = []
    crashing = None
    in_kexts = False
    for line in text.splitlines():
        if "Kernel Extensions in backtrace:" in line:
            in_kexts = True
            continue
        if in_kexts:
            m = _MODULE_RE.search(line)
            if not m:
                # The section ends at the first line without a module entry.
                if line.strip() and "dependency:" not in line:
                    break
                continue
            name, base, end = m.group(1), int(m.group(2), 16), int(m.group(3), 16)
            ranges.append((name, base, end))
            if crashing is None and "dependency:" not in line:
                crashing = name
    km = _KTEXT_RE.search(text)
    if km:
        # Bound the kernel text range: an address far above the base is not text
        # (see KERNEL_TEXT_MAX), so it stays unresolved rather than getting a
        # bogus, slide-varying offset.
        base = int(km.group(1), 16)
        ranges.append(("kernel", base, base + KERNEL_TEXT_MAX))
    return crashing, ranges


def parse_backtrace(text):
    """The panicked thread's return addresses, in order.

    The block starts at the "Panicked thread: ... backtrace:" line and runs to
    "Kernel Extensions in backtrace:". Each frame line carries an lr: (the call
    site) and an fp: (a stack pointer); only lr is a code address, so fp is
    dropped — taking both would poison the signature with stack noise.
    """
    addrs = []
    inside = False
    for line in text.splitlines():
        if not inside:
            if "backtrace:" in line and "tid:" in line:
                inside = True
            continue
        if "Kernel Extensions in backtrace:" in line:
            break
        m = _LR_RE.search(line)
        if m:
            addrs.append(int(m.group(1), 16))
    return addrs


def deslide(addrs, ranges):
    """Turn raw return addresses into load-invariant "module+0xoffset" tokens.

    Each address is canonicalized, then matched against the module ranges;
    kexts are tried before the bounded kernel range so a kext frame is never
    mis-attributed to the kernel. An address in no range becomes a bare "?" —
    its raw value moves with KASLR, so keeping the value would split one bug
    across boots (exactly the failure this guards against). The frame's position
    in the trace is preserved, just not its address.
    """
    kexts = [r for r in ranges if r[0] != "kernel"]
    kernel = [r for r in ranges if r[0] == "kernel"]
    frames = []
    for a in addrs:
        a = canonicalize(a)
        tok = None
        for name, base, end in kexts:
            if base <= a < end:
                tok = "%s+0x%x" % (short_kext(name), a - base)
                break
        if tok is None:
            for name, base, end in kernel:
                if base <= a < end:
                    tok = "kernel+0x%x" % (a - base)
                    break
        frames.append(tok or "?")
    return frames


def fingerprint(path):
    """Parse a report and return its signature and the parts it was built from."""
    text = load_panic_text(path)
    title = parse_title(text)
    crashing, ranges = parse_modules(text)
    frames = deslide(parse_backtrace(text), ranges)
    key = "%s|%s|%s" % (title, crashing or "?", ";".join(frames))
    sig = hashlib.sha256(key.encode()).hexdigest()[:16]
    return {
        "signature": sig,
        "title": title,
        "crashing_kext": short_kext(crashing) if crashing else None,
        "crashing_kext_full": crashing,
        "frames": frames,
    }


# --- signature store --------------------------------------------------------
# A signature store is a JSON object: {"signatures": {sig: record}}. Each record
# is the dedup ledger for one distinct bug — when it was first and last seen, how
# many times, its title/kext, and the reports that produced it. An "ignore" store
# (ignore_signatures.json) has the same shape and is consulted to suppress known
# bugs; a suppressed signature reappearing is still worth flagging to the caller.
def load_store(path):
    """Load a signature store, or an empty one if absent/corrupt."""
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {"signatures": {}}
    data.setdefault("signatures", {})
    return data


def save_store(path, store):
    """Write a store durably (temp file + rename) so a crash mid-write cannot
    corrupt the ledger."""
    tmp = "%s.tmp" % path
    with open(tmp, "w") as f:
        json.dump(store, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def classify(fp, store, ignore=None, report_name=None):
    """Record a fingerprint in the store and say what it is.

    Returns one of: "new" (first time this bug is seen), "known" (seen before),
    or "ignored" (matches the ignore store). The store record is created or
    updated in place; the caller saves it. Ignored signatures are still counted,
    so a suppressed bug's recurrence is visible.
    """
    sig = fp["signature"]
    if ignore and sig in ignore.get("signatures", {}):
        status = "ignored"
    else:
        status = "known" if sig in store["signatures"] else "new"

    rec = store["signatures"].get(sig)
    if rec is None:
        rec = {
            "title": fp["title"],
            "crashing_kext": fp["crashing_kext"],
            "frames": fp["frames"],
            "first_seen": now_iso(),
            "count": 0,
            "reports": [],
        }
        store["signatures"][sig] = rec
    rec["last_seen"] = now_iso()
    rec["count"] += 1
    if report_name:
        rec["reports"].append(report_name)
    return status


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- CLI --------------------------------------------------------------------
def _print_one(fp, frames=False):
    if fp.get("error"):
        print("%s\n  error: %s" % (fp["report"], fp["error"]))
        return
    print("%s  %s  %s  (%d frames)" % (
        fp["signature"], fp["crashing_kext"] or "?", fp["title"], len(fp["frames"])))
    if frames:
        for f in fp["frames"]:
            print("    %s" % f)


def cmd_print(args):
    """Fingerprint reports and print (no store touched)."""
    results = []
    for path in args.report:
        try:
            fp = fingerprint(path)
        except Exception as e:  # noqa: BLE001
            fp = {"signature": None, "error": str(e)}
        fp["report"] = path
        results.append(fp)
    if args.json:
        json.dump(results if len(results) > 1 else results[0], sys.stdout, indent=2)
        print()
        return
    for fp in results:
        _print_one(fp, args.frames)


def cmd_classify(args):
    """Fingerprint reports against a store, updating it; print new/known/ignored.

    Exit status is 0 when at least one report is a NEW signature, 1 otherwise —
    so a driver can branch on "did this crash reveal a new bug?".
    """
    store = load_store(args.store)
    ignore = load_store(args.ignore) if args.ignore else None
    saw_new = False
    out = []
    for path in args.report:
        try:
            fp = fingerprint(path)
        except Exception as e:  # noqa: BLE001
            print("%s\n  error: %s" % (path, e), file=sys.stderr)
            continue
        status = classify(fp, store, ignore, report_name=os.path.basename(path))
        saw_new = saw_new or status == "new"
        rec = {"report": path, "status": status, **fp}
        out.append(rec)
        if not args.json:
            print("%-8s %s  %s  %s" % (status, fp["signature"],
                                       fp["crashing_kext"] or "?", fp["title"]))
    if not args.dry_run:
        save_store(args.store, store)
    if args.json:
        json.dump(out, sys.stdout, indent=2)
        print()
    sys.exit(0 if saw_new else 1)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")

    pp = sub.add_parser("print", help="fingerprint report(s), print, touch no store")
    pp.add_argument("report", nargs="+")
    pp.add_argument("--json", action="store_true")
    pp.add_argument("--frames", action="store_true", help="print the de-slid backtrace")
    pp.set_defaults(func=cmd_print)

    pc = sub.add_parser("classify",
                        help="fingerprint against a store; exit 0 iff a NEW signature")
    pc.add_argument("report", nargs="+")
    pc.add_argument("--store", required=True, help="signatures.json to read+update")
    pc.add_argument("--ignore", help="ignore_signatures.json (suppressed bugs)")
    pc.add_argument("--json", action="store_true")
    pc.add_argument("--dry-run", action="store_true", help="do not write the store")
    pc.set_defaults(func=cmd_classify)

    args = ap.parse_args()
    if not getattr(args, "func", None):
        ap.print_help()
        sys.exit(2)
    args.func(args)


if __name__ == "__main__":
    main()
