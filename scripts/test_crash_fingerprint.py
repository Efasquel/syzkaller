#!/usr/bin/env python3
"""Offline tests for crash_fingerprint against synthetic and real panic logs."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import crash_fingerprint as cf  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def real(*globs):
    """Return sorted real panic reports matching any glob under workdir/, or []."""
    import glob
    out = []
    for g in globs:
        out += glob.glob(os.path.join(REPO, g), recursive=True)
    return sorted(out)


class TitleNorm(unittest.TestCase):
    def test_scrubs_addresses_and_numbers(self):
        # A watchdog title embeds elapsed seconds + checkin count; both vary.
        a = cf.parse_title("panic(cpu 4 caller 0xabc): watchdog timeout: no "
                           "checkins from watchdogd in 91 seconds (998 total)")
        b = cf.parse_title("panic(cpu 1 caller 0xdef): watchdog timeout: no "
                           "checkins from watchdogd in 12 seconds (5 total)")
        self.assertEqual(a, b)
        self.assertIn("N seconds", a)

    def test_data_abort_stable(self):
        a = cf.parse_title("panic(cpu 4 caller 0x1): Kernel data abort. at pc 0x2, lr 0x3")
        self.assertEqual(a, "Kernel data abort")


class Deslide(unittest.TestCase):
    def test_kext_and_kernel_and_unknown(self):
        # Use canonical-form kernel addresses (deslide canonicalizes its input).
        kbase = 0xFFFFFE004B094000
        fbase = 0xFFFFFE004AA05250
        ranges = [("com.apple.iokit.Foo", fbase, fbase + 0x1000),
                  ("kernel", kbase, kbase + cf.KERNEL_TEXT_MAX)]
        # in-kext, in-kernel, and a stack address far above kernel base.
        got = cf.deslide([fbase + 0x500, kbase + 0xabc, kbase + cf.KERNEL_TEXT_MAX + 1], ranges)
        self.assertEqual(got, ["Foo+0x500", "kernel+0xabc", "?"])

    def test_bogus_offset_becomes_unknown_not_giant(self):
        # The AppleJPEG failure: an address just past the text cap must NOT get a
        # multi-GB "kernel+0x..." offset that moves with KASLR.
        kbase = 0xFFFFFE004B094000
        ranges = [("kernel", kbase, kbase + cf.KERNEL_TEXT_MAX)]
        self.assertEqual(cf.deslide([kbase + 0x138239c34], ranges), ["?"])


@unittest.skipUnless(real("workdir/AppleJPEGDriver/**/panic-full-*.panic"),
                     "no real AppleJPEGDriver panics present")
class RealPanics(unittest.TestCase):
    def test_same_bug_same_signature(self):
        # Every AppleJPEGDriver repro panic is the same bug -> one signature.
        import glob
        files = sorted(glob.glob(os.path.join(
            REPO, "workdir/AppleJPEGDriver/260608_nocov_nogram_2/crashes/repro/"
            "panic-full-*.panic")))
        if len(files) < 2:
            self.skipTest("need >=2 AppleJPEG repro panics")
        sigs = {cf.fingerprint(f)["signature"] for f in files}
        self.assertEqual(len(sigs), 1, "same bug produced %d signatures" % len(sigs))

    def test_distinct_bugs_distinct_signatures(self):
        bt = real("workdir/IOBluetoothFamily/**/panic-full-*.panic")
        jpeg = real("workdir/AppleJPEGDriver/260608_nocov_nogram_2/crashes/repro/panic-full-*.panic")
        if not bt or not jpeg:
            self.skipTest("need both a bluetooth and a jpeg panic")
        self.assertNotEqual(cf.fingerprint(bt[0])["signature"],
                            cf.fingerprint(jpeg[0])["signature"])


class Store(unittest.TestCase):
    def _fp(self, sig, title="t", kext="K"):
        return {"signature": sig, "title": title, "crashing_kext": kext, "frames": []}

    def test_new_then_known(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sig.json")
            store = cf.load_store(path)
            self.assertEqual(cf.classify(self._fp("aaa"), store), "new")
            self.assertEqual(cf.classify(self._fp("aaa"), store), "known")
            self.assertEqual(store["signatures"]["aaa"]["count"], 2)
            cf.save_store(path, store)
            self.assertEqual(cf.load_store(path)["signatures"]["aaa"]["count"], 2)

    def test_ignore_suppresses(self):
        store = cf.load_store("/nonexistent")
        ignore = {"signatures": {"bbb": {}}}
        self.assertEqual(cf.classify(self._fp("bbb"), store, ignore), "ignored")
        # still counted, so recurrence of a suppressed bug is visible.
        self.assertEqual(store["signatures"]["bbb"]["count"], 1)


class MatchSince(unittest.TestCase):
    """The crash gate's match-since verdict (fingerprint stubbed by path)."""

    def _run(self, tmp, files_by_sig, target, since):
        # files_by_sig: {filename: (signature, mtime)}. Write each and map its
        # path to that signature via a stubbed fingerprint.
        from argparse import Namespace
        from io import StringIO
        from unittest import mock
        import contextlib

        path_sig = {}
        for fname, (sig, mtime) in files_by_sig.items():
            p = os.path.join(tmp, fname)
            with open(p, "w") as f:
                f.write("report")
            os.utime(p, (mtime, mtime))
            path_sig[os.path.abspath(p)] = sig

        def fake_fp(path):
            return {"signature": path_sig.get(os.path.abspath(path))}

        out = StringIO()
        args = Namespace(target=target, since=since, dir=[tmp])
        with mock.patch.object(cf, "fingerprint", fake_fp), \
             contextlib.redirect_stdout(out):
            cf.cmd_match_since(args)
        return out.getvalue().strip()

    def test_match(self):
        with tempfile.TemporaryDirectory() as d:
            v = self._run(d, {"a.panic": ("SIGT", 1000.0)}, target="SIGT", since=900.0)
            self.assertEqual(v, "match")

    def test_other(self):
        with tempfile.TemporaryDirectory() as d:
            v = self._run(d, {"a.panic": ("SIGX", 1000.0)}, target="SIGT", since=900.0)
            self.assertEqual(v, "other SIGX")

    def test_none_when_all_older(self):
        with tempfile.TemporaryDirectory() as d:
            # mtime well before since - slack => not considered.
            v = self._run(d, {"a.panic": ("SIGT", 100.0)}, target="SIGT", since=900.0)
            self.assertEqual(v, "none")

    def test_slack_window_includes_just_before(self):
        with tempfile.TemporaryDirectory() as d:
            # 1s before since is within the 2s grace window => counted.
            v = self._run(d, {"a.panic": ("SIGT", 899.0)}, target="SIGT", since=900.0)
            self.assertEqual(v, "match")


if __name__ == "__main__":
    unittest.main()
