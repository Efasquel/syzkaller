#!/usr/bin/env python3
"""Offline tests for triage.py: state machine, panic reconcile, dedup."""
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
import triage  # noqa: E402
import crash_fingerprint as cf  # noqa: E402

REPO = Path(__file__).resolve().parent.parent


def real_panics(*globs):
    out = []
    for g in globs:
        out += list(REPO.glob(g))
    return sorted(out)


class TriageOffline(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        # Redirect all triage state/output into the sandbox.
        triage.STATE_DIR = self.tmp / ".state"
        triage.TRIAGE_ROOT = self.tmp / "triage"
        self.panic_dir = self.tmp / "panics"
        self.panic_dir.mkdir()
        triage.PANIC_DIRS = [self.panic_dir]

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _job(self):
        jdir = self.tmp / "job"
        jdir.mkdir(exist_ok=True)
        st = {"name": "j", "dir": str(jdir), "ring_buffer": "x",
              "ringrepro": "rr", "executor": "ex", "flags": {}, "from": -1,
              "to": 0, "stage": "MERGE", "panic_watermark": 0,
              "target_signature": None, "incidents": []}
        triage.save_job(st)
        return triage.load_job("j")

    def _drop(self, src, newer=True):
        """Copy a real panic into the panic dir with a fresh mtime."""
        dst = self.panic_dir / (src.name)
        shutil.copy2(src, dst)
        if newer:
            os.utime(dst, None)   # now
        return dst

    def test_reconcile_sets_target_and_dedups(self):
        jpeg = real_panics("workdir/AppleJPEGDriver/260608_nocov_nogram_2/crashes/repro/panic-full-*.panic")
        if len(jpeg) < 2:
            self.skipTest("need >=2 AppleJPEG panics")
        st = self._job()
        for p in jpeg[:2]:
            self._drop(p)
        inc = triage.reconcile_panics(triage.load_job("j"))
        self.assertEqual(len(inc), 2)
        st = triage.load_job("j")
        target = st["target_signature"]
        self.assertIsNotNone(target)
        # Both are the same bug: one distinct signature, count 2.
        store = cf.load_store(Path(st["dir"]) / "signatures.json")
        self.assertEqual(len(store["signatures"]), 1)
        self.assertEqual(store["signatures"][target]["count"], 2)
        # First is "new", second "known".
        self.assertEqual([i["status"] for i in inc], ["new", "known"])

    def test_reconcile_flags_second_bug(self):
        jpeg = real_panics("workdir/AppleJPEGDriver/260608_nocov_nogram_2/crashes/repro/panic-full-*.panic")
        bt = real_panics("workdir/IOBluetoothFamily/**/panic-full-*.panic")
        if not jpeg or not bt:
            self.skipTest("need a jpeg and a bluetooth panic")
        st = self._job()
        self._drop(jpeg[0])
        triage.reconcile_panics(triage.load_job("j"))
        target = triage.load_job("j")["target_signature"]
        self._drop(bt[0])
        inc = triage.reconcile_panics(triage.load_job("j"))
        # The bluetooth panic is a distinct, new signature (a second bug).
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]["status"], "new")
        self.assertNotEqual(inc[0]["signature"], target)
        self.assertEqual(len(cf.load_store(Path(st["dir"]) / "signatures.json")["signatures"]), 2)

    def test_watermark_skips_seen_reports(self):
        jpeg = real_panics("workdir/AppleJPEGDriver/260608_nocov_nogram_2/crashes/repro/panic-full-*.panic")
        if not jpeg:
            self.skipTest("need a jpeg panic")
        self._job()
        self._drop(jpeg[0])
        self.assertEqual(len(triage.reconcile_panics(triage.load_job("j"))), 1)
        # Second reconcile with no new files: watermark suppresses the old one.
        self.assertEqual(len(triage.reconcile_panics(triage.load_job("j"))), 0)

    def test_stage_verified_reads_checkpoint(self):
        p = self.tmp / "conn_state.json"
        triage.write_json(p, {"verified_crash": "2"})
        self.assertTrue(triage.stage_verified(p))
        triage.write_json(p, {"verified_crash": ""})
        self.assertFalse(triage.stage_verified(p))
        self.assertFalse(triage.stage_verified(self.tmp / "absent.json"))

    def test_ringrepro_cmd_flag_passthrough(self):
        st = self._job()
        st["flags"] = {"kext_id": 1, "sandbox": "none", "debug": True}
        cmd = triage.ringrepro_cmd(st, "-minimize-conn", "prog.syz")
        self.assertIn("-kext_id", cmd)
        self.assertIn("1", cmd)
        self.assertIn("-sandbox", cmd)
        self.assertIn("none", cmd)
        # A bool flag is bare (no value token following it).
        i = cmd.index("-debug")
        self.assertNotEqual(cmd[i + 1], "True")


if __name__ == "__main__":
    unittest.main()
