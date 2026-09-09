#!/usr/bin/env python3
"""Offline tests for triage.py: state machine, panic reconcile, dedup."""
import os
import shutil
import sys
import json
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


class StuckTest(unittest.TestCase):
    """A minimization that cannot do better must stop, not loop.

    The failure this prevents: syz-ring-repro exits 0 with no verified culprit
    both when it needs another boot AND when it has proved no subset reproduces
    alone. Treating both as "relaunch me" spun six triage advances on a real
    campaign and would have burned all forty before halting."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _state(self, **kw):
        p = self.dir / "conn_state.json"
        p.write_text(json.dumps(kw))
        return p

    def test_not_exhausted_when_flag_absent(self):
        self.assertFalse(triage.stage_exhausted(self._state(memo={})))

    def test_exhausted_when_flag_set(self):
        self.assertTrue(triage.stage_exhausted(self._state(exhausted=True)))

    def test_missing_checkpoint_is_not_exhausted(self):
        """No file means nothing has run yet -- that is 'resume', not 'give up'."""
        self.assertFalse(triage.stage_exhausted(self.dir / "absent.json"))

    def test_verified_and_exhausted_are_independent(self):
        st = self._state(verified_crash="8", exhausted=False)
        self.assertTrue(triage.stage_verified(st))
        self.assertFalse(triage.stage_exhausted(st))

    def test_stuck_is_terminal_but_not_a_stage(self):
        """STUCK must not be reachable by advancing through STAGES."""
        self.assertNotIn(triage.STUCK, triage.STAGES)
        self.assertIn(triage.STUCK, triage.TERMINAL)
        self.assertIn("DONE", triage.TERMINAL)




class NoReproDiagnosis(unittest.TestCase):
    """Tell "nothing ever reproduced" apart from "the candidate failed re-check".

    Both end in STUCK, and reporting them identically is what let four
    IOBluetoothFamily jobs spend 25,461 probes concluding "the bug needs
    accumulated state" when the real answer was that syz-ring-repro ran without
    the config's executor_name and never opened a single connection.
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _state(self, memo):
        p = self.tmp / "conn_state.json"
        p.write_text(json.dumps({"kind": "connection", "n_units": 3,
                                 "prog_hash": "abc", "memo": memo,
                                 "exhausted": True}))
        return str(p)

    def test_zero_reproductions_is_an_environment_verdict(self):
        # 3,651 probes, every one clean -- the t4 shape.
        memo = {format(i, "x"): False for i in range(1, 8)}
        self.assertTrue(triage.stage_no_repro(self._state(memo)))

    def test_any_reproduction_is_a_bug_verdict(self):
        memo = {"1": False, "2": True, "4": False}
        self.assertFalse(triage.stage_no_repro(self._state(memo)))

    def test_empty_and_missing_memo_are_not_claimed_as_no_repro(self):
        # Nothing measured yet is not the same as "measured, found nothing"; the
        # caller only consults this once the search reports itself exhausted.
        self.assertTrue(triage.stage_no_repro(self._state({})))
        self.assertFalse(triage.stage_no_repro(str(self.tmp / "absent.json")))


class ExecutorNameFlag(unittest.TestCase):
    """The process name has to survive into the syz-ring-repro argv."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _job(self, **flags):
        return {"ringrepro": "/bin/rr", "executor": "/bin/ex", "flags": flags}

    def test_name_becomes_a_ring_repro_flag(self):
        cmd = triage.ringrepro_cmd(self._job(executor_name="bluetoothd"), "-minimize-conn")
        self.assertIn("-executor_name", cmd)
        self.assertEqual(cmd[cmd.index("-executor_name") + 1], "bluetoothd")

    def test_absent_name_adds_no_flag(self):
        cmd = triage.ringrepro_cmd(self._job(kext_id=32), "-minimize-conn")
        self.assertNotIn("-executor_name", cmd)


if __name__ == "__main__":
    unittest.main()


class ExecScratchPrune(unittest.TestCase):
    """A minimization probe leaves an empty ./syzkaller.XXXXXX behind (created by
    executor/common.h under the cwd exec_dir hands it). Nothing removed them, so
    finished jobs accumulated one per probe -- 407k empty dirs across four jobs,
    which came to 92% of the published tree and dominated every sync's chmod
    walk. They are pruned when a job reaches a terminal stage."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.st = {"name": "j", "dir": str(self.tmp)}
        self.exec_dir = triage.job_dir(self.st) / "exec"
        self.exec_dir.mkdir(parents=True)

    def test_empty_scratch_is_removed(self):
        for i in range(5):
            (self.exec_dir / ("syzkaller.%06d" % i)).mkdir()
        self.assertEqual(triage.prune_exec_scratch(self.st), 5)
        self.assertEqual(list(self.exec_dir.glob("syzkaller.*")), [])

    def test_non_empty_scratch_is_kept(self):
        # Conservative on purpose: a probe that left evidence keeps it.
        keep = self.exec_dir / "syzkaller.KEEPME"
        keep.mkdir()
        (keep / "core").write_text("evidence")
        (self.exec_dir / "syzkaller.000001").mkdir()
        self.assertEqual(triage.prune_exec_scratch(self.st), 1)
        self.assertTrue((keep / "core").exists())

    def test_unrelated_entries_are_untouched(self):
        (self.exec_dir / "notes.txt").write_text("x")
        (self.exec_dir / "other-dir").mkdir()
        triage.prune_exec_scratch(self.st)
        self.assertTrue((self.exec_dir / "notes.txt").exists())
        self.assertTrue((self.exec_dir / "other-dir").is_dir())

    def test_missing_exec_dir_is_not_an_error(self):
        shutil.rmtree(self.exec_dir)
        self.assertEqual(triage.prune_exec_scratch(self.st), 0)
