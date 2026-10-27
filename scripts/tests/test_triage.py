#!/usr/bin/env python3
"""Offline tests for triage.py: state machine, panic reconcile, dedup."""
import contextlib
import io
import os
import shutil
import sys
import json
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

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


class ProbesLogTest(unittest.TestCase):
    """A probe's output goes to the job's probes.log, not to whoever runs
    triage: one minimization once wrote 33k lines into the campaign's log."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.st = {"dir": str(self.tmp), "name": "t1"}

    def test_a_probe_writes_to_probes_log(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = triage.run_probe(self.st, ["/bin/echo", "probe chatter"])
        self.assertEqual(rc, 0)
        text = (self.tmp / "probes.log").read_text()
        self.assertIn("$ /bin/echo probe chatter", text)
        self.assertIn("probe chatter\n", text)

    def test_probes_log_rotates_past_its_cap(self):
        (self.tmp / "probes.log").write_text("old\n")
        with mock.patch.object(triage, "PROBES_MAX_MB", 0):
            triage.run_probe(self.st, ["/bin/echo", "new"])
        self.assertEqual((self.tmp / "probes.log.1").read_text(), "old\n")
        self.assertNotIn("old", (self.tmp / "probes.log").read_text())


class FakeRingRepro:
    """Stands in for subprocess.run: plays syz-ring-repro by writing the
    checkpoint a real run would leave, then returning its exit code."""

    def __init__(self, jdir, write, rc=0):
        self.jdir, self.write, self.rc, self.calls = Path(jdir), write, rc, []

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        self.write(self.jdir, cmd)
        return types.SimpleNamespace(returncode=self.rc, stdout="")


class OutcomeTest(unittest.TestCase):
    """What each way a minimization can end turns the job into."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        triage.STATE_DIR = self.tmp / ".state"
        triage.PANIC_DIRS = []
        self.jdir = self.tmp / "job"
        self.jdir.mkdir()
        ring = self.tmp / "ring"
        ring.mkdir()
        for i in range(3):
            (ring / ("slot_%04d.syz" % i)).write_text("id=%d\nopen()\n" % i)
        self.st = {"name": "j", "dir": str(self.jdir), "ring_buffer": str(ring),
                   "ringrepro": "rr", "executor": "ex", "flags": {}, "from": -1,
                   "to": 0, "stage": "MINIMIZE_CONN", "panic_watermark": 0,
                   "target_signature": "abcd", "incidents": [],
                   "merged": str(self.jdir / "merged.syz")}
        Path(self.st["merged"]).write_text("merged\n")
        triage.save_job(self.st)
        self.orig_run = triage.subprocess.run
        self.addCleanup(setattr, triage.subprocess, "run", self.orig_run)
        self.addCleanup(setattr, triage, "REBOOT_ON_HANG", False)
        for name in ("diagnose_hang", "job_executor_pids"):
            self.addCleanup(setattr, triage, name, getattr(triage, name))
        triage.diagnose_hang = lambda st, n: str(self.jdir / "hangs" / str(n))
        # cmd_run asks for the boot time; never let the fake answer that.
        self.addCleanup(setattr, triage.bootinfo, "boot_epoch", triage.bootinfo.boot_epoch)
        triage.bootinfo.boot_epoch = lambda: time.time() - 600

    def play(self, write, rc=0):
        fake = FakeRingRepro(self.jdir, write, rc)
        triage.subprocess.run = fake
        st = triage.load_job("j")
        triage.advance(st)
        return triage.load_job("j"), fake

    @staticmethod
    def checkpoint(name, **kw):
        def write(jdir, cmd):
            (jdir / name).write_text(json.dumps(kw))
            (jdir / "culprit.syz").write_text("culprit\n")
        return write

    def test_conn_search_with_no_hit_replays_the_ring(self):
        st, _ = self.play(self.checkpoint(
            "conn_state.json", memo={"1": False, "2": False}, exhausted=True,
            untestable=["3"]))
        self.assertEqual(st["stage"], triage.REPLAY)
        self.assertEqual(st["conn_untestable"], 1)

    def test_conn_search_with_hits_that_fail_recheck_is_an_unverified_lead(self):
        st, _ = self.play(self.checkpoint(
            "conn_state.json", memo={"1": True, "2": False}, exhausted=True))
        self.assertEqual((st["stage"], st["stuck_kind"]), (triage.STUCK, "unverified"))
        self.assertTrue(Path(st["conn_culprit"]).exists())

    def test_call_search_failing_keeps_the_verified_connection_culprit(self):
        conn = self.jdir / "conn_culprit.syz"
        conn.write_text("conn\n")
        self.st.update(stage="MINIMIZE_CALLS", conn_culprit=str(conn))
        triage.save_job(self.st)
        st, _ = self.play(self.checkpoint(
            "call_state.json", memo={"1": False}, exhausted=True))
        self.assertEqual(st["stage"], "DONE")
        self.assertEqual(st["final_culprit"], str(conn))
        self.assertIs(st["calls_reduced"], False)
        self.assertTrue(Path(st["call_lead"]).exists())
        self.assertEqual(triage.result_path(st), str(conn))

    def replay(self, **result):
        self.st["stage"] = triage.REPLAY
        triage.save_job(self.st)
        st, fake = self.play(self.checkpoint("replay_state.json", **result))
        self.assertIn("-replay-ring", fake.calls[0])
        return st

    def test_ring_that_does_not_crash_ends_no_repro(self):
        st = self.replay(result="clean")
        self.assertEqual((st["stage"], st["stuck_kind"]), (triage.STUCK, "no-repro"))
        self.assertIsNone(triage.result_path(st))
        self.assertIn("no-repro", triage.NO_CULPRIT_KINDS)

    def test_ring_that_crashes_twice_is_kept_as_the_reproducer(self):
        st = self.replay(result="verified", crash_slot="slot_0002.syz")
        self.assertEqual(st["stuck_kind"], "ring-only")
        self.assertEqual(sorted(p.name for p in Path(st["ring_copy"]).iterdir()),
                         ["slot_0000.syz", "slot_0001.syz", "slot_0002.syz"])
        self.assertEqual(triage.result_path(st), st["ring_copy"])
        self.assertIn("slot_0002.syz", st["stuck_reason"])

    def test_ring_replay_hitting_another_bug(self):
        self.assertEqual(self.replay(result="other")["stuck_kind"], "ring-other")

    def test_ring_replay_without_an_answer_resumes(self):
        st = self.replay(pending="replay")
        self.assertEqual(st["stage"], triage.REPLAY)

    def hang(self, rc=1):
        def write(jdir, cmd):
            if cmd[0] == "rr":
                (jdir / "conn_state.json").write_text(json.dumps(
                    {"memo": {}, "hanging": "5", "hanging_at": time.time()}))
                (jdir / "hang.syz").write_text("hung\n")
        return self.play(write, rc)

    def test_a_hang_is_recorded_and_the_job_waits_for_a_reboot(self):
        st, fake = self.hang()
        self.assertEqual(st["stage"], "MINIMIZE_CONN")
        self.assertEqual([h["unit"] for h in st["hangs"]], ["5"])
        self.assertNotIn("needs_reboot", st)        # not asked to reboot
        self.assertEqual(len(fake.calls), 1)        # no shutdown attempted

    def test_the_third_hang_is_the_answer(self):
        for _ in range(3):
            st, _ = self.hang()
        self.assertEqual((st["stage"], st["stuck_kind"]), (triage.STUCK, "hang"))
        self.assertEqual(Path(st["hang_culprit"]).read_text(), "hung\n")
        self.assertEqual(triage.result_path(st), st["hang_culprit"])

    def test_a_failed_reboot_is_recorded_for_the_campaign(self):
        triage.REBOOT_ON_HANG = True
        st, fake = self.hang()
        self.assertEqual(fake.calls[-1], triage.REBOOT_CMD)
        self.assertIn("needs_reboot", st)

    def test_old_hang_is_not_this_runs(self):
        def write(jdir, cmd):
            (jdir / "conn_state.json").write_text(json.dumps(
                {"memo": {}, "hanging": "5", "hanging_at": 1}))
        st, _ = self.play(write, rc=1)
        self.assertNotIn("hangs", st)

    def test_a_job_waiting_for_a_reboot_does_nothing_until_one_happens(self):
        self.st["needs_reboot"] = {"at": time.time(), "why": "sudo refused"}
        triage.save_job(self.st)
        fake = FakeRingRepro(self.jdir, lambda j, c: None)
        triage.subprocess.run = fake
        triage.cmd_run("j")
        self.assertEqual(fake.calls, [])
        self.st["needs_reboot"]["at"] = 1            # a boot has happened since
        triage.save_job(self.st)
        triage.cmd_run("j")
        self.assertNotIn("needs_reboot", triage.load_job("j"))

    def test_programs_saved_for_other_bugs_are_recorded(self):
        def write(jdir, cmd):
            (jdir / "conn_state.json").write_text(json.dumps({"memo": {}}))
            (jdir / "other_beef01.syz").write_text("other\n")
        triage.subprocess.run = FakeRingRepro(self.jdir, write, rc=1)
        triage.cmd_run("j")
        st = triage.load_job("j")
        self.assertEqual(st["other_bugs"]["beef01"]["program"],
                         str(self.jdir / "other_beef01.syz"))
        self.assertEqual(st["stage"], "MINIMIZE_CONN")   # the job itself goes on


class ProgressTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_a_search_in_progress(self):
        (self.tmp / "conn_state.json").write_text(json.dumps({
            "n_units": 14, "memo": {"1": False, "2": False, "4": True},
            "attempting": "6", "untestable": ["ff"]}))
        st = {"dir": str(self.tmp), "stage": "MINIMIZE_CONN", "hangs": [{}],
              "incidents": [{"signature": "T"}, {"signature": "O", "other": True}],
              "other_bugs": {"O": {}}}
        p = triage.progress(st)
        self.assertEqual((p["tested"], p["hits"], p["units"], p["pending_size"],
                          p["untestable"], p["other_panics"], p["hangs"]),
                         (3, 1, 14, 2, 1, 1, 1))
        line = triage.progress_line(p)
        self.assertIn("3 connection subset(s) tested of 14 connections, 1 crashed", line)
        self.assertIn("testing a 2-connection subset", line)
        self.assertIn("1 from OTHER bugs (O)", line)

    def test_a_ring_replay_in_progress(self):
        (self.tmp / "replay_state.json").write_text(json.dumps({
            "slots": 40, "pending": "verify", "pending_slot": "slot_0012.syz",
            "crash_slot": "slot_0030.syz"}))
        p = triage.progress({"dir": str(self.tmp), "stage": triage.REPLAY})
        self.assertIn("verify pass at slot_0012.syz of 40 slots", triage.progress_line(p))


class PathAddressed(unittest.TestCase):
    """A job can live in an arbitrary dir with its state INSIDE that dir,
    addressed by path, while legacy name-keyed jobs keep working. This is what
    lets a triage job live under its campaign item, where no name is unique."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        # list and the launchd plist walk REPO_ROOT; everything is name/path
        # resolution otherwise. Sandbox all three and restore on teardown.
        self._saved = (triage.STATE_DIR, triage.TRIAGE_ROOT, triage.REPO_ROOT,
                       triage.PANIC_DIRS)
        triage.STATE_DIR = self.tmp / ".state"
        triage.TRIAGE_ROOT = self.tmp / "triage"
        triage.REPO_ROOT = self.tmp
        triage.PANIC_DIRS = []
        self.addCleanup(self._restore)

    def _restore(self):
        (triage.STATE_DIR, triage.TRIAGE_ROOT, triage.REPO_ROOT,
         triage.PANIC_DIRS) = self._saved

    def _ring(self):
        r = self.tmp / "ring"
        r.mkdir(exist_ok=True)
        (r / "slot_0000.syz").write_text("open()\n")
        return r

    def _new(self, name, job_dir_arg=None):
        # cmd_new requires only that the ring buffer exists; the rest are strings.
        triage.cmd_new(name, str(self._ring()), "ex", "rr", None, None, None,
                       None, None, None, -1, 0, False, job_dir_arg=job_dir_arg)

    @staticmethod
    def _capture(fn, *a):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            fn(*a)
        return buf.getvalue()

    def test_new_dir_writes_job_json_in_the_dir_and_nothing_under_state_dir(self):
        jdir = (self.tmp / "campaigns" / "c" / "cfg" / "item" / "triage" / "t1")
        self._new("t1", job_dir_arg=str(jdir))
        self.assertTrue((jdir / "job.json").is_file())
        st = triage.read_json(jdir / "job.json")
        # The short name is preserved; dir and state_path are absolute.
        self.assertEqual(st["name"], "t1")
        self.assertEqual(st["dir"], str(jdir.resolve()))
        self.assertEqual(st["state_path"], str((jdir / "job.json").resolve()))
        self.assertTrue(triage.is_path_addressed(st))
        state_jsons = (sorted(triage.STATE_DIR.glob("*.json"))
                       if triage.STATE_DIR.is_dir() else [])
        self.assertEqual(state_jsons, [])

    def test_legacy_new_still_writes_under_state_dir_with_state_path(self):
        self._new("leg")
        sp = triage.STATE_DIR / "leg.json"
        self.assertTrue(sp.is_file())
        st = triage.read_json(sp)
        # state_path is recorded for uniformity, but the job is NOT path-addressed.
        self.assertEqual(st["state_path"], str(sp.resolve()))
        self.assertFalse(triage.is_path_addressed(st))
        self.assertEqual(triage.job_ident(st), "leg")

    def test_load_job_by_dir_by_file_and_by_legacy_name(self):
        jdir = (self.tmp / "job").resolve()
        self._new("t2", job_dir_arg=str(jdir))
        self.assertEqual(triage.load_job(str(jdir))["name"], "t2")
        self.assertEqual(triage.load_job(str(jdir / "job.json"))["name"], "t2")
        self._new("leg")
        self.assertEqual(triage.load_job("leg")["name"], "leg")

    def test_save_job_round_trips_to_the_dir(self):
        jdir = (self.tmp / "job").resolve()
        self._new("t2", job_dir_arg=str(jdir))
        st = triage.load_job(str(jdir))
        st["stage"] = "DONE"
        triage.save_job(st)
        # It went back into the dir, not to the legacy STATE_DIR path.
        self.assertEqual(triage.read_json(jdir / "job.json")["stage"], "DONE")
        self.assertFalse((triage.STATE_DIR / "t2.json").exists())
        self.assertEqual(triage.load_job(str(jdir))["stage"], "DONE")

    def test_list_finds_path_addressed_and_legacy_jobs(self):
        jdir = self.tmp / "campaigns" / "camp" / "cfg" / "item" / "triage" / "t1"
        self._new("t1", job_dir_arg=str(jdir))
        self._new("leg")
        out = self._capture(triage.cmd_list)
        self.assertIn("t1", out)
        self.assertIn("leg", out)
        # The path-addressed row shows its location, relative to REPO_ROOT.
        self.assertIn("campaigns/camp/cfg/item/triage/t1", out)

    def test_run_accepts_a_path_and_persists_back_into_the_dir(self):
        jdir = (self.tmp / "job").resolve()
        self._new("t3", job_dir_arg=str(jdir))
        # Stub the stage runner: prove run resolves the job by path, advances it,
        # and saves back into the dir -- no device work.
        seen = []

        def fake_merge(st):
            seen.append(st["name"])
            st["stage"] = "DONE"
            triage.save_job(st)
        self.addCleanup(setattr, triage, "run_merge", triage.run_merge)
        triage.run_merge = fake_merge
        self.addCleanup(setattr, triage.bootinfo, "boot_epoch",
                        triage.bootinfo.boot_epoch)
        triage.bootinfo.boot_epoch = lambda: time.time()
        triage.cmd_run(str(jdir))
        self.assertEqual(seen, ["t3"])
        self.assertEqual(triage.load_job(str(jdir))["stage"], "DONE")

    def test_status_accepts_a_path(self):
        jdir = (self.tmp / "job").resolve()
        self._new("t3", job_dir_arg=str(jdir))
        out = self._capture(triage.cmd_status, str(jdir))
        self.assertIn("t3", out)
        self.assertIn(str(jdir), out)

    def test_plist_argv_round_trips_a_path_for_relaunch(self):
        jdir = (self.tmp / "job").resolve()
        self._new("t3", job_dir_arg=str(jdir))
        st = triage.load_job(str(jdir))
        xml = triage._plist_xml(st)
        # The relaunch must re-address the same job: its dir is in the argv, and
        # load_job accepts that dir.
        self.assertIn("<string>run</string>", xml)
        self.assertIn("<string>%s</string>" % str(jdir), xml)
        self.assertEqual(triage.job_ident(st), str(jdir))
        # A path-addressed job's launchd label/log fold in the path, so two jobs
        # that share the short name "t3" do not collide.
        other = (self.tmp / "job2").resolve()
        self._new("t3", job_dir_arg=str(other))
        st2 = triage.load_job(str(other))
        self.assertNotEqual(triage.plist_label(st), triage.plist_label(st2))
        self.assertNotEqual(triage.launchd_log(st), triage.launchd_log(st2))
