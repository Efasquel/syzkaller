#!/usr/bin/env python3
"""Tests for fuzz-session liveness and scratch handling.

Both bugs covered here produced the same class of failure: a healthy thing
reported as dead, or an impossible cleanup reported as work."""

import errno
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


def _load():
    path = Path(__file__).resolve().parent / "fuzz-session.py"
    spec = importlib.util.spec_from_file_location("fuzz_session", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


fs = _load()


class PidAliveTest(unittest.TestCase):
    """os.kill(pid, 0) distinguishes three cases, and only one of them is death."""

    def test_live_process_is_alive(self):
        self.assertTrue(fs.pid_alive(os.getpid()))

    def test_eperm_means_alive_not_dead(self):
        """EPERM says the process EXISTS but belongs to another user. The
        campaign runs as `fuzz` and is inspected from an admin account, so
        reading EPERM as death made every cross-user check lie -- it reported a
        manager with twenty hours of uptime as crashed, and stop_one() then
        refused to signal it."""
        def eperm(pid, sig):
            raise PermissionError(errno.EPERM, "Operation not permitted")
        with mock.patch.object(fs.os, "kill", eperm):
            self.assertTrue(fs.pid_alive(4242))

    def test_esrch_means_dead(self):
        def esrch(pid, sig):
            raise ProcessLookupError(errno.ESRCH, "No such process")
        with mock.patch.object(fs.os, "kill", esrch):
            self.assertFalse(fs.pid_alive(4242))

    def test_no_pid_is_dead(self):
        self.assertFalse(fs.pid_alive(None))
        self.assertFalse(fs.pid_alive(0))

    def test_pid_from_a_previous_boot_is_dead(self):
        """Otherwise a stale record reads as running after every panic-reboot,
        and the stop path signals whatever inherited the number."""
        with mock.patch.object(fs, "boot_epoch", lambda: 2000):
            self.assertFalse(fs.pid_alive(os.getpid(), rec_boot=1000))

    def test_matching_boot_epoch_is_checked_normally(self):
        with mock.patch.object(fs, "boot_epoch", lambda: 1000):
            self.assertTrue(fs.pid_alive(os.getpid(), rec_boot=1000))


class RetireScratchTest(unittest.TestCase):
    """Scratch dirs live in sticky /tmp, so only their owner can rename them."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.scratch = self.dir / "syz-exec-sid-0"
        self.scratch.mkdir()
        (self.scratch / "child").mkdir()

    def test_rename_is_the_normal_path(self):
        with mock.patch.object(fs, "EXEC_SCRATCH_BASE", self.dir):
            trash = fs.retire_scratch(self.scratch)
        self.assertIsNotNone(trash)
        self.assertFalse(self.scratch.exists())
        self.assertTrue(Path(trash).is_dir())

    def test_eperm_does_not_walk_the_tree(self):
        """The fallback walked all 65,535 subdirectories, failed on each,
        swallowed the error and deleted nothing -- minutes that looked exactly
        like a hung stop."""
        walked = []

        def eperm(a, b):
            raise OSError(errno.EPERM, "Operation not permitted")

        with mock.patch.object(fs, "EXEC_SCRATCH_BASE", self.dir), \
             mock.patch.object(fs.os, "rename", eperm), \
             mock.patch.object(fs.shutil, "rmtree",
                               lambda *a, **k: walked.append(a)):
            self.assertIsNone(fs.retire_scratch(self.scratch))
        self.assertEqual(walked, [])          # never started the walk
        self.assertTrue(self.scratch.exists())  # left for its owner

    def test_exdev_does_fall_back_to_a_delete(self):
        """Cross-device is the one case where the rename is impossible but the
        removal is not."""
        walked = []

        def exdev(a, b):
            raise OSError(errno.EXDEV, "Cross-device link")

        with mock.patch.object(fs, "EXEC_SCRATCH_BASE", self.dir), \
             mock.patch.object(fs.os, "rename", exdev), \
             mock.patch.object(fs.shutil, "rmtree",
                               lambda *a, **k: walked.append(a)):
            fs.retire_scratch(self.scratch)
        self.assertEqual(len(walked), 1)

    def test_missing_dir_is_a_no_op(self):
        self.assertIsNone(fs.retire_scratch(self.dir / "absent"))


class RpcPortTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.log = self.dir / "run.log"

    def test_reads_the_port(self):
        self.log.write_text("blah\nserving rpc on tcp://53481\n")
        self.assertEqual(fs.wait_for_rpc_port(self.log, timeout=1), 53481)

    def test_timeout_returns_none(self):
        self.log.write_text("nothing here\n")
        self.assertIsNone(fs.wait_for_rpc_port(self.log, timeout=0.2))

    def test_gives_up_early_when_the_manager_dies(self):
        """No point burning the whole timeout on a corpse."""
        self.log.write_text("starting\n")
        with mock.patch.object(fs, "pid_alive", lambda *a, **k: False):
            self.assertIsNone(fs.wait_for_rpc_port(self.log, timeout=30, pid=999))

    def test_timeout_is_generous_enough_for_a_large_grammar(self):
        """A 91-syscall config took 96s to serve; a 60s cap cost it an hour of
        budget sitting idle with no executor."""
        self.assertGreaterEqual(fs.RPC_PORT_TIMEOUT, 120)


class OrphanExecutorTest(unittest.TestCase):
    """The executor holds the coverage device EXCLUSIVELY, so one wedged in the
    kernel makes every later manager die with 'open of kcov device failed
    (errno 16)'. No restart can succeed until it is gone -- which is how a single
    hung program turned a campaign into a halt rather than a recovery."""

    def _ps(self, lines):
        out = "PID COMMAND\n" + "".join(lines)
        return mock.patch.object(fs.subprocess, "run",
                                 lambda *a, **k: type("R", (), {"stdout": out})())

    def test_untracked_executor_is_an_orphan(self):
        with self._ps(["  527 %s exec\n" % fs.EXECUTOR_BIN]):
            self.assertEqual([p for p, _ in fs.orphan_executors({})], [527])

    def test_this_sessions_own_executors_are_left_alone(self):
        state = {"executors": [{"pid": 527}]}
        with self._ps(["  527 %s exec\n" % fs.EXECUTOR_BIN]):
            self.assertEqual(fs.orphan_executors(state), [])

    def test_only_our_executor_binary_is_touched(self):
        """Nothing outside this tree is ever killed."""
        with self._ps(["  900 /somewhere/else/syz-executor exec\n"]):
            self.assertEqual(fs.orphan_executors({}), [])

    def test_nothing_running_is_no_orphans(self):
        with self._ps([]):
            self.assertEqual(fs.orphan_executors({}), [])

    def test_reap_kills_a_normal_orphan(self):
        killed = []
        with self._ps(["  527 %s exec\n" % fs.EXECUTOR_BIN]), \
             mock.patch.object(fs, "proc_state", lambda pid: "S"), \
             mock.patch.object(fs.os, "kill", lambda pid, sig: killed.append(pid)), \
             mock.patch.object(fs.time, "sleep", lambda n: None):
            freed, wedged = fs.reap_orphan_executors({})
        self.assertIn(527, killed)
        self.assertEqual(wedged, [])

    def test_a_permission_error_does_not_raise(self):
        """Killing another user's executor needs sudo; that must warn, not crash
        the session start."""
        def eperm(pid, sig):
            raise PermissionError("nope")
        with self._ps(["  527 %s exec\n" % fs.EXECUTOR_BIN]), \
             mock.patch.object(fs, "proc_state", lambda pid: "S"), \
             mock.patch.object(fs.os, "kill", eperm), \
             mock.patch.object(fs.time, "sleep", lambda n: None):
            fs.reap_orphan_executors({})


class UnkillableTest(unittest.TestCase):
    """STAT 'U' is uninterruptible sleep: the thread is inside a kernel call
    that never returns and never checks for signals, so SIGKILL is only QUEUED.
    This is what a real driver hang looks like from userspace, and it is the one
    case where the honest answer is 'only a reboot clears this'."""

    def test_u_state_is_unkillable(self):
        with mock.patch.object(fs, "proc_state", lambda pid: "U"):
            self.assertTrue(fs.unkillable(527))

    def test_ordinary_states_are_killable(self):
        for st in ("S", "R", "S+", "Ss", "Z"):
            with mock.patch.object(fs, "proc_state", lambda pid, _s=st: _s):
                self.assertFalse(fs.unkillable(1), st)

    def test_a_gone_process_is_not_unkillable(self):
        with mock.patch.object(fs, "proc_state", lambda pid: ""):
            self.assertFalse(fs.unkillable(999999))

    def test_reap_does_not_bother_signalling_a_wedged_process(self):
        """SIGKILL cannot reach it, so sending one is noise that also looks like
        the problem was addressed."""
        killed = []
        with self._ps_u(["  527 %s exec\n" % fs.EXECUTOR_BIN]), \
             mock.patch.object(fs, "proc_state", lambda pid: "U"), \
             mock.patch.object(fs.os, "kill", lambda pid, sig: killed.append(pid)), \
             mock.patch.object(fs.time, "sleep", lambda n: None):
            freed, wedged = fs.reap_orphan_executors({})
        self.assertEqual(killed, [])
        self.assertEqual(wedged, [527])

    def _ps_u(self, lines):
        out = "PID COMMAND\n" + "".join(lines)
        return mock.patch.object(fs.subprocess, "run",
                                 lambda *a, **k: type("R", (), {"stdout": out})())


class DiagnoseHangTest(unittest.TestCase):
    """A wedged executor is blocked in ONE call, so unlike a crash -- where the
    fault is state-dependent and you need the whole sequence -- the stack IS the
    answer. Seconds and no reboots, against a minimizer that costs a reboot per
    positive probe."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def _sample(self, body, rc=0):
        return mock.patch.object(
            fs, "_run_capture", lambda cmd, timeout=90: (rc, body))

    def test_extracts_the_blocked_call(self):
        body = ("Thread 0x1\n"
                "  2000 IOConnectCallMethod  (in IOKit)\n"
                "  2000 unrelated_frame  (in libsystem)\n")
        with self._sample(body), \
             mock.patch.object(fs, "proc_state", lambda pid: "U"):
            res = fs.diagnose_hang([527], self.dir)
        pid, path, frames = res[0]
        self.assertEqual(pid, 527)
        self.assertTrue(Path(path).is_file())
        self.assertTrue(any("IOConnectCallMethod" in f for f in frames))
        self.assertFalse(any("unrelated_frame" in f for f in frames))

    def test_saves_the_full_dump_not_just_the_matches(self):
        """The filter is a convenience; the evidence is the whole stack."""
        body = "Thread 0x1\n  2000 mach_msg_trap\n  2000 something_else\n"
        with self._sample(body), mock.patch.object(fs, "proc_state", lambda pid: "U"):
            _, path, _ = fs.diagnose_hang([527], self.dir)[0]
        self.assertIn("something_else", Path(path).read_text())

    def test_no_stack_is_reported_not_faked(self):
        """Both tools need root for another user's process; that must be said,
        not silently produce an empty result that looks like a clean stack."""
        with self._sample("", rc=1), mock.patch.object(fs, "proc_state", lambda pid: "U"):
            pid, path, frames = fs.diagnose_hang([527], self.dir)[0]
        self.assertIsNone(path)
        self.assertEqual(frames, [])

    def test_no_wedged_process_is_not_an_error(self):
        with mock.patch.object(fs, "orphan_executors", lambda st: []):
            self.assertEqual(fs.diagnose_hang(None, self.dir), [])

    def test_finds_wedged_executors_when_no_pid_given(self):
        with mock.patch.object(fs, "orphan_executors",
                               lambda st: [(527, "syz-executor exec")]), \
             mock.patch.object(fs, "unkillable", lambda pid: True), \
             mock.patch.object(fs, "proc_state", lambda pid: "U"), \
             self._sample("  IOAVBFamily::doSomething\n"):
            res = fs.diagnose_hang(None, self.dir)
        self.assertEqual(res[0][0], 527)
        self.assertTrue(any("IOAVB" in f for f in res[0][2]))


if __name__ == "__main__":
    unittest.main(verbosity=1)
