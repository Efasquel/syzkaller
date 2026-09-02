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


if __name__ == "__main__":
    unittest.main(verbosity=1)
