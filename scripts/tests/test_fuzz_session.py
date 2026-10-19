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
    path = Path(__file__).resolve().parent.parent / "fuzz-session.py"
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

    def test_ntp_drift_of_the_boot_epoch_is_the_same_boot(self):
        """kern.boottime is wall clock minus uptime, so an NTP correction moves
        it. A one-second drift made a live manager read as dead: the next resume
        killed its executor as an orphan and started a second manager that died
        on the http port, every ten minutes, for over an hour."""
        with mock.patch.object(fs, "boot_epoch", lambda: 1791805751):
            self.assertTrue(fs.pid_alive(os.getpid(), rec_boot=1791805750))
            self.assertTrue(fs.pid_alive(os.getpid(),
                                         rec_boot=1791805751 - fs.BOOT_EPOCH_SLACK))
            self.assertFalse(fs.pid_alive(os.getpid(),
                                          rec_boot=1791805750 - fs.BOOT_EPOCH_SLACK))


class LatestRunLogTest(unittest.TestCase):
    def test_latest_started_run_wins_over_latest_written(self):
        """A manager that outlived its record keeps appending to its own log;
        by mtime its run stayed 'latest' and every incident re-measured from it,
        adding the same hours to the fuzzing budget again and again."""
        with tempfile.TemporaryDirectory() as wd:
            res = Path(wd) / "results"
            res.mkdir()
            old = res / "run-20261012-140038.log"
            new = res / "run-20261012-144336.log"
            new.write_text("died at startup\n")
            old.write_text("still running\n")
            os.utime(new, (1000, 1000))
            os.utime(old, (2000, 2000))           # the old one was written last
            self.assertEqual(fs.latest_run_log(wd), new)


class PortInUseTest(unittest.TestCase):
    def test_listener_is_reported_and_free_port_is_not(self):
        import socket
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            self.assertTrue(fs.port_in_use("127.0.0.1:%d" % port))
        finally:
            srv.close()
        self.assertIsNone(fs.port_in_use("127.0.0.1:%d" % port))

    def test_no_http_is_not_checked(self):
        self.assertIsNone(fs.port_in_use(""))
        self.assertIsNone(fs.port_in_use("bogus"))


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


class RunTimelineTest(unittest.TestCase):
    """The two instants the campaign clocks are cut at: the first executed
    program (end of preparation) and the run's last sign of life."""

    LOG = ("2026/10/12 14:00:40 serving rpc on tcp://49246\n"
           "2026/10/12 14:00:40 no VMs started (type=none)\n"
           "2026/10/12 14:00:41 candidates=0 corpus=0 coverage=0 exec total=0 (0/sec)\n"
           "2026/10/12 14:00:50 candidates=0 corpus=0 coverage=0 exec total=456 (41/sec)\n"
           "2026/10/12 14:01:00 candidates=0 corpus=0 coverage=0 exec total=1064 (50/sec)\n"
           "SYZ-EXECUTOR: PREEMPTED (errno 4)\n")

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.log = self.dir / "run-20261012-140038.log"
        self.log.write_text(self.LOG)

    def tearDown(self):
        self._tmp.cleanup()

    def _epoch(self, hms):
        from datetime import datetime
        return datetime.strptime("20261012" + hms, "%Y%m%d%H%M%S").timestamp()

    def test_fuzzing_starts_at_the_first_nonzero_exec_total(self):
        self.assertEqual(fs.run_fuzz_start_epoch(self.log), self._epoch("140050"))

    def test_a_run_that_never_executed_has_no_fuzz_start(self):
        self.log.write_text(self.LOG.split("2026/10/12 14:00:50")[0])
        self.assertIsNone(fs.run_fuzz_start_epoch(self.log))

    def test_last_activity_is_the_newest_timestamped_line(self):
        """The trailing executor line has no timestamp and is skipped."""
        self.assertEqual(fs.run_last_activity_epoch(self.log), self._epoch("140100"))

    def test_a_newer_cover_log_extends_the_run(self):
        cover = self.dir / "cover.log"
        cover.write_text("0x1\n")
        later = self._epoch("140105")
        os.utime(cover, (later, later))
        self.assertEqual(fs.run_last_activity_epoch(self.log, cover), later)

    def test_missing_log_is_none(self):
        self.assertIsNone(fs.run_fuzz_start_epoch(self.dir / "nope.log"))
        self.assertIsNone(fs.run_last_activity_epoch(self.dir / "nope.log"))


if __name__ == "__main__":
    unittest.main(verbosity=1)


class StatusHeadlineTest(unittest.TestCase):
    """The first two lines say whether the manager is alive and whether it is
    doing anything; the rest is grouped under short headers."""

    def _lines(self, state, alive, rate=78):
        metrics = {k: "" for k in fs.BENCH_KEYS}
        metrics["uptime"] = 3723
        with mock.patch.object(fs, "refresh_status", lambda sid: state), \
             mock.patch.object(fs, "latest_bench", lambda wd: None), \
             mock.patch.object(fs, "bench_metrics", lambda b: metrics), \
             mock.patch.object(fs, "run_log_stats",
                               lambda wd: {"exec total": 100, "rate": rate,
                                           "coverage": "", "corpus": ""}), \
             mock.patch.object(fs, "session_exec_lifetime", lambda wd: 1000), \
             mock.patch.object(fs, "crash_events", lambda st: {}), \
             mock.patch.object(fs, "live_executors", lambda st: [{"pid": 1}]), \
             mock.patch.object(fs, "state_pid_alive", lambda st: alive), \
             mock.patch.object(fs, "cover_log_path", lambda st: Path("/nonexistent/cover")), \
             mock.patch.object(fs, "cover_log_archives", lambda wd: []), \
             mock.patch.object(fs, "load_config", lambda p: {}), \
             mock.patch.object(fs, "style", type(fs.style)(False)):
            return fs.status_lines("sid")

    def _state(self, status):
        return {"status": status, "pid": 4120, "workdir": "/w", "config": "/c.cfg",
                "run_count": 3, "started_at": "s", "stopped_at": "2026-10-19T10:00:00",
                "stdout": "/log", "http": "127.0.0.1:1"}

    def test_running_headline_has_pid_executors_uptime_and_rate(self):
        lines = self._lines(self._state("running"), alive=True)
        self.assertEqual(lines[0], "session   : sid")
        self.assertEqual(lines[1],
                         "status    : RUNNING (pid 4120, 1 executor, up 1h 02m 03s, 78 exec/s)")

    def test_stopped_headline_says_since_when(self):
        lines = self._lines(self._state("stopped"), alive=False)
        self.assertEqual(lines[1], "status    : STOPPED (since 2026-10-19T10:00:00)")

    def test_rows_are_grouped_under_headers(self):
        lines = self._lines(self._state("running"), alive=True)
        for header in ("-- process --", "-- incidents --"):
            self.assertIn(header, lines)
            self.assertEqual(lines[lines.index(header) - 1], "")   # blank line before each
        self.assertTrue(any(ln.startswith("-- metrics") for ln in lines))


class InspectBasicBlocksTest(unittest.TestCase):
    def test_inspect_counts_blocks_from_this_run_and_all_archived_runs(self):
        import io as _io, json as _json, contextlib as _ctx
        with tempfile.TemporaryDirectory() as tmp:
            wd = Path(tmp) / "wd"
            (wd / "results").mkdir(parents=True)
            (wd / "cover.log").write_text("0x1\n0x2\n0x3\n")
            (wd / "results/cover-1.log").write_text("0x2\n0x3\n0x4\n0x5\n")
            state = {"id": "s", "status": "stopped", "workdir": str(wd), "config": None}
            buf = _io.StringIO()
            with mock.patch.object(fs, "resolve_id", lambda t: "s"), \
                 mock.patch.object(fs, "refresh_status", lambda sid: state), \
                 mock.patch.object(fs, "run_start_epoch", lambda wd: None), \
                 mock.patch.object(fs, "run_log_stats", lambda wd: {"exec total": "", "coverage": "", "rate": "", "corpus": ""}), \
                 mock.patch.object(fs, "state_pid_alive", lambda st: False), \
                 mock.patch.object(fs, "crash_events", lambda st: {}), \
                 mock.patch.object(fs, "uncollected_run", lambda st: None), \
                 _ctx.redirect_stdout(buf):
                fs.cmd_inspect("s")
        out = _json.loads(buf.getvalue())
        self.assertEqual((out["bb_run"], out["bb_all"]), (3, 5))
        self.assertEqual(out["executors"], 0)
        self.assertEqual(out["cover_log"], str(wd / "cover.log"))
