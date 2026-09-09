#!/usr/bin/env python3
"""Tests for the exclude/include (bench + rotate) step in fuzz-campaign.py.

fuzz-campaign.py has a hyphen, so it is loaded by path rather than imported.
These cover exclude_syscalls (bench: add names to disable_syscalls) and
include_syscalls (rotate a benched syscall back in). The culprit -> name list
translation (syz-ring-repro -emit-json) is exercised by the Go tests.
"""

import importlib.util
import json
import os
import signal
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


def _load_campaign():
    path = Path(__file__).resolve().parent / "fuzz-campaign.py"
    spec = importlib.util.spec_from_file_location("fuzz_campaign", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


fc = _load_campaign()


def write_cfg(d: Path, cfg: dict) -> Path:
    p = d / "target.cfg"
    p.write_text(json.dumps(cfg, indent=4))
    return p


class ExcludeSyscallsTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_added(self):
        cfg = write_cfg(self.dir, {
            "target": "darwin/arm64",
            "enable_syscalls": ["syz_IOConnectCallMethod$AppleJPEGDriverUserClient_*"],
        })
        added, already = fc.exclude_syscalls(
            ["syz_IOConnectCallMethod$AppleJPEGDriverUserClient_5"], cfg)
        self.assertEqual(added, ["syz_IOConnectCallMethod$AppleJPEGDriverUserClient_5"])
        self.assertEqual(already, [])
        out = json.loads(cfg.read_text())
        self.assertIn("syz_IOConnectCallMethod$AppleJPEGDriverUserClient_5",
                      out["disable_syscalls"])
        # enable_syscalls (incl. its glob) is left untouched.
        self.assertEqual(out["enable_syscalls"],
                         ["syz_IOConnectCallMethod$AppleJPEGDriverUserClient_*"])

    def test_idempotent(self):
        cfg = write_cfg(self.dir, {"target": "darwin/arm64"})
        first, _ = fc.exclude_syscalls(["syz_IOConnectCallMethod$Foo_2"], cfg)
        self.assertEqual(first, ["syz_IOConnectCallMethod$Foo_2"])
        added, already = fc.exclude_syscalls(["syz_IOConnectCallMethod$Foo_2"], cfg)
        self.assertEqual(added, [])
        self.assertEqual(already, ["syz_IOConnectCallMethod$Foo_2"])
        out = json.loads(cfg.read_text())
        self.assertEqual(out["disable_syscalls"].count("syz_IOConnectCallMethod$Foo_2"), 1)

    def test_multiple_names(self):
        cfg = write_cfg(self.dir, {"target": "darwin/arm64"})
        added, _ = fc.exclude_syscalls(["a", "b", "c"], cfg)
        self.assertEqual(added, ["a", "b", "c"])
        self.assertEqual(json.loads(cfg.read_text())["disable_syscalls"], ["a", "b", "c"])

    def test_dry_run_writes_nothing(self):
        cfg = write_cfg(self.dir, {"target": "darwin/arm64"})
        added, _ = fc.exclude_syscalls(["syz_IOConnectCallMethod$Foo_5"], cfg, dry_run=True)
        self.assertEqual(added, ["syz_IOConnectCallMethod$Foo_5"])
        out = json.loads(cfg.read_text())
        self.assertNotIn("disable_syscalls", out)


class IncludeSyscallsTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_removes_named(self):
        cfg = write_cfg(self.dir, {
            "target": "darwin/arm64",
            "disable_syscalls": ["a", "b", "c"],
        })
        removed, absent = fc.include_syscalls(["b"], cfg)
        self.assertEqual(removed, ["b"])
        self.assertEqual(absent, [])
        out = json.loads(cfg.read_text())
        self.assertEqual(out["disable_syscalls"], ["a", "c"])

    def test_absent_reported_not_removed(self):
        cfg = write_cfg(self.dir, {"target": "darwin/arm64", "disable_syscalls": ["a"]})
        removed, absent = fc.include_syscalls(["z"], cfg)
        self.assertEqual(removed, [])
        self.assertEqual(absent, ["z"])
        out = json.loads(cfg.read_text())
        self.assertEqual(out["disable_syscalls"], ["a"])

    def test_all_clears_benched_set(self):
        cfg = write_cfg(self.dir, {
            "target": "darwin/arm64",
            "disable_syscalls": ["a", "b"],
        })
        removed, absent = fc.include_syscalls([], cfg, all_=True)
        self.assertEqual(sorted(removed), ["a", "b"])
        out = json.loads(cfg.read_text())
        self.assertEqual(out["disable_syscalls"], [])

    def test_dry_run_writes_nothing(self):
        cfg = write_cfg(self.dir, {"target": "darwin/arm64", "disable_syscalls": ["a", "b"]})
        removed, _ = fc.include_syscalls(["a"], cfg, dry_run=True)
        self.assertEqual(removed, ["a"])
        out = json.loads(cfg.read_text())
        self.assertEqual(out["disable_syscalls"], ["a", "b"])

    def test_exclude_then_include_round_trips(self):
        cfg = write_cfg(self.dir, {
            "target": "darwin/arm64",
            "enable_syscalls": ["syz_IOConnectCallMethod$Foo_*"],
        })
        fc.exclude_syscalls(["syz_IOConnectCallMethod$Foo_5"], cfg)
        self.assertIn("syz_IOConnectCallMethod$Foo_5",
                      json.loads(cfg.read_text())["disable_syscalls"])
        removed, _ = fc.include_syscalls(["syz_IOConnectCallMethod$Foo_5"], cfg)
        self.assertEqual(removed, ["syz_IOConnectCallMethod$Foo_5"])
        out = json.loads(cfg.read_text())
        self.assertEqual(out["disable_syscalls"], [])
        # enable_syscalls untouched throughout.
        self.assertEqual(out["enable_syscalls"], ["syz_IOConnectCallMethod$Foo_*"])


class CoordinatorTest(unittest.TestCase):
    """The crash -> triage -> bench -> resume phase logic, with the on-device
    pieces (triage.py, syz-ring-repro) stubbed."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _done_triage(self, s, cfg, culprit, selectors):
        """Drive advance_triage through a DONE job, with the on-device pieces
        stubbed and the quarantine ledger redirected into the test's tmp dir."""
        d = dict(fc.DEFAULTS)
        with mock.patch.object(fc, "STATE_DIR", self.dir / "state"), \
             mock.patch.object(fc, "triage", lambda *a, **k: (0, "")), \
             mock.patch.object(fc, "triage_state",
                               lambda job: {"stage": "DONE", "final_culprit": str(culprit)}), \
             mock.patch.object(fc, "culprit_sequence", lambda c: list(selectors)), \
             mock.patch.object(fc, "save_state", lambda st: None):
            fc.advance_triage(s, d)

    def _triaging_state(self, cfg):
        s = fc.init_state("camp")
        s.update({"phase": "triaging", "triage_job": "camp_t1",
                  "triage_bug_sig": "SIG1", "current_config": str(cfg)})
        return s

    def test_advance_triage_done_confirms_and_benches(self):
        """The coordinator only triages a signature the quarantine has already
        seen once, so the DONE call is the CONFIRMING occurrence: it classifies
        HARD and writes the disabled set into the config."""
        cfg = write_cfg(self.dir, {"target": "darwin/arm64", "enable_syscalls": ["a"]})
        culprit = self.dir / "culprit.syz"
        culprit.write_text("syz_IOConnectCallMethod$Foo_5(0x0)\n")
        s = self._triaging_state(cfg)
        # first occurrence: what quarantine_decide recorded when the crash landed
        with mock.patch.object(fc, "STATE_DIR", self.dir / "state"):
            qs = fc.load_qstate(str(cfg))
            fc.qm.on_crash(qs, "SIG1", None)
            fc.save_qstate(str(cfg), qs)
        self._done_triage(s, cfg, culprit, ["syz_IOConnectCallMethod$Foo_5"])
        self.assertEqual(s["phase"], "fuzzing")
        self.assertIn("SIG1", s["suppressed_sigs"])
        self.assertIsNone(s["triage_job"])
        self.assertEqual(json.loads(cfg.read_text())["disable_syscalls"],
                         ["syz_IOConnectCallMethod$Foo_5"])

    def test_advance_triage_done_on_first_occurrence_benches_nothing(self):
        """The SUSPECT gate: a signature seen for the first time is recorded but
        never benched, so a one-off crash cannot cost a selector its coverage."""
        cfg = write_cfg(self.dir, {"target": "darwin/arm64", "enable_syscalls": ["a"]})
        culprit = self.dir / "culprit.syz"
        culprit.write_text("syz_IOConnectCallMethod$Foo_5(0x0)\n")
        s = self._triaging_state(cfg)
        self._done_triage(s, cfg, culprit, ["syz_IOConnectCallMethod$Foo_5"])
        self.assertEqual(s["phase"], "fuzzing")
        self.assertNotIn("disable_syscalls", json.loads(cfg.read_text()))

    def test_budget_counts_real_elapsed_not_completed_polls(self):
        """A run that panics partway through a poll interval must still count.
        The old accounting credited whole polls only, so on a target that crashes
        every ~40s the budget sat at 0.00h no matter how long the campaign ran."""
        cfg = write_cfg(self.dir, {"target": "darwin/arm64", "enable_syscalls": ["a"]})
        s = fc.init_state("camp")
        s.update({"current_config": str(cfg), "run_active_base": 0.0})
        d = dict(fc.DEFAULTS)
        fc.record_incident(s, d, "crash",
                           {"run_started_epoch": time.time() - 42, "panic_evidence": True})
        self.assertGreaterEqual(s["active_seconds"], 41)
        first = s["active_seconds"]
        fc.record_incident(s, d, "crash",
                           {"run_started_epoch": time.time() - 10, "panic_evidence": True})
        self.assertGreaterEqual(s["active_seconds"], first + 9)   # accumulates

    def test_triage_panics_reach_the_bug_inventory(self):
        """A crash that minimization produced must be catalogued, not left in the
        triage job's ledger where no report ever sees it."""
        panic = self.dir / "panic-full-x.panic"
        panic.write_text("x")
        routed = []
        with mock.patch.object(fc, "PANIC_DIRS", [self.dir]), \
             mock.patch.object(fc, "route_bug_registry",
                               lambda p, *a, **kw: routed.append((p, kw.get("origin")))):
            fc.route_triage_panics({"incidents": [
                {"report": "panic-full-x.panic"},
                {"report": "panic-full-missing.panic"},   # not on disk -> skipped
                {},                                       # no report key -> skipped
            ]})
        # Filed as triage-origin: the minimizer caused this panic on purpose, so
        # it is evidence for the bug but must not count as another sighting.
        self.assertEqual(routed, [(str(panic), "triage")])

    def test_halt_is_honoured_in_the_triaging_phase(self):
        """halt writes the state FILE; the loop must re-read it. Otherwise a
        campaign stuck triaging ignores the pause and advance_triage's save_state
        overwrites the halt from stale memory."""
        import json as _json
        camp_dir = self.dir / "campaigns"
        state_dir = camp_dir / ".state"
        state_dir.mkdir(parents=True)
        cfg = write_cfg(self.dir, {"target": "darwin/arm64", "enable_syscalls": ["a"]})
        (camp_dir / "camp.json").write_text(_json.dumps(
            {"name": "camp", "configs": [str(cfg)], "budget_hours": 1}))
        with mock.patch.object(fc, "STATE_DIR", state_dir), \
             mock.patch.object(fc, "CAMPAIGN_DIR", camp_dir):
            s = fc.init_state("camp")
            s.update({"status": "running", "phase": "triaging", "triage_job": "camp_t1"})
            fc.save_state(s)
            fc.cmd_halt("camp")          # what the operator runs
            # cmd_run must exit without advancing: make advancing fatal.
            with mock.patch.object(fc, "advance_triage",
                                   lambda *a: self.fail("advanced while halted")), \
                 mock.patch.object(fc, "reconcile_boot", lambda *a: None):
                fc.cmd_run("camp")
        self.assertEqual(_json.loads((state_dir / "camp.json").read_text())["status"],
                         "halted")

    def test_quarantine_decide_labels_a_confirmation_not_an_escape(self):
        """qm.SUSPECT is a category, qm.SUSPECTED a disposition -- mixing them up
        made every ordinary confirmation log as an ESCAPE."""
        cfg = write_cfg(self.dir, {"target": "darwin/arm64", "enable_syscalls": ["a"]})
        s = {"current_config": str(cfg)}
        lines = []
        with mock.patch.object(fc, "STATE_DIR", self.dir / "state"), \
             mock.patch.object(fc, "log", lines.append):
            qs = fc.load_qstate(str(cfg))
            fc.qm.on_crash(qs, "SIG1", None)          # first sighting -> suspect
            fc.save_qstate(str(cfg), qs)
            self.assertEqual(fc.quarantine_decide(s, "SIG1"), "triage")
        self.assertTrue(any("CONFIRMED" in x for x in lines), lines)
        self.assertFalse(any("ESCAPED" in x for x in lines), lines)

    def test_reconcile_boot_crash_runs_the_coordinator(self):
        """A panic reboots the box, so reconcile_boot -- not supervise -- is how
        nearly every crash is discovered. It must do the same coordinator work,
        or the quarantine never sees a single crash on this target."""
        cfg = write_cfg(self.dir, {"target": "darwin/arm64", "enable_syscalls": ["a"]})
        s = fc.init_state("camp")
        s.update({"session_id": "sess", "current_config": str(cfg)})
        info = {"found": True, "status": "crashed", "pid_alive": False,
                "uncollected": {"run_started": "x"}, "panic_evidence": True,
                "panics": ["/tmp/p.panic"], "run_started_epoch": None}
        seen = {}
        with mock.patch.object(fc, "inspect", lambda sid: info), \
             mock.patch.object(fc, "collect_and_prune", lambda *a: None), \
             mock.patch.object(fc, "save_state", lambda st: None), \
             mock.patch.object(fc, "route_bug_registry",
                               lambda p, *a: seen.setdefault("routed", []).append(p)), \
             mock.patch.object(fc, "latest_panic_signature", lambda st: "SIG9"), \
             mock.patch.object(fc, "quarantine_decide",
                               lambda st, sig: seen.setdefault("decided", sig) and "resume"):
            fc.reconcile_boot(s, dict(fc.DEFAULTS))
        self.assertEqual(seen.get("routed"), ["/tmp/p.panic"])
        self.assertEqual(seen.get("decided"), "SIG9")
        self.assertEqual(s["crashes"], 1)

    def test_reconcile_boot_hang_does_not_run_the_coordinator(self):
        """A hang leaves no panic to fingerprint; it must not reach the quarantine."""
        cfg = write_cfg(self.dir, {"target": "darwin/arm64", "enable_syscalls": ["a"]})
        s = fc.init_state("camp")
        s.update({"session_id": "sess", "current_config": str(cfg)})
        info = {"found": True, "status": "crashed", "pid_alive": False,
                "uncollected": {"run_started": "x"}, "panic_evidence": False,
                "panics": [], "run_started_epoch": None}
        called = []
        with mock.patch.object(fc, "inspect", lambda sid: info), \
             mock.patch.object(fc, "collect_and_prune", lambda *a: None), \
             mock.patch.object(fc, "save_state", lambda st: None), \
             mock.patch.object(fc, "latest_panic_signature",
                               lambda st: called.append("sig") or "SIG9"):
            fc.reconcile_boot(s, dict(fc.DEFAULTS))
        self.assertEqual(called, [])
        self.assertEqual(s["hangs"], 1)

    def test_advance_triage_not_done_waits(self):
        s = fc.init_state("camp")
        s.update({"phase": "triaging", "triage_job": "camp_t1", "triage_boots": 0})
        d = dict(fc.DEFAULTS)
        with mock.patch.object(fc, "triage", lambda *a, **k: (0, "")), \
             mock.patch.object(fc, "triage_state", lambda job: {"stage": "MINIMIZE_CONN"}), \
             mock.patch.object(fc, "save_state", lambda st: None), \
             mock.patch.object(fc.time, "sleep", lambda x: None):
            fc.advance_triage(s, d)
        self.assertEqual(s["phase"], "triaging")   # still triaging
        self.assertEqual(s["triage_boots"], 1)     # advance counted
        self.assertEqual(s["status"], "running")

    def test_advance_triage_gives_up_and_halts(self):
        s = fc.init_state("camp")
        d = dict(fc.DEFAULTS)
        s.update({"phase": "triaging", "triage_job": "camp_t1",
                  "triage_bug_sig": "SIG1", "triage_boots": d["triage_max_boots"]})
        with mock.patch.object(fc, "triage", lambda *a, **k: (0, "")), \
             mock.patch.object(fc, "save_state", lambda st: None):
            fc.advance_triage(s, d)
        self.assertEqual(s["status"], "halted")
        self.assertIn("triage stuck", s["halt_reason"])

    def test_latest_panic_signature(self):
        rep = self.dir / "boom.panic"
        rep.write_text("panic report")
        s = {"panic_sig_watermark": 0.0}
        with mock.patch.object(fc, "PANIC_DIRS", [self.dir]), \
             mock.patch.object(fc.cf, "fingerprint",
                               lambda path: {"signature": "SIGX"}):
            sig = fc.latest_panic_signature(s)
        self.assertEqual(sig, "SIGX")
        self.assertGreater(s["panic_sig_watermark"], 0.0)

    def test_begin_triage_without_workdir_fails_gracefully(self):
        s = fc.init_state("camp")
        s["session_id"] = "sess"
        d = dict(fc.DEFAULTS)
        with mock.patch.object(fc, "inspect", lambda sid: {"found": False}):
            ok = fc.begin_triage(s, d, "SIG1")
        self.assertFalse(ok)
        self.assertEqual(s["phase"], "fuzzing")    # unchanged
        self.assertIsNone(s["triage_job"])


class ClockTest(unittest.TestCase):
    """The three budget clocks and their lifetime totals.

    A finished 2h campaign reported active_seconds 0.0 because the per-config
    budget reset was also the only record of how long the campaign ran."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_wall_is_the_sum_of_the_three(self):
        s = {"active_seconds": 100.0, "triage_seconds": 20.0, "overhead_seconds": 5.0}
        self.assertEqual(fc.wall_seconds(s), 125.0)

    def test_budget_clock_fuzz_ignores_triage_and_reboots(self):
        s = {"active_seconds": 100.0, "triage_seconds": 900.0, "overhead_seconds": 900.0}
        self.assertEqual(fc.budget_spent(s, {"budget_clock": "fuzz"}), 100.0)

    def test_budget_clock_wall_charges_everything(self):
        s = {"active_seconds": 100.0, "triage_seconds": 900.0, "overhead_seconds": 900.0}
        self.assertEqual(fc.budget_spent(s, {"budget_clock": "wall"}), 1900.0)

    def test_default_budget_clock_is_wall(self):
        """"Give this config 24 hours of machine time" is what comparing
        configurations needs, so every phase is charged by default."""
        self.assertEqual(fc.DEFAULTS["budget_clock"], "wall")

    def test_wall_is_never_less_than_fuzz(self):
        """So the default can only ever end a campaign sooner, never overrun."""
        s = {"active_seconds": 100.0, "triage_seconds": 50.0,
             "overhead_seconds": 25.0}
        self.assertGreaterEqual(fc.budget_spent(s, {"budget_clock": "wall"}),
                                fc.budget_spent(s, {"budget_clock": "fuzz"}))

    def test_triage_phase_stops_when_the_wall_budget_is_spent(self):
        """The budget is otherwise only tested inside supervise, which does not
        run while triaging -- so a long minimization would overrun the envelope
        without ever noticing."""
        s = fc.init_state("camp")
        s.update({"phase": "triaging", "triage_job": "camp_t1",
                  "triage_bug_sig": "S", "active_seconds": 3600.0,
                  "triage_seconds": 3600.0})
        d = dict(fc.DEFAULTS, budget_clock="wall",
                 items=[{"config": "/x.cfg", "budget_seconds": 7200}], name="camp")
        advanced = []
        with mock.patch.object(fc, "STATE_DIR", self.dir), \
             mock.patch.object(fc, "load_def", lambda n: d), \
             mock.patch.object(fc, "advance_triage",
                               lambda *a: advanced.append(1)), \
             mock.patch.object(fc, "reconcile_boot", lambda *a: None), \
             mock.patch.object(fc, "reconcile_gap", lambda *a: None), \
             mock.patch.object(fc, "save_state", lambda st: None), \
             mock.patch.object(fc, "load_state", lambda n: s), \
             mock.patch.object(fc, "brake_held", lambda n: None), \
             mock.patch.object(fc, "breaker", lambda *a: None):
            fc.cmd_run("camp")
        self.assertEqual(advanced, [])          # never spent another triage boot
        self.assertEqual(s["status"], "done")

    def test_triage_phase_continues_while_budget_remains(self):
        s = fc.init_state("camp")
        s.update({"phase": "triaging", "triage_job": "camp_t1",
                  "triage_bug_sig": "S", "active_seconds": 60.0})
        d = dict(fc.DEFAULTS, budget_clock="wall",
                 items=[{"config": "/x.cfg", "budget_seconds": 7200}], name="camp")
        advanced = []

        def stop_after_one(st, dd):
            advanced.append(1)
            st["status"] = "halted"

        with mock.patch.object(fc, "STATE_DIR", self.dir), \
             mock.patch.object(fc, "load_def", lambda n: d), \
             mock.patch.object(fc, "advance_triage", stop_after_one), \
             mock.patch.object(fc, "reconcile_boot", lambda *a: None), \
             mock.patch.object(fc, "reconcile_gap", lambda *a: None), \
             mock.patch.object(fc, "save_state", lambda st: None), \
             mock.patch.object(fc, "load_state", lambda n: s), \
             mock.patch.object(fc, "brake_held", lambda n: None), \
             mock.patch.object(fc, "breaker", lambda *a: None):
            fc.cmd_run("camp")
        self.assertEqual(advanced, [1])

    def test_roll_banks_totals_and_zeroes_the_budget(self):
        s = fc.init_state("camp")
        s.update({"active_seconds": 60.0, "triage_seconds": 30.0, "overhead_seconds": 10.0})
        fc.roll_budget_clocks(s)
        self.assertEqual(s["active_seconds"], 0.0)
        self.assertEqual(s["total_active_seconds"], 60.0)
        self.assertEqual(fc.lifetime(s, "active_seconds"), 60.0)
        self.assertEqual(fc.lifetime_wall(s), 100.0)

    def test_lifetime_survives_repeated_advances(self):
        """The bug this exists to prevent: time vanishing on config advance."""
        s = fc.init_state("camp")
        for _ in range(3):
            s["active_seconds"] = 60.0
            fc.roll_budget_clocks(s)
        self.assertEqual(fc.lifetime(s, "active_seconds"), 180.0)

    def test_roll_rebases_run_active_base(self):
        """A stale base would re-add the previous config's time on the next run."""
        s = fc.init_state("camp")
        s.update({"active_seconds": 60.0, "run_active_base": 60.0})
        fc.roll_budget_clocks(s)
        self.assertEqual(s["run_active_base"], 0.0)

    def test_reconcile_gap_charges_reboot_overhead(self):
        s = fc.init_state("camp")
        s["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                        time.gmtime(time.time() - 120))
        fc.reconcile_gap(s, dict(fc.DEFAULTS))
        self.assertGreaterEqual(s["overhead_seconds"], 110)
        self.assertLessEqual(s["overhead_seconds"], 130)

    def test_reconcile_gap_caps_an_idle_rig(self):
        """A week of downtime is not reboot overhead; capping keeps wall honest."""
        s = fc.init_state("camp")
        s["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                        time.gmtime(time.time() - 7 * 86400))
        fc.reconcile_gap(s, dict(fc.DEFAULTS))
        self.assertEqual(s["overhead_seconds"], fc.DEFAULTS["max_boot_gap_seconds"])

    def test_reconcile_gap_tolerates_a_missing_timestamp(self):
        s = fc.init_state("camp")
        s["updated_at"] = None
        fc.reconcile_gap(s, dict(fc.DEFAULTS))
        self.assertEqual(s["overhead_seconds"], 0.0)

    def test_triage_time_lands_on_the_triage_clock(self):
        """An advance charges minimization, never the fuzzing budget."""
        s = fc.init_state("camp")
        s.update({"phase": "triaging", "triage_job": "camp_t1", "triage_bug_sig": "S"})
        d = dict(fc.DEFAULTS)
        d["poll_seconds"] = 0
        with mock.patch.object(fc, "STATE_DIR", self.dir), \
             mock.patch.object(fc, "triage", lambda *a, **k: (0, "")), \
             mock.patch.object(fc, "triage_state", lambda job: {"stage": "MINIMIZE_CONN"}), \
             mock.patch.object(fc, "route_triage_panics", lambda *a, **k: None):
            fc.advance_triage(s, d)
        self.assertGreater(s["triage_seconds"], 0.0)
        self.assertEqual(s["active_seconds"], 0.0)


class StopLatencyTest(unittest.TestCase):
    """`halt` used to take up to poll_seconds (10 min) to be noticed, because
    the state re-read was welded to the expensive progress poll. Long enough to
    feel broken, and to invite killing the driver instead."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.state = self.dir / "state"
        self.state.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def _d(self):
        return dict(fc.DEFAULTS, stop_check_seconds=0.01, name="camp")

    def test_returns_none_when_nothing_asks_it_to_stop(self):
        s = fc.init_state("camp")
        with mock.patch.object(fc, "STATE_DIR", self.state), \
             mock.patch.object(fc, "GLOBAL_BRAKE", self.dir / "STOP"):
            fc.save_state(s)
            t0 = time.time()
            self.assertIsNone(fc.wait_for_stop(s, self._d(), 0.05))
            self.assertGreaterEqual(time.time() - t0, 0.04)

    def test_notices_a_halt_far_sooner_than_the_poll_interval(self):
        s = fc.init_state("camp")
        with mock.patch.object(fc, "STATE_DIR", self.state), \
             mock.patch.object(fc, "GLOBAL_BRAKE", self.dir / "STOP"):
            fc.save_state(s)
            halted = dict(s, status="halted")
            fc.save_state(halted)
            t0 = time.time()
            # Ask for a 600s wait, as production does; it must not take that.
            self.assertEqual(fc.wait_for_stop(s, self._d(), 600), "halted")
            self.assertLess(time.time() - t0, 1.0)

    def test_a_brake_set_mid_run_stops_it_too(self):
        """The brake is the stop you reach for when the box misbehaves; waiting
        out a poll interval for it defeats the purpose."""
        s = fc.init_state("camp")
        with mock.patch.object(fc, "STATE_DIR", self.state), \
             mock.patch.object(fc, "GLOBAL_BRAKE", self.dir / "STOP"):
            fc.save_state(s)
            (self.dir / "STOP").write_text("box is wedged")
            self.assertEqual(fc.wait_for_stop(s, self._d(), 600), "brake")
            self.assertEqual(s["status"], "halted")
            self.assertIn("box is wedged", s["halt_reason"])

    def test_stop_check_is_decoupled_from_the_progress_poll(self):
        """The two have very different costs: one stat() versus an HTTP round
        trip to the manager."""
        self.assertLess(fc.DEFAULTS["stop_check_seconds"],
                        fc.DEFAULTS["poll_seconds"])


class StopTest(unittest.TestCase):
    """The stop that does not assume a supervisor is alive.

    halt and brake are both flags a supervisor has to READ. When it is gone --
    killed by a launchctl bootout, say -- syz-manager keeps fuzzing detached,
    the campaign still reports "running" because nothing updates it, and the
    orphan holds /dev/pishi against the next campaign."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _state(self):
        s = fc.init_state("camp")
        s.update({"session_id": "sid1", "current_config": "/cfg/mine.cfg"})
        return s

    def test_matches_this_campaigns_manager_only(self):
        """A stop must never reach into an unrelated session."""
        table = [(1, "/bin/syz-manager -config /cfg/mine.cfg"),
                 (2, "/bin/syz-manager -config /cfg/other.cfg")]
        with mock.patch.object(fc, "running_processes",
                               lambda pat: table if "manager" in pat else []):
            managers, _ = fc.campaign_processes(self._state())
        self.assertEqual([p for p, _ in managers], [1])

    def test_matches_executors_by_binary_path_not_session_id(self):
        """A session id never appears in an executor's argv -- it is only the
        cwd. Matching on it found NOTHING, so stop reported "all processes gone"
        while two executors were still running, one of them unkillable and
        holding the coverage device."""
        exe = str(fc.REPO_ROOT / "bin" / "darwin_arm64" / "syz-executor")
        table = [(3, "%s runner 0 127.0.0.1 49182" % exe),
                 (4, "%s exec" % exe),
                 (5, "/somewhere/else/syz-executor exec")]
        with mock.patch.object(fc, "running_processes",
                               lambda pat: table if "executor" in pat else []):
            _, execs = fc.campaign_processes(self._state())
        self.assertEqual([p for p, _ in execs], [3, 4])   # 5 is not ours

    def test_no_config_matches_nothing(self):
        """Rather than matching every manager on the box."""
        s = fc.init_state("camp")
        with mock.patch.object(fc, "running_processes",
                               lambda pat: [(1, "syz-manager -config /a.cfg")]):
            managers, execs = fc.campaign_processes(s)
        self.assertEqual(managers, [])
        self.assertEqual(execs, [])

    def _run_stop(self, procs_over_time, **kw):
        """procs_over_time: list of (managers, executors) returned in sequence."""
        s = self._state()
        calls = {"session_stop": 0, "signals": []}
        seq = list(procs_over_time)

        def fake_procs(_s):
            return seq.pop(0) if len(seq) > 1 else seq[0]

        def fake_run(cmd, *a, **k):
            if isinstance(cmd, list) and "stop" in cmd:
                calls["session_stop"] += 1
                if kw.get("hang"):
                    raise fc.subprocess.TimeoutExpired(cmd, 1)
            return None

        with mock.patch.object(fc, "STATE_DIR", self.dir), \
             mock.patch.object(fc, "load_state", lambda n: s), \
             mock.patch.object(fc, "save_state", lambda st: None), \
             mock.patch.object(fc, "campaign_processes", fake_procs), \
             mock.patch.object(fc, "proc_stat", lambda pid: kw.get("stat", "S")), \
             mock.patch.object(fc, "_signal",
                               lambda pid, sig, what: calls["signals"].append((pid, sig))), \
             mock.patch.object(fc.subprocess, "run", fake_run):
            rc = fc.cmd_stop("camp", grace=kw.get("grace", 0),
                             keep_agent=kw.get("keep_agent", True))
        return rc, calls, s

    def test_clean_stop_reports_success(self):
        rc, calls, s = self._run_stop([([], [])])
        self.assertEqual(rc, 0)
        self.assertEqual(calls["session_stop"], 1)
        self.assertEqual(calls["signals"], [])
        self.assertEqual(s["status"], "halted")

    def test_survivor_is_signalled_not_reported_as_stopped(self):
        """A graceful stop that silently did nothing is the failure this whole
        command exists to prevent."""
        alive = ([(46434, "syz-manager -config /cfg/mine.cfg")], [])
        rc, calls, _ = self._run_stop([alive])
        self.assertEqual(rc, 1)                       # loud, not a false success
        self.assertTrue(calls["signals"])
        self.assertIn(46434, [pid for pid, _ in calls["signals"]])

    def test_escalates_to_sigkill(self):
        alive = ([(46434, "syz-manager -config /cfg/mine.cfg")], [])
        _, calls, _ = self._run_stop([alive])
        sigs = [sig for _, sig in calls["signals"]]
        self.assertIn(signal.SIGINT, sigs)
        self.assertIn(signal.SIGKILL, sigs)


    def test_a_hung_graceful_stop_does_not_block_the_teardown(self):
        """One did: a scratch retire that could not rename fell back to walking
        65,000 directories it had no permission to delete."""
        alive = ([(46434, "syz-manager -config /cfg/mine.cfg")], [])
        rc, calls, _ = self._run_stop([alive], hang=True)
        self.assertEqual(calls["session_stop"], 1)
        self.assertTrue(calls["signals"])       # escalated instead of hanging


    def test_a_wedged_survivor_is_not_signalled_and_not_called_success(self):
        """SIGKILL cannot reach a STAT U process. Reporting success while it
        still holds the coverage device is the exact failure this command
        exists to prevent -- and it happened."""
        alive = ([(3958, "syz-executor exec")], [])
        rc, calls, _ = self._run_stop([alive], stat="U")
        self.assertEqual(rc, 1)                 # loud, not a false success
        self.assertEqual(calls["signals"], [])  # no futile signals

    def test_marks_halted_so_a_relaunch_exits(self):
        _, _, s = self._run_stop([([], [])])
        self.assertEqual(s["status"], "halted")
        self.assertTrue(s["halt_reason"])


class HangDetectionTest(unittest.TestCase):
    """The detector used to require exec_total to be READABLE, on both branches.
    A manager that stopped reporting -- which is what a bad hang looks like --
    could therefore never be declared hung: the worse the wedge, the more
    invisible it was. A box sat 38 minutes on one stuck program."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _supervise(self, infos, hang_after=1, stuck=None):
        """Run supervise against a scripted sequence of inspect() results."""
        s = fc.init_state("camp")
        s.update({"session_id": "sid", "current_config": "/x.cfg"})
        d = dict(fc.DEFAULTS, hang_after_seconds=hang_after, poll_seconds=0,
                 stop_check_seconds=0.01, name="camp")
        seq = list(infos)

        def fake_inspect(sid):
            return seq.pop(0) if len(seq) > 1 else seq[0]

        with mock.patch.object(fc, "STATE_DIR", self.dir), \
             mock.patch.object(fc, "load_state", lambda n: s), \
             mock.patch.object(fc, "save_state", lambda st: None), \
             mock.patch.object(fc, "brake_held", lambda n: None), \
             mock.patch.object(fc, "inspect", fake_inspect), \
             mock.patch.object(fc, "breaker", lambda *a: None), \
             mock.patch.object(fc, "quarantine_rotate_due", lambda st: False), \
             mock.patch.object(fc, "stuck_executor_seconds", lambda dd: stuck), \
             mock.patch.object(fc, "session", lambda *a, **k: (0, "")):
            return fc.supervise(s, d, "sid", budget=10 ** 9)

    def test_unreadable_exec_total_is_a_hang(self):
        """The bug: this returned nothing and supervised forever."""
        alive = {"found": True, "pid_alive": True, "exec_total": None,
                 "run_started_epoch": time.time()}
        self.assertEqual(self._supervise([alive], hang_after=0), "hang")

    def test_frozen_exec_total_is_still_a_hang(self):
        alive = {"found": True, "pid_alive": True, "exec_total": 500,
                 "run_started_epoch": time.time()}
        self.assertEqual(self._supervise([alive, alive], hang_after=0), "hang")

    def test_progress_is_not_a_hang(self):
        """Advancing exec_total must reset the clock, or a healthy run would be
        killed the moment it exceeded hang_after."""
        base = {"found": True, "pid_alive": True, "run_started_epoch": time.time()}
        moving = [dict(base, exec_total=n) for n in (100, 200, 300)]
        # Budget expiry is the only other way out, so a non-hang shows as budget.
        s = fc.init_state("camp")
        s.update({"session_id": "sid", "current_config": "/x.cfg"})
        d = dict(fc.DEFAULTS, hang_after_seconds=9999, poll_seconds=0,
                 stop_check_seconds=0.01, name="camp")
        seq = list(moving)
        with mock.patch.object(fc, "STATE_DIR", self.dir), \
             mock.patch.object(fc, "load_state", lambda n: s), \
             mock.patch.object(fc, "save_state", lambda st: None), \
             mock.patch.object(fc, "brake_held", lambda n: None), \
             mock.patch.object(fc, "inspect",
                               lambda sid: seq.pop(0) if len(seq) > 1 else seq[0]), \
             mock.patch.object(fc, "breaker", lambda *a: None), \
             mock.patch.object(fc, "quarantine_rotate_due", lambda st: False), \
             mock.patch.object(fc, "stuck_executor_seconds", lambda dd: None), \
             mock.patch.object(fc, "session", lambda *a, **k: (0, "")):
            self.assertEqual(fc.supervise(s, d, "sid", budget=0), "budget")

    def test_a_wedged_executor_is_a_hang_regardless_of_counters(self):
        """One `syz-executor exec` per program, so one alive for minutes is a
        syscall that never returned -- direct evidence, not an inference."""
        alive = {"found": True, "pid_alive": True, "exec_total": 1,
                 "run_started_epoch": time.time()}
        self.assertEqual(self._supervise([alive], hang_after=9999, stuck=2398),
                         "hang")


class EtimeTest(unittest.TestCase):
    def test_parses_ps_elapsed_forms(self):
        self.assertEqual(fc._etime_seconds("04:59"), 299)
        self.assertEqual(fc._etime_seconds("38:35"), 2315)
        self.assertEqual(fc._etime_seconds("12:34:56"), 45296)
        self.assertEqual(fc._etime_seconds("1-02:03:04"), 93784)

    def test_garbage_is_none(self):
        for bad in ("", None, "abc", "1:2:x"):
            self.assertIsNone(fc._etime_seconds(bad), bad)

    def test_below_the_limit_is_not_stuck(self):
        ps = "ELAPSED COMMAND\n    00:02 /bin/syz-executor exec\n"
        with mock.patch.object(fc.subprocess, "run",
                               lambda *a, **k: type("R", (), {"stdout": ps})()):
            self.assertIsNone(fc.stuck_executor_seconds(dict(fc.DEFAULTS)))

    def test_above_the_limit_is_stuck(self):
        ps = "ELAPSED COMMAND\n    38:35 /bin/syz-executor exec\n"
        with mock.patch.object(fc.subprocess, "run",
                               lambda *a, **k: type("R", (), {"stdout": ps})()):
            self.assertEqual(fc.stuck_executor_seconds(dict(fc.DEFAULTS)), 2315)

    def test_the_runner_process_is_not_an_exec(self):
        """`syz-executor runner` is long-lived by design; only `exec` is per-program."""
        ps = "ELAPSED COMMAND\n 20:03:09 /bin/syz-executor runner 0 127.0.0.1 49178\n"
        with mock.patch.object(fc.subprocess, "run",
                               lambda *a, **k: type("R", (), {"stdout": ps})()):
            self.assertIsNone(fc.stuck_executor_seconds(dict(fc.DEFAULTS)))


class BrakeTest(unittest.TestCase):
    """The file brake: the only stop that works on a box which panics its way
    through every relaunch, because it is checked before anything else runs."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.state = self.dir / "state"
        self.state.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def _patch(self):
        return (mock.patch.object(fc, "GLOBAL_BRAKE", self.dir / "STOP"),
                mock.patch.object(fc, "STATE_DIR", self.state))

    def test_no_brake_by_default(self):
        a, b = self._patch()
        with a, b:
            self.assertIsNone(fc.brake_held("camp"))

    def test_global_brake_stops_every_campaign(self):
        a, b = self._patch()
        with a, b:
            (self.dir / "STOP").write_text("boot loop\n")
            held = fc.brake_held("anything")
            self.assertIsNotNone(held)
            self.assertEqual(held[1], "boot loop")

    def test_per_campaign_brake_is_scoped(self):
        a, b = self._patch()
        with a, b:
            (self.state / "camp.brake").write_text("")
            self.assertIsNotNone(fc.brake_held("camp"))
            self.assertIsNone(fc.brake_held("other"))

    def test_reason_is_optional(self):
        a, b = self._patch()
        with a, b:
            (self.state / "camp.brake").touch()
            self.assertEqual(fc.brake_held("camp")[1], "")

    def test_run_halts_without_touching_the_box(self):
        """The brake must stop the driver BEFORE it reconciles or starts a
        session -- that is the whole point on a box in a panic loop."""
        a, b = self._patch()
        started = []
        with a, b, \
             mock.patch.object(fc, "load_def", lambda n: dict(fc.DEFAULTS, items=[], name=n)), \
             mock.patch.object(fc, "reconcile_boot", lambda *x: started.append("reconcile")), \
             mock.patch.object(fc, "ensure_running", lambda *x: started.append("start")):
            (self.dir / "STOP").write_text("halt now\n")
            fc.cmd_run("camp")
        self.assertEqual(started, [])
        s = json.loads((self.state / "camp.json").read_text())
        self.assertEqual(s["status"], "halted")
        self.assertIn("halt now", s["halt_reason"])

    def test_set_and_clear_round_trip(self):
        a, b = self._patch()
        with a, b:
            fc.cmd_brake("camp", reason="testing")
            self.assertIsNotNone(fc.brake_held("camp"))
            fc.cmd_brake("camp", clear=True)
            self.assertIsNone(fc.brake_held("camp"))

    def test_resume_refuses_while_braked(self):
        """Marking a braked campaign 'running' would look like it worked, and the
        next driver start would silently re-halt it."""
        a, b = self._patch()
        with a, b:
            (self.state / "camp.brake").write_text("still broken")
            with self.assertRaises(SystemExit):
                fc.cmd_resume("camp")


class StatusWatchTest(unittest.TestCase):
    """status -w exists to show movement. An absolute counter does not: 11.2M
    programs looks identical one refresh later whether the box is fuzzing hard
    or wedged."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_no_delta_without_a_previous_sample(self):
        self.assertEqual(fc._delta(100, None), "")

    def test_no_delta_when_nothing_moved(self):
        """A wedged manager must read as 'nothing changed', not as a 0 to parse."""
        self.assertEqual(fc._delta(100, 100), "")

    def test_delta_is_signed(self):
        self.assertIn("+25", fc._delta(125, 100))
        self.assertIn("-25", fc._delta(75, 100))

    def test_delta_tolerates_non_numeric(self):
        """exec_total is '-' before the manager reports; that must not raise."""
        self.assertEqual(fc._delta("n/a", 100), "")
        self.assertEqual(fc._delta(None, 100), "")

    def test_corpus_facts_none_when_absent(self):
        cfg = write_cfg(self.dir, {"workdir": str(self.dir / "nope")})
        self.assertIsNone(fc.corpus_facts(str(cfg)))

    def test_corpus_facts_none_without_a_workdir_key(self):
        cfg = write_cfg(self.dir, {"target": "darwin/arm64"})
        self.assertIsNone(fc.corpus_facts(str(cfg)))

    def test_corpus_facts_reports_an_existing_db(self):
        wd = self.dir / "wd"
        wd.mkdir()
        (wd / "corpus.db").write_bytes(b"x" * 128)
        cfg = write_cfg(self.dir, {"workdir": str(wd)})
        facts = fc.corpus_facts(str(cfg))
        self.assertEqual(facts["bytes"], 128)
        self.assertEqual(facts["workdir"], str(wd))

    def test_status_lines_returns_a_sample_for_the_next_call(self):
        cfg = write_cfg(self.dir, {"target": "darwin/arm64", "workdir": str(self.dir)})
        with mock.patch.object(fc, "STATE_DIR", self.dir / "state"), \
             mock.patch.object(fc, "load_def",
                               lambda n: dict(fc.DEFAULTS, items=[
                                   {"config": str(cfg), "budget_seconds": 3600}],
                                   name=n)), \
             mock.patch.object(fc, "inspect", lambda sid: {"found": False}), \
             mock.patch.object(fc, "free_gb", lambda: 100.0):
            lines, sample = fc.status_lines("camp")
        self.assertTrue(any("campaign camp" in ln for ln in lines))
        self.assertIn("crashes", sample)

    def test_status_says_when_a_config_starts_from_scratch(self):
        """A config IS a workdir, so re-running one resumes its corpus. Whether
        this run inherited anything must not have to be inferred from a log line
        that scrolled past hours ago."""
        cfg = write_cfg(self.dir, {"target": "darwin/arm64",
                                   "workdir": str(self.dir / "fresh")})
        s = fc.init_state("camp")
        s["current_config"] = str(cfg)
        with mock.patch.object(fc, "STATE_DIR", self.dir / "state"), \
             mock.patch.object(fc, "load_state", lambda n: s), \
             mock.patch.object(fc, "load_def",
                               lambda n: dict(fc.DEFAULTS, items=[
                                   {"config": str(cfg), "budget_seconds": 3600}],
                                   name=n)), \
             mock.patch.object(fc, "inspect", lambda sid: {"found": False}), \
             mock.patch.object(fc, "free_gb", lambda: 100.0):
            lines, _ = fc.status_lines("camp")
        self.assertTrue(any("starts from scratch" in ln for ln in lines))




class ConfigTriageFlagsTest(unittest.TestCase):
    """The crashing config's device settings must reach triage.

    A missing executor_name is silent and catastrophic: the driver refuses every
    IOServiceOpen, every later call is inert, and minimization reports "nothing
    reproduces" from a search that never touched the driver. Campaign
    drivers_260902 spent 25,461 probes that way.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_executor_name_is_carried(self):
        cfg = write_cfg(self.dir, {
            "executor_name": "bluetoothd",
            "kext_coverage": {"kext_id": 32, "kcov_device": "/dev/pishi"},
        })
        flags = fc.config_triage_flags(str(cfg))
        self.assertEqual(flags["executor_name"], "bluetoothd")
        self.assertEqual(flags["kext_id"], 32)
        self.assertEqual(flags["kcov_device"], "/dev/pishi")

    def test_absent_and_blank_names_are_omitted(self):
        for value in (None, "", "   "):
            body = {"kext_coverage": {"kext_id": 1}}
            if value is not None:
                body["executor_name"] = value
            flags = fc.config_triage_flags(str(write_cfg(self.dir, body)))
            self.assertNotIn("executor_name", flags, value)

    def test_unreadable_config_yields_no_flags(self):
        bad = self.dir / "broken.cfg"
        bad.write_text("{ not json")
        self.assertEqual(fc.config_triage_flags(str(bad)), {})


class ExhaustedSignatureTest(unittest.TestCase):
    """A search that reproduced NOTHING must not be repeated.

    Signature b2db82ffad422697 was triaged three times in a row -- 6,657 / 6,093 /
    8,557 probes -- because nothing recorded that the previous attempt had already
    exhausted the whole search space without a single reproduction.
    """

    def _state(self, **over):
        s = {"name": "c", "exhausted_sigs": [], "suppressed_sigs": [],
             "current_config": None, "triage_bug_sig": None}
        s.update(over)
        return s

    def test_exhausted_signature_is_not_retriaged(self):
        s = self._state(exhausted_sigs=["deadbeef"])
        with mock.patch.object(fc, "latest_panic_signature", return_value="deadbeef"), \
             mock.patch.object(fc, "route_bug_registry"), \
             mock.patch.object(fc, "quarantine_decide") as decide, \
             mock.patch.object(fc, "begin_triage") as begin:
            self.assertFalse(fc.handle_crash(s, {}, {"panics": []}))
        decide.assert_not_called()
        begin.assert_not_called()

    def test_fresh_signature_still_triages(self):
        s = self._state()
        with mock.patch.object(fc, "latest_panic_signature", return_value="cafe"), \
             mock.patch.object(fc, "route_bug_registry"), \
             mock.patch.object(fc, "quarantine_decide", return_value="triage"), \
             mock.patch.object(fc, "begin_triage", return_value=True) as begin:
            self.assertTrue(fc.handle_crash(s, {}, {"panics": []}))
        begin.assert_called_once()

    def test_forget_exhausted_clears_one_and_all(self):
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.object(fc, "STATE_DIR", Path(td)):
                s = self._state(exhausted_sigs=["aa", "bb"])
                with mock.patch.object(fc, "load_state", return_value=s), \
                     mock.patch.object(fc, "save_state"):
                    fc.cmd_forget_exhausted("c", "aa")
                    self.assertEqual(s["exhausted_sigs"], ["bb"])
                    fc.cmd_forget_exhausted("c")
                    self.assertEqual(s["exhausted_sigs"], [])


class NewSeedsDeviceSettingsFromConfig(unittest.TestCase):
    """`new` should take device settings from the config, not from your typing.

    Each driver has its own Pishi kext id (AppleJPEGDriver=1 ... AppleFDEKeyStore
    =256). A campaign carrying the wrong one triages a crash against the wrong
    kext, and the only thing that stopped that was remembering to pass --kext-id
    correctly every time.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        (self.dir / "campaigns").mkdir()
        self._patch = mock.patch.object(fc, "CAMPAIGN_DIR", self.dir / "campaigns")
        self._patch.start()

    def tearDown(self):
        self._patch.stop()
        self._tmp.cleanup()

    def _cfg(self, stem, kext=None, workdir="w", name=None, syscalls=()):
        body = {"workdir": "/tmp/%s" % workdir, "enable_syscalls": list(syscalls)}
        if kext is not None:
            body["kext_coverage"] = {"kext_id": kext, "kcov_device": "/dev/pishi"}
        if name:
            body["executor_name"] = name
        p = self.dir / ("%s.cfg" % stem)
        p.write_text(json.dumps(body))
        return str(p)

    def _new(self, configs, **over):
        kw = dict(budget_hours=1.0, loop=False, poll_seconds=1,
                  hang_after_seconds=1, max_crashes=1, min_free_gb=1.0,
                  keep_cores=1, force=True)
        kw.update(over)
        fc.cmd_new("c", configs, **kw)
        return json.loads((self.dir / "campaigns" / "c.json").read_text())

    def test_kext_id_and_device_come_from_the_config(self):
        d = self._new([self._cfg("fde", kext=256)])
        self.assertEqual(d["triage"]["kext_id"], 256)
        self.assertEqual(d["triage"]["kcov_device"], "/dev/pishi")

    def test_explicit_flag_still_wins(self):
        d = self._new([self._cfg("fde", kext=256)],
                      triage_opts={"kext_id": 4, "kcov_device": None})
        self.assertEqual(d["triage"]["kext_id"], 4)
        # the unset one is still seeded from the config
        self.assertEqual(d["triage"]["kcov_device"], "/dev/pishi")

    def test_config_without_kext_coverage_seeds_nothing(self):
        d = self._new([self._cfg("bare")])
        self.assertNotIn("kext_id", d.get("triage", {}))

    def test_executor_name_is_not_seeded_into_the_campaign(self):
        # It is per-config and read at triage time by config_triage_flags; copying
        # the first config's name onto a whole sweep would be wrong the moment the
        # sweep spans drivers.
        d = self._new([self._cfg("bt", kext=32, name="bluetoothd")])
        self.assertNotIn("executor_name", d.get("triage", {}))


class BoxBusyPrecision(unittest.TestCase):
    """box_busy must match the program EXECUTED, not any mention of its name.

    running_processes() substring-matches the whole command line, so a shell whose
    argv merely contains "syz-manager" reads as a live campaign -- which is exactly
    what a doctor run in a terminal looks like.
    """

    def _busy(self, table):
        with mock.patch.object(fc, "running_processes", return_value=table):
            return fc.box_busy()

    def test_a_shell_mentioning_the_name_is_not_a_campaign(self):
        self.assertEqual(self._busy([
            (1, "/bin/zsh -c grep syz-manager /var/log/x"),
            (2, "/bin/zsh -c ./scripts/fuzz-campaign.py run notes.txt"),
        ]), [])

    def test_a_real_manager_and_supervisor_are_found(self):
        got = self._busy([
            (10, "/Users/Shared/fuzz-run/bin/syz-manager -config /x.cfg"),
            (11, "/usr/bin/python3 /Users/Shared/fuzz-run/scripts/fuzz-campaign.py run camp"),
        ])
        self.assertEqual([(w, p) for w, p, _ in got],
                         [("syz-manager", 10), ("supervisor", 11)])

    def test_our_own_process_is_skipped(self):
        self.assertEqual(self._busy([
            (os.getpid(), "/Users/Shared/fuzz-run/bin/syz-manager -config /x.cfg"),
        ]), [])

    def test_status_watch_is_not_a_running_campaign(self):
        self.assertEqual(self._busy([
            (12, "/usr/bin/python3 scripts/fuzz-campaign.py status camp -w"),
            (13, "/usr/bin/python3 scripts/fuzz-campaign.py doctor camp"),
        ]), [])


if __name__ == "__main__":
    unittest.main()


class RealClock(unittest.TestCase):
    """The 'real' budget clock: elapsed time since the config started, counting
    everything. Neither 'fuzz' nor 'wall' can express a window like 2pm-4pm --
    wall_seconds is occupancy (active+triage+overhead) and explicitly excludes
    time halted or idle, so a halted campaign's budget simply stops moving."""

    def _state(self, started_at=None, **clocks):
        s = {"config_started_at": started_at}
        s.update(clocks)
        return s

    def test_real_measures_elapsed_not_occupancy(self):
        # Started 90 minutes ago, but the campaign only ever ran 1 minute of
        # anything -- the rest was halted, rebooting, or powered off.
        from datetime import datetime, timezone
        stamp = datetime.fromtimestamp(
            time.time() - 5400, timezone.utc).astimezone().isoformat()
        s = self._state(stamp, active_seconds=60.0)
        d = {"budget_clock": "real"}
        self.assertAlmostEqual(fc.budget_spent(s, d), 5400, delta=5)
        # the other clocks see only the minute that was actually spent
        self.assertEqual(fc.budget_spent(s, {"budget_clock": "fuzz"}), 60.0)
        self.assertEqual(fc.budget_spent(s, {"budget_clock": "wall"}), 60.0)

    def test_missing_stamp_is_zero_not_a_crash(self):
        self.assertEqual(fc.budget_spent(self._state(None), {"budget_clock": "real"}), 0.0)
        self.assertEqual(fc.budget_spent(self._state("garbage"), {"budget_clock": "real"}), 0.0)

    def test_advancing_config_clears_the_origin(self):
        # Each config gets its own window; roll_budget_clocks drops the stamp so
        # the next config stamps a fresh one.
        s = {"config_started_at": fc.now_iso(), "active_seconds": 10.0}
        fc.roll_budget_clocks(s)
        self.assertIsNone(s["config_started_at"])

    def test_real_is_a_valid_clock_choice(self):
        self.assertIn("real", fc.BUDGET_CLOCKS)
