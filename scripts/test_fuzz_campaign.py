#!/usr/bin/env python3
"""Tests for the exclude/include (bench + rotate) step in fuzz-campaign.py.

fuzz-campaign.py has a hyphen, so it is loaded by path rather than imported.
These cover exclude_syscalls (bench: add names to disable_syscalls) and
include_syscalls (rotate a benched syscall back in). The culprit -> name list
translation (syz-ring-repro -emit-json) is exercised by the Go tests.
"""

import importlib.util
import json
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

    def test_default_budget_clock_is_fuzz(self):
        """Minimizing a bug must not eat the fuzzing budget by default."""
        self.assertEqual(fc.DEFAULTS["budget_clock"], "fuzz")

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


if __name__ == "__main__":
    unittest.main()
