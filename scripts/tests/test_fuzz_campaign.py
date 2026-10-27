#!/usr/bin/env python3
"""Tests for the exclude/include (bench + rotate) step in fuzz-campaign.py.

fuzz-campaign.py has a hyphen, so it is loaded by path rather than imported.
These cover exclude_syscalls (bench: add names to disable_syscalls) and
include_syscalls (rotate a benched syscall back in). The culprit -> name list
translation (syz-ring-repro -emit-json) is exercised by the Go tests.
"""

import contextlib
import importlib.util
import io
import json
import os
import signal
import tempfile
import types
import time
import unittest
from pathlib import Path
from unittest import mock

# Never post a notification or open a Terminal from a test run on the box.
os.environ.setdefault("FUZZ_NO_GUI", "1")


def _load_campaign():
    path = Path(__file__).resolve().parent.parent / "fuzz-campaign.py"
    spec = importlib.util.spec_from_file_location("fuzz_campaign", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


fc = _load_campaign()
# Tests that drive cmd_run take the per-campaign lock and read requests; without
# this they would write into the repo's own run/ directory.
fc.RUN_DIR = Path(tempfile.mkdtemp(prefix="fc-run-")) / "run"


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
        s.update({"status": "running", "phase": "triaging", "triage_job": "camp_t1",
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
        now = time.time()
        s["run_prep_started"] = now - 45
        fc.record_incident(s, d, "crash",
                           {"run_started_epoch": now - 44, "fuzz_started_epoch": now - 42,
                            "last_activity_epoch": now, "boot_epoch": 1,
                            "panic_evidence": True})
        self.assertAlmostEqual(s["active_seconds"], 42, delta=1)
        first = s["active_seconds"]
        s["run_prep_started"] = now - 12
        fc.record_incident(s, d, "crash",
                           {"run_started_epoch": now - 11, "fuzz_started_epoch": now - 10,
                            "last_activity_epoch": now, "boot_epoch": 1,
                            "panic_evidence": True})
        self.assertAlmostEqual(s["active_seconds"], first + 10, delta=1)   # accumulates

    def test_triage_panics_reach_the_bug_inventory(self):
        """A crash that minimization produced must be catalogued, not left in the
        triage job's ledger where no report ever sees it."""
        panic = self.dir / "panic-full-x.panic"
        panic.write_text("x")
        routed = []
        with mock.patch.object(fc, "PANIC_DIRS", [self.dir]), \
             mock.patch.object(fc, "route_bug_registry",
                               lambda p, *a, **kw: routed.append((p, kw.get("origin")))):
            fc.route_triage_panics(fc.init_state("camp"), {"incidents": [
                {"report": "panic-full-x.panic"},
                {"report": "panic-full-missing.panic"},   # not on disk -> skipped
                {},                                       # no report key -> skipped
            ]}, "camp_t1")
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
        s.update({"status": "running", "phase": "triaging", "triage_job": "camp_t1", "triage_boots": 0})
        d = dict(fc.DEFAULTS)
        waited = []
        with mock.patch.object(fc, "triage", lambda *a, **k: (0, "")), \
             mock.patch.object(fc, "triage_state", lambda job: {"stage": "MINIMIZE_CONN"}), \
             mock.patch.object(fc, "save_state", lambda st: None), \
             mock.patch.object(fc, "route_triage_panics", lambda *a, **k: None), \
             mock.patch.object(fc, "wait_for_stop",
                               lambda st, dd, sec: waited.append(sec)):
            fc.advance_triage(s, d)
        # A short, interruptible breather -- not a whole 10-minute poll.
        self.assertEqual(waited, [d["triage_retry_seconds"]])
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
        s.update(status="running", phase="fuzzing")      # a started campaign
        s["session_id"] = "sess"
        d = dict(fc.DEFAULTS)
        with mock.patch.object(fc, "inspect", lambda sid: {"found": False}):
            ok = fc.begin_triage(s, d, "SIG1")
        self.assertFalse(ok)
        self.assertEqual(s["phase"], "fuzzing")    # unchanged
        self.assertIsNone(s["triage_job"])


class TriageOutcomeTest(unittest.TestCase):
    """What the campaign does with each way a triage job can end."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.cfg = write_cfg(self.dir, {"target": "darwin/arm64", "enable_syscalls": ["a"]})
        self.s = fc.init_state("camp")
        self.s.update({"phase": "triaging", "triage_job": "camp_t1",
                       "triage_bug_sig": "SIG1", "current_config": str(self.cfg)})

    def tearDown(self):
        self._tmp.cleanup()

    def advance(self, st, selectors=("syz_IOConnectCallMethod$Foo_5",)):
        runs = []
        with mock.patch.object(fc, "STATE_DIR", self.dir / "state"), \
             mock.patch.object(fc, "triage", lambda *a, **k: runs.append(a) or (0, "")), \
             mock.patch.object(fc, "triage_state", lambda job: st), \
             mock.patch.object(fc, "route_triage_panics", lambda *a, **k: None), \
             mock.patch.object(fc, "wait_for_stop", lambda *a, **k: None), \
             mock.patch.object(fc, "attribute_bug", lambda *a, **k: None), \
             mock.patch.object(fc, "culprit_sequence", lambda c: list(selectors)), \
             mock.patch.object(fc, "save_state", lambda st: None):
            fc.advance_triage(self.s, dict(fc.DEFAULTS))
        return runs

    def disabled(self):
        return json.loads(self.cfg.read_text()).get("disable_syscalls", [])

    def test_triage_runs_with_reboot_on_hang(self):
        runs = self.advance({"stage": "MINIMIZE_CONN"})
        self.assertEqual(runs, [("run", "camp_t1", "--reboot-on-hang")])

    def test_no_repro_is_exhausted_and_benches_nothing(self):
        self.advance({"stage": "STUCK", "stuck_kind": "no-repro",
                      "conn_culprit": str(self.cfg)})
        self.assertEqual(self.s["exhausted_sigs"], ["SIG1"])
        self.assertEqual(self.s["exhausted_why"], {"SIG1": "no-repro"})
        self.assertEqual(self.disabled(), [])
        self.assertEqual(self.s["phase"], "fuzzing")

    def test_a_ring_only_reproducer_is_not_benched_either(self):
        self.advance({"stage": "STUCK", "stuck_kind": "ring-only",
                      "ring_copy": str(self.dir)})
        self.assertEqual(self.s["exhausted_why"], {"SIG1": "ring-only"})
        self.assertEqual(self.disabled(), [])

    def test_a_hang_benches_the_hung_program_under_its_own_key(self):
        hung = self.dir / "hang_culprit.syz"
        hung.write_text("syz_IOConnectCallMethod$Foo_9(0x0)\n")
        self.advance({"stage": "STUCK", "stuck_kind": "hang", "hang_culprit": str(hung)},
                     selectors=["syz_IOConnectCallMethod$Foo_9"])
        self.assertEqual(self.disabled(), ["syz_IOConnectCallMethod$Foo_9"])
        with mock.patch.object(fc, "STATE_DIR", self.dir / "state"):
            cat = fc.load_qstate(str(self.cfg))["catalog"]
        self.assertIn("hang:camp_t1", cat)
        self.assertNotIn("SIG1", cat)             # not filed as the target crash
        self.assertEqual(self.s["exhausted_why"], {"SIG1": "hang"})

    def test_a_verified_connection_culprit_is_benched_when_calls_did_not_reduce(self):
        culprit = self.dir / "conn_culprit.syz"
        culprit.write_text("x\n")
        with mock.patch.object(fc, "STATE_DIR", self.dir / "state"):
            qs = fc.load_qstate(str(self.cfg))
            fc.qm.on_crash(qs, "SIG1", None)
            fc.save_qstate(str(self.cfg), qs)
        self.advance({"stage": "DONE", "final_culprit": str(culprit),
                      "conn_culprit": str(culprit), "calls_reduced": False})
        self.assertEqual(self.disabled(), ["syz_IOConnectCallMethod$Foo_5"])
        self.assertEqual(self.s.get("exhausted_sigs"), [])

    def test_a_hang_the_box_could_not_reboot_from_halts(self):
        self.advance({"stage": "MINIMIZE_CONN",
                      "needs_reboot": {"at": 1, "why": "sudo: a password is required"}})
        self.assertEqual(self.s["status"], "halted")
        self.assertIn("password is required", self.s["halt_reason"])


class SecondBugTest(unittest.TestCase):
    """A different bug panicking the box during minimization: filed once as a
    genuine find, seeded SUSPECT, and queued for its own triage."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.cfg = write_cfg(self.dir, {"target": "darwin/arm64", "enable_syscalls": ["a"]})
        self.panics = self.dir / "panics"
        self.panics.mkdir()
        for n in ("t.panic", "o.panic"):
            (self.panics / n).write_text("x")
        self.prog = self.dir / "other_OTHER.syz"
        self.prog.write_text("syz_IOConnectCallMethod$Foo_7(0x0)\n")
        self.st = {"target_signature": "TARGET", "incidents": [
            {"report": "t.panic", "signature": "TARGET"},
            {"report": "o.panic", "signature": "OTHER", "title": "panic: x",
             "kext": "com.apple.Foo"}],
            "other_bugs": {"OTHER": {"program": str(self.prog)}}}
        self.s = fc.init_state("camp")
        self.s.update({"phase": "triaging", "triage_job": "camp_t1",
                       "triage_bug_sig": "TARGET", "current_config": str(self.cfg)})
        self.d = dict(fc.DEFAULTS, items=[{"config": str(self.cfg), "max_hours": 2}])
        self.routed = []
        for p in (mock.patch.object(fc, "STATE_DIR", self.dir / "state"),
                  mock.patch.object(fc, "PANIC_DIRS", [self.panics]),
                  mock.patch.object(fc, "route_bug_registry",
                                    lambda p, *a, **kw: self.routed.append(
                                        (Path(p).name, kw.get("origin"))))):
            p.start()
            self.addCleanup(p.stop)

    def tearDown(self):
        self._tmp.cleanup()

    def test_each_panic_is_routed_once_with_its_origin(self):
        fc.route_triage_panics(self.s, self.st, "camp_t1")
        fc.route_triage_panics(self.s, self.st, "camp_t1")     # the next advance
        self.assertEqual(self.routed, [("t.panic", "triage"),
                                       ("o.panic", "fuzz-during-triage")])

    def test_a_second_bug_is_seeded_suspect(self):
        fc.route_triage_panics(self.s, self.st, "camp_t1")
        rec = fc.load_qstate(str(self.cfg))["catalog"]["OTHER"]
        self.assertEqual((rec["disposition"], rec["occurrence_count"]), (fc.qm.SUSPECTED, 1))
        self.assertNotIn("TARGET", fc.load_qstate(str(self.cfg))["catalog"])

    def test_a_second_bug_is_queued_once(self):
        fc.queue_second_bugs(self.s, self.st, "camp_t1")
        fc.queue_second_bugs(self.s, self.st, "camp_t1")
        self.assertEqual([q["sig"] for q in self.s["triage_queue"]], ["OTHER"])
        self.assertEqual(self.s["triage_queue"][0]["program"], str(self.prog))

    def test_an_exhausted_or_benched_second_bug_is_not_queued(self):
        self.s["exhausted_sigs"] = ["OTHER"]
        fc.queue_second_bugs(self.s, self.st, "camp_t1")
        self.assertEqual(self.s["triage_queue"], [])
        self.s["exhausted_sigs"] = []
        qs = fc.load_qstate(str(self.cfg))
        fc.qm.bench_lead(qs, "OTHER", ["A"], "x")
        fc.save_qstate(str(self.cfg), qs)
        fc.queue_second_bugs(self.s, self.st, "camp_t2")
        self.assertEqual(self.s["triage_queue"], [])

    def finish_job(self, spent=0.0):
        """End the current job (DONE, nothing to bench) and return the ring a
        queued triage was started from, if any."""
        started = []
        self.s["triage_seconds"] = spent
        with mock.patch.object(fc, "triage", lambda *a, **k: (0, "")), \
             mock.patch.object(fc, "triage_state", lambda job: dict(self.st, stage="DONE")), \
             mock.patch.object(fc, "attribute_bug", lambda *a, **k: None), \
             mock.patch.object(fc, "quarantine_apply_culprit", lambda *a, **k: None), \
             mock.patch.object(fc, "save_state", lambda st: None), \
             mock.patch.object(fc, "begin_triage",
                               lambda s, d, sig, ring=None: started.append((sig, ring)) or True):
            fc.advance_triage(self.s, self.d)
        return started

    def test_the_queued_bug_is_triaged_when_the_job_ends(self):
        before = self.s["panic_sig_watermark"]
        os.utime(self.panics / "o.panic", (before + 100, before + 100))
        started = self.finish_job()
        self.assertEqual(len(started), 1)
        sig, ring = started[0]
        self.assertEqual(sig, "OTHER")
        self.assertEqual((ring / "slot_0000.syz").read_text(),
                         "id=0\n" + self.prog.read_text())
        self.assertEqual(self.s["triage_queue"], [])
        self.assertNotIn("camp_t1", self.s["triage_seen"])
        # the next fuzzing crash must not fingerprint the triage panics again
        self.assertGreaterEqual(self.s["panic_sig_watermark"], before + 100)

    def test_a_spent_budget_drops_the_queue(self):
        self.d["clock"] = "wall"      # the clock that charges triage_seconds
        self.assertEqual(self.finish_job(spent=7200.0), [])
        self.assertEqual(self.s["triage_queue"], [])

    def test_advancing_the_config_drops_the_queue(self):
        self.s["triage_queue"] = [{"sig": "OTHER", "program": "p"}]
        fc.advance_config(self.s)
        self.assertEqual(self.s["triage_queue"], [])


class DisplayFixesTest(unittest.TestCase):
    """Bugs seen in real campaign logs: a lost crash window, "HALT: None", a
    phantom hang after a halt, and a hardcoded launchd domain."""

    def test_the_session_is_named_before_it_starts(self):
        s = fc.init_state("camp")
        s.update({"session_id": None, "current_config": None})
        saved_at_start = []

        def session(verb, *a, **k):
            saved_at_start.append((verb, dict(saved[-1])))
            return 0, ""
        saved = []
        with mock.patch.object(fc, "inspect", lambda sid: {"found": False}), \
             mock.patch.object(fc, "apply_disabled", lambda *a: None), \
             mock.patch.object(fc, "load_qstate", lambda c: {}), \
             mock.patch.object(fc, "results_commit", lambda *a, **k: None), \
             mock.patch.object(fc, "session", session), \
             mock.patch.object(fc, "save_state", lambda st: saved.append(dict(st))):
            fc.ensure_running(s, "/cfg/x.cfg", dict(fc.DEFAULTS))
        verb, state = saved_at_start[0]
        self.assertEqual(verb, "start")
        self.assertEqual(state["session_id"], fc.config_id("/cfg/x.cfg"))
        self.assertEqual(state["current_config"], "/cfg/x.cfg")

    def reconcile(self, info, s=None):
        s = s or fc.init_state("camp")
        s["session_id"] = s.get("session_id") or "sess"
        s["current_config"] = s.get("current_config") or "/cfg/x.cfg"
        calls = []
        with mock.patch.object(fc, "inspect", lambda sid: info), \
             mock.patch.object(fc, "session", lambda *a, **k: calls.append(a) or (0, "")), \
             mock.patch.object(fc, "collect_and_prune", lambda *a: calls.append("incident")), \
             mock.patch.object(fc, "save_state", lambda st: None):
            end = fc.reconcile_boot(s, dict(fc.DEFAULTS))
        return s, calls, end

    def test_a_deliberately_stopped_run_is_not_a_hang(self):
        s, calls, _ = self.reconcile({
            "found": True, "status": "stopped", "pid_alive": False,
            "uncollected": {"run_started": "x"}, "panic_evidence": False})
        self.assertEqual(s["hangs"], 0)
        self.assertEqual(s["incidents"], [])
        self.assertEqual(calls, [("collect", "sess", "snapshot")])

    def test_a_run_that_died_uncollected_is_still_an_incident(self):
        s, calls, _ = self.reconcile({
            "found": True, "status": "crashed", "pid_alive": False,
            "uncollected": {"run_started": "x"}, "panic_evidence": False,
            "panics": [], "run_started_epoch": None})
        self.assertEqual(s["hangs"], 1)
        self.assertIn("incident", calls)

    def test_a_previous_runs_record_does_not_end_the_new_run_early(self):
        """Named before its manager started, then the box went down: the record
        found is the previous, collected run, which ended before this one opened."""
        s = fc.init_state("camp")
        s.update({"session_id": "sess", "run_prep_started": 5000.0})
        _, _, end = self.reconcile({
            "found": True, "status": "stopped", "pid_alive": False, "uncollected": None,
            "run_started_epoch": 1000.0, "last_activity_epoch": 2000.0,
            "boot_epoch": 6000.0}, s)
        self.assertEqual(end, 5000.0)
        self.assertEqual(s["active_seconds"], 0.0)

    def test_a_user_halt_has_a_reason(self):
        s = fc.init_state("camp")
        with mock.patch.object(fc, "load_state", lambda n: s), \
             mock.patch.object(fc, "save_state", lambda st: None), \
             mock.patch.object(fc, "session", lambda *a, **k: (0, "")):
            fc.cmd_halt("camp")
        self.assertEqual((s["status"], s["halt_reason"]), ("halted", "halted by user"))
        with mock.patch.object(fc, "load_state", lambda n: s), \
             mock.patch.object(fc, "save_state", lambda st: None):
            fc.cmd_resume("camp")
        self.assertIsNone(s["halt_reason"])

    def test_agent_domains_follow_the_install_not_a_fixed_uid(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "fuzz"
            agents = home / "Library" / "LaunchAgents"
            agents.mkdir(parents=True)
            (agents / ("%s.plist" % fc.plist_label("camp"))).write_text("x")
            users = [types.SimpleNamespace(pw_uid=503, pw_dir=str(home)),
                     types.SimpleNamespace(pw_uid=501, pw_dir=str(Path(tmp) / "wan"))]
            with mock.patch.object(fc.pwd, "getpwall", lambda: users), \
                 mock.patch.object(fc, "state_path", lambda n: Path(tmp) / "absent.json"):
                self.assertEqual(fc.agent_domains("camp"), ["gui/503"])


class AttributionTest(unittest.TestCase):
    """What each incident says about the crash: signature, kexts, bug, decision."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.cfg = write_cfg(self.dir, {
            "target": "darwin/arm64",
            "workdir": "/Users/Shared/fuzz-run/workdir/AppleSMC/261016_cov",
            "kext_coverage": {"kext_id": 2},
            "enable_syscalls": ["syz_IOServiceOpen$AppleSMCKeysEndpoint_AppleSMCClient",
                                "syz_IOConnectCallMethod$AppleSMCClient_0"]})

    def tearDown(self):
        self._tmp.cleanup()

    def test_fuzzed_target_reads_the_config(self):
        t = fc.fuzzed_target(str(self.cfg))
        self.assertEqual(t, {"kext_id": 2, "kext": "AppleSMC",
                             "services": ["AppleSMCKeysEndpoint"]})

    def test_kext_match(self):
        t = fc.fuzzed_target(str(self.cfg))
        self.assertIs(fc.kext_matches(t, "AppleSMC"), True)
        self.assertIs(fc.kext_matches(t, "IOSurface"), False)
        self.assertIsNone(fc.kext_matches(t, "kernel"))
        self.assertIsNone(fc.kext_matches(t, None))

    def crash(self, decision="resume", sig="SIG9", kext="IOSurface", begin=False):
        s = fc.init_state("camp")
        s.update({"session_id": "sess", "current_config": str(self.cfg)})
        fc.record_incident(s, dict(fc.DEFAULTS), "crash",
                           {"run_started_epoch": 1.0, "panic_evidence": True}, 2.0)

        def latest(st):
            st["last_panic"] = {"signature": sig, "title": "panic: x", "crashing_kext": kext}
            return sig
        with mock.patch.object(fc, "STATE_DIR", self.dir / "state"), \
             mock.patch.object(fc, "route_bug_registry", lambda *a, **k: ["BUG-0007"]), \
             mock.patch.object(fc, "latest_panic_signature", latest), \
             mock.patch.object(fc, "quarantine_decide", lambda st, g: decision), \
             mock.patch.object(fc, "begin_triage",
                               lambda st, d, g: st.update(triage_job="camp_t3") or begin):
            fc.handle_crash(s, dict(fc.DEFAULTS), {"panics": ["/p.panic"]})
        return s["incidents"][-1]

    def test_a_crash_outside_the_fuzzed_kext_is_flagged(self):
        inc = self.crash()
        self.assertEqual((inc["fuzzed_kext"], inc["kext_id"]), ("AppleSMC", 2))
        self.assertEqual((inc["signature"], inc["crashing_kext"]), ("SIG9", "IOSurface"))
        self.assertIs(inc["kext_match"], False)
        self.assertEqual(inc["bug_ids"], ["BUG-0007"])
        self.assertIn("NOT the fuzzed AppleSMC", fc.incident_line(inc))

    def test_the_decision_and_triage_job_are_recorded(self):
        inc = self.crash(decision="triage", kext="AppleSMC", begin=True)
        self.assertEqual((inc["decision"], inc["triage_job"]), ("triage", "camp_t3"))
        self.assertIs(inc["kext_match"], True)
        line = fc.incident_line(inc)
        self.assertIn("sig SIG9 BUG-0007", line)
        self.assertIn("-> triage camp_t3", line)

    def test_route_bug_registry_returns_the_bug_ids(self):
        out = "NEW BUG  BUG-0012 [new]  Drv:m:READ\n"
        with mock.patch.object(fc, "BUG_REGISTRY", self.cfg), \
             mock.patch.object(fc, "BUGS_DIR", self.dir / "bugs"), \
             mock.patch.object(fc.subprocess, "run",
                               lambda *a, **k: types.SimpleNamespace(returncode=0, stdout=out)):
            self.assertEqual(fc.route_bug_registry("/p.panic"), ["BUG-0012"])


class ExhaustedRecurrenceTest(unittest.TestCase):
    """An exhausted signature that keeps panicking the box: counted, then a lead
    is benched so it stops costing a reboot every time."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.cfg = write_cfg(self.dir, {"target": "darwin/arm64", "enable_syscalls": ["a"]})
        ring = self.dir / "wd" / "ring_buffer"
        ring.mkdir(parents=True)
        (ring / "slot_0001.syz").write_text("id=9\nnewest()\n")
        (ring / "slot_0002.syz").write_text("id=3\nolder()\n")
        self.s = fc.init_state("camp")
        self.s.update({"current_config": str(self.cfg), "exhausted_sigs": ["SIG1"],
                       "exhausted_why": {"SIG1": "no-repro"}})

    def tearDown(self):
        self._tmp.cleanup()

    def test_newest_ring_program_is_the_highest_id_without_its_header(self):
        out = fc.newest_ring_program(self.dir / "wd", self.dir / "lead.syz")
        self.assertEqual(Path(out).read_text(), "newest()\n")
        self.assertIsNone(fc.newest_ring_program(self.dir / "nowhere", self.dir / "x.syz"))

    def test_lead_is_benched_after_the_tolerate_budget(self):
        seen = []
        info = {"panics": [], "workdir": str(self.dir / "wd")}
        with mock.patch.object(fc, "STATE_DIR", self.dir / "state"), \
             mock.patch.object(fc, "route_bug_registry", lambda *a, **k: None), \
             mock.patch.object(fc, "latest_panic_signature", lambda s: "SIG1"), \
             mock.patch.object(fc, "culprit_sequence",
                               lambda c: seen.append(Path(c).read_text()) or ["sel_A"]):
            results = [fc.handle_crash(self.s, dict(fc.DEFAULTS), info) for _ in range(4)]
            disabled = json.loads(self.cfg.read_text()).get("disable_syscalls", [])
            rec = fc.load_qstate(str(self.cfg))["catalog"]["SIG1"]
        self.assertEqual(results, [False] * 4)      # never re-triaged
        self.assertEqual(seen, ["newest()\n"])      # benched once, on the 4th
        self.assertEqual(disabled, ["sel_A"])
        self.assertFalse(rec["leads"][0]["verified"])


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
        self.assertEqual(fc.budget_spent(s, {"clock": "fuzz"}), 100.0)

    def test_budget_clock_wall_charges_everything(self):
        s = {"active_seconds": 100.0, "triage_seconds": 900.0, "overhead_seconds": 900.0}
        self.assertEqual(fc.budget_spent(s, {"clock": "wall"}), 1900.0)

    def test_default_budget_clock_is_real(self):
        """An item asked for 6h ends 6h after it started, whatever happened in
        between: the operator can say when the box frees up. One default for
        plans and for a legacy definition that says nothing."""
        self.assertEqual(fc.budget_clock({}), "real")
        self.assertEqual(fc.planlib.DEFAULT_CLOCK, "real")

    def test_wall_is_never_less_than_fuzz(self):
        """So the default can only ever end a campaign sooner, never overrun."""
        s = {"active_seconds": 100.0, "triage_seconds": 50.0,
             "overhead_seconds": 25.0}
        self.assertGreaterEqual(fc.budget_spent(s, {"clock": "wall"}),
                                fc.budget_spent(s, {"clock": "fuzz"}))

    def test_budget_spent_while_triaging_finishes_the_job_then_advances(self):
        """A job is not abandoned half-way when the budget runs out (that used to
        end the whole campaign, so later configs never ran): it is finished, and
        the config is advanced without starting a manager only to stop it."""
        s = fc.init_state("camp")
        s.update({"phase": "triaging", "triage_job": "camp_t1",
                  "triage_bug_sig": "S", "active_seconds": 3600.0,
                  "triage_seconds": 3600.0})
        d = dict(fc.DEFAULTS, clock="wall", loop=False,
                 items=[{"config": "/x.cfg", "max_hours": 2}], name="camp")
        advanced, commits = [], []

        def finish(st, dd):
            advanced.append(1)
            st["phase"] = "fuzzing"
            st["triage_job"] = None

        def no_start(*a, **k):
            raise AssertionError("a manager was started on a spent budget")

        with mock.patch.object(fc, "STATE_DIR", self.dir), \
             mock.patch.object(fc, "load_def", lambda n: d), \
             mock.patch.object(fc, "advance_triage", finish), \
             mock.patch.object(fc, "ensure_running", no_start), \
             mock.patch.object(fc, "results_commit",
                               lambda st, dd, ev, cfg=None, **k: commits.append(ev)), \
             mock.patch.object(fc, "reconcile_boot", lambda *a: None), \
             mock.patch.object(fc, "reconcile_gap", lambda *a, **k: None), \
             mock.patch.object(fc, "reconcile_triage_gap", lambda *a, **k: None), \
             mock.patch.object(fc, "save_state", lambda st: None), \
             mock.patch.object(fc, "load_state", lambda n: s), \
             mock.patch.object(fc, "brake_held", lambda n: None), \
             mock.patch.object(fc, "breaker", lambda *a: None):
            fc.cmd_run("camp")
        self.assertEqual(advanced, [1])         # the job was finished
        self.assertEqual(commits, ["end"])      # the config was closed
        self.assertEqual(s["cursor"], 1)
        self.assertEqual(s["status"], "done")   # one item, nothing after it

    def test_triage_phase_continues_while_budget_remains(self):
        s = fc.init_state("camp")
        s.update({"phase": "triaging", "triage_job": "camp_t1",
                  "triage_bug_sig": "S", "active_seconds": 60.0})
        d = dict(fc.DEFAULTS, clock="wall",
                 items=[{"config": "/x.cfg", "max_hours": 2}], name="camp")
        advanced = []

        def stop_after_one(st, dd):
            advanced.append(1)
            st["status"] = "halted"

        with mock.patch.object(fc, "STATE_DIR", self.dir), \
             mock.patch.object(fc, "load_def", lambda n: d), \
             mock.patch.object(fc, "advance_triage", stop_after_one), \
             mock.patch.object(fc, "reconcile_boot", lambda *a: None), \
             mock.patch.object(fc, "reconcile_gap", lambda *a, **k: None), \
             mock.patch.object(fc, "reconcile_triage_gap", lambda *a, **k: None), \
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

    def test_a_halt_is_not_charged_as_rebooting(self):
        # The run ended at 16:35:50, the campaign sat halted, `resume` ran at
        # 16:41:40 and the driver at 16:41:53: only the 13s after the resume
        # are relaunch overhead. Counting from the run's end charged 6 minutes.
        end = time.time() - 363
        s = fc.init_state("camp")
        s["resumed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 13))
        with mock.patch.object(fc, "boot_epoch", lambda: end - 3600):
            fc.reconcile_gap(s, dict(fc.DEFAULTS), since=fc.gap_origin(s, end))
        self.assertLess(s["overhead_seconds"], 20)
        # no resume: the origin is what the caller had
        self.assertEqual(fc.gap_origin(fc.init_state("camp"), end), end)
        # a resume before the last run ended changes nothing
        old = fc.init_state("camp")
        old["resumed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(end - 60))
        self.assertEqual(fc.gap_origin(old, end), end)

    def test_resume_stamps_the_end_of_the_halt(self):
        s = fc.init_state("camp")
        s["status"] = "halted"
        with mock.patch.object(fc, "load_state", lambda n: s), \
             mock.patch.object(fc, "save_state", lambda st: None):
            fc._set_status("camp", "running")
        self.assertLess(abs(fc.timefmt.to_epoch(s["resumed_at"]) - time.time()), 5)

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
        with mock.patch.object(fc, "boot_epoch", lambda: None):
            fc.reconcile_gap(s, dict(fc.DEFAULTS))
        self.assertEqual(s["overhead_seconds"], fc.DEFAULTS["max_boot_gap_seconds"])

    def test_reconcile_gap_never_charges_more_than_one_cap(self):
        """Powered off for days after a panic: still one cap, not one per part."""
        now = 1_000_000.0
        s = fc.init_state("camp")
        with mock.patch.object(fc, "boot_epoch", lambda: now - 60):
            fc.reconcile_gap(s, dict(fc.DEFAULTS), since=now - 3 * 86400, now=now)
        self.assertEqual(s["overhead_seconds"], fc.DEFAULTS["max_boot_gap_seconds"])

    def test_a_late_manual_relaunch_is_not_overhead(self):
        """Rebooted Saturday, driver started by hand Monday: the reboot counts,
        the weekend after it does not."""
        now = 1_000_000.0
        s = fc.init_state("camp")
        with mock.patch.object(fc, "boot_epoch", lambda: now - 2 * 86400):
            fc.reconcile_gap(s, dict(fc.DEFAULTS), since=now - 2 * 86400 - 90, now=now)
        self.assertEqual(s["overhead_seconds"], 90 + fc.DEFAULTS["max_relaunch_seconds"])

    def test_crash_found_after_a_long_power_off_is_not_fuzzing(self):
        """The 68h41m bug: a run discovered dead on the next boot was charged as
        fuzzing up to the moment it was found, through the whole downtime."""
        now = 1_000_000.0
        s = fc.init_state("camp")
        s.update({"session_id": "sid", "current_config": "/x.cfg",
                  "run_prep_started": now - 68 * 3600 - 700})
        info = {"found": True, "status": "crashed", "pid_alive": False,
                "uncollected": {"run_started": "x"}, "panic_evidence": False,
                "run_started_epoch": now - 68 * 3600 - 690,
                "fuzz_started_epoch": now - 68 * 3600 - 660,
                "last_activity_epoch": now - 68 * 3600,      # last log line
                "boot_epoch": now - 120}
        with mock.patch.object(fc, "inspect", lambda sid: info), \
             mock.patch.object(fc, "collect_and_prune", lambda *a: None), \
             mock.patch.object(fc, "save_state", lambda st: None), \
             mock.patch.object(fc, "boot_epoch", lambda: now - 120), \
             mock.patch.object(fc.time, "time", lambda: now):
            end = fc.reconcile_boot(s, dict(fc.DEFAULTS))
            fc.reconcile_gap(s, dict(fc.DEFAULTS), since=end)
        self.assertAlmostEqual(s["active_seconds"], 660, delta=1)
        self.assertAlmostEqual(s["prep_seconds"], 40, delta=1)
        # the panic->boot part alone exceeds the cap; nothing beyond one cap
        self.assertEqual(s["overhead_seconds"], fc.DEFAULTS["max_boot_gap_seconds"])
        self.assertEqual(s["incidents"][-1]["ran_seconds"], 690)

    def test_a_run_that_never_executed_is_all_preparation(self):
        now = 5000.0
        s = fc.init_state("camp")
        s.update({"run_prep_started": now - 100})
        fc.close_run(s, {"run_started_epoch": now - 90, "fuzz_started_epoch": None},
                     now - 88)
        self.assertEqual(s["active_seconds"], 0.0)
        self.assertAlmostEqual(s["prep_seconds"], 12, delta=0.01)
        self.assertIsNone(s["run_prep_started"])

    def test_closing_a_run_twice_counts_it_once(self):
        now = 5000.0
        s = fc.init_state("camp")
        s.update({"run_prep_started": now - 100})
        info = {"run_started_epoch": now - 95, "fuzz_started_epoch": now - 80}
        fc.close_run(s, info, now)
        fc.close_run(s, info, now)
        self.assertAlmostEqual(s["active_seconds"], 80, delta=0.01)
        self.assertAlmostEqual(s["prep_seconds"], 20, delta=0.01)

    def test_reattaching_does_not_recount_the_open_run(self):
        """Re-basing on attach re-added the run's elapsed time on every relaunch."""
        s = fc.init_state("camp")
        s.update({"session_id": "x", "active_seconds": 300.0, "run_active_base": 100.0,
                  "prep_seconds": 30.0, "run_prep_base": 0.0, "run_prep_started": 1000.0})
        alive = {"found": True, "status": "running", "pid_alive": True,
                 "run_started_epoch": 1010.0}
        with mock.patch.object(fc, "inspect", lambda sid: alive), \
             mock.patch.object(fc, "apply_disabled", lambda *a: None), \
             mock.patch.object(fc, "load_qstate", lambda c: {}), \
             mock.patch.object(fc, "save_state", lambda st: None):
            fc.ensure_running(s, "/cfg/x.cfg", dict(fc.DEFAULTS))
        self.assertEqual(s["run_active_base"], 100.0)
        self.assertEqual(s["run_prep_started"], 1000.0)

    def test_reattaching_a_closed_run_counts_only_what_came_after(self):
        """The review's case: a halt closes the run but leaves its manager alive.
        Re-attaching reopened it from the manager's own start, on bases that
        already held it -- an hour of fuzzing read as two."""
        t0 = 1_000_000.0
        s = fc.init_state("camp")
        s.update({"session_id": "x", "run_prep_started": t0})
        run = {"run_started_epoch": t0 + 5, "fuzz_started_epoch": t0 + 60}
        fc.close_run(s, run, t0 + 3600)                     # halted after 1h
        self.assertAlmostEqual(s["active_seconds"], 3540, delta=0.01)
        alive = dict(run, found=True, status="running", pid_alive=True)
        with mock.patch.object(fc, "inspect", lambda sid: alive), \
             mock.patch.object(fc, "apply_disabled", lambda *a: None), \
             mock.patch.object(fc, "load_qstate", lambda c: {}), \
             mock.patch.object(fc, "save_state", lambda st: None):
            fc.ensure_running(s, "/cfg/x.cfg", dict(fc.DEFAULTS))
        fc.account_run(s, alive, t0 + 3660)                # one poll, 60s later
        self.assertAlmostEqual(s["active_seconds"], 3600, delta=0.01)
        self.assertAlmostEqual(s["prep_seconds"], 60, delta=0.01)

    def test_a_breaker_halt_stops_the_manager(self):
        s = fc.init_state("camp")
        s.update({"session_id": "sid", "current_config": "/x.cfg"})
        d = dict(fc.DEFAULTS, poll_seconds=0, stop_check_seconds=0.01, name="camp")
        calls = []
        alive = {"found": True, "pid_alive": True, "exec_total": 1,
                 "run_started_epoch": time.time()}
        with mock.patch.object(fc, "STATE_DIR", self.dir), \
             mock.patch.object(fc, "load_state", lambda n: s), \
             mock.patch.object(fc, "save_state", lambda st: None), \
             mock.patch.object(fc, "brake_held", lambda n: None), \
             mock.patch.object(fc, "inspect", lambda sid: alive), \
             mock.patch.object(fc, "breaker", lambda *a: "low disk"), \
             mock.patch.object(fc, "quarantine_rotate_due", lambda st: False), \
             mock.patch.object(fc, "stuck_executor_seconds", lambda dd: None), \
             mock.patch.object(fc, "results_commit", lambda *a, **k: None), \
             mock.patch.object(fc, "session", lambda *a, **k: calls.append(a) or (0, "")):
            self.assertEqual(fc.supervise(s, d, "sid", budget=10 ** 9), "halted")
        self.assertIn(("stop", "sid"), calls)

    def test_wall_includes_preparation(self):
        s = {"prep_seconds": 7.0, "active_seconds": 100.0, "triage_seconds": 20.0,
             "overhead_seconds": 5.0}
        self.assertEqual(fc.wall_seconds(s), 132.0)
        self.assertEqual(fc.budget_spent(s, {"clock": "fuzz"}), 100.0)

    def test_triage_advance_cut_by_a_panic_is_split_at_the_last_probe(self):
        """Up to the crashing probe is minimization; after it, rebooting."""
        now = 1_000_000.0
        job = self.dir / "job"
        job.mkdir()
        ck = job / "conn_state.json"
        ck.write_text(json.dumps({"attempting_at": now - 400}))
        os.utime(ck, (now - 400, now - 400))
        s = fc.init_state("camp")
        s.update({"phase": "triaging", "triage_job": "camp_t1",
                  "triage_advance_started": now - 1000})
        with mock.patch.object(fc, "boot_epoch", lambda: now - 100), \
             mock.patch.object(fc, "triage_state", lambda j: {"dir": str(job)}):
            fc.reconcile_triage_gap(s, dict(fc.DEFAULTS), last_save=now - 1000, now=now)
        self.assertAlmostEqual(s["triage_seconds"], 600, delta=0.01)
        self.assertAlmostEqual(s["overhead_seconds"], 400, delta=0.01)
        self.assertIsNone(s["triage_advance_started"])

    def test_a_ring_replay_cut_by_a_panic_is_split_at_its_last_slot(self):
        now = 1_000_000.0
        job = self.dir / "job"
        job.mkdir()
        ck = job / "replay_state.json"
        ck.write_text(json.dumps({"pending": "replay", "pending_at": now - 700}))
        os.utime(ck, (now - 300, now - 300))     # rewritten before the last slot
        s = fc.init_state("camp")
        s.update({"phase": "triaging", "triage_job": "camp_t1",
                  "triage_advance_started": now - 1000})
        with mock.patch.object(fc, "boot_epoch", lambda: now - 100), \
             mock.patch.object(fc, "triage_state", lambda j: {"dir": str(job)}):
            fc.reconcile_triage_gap(s, dict(fc.DEFAULTS), last_save=now - 1000, now=now)
        self.assertAlmostEqual(s["triage_seconds"], 700, delta=0.01)

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
        d["triage_retry_seconds"] = 0
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

    def test_budget_wakes_at_the_deadline_not_the_next_poll(self):
        """A check that lands 54s short of the budget must not sleep a full
        600s poll: a 1h campaign ran to 1h09m that way."""
        s = fc.init_state("camp")
        s.update({"session_id": "sid", "current_config": "/x.cfg"})
        d = dict(fc.DEFAULTS, hang_after_seconds=9999, poll_seconds=600, name="camp")
        clock = [3546.0]
        waits = []

        def fake_wait(st, dd, seconds):
            waits.append(seconds)
            clock[0] += seconds
            return None

        alive = {"found": True, "pid_alive": True, "exec_total": 1,
                 "run_started_epoch": time.time(), "fuzz_started_epoch": time.time()}
        with mock.patch.object(fc, "STATE_DIR", self.dir), \
             mock.patch.object(fc, "load_state", lambda n: s), \
             mock.patch.object(fc, "save_state", lambda st: None), \
             mock.patch.object(fc, "wait_for_stop", fake_wait), \
             mock.patch.object(fc, "budget_spent", lambda st, dd: clock[0]), \
             mock.patch.object(fc, "inspect", lambda sid: alive), \
             mock.patch.object(fc, "breaker", lambda *a: None), \
             mock.patch.object(fc, "quarantine_rotate_due", lambda st: False), \
             mock.patch.object(fc, "stuck_executor_seconds", lambda dd: None), \
             mock.patch.object(fc, "session", lambda *a, **k: (0, "")):
            self.assertEqual(fc.supervise(s, d, "sid", budget=3600), "budget")
        # The first wait is the short startup poll (supervise has not yet seen
        # the first exec); the deadline still lands exactly, not a poll later.
        self.assertEqual(sum(waits), 54.0)
        self.assertLessEqual(max(waits), 54.0)

    def test_a_wedged_executor_is_a_hang_regardless_of_counters(self):
        """One `syz-executor exec` per program, so one alive for minutes is a
        syscall that never returned -- direct evidence, not an inference."""
        alive = {"found": True, "pid_alive": True, "exec_total": 1,
                 "run_started_epoch": time.time()}
        self.assertEqual(self._supervise([alive], hang_after=9999, stuck=2398),
                         "hang")


class BreakerTest(unittest.TestCase):
    """Area 2: which limits halt the campaign and which only move it on."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _supervise(self, info, s=None):
        s = s or fc.init_state("camp")
        s.update({"session_id": "sid", "current_config": "/x.cfg"})
        d = dict(fc.DEFAULTS, poll_seconds=600, name="camp")
        waits = []
        with mock.patch.object(fc, "STATE_DIR", self.dir), \
             mock.patch.object(fc, "load_state", lambda n: s), \
             mock.patch.object(fc, "save_state", lambda st: None), \
             mock.patch.object(fc, "wait_for_stop",
                               lambda st, dd, sec: waits.append(sec)), \
             mock.patch.object(fc, "inspect", lambda sid: info), \
             mock.patch.object(fc, "breaker", lambda *a: None), \
             mock.patch.object(fc, "session", lambda *a, **k: (0, "")):
            return fc.supervise(s, d, "sid", budget=10 ** 9), waits

    def test_a_manager_dead_before_its_first_exec_is_a_startup_failure(self):
        dead = {"found": True, "pid_alive": False, "panic_evidence": False,
                "fuzz_started_epoch": None}
        outcome, waits = self._supervise(dead)
        self.assertEqual(outcome, "startup")
        # noticed at the startup poll, not after a whole 10-minute poll
        self.assertEqual(waits, [fc.DEFAULTS["startup_poll_seconds"]])

    def test_a_manager_that_fuzzed_then_died_is_still_a_hang(self):
        dead = {"found": True, "pid_alive": False, "panic_evidence": False,
                "fuzz_started_epoch": 123.0}
        self.assertEqual(self._supervise(dead)[0], "hang")

    def test_a_panic_before_the_first_exec_is_a_crash(self):
        dead = {"found": True, "pid_alive": False, "panic_evidence": True,
                "fuzz_started_epoch": None}
        self.assertEqual(self._supervise(dead)[0], "crash")

    def test_repeated_startup_failures_halt_with_the_reason(self):
        s = fc.init_state("camp")
        s.update({"startup_failures": 3,
                  "last_startup_error": "[FATAL] bind: address already in use"})
        with mock.patch.object(fc, "free_gb", lambda: 1e9):
            why = fc.breaker(s, dict(fc.DEFAULTS))
        self.assertIn("address already in use", why)

    def test_max_crashes_counts_one_config_not_the_campaign(self):
        s = fc.init_state("camp")
        s.update({"crashes": 50, "config_incidents": 3})
        d = dict(fc.DEFAULTS, max_crashes=20)
        with mock.patch.object(fc, "free_gb", lambda: 1e9):
            self.assertIsNone(fc.breaker(s, d))
        self.assertIsNone(fc.config_breaker(s, d))
        s["config_incidents"] = 20
        self.assertIn("max_crashes", fc.config_breaker(s, d))

    def test_advancing_resets_the_config_counters(self):
        s = fc.init_state("camp")
        s.update({"config_incidents": 20, "consec_fast_crashes": 4,
                  "startup_failures": 2, "crashes": 20})
        fc.advance_config(s)
        self.assertEqual((s["cursor"], s["config_incidents"], s["consec_fast_crashes"],
                          s["startup_failures"]), (1, 0, 0, 0))
        self.assertEqual(s["crashes"], 20)          # lifetime total kept

    def _run(self, s, items):
        d = dict(fc.DEFAULTS, name="camp",
                 items=[{"config": c, "max_hours": 1} for c in items])
        started = []

        def fake_ensure(st, cfg, dd=None):
            started.append(cfg)
            st["status"] = "halted"           # stop after one start
            raise RuntimeError("stop here")

        with mock.patch.object(fc, "STATE_DIR", self.dir), \
             mock.patch.object(fc, "load_def", lambda n: d), \
             mock.patch.object(fc, "load_state", lambda n: s), \
             mock.patch.object(fc, "save_state", lambda st: None), \
             mock.patch.object(fc, "brake_held", lambda n: None), \
             mock.patch.object(fc, "breaker", lambda *a: None), \
             mock.patch.object(fc, "reconcile_boot", lambda *a: None), \
             mock.patch.object(fc, "reconcile_gap", lambda *a, **k: None), \
             mock.patch.object(fc, "results_commit", lambda *a, **k: None), \
             mock.patch.object(fc, "ensure_running", fake_ensure):
            fc.cmd_run("camp")
        return started

    def test_a_config_over_max_crashes_is_abandoned_and_the_next_runs(self):
        s = fc.init_state("camp")
        s["config_incidents"] = fc.DEFAULTS["max_crashes"]
        started = self._run(s, ["/a.cfg", "/b.cfg"])
        self.assertEqual(started, ["/b.cfg"])
        self.assertEqual([a["config"] for a in s["abandoned"]], ["/a.cfg"])

    def test_one_abandoned_item_among_others_ends_done(self):
        s = fc.init_state("camp")
        s["abandoned"] = [{"config": "/a.cfg", "reason": "x", "at": None}]
        s["items"] = {"a-1": {"config": "/a.cfg", "status": "abandoned", "reason": "max_crashes"},
                      "b-1": {"config": "/b.cfg", "status": "done", "reason": "max_hours"}}
        s["item_order"] = ["a-1", "b-1"]
        self.assertEqual(self._run(s, ["/a.cfg", "/b.cfg"]), [])
        self.assertEqual(s["status"], "done")   # a sample outcome, not a failure

    def test_every_item_abandoned_halts_as_max_crashes(self):
        s = fc.init_state("camp")
        s["abandoned"] = [{"config": "/a.cfg", "reason": "x", "at": None}]
        self.assertEqual(self._run(s, ["/a.cfg"]), [])
        self.assertEqual(s["status"], "halted")
        self.assertEqual(s["halt_reason"], "every item reached max_crashes")
        self.assertEqual(fc.halt_kind(s["halt_reason"]), "max_crashes")
        s["activity"] = "halted"
        self.assertEqual(fc.activity_word(s), "HALTED/MAX_CRASHES")

    def test_startup_failures_are_collected_and_halt_at_the_limit(self):
        log = self.dir / "run-20261009-093353.log"
        log.write_text("2026/10/09 09:33:55 serving rpc on tcp://49209\n"
                       "2026/10/09 09:33:55 [FATAL] failed to serve HTTP: listen tcp "
                       "127.0.0.1:56741: bind: address already in use\n")
        s = fc.init_state("camp")
        d = dict(fc.DEFAULTS, name="camp",
                 items=[{"config": "/a.cfg", "max_hours": 1}])
        dead = {"found": True, "pid_alive": False, "run_log": str(log),
                "run_started_epoch": 100.0, "last_activity_epoch": 102.0,
                "boot_epoch": 1}
        collected, retries = [], []

        def fake_ensure(st, cfg, dd=None):
            st.update({"session_id": "a", "current_config": cfg,
                       "run_prep_started": 99.0})

        with mock.patch.object(fc, "STATE_DIR", self.dir), \
             mock.patch.object(fc, "load_def", lambda n: d), \
             mock.patch.object(fc, "load_state", lambda n: s), \
             mock.patch.object(fc, "save_state", lambda st: None), \
             mock.patch.object(fc, "brake_held", lambda n: None), \
             mock.patch.object(fc, "free_gb", lambda: 1e9), \
             mock.patch.object(fc, "reconcile_boot", lambda *a: None), \
             mock.patch.object(fc, "reconcile_gap", lambda *a, **k: None), \
             mock.patch.object(fc, "results_commit", lambda *a, **k: None), \
             mock.patch.object(fc, "ensure_running", fake_ensure), \
             mock.patch.object(fc, "supervise", lambda *a: "startup"), \
             mock.patch.object(fc, "inspect", lambda sid: dead), \
             mock.patch.object(fc, "wait_for_stop",
                               lambda st, dd, sec: retries.append(sec)), \
             mock.patch.object(fc, "session",
                               lambda *a, **k: collected.append(a) or (0, "")):
            fc.cmd_run("camp")
        self.assertEqual(s["status"], "halted")
        self.assertIn("address already in use", s["halt_reason"])
        self.assertEqual(collected.count(("collect", "a", "startup")), 3)
        self.assertEqual(len(retries), 2)               # no pause after the last
        self.assertEqual(s["hangs"], 0)                 # not filed as hangs
        self.assertEqual([i["kind"] for i in s["incidents"]], ["startup"] * 3)

    def _crash(self, s, execs, run_s=123.0, fuzz_s=3.0):
        t = 10_000.0
        fc.record_incident(s, dict(fc.DEFAULTS), "crash",
                           {"run_started_epoch": t, "fuzz_started_epoch": t + run_s - fuzz_s,
                            "last_activity_epoch": t + run_s, "boot_epoch": 1,
                            "exec_total": execs, "panic_evidence": True})

    def test_a_crash_after_a_long_compile_is_still_fast(self):
        """Two minutes of grammar compile, then a panic before anything ran:
        measured over the manager's life it read 123s and was never fast."""
        s = fc.init_state("camp")
        s["current_config"] = "/x.cfg"
        self._crash(s, execs=12)
        self.assertEqual(s["consec_fast_crashes"], 1)
        self.assertEqual(s["incidents"][-1]["fuzzed_seconds"], 3)
        self.assertEqual(s["config_incidents"], 1)

    def test_a_quick_real_bug_is_not_a_crash_loop(self):
        """The time window's false positive: a healthy run that panics 15s into
        fuzzing has executed hundreds of programs. It is a bug, not a loop."""
        s = fc.init_state("camp")
        s["current_config"] = "/x.cfg"
        s["consec_fast_crashes"] = 14
        self._crash(s, execs=650, run_s=45.0, fuzz_s=15.0)
        self.assertEqual(s["consec_fast_crashes"], 0)

    def test_no_stat_line_at_all_counts_as_fast(self):
        s = fc.init_state("camp")
        s["current_config"] = "/x.cfg"
        self._crash(s, execs=None)
        self.assertEqual(s["consec_fast_crashes"], 1)

    def test_fifteen_fast_crashes_halt(self):
        s = fc.init_state("camp")
        s["current_config"] = "/x.cfg"
        for _ in range(fc.DEFAULTS["crashloop_limit"]):
            self._crash(s, execs=0)
        with mock.patch.object(fc, "free_gb", lambda: 1e9):
            self.assertIn("crash loop", fc.breaker(s, dict(fc.DEFAULTS)))


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

        self._run = mock.patch.object(fc, "RUN_DIR", self.state)
        self._run.start()

    def tearDown(self):
        self._run.stop()
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
                                   {"config": str(cfg), "max_hours": 1}],
                                   name=n)), \
             mock.patch.object(fc, "inspect", lambda sid: {"found": False}), \
             mock.patch.object(fc, "free_gb", lambda: 100.0):
            lines, sample = fc.status_lines("camp")
        self.assertIn("  name        : camp", lines)
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
                                   {"config": str(cfg), "max_hours": 1}],
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


class NewPlanTest(unittest.TestCase):
    """`new` writes a plan that references hand-written configs; `plan check`
    renders it; `install` freezes it. Device flags for triage are gone: the
    effective config carries them."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        # resolved: on macOS the temp dir is a /var -> /private/var symlink, and
        # `new` stores resolved config paths
        self.dir = Path(self._tmp.name).resolve()
        (self.dir / "campaigns").mkdir()
        self._patches = [mock.patch.object(fc, "CAMPAIGN_DIR", self.dir / "campaigns"),
                         mock.patch.object(fc, "STATE_DIR", self.dir / "state"),
                         mock.patch.object(fc, "RUN_DIR", self.dir / "run"),
                         mock.patch.object(fc, "BOX_PATH", self.dir / "box.json"),
                         mock.patch.object(fc, "log", lambda m: None)]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()
        self._tmp.cleanup()

    def _cfg(self, stem, **extra):
        body = dict({"enable_syscalls": ["syz_IOServiceOpen$X_C", "syz_IOConnectCallMethod$X_C_0"],
                     "kext_coverage": {"kext_id": 2}, "executor_name": "x"}, **extra)
        p = self.dir / ("%s.cfg" % stem)
        p.write_text(json.dumps(body))
        return str(p)

    def test_new_creates_the_campaign_with_repeats_and_no_triage_block(self):
        cfg = self._cfg("AppleX_gram")
        with contextlib.redirect_stdout(io.StringIO()):
            fc.cmd_new("c", [cfg], 1.5, repeat=2, max_crashes=7)
        cdir = self.dir / "campaigns" / "c"
        plan = json.loads((cdir / "campaign.json").read_text())
        self.assertEqual([it["config"] for it in plan["items"]], [cfg, cfg])
        self.assertEqual(json.loads((cdir / "state.json").read_text())["status"], "new")
        self.assertTrue((cdir / "README.md").exists())
        self.assertEqual(fc.load_def("c")["layout"], "plan")
        self.assertEqual([it["id"] for it in fc.load_def("c")["items"]], ["AppleX_gram-1", "AppleX_gram-2"])
        self.assertEqual(plan["defaults"]["max_hours"], 1.5)
        self.assertEqual(plan["limits"], {"max_crashes": 7})     # only what was given
        self.assertNotIn("triage", plan)
        self.assertFalse(plan["defaults"]["reuse_known_culprits"])
        # ids are written out, so inserting an entry later cannot move them
        self.assertEqual([it["id"] for it in plan["items"]], ["AppleX_gram-1", "AppleX_gram-2"])

    def test_new_refuses_a_config_that_would_fuzz_every_syscall(self):
        empty = self._cfg("AppleX_empty", enable_syscalls=[])
        with contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit):
            fc.cmd_new("c", [empty], 1.0)
        self.assertIn("every syscall", err.getvalue())
        self.assertFalse((self.dir / "campaigns" / "c").exists())     # nothing written
        with contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit):
            fc.cmd_new("c", [str(fc.BOX_PATH)], 1.0)
        self.assertIn("box.json", err.getvalue())

    def test_load_def_is_the_campaign_itself_with_the_runner_settings_resolved(self):
        cfg = self._cfg("AppleX_gram")
        with contextlib.redirect_stdout(io.StringIO()):
            fc.cmd_new("c", [cfg], 1.5, clock="wall", max_crashes=7,
                       reuse_known_culprits=True)
        d = fc.load_def("c")
        # one shape: what campaign.json says stays where it says it
        self.assertEqual(d["clock"], "wall")
        self.assertEqual(fc.budget_clock(d), "wall")
        self.assertEqual(d["items"][0]["max_hours"], 1.5)
        self.assertNotIn("budget_seconds", d["items"][0])
        self.assertEqual(fc.budget_seconds(d["items"][0]), 5400.0)
        self.assertIs(d["defaults"]["reuse_known_culprits"], True)
        self.assertNotIn("budget_clock", d)
        # the runner's settings: DEFAULTS, overridden by the campaign's limits
        self.assertEqual(d["max_crashes"], 7)
        self.assertEqual(d["poll_seconds"], fc.DEFAULTS["poll_seconds"])

    def test_a_commented_config_is_readable_and_keeps_its_triage_flags(self):
        # syz-manager allows whole-line # comments; read_json does not, and
        # doctor called every commented config "unreadable".
        p = self.dir / "Fake_c.cfg"
        p.write_text('# why this config exists\n{"enable_syscalls": ["getpid"],\n'
                     '# the kext\n "kext_coverage": {"kext_id": 4}, "executor_name": "x"}\n')
        self.assertIsNone(fc.read_json(p))
        self.assertEqual(fc.read_cfg(p)["enable_syscalls"], ["getpid"])
        self.assertEqual(fc.config_triage_flags(str(p)), {"kext_id": 4, "executor_name": "x"})
        self.assertIsNone(fc.read_cfg(self.dir / "missing.cfg"))
        (self.dir / "bad.cfg").write_text("{not json")
        self.assertIsNone(fc.read_cfg(self.dir / "bad.cfg"))

    def test_an_edit_is_picked_up_and_a_bad_one_keeps_the_last_good(self):
        cfg = self._cfg("AppleX_gram")
        with contextlib.redirect_stdout(io.StringIO()):
            fc.cmd_new("c", [cfg], 1.0, repeat=2)
        path = self.dir / "campaigns" / "c" / "campaign.json"
        d = fc.load_def("c")
        s = {"items": {"AppleX_gram-1": {"status": "running"},
                       "AppleX_gram-2": {"status": "pending"}}}
        camp = json.loads(path.read_text())
        # an appended item shows up
        camp["items"].append({"config": cfg, "id": "AppleX_gram-3", "max_hours": 2})
        path.write_text(json.dumps(camp))
        d = fc.reload_def("c", d, s)
        self.assertEqual([it["id"] for it in d["items"]],
                         ["AppleX_gram-1", "AppleX_gram-2", "AppleX_gram-3"])
        # a half-saved edit keeps the last good definition, and says so once
        path.write_text('{"name": "c", "items": [')
        self.assertIs(fc.reload_def("c", d, s), d)
        self.assertIn("bad JSON", s["def_error"])
        # dropping the running item is refused the same way
        camp["items"] = camp["items"][1:]
        path.write_text(json.dumps(camp))
        self.assertIs(fc.reload_def("c", d, s), d)
        self.assertIn("drops the running item AppleX_gram-1", s["def_error"])
        # fixed: loads again, and the error is cleared
        camp["items"].insert(0, {"config": cfg, "id": "AppleX_gram-1"})
        path.write_text(json.dumps(camp))
        self.assertEqual(len(fc.reload_def("c", d, s)["items"]), 3)
        self.assertNotIn("def_error", s)

    def test_a_campaign_from_before_the_rename_is_read_from_plan_json(self):
        cfg = self._cfg("AppleX_gram")
        with contextlib.redirect_stdout(io.StringIO()):
            fc.cmd_new("c", [cfg], 2.0)
        cdir = self.dir / "campaigns" / "c"
        (cdir / "campaign.json").rename(cdir / "plan.json")
        self.assertEqual(fc.campaign_path("c"), cdir / "plan.json")
        self.assertEqual(fc.load_def("c")["layout"], "plan")
        self.assertEqual(fc.load_def("c")["items"][0]["max_hours"], 2.0)
        # both present (should not happen): campaign.json is the one read
        (cdir / "campaign.json").write_text((cdir / "plan.json").read_text())
        self.assertEqual(fc.campaign_path("c"), cdir / "campaign.json")

    def test_a_legacy_definition_is_read_in_the_campaign_shape(self):
        cfg = self._cfg("AppleX_gram")
        cfg2 = self._cfg("AppleX_sel")
        (self.dir / "campaigns" / "old.json").write_text(json.dumps(
            {"configs": [cfg, {"config": cfg2, "budget_hours": 3}], "budget_hours": 2,
             "budget_clock": "fuzz", "max_crashes": 5, "poll_seconds": 60,
             "triage": {"kext_id": 2}, "loop": True}))
        d = fc.load_def("old")
        self.assertEqual(d["layout"], "legacy")
        self.assertEqual(d["clock"], "fuzz")
        self.assertEqual([it["max_hours"] for it in d["items"]], [2, 3])
        self.assertEqual([it["id"] for it in d["items"]], ["AppleX_gram-1", "AppleX_sel-1"])
        # its runner overrides are limits now, and resolved like any campaign's
        self.assertEqual(d["limits"]["poll_seconds"], 60)
        self.assertEqual((d["max_crashes"], d["poll_seconds"]), (5, 60))
        self.assertEqual(d["triage"], {"kext_id": 2})
        self.assertNotIn("loop", d["limits"])

    def test_plan_check_shows_drift_and_strict_fails_on_it(self):
        (self.dir / "box.json").write_text(json.dumps({"procs": 1, "target": "darwin/arm64"}))
        cfg = self._cfg("AppleX_gram", procs=2)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            fc.cmd_new("c", [cfg], 1.0)
        self.assertIn("procs", buf.getvalue())
        self.assertIn("AppleX_gram-1", buf.getvalue())
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
            fc.cmd_plan_check("c", strict=True)

    def test_a_campaign_is_not_created_twice_and_copy_copies_another(self):
        cfg = self._cfg("AppleX_gram")
        with contextlib.redirect_stdout(io.StringIO()):
            fc.cmd_new("c", [cfg], 12.0, description="first run", watch_window=False)
            with self.assertRaises(SystemExit):
                fc.cmd_new("c", [cfg], 1.0)                 # exists: refused
            fc.cmd_new("c2", [], copy="c", repeat=1)         # same experiment, new name
            # a flag given alongside --copy wins, even one equal to its default
            fc.cmd_new("c3", [], copy="c", max_hours=fc.planlib.DEFAULTS["max_hours"])
        plan2 = json.loads((self.dir / "campaigns" / "c2" / "campaign.json").read_text())
        self.assertEqual([it["config"] for it in plan2["items"]], [cfg])
        self.assertEqual(plan2["name"], "c2")
        self.assertEqual(plan2["description"], "copy of c: first run")
        self.assertEqual(plan2["defaults"]["max_hours"], 12.0)    # --copy keeps the original's
        self.assertIs(plan2["watch_window"], False)              # ... all of it
        plan3 = json.loads((self.dir / "campaigns" / "c3" / "campaign.json").read_text())
        self.assertEqual(plan3["defaults"]["max_hours"], fc.planlib.DEFAULTS["max_hours"])
        self.assertIs(plan3["watch_window"], False)
        # legacy campaigns are read-only: install refuses, status still reads them
        (self.dir / "campaigns" / "old.json").write_text(json.dumps({"configs": [cfg]}))
        with self.assertRaises(SystemExit):
            fc.require_campaign("old")
        self.assertEqual(fc.load_def("old")["layout"], "legacy")

    def test_the_readme_carries_the_description_and_keeps_your_notes(self):
        cfg = self._cfg("AppleX_gram")
        with contextlib.redirect_stdout(io.StringIO()):
            fc.cmd_new("c", [cfg], 1.0, description="Does grammar X beat Y on FDE?")
        self.assertEqual(json.loads((self.dir / "campaigns" / "c" / "campaign.json").read_text())["description"],
                         "Does grammar X beat Y on FDE?")
        readme = self.dir / "campaigns" / "c" / "README.md"
        text = readme.read_text()
        self.assertTrue(text.startswith("# c\n\nDoes grammar X beat Y on FDE?\n"))
        self.assertIn("| AppleX_gram-1 |", text)
        self.assertIn("## Results", text)
        # the operator writes; a regeneration touches only the generated block
        readme.write_text(text.replace("## Results\n", "## Results\n\n3 bugs, see BUG-0007.\n")
                          .replace("## Notes\n", "## Notes\n\nbox rebooted twice by hand.\n"))
        with contextlib.redirect_stdout(io.StringIO()):
            fc.cmd_readme("c")
        text2 = readme.read_text()
        self.assertIn("3 bugs, see BUG-0007.", text2)
        self.assertIn("box rebooted twice by hand.", text2)
        self.assertEqual(text2.count(fc.README_BEGIN), 1)
        self.assertEqual(text2.count(fc.README_END), 1)

    def test_the_readme_gets_the_outcome_when_items_end_and_when_the_campaign_does(self):
        cfg = self._cfg("AppleX_gram")
        with contextlib.redirect_stdout(io.StringIO()):
            fc.cmd_new("c", [cfg, cfg], 1.0)
        s = fc.load_state("c")
        fc.ensure_items(s, fc.load_def("c"))
        s["items"]["AppleX_gram-1"]["status"] = "running"
        s.update(active_seconds=3600.0, crashes=2, exec_by_config={"c.AppleX_gram-1": 123456},
                 bb_covered={"c.AppleX_gram-1": 77},
                 incidents=[{"item": "AppleX_gram-1", "kind": "crash", "bug_ids": ["BUG-0007"]},
                            {"item": "AppleX_gram-1", "kind": "crash", "bug_ids": ["BUG-0007"]}])
        with mock.patch.object(fc, "log", lambda m: None):
            fc.end_item(s, "AppleX_gram-1", "max_hours")        # refreshes the README
        rec = s["items"]["AppleX_gram-1"]
        self.assertEqual((rec["clocks"]["active_seconds"], rec["crashes"], rec["bug_ids"]),
                         (3600, 2, ["BUG-0007"]))
        text = (self.dir / "campaigns" / "c" / "README.md").read_text()
        self.assertIn("**Outcome** (running", text)
        self.assertIn("| AppleX_gram-1 | done (max_hours) | %s | 123,456 | 77 | 2 | 0 | BUG-0007 |"
                      % fc.fmt_hms(3600), text)
        self.assertNotIn("| AppleX_gram-2 |", text.split("**Outcome**")[1])   # pending: not yet a row
        s["status"], s["halt_reason"] = "halted", "halted by user"
        fc.save_state(s)                                          # terminal: refreshed again
        text = (self.dir / "campaigns" / "c" / "README.md").read_text()
        self.assertIn("**Outcome** (halted", text)
        self.assertIn("Halt reason: halted by user.", text)

    def test_the_campaign_keeps_its_own_bug_log_and_the_readme_lists_its_bugs(self):
        cfg = self._cfg("AppleX_gram")
        with contextlib.redirect_stdout(io.StringIO()):
            fc.cmd_new("c", [cfg], 1.0)
        bugs = self.dir / "bugs"
        bugs.mkdir()
        (bugs / "registry.json").write_text(json.dumps({"version": 1, "bugs": {
            "k1": {"id": "BUG-0007", "bug_key": "k1", "crashes": [
                {"report": "a.panic", "first_seen": "2026-10-01T00:00:00+00:00", "signature": "S1",
                 "campaign": "earlier", "item": None, "origin": "fuzz"},
                {"report": "b.panic", "first_seen": "2026-10-23T00:00:00+00:00", "signature": "S1",
                 "campaign": "c", "item": "AppleX_gram-1", "origin": "fuzz"}]},
            "k2": {"id": "BUG-0009", "bug_key": "k2", "crashes": [
                {"report": "d.panic", "first_seen": "2026-10-23T01:00:00+00:00", "signature": "S2",
                 "campaign": "c", "item": "AppleX_gram-1", "origin": "fuzz"}]}}}))
        s = fc.load_state("c")
        s["incidents"] = [{"kind": "crash", "item": "AppleX_gram-1", "signature": "S1",
                           "bug_ids": ["BUG-0007"], "crashing_kext": "AppleX", "decision": "suspect",
                           "title": "panic: x"}]
        with mock.patch.object(fc, "BUGS_DIR", bugs):
            fc.record_bug_line(s)
            found = fc.campaign_bugs("c")
            fc.write_readme("c", s=dict(s, items={"AppleX_gram-1": {"status": "running"}},
                                         item_order=["AppleX_gram-1"]))
        line = (self.dir / "campaigns" / "c" / "bugs.log").read_text()
        self.assertIn("AppleX_gram-1", line)
        self.assertIn("sig S1  BUG-0007  (first seen in earlier)  in AppleX  -> suspect  panic: x", line)
        self.assertEqual(found["BUG-0007"]["first_here"], False)
        self.assertEqual(found["BUG-0009"]["first_here"], True)
        text = (self.dir / "campaigns" / "c" / "README.md").read_text()
        self.assertIn("`BUG-0007` -- 1 sighting(s) in AppleX_gram-1; first seen in earlier", text)
        self.assertIn("`BUG-0009` -- 1 sighting(s) in AppleX_gram-1; first seen here", text)


class PlanLayoutTest(unittest.TestCase):
    """A plan-layout campaign: the manager runs on a rendered effective config
    under campaigns/<name>/<config-id>/<item-id>/, and everything an item
    produces lives there."""

    BOX = {"target": "darwin/arm64", "syzkaller": "/tree", "http": "127.0.0.1:1", "procs": 1,
           "type": "none", "sandbox": "none", "reproduce": False,
           "kext_coverage": {"kcov_device": "/dev/pishi"}}

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "config").mkdir()
        (self.root / "campaigns").mkdir()
        (self.root / "config" / "box.json").write_text(json.dumps(self.BOX))
        self.cfg = self.root / "config" / "AppleSMC_gram.cfg"
        self.cfg.write_text("# the authored exclusion must survive rendering\n" + json.dumps({
            "workdir": "/should/be/ignored", "procs": 1,
            "kext_coverage": {"kext_id": 2, "cover_log": "x.log"},
            "enable_syscalls": ["syz_IOServiceOpen$AppleSMC_C", "syz_IOConnectCallMethod$C_0",
                                "syz_IOConnectCallMethod$C_1"],
            "disable_syscalls": ["syz_IOConnectCallMethod$C_1"], "executor_name": "smc"}))
        self._patches = [mock.patch.object(fc, "REPO_ROOT", self.root),
                         mock.patch.object(fc, "CAMPAIGN_DIR", self.root / "campaigns"),
                         mock.patch.object(fc, "STATE_DIR", self.root / "state"),
                         mock.patch.object(fc, "RUN_DIR", self.root / "run"),
                         mock.patch.object(fc, "BOX_PATH", self.root / "config" / "box.json"),
                         mock.patch.object(fc, "log", lambda m: None)]
        for p in self._patches:
            p.start()
        (self.root / "state").mkdir()

    def tearDown(self):
        for p in self._patches:
            p.stop()
        self._tmp.cleanup()

    def _def(self):
        return dict(fc.DEFAULTS, layout="plan", name="camp",
                    items=[{"id": "AppleSMC_gram-1", "config": str(self.cfg), "max_hours": 1},
                           {"id": "AppleSMC_gram-2", "config": str(self.cfg), "max_hours": 1}])

    def _item(self, n=1):
        return {"id": "AppleSMC_gram-%d" % n, "config": str(self.cfg)}

    def test_the_manager_runs_on_the_rendered_effective_config(self):
        s = fc.init_state("camp")
        started = []

        def fake_ensure(st, cfg, dd=None):
            started.append(cfg)
            st["status"] = "halted"
            raise RuntimeError("stop here")
        with mock.patch.object(fc, "load_def", lambda n: self._def()), \
             mock.patch.object(fc, "load_state", lambda n: s), \
             mock.patch.object(fc, "save_state", lambda st: None), \
             mock.patch.object(fc, "brake_held", lambda n: None), \
             mock.patch.object(fc, "breaker", lambda *a: None), \
             mock.patch.object(fc, "reconcile_boot", lambda *a: None), \
             mock.patch.object(fc, "reconcile_gap", lambda *a, **k: None), \
             mock.patch.object(fc, "results_commit", lambda *a, **k: None), \
             mock.patch.object(fc, "ensure_running", fake_ensure):
            fc.cmd_run("camp")
        idir = self.root / "campaigns" / "camp" / "AppleSMC_gram" / "AppleSMC_gram-1"
        self.assertEqual(started, [str(idir / "camp.AppleSMC_gram-1.cfg")])
        eff = json.loads((idir / "camp.AppleSMC_gram-1.cfg").read_text())
        self.assertEqual(eff["workdir"], str(idir / "workdir"))          # runtime: rendered per item
        self.assertEqual(eff["kext_coverage"], {"kcov_device": "/dev/pishi", "kext_id": 2,
                                                "cover_log": "cover.log"})
        self.assertEqual(eff["procs"], 1)                                 # box key
        self.assertEqual(eff["disable_syscalls"], ["syz_IOConnectCallMethod$C_1"])   # authored kept
        meta = json.loads((idir / "item.json").read_text())
        self.assertEqual((meta["campaign"], meta["item"], meta["config"]),
                         ("camp", "AppleSMC_gram-1", str(self.cfg)))
        self.assertEqual(s["current_item"], "AppleSMC_gram-1")
        # the per-item keys everything else hangs off
        s["current_config"] = started[0]
        self.assertEqual(fc.qstate_path(started[0]), idir / "quarantine.json")
        self.assertEqual(fc.authored_config(s), str(self.cfg))
        self.assertEqual(fc.target_of(s)["kext"], "AppleSMC")        # from the config's name
        self.assertEqual(fc.evidence_root(s), idir)
        self.assertEqual(fc.config_id(started[0]), "camp.AppleSMC_gram-1")   # the session id

    def test_the_quarantine_is_unioned_into_the_authored_exclusions(self):
        eff, _ = fc.render_item("camp", self._item())
        qs = fc.qm.init_state()
        fc.qm._add_hard(qs, ["syz_IOConnectCallMethod$C_0"])
        self.assertTrue(fc.apply_disabled(eff, qs))
        self.assertEqual(json.loads(Path(eff).read_text())["disable_syscalls"],
                         ["syz_IOConnectCallMethod$C_0", "syz_IOConnectCallMethod$C_1"])
        self.assertFalse(fc.apply_disabled(eff, qs))                  # nothing changed

    def test_a_known_culprit_is_benched_at_first_sighting_when_opted_in(self):
        eff, _ = fc.render_item("camp", self._item())
        s = fc.init_state("camp")
        s.update(current_config=str(eff), current_item="AppleSMC_gram-1",
                 incidents=[{"kind": "crash", "config": str(eff)}])
        d = dict(self._def(), defaults={"reuse_known_culprits": True})
        with mock.patch.object(fc, "route_bug_registry", lambda *a, **k: ["BUG-0001"]), \
             mock.patch.object(fc, "latest_panic_signature", lambda st: "S1"), \
             mock.patch.object(fc, "known_culprit", lambda sig: {"bug_id": "BUG-0001", "job": "j",
                                                                 "selectors": ["syz_IOConnectCallMethod$C_0"]}):
            self.assertFalse(fc.handle_crash(s, d, {"panics": ["/p.panic"]}))
        self.assertEqual(s["incidents"][-1]["decision"], "benched (known BUG-0001)")
        self.assertIn("syz_IOConnectCallMethod$C_0", json.loads(Path(eff).read_text())["disable_syscalls"])
        q = json.loads((Path(eff).parent / "quarantine.json").read_text())
        self.assertEqual(q["catalog"]["S1"]["known_from"], "BUG-0001")
        # off by default: the same crash goes through the SUSPECT gate instead
        s2 = fc.init_state("camp")
        s2.update(current_config=str(eff), current_item="AppleSMC_gram-1",
                  incidents=[{"kind": "crash", "config": str(eff)}])
        with mock.patch.object(fc, "route_bug_registry", lambda *a, **k: []), \
             mock.patch.object(fc, "latest_panic_signature", lambda st: "S2"), \
             mock.patch.object(fc, "known_culprit", lambda sig: {"bug_id": "B", "selectors": ["x"]}):
            fc.handle_crash(s2, self._def(), {"panics": []})
        self.assertEqual(s2["incidents"][-1]["decision"], "suspect")

    def test_triage_jobs_live_under_the_item_and_are_addressed_by_path(self):
        eff, _ = fc.render_item("camp", self._item())
        s = fc.init_state("camp")
        s.update(current_config=str(eff), current_item="AppleSMC_gram-1", session_id="camp.AppleSMC_gram-1")
        ring = Path(eff).parent / "workdir" / "ring_buffer"
        ring.mkdir(parents=True)
        calls = []
        with mock.patch.object(fc, "triage", lambda *a, **k: calls.append(a) or (0, "")):
            self.assertTrue(fc.begin_triage(s, self._def(), "S1", ring=ring))
        args = calls[0]
        jdir = Path(eff).parent / "triage" / "t1"
        self.assertEqual(args[:2], ("new", "t1"))
        self.assertEqual(args[args.index("--dir") + 1], str(jdir))
        self.assertEqual(args[args.index("--config") + 1], "AppleSMC_gram")
        self.assertEqual(args[args.index("--fuzzed-kext") + 1], "AppleSMC")
        self.assertEqual(args[args.index("--kcov-device") + 1], "/dev/pishi")   # from box.json
        self.assertEqual(s["triage_job"], str(jdir))
        jdir.mkdir(parents=True)
        (jdir / "job.json").write_text(json.dumps({"stage": "MERGE"}))
        self.assertEqual(fc.triage_state(s["triage_job"])["stage"], "MERGE")
        self.assertEqual(fc.job_label(s["triage_job"]), "t1")

    def test_results_are_committed_per_item(self):
        eff, _ = fc.render_item("camp", self._item())
        s = fc.init_state("camp")
        s["current_config"] = str(eff)
        d = dict(self._def(), results_repo="/r")
        cmds = []
        with mock.patch.object(fc.subprocess, "run", lambda cmd, **k: cmds.append(cmd) or mock.Mock(returncode=0)):
            fc.results_commit(s, d, "start")
        cmd = cmds[0]
        self.assertEqual(cmd[cmd.index("--unit") + 1], "camp/AppleSMC_gram/AppleSMC_gram-1")
        self.assertEqual(cmd[cmd.index("--kext") + 1], "AppleSMC")
        self.assertEqual(cmd[cmd.index("--tag-prefix") + 1], "camp/AppleSMC_gram-1")

    def test_a_legacy_campaign_does_not_run(self):
        s = fc.init_state("camp")
        started = []
        with mock.patch.object(fc, "load_def", lambda n: dict(fc.DEFAULTS, layout="legacy", name="camp",
                                                                 items=[{"config": str(self.cfg), "max_hours": 1 / 3600}])), \
             mock.patch.object(fc, "load_state", lambda n: s), \
             mock.patch.object(fc, "ensure_running", lambda *a, **k: started.append(a)):
            fc.cmd_run("camp")
        self.assertEqual(started, [])


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
        d = {"clock": "real"}
        self.assertAlmostEqual(fc.budget_spent(s, d), 5400, delta=5)
        # the other clocks see only the minute that was actually spent
        self.assertEqual(fc.budget_spent(s, {"clock": "fuzz"}), 60.0)
        self.assertEqual(fc.budget_spent(s, {"clock": "wall"}), 60.0)

    def test_missing_stamp_is_zero_not_a_crash(self):
        self.assertEqual(fc.budget_spent(self._state(None), {"clock": "real"}), 0.0)
        self.assertEqual(fc.budget_spent(self._state("garbage"), {"clock": "real"}), 0.0)

    def test_advancing_config_clears_the_origin(self):
        # Each config gets its own window; roll_budget_clocks drops the stamp so
        # the next config stamps a fresh one.
        s = {"config_started_at": fc.now_iso(), "active_seconds": 10.0}
        fc.roll_budget_clocks(s)
        self.assertIsNone(s["config_started_at"])

    def test_real_is_a_valid_clock_choice(self):
        self.assertIn("real", fc.BUDGET_CLOCKS)


class ResultsCommitTest(unittest.TestCase):
    """fuzz-campaign hands results to fuzz-results.py, never blocking on it."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.state_dir = mock.patch.object(fc, "STATE_DIR", Path(self._tmp.name))
        self.state_dir.start()
        self.s = {"name": "C", "current_config": "/cfg/K_x.cfg", "active_seconds": 10.0}
        self.d = {"results_repo": "/repo", "items": [{"config": "/cfg/K_x.cfg"}]}

    def tearDown(self):
        self.state_dir.stop()
        self._tmp.cleanup()

    def test_off_without_results_repo(self):
        with mock.patch.object(fc.subprocess, "run") as run, \
                mock.patch.object(fc.subprocess, "Popen") as popen:
            fc.results_commit(self.s, {"items": []}, "start")
            fc.results_commit(self.s, None, "start")
        run.assert_not_called()
        popen.assert_not_called()

    def test_restart_is_synchronous_and_skips_freq(self):
        with mock.patch.object(fc.subprocess, "run") as run:
            run.return_value.returncode = 0
            fc.results_commit(self.s, self.d, "restart")
        cmd = run.call_args[0][0]
        self.assertIn("--no-freq", cmd)
        self.assertEqual(cmd[cmd.index("--event") + 1], "restart")
        self.assertEqual(cmd[cmd.index("--tag-prefix") + 1], "C")
        self.assertEqual(cmd[cmd.index("--push") + 1], "detach")

    def test_poll_is_detached(self):
        with mock.patch.object(fc.subprocess, "Popen") as popen:
            fc.results_commit(self.s, self.d, "corpus", detach=True)
        self.assertTrue(popen.call_args[1]["start_new_session"])

    def test_multi_config_tags_are_per_config(self):
        self.d["items"].append({"config": "/cfg/K_y.cfg"})
        with mock.patch.object(fc.subprocess, "run") as run:
            run.return_value.returncode = 0
            fc.results_commit(self.s, self.d, "end")
        cmd = run.call_args[0][0]
        self.assertEqual(cmd[cmd.index("--tag-prefix") + 1], "C/K_x")
        self.assertEqual(cmd[cmd.index("--push") + 1], "wait")


class ActivityTest(unittest.TestCase):
    """What the box is doing, as one word with a start time. It is the line you
    read between two panics, when there is no time to type a command -- so it
    must be first on screen, survive a reboot, and keep its start time across
    the relaunch that follows one."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.state_dir = self.dir / "state"
        self.state_dir.mkdir()
        self._p = mock.patch.object(fc, "STATE_DIR", self.state_dir)
        self._p.start()

    def tearDown(self):
        self._p.stop()
        self._tmp.cleanup()

    def _status(self, s, cfg, colour=False):
        with mock.patch.object(fc, "load_state", lambda n: s), \
             mock.patch.object(fc, "load_def",
                               lambda n: dict(fc.DEFAULTS, items=[
                                   {"config": str(cfg), "max_hours": 1}],
                                   name=n)), \
             mock.patch.object(fc, "inspect", lambda sid: {"found": False}), \
             mock.patch.object(fc, "free_gb", lambda: 100.0), \
             mock.patch.object(fc, "style", type(fc.style)(colour)):
            lines, _ = fc.status_lines("camp")
        return lines

    def test_unchanged_activity_keeps_its_start_time(self):
        s = fc.init_state("camp")
        self.assertTrue(fc.set_activity(s, "triaging", "advance 1/40"))
        t0 = s["activity_since"]
        self.assertFalse(fc.set_activity(s, "triaging", "advance 1/40"))
        self.assertEqual(s["activity_since"], t0)
        self.assertTrue(fc.set_activity(s, "triaging", "advance 2/40"))

    def test_halting_sets_the_activity_whichever_path_halted(self):
        """Eight places set status = "halted"; the save hook covers them all."""
        s = fc.init_state("camp")
        fc.set_activity(s, "fuzzing", "cfg")
        s["status"], s["halt_reason"] = "halted", "crash loop (15 crashes)"
        fc.save_state(s)
        self.assertEqual(s["activity"], "halted")
        self.assertEqual(s["activity_detail"], "crash loop (15 crashes)")
        on_disk = json.loads((self.state_dir / "camp.json").read_text())
        self.assertEqual(on_disk["activity"], "halted")

    def test_resume_says_it_is_waiting_for_the_driver(self):
        s = fc.init_state("camp")
        s["status"] = "halted"
        fc.save_state(s)
        with mock.patch.object(fc, "log", lambda m: None):
            fc._set_status("camp", "running")
        self.assertEqual(fc.load_state("camp")["activity"], "waiting")

    def test_status_puts_the_activity_second_with_its_duration(self):
        from datetime import datetime, timedelta, timezone
        cfg = write_cfg(self.dir, {"target": "darwin/arm64", "workdir": str(self.dir)})
        s = fc.init_state("camp")
        s.update(activity="triaging", activity_detail="bug S",
                 activity_since=(datetime.now(timezone.utc)
                                 - timedelta(minutes=12)).isoformat())
        lines = self._status(s, cfg)
        # The status IS the activity; there is no separate "running" line.
        self.assertEqual(lines[0], "campaign (item 1/1):")
        self.assertEqual(lines[1], "  name        : camp")
        self.assertTrue(lines[2].startswith("  status      : TRIAGING bug S"), lines[2])
        self.assertIn("for %s" % fc.fmt_hms(12 * 60 + 4), lines[2])
        self.assertNotIn("running", lines[2])
        # The old phase row is folded into it, and the block is grouped.
        self.assertFalse(any(ln.strip().startswith("phase") for ln in lines))
        self.assertIn("", lines)

    def test_status_colours_the_word_only_when_asked(self):
        cfg = write_cfg(self.dir, {"target": "darwin/arm64", "workdir": str(self.dir)})
        s = fc.init_state("camp")
        fc.set_activity(s, "fuzzing", "cfg")
        plain = self._status(s, cfg, colour=False)[2]
        coloured = self._status(s, cfg, colour=True)[2]
        self.assertNotIn("\033[", plain)
        self.assertIn("\033[32;1mFUZZING\033[0m cfg", coloured)   # green, word only

    def test_status_before_any_activity_falls_back_to_the_phase(self):
        cfg = write_cfg(self.dir, {"target": "darwin/arm64", "workdir": str(self.dir)})
        s = fc.init_state("camp")
        s.pop("activity")        # a state file written before activity existed
        head = self._status(s, cfg)[2]
        self.assertIn("NEW", head)                 # never started: says so, not "running"
        s["status"], s["phase"] = "running", "fuzzing"   # a state file from before activity existed
        head = self._status(s, cfg)[2]
        self.assertIn("running", head)
        self.assertIn("phase fuzzing", head)

    def test_a_campaign_is_new_until_the_driver_first_runs_it(self):
        s = fc.init_state("camp")
        self.assertEqual((s["status"], s["phase"]), ("new", None))
        d = dict(fc.DEFAULTS, name="camp", items=[{"config": "/a.cfg", "max_hours": 1 / 3600}])
        with mock.patch.object(fc, "STATE_DIR", self.state_dir), \
             mock.patch.object(fc, "RUN_DIR", self.state_dir), \
             mock.patch.object(fc, "load_def", lambda n: d), \
             mock.patch.object(fc, "load_state", lambda n: s), \
             mock.patch.object(fc, "save_state", lambda st: None), \
             mock.patch.object(fc, "brake_held", lambda n: None), \
             mock.patch.object(fc, "breaker", lambda *a: None), \
             mock.patch.object(fc, "reconcile_boot", lambda *a: None), \
             mock.patch.object(fc, "reconcile_gap", lambda *a, **k: None), \
             mock.patch.object(fc, "results_commit", lambda *a, **k: None), \
             mock.patch.object(fc, "log", lambda m: None), \
             mock.patch.object(fc, "ensure_running",
                               lambda st, cfg, dd=None: (_ for _ in ()).throw(RuntimeError("stop"))):
            fc.cmd_run("camp")
        self.assertEqual(s["phase"], "fuzzing")            # flipped at the first start

    def test_list_shows_the_activity(self):
        camps = self.dir / "camps"
        camps.mkdir()
        (camps / "camp.json").write_text("{}")
        s = fc.init_state("camp")
        fc.set_activity(s, "fuzzing", "cfg")
        buf = io.StringIO()
        with mock.patch.object(fc, "CAMPAIGN_DIR", camps), \
             mock.patch.object(fc, "load_def", lambda n: dict(fc.DEFAULTS, items=[], name=n)), \
             mock.patch.object(fc, "load_state", lambda n: s), \
             contextlib.redirect_stdout(buf):
            fc.cmd_list()
        self.assertIn("FUZZING %s" % fc.fmt_hms(0), buf.getvalue())
        self.assertNotIn("running", buf.getvalue())   # the activity IS the status column


class GlanceTest(unittest.TestCase):
    """The two things that reach your eyes without a command: the Terminal
    window the driver opens at each start, and the notifications."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self._p = mock.patch.object(fc, "STATE_DIR", self.dir / "state")
        self._p.start()
        self._r = mock.patch.object(fc, "RUN_DIR", self.dir / "state")
        self._r.start()

    def tearDown(self):
        self._r.stop()
        self._p.stop()
        self._tmp.cleanup()

    def test_watch_window_is_written_and_opened_once(self):
        calls = []
        with mock.patch.object(fc, "gui_available", lambda: True), \
             mock.patch.object(fc, "watch_running", lambda n: False), \
             mock.patch.object(fc.subprocess, "run", lambda *a, **k: calls.append(a[0])):
            self.assertTrue(fc.open_watch_window("camp", dict(fc.DEFAULTS)))
        cmd = self.dir / "state" / "camp.watch.command"
        self.assertTrue(os.access(cmd, os.X_OK))
        self.assertIn("fuzz-campaign.py status camp -w", cmd.read_text())
        self.assertEqual(calls[0][:3], ["/usr/bin/open", "-a", "Terminal"])
        # A relaunch with a watch already on screen does not stack a second one.
        with mock.patch.object(fc, "gui_available", lambda: True), \
             mock.patch.object(fc, "watch_running", lambda n: True), \
             mock.patch.object(fc.subprocess, "run", lambda *a, **k: calls.append(a[0])):
            self.assertFalse(fc.open_watch_window("camp", dict(fc.DEFAULTS)))
        self.assertEqual(len(calls), 1)
        # And a campaign authored --no-watch-window never opens one.
        with mock.patch.object(fc, "gui_available", lambda: True), \
             mock.patch.object(fc.subprocess, "run", lambda *a, **k: calls.append(a[0])):
            self.assertFalse(fc.open_watch_window("camp", dict(fc.DEFAULTS, watch_window=False)))
        self.assertEqual(len(calls), 1)

    def test_watch_running_matches_only_a_watch_of_this_campaign(self):
        def with_procs(procs, name):
            with mock.patch.object(fc, "running_processes", lambda p: procs):
                return fc.watch_running(name)
        watch = [(1, "/usr/bin/python3 scripts/fuzz-campaign.py status camp -w")]
        self.assertTrue(with_procs(watch, "camp"))
        self.assertFalse(with_procs(watch, "cam"))
        self.assertTrue(with_procs([(2, "python3 fuzz-campaign.py status camp --watch")], "camp"))
        self.assertFalse(with_procs([(3, "python3 fuzz-campaign.py status camp")], "camp"))
        self.assertFalse(with_procs([(4, "python3 fuzz-campaign.py status camp2 -w")], "camp"))

    def test_notify_is_an_osascript_and_never_raises(self):
        calls = []
        with mock.patch.object(fc, "gui_available", lambda: True), \
             mock.patch.object(fc.subprocess, "run", lambda *a, **k: calls.append(a[0])):
            self.assertTrue(fc.notify("camp", "FUZZING", 'cfg "x"'))
        self.assertEqual(calls[0][:2], ["/usr/bin/osascript", "-e"])
        self.assertIn('title "fuzz-campaign camp"', calls[0][2])
        self.assertIn('subtitle "FUZZING"', calls[0][2])
        self.assertIn('cfg \\"x\\"', calls[0][2])            # quotes escaped, not injected

        def boom(*a, **k):
            raise OSError("no session")
        with mock.patch.object(fc, "gui_available", lambda: True), \
             mock.patch.object(fc.subprocess, "run", boom), \
             mock.patch.object(fc, "log", lambda m: None):
            self.assertFalse(fc.notify("camp", "HALTED", "x"))

    def test_gui_side_effects_are_off_outside_macos_or_when_opted_out(self):
        env = {k: v for k, v in os.environ.items() if k != "FUZZ_NO_GUI"}
        with mock.patch.dict(os.environ, env, clear=True):
            with mock.patch.object(fc.sys, "platform", "darwin"):
                self.assertTrue(fc.gui_available())
            with mock.patch.object(fc.sys, "platform", "linux"):
                self.assertFalse(fc.gui_available())
        with mock.patch.dict(os.environ, {"FUZZ_NO_GUI": "1"}), \
             mock.patch.object(fc.sys, "platform", "darwin"):
            self.assertFalse(fc.gui_available())

    def test_only_the_transitions_worth_looking_up_for_notify(self):
        posted = []
        with mock.patch.object(fc, "notify", lambda *a: posted.append(a[1])), \
             mock.patch.object(fc, "save_state", lambda st: None):
            s = fc.init_state("camp")
            for what in ("booting", "preparing", "fuzzing", "collecting", "triaging"):
                fc.set_activity(s, what, "x")
        self.assertEqual(posted, ["FUZZING", "TRIAGING"])


class TriageAdvanceActivityTest(unittest.TestCase):
    def test_an_advance_names_the_bug_stage_and_count(self):
        s = fc.init_state("camp")
        s.update(phase="triaging", triage_job="camp_t1", triage_bug_sig="S")
        d = dict(fc.DEFAULTS, triage_max_boots=40)
        posted = []
        with mock.patch.object(fc, "triage", lambda *a, **k: (0, "")), \
             mock.patch.object(fc, "triage_state", lambda job: {"stage": "MINIMIZE_CALLS"}), \
             mock.patch.object(fc, "route_triage_panics", lambda *a: None), \
             mock.patch.object(fc, "queue_second_bugs", lambda *a: None), \
             mock.patch.object(fc, "wait_for_stop", lambda *a: None), \
             mock.patch.object(fc, "save_state", lambda st: None), \
             mock.patch.object(fc, "notify", lambda *a: posted.append(a[2])), \
             mock.patch.object(fc, "log", lambda m: None):
            fc.advance_triage(s, d)
        self.assertIn("bug S: advance 1/40, MINIMIZE_CALLS", posted)
        self.assertEqual(s["activity"], "triaging")
        self.assertEqual(s["activity_detail"], "bug S")      # per bug, not per advance


class HaltedHeadlineTest(unittest.TestCase):
    def test_a_halted_campaign_says_it_once(self):
        """Status, activity and halt reason used to be three lines saying the
        same thing; the halt reason is only repeated when it adds something."""
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            cfg = write_cfg(d, {"target": "darwin/arm64", "workdir": str(d)})
            s = fc.init_state("camp")
            s.update(status="halted", halt_reason="crash loop (15 crashes)")
            with mock.patch.object(fc, "STATE_DIR", d / "state"), \
                 mock.patch.object(fc, "load_state", lambda n: s), \
                 mock.patch.object(fc, "load_def", lambda n: dict(fc.DEFAULTS, items=[
                     {"config": str(cfg), "max_hours": 1}], name=n)), \
                 mock.patch.object(fc, "inspect", lambda sid: {"found": False}), \
                 mock.patch.object(fc, "free_gb", lambda: 100.0), \
                 mock.patch.object(fc, "style", type(fc.style)(False)):
                fc.save_state(s)                      # the hook sets activity=halted
                lines, _ = fc.status_lines("camp")
        self.assertTrue(lines[2].startswith(
            "  status      : HALTED/CRASH-LOOP crash loop (15 crashes)"), lines[2])
        self.assertEqual(sum("crash loop (15" in ln for ln in lines), 1)
        # one scope per block: campaign-wide counters live under the campaign header
        self.assertLess(lines.index("  crashes     : 0"), lines.index("  time breakdown:"))

    def test_the_kind_of_stop_is_read_from_the_reason(self):
        """Every halt path writes a reason in its own words; the kind is what
        you need first, so it is recognised from them rather than stored."""
        for reason, kind in [
                ("brake: /Users/Shared/fuzz-run/STOP -- boot loop 03:12", "brake"),
                ("halted by user", "user"), ("stopped by user", "user"),
                ("crash loop (15 crashes in a row before 50 programs executed)", "crash-loop"),
                ("low disk (12.0GB free < 20.0GB)", "disk"),
                ("syz-manager failed to start 5 times in a row (died before ...)", "startup"),
                ("triage stuck on S after 40 boots (job j)", "triage"),
                ("triage job j hung and the box must be rebooted, but ...", "triage"),
                ("every item reached max_crashes", "max_crashes"),
                ("could not start session for x.cfg", "error"), (None, "?")]:
            self.assertEqual(fc.halt_kind(reason), kind, reason)
        s = fc.init_state("camp")
        s.update(activity="halted", halt_reason="brake: STOP")
        self.assertEqual(fc.activity_word(s), "HALTED/BRAKE")


class StopPlanTest(unittest.TestCase):
    """What is left of the current config's budget, named by its clock."""

    def _d(self, clock="fuzz", hours=24):
        return dict(fc.DEFAULTS, clock=clock,
                    items=[{"config": "/c/cfg.cfg", "max_hours": hours}])

    def test_fuzz_clock_counts_fuzzing_left(self):
        s = fc.init_state("camp")
        s["active_seconds"] = 6 * 3600
        self.assertEqual(fc.stop_plan(s, self._d()),
                         "%s / %s (fuzzing)" % (fc.fmt_hms(18 * 3600), fc.fmt_hms(24 * 3600)))
        self.assertEqual(fc.stop_plan(s, self._d(clock="wall")),
                         "%s / %s (total)" % (fc.fmt_hms(18 * 3600), fc.fmt_hms(24 * 3600)))

    def test_real_clock_names_the_moment(self):
        from datetime import datetime, timedelta, timezone
        s = fc.init_state("camp")
        t0 = datetime.now(timezone.utc) - timedelta(hours=1)
        s["config_started_at"] = t0.isoformat()
        self.assertEqual(fc.stop_plan(s, self._d(clock="real", hours=2)),
                         "at %s (%s, real)" % (fc.timefmt.fmt_epoch(t0.timestamp() + 7200, short=True),
                                                fc.fmt_hms(7200)))

    def test_a_stopped_campaign_has_nothing_left(self):
        s = fc.init_state("camp")
        s["status"] = "halted"
        self.assertIsNone(fc.stop_plan(s, self._d()))

    def test_status_and_list_show_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            cfg = write_cfg(d, {"target": "darwin/arm64", "workdir": str(d)})
            camps = d / "camps"
            camps.mkdir()
            (camps / "camp.json").write_text("{}")
            s = fc.init_state("camp")
            s["current_config"] = str(cfg)
            fc.set_activity(s, "fuzzing", "cfg", save=False)
            buf = io.StringIO()
            with mock.patch.object(fc, "STATE_DIR", d / "state"), \
                 mock.patch.object(fc, "CAMPAIGN_DIR", camps), \
                 mock.patch.object(fc, "load_state", lambda n: s), \
                 mock.patch.object(fc, "load_def", lambda n: dict(
                     fc.DEFAULTS, clock="fuzz", items=[
                         {"config": str(cfg), "max_hours": 1}], name=n)), \
                 mock.patch.object(fc, "inspect", lambda sid: {"found": False}), \
                 mock.patch.object(fc, "free_gb", lambda: 100.0), \
                 mock.patch.object(fc, "style", type(fc.style)(False)), \
                 contextlib.redirect_stdout(buf):
                lines, _ = fc.status_lines("camp")
                fc.cmd_list()
        self.assertTrue(lines[3].startswith("  updated     : "), lines[3])
        # Under the config header: it is this config's budget, not the campaign's end.
        self.assertIn("  stop        : %s / %s (fuzzing)" % (fc.fmt_hms(3600), fc.fmt_hms(3600)),
                      lines)
        self.assertLess(lines.index("config:"),
                        lines.index("  stop        : %s / %s (fuzzing)" % (fc.fmt_hms(3600), fc.fmt_hms(3600))))
        self.assertIn("  fuzzed      : %s  (prep %s, triage %s, reboots %s)" % ((fc.fmt_hms(0),) * 4),
                      lines)
        self.assertIn("STOP ", buf.getvalue())
        self.assertNotIn("THEN", buf.getvalue())
        self.assertIn("%s / %s (fuzzing)" % (fc.fmt_hms(3600), fc.fmt_hms(3600)), buf.getvalue())


class BasicBlocksTest(unittest.TestCase):
    """Coverage in status is basic blocks from the cover logs. The manager's
    `coverage` stat is its signal count and used to be printed under that name."""

    def test_note_coverage_keeps_the_max_per_config(self):
        s = fc.init_state("camp")
        fc.note_coverage(s, "a", {"bb_all": 300})
        fc.note_coverage(s, "a", {"bb_all": 250})       # a pruned archive: not a loss
        fc.note_coverage(s, "b", {"bb_all": 40})
        fc.note_coverage(s, "b", {})                     # no cover log: nothing to say
        self.assertEqual(s["bb_covered"], {"a": 300, "b": 40})
        fc.note_coverage(s, "a", {"exec_lifetime": 5000})
        fc.note_coverage(s, "a", {"exec_lifetime": 4000})
        self.assertEqual(s["exec_by_config"], {"a": 5000})

    def _status(self, s, cfg, live):
        with mock.patch.object(fc, "STATE_DIR", cfg.parent / "state"), \
             mock.patch.object(fc, "load_state", lambda n: s), \
             mock.patch.object(fc, "load_def", lambda n: dict(fc.DEFAULTS, items=[
                 {"config": str(cfg), "max_hours": 1}], name=n)), \
             mock.patch.object(fc, "inspect", lambda sid: live), \
             mock.patch.object(fc, "free_gb", lambda: 100.0), \
             mock.patch.object(fc, "style", type(fc.style)(False)):
            return fc.status_lines("camp")[0]

    def test_status_reads_blocks_from_the_logs_and_names_the_signal_stat(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = write_cfg(Path(tmp), {"target": "darwin/arm64", "workdir": tmp})
            s = fc.init_state("camp")
            s.update(session_id="a", current_config=str(cfg), bb_covered={"a": 900, "b": 40})
            s["exec_by_config"] = {"a": 40000000}
            s["active_seconds"] = 48117004 / 62.0
            lines = self._status(s, cfg, {"found": True, "bb_all": 1204, "bb_run": 317,
                                          "coverage": 9412, "exec_total": 1214880,
                                          "exec_lifetime": 48117004, "rate": 78})
            rows = {ln.split(":")[0].strip(): ln for ln in lines if ":" in ln}
            self.assertIn("317 (total: 1,204)", rows["basic blocks"])
            self.assertIn("1,214,880 (total: 48,117,004)", rows["exec total"])
            self.assertIn("78/s now, 62/s average", rows["exec rate"])
            self.assertIn("b 40", rows["earlier cfgs"])
            self.assertIn("9412  (syz-manager's coverage stat, not blocks)", rows["signal"])
            self.assertNotIn("coverage", rows)
            # Manager gone (post-crash, or a halted campaign): the recorded max stands.
            s["last_exec_total"] = 1214880
            lines = self._status(s, cfg, {"found": False})
            rows = {ln.split(":")[0].strip(): ln for ln in lines if ":" in ln}
            self.assertIn("- (total: 900)", rows["basic blocks"])
            self.assertIn("1,214,880 (total: 40,000,000)", rows["exec total"])


class TriageBlockTest(unittest.TestCase):
    """The triage block: one fact per row, read from the job's checkpoint."""

    def _lines(self, job_state, boots=7):
        s = fc.init_state("camp")
        s.update(phase="triaging", triage_job="j", triage_boots=boots)
        rows = []
        with mock.patch.object(fc, "triage_state", lambda job: job_state):
            return fc.triage_lines(s, dict(fc.DEFAULTS, triage_max_boots=40),
                                   lambda *a: rows.append(a))

    def test_minimization_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "call_state.json").write_text(json.dumps(
                {"n_units": 40, "memo": {"a": True, "b": False, "c": False},
                 "attempting": "ff", "untestable": ["x"]}))
            lines = self._lines({"stage": "MINIMIZE_CALLS", "dir": tmp,
                                 "incidents": [{}, {"other": True}], "hangs": [{}],
                                 "other_bugs": {"beef01": {}}})
        self.assertEqual(lines[0], "  triage (job j, boot 7 / 40):")
        got = {ln.split(":")[0].strip(): ln.split(": ", 1)[1] for ln in lines[1:]}
        self.assertEqual(got["stage"], "MINIMIZE_CALLS")
        self.assertEqual(got["progress"],
                         "3 subsets tested for 40 calls, 1 crashing  (1 over the 64-call limit)")
        self.assertEqual(got["other bugs"], "1 panic(s): beef01")
        self.assertNotIn("panics", got)       # the target's panics are the "crashed" count
        self.assertEqual(got["hangs"], "1")

    def test_replay_stage_and_a_job_not_started(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "replay_state.json").write_text(json.dumps(
                {"pending": "verify", "pending_slot": "slot_0002", "slots": 5}))
            lines = self._lines({"stage": "REPLAY_RING", "dir": tmp, "incidents": []})
        self.assertIn("    progress    : verify pass at slot slot_0002 of 5 slots", lines)
        lines = self._lines(None, boots=1)
        self.assertIn("    stage       : starting", lines)
        self.assertEqual(lines[0], "  triage (job j, boot 1 / 40):")


class AnomalyColourTest(unittest.TestCase):
    """Colour marks anomalies only; normal rows stay plain, and strings that
    double as notification bodies are never coloured."""

    def test_kext_mismatch_is_coloured_for_status_only(self):
        inc = {"at": "2026-10-19T10:00:00+00:00", "kind": "crash", "config": "/c/x.cfg",
               "ran_seconds": 5, "crashing_kext": "IOSurface", "kext_match": False,
               "fuzzed_kext": "AppleSMC"}
        with mock.patch.object(fc, "style", type(fc.style)(True)):
            self.assertNotIn("\033[", fc.incident_line(inc))            # notification body
            self.assertIn("\033[33;1m (NOT the fuzzed AppleSMC)\033[0m",
                          fc.incident_line(inc, colour=True))

    def test_stale_state_and_dead_manager_under_fuzzing_go_red(self):
        from datetime import datetime, timedelta, timezone
        with tempfile.TemporaryDirectory() as tmp:
            cfg = write_cfg(Path(tmp), {"target": "darwin/arm64", "workdir": tmp})
            s = fc.init_state("camp")
            s.update(status="running", session_id="a", current_config=str(cfg), activity="fuzzing",
                     activity_since=fc.now_iso(),
                     updated_at=(datetime.now(timezone.utc) - timedelta(hours=1)).isoformat())
            live = {"found": True, "pid_alive": False, "http": "127.0.0.1:1"}
            with mock.patch.object(fc, "STATE_DIR", Path(tmp) / "state"), \
                 mock.patch.object(fc, "load_state", lambda n: s), \
                 mock.patch.object(fc, "load_def", lambda n: dict(fc.DEFAULTS, items=[
                     {"config": str(cfg), "max_hours": 1}], name=n)), \
                 mock.patch.object(fc, "inspect", lambda sid: live), \
                 mock.patch.object(fc, "free_gb", lambda: 100.0), \
                 mock.patch.object(fc, "style", type(fc.style)(True)):
                lines, _ = fc.status_lines("camp")
                s["activity"] = "triaging"
                s["updated_at"] = fc.now_iso()
                calm, _ = fc.status_lines("camp")
        rows = {ln.split(":")[0].strip(): ln for ln in lines if ":" in ln}
        self.assertIn("\033[31;1m", rows["updated"])
        self.assertIn("\033[31;1mdown\033[0m", rows["manager"])
        self.assertNotIn("web ui", rows)                     # nothing is serving
        rows = {ln.split(":")[0].strip(): ln for ln in calm if ":" in ln}
        self.assertNotIn("\033[", rows["updated"])
        self.assertNotIn("\033[", rows["manager"])         # expected while triaging


class QuarantineViewTest(unittest.TestCase):
    """What the quarantine took out of the search space: one line in status,
    the full picture from `quarantine <name>`."""

    def _qs(self):
        qs = fc.qm.init_state(config="/c/x.cfg")
        fc.qm.on_crash(qs, "HARD1")                                    # suspect
        fc.qm.on_crash(qs, "HARD1", seq=["syz_IOConnectCallMethod$X_5"])  # confirmed HARD
        fc.qm.on_crash(qs, "SOFT1")
        fc.qm.on_crash(qs, "SOFT1", seq=["syz_IOConnectCallMethod$X_2",
                                         "syz_IOConnectCallMethod$X_7"])  # SOFT group
        fc.qm.on_crash(qs, "NEW1")                                     # still suspect
        return qs

    def test_summary_counts_what_is_benched_and_why(self):
        self.assertEqual(fc.quarantine_summary(fc.qm.init_state()), "none")
        self.assertEqual(fc.quarantine_summary(fc.qm.init_state(), 38), "0 / 38 disabled")
        self.assertEqual(fc.quarantine_summary(self._qs()),
                         "2 disabled (1 hard, 1 soft), 1 suspect")
        self.assertEqual(fc.quarantine_summary(self._qs(), 38),
                         "2 / 38 disabled (1 hard, 1 soft), 1 suspect")

    def test_benchable_syscalls_resolves_globs_and_skips_service_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sys/darwin").mkdir(parents=True)
            (root / "sys/darwin/iokit_X.txt").write_text(
                "syz_IOServiceOpen$X_Client(name ptr[in, string])\n"
                "syz_IOConnectCallMethod$X_Client_0(c connection)\n"
                "syz_IOConnectCallMethod$X_Client_1(c connection)\n"
                "syz_IOConnectTrap$X_Client_0(c connection)\n"
                "\tnot_a_syscall(indented)\n"
                "syz_IOConnectCallMethod$Y_Client_0(c connection)\n")
            cfg = write_cfg(root, {"target": "darwin/arm64", "enable_syscalls": [
                "syz_IOServiceOpen$X_Client", "syz_IOConnectCallMethod$X_Client_*",
                "syz_IOConnectTrap$X_Client_0"]})
            with mock.patch.object(fc, "REPO_ROOT", root):
                self.assertEqual(fc.benchable_syscalls(str(cfg)), [
                    "syz_IOConnectCallMethod$X_Client_0", "syz_IOConnectCallMethod$X_Client_1",
                    "syz_IOConnectTrap$X_Client_0"])
            with mock.patch.object(fc, "REPO_ROOT", root / "elsewhere"):
                self.assertIsNone(fc.benchable_syscalls(str(cfg)))   # no descriptions here

    def test_detailed_view_is_one_row_per_crash_with_short_selectors(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = write_cfg(Path(tmp), {"target": "darwin/arm64"})
            with mock.patch.object(fc, "STATE_DIR", Path(tmp) / "state"), \
                 mock.patch.object(fc, "benchable_syscalls", lambda c: None):
                lines = fc.quarantine_lines(str(cfg), self._qs())
        self.assertEqual(lines[0], "quarantine for target : 2 disabled (1 hard, 1 soft), 1 suspect")
        self.assertEqual(lines[1], "  selectors are syz_IOConnectCallMethod$<name>")
        rows = {ln.split()[0]: ln.split() for ln in lines if ln.startswith("  ") and
                ln.split() and ln.split()[0] in ("HARD1", "SOFT1", "NEW1")}
        self.assertEqual(rows["HARD1"][1:], ["HARD", "disabled", "2", "X_5*"])
        self.assertEqual(rows["SOFT1"][1:], ["SOFT", "rotating", "2", "X_2*,", "X_7"])
        self.assertEqual(rows["NEW1"][1:], ["SUSPECT", "watching", "1", "-"])
        i = lines.index("  disabled now (2):")
        self.assertEqual(lines[i + 1:i + 3], ["    X_2", "    X_5"])
        self.assertTrue(lines[-1].startswith("  state        : "), lines[-1])
        self.assertFalse(any("escaped" in ln for ln in lines))   # column only when nonzero

    def test_short_selectors_keep_kinds_apart_only_when_mixed(self):
        short, header = fc.short_selectors(["syz_IOConnectCallMethod$A_2", "syz_IOConnectCallMethod$B_2"])
        self.assertEqual(short, {"syz_IOConnectCallMethod$A_2": "A_2", "syz_IOConnectCallMethod$B_2": "B_2"})
        self.assertEqual(header, "selectors are syz_IOConnectCallMethod$<name>")
        short, header = fc.short_selectors(["syz_IOConnectCallMethod$A_2", "syz_IOConnectTrap$A_2"])
        self.assertEqual(short, {"syz_IOConnectCallMethod$A_2": "call$A_2",
                                 "syz_IOConnectTrap$A_2": "trap$A_2"})
        self.assertIn("call$ = syz_IOConnectCallMethod$", header)


class ManagerRowTest(unittest.TestCase):
    def test_a_live_manager_shows_its_pid_and_executors(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = write_cfg(Path(tmp), {"target": "darwin/arm64", "workdir": tmp})
            s = fc.init_state("camp")
            s.update(session_id="a", current_config=str(cfg), activity="fuzzing",
                     activity_since=fc.now_iso())
            live = {"found": True, "pid_alive": True, "pid": 4120, "executors": 2,
                    "http": "127.0.0.1:56741"}
            with mock.patch.object(fc, "STATE_DIR", Path(tmp) / "state"), \
                 mock.patch.object(fc, "load_state", lambda n: s), \
                 mock.patch.object(fc, "load_def", lambda n: dict(fc.DEFAULTS, items=[
                     {"config": str(cfg), "max_hours": 1}], name=n)), \
                 mock.patch.object(fc, "inspect", lambda sid: live), \
                 mock.patch.object(fc, "free_gb", lambda: 100.0), \
                 mock.patch.object(fc, "style", type(fc.style)(False)):
                lines, _ = fc.status_lines("camp")
        self.assertIn("  manager     : pid 4120, 2 executor(s) live", lines)
        self.assertIn("  web ui      : http://127.0.0.1:56741", lines)


class BenchableMemoTest(unittest.TestCase):
    def test_descriptions_are_parsed_once_until_something_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sys/darwin").mkdir(parents=True)
            desc = root / "sys/darwin/iokit_X.txt"
            desc.write_text("syz_IOConnectCallMethod$X_0(c connection)\n")
            cfg = write_cfg(root, {"target": "darwin/arm64",
                                   "enable_syscalls": ["syz_IOConnectCallMethod$X_*"]})
            reads = []
            real = Path.read_text

            def counting(self, *a, **k):
                if self.name == "iokit_X.txt":
                    reads.append(self.name)
                return real(self, *a, **k)
            with mock.patch.object(fc, "REPO_ROOT", root), \
                 mock.patch.object(fc, "_BENCHABLE_MEMO", {}), \
                 mock.patch.object(Path, "read_text", counting):
                self.assertEqual(len(fc.benchable_syscalls(str(cfg))), 1)
                self.assertEqual(len(fc.benchable_syscalls(str(cfg))), 1)
                self.assertEqual(len(reads), 1)                 # second call: memo
                desc.write_text("syz_IOConnectCallMethod$X_0(c connection)\n"
                                "syz_IOConnectCallMethod$X_1(c connection)\n")
                os.utime(desc, (time.time() + 5, time.time() + 5))  # mtime moves
                self.assertEqual(len(fc.benchable_syscalls(str(cfg))), 2)
                self.assertEqual(len(reads), 2)


class IncidentTableTest(unittest.TestCase):
    def _inc(self, cfg="/c/a.cfg", **kw):
        inc = {"at": "2026-10-19T10:00:00+00:00", "kind": "crash", "config": cfg,
               "ran_seconds": 84, "panic_evidence": True, "signature": "3f2a9c01",
               "bug_ids": ["BUG-0007"], "crashing_kext": "AppleSMC", "kext_match": True,
               "decision": "triage", "triage_job": "camp_t1"}
        inc.update(kw)
        return inc

    def test_one_row_per_incident_with_the_mismatch_marked(self):
        lines = fc.incident_table([self._inc(),
                                   self._inc(crashing_kext="IOSurface", kext_match=False,
                                             decision="suspect", triage_job=None)])
        self.assertEqual(lines[0].split(), ["when", "kind", "ran", "sig", "bug", "kext", "decision"])
        self.assertEqual(lines[1].split()[2:], ["crash", "84s", "3f2a9c01", "BUG-0007", "AppleSMC",
                                                "triage", "camp_t1"])
        self.assertIn("IOSurface (NOT fuzzed)  suspect", lines[2])

    def test_a_plan_job_shows_as_its_short_name(self):
        # A plan campaign's job is addressed by its path; status and the
        # notification body say 't1', the way the triage block already does.
        job = "/tree/campaigns/camp/a/a-1/triage/t1"
        self.assertTrue(fc.incident_table([self._inc(triage_job=job)])[1].endswith("triage t1"))
        self.assertTrue(fc.incident_line(self._inc(triage_job=job)).endswith("-> triage t1"))
        with mock.patch.object(fc, "style", type(fc.style)(True)):
            coloured = fc.incident_table([self._inc(kext_match=False)], colour=True)
        self.assertIn("\033[33;1m (NOT fuzzed)\033[0m", coloured[1])

    def test_config_column_only_for_a_sweep(self):
        one = fc.incident_table([self._inc(), self._inc()])
        self.assertNotIn("config", one[0])
        two = fc.incident_table([self._inc(), self._inc(cfg="/c/b.cfg")])
        self.assertEqual(two[0].split()[2], "config")
        self.assertIn("  b  ", two[2])

    def test_startup_and_no_report_fall_back_to_what_is_known(self):
        lines = fc.incident_table([
            self._inc(kind="startup", signature=None, bug_ids=None, crashing_kext=None,
                      decision=None, triage_job=None, panic_evidence=False,
                      log_tail="SYZFAIL: shmem open failed"),
            self._inc(decision=None, triage_job=None, panic_evidence=False)])
        self.assertIn("SYZFAIL: shmem open failed", lines[1])
        self.assertIn("(no panic report)", lines[2])


class ProgressSeriesTest(unittest.TestCase):
    """The sampled progress series: the only time axis for blocks (the cover
    log carries none) and for programs across manager restarts."""

    def test_a_poll_appends_one_sample_and_skips_when_there_is_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = fc.init_state("camp")
            s["active_seconds"] = 1234.6
            info = {"workdir": tmp, "exec_lifetime": 5000, "bb_all": 300}
            self.assertTrue(fc.record_progress(s, info, now=1000.4))
            self.assertFalse(fc.record_progress(s, {"workdir": tmp}, now=1010))
            self.assertFalse(fc.record_progress(s, {"exec_lifetime": 1}, now=1020))  # no workdir
            self.assertTrue(fc.record_progress(s, dict(info, bb_all=320), now=1600))
            rows = fc.progress_samples(tmp)
        self.assertEqual(rows, [{"at": 1000, "fuzz_s": 1235, "exec": 5000, "blocks": 300},
                                {"at": 1600, "fuzz_s": 1235, "exec": 5000, "blocks": 320}])

    def test_trend_is_the_growth_over_the_window_of_recent_samples(self):
        with tempfile.TemporaryDirectory() as tmp:
            s = fc.init_state("camp")
            for at, ex, bb in ((0, 100, 10), (600, 700, 12), (3000, 3000, 20), (3600, 3600, 25)):
                fc.record_progress(s, {"workdir": tmp, "exec_lifetime": ex, "bb_all": bb}, now=at)
            # window of 1h ending at the newest sample (3600): the sample at 0 is
            # on the edge and counts; the span shown is the real one
            self.assertEqual(fc.progress_trend(tmp, "blocks", now=3600),
                             "  +15 / %s" % fc.fmt_hms(3600))
            self.assertEqual(fc.progress_trend(tmp, "exec", window=1800, now=3600),
                             "  +600 / %s" % fc.fmt_hms(600))
            # samples older than the window: nothing to say rather than a stale number
            self.assertEqual(fc.progress_trend(tmp, "blocks", now=3600 + 7200), "")
            # one sample is not a trend
            with tempfile.TemporaryDirectory() as tmp2:
                fc.record_progress(s, {"workdir": tmp2, "exec_lifetime": 1, "bb_all": 1}, now=5)
                self.assertEqual(fc.progress_trend(tmp2, "blocks", now=10), "")

    def test_status_rows_carry_the_trend(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = write_cfg(Path(tmp), {"target": "darwin/arm64", "workdir": tmp})
            s = fc.init_state("camp")
            s.update(session_id="a", current_config=str(cfg), activity="fuzzing",
                     activity_since=fc.now_iso())
            now = time.time()
            for dt, ex, bb in ((-1800, 1000, 100), (-900, 2000, 110), (-10, 3000, 115)):
                fc.record_progress(s, {"workdir": tmp, "exec_lifetime": ex, "bb_all": bb},
                                   now=now + dt)
            live = {"found": True, "pid_alive": True, "pid": 1, "executors": 1,
                    "exec_total": 500, "exec_lifetime": 3000, "bb_all": 115, "bb_run": 15}
            with mock.patch.object(fc, "STATE_DIR", Path(tmp) / "state"), \
                 mock.patch.object(fc, "load_state", lambda n: s), \
                 mock.patch.object(fc, "load_def", lambda n: dict(fc.DEFAULTS, items=[
                     {"config": str(cfg), "max_hours": 1}], name=n)), \
                 mock.patch.object(fc, "inspect", lambda sid: live), \
                 mock.patch.object(fc, "free_gb", lambda: 100.0), \
                 mock.patch.object(fc, "style", type(fc.style)(False)):
                lines, _ = fc.status_lines("camp")
        rows = {ln.split(":")[0].strip(): ln for ln in lines if ":" in ln}
        self.assertIn("500 (total: 3,000)  +2000 / %s" % fc.fmt_hms(1790), rows["exec total"])
        self.assertIn("15 (total: 115)  +15 / %s" % fc.fmt_hms(1790), rows["basic blocks"])


class SchedulerLoopTest(unittest.TestCase):
    """Phase 1 of the redesign: state keyed by item id, the loop driven by
    lib.schedule, operator verbs as requests the runner applies."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.state_dir = self.dir / "state"
        self.state_dir.mkdir()
        self._run_dir = mock.patch.object(fc, "RUN_DIR", self.state_dir)
        self._run_dir.start()

    def tearDown(self):
        self._run_dir.stop()
        self._tmp.cleanup()

    def _run(self, s, configs, supervise=None, calls=None):
        d = dict(fc.DEFAULTS, name="camp",
                 items=[{"config": c, "max_hours": 1} for c in configs])
        started = []
        calls = calls if calls is not None else []
        n = {"ensure": 0}

        def fake_ensure(st, cfg, dd=None):
            started.append(cfg)
            n["ensure"] += 1
            st["session_id"] = fc.config_id(cfg)
            if supervise is None or n["ensure"] > len(supervise):
                st["status"] = "halted"            # stop after the scripted outcomes
                raise RuntimeError("stop here")

        outcomes = list(supervise or [])

        def fake_supervise(*a):
            o = outcomes.pop(0)
            return o() if callable(o) else o
        with mock.patch.object(fc, "STATE_DIR", self.state_dir), \
             mock.patch.object(fc, "load_def", lambda name: d), \
             mock.patch.object(fc, "load_state", lambda name: s), \
             mock.patch.object(fc, "save_state", lambda st: None), \
             mock.patch.object(fc, "brake_held", lambda name: None), \
             mock.patch.object(fc, "breaker", lambda *a: None), \
             mock.patch.object(fc, "reconcile_boot", lambda *a: None), \
             mock.patch.object(fc, "reconcile_gap", lambda *a, **k: None), \
             mock.patch.object(fc, "results_commit", lambda *a, **k: None), \
             mock.patch.object(fc, "inspect", lambda sid: {"found": False}), \
             mock.patch.object(fc, "session", lambda *a, **k: calls.append(a) or (0, "")), \
             mock.patch.object(fc, "supervise", fake_supervise), \
             mock.patch.object(fc, "ensure_running", fake_ensure), \
             mock.patch.object(fc, "log", lambda m: None):
            fc.cmd_run("camp")
        return started

    def test_items_are_keyed_by_id_and_the_cursor_is_derived(self):
        s = fc.init_state("camp")
        self.assertEqual(self._run(s, ["/a.cfg", "/b.cfg"]), ["/a.cfg"])
        self.assertEqual(s["item_order"], ["a-1", "b-1"])
        self.assertEqual(s["items"]["a-1"]["status"], "running")
        self.assertEqual(s["items"]["b-1"]["status"], "pending")
        self.assertEqual(s["cursor"], 0)

    def test_a_repeated_config_is_two_items(self):
        s = fc.init_state("camp")
        self._run(s, ["/a.cfg", "/a.cfg"])
        self.assertEqual(s["item_order"], ["a-1", "a-2"])

    def test_a_skip_request_leaves_a_pending_item_out(self):
        s = fc.init_state("camp")
        fc.req.append(self.state_dir / "camp.requests.json", "skip", "a-1")
        self.assertEqual(self._run(s, ["/a.cfg", "/b.cfg"]), ["/b.cfg"])
        self.assertEqual((s["items"]["a-1"]["status"], s["items"]["a-1"]["reason"]),
                         ("skipped", "skip"))
        self.assertEqual(fc.req.pending(self.state_dir / "camp.requests.json"), [])

    def test_a_next_request_ends_the_running_item_and_keeps_the_rest(self):
        s = fc.init_state("camp")
        calls = []

        def operator_types_next():
            # the request arrives while the item fuzzes; supervise hands back
            fc.req.append(self.state_dir / "camp.requests.json", "next")
            return "request"
        started = self._run(s, ["/a.cfg", "/b.cfg"], supervise=[operator_types_next], calls=calls)
        self.assertEqual(started, ["/a.cfg", "/b.cfg"])
        self.assertEqual((s["items"]["a-1"]["status"], s["items"]["a-1"]["reason"]),
                         ("done", "next"))
        self.assertEqual(s["cursor"], 1)

    def test_a_skip_of_the_running_item_keeps_it_skipped_with_its_record(self):
        s = fc.init_state("camp")
        s["active_seconds"] = 600.0
        s["incidents"] = [{"item": "a-1", "kind": "crash", "bug_ids": ["BUG-0001"]}]

        def operator_skips_the_running_item():
            fc.req.append(self.state_dir / "camp.requests.json", "skip", "a-1")
            return "request"
        started = self._run(s, ["/a.cfg", "/b.cfg"], supervise=[operator_skips_the_running_item])
        self.assertEqual(started, ["/a.cfg", "/b.cfg"])
        rec = s["items"]["a-1"]
        self.assertEqual((rec["status"], rec["reason"]), ("skipped", "skip"))
        # left out of the samples, but what it ran and found is on record
        self.assertEqual(rec["clocks"]["active_seconds"], 600)
        self.assertEqual((rec["crashes"], rec["bug_ids"]), (1, ["BUG-0001"]))

    def test_a_next_that_arrives_between_restarts_still_cuts_the_running_item(self):
        """A crash-restart passes through the loop top; a request taken there
        must apply to the item that was running, not be dropped."""
        s = fc.init_state("camp")
        s["items"] = {"a-1": {"config": "/a.cfg", "status": "running"},
                      "b-1": {"config": "/b.cfg", "status": "pending"}}
        s["item_order"] = ["a-1", "b-1"]
        fc.req.append(self.state_dir / "camp.requests.json", "next")
        self.assertEqual(self._run(s, ["/a.cfg", "/b.cfg"]), ["/b.cfg"])
        self.assertEqual((s["items"]["a-1"]["status"], s["items"]["a-1"]["reason"]), ("done", "next"))

    def test_a_next_with_nothing_running_does_not_cut_the_item_about_to_start(self):
        s = fc.init_state("camp")
        fc.req.append(self.state_dir / "camp.requests.json", "next")
        self.assertEqual(self._run(s, ["/a.cfg", "/b.cfg"]), ["/a.cfg"])
        self.assertEqual(s["items"]["a-1"]["status"], "running")

    def test_a_halt_request_halts_the_campaign(self):
        s = fc.init_state("camp")
        fc.req.append(self.state_dir / "camp.requests.json", "halt")
        self.assertEqual(self._run(s, ["/a.cfg"]), [])
        self.assertEqual(s["status"], "halted")
        self.assertIn("halted by user", s["halt_reason"])    # halt_kind: user

    def test_legacy_state_is_backfilled_from_the_positional_cursor(self):
        s = fc.init_state("camp")
        s.update(cursor=1, current_config="/b.cfg", status="running",
                 abandoned=[{"config": "/c.cfg", "reason": "max", "at": None}])
        d = dict(fc.DEFAULTS, items=[{"config": c, "max_hours": 1 / 3600}
                                     for c in ("/a.cfg", "/b.cfg", "/c.cfg")])
        order = fc.ensure_items(s, d)
        self.assertEqual(order, ["a-1", "b-1", "c-1"])
        self.assertEqual([s["items"][i]["status"] for i in order], ["done", "running", "abandoned"])
        self.assertEqual(fc.derived_cursor(s), 1)
        # advancing an item-keyed state derives the cursor rather than stepping it
        fc.end_item(s, "b-1", "max_hours")
        self.assertEqual((s["items"]["b-1"]["status"], s["cursor"]), ("done", 3))

    def test_a_halt_seen_while_supervising_is_persisted(self):
        """wait_for_stop returned "halted" without setting the status, so the
        loop's next save wrote "running" back and the next boot resumed."""
        s = fc.init_state("camp")
        s["session_id"] = "sid"
        with mock.patch.object(fc, "wait_for_stop", lambda *a: "halted"), \
             mock.patch.object(fc, "load_state", lambda n: {"status": "halted",
                                                            "halt_reason": "halted by user"}), \
             mock.patch.object(fc, "session", lambda *a, **k: (0, "")):
            self.assertEqual(fc.supervise(s, dict(fc.DEFAULTS), "sid", 10 ** 9), "halted")
        self.assertEqual((s["status"], s["halt_reason"]), ("halted", "halted by user"))

    def test_a_skip_of_a_later_item_does_not_wake_the_wait(self):
        s = fc.init_state("camp")
        s["current_item"] = "a-1"
        fc.req.append(self.state_dir / "camp.requests.json", "skip", "b-1")
        d = dict(fc.DEFAULTS, stop_check_seconds=0.01)
        with mock.patch.object(fc, "STATE_DIR", self.state_dir), \
             mock.patch.object(fc, "load_state", lambda n: s), \
             mock.patch.object(fc, "brake_held", lambda n: None):
            self.assertIsNone(fc.wait_for_stop(s, d, 0.1))
            # ... while a skip of the running item does
            fc.req.append(self.state_dir / "camp.requests.json", "skip", "a-1")
            self.assertEqual(fc.wait_for_stop(s, d, 30), "request")

    def test_a_request_wakes_the_wait_within_a_stop_check(self):
        s = fc.init_state("camp")
        fc.req.append(self.state_dir / "camp.requests.json", "next")
        d = dict(fc.DEFAULTS, stop_check_seconds=0.01)
        with mock.patch.object(fc, "STATE_DIR", self.state_dir), \
             mock.patch.object(fc, "load_state", lambda n: s), \
             mock.patch.object(fc, "brake_held", lambda n: None):
            t0 = time.time()
            self.assertEqual(fc.wait_for_stop(s, d, 30), "request")
        self.assertLess(time.time() - t0, 1)

    def test_cmd_request_validates_the_item_and_queues(self):
        d = dict(fc.DEFAULTS, items=[{"config": "/a.cfg", "max_hours": 1 / 3600}], name="camp")
        with mock.patch.object(fc, "STATE_DIR", self.state_dir), \
             mock.patch.object(fc, "load_def", lambda n: d), \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                fc.cmd_request("camp", "skip", "nope")
            fc.cmd_request("camp", "skip", "a-1")
            fc.cmd_request("camp", "next")
        pend = fc.req.pending(self.state_dir / "camp.requests.json")
        self.assertEqual([(r["verb"], r["item"]) for r in pend], [("skip", "a-1"), ("next", None)])

    def test_status_shows_pending_requests_and_the_item(self):
        cfg = write_cfg(self.dir, {"target": "darwin/arm64", "workdir": str(self.dir)})
        s = fc.init_state("camp")
        s.update(current_config=str(cfg), items={"target-1": {"config": str(cfg), "status": "running"}},
                 item_order=["target-1"])
        fc.req.append(self.state_dir / "camp.requests.json", "next")
        with mock.patch.object(fc, "STATE_DIR", self.state_dir), \
             mock.patch.object(fc, "load_state", lambda n: s), \
             mock.patch.object(fc, "load_def", lambda n: dict(fc.DEFAULTS, items=[
                 {"config": str(cfg), "max_hours": 1}], name=n)), \
             mock.patch.object(fc, "inspect", lambda sid: {"found": False}), \
             mock.patch.object(fc, "free_gb", lambda: 100.0), \
             mock.patch.object(fc, "style", type(fc.style)(False)):
            lines, _ = fc.status_lines("camp")
        rows = {ln.split(":")[0].strip(): ln.split(": ", 1)[1] for ln in lines if ": " in ln}
        self.assertEqual(rows["requests"], "next  (applied at the runner's next poll)")
        self.assertEqual(rows["item"], "target-1  (running)")


class MigrateTest(unittest.TestCase):
    """Finished legacy campaigns move into the folder layout; the ledger moves
    up; nothing a campaign produced moves."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "campaigns" / ".state").mkdir(parents=True)
        (self.root / "campaigns" / "bugs" / "BUG-0001" / "reports").mkdir(parents=True)
        (self.root / "campaigns" / "bugs" / "registry.json").write_text("{}")
        (self.root / "config").mkdir()
        self.cfg = self.root / "config" / "X_v.cfg"
        self.cfg.write_text(json.dumps({"enable_syscalls": ["a"], "disable_syscalls": ["b"]}))
        (self.root / "campaigns" / "old.json").write_text(json.dumps(
            {"configs": ["config/X_v.cfg"], "budget_hours": 2, "max_crashes": 5}))
        (self.root / "campaigns" / ".state" / "old.json").write_text(json.dumps(
            {"name": "old", "status": "done", "cursor": 1}))
        (self.root / "campaigns" / ".state" / "old.coordinator.log").write_text("x\n")
        (self.root / "campaigns" / "live.json").write_text(json.dumps({"configs": ["config/X_v.cfg"]}))
        (self.root / "campaigns" / ".state" / "live.json").write_text(json.dumps(
            {"name": "live", "status": "running"}))
        self._patches = [mock.patch.object(fc, "REPO_ROOT", self.root),
                         mock.patch.object(fc, "CAMPAIGN_DIR", self.root / "campaigns"),
                         mock.patch.object(fc, "STATE_DIR", self.root / "campaigns" / ".state"),
                         mock.patch.object(fc, "running_processes", lambda p: []),
                         mock.patch.object(fc, "log", lambda m: None)]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()
        self._tmp.cleanup()

    def test_finished_campaigns_and_the_ledger_move_running_ones_stay(self):
        with contextlib.redirect_stdout(io.StringIO()):
            fc.cmd_migrate()
        cdir = self.root / "campaigns" / "old"
        plan = json.loads((cdir / "campaign.json").read_text())
        self.assertTrue(plan["legacy"])
        self.assertEqual([it["config"] for it in plan["items"]], ["config/X_v.cfg"])
        self.assertEqual(plan["limits"], {"max_crashes": 5})
        self.assertEqual(json.loads((cdir / "state.json").read_text())["status"], "done")
        self.assertTrue((cdir / "coordinator.log").exists())
        self.assertTrue((cdir / "legacy-def.json").exists())
        self.assertFalse((self.root / "campaigns" / "old.json").exists())
        self.assertTrue((self.root / "bugs" / "BUG-0001" / "reports").is_dir())
        self.assertFalse((self.root / "campaigns" / "bugs").exists())
        # the running one is left exactly where it was
        self.assertTrue((self.root / "campaigns" / "live.json").exists())
        self.assertFalse((self.root / "campaigns" / "live").exists())
        # a migrated campaign loads as read-only
        self.assertEqual(fc.load_def("old")["layout"], "legacy")
        self.assertEqual(json.loads(self.cfg.read_text())["disable_syscalls"], ["b"])   # untouched

    def test_strip_is_opt_in_and_dry_run_moves_nothing(self):
        with contextlib.redirect_stdout(io.StringIO()):
            fc.cmd_migrate(dry_run=True)
        self.assertTrue((self.root / "campaigns" / "old.json").exists())
        with contextlib.redirect_stdout(io.StringIO()):
            fc.cmd_migrate(strip_disable_syscalls=True)
        self.assertEqual(json.loads(self.cfg.read_text())["disable_syscalls"], [])

    def test_refuses_while_a_driver_runs(self):
        with mock.patch.object(fc, "running_processes", lambda p: [(1, "fuzz-campaign.py run x")]), \
             self.assertRaises(SystemExit):
            fc.cmd_migrate()
