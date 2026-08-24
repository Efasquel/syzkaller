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

    def test_advance_triage_done_benches_and_resumes(self):
        cfg = write_cfg(self.dir, {"target": "darwin/arm64", "enable_syscalls": ["a"]})
        culprit = self.dir / "culprit.syz"
        culprit.write_text("x")
        s = fc.init_state("camp")
        s.update({"phase": "triaging", "triage_job": "camp_t1",
                  "triage_bug_sig": "SIG1", "current_config": str(cfg)})
        d = dict(fc.DEFAULTS)
        with mock.patch.object(fc, "triage", lambda *a, **k: (0, "")), \
             mock.patch.object(fc, "triage_state",
                               lambda job: {"stage": "DONE", "final_culprit": str(culprit)}), \
             mock.patch.object(fc, "emit_syscalls",
                               lambda c: ["syz_IOConnectCallMethod$Foo_5"]), \
             mock.patch.object(fc, "save_state", lambda st: None):
            fc.advance_triage(s, d)
        self.assertEqual(s["phase"], "fuzzing")
        self.assertIn("SIG1", s["suppressed_sigs"])
        self.assertIsNone(s["triage_job"])
        self.assertEqual(json.loads(cfg.read_text())["disable_syscalls"],
                         ["syz_IOConnectCallMethod$Foo_5"])

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


if __name__ == "__main__":
    unittest.main()
