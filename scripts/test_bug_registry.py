#!/usr/bin/env python3
"""Tests for bug_registry: crash provenance, signature lookup, attribution."""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bug_registry as br  # noqa: E402
import fsutil  # noqa: E402


def analyzed(report, key="Drv:m:READ", sig="aaaa", fault="READ"):
    """The subset of crash_fingerprint.analyze()'s output route_one consumes."""
    return {
        "report": report, "bug_key": key, "signature": sig, "fault_class": fault,
        "culprit_module": "Drv", "culprit_off": 0x100, "culprit_func": None,
        "culprit_func_confidence": None, "far": 0, "pc_site": "Pishi+0x1",
        "pc_instrumented": True, "pgz_verdict": None,
    }


class Args(object):
    def __init__(self, **kw):
        self.__dict__.update(kw)


class OriginTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.reg = {"counter": 0, "bugs": {}}

    def test_default_origin_is_fuzz(self):
        br.route_one(self.reg, self.dir, analyzed("a.panic"))
        rec = self.reg["bugs"]["Drv:m:READ"]
        self.assertEqual(rec["crashes"][0]["origin"], "fuzz")

    def test_triage_origin_recorded(self):
        br.route_one(self.reg, self.dir, analyzed("a.panic"), origin="triage")
        rec = self.reg["bugs"]["Drv:m:READ"]
        self.assertEqual(br.crash_origin(rec["crashes"][0]), "triage")

    def test_reroute_is_idempotent(self):
        br.route_one(self.reg, self.dir, analyzed("a.panic"))
        _, _, new_bug, new_crash = br.route_one(self.reg, self.dir, analyzed("a.panic"))
        self.assertFalse(new_bug)
        self.assertFalse(new_crash)
        self.assertEqual(len(self.reg["bugs"]["Drv:m:READ"]["crashes"]), 1)

    def test_legacy_row_reads_as_fuzz(self):
        """Rows written before the field existed predate triage routing."""
        self.assertEqual(br.crash_origin({"report": "x"}), "fuzz")

    def test_backfill_only_fills_missing_origin(self):
        br.route_one(self.reg, self.dir, analyzed("a.panic"))
        rec = self.reg["bugs"]["Drv:m:READ"]
        del rec["crashes"][0]["origin"]          # simulate a pre-origin row
        br.route_one(self.reg, self.dir, analyzed("a.panic"), origin="triage")
        self.assertEqual(rec["crashes"][0]["origin"], "triage")

    def test_backfill_never_overwrites_explicit_origin(self):
        """A re-route must not be able to relabel a genuine find as self-inflicted."""
        br.route_one(self.reg, self.dir, analyzed("a.panic"), origin="fuzz")
        br.route_one(self.reg, self.dir, analyzed("a.panic"), origin="triage")
        rec = self.reg["bugs"]["Drv:m:READ"]
        self.assertEqual(rec["crashes"][0]["origin"], "fuzz")


class SignatureTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.reg = {"counter": 0, "bugs": {}}

    def test_distinct_signatures_deduped_in_order(self):
        br.route_one(self.reg, self.dir, analyzed("a.panic", sig="s1"))
        br.route_one(self.reg, self.dir, analyzed("b.panic", sig="s2"))
        br.route_one(self.reg, self.dir, analyzed("c.panic", sig="s1"))
        rec = self.reg["bugs"]["Drv:m:READ"]
        self.assertEqual(br.bug_signatures(rec), ["s1", "s2"])

    def test_find_by_signature(self):
        br.route_one(self.reg, self.dir, analyzed("a.panic", sig="deadbeef"))
        rec = br.find_bug(self.reg, None, "deadbeef")
        self.assertEqual(rec["id"], "BUG-0001")

    def test_find_by_id_and_key(self):
        br.route_one(self.reg, self.dir, analyzed("a.panic"))
        self.assertIsNotNone(br.find_bug(self.reg, "BUG-0001", None))
        self.assertIsNotNone(br.find_bug(self.reg, "Drv:m:READ", None))

    def test_find_miss_returns_none(self):
        self.assertIsNone(br.find_bug(self.reg, "BUG-9999", "nope"))


class AttributeTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.reg = {"counter": 0, "bugs": {}}
        br.route_one(self.reg, self.dir, analyzed("a.panic", sig="sig1"))
        br.save_registry(self.dir, self.reg)
        self.culprit = os.path.join(self.dir, "c.syz")
        with open(self.culprit, "w") as f:
            f.write("open(&(0x0))\ncall(r0)\n")

    def attribute(self, **kw):
        args = Args(bugs=self.dir, sig="sig1", which=None, culprit=self.culprit,
                    selector=["sel_5"], job="job1", verified=True)
        args.__dict__.update(kw)
        with redirect_stdout(io.StringIO()):
            br.cmd_attribute(args)
        with open(br.registry_path(self.dir)) as f:
            return json.load(f)["bugs"]["Drv:m:READ"]

    def test_records_reproducer(self):
        rec = self.attribute()
        rp = rec["reproducer"]
        self.assertTrue(rp["verified"])
        self.assertEqual(rp["calls"], 2)
        self.assertEqual(rp["selectors"], ["sel_5"])
        self.assertEqual(rp["job"], "job1")

    def test_backfills_method_from_selector(self):
        """The selector IS the method for an IOKit external method."""
        rec = self.attribute()
        self.assertEqual(rec["method"], "sel_5")

    def test_verified_survives_a_later_unverified_attribution(self):
        self.attribute(verified=True)
        rec = self.attribute(verified=False)
        self.assertTrue(rec["reproducer"]["verified"])

    def test_unverified_is_recorded_and_flagged(self):
        rec = self.attribute(verified=False)
        self.assertFalse(rec["reproducer"]["verified"])
        self.assertIn("NO --", br.render_reproducer(rec))

    def test_dossier_leads_with_reproducer(self):
        rec = self.attribute()
        with open(os.path.join(self.dir, rec["dossier"])) as f:
            body = f.read()
        self.assertLess(body.index("## Reproducer"), body.index("## Evidence log"))
        self.assertIn("sel_5", body)

    def test_missing_bug_exits_nonzero(self):
        args = Args(bugs=self.dir, sig="absent", which=None, culprit=None,
                    selector=[], job=None, verified=False)
        with self.assertRaises(SystemExit) as cm:
            with redirect_stdout(io.StringIO()):
                br.cmd_attribute(args)
        self.assertEqual(cm.exception.code, 1)


class RenderTest(unittest.TestCase):
    def test_elide_keeps_short_lines(self):
        self.assertEqual(br._elide("abc\ndef"), "abc\ndef")

    def test_elide_shortens_long_lines(self):
        out = br._elide("x" * 5000)
        self.assertLess(len(out), 400)
        self.assertIn("chars]...", out)

    def test_evidence_counts_only_fuzz_sightings(self):
        reg = {"counter": 0, "bugs": {}}
        d = tempfile.mkdtemp()
        br.route_one(reg, d, analyzed("a.panic"), origin="fuzz")
        br.route_one(reg, d, analyzed("b.panic"), origin="triage")
        text = br.render_evidence(reg["bugs"]["Drv:m:READ"])
        self.assertIn("_1 crash(es) grouped under this bug (1 self-inflicted", text)

    def test_tabulate_sizes_to_content(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            br._tabulate([("a-very-long-value", "x")], ("H1", "H2"))
        head, row = buf.getvalue().splitlines()
        # H1's column widens to the value, so H2 starts at the same offset in both
        self.assertEqual(head.index("H2"), row.index("x"))

    def test_tabulate_has_no_trailing_whitespace(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            br._tabulate([("a", "bb")], ("H1", "H2"))
        for ln in buf.getvalue().splitlines():
            self.assertEqual(ln, ln.rstrip())


class RegistryIOTest(unittest.TestCase):
    def test_missing_registry_exits_for_read_commands(self):
        """A typo'd --bugs must not read as 'no bugs found'."""
        with self.assertRaises(SystemExit) as cm:
            br.load_registry("/nonexistent-registry-dir", must_exist=True)
        self.assertEqual(cm.exception.code, 2)

    def test_missing_registry_is_empty_for_writers(self):
        reg = br.load_registry("/nonexistent-registry-dir")
        self.assertEqual(reg, {"counter": 0, "bugs": {}})

    def test_default_bugs_dir_is_the_campaign_inventory(self):
        self.assertTrue(br.DEFAULT_BUGS_DIR.endswith("campaigns/bugs"))


class EvidenceRetentionTest(unittest.TestCase):
    """The registry stored a basename pointing into an OS-rotated directory, so a
    dossier's oldest citations rot on their own. Now it holds the file."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.reg = {"counter": 0, "bugs": {}}
        self.panic = os.path.join(self.dir, "panic-full-x.panic")
        with open(self.panic, "w") as f:
            f.write("panic body")

    def test_report_is_kept_under_the_bug(self):
        br.route_one(self.reg, self.dir, analyzed(self.panic))
        rec = self.reg["bugs"]["Drv:m:READ"]
        kept = os.path.join(br.bug_reports_dir(self.dir, rec), "panic-full-x.panic")
        self.assertTrue(os.path.exists(kept))
        with open(kept) as f:
            self.assertEqual(f.read(), "panic body")

    def test_kept_report_survives_the_original(self):
        """A hardlink is a second name, not a pointer: rotating the OS copy away
        must not take the evidence with it."""
        br.route_one(self.reg, self.dir, analyzed(self.panic))
        rec = self.reg["bugs"]["Drv:m:READ"]
        kept = os.path.join(br.bug_reports_dir(self.dir, rec), "panic-full-x.panic")
        os.unlink(self.panic)
        with open(kept) as f:
            self.assertEqual(f.read(), "panic body")

    def test_keeping_costs_no_extra_blocks(self):
        br.route_one(self.reg, self.dir, analyzed(self.panic))
        self.assertEqual(fsutil.link_count(self.panic), 2)

    def test_missing_report_does_not_stop_filing(self):
        """Failing to hold a copy must never lose the crash itself."""
        a = analyzed(os.path.join(self.dir, "gone.panic"))
        br.route_one(self.reg, self.dir, a)
        self.assertEqual(len(self.reg["bugs"]["Drv:m:READ"]["crashes"]), 1)

    def test_reroute_is_idempotent_for_evidence(self):
        br.route_one(self.reg, self.dir, analyzed(self.panic))
        br.route_one(self.reg, self.dir, analyzed(self.panic))
        self.assertEqual(fsutil.link_count(self.panic), 2)


class HardlinkTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.src = os.path.join(self.dir, "src")
        with open(self.src, "w") as f:
            f.write("data")

    def test_links_on_the_same_volume(self):
        dst = os.path.join(self.dir, "sub", "dst")
        self.assertTrue(fsutil.hardlink_or_copy(self.src, dst))
        self.assertEqual(fsutil.link_count(self.src), 2)

    def test_existing_destination_is_left_alone(self):
        dst = os.path.join(self.dir, "dst")
        with open(dst, "w") as f:
            f.write("other")
        self.assertFalse(fsutil.hardlink_or_copy(self.src, dst))
        with open(dst) as f:
            self.assertEqual(f.read(), "other")

    def test_link_count_of_a_missing_file_is_zero(self):
        self.assertEqual(fsutil.link_count(os.path.join(self.dir, "absent")), 0)


if __name__ == "__main__":
    unittest.main(verbosity=1)
