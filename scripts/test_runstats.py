#!/usr/bin/env python3
"""Tests for runstats: the three ways naive run comparison goes wrong."""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import runstats as rs  # noqa: E402


def bench(path, samples):
    """syz-manager writes pretty-printed objects back to back, not JSONL."""
    with open(path, "w") as f:
        for s in samples:
            json.dump(s, f, indent=2)
            f.write("\n")


def sample(uptime, fuzz_s, execs, coverage, corpus=0, crashes=0):
    return {"uptime": uptime, "fuzzing": int(fuzz_s * 1e9), "exec total": execs,
            "coverage": coverage, "corpus": corpus, "crashes": crashes}


class BenchParseTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        (self.dir / "results").mkdir()

    def test_reads_a_concatenated_object_stream(self):
        bench(self.dir / "results" / "bench-20260901-120000.json",
              [sample(60, 60, 100, 10), sample(120, 120, 200, 20)])
        rows = rs.parse_bench(self.dir / "results" / "bench-20260901-120000.json")
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[-1]["exec total"], 200)

    def test_truncated_tail_keeps_what_was_written(self):
        """A panic cuts the last write mid-object; the earlier samples are still
        good data and must not be thrown away."""
        p = self.dir / "results" / "bench-20260901-120000.json"
        bench(p, [sample(60, 60, 100, 10)])
        with open(p, "a") as f:
            f.write('{\n  "uptime": 12')
        self.assertEqual(len(rs.parse_bench(p)), 1)

    def test_empty_bench_yields_nothing(self):
        p = self.dir / "results" / "bench-20260901-120000.json"
        p.write_text("")
        self.assertEqual(rs.parse_bench(p), [])


class MergeTest(unittest.TestCase):
    """A run on this target is dozens of manager restarts."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        (self.dir / "results").mkdir()
        bench(self.dir / "results" / "bench-20260901-120000.json",
              [sample(60, 60, 1000, 50, corpus=10)])
        bench(self.dir / "results" / "bench-20260901-130000.json",
              [sample(60, 60, 800, 55, corpus=12)])

    def test_resetting_counters_are_summed(self):
        """exec total restarts at 0 each segment; reading the last sample alone
        under-reports execution by an order of magnitude."""
        self.assertEqual(rs.merge_bench(self.dir)["exec_total"], 1800)

    def test_cumulative_counters_are_maxed_not_summed(self):
        """coverage is rebuilt from corpus.db at startup, so it is already
        cumulative; summing it would multiply-count the same blocks."""
        m = rs.merge_bench(self.dir)
        self.assertEqual(m["coverage"], 55)
        self.assertEqual(m["corpus"], 12)

    def test_fuzz_seconds_accumulate_across_segments(self):
        self.assertAlmostEqual(rs.merge_bench(self.dir)["fuzz_seconds"], 120.0)

    def test_segments_counted(self):
        self.assertEqual(rs.merge_bench(self.dir)["segments"], 2)

    def test_no_bench_is_no_data_not_zero(self):
        empty = Path(tempfile.mkdtemp())
        (empty / "results").mkdir()
        (empty / "results" / "bench-20260901-120000.json").write_text("")
        self.assertEqual(rs.merge_bench(empty)["segments"], 0)


class FuzzClockTest(unittest.TestCase):
    """A bug found 40 wall-minutes in, 30 of them rebooting, was found after 10
    minutes of fuzzing -- and only the second number says anything about the
    fuzzer."""

    def setUp(self):
        # wall advances 100s per sample; fuzzing advances only 10s per sample.
        self.series = [(int(10e9), 1000, {}), (int(20e9), 1100, {}),
                       (int(30e9), 1200, {})]

    def test_maps_wall_onto_the_fuzz_clock(self):
        self.assertAlmostEqual(rs.fuzz_seconds_at(self.series, 1100), 20.0)

    def test_interpolates_within_a_tick(self):
        self.assertAlmostEqual(rs.fuzz_seconds_at(self.series, 1150), 25.0)

    def test_before_the_first_sample_is_the_first_value(self):
        self.assertAlmostEqual(rs.fuzz_seconds_at(self.series, 900), 10.0)

    def test_after_the_last_sample_is_all_of_it(self):
        self.assertAlmostEqual(rs.fuzz_seconds_at(self.series, 9999), 30.0)

    def test_wall_time_is_not_fuzz_time(self):
        """The whole point: 200s of wall clock is 20s of fuzzing here."""
        self.assertNotAlmostEqual(rs.fuzz_seconds_at(self.series, 1200), 200.0)

    def test_empty_series_is_none(self):
        self.assertIsNone(rs.fuzz_seconds_at([], 1000))
        self.assertIsNone(rs.fuzz_seconds_at(self.series, None))


class VariantTest(unittest.TestCase):
    def test_parses_the_convention(self):
        v = rs.parse_variant("260804_cov_gram")
        self.assertEqual((v["date"], v["cov"], v["grammar"]),
                         ("260804", "cov", "gram"))

    def test_modifiers_are_captured(self):
        v = rs.parse_variant("260709_cov_gram-no23_2")
        self.assertEqual(v["grammar"], "gram")
        self.assertIn("no23", v["mods"])
        self.assertEqual(v["seq"], "2")

    def test_retired_spelling_is_normalised(self):
        self.assertEqual(rs.parse_variant("260610_cov_nogrammar")["grammar"],
                         "nogram")

    def test_gramsel_extended(self):
        v = rs.parse_variant("260707_cov_gramsel-extended")
        self.assertEqual(v["grammar"], "gramsel")
        self.assertIn("extended", v["mods"])

    def test_test_configs_are_flagged(self):
        self.assertTrue(rs.parse_variant("260831_cov_gram_no7_test")["test"])
        self.assertFalse(rs.parse_variant("260831_cov_gram")["test"])


class CorpusTest(unittest.TestCase):
    def test_corpus_db_is_not_sqlite(self):
        """It is syzkaller's own format; the program count comes from bench."""
        d = Path(tempfile.mkdtemp())
        (d / "corpus.db").write_bytes(b"\xdb\xad\x0b\x00rest")
        self.assertEqual(rs.corpus_bytes(d), 8)

    def test_missing_corpus_is_none(self):
        self.assertIsNone(rs.corpus_bytes(Path(tempfile.mkdtemp())))


class ReportTest(unittest.TestCase):
    def test_hours_helper_handles_none(self):
        self.assertEqual(rs._h(None), "-")
        self.assertEqual(rs._h(3600), "1.0")

    def test_curve_emits_fuzz_hours_not_wall(self):
        d = Path(tempfile.mkdtemp())
        (d / "AppleX").mkdir()
        wd = d / "AppleX" / "260901_cov_gram"
        (wd / "results").mkdir(parents=True)
        bench(wd / "results" / "bench-20260901-120000.json",
              [sample(3600, 60, 100, 42)])
        rs.set_root(d.parent)          # rebind, then point WORKDIR_ROOT at d
        rs.WORKDIR_ROOT = d
        buf = io.StringIO()
        with redirect_stdout(buf):
            rs.cmd_curve(type("A", (), {"run": "AppleX/260901_cov_gram",
                                        "field": "coverage"})())
        body = buf.getvalue().splitlines()
        self.assertEqual(body[0].split("\t")[0], "fuzz_hours")
        # 3600s of uptime but only 60s of fuzzing -> 0.0167 h, not 1.0
        self.assertAlmostEqual(float(body[1].split("\t")[0]), 60 / 3600.0, places=3)


class AttributionTest(unittest.TestCase):
    """How a bug gets tied to a run, and why the answer is often 'cannot tell'."""

    def test_panic_time_beats_filing_time(self):
        """first_seen is when bug_registry routed the report, which can be an
        hour later; the basename carries when the panic actually happened."""
        e = rs.crash_epoch({"report": "panic-full-2026-08-27-103027.0002.panic",
                            "first_seen": "2026-08-27T09:25:04Z"})
        self.assertAlmostEqual(e, rs.timefmt.to_epoch("20260827-103027"))

    def test_falls_back_to_filing_time(self):
        e = rs.crash_epoch({"report": "weird.panic",
                            "first_seen": "2026-08-27T09:25:04Z"})
        self.assertAlmostEqual(e, rs.timefmt.to_epoch("2026-08-27T09:25:04Z"))

    def test_no_timestamp_at_all_is_none(self):
        self.assertIsNone(rs.crash_epoch({"report": "x.panic"}))

    def test_window_spans_the_series(self):
        series = [(0, 1000, {}), (0, 2000, {}), (0, 1500, {})]
        self.assertEqual(rs.run_window(series), (1000, 2000))

    def test_empty_series_has_no_window(self):
        self.assertIsNone(rs.run_window([]))


class NormalisationTest(unittest.TestCase):
    """Effort-normalised yield, and the averaging trap."""

    def test_blocks_per_effort_is_averaged_per_run_not_pooled(self):
        """mean(blocks)/total(hours) would punish a variant purely for having
        been left running longer. Each run is normalised by its OWN effort
        first, then averaged."""
        runs = [{"blocks": 100, "fuzz_seconds": 3600, "execs": 1000000},
                {"blocks": 100, "fuzz_seconds": 36000, "execs": 10000000}]
        per_h = [r["blocks"] / (r["fuzz_seconds"] / 3600.0) for r in runs]
        self.assertAlmostEqual(sum(per_h) / len(per_h), 55.0)
        pooled = (sum(r["blocks"] for r in runs)
                  / (sum(r["fuzz_seconds"] for r in runs) / 3600.0))
        self.assertNotAlmostEqual(pooled, 55.0)   # the trap this avoids

    def test_per_million_execs_is_rate_independent(self):
        """Two runs reaching the same blocks for the same executions score the
        same even when one ran at half the rate."""
        fast = {"blocks": 100, "execs": 1000000, "fuzz_seconds": 1000}
        slow = {"blocks": 100, "execs": 1000000, "fuzz_seconds": 2000}
        self.assertEqual(fast["blocks"] / (fast["execs"] / 1e6),
                         slow["blocks"] / (slow["execs"] / 1e6))


class ScopingTest(unittest.TestCase):
    """A config IS a workdir, so re-running it as a new campaign appends
    segments to the same directory. Folding them together reports one
    experiment's numbers as another's -- a real 916,607-exec error in practice."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        (self.dir / "results").mkdir()
        bench(self.dir / "results" / "bench-20260831-154135.json",
              [sample(7200, 5220, 916607, 300)])
        bench(self.dir / "results" / "bench-20260901-145429.json",
              [sample(68000, 38400, 5260905, 316)])

    def test_unscoped_folds_every_campaign_together(self):
        m = rs.merge_bench(self.dir)
        self.assertEqual(m["exec_total"], 916607 + 5260905)

    def test_since_excludes_the_earlier_campaign(self):
        cutoff = rs.timefmt.to_epoch("20260901-000000")
        m = rs.merge_bench(self.dir, since=cutoff)
        self.assertEqual(m["exec_total"], 5260905)
        self.assertEqual(m["segments"], 1)

    def test_until_excludes_the_later_campaign(self):
        cutoff = rs.timefmt.to_epoch("20260901-000000")
        m = rs.merge_bench(self.dir, until=cutoff)
        self.assertEqual(m["exec_total"], 916607)

    def test_segment_rows_expose_the_split(self):
        """The breakdown is what made the discrepancy diagnosable, so it is
        part of the output rather than something to reconstruct by hand."""
        rows = rs.merge_bench(self.dir)["segment_rows"]
        self.assertEqual(len(rows), 2)
        self.assertEqual([r["execs"] for r in rows], [916607, 5260905])

    def test_empty_segments_are_listed_not_counted(self):
        (self.dir / "results" / "bench-20260830-120000.json").write_text("")
        m = rs.merge_bench(self.dir)
        self.assertEqual(m["segments"], 2)
        self.assertTrue(any(r.get("empty") for r in m["segment_rows"]))


class EfficiencyTest(unittest.TestCase):
    """Session uptime is not time spent executing programs."""

    def test_fuzzing_is_a_fraction_of_uptime(self):
        d = Path(tempfile.mkdtemp())
        (d / "results").mkdir()
        # 18.9h alive, 10.7h executing -- the real measured ratio.
        bench(d / "results" / "bench-20260901-145429.json",
              [sample(68040, 38520, 5260905, 316)])
        m = rs.merge_bench(d)
        ratio = m["fuzz_seconds"] / m["uptime_seconds"]
        self.assertLess(ratio, 0.6)
        self.assertGreater(ratio, 0.5)


if __name__ == "__main__":
    unittest.main(verbosity=1)
