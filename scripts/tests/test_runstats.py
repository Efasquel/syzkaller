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


class CurveTest(unittest.TestCase):
    """`curve`: blocks and exec from the driver's sampled series; a resetting
    bench counter accumulated across restarts instead of sawtoothing."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.wd = self.root / "workdir" / "Drv" / "run"
        (self.wd / "results").mkdir(parents=True)
        rs.set_root(self.root)

    def test_exec_total_accumulates_across_restarts(self):
        bench(self.wd / "results" / "bench-20260901-120000.json",
              [sample(60, 60, 100, 10), sample(120, 120, 200, 20)])
        bench(self.wd / "results" / "bench-20260901-130000.json",
              [sample(60, 60, 50, 20), sample(120, 120, 150, 25)])   # counter restarted
        rows = rs.curve_rows(self.wd, "exec total")
        self.assertEqual([v for _, v, _ in rows], [100, 200, 250, 350])
        # a cumulative field is left alone
        self.assertEqual([v for _, v, _ in rs.curve_rows(self.wd, "coverage")], [10, 20, 20, 25])

    def test_blocks_and_exec_come_from_the_sampled_series(self):
        with open(self.wd / "results" / "progress.jsonl", "w") as f:
            f.write(json.dumps({"at": 1000, "fuzz_s": 600, "exec": 5000, "blocks": 300}) + "\n")
            f.write("not json\n")
            f.write(json.dumps({"at": 1600, "fuzz_s": 1200, "exec": 9000, "blocks": None}) + "\n")
        self.assertEqual(rs.curve_rows(self.wd, "blocks"), [(600, 300, 1000)])
        self.assertEqual(rs.curve_rows(self.wd, "exec"), [(600, 5000, 1000), (1200, 9000, 1600)])
        buf = io.StringIO()
        with redirect_stdout(buf):
            rs.cmd_curve(type("A", (), {"run": "Drv/run", "field": "exec"})())
        self.assertEqual(buf.getvalue().splitlines()[0], "fuzz_hours\texec\twall")
        self.assertTrue(buf.getvalue().splitlines()[1].startswith("0.1667\t5000\t"))

    def test_cover_log_lines_may_carry_a_timestamp(self):
        (self.wd / "cover.log").write_text("0x1 1761030412\n0x2 1761030412\n0x2\n")
        (self.wd / "results" / "cover-1.log").write_text("0x3\n")
        self.assertEqual(rs.cover_blocks(self.wd), 3)


class StateDirNoiseTest(unittest.TestCase):
    """campaigns/.state holds more than state files: the operator's request
    lists (a JSON list) must not crash the campaign lookups."""

    def test_request_lists_are_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "campaigns" / ".state").mkdir(parents=True)
            (root / "campaigns" / ".state" / "camp.requests.json").write_text(
                json.dumps([{"verb": "next", "item": None, "at": 1}]))
            (root / "campaigns" / ".state" / "camp.json").write_text(
                json.dumps({"name": "camp", "current_config": "/c/X_v.cfg",
                            "started_at": "2026-10-01T00:00:00+00:00", "incidents": []}))
            rs.set_root(root)
            self.assertEqual(rs.campaign_for("X_v")["name"], "camp")
            self.assertEqual(len(rs.campaign_windows("X_v")), 1)


class PlanLayoutTest(unittest.TestCase):
    """campaign-planning.md §4: a run is still one workdir, but plan-layout items
    live at campaigns/<name>/<config-id>/<item-id>/workdir. Discovery, identity,
    per-item clocks/bugs, and `compare --by config` mean +/- spread, all without
    disturbing the legacy workdir/<Driver>/<variant> tree that coexists with it.

    The fixture is the minimum real shape: one legacy run plus one campaign whose
    single config ran twice -- the 3-sample comparison an evaluation makes, here
    with 2 so the spread is defined."""

    def _item(self, cfg_id, item_id, execs, coverage):
        """Write campaigns/eval/<cfg_id>/<item_id>/ with item.json, quarantine
        and a bench, as fuzz-campaign.render_item/item_paths lay it out."""
        idir = self.root / "campaigns" / "eval" / cfg_id / item_id
        wd = idir / "workdir"
        (wd / "results").mkdir(parents=True)
        (idir / "item.json").write_text(json.dumps({
            "campaign": "eval", "item": item_id,
            "config": str(self.root / "config" / ("%s.cfg" % cfg_id)),
            "workdir": str(wd)}))
        (idir / "quarantine.json").write_text(json.dumps(
            {"hard": ["sel_a"], "catalog": {"sig1": {}}}))
        bench(wd / "results" / "bench-20260901-120000.json",
              [sample(execs // 1, execs, execs, coverage)])
        (wd / "cover.log").write_text("".join("0x%x\n" % i for i in range(coverage)))
        return wd

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        # A legacy run, which must keep working exactly as before.
        leg = self.root / "workdir" / "AppleX" / "260901_cov_gram"
        (leg / "results").mkdir(parents=True)
        bench(leg / "results" / "bench-20260901-120000.json",
              [sample(3600, 3600, 5000, 42)])
        # One authored config, run twice -> two item folders under one config.
        (self.root / "config").mkdir()
        (self.root / "config" / "AppleFDE_gram.cfg").write_text(json.dumps(
            {"enable_syscalls": ["a", "b", "c"], "disable_syscalls": ["d"]}))
        # item-1: 1.0h fuzzing, 100 blocks, 1000 execs, found BUG-0001.
        # item-2: 2.0h fuzzing, 140 blocks, 2000 execs, found nothing.
        self.wd1 = self._item("AppleFDE_gram", "AppleFDE_gram-1", 1000, 100)
        self.wd2 = self._item("AppleFDE_gram", "AppleFDE_gram-2", 2000, 140)
        (self.root / "campaigns" / "eval" / "state.json").write_text(json.dumps({
            "name": "eval", "status": "done",
            # Live top-level counters belong to no finished item; the per-item
            # record is what collect must read.
            "active_seconds": 99999,
            "items": {
                "AppleFDE_gram-1": {"status": "done", "reason": "max_hours",
                    "clocks": {"prep_seconds": 100, "active_seconds": 3600,
                               "triage_seconds": 200, "overhead_seconds": 50},
                    "crashes": 1, "hangs": 0, "bug_ids": ["BUG-0001"]},
                "AppleFDE_gram-2": {"status": "done", "reason": "next",
                    "clocks": {"prep_seconds": 120, "active_seconds": 7200,
                               "triage_seconds": 0, "overhead_seconds": 60},
                    "crashes": 0, "hangs": 0, "bug_ids": []}},
            "incidents": [{"item": "AppleFDE_gram-1", "kind": "crash",
                           "bug_ids": ["BUG-0001"]}],
        }))
        (self.root / "campaigns" / "bugs").mkdir(parents=True)
        (self.root / "campaigns" / "bugs" / "registry.json").write_text(json.dumps({
            "bugs": {"BUG-0001": {
                "id": "BUG-0001", "bug_key": "fde::panic",
                "reproducer": {"verified": True},
                "crashes": [{"origin": "fuzz", "campaign": "eval",
                             "item": "AppleFDE_gram-1", "config": "AppleFDE_gram",
                             "report": "panic-full-2026-09-01-120500.panic",
                             "first_seen": "2026-09-01T12:05:00Z"}]}}}))
        rs.set_root(self.root)

    def test_discovers_legacy_and_item_workdirs(self):
        """All three: the legacy run plus both samples of the campaign config."""
        names = sorted(rs.run_name(w) for w in rs.discover_runs())
        self.assertEqual(names, ["AppleX/260901_cov_gram",
                                 "eval/AppleFDE_gram/AppleFDE_gram-1",
                                 "eval/AppleFDE_gram/AppleFDE_gram-2"])

    def test_ledger_is_bugs_once_migrated_else_campaigns_bugs(self):
        """The same rule as fuzz-campaign.py: `migrate` moves the ledger up to
        <tree>/bugs, and a tree that has one must be read there -- otherwise a
        migrated box reports every run as finding nothing."""
        self.assertEqual(rs.BUGS_DIR, self.root / "campaigns" / "bugs")
        (self.root / "bugs").mkdir()
        rs.set_root(self.root)
        self.assertEqual(rs.BUGS_DIR, self.root / "bugs")

    def test_item_run_name_is_three_components(self):
        self.assertEqual(rs.run_name(self.wd1),
                         "eval/AppleFDE_gram/AppleFDE_gram-1")

    def test_config_id_is_the_authored_stem_not_parent_plus_name(self):
        """It comes from item.json's config, so every sample of a config shares
        one id -- which is what `compare --by config` groups on."""
        self.assertEqual(rs.config_id_for(self.wd1), "AppleFDE_gram")
        self.assertEqual(rs.config_id_for(self.wd2), "AppleFDE_gram")

    def test_driver_and_variant_from_the_config_stem(self):
        r = rs.collect(self.wd1)
        self.assertEqual(r["driver"], "AppleFDE")
        self.assertEqual(r["grammar"], "gram")

    def test_collect_reads_this_items_clocks_not_the_lifetime_sum(self):
        """The per-item banked clocks, never the campaign's live counter or a sum
        across samples."""
        r1 = rs.collect(self.wd1)
        self.assertEqual(r1["campaign"], "eval")
        self.assertEqual(r1["campaign_fuzz_s"], 3600)
        self.assertEqual(r1["prep_s"], 100)
        self.assertEqual(r1["minimize_s"], 200)
        r2 = rs.collect(self.wd2)
        self.assertEqual(r2["campaign_fuzz_s"], 7200)

    def test_bugs_attributed_by_campaign_and_item(self):
        self.assertEqual(rs.collect(self.wd1)["bugs"], 1)
        self.assertEqual(rs.collect(self.wd1)["bugs_verified"], 1)
        self.assertEqual(rs.collect(self.wd2)["bugs"], 0)

    def test_quarantine_read_from_the_item_folder(self):
        r = rs.collect(self.wd1)
        self.assertEqual(r["benched"], 1)
        self.assertEqual(r["catalogued"], 1)

    def test_config_facts_read_from_the_authored_path(self):
        r = rs.collect(self.wd1)
        self.assertEqual(r["enabled"], 3)
        self.assertEqual(r["disabled"], 1)

    def test_compare_by_config_gives_n2_with_mean_and_spread(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rs.cmd_compare(type("A", (), {"all": False, "driver": None,
                                          "by": "config"})())
        out = buf.getvalue()
        # One group for the config, counting both samples.
        line = next(ln for ln in out.splitlines() if "AppleFDE_gram" in ln)
        self.assertIn(" 2 ", " %s " % line)        # N column
        # blocks mean 120 with spread 100..140 (per-run maximum, averaged).
        self.assertIn("120", line)
        self.assertIn("100..140", line)
        # The legacy single run is flagged as an anecdote, not a measurement.
        self.assertIn("anecdote", out)

    def test_show_accepts_the_three_component_name(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rs.cmd_show(type("A", (), {"run": "eval/AppleFDE_gram/AppleFDE_gram-1",
                                       "campaign": None})())
        self.assertIn("eval/AppleFDE_gram/AppleFDE_gram-1", buf.getvalue())

    def test_curve_accepts_the_three_component_name(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rs.cmd_curve(type("A", (), {"run": "eval/AppleFDE_gram/AppleFDE_gram-1",
                                        "field": "coverage"})())
        self.assertEqual(buf.getvalue().splitlines()[0], "fuzz_hours\tcoverage\twall")

    def test_list_shows_a_campaign_column(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rs.cmd_list(type("A", (), {"all": False, "driver": None,
                                       "empty": False})())
        out = buf.getvalue()
        self.assertIn("CAMPAIGN", out)
        self.assertIn("eval", out)
        # The legacy run has no plan campaign, so it shows '-'.
        legacy = next(ln for ln in out.splitlines() if "260901_cov_gram" in ln)
        self.assertRegex(legacy, r"260901_cov_gram\s+-\s")
