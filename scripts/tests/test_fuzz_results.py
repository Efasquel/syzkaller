#!/usr/bin/env python3
"""Tests for fuzz-results.py: commits, chunking, tags, record, restore.

Each test gets a fresh clone of a bare repo in a temp dir and a fake workdir
laid out like fuzz-run's (workdir/<kext>/<name>). syz-db is not needed: without
it the corpus is still committed as corpus.db, just not unpacked.
"""

import importlib.util
import json
import lzma
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "fuzz-results.py"


def _load():
    spec = importlib.util.spec_from_file_location("fuzz_results", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


fr = _load()


def sh(*args, cwd=None):
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True).stdout


class ResultsRepoTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.remote = self.tmp / "remote.git"
        sh("git", "init", "--quiet", "--bare", "-b", "main", str(self.remote))
        self.repo = self.tmp / "results"
        sh("git", "clone", "--quiet", str(self.remote), str(self.repo))
        sh("git", "-C", str(self.repo), "config", "user.name", "t")
        sh("git", "-C", str(self.repo), "config", "user.email", "t@t")
        sh("git", "-C", str(self.repo), "commit", "--quiet", "--allow-empty", "-m", "init")
        sh("git", "-C", str(self.repo), "push", "--quiet", "origin", "main")
        self.wd = self.tmp / "workdir" / "KextX" / "260101_cov"
        (self.wd / "results").mkdir(parents=True)
        (self.wd / "corpus.db").write_bytes(b"db-v1")
        (self.wd / "cover.log").write_text("0x1\n0x2\n")
        (self.wd / "results" / "run-20260101-100000.log").write_text(
            "stats coverage=40 exec total=100 (5/sec)\n")
        self.cfg = self.tmp / "KextX_260101_cov.cfg"
        self.cfg.write_text(json.dumps({"workdir": str(self.wd), "kernel_obj": "/bkc",
                                        "kext_coverage": {"kext_id": 2}}))
        self.env = dict(os.environ, SYZ_DB_BIN="/nonexistent")

    def tearDown(self):
        self._tmp.cleanup()

    def run_cli(self, *args):
        p = subprocess.run([sys.executable, str(SCRIPT), "--repo", str(self.repo)] + list(args),
                           capture_output=True, text=True, env=self.env)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        return p.stdout

    def commit(self, event, *extra):
        return self.run_cli("commit", str(self.cfg), "--event", event,
                            "--campaign", "C1", *extra)

    def log(self, fmt="%s"):
        return sh("git", "-C", str(self.repo), "log", "--format=" + fmt).splitlines()

    def tags(self):
        return sorted(sh("git", "-C", str(self.repo), "tag", "-l").split())

    def test_start_commits_trailers_tags_and_pushes(self):
        self.commit("start")
        body = sh("git", "-C", str(self.repo), "log", "-1", "--format=%B")
        self.assertTrue(body.startswith("C1: start corpus -, cov 2, 100 execs"), body)
        for tr in ("Campaign: C1", "Event: start", "Coverage: 2", "Signal: 40",
                   "Exec-Total: 100", "BKC: /bkc", "Kext-Id: 2", "Session: 20260101-100000"):
            self.assertIn(tr, body)
        unit = self.repo / "KextX" / "260101_cov"
        self.assertEqual((unit / "corpus.db").read_bytes(), b"db-v1")
        self.assertTrue((unit / "config" / self.cfg.name).is_file())
        self.assertEqual(self.tags(), ["C1/start"])
        remote_head = sh("git", "-C", str(self.remote), "rev-parse", "main").strip()
        self.assertEqual(remote_head, self.log("%H")[0])
        self.assertIn("C1/start", sh("git", "-C", str(self.remote), "tag", "-l"))

    def test_corpus_event_skips_when_nothing_moved(self):
        self.commit("start")
        n = len(self.log())
        self.commit("corpus")
        self.assertEqual(len(self.log()), n)
        (self.wd / "corpus.db").write_bytes(b"db-v2")
        self.commit("corpus")
        self.assertEqual(len(self.log()), n + 1)
        self.assertIn("Event: corpus", sh("git", "-C", str(self.repo), "log", "-1", "--format=%B"))

    def test_freq_chunks_are_append_only_and_restore_joins_them(self):
        fl = self.wd / "freqlab"
        (fl / "progs").mkdir(parents=True)
        (fl / "records.jsonl").write_text('{"id":1}\n{"id":2}\n{"id":')   # torn tail
        (fl / "progs" / "1.syz").write_text("p1\n")
        self.commit("start")
        self.commit("crash")
        unit = self.repo / "KextX" / "260101_cov"
        c1 = unit / "freqlab" / "records.0001.jsonl.xz"
        self.assertEqual(lzma.decompress(c1.read_bytes()), b'{"id":1}\n{"id":2}\n')
        first = c1.read_bytes()
        with open(fl / "records.jsonl", "a") as f:
            f.write('3}\n')
        (fl / "progs" / "2.syz").write_text("p2\n")
        os.utime(fl / "progs" / "2.syz", (os.path.getmtime(fl / "progs" / "1.syz") + 5,) * 2)
        self.commit("end")
        self.assertEqual(c1.read_bytes(), first, "an old chunk was rewritten")
        self.assertEqual(lzma.decompress((unit / "freqlab" / "records.0002.jsonl.xz").read_bytes()),
                         b'{"id":3}\n')
        out = self.tmp / "restored"
        self.run_cli("restore", "KextX/260101_cov", str(out))
        self.assertEqual((out / "freqlab" / "records.jsonl").read_text(),
                         '{"id":1}\n{"id":2}\n{"id":3}\n')
        self.assertEqual(sorted(p.name for p in (out / "freqlab" / "progs").iterdir()),
                         ["1.syz", "2.syz"])
        self.assertEqual((out / "corpus.db").read_bytes(), b"db-v1")

    def test_restore_refuses_a_non_empty_destination(self):
        self.commit("start")
        out = self.tmp / "busy"
        out.mkdir()
        (out / "corpus.db").write_bytes(b"live")
        p = subprocess.run([sys.executable, str(SCRIPT), "--repo", str(self.repo), "restore",
                            "KextX/260101_cov", str(out)], capture_output=True, text=True)
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual((out / "corpus.db").read_bytes(), b"live")

    def test_incident_tags_count_up_and_bundles_drop_cores_and_freq(self):
        b = self.wd / "artifacts" / "crashes" / "20260101-110000"
        (b / "freq").mkdir(parents=True)
        (b / "freq" / "p.csv").write_text("x\n")
        (b / "event.json").write_text("{}")
        (b / "x.kernel.core.gz").write_bytes(b"core")
        self.commit("start")
        self.commit("crash")
        self.commit("crash")
        self.assertEqual(self.tags(), ["C1/crash-1", "C1/crash-2", "C1/start"])
        dst = self.repo / "KextX" / "260101_cov" / "artifacts" / "crashes" / "20260101-110000"
        self.assertTrue((dst / "event.json").is_file())
        self.assertFalse((dst / "freq").exists())
        self.assertFalse((dst / "x.kernel.core.gz").exists())
        cores = json.loads((dst / "cores.json").read_text())
        self.assertEqual(cores[0]["size"], 4)

    def test_record_tag_only_when_the_kext_record_is_beaten(self):
        self.commit("start")
        (self.wd / "cover.log").write_text("0x1\n0x2\n0x3\n")
        self.commit("corpus")
        peak = self.log("%H")[0]
        self.commit("end")
        self.assertIn("KextX/record-cov-3", self.tags())
        tagged = sh("git", "-C", str(self.repo), "rev-list", "-n1", "KextX/record-cov-3").strip()
        self.assertEqual(tagged, peak, "record must point where the max was first reached")
        # A second campaign that does not beat 3 gets no record tag.
        (self.wd / "cover.log").write_text("0x9\n")
        for ev in ("start", "end"):
            self.run_cli("commit", str(self.cfg), "--event", ev, "--campaign", "C2")
        self.assertEqual([t for t in self.tags() if "record" in t], ["KextX/record-cov-3"])

    def test_push_failure_does_not_fail_the_commit(self):
        sh("git", "-C", str(self.repo), "remote", "set-url", "origin", str(self.tmp / "gone.git"))
        out = self.commit("start")
        self.assertIn("push failed", out)
        self.assertIn("Event: start", sh("git", "-C", str(self.repo), "log", "-1", "--format=%B"))

    def test_backfill_dates_commits_and_restores_each_corpus(self):
        snap = self.wd / "snapshots" / "20251231-090000_auto"
        snap.mkdir(parents=True)
        (snap / "corpus.db").write_bytes(b"db-old")
        (snap / "manifest.json").write_text(json.dumps({"created_at": "2025-12-31T09:00:00+01:00"}))
        hang = self.wd / "artifacts" / "hangs" / "20260101-120000"
        hang.mkdir(parents=True)
        (hang / "corpus.db").write_bytes(b"db-hang")
        (hang / "event.json").write_text(json.dumps({"kind": "hang",
                                                     "collected_at": "2026-01-01T12:00:00+01:00"}))
        (hang / "manifest.txt").write_text("basic blks : 0 (this run) / 509 (all runs, cover_log)\n")
        self.run_cli("backfill", str(self.cfg), "--campaign", "C0")
        subjects = self.log("%ad %s")
        self.assertEqual(len(subjects), 4, subjects)          # init, snap, hang, current
        self.assertIn("2025", subjects[2])
        self.assertIn("cov 509", subjects[1])
        old = sh("git", "-C", str(self.repo), "show", "HEAD~2:KextX/260101_cov/corpus.db")
        self.assertEqual(old, "db-old")
        self.assertIn("KextX/record-cov-509", self.tags())
        # Idempotent: a second backfill adds only the current-state commit.
        self.run_cli("backfill", str(self.cfg), "--campaign", "C0")
        self.assertEqual(len(self.log()), 5)

    def test_unit_and_kext_land_under_a_three_component_unit(self):
        # The new layout runs a config several times under one campaign; each
        # item gets its own 3-component unit and names its own kext for the tag.
        (self.wd / "cover.log").write_text("0xA\n")          # one block -> record-cov-1
        unit = "fde_eval/KextX_gram/KextX_gram-1"
        for ev in ("start", "end"):
            self.run_cli("commit", str(self.cfg), "--event", ev, "--campaign", "fde_eval",
                         "--tag-prefix", "fde_eval/KextX_gram-1", "--unit", unit,
                         "--kext", "AppleKext")
        d = self.repo / "fde_eval" / "KextX_gram" / "KextX_gram-1"
        self.assertEqual((d / "corpus.db").read_bytes(), b"db-v1")
        self.assertTrue((d / "config" / self.cfg.name).is_file())
        # record-cov is tagged for the authored kext, not the campaign name.
        self.assertIn("AppleKext/record-cov-1", self.tags())
        self.assertNotIn("fde_eval/record-cov-1", self.tags())
        # The legacy <kext>/<name> unit was not written.
        self.assertFalse((self.repo / "KextX" / "260101_cov").exists())

    def test_two_items_of_one_config_do_not_overwrite_each_other(self):
        base = "fde_eval/KextX_gram"
        for item in ("KextX_gram-1", "KextX_gram-2"):
            (self.wd / "corpus.db").write_bytes(b"db-" + item.encode()[-1:])
            self.run_cli("commit", str(self.cfg), "--event", "start", "--campaign", "fde_eval",
                         "--unit", "%s/%s" % (base, item), "--kext", "AppleKext")
        d1 = self.repo / "fde_eval" / "KextX_gram" / "KextX_gram-1" / "corpus.db"
        d2 = self.repo / "fde_eval" / "KextX_gram" / "KextX_gram-2" / "corpus.db"
        self.assertEqual(d1.read_bytes(), b"db-1")
        self.assertEqual(d2.read_bytes(), b"db-2")

    def test_restore_accepts_a_three_component_unit(self):
        unit = "fde_eval/KextX_gram/KextX_gram-1"
        self.run_cli("commit", str(self.cfg), "--event", "start", "--campaign", "fde_eval",
                     "--unit", unit, "--kext", "AppleKext")
        out = self.tmp / "restored3"
        self.run_cli("restore", unit, str(out))
        self.assertEqual((out / "corpus.db").read_bytes(), b"db-v1")
        self.assertTrue((out / "config" / self.cfg.name).is_file())

    def test_cover_log_named_by_the_config_is_stored_as_cover_log(self):
        (self.wd / "cover.log").unlink()
        (self.wd / "kcov.log").write_text("0x1\n0x2\n0x3\n")
        cfg2 = self.tmp / "named.cfg"
        cfg2.write_text(json.dumps({"workdir": str(self.wd), "kernel_obj": "/bkc",
                                    "kext_coverage": {"kext_id": 2, "cover_log": "kcov.log"}}))
        self.run_cli("commit", str(cfg2), "--event", "start", "--campaign", "C1")
        unit = self.repo / "KextX" / "260101_cov"
        self.assertEqual((unit / "cover.log").read_text(), "0x1\n0x2\n0x3\n")
        self.assertIn("Coverage: 3", sh("git", "-C", str(self.repo), "log", "-1", "--format=%B"))


class ChunkLinesTest(unittest.TestCase):
    def test_recreated_file_is_chunked_again_from_zero(self):
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            src = t / "p.csv"
            src.write_text("a\nb\n")
            st = {}
            fr.chunk_lines(src, t / "out", "p", "csv", st)
            src.write_text("c\n")                       # shorter: recreated
            dst = fr.chunk_lines(src, t / "out", "p", "csv", st)
            self.assertEqual(dst.name, "p.0002.csv.xz")
            self.assertEqual(lzma.decompress(dst.read_bytes()), b"c\n")


if __name__ == "__main__":
    unittest.main()


class CoverLogTimestampTest(unittest.TestCase):
    def test_bb_coverage_reads_the_pc_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "results").mkdir()
            Path(tmp, "cover.log").write_text("0x1 1761030412\n0x2\n")
            Path(tmp, "results", "cover-1.log").write_text("0x2 1761030000\n0x3\n")
            self.assertEqual(fr.bb_coverage(tmp), 3)
