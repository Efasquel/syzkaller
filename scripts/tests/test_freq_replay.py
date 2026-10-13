#!/usr/bin/env python3
"""Tests for freq-replay: the schedule shape, the noise-floor judgement, and the
panic-resume path. The last one matters most -- an overnight replay of CLPC
programs WILL meet a program that panics the box, and a tool that replays it on
every resume never finishes."""

import importlib.util
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path


def _load():
    path = Path(__file__).resolve().parent.parent / "freq-replay.py"
    spec = importlib.util.spec_from_file_location("freq_replay", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


fr = _load()


def rec(name, pas, act=0.0, cls="none"):
    return {"name": name, "response_class": cls,
            "active": {"delta_ghz": act}, "passive": {"delta_ghz": pas}}


def controls(n=40, spread=0.01):
    # Symmetric around zero: median 0, MAD = spread.
    return [rec(fr.CONTROL, spread if i % 2 else -spread) for i in range(n)]


class Schedule(unittest.TestCase):
    def test_every_candidate_is_preceded_by_a_control(self):
        s = fr.interleave(["a", "b", "c"], seed=3)
        self.assertEqual(s[0::2], [fr.CONTROL] * 3)
        self.assertEqual(sorted(s[1::2]), ["a", "b", "c"])

    def test_seed_fixes_the_order(self):
        names = ["p%d" % i for i in range(50)]
        self.assertEqual(fr.interleave(names, 7), fr.interleave(names, 7))
        self.assertNotEqual(fr.interleave(names, 7), fr.interleave(names, 8))


class Judgement(unittest.TestCase):
    def test_floor_is_median_and_scaled_mad(self):
        fl = fr.floor_of(controls(spread=0.01))
        self.assertAlmostEqual(fl["passive"]["median"], 0.0)
        self.assertAlmostEqual(fl["passive"]["sigma"], 0.01 * fr.MAD_SCALE)

    def test_identical_controls_do_not_make_a_zero_width_floor(self):
        fl = fr.floor_of([rec(fr.CONTROL, 0.0)] * 30)
        self.assertGreater(fl["passive"]["sigma"], 0)

    def test_active_only_movement_is_not_a_hit(self):
        # The program's own load moving its own core is not influence.
        fl = fr.floor_of(controls())
        self.assertFalse(fr.is_hit(rec("x", 0.0, act=0.5), fl, 4))
        self.assertTrue(fr.is_hit(rec("x", 0.5), fl, 4))

    def test_confirm_requires_a_consistent_direction(self):
        fl = fr.floor_of(controls())
        big = 0.2
        steady = [rec("s", -big) for _ in range(8)] + [rec("s", 0.0)] * 2
        flappy = [rec("f", big if i % 2 else -big) for i in range(10)]
        v = {x["name"]: x for x in fr.confirm_verdicts(steady + flappy, fl, 4, 7)}
        self.assertTrue(v["s"]["confirmed"])
        self.assertEqual(v["s"]["hits"], 8)
        self.assertFalse(v["f"]["confirmed"])


STUB_BINFREQ = r'''#!/usr/bin/env python3
# Minimal stand-in for `binfreq --fuzzer-loop -j ... -- RUNNER...`: runs the
# runner per stdin line and prints one record; programs named "slow*" get a
# passive delta of +0.3 GHz, everything else 0.
import json, subprocess, sys
argv = sys.argv[sys.argv.index("--") + 1:]
for line in sys.stdin:
    tok = line.strip()
    if not tok:
        continue
    rc = subprocess.call(argv + [tok])
    if "/noisy" in tok:   # binfreq's own give-up: message, exit 1, loop over
        sys.stderr.write("binfreq: fuzzer trial: too few uncontended gates\n")
        sys.exit(1)
    d = 0.3 if "/slow" in tok else 0.0
    print(json.dumps({"input": tok, "call_status": rc, "response_class": "none",
                      "active": {"delta_ghz": 0.0}, "passive": {"delta_ghz": d}}))
    sys.stdout.flush()
'''

# Exits the whole stub chain when it meets the poisoned program, the way a
# panic ends the replay with the started-marker naming it.
STUB_EXECPROG = r'''#!/bin/sh
for a; do last="$a"; done
echo "ran $last"
case "$last" in */boom) kill -9 $PPID; exit 9;; esac
exit 0
'''


class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.d = self.tmp / "replay"
        (self.d / "progs").mkdir(parents=True)
        (self.d / "control.prog").write_text(fr.CONTROL_PROG)
        for n in ("a", "b", "slow1", "boom"):
            (self.d / "progs" / n).write_text("getpid()\n")
        self.saved = (fr.BINFREQ_BIN, fr.EXECPROG, fr.EXECUTOR)
        fr.BINFREQ_BIN = self._exe("binfreq", STUB_BINFREQ)
        fr.EXECPROG = self._exe("execprog", STUB_EXECPROG)
        fr.EXECUTOR = self._exe("executor", "#!/bin/sh\n")

    def tearDown(self):
        fr.BINFREQ_BIN, fr.EXECPROG, fr.EXECUTOR = self.saved

    def _exe(self, name, body):
        p = self.tmp / name
        p.write_text(body)
        p.chmod(p.stat().st_mode | stat.S_IXUSR)
        return p

    def _run(self, phase):
        fr.cmd_run(self.d, phase, "p,p", batch=100, seed=1, calib_trials=4,
                   reps=3, k=4, active_sweeps=8, sandbox="none", force=True)

    def test_panic_is_recorded_once_and_skipped_on_resume(self):
        with self.assertRaises(SystemExit):
            self._run("screen")              # dies at "boom", like a reboot would
        self._run("screen")                  # resume
        sus = fr.read_jsonl(self.d / "suspects.jsonl")
        self.assertEqual([s["name"] for s in sus], ["boom"])
        names = [r["name"] for r in fr.read_jsonl(self.d / "screen.jsonl")]
        self.assertEqual(sorted(n for n in names if n != fr.CONTROL),
                         ["a", "b", "slow1"])
        self.assertEqual(names.count(fr.CONTROL), 4)
        self._run("screen")                  # nothing left: no duplicate records
        self.assertEqual(len(fr.read_jsonl(self.d / "screen.jsonl")), 7)

    def test_binfreq_give_up_is_a_failure_not_a_suspect(self):
        (self.d / "progs" / "boom").unlink()
        (self.d / "progs" / "noisy").write_text("getpid()\n")
        self._run("screen")                  # carries on past the failed trial
        fails = fr.read_jsonl(self.d / "failures.jsonl")
        self.assertEqual([f["name"] for f in fails], ["noisy"])
        self.assertIn("uncontended", fails[0]["error"])
        self.assertEqual(fr.read_jsonl(self.d / "suspects.jsonl"), [])
        self._run("screen")                  # resume: still not a suspect
        self.assertEqual(fr.read_jsonl(self.d / "suspects.jsonl"), [])
        names = [r["name"] for r in fr.read_jsonl(self.d / "screen.jsonl")]
        self.assertEqual(sorted(n for n in names if n != fr.CONTROL),
                         ["a", "b", "slow1"])

    def test_relative_replay_dir_still_runs_programs(self):
        """The runner cd's into exec/ before writing its log and marker; with a
        relative replay dir every trial failed and nothing was measured."""
        (self.d / "progs" / "boom").unlink()
        cwd = os.getcwd()
        os.chdir(self.tmp)
        try:
            fr.cmd_run(Path("replay"), "screen", "p,p", batch=100, seed=1,
                       calib_trials=4, reps=3, k=4, active_sweeps=8,
                       sandbox="none", force=True)
        finally:
            os.chdir(cwd)
        recs = fr.read_jsonl(self.d / "screen.jsonl")
        self.assertTrue(recs)
        self.assertTrue(all(r["call_status"] == 0 for r in recs))

    def test_a_runner_that_never_runs_anything_stops_the_run(self):
        fr.EXECPROG = self._exe("execprog", "#!/bin/sh\nexit 3\n")
        with self.assertRaises(SystemExit):
            self._run("screen")

    def test_failed_trials_are_not_measurements(self):
        recs = [rec(fr.CONTROL, 0.0), dict(rec("x", 0.5), call_status=1)]
        self.assertEqual([r["name"] for r in fr.measured(recs)], [fr.CONTROL])

    def test_runner_output_never_reaches_the_record_stream(self):
        with self.assertRaises(SystemExit):
            self._run("screen")
        log = (self.d / "runner.log").read_text()
        self.assertIn("ran ", log)
        for r in fr.read_jsonl(self.d / "screen.jsonl"):
            self.assertIn("idx", r)


if __name__ == "__main__":
    unittest.main()
