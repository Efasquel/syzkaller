#!/usr/bin/env python3
"""Tests for lib/plan: loading, normalizing, rendering, and the driver adapter.

The plan library is pure over dicts and paths, so these are table tests against
a throwaway tree: a temp root with a handful of config files, no box, no
syz-manager. What they pin down is the contract of campaign-planning.md §3:
box ⊕ config ⊕ runtime, config wins and is reported as drift, runtime fields
are the runner's, and the authored disable_syscalls is never lost.
"""

import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib import plan as pl  # noqa: E402


BOX = {
    "target": "darwin/arm64",
    "http": "127.0.0.1:56741",
    "syzkaller": "/Users/Shared/fuzz-run",
    "procs": 1,
    "type": "none",
    "sandbox": "none",
    "reproduce": False,
    "kext_coverage": {"kcov_device": "/dev/pishi"},
}

# A config that carries only experiment fields, as a stripped config does.
CLEAN_CFG = {
    "cover": True,
    "kext_coverage": {"kext_id": 2},
    "ring_buffer_size": 5,
    "enable_syscalls": ["syz_IOServiceOpen$A", "syz_IOConnectCallMethod$A_0"],
    "disable_syscalls": ["syz_IOConnectCallMethod$A_9"],
}


def write(path, data):
    """Write a JSON file, creating its directory; returns the path."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")
    return path


class TreeTest(unittest.TestCase):
    """A temp tree with config/a.cfg and config/b.cfg for the tests that need
    real files: normalize checks existence, check_table counts syscalls."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        write(self.root / "config" / "a.cfg", CLEAN_CFG)
        b = dict(CLEAN_CFG, enable_syscalls=["x", "y", "z"], http="127.0.0.1:1")
        write(self.root / "config" / "b.cfg", b)

    def tearDown(self):
        self._tmp.cleanup()

    def plan(self, **over):
        base = {"name": "eval", "items": [{"config": "config/a.cfg"}]}
        base.update(over)
        return base


class LoadTest(TreeTest):
    def test_plan_with_comments(self):
        """Plans allow the same whole-line '#' comments as configs, so an
        operator can annotate an item out of a plan the way they do a syscall."""
        text = (
            "{\n"
            "  # the evaluation of the grammar sampler\n"
            '  "name": "eval",\n'
            '  "items": [\n'
            '    {"config": "config/a.cfg"}\n'
            "    # ,{\"config\": \"config/b.cfg\"}\n"
            "  ]\n"
            "}\n"
        )
        path = self.root / "plans" / "eval.json"
        path.parent.mkdir()
        path.write_text(text)
        self.assertEqual(pl.load_plan(path),
                         {"name": "eval", "items": [{"config": "config/a.cfg"}]})

    def test_bad_json_names_the_file(self):
        path = self.root / "plans" / "bad.json"
        path.parent.mkdir()
        path.write_text('{"name": "eval",}')
        with self.assertRaises(ValueError) as cm:
            pl.load_plan(path)
        self.assertIn("bad.json", str(cm.exception))
        self.assertIn("bad JSON", str(cm.exception))

    def test_box_missing_is_empty(self):
        """No box.json is a legitimate state (configs still carry their box
        fields), so it is an empty overlay, not an error."""
        self.assertEqual(pl.load_box(self.root / "config" / "box.json"), {})

    def test_box_present(self):
        write(self.root / "config" / "box.json", BOX)
        self.assertEqual(pl.load_box(self.root / "config" / "box.json"), BOX)

    def test_box_bad_json_raises(self):
        (self.root / "config" / "box.json").write_text("{nope")
        with self.assertRaises(ValueError):
            pl.load_box(self.root / "config" / "box.json")


class NormalizeTest(TreeTest):
    def test_fills_defaults(self):
        out = pl.normalize(self.plan(), self.root)
        self.assertEqual(out["clock"], "real")
        self.assertIs(out["watch_window"], True)
        self.assertEqual(out["defaults"], {"max_hours": 6, "max_plateau_hours": None,
                                           "reuse_known_culprits": False})
        self.assertEqual(out["limits"], {"max_crashes": 20, "min_free_gb": 20.0,
                                         "crashloop_limit": 15})
        item = out["items"][0]
        self.assertEqual(item["max_hours"], 6)
        self.assertIsNone(item["max_plateau_hours"])

    def test_explicit_values_kept(self):
        p = self.plan(clock="wall",
                      defaults={"max_hours": 2, "max_plateau_hours": 1, "reuse_known_culprits": True},
                      limits={"max_crashes": 5},
                      items=[{"config": "config/a.cfg", "max_hours": 12}])
        out = pl.normalize(p, self.root)
        self.assertEqual(out["clock"], "wall")
        self.assertEqual(out["defaults"]["reuse_known_culprits"], True)
        # Partial limits are completed, not replaced.
        self.assertEqual(out["limits"], {"max_crashes": 5, "min_free_gb": 20.0,
                                         "crashloop_limit": 15})
        self.assertEqual(out["items"][0]["max_hours"], 12)
        # Per-item plateau comes from defaults when the item does not say.
        self.assertEqual(out["items"][0]["max_plateau_hours"], 1)

    def test_configs_made_absolute_against_root(self):
        out = pl.normalize(self.plan(), self.root)
        self.assertEqual(out["items"][0]["config"], str(self.root / "config" / "a.cfg"))
        absolute = str(self.root / "config" / "b.cfg")
        out = pl.normalize(self.plan(items=[{"config": absolute}]), self.root)
        self.assertEqual(out["items"][0]["config"], absolute)

    def test_ids_derived_per_stem(self):
        """Repeats are entries in the list; the ids are <stem>-1, -2 per stem,
        always suffixed, so a config run once still has a numbered folder."""
        p = self.plan(items=[{"config": "config/a.cfg"}, {"config": "config/a.cfg"},
                             {"config": "config/b.cfg"}])
        out = pl.normalize(p, self.root)
        self.assertEqual([it["id"] for it in out["items"]], ["a-1", "a-2", "b-1"])

    def test_explicit_ids_kept_and_derived_ones_number_only_the_rest(self):
        p = self.plan(items=[{"config": "config/a.cfg", "id": "warmup"},
                             {"config": "config/a.cfg"}])
        out = pl.normalize(p, self.root)
        self.assertEqual([it["id"] for it in out["items"]], ["warmup", "a-1"])

    def test_does_not_mutate_input(self):
        p = self.plan()
        before = copy.deepcopy(p)
        pl.normalize(p, self.root)
        self.assertEqual(p, before)

    def test_rejections(self):
        """Each row is one plan that must be refused, and the text its problem
        list must contain. Table-driven because the point is the set of
        rules, not any single one."""
        table = [
            ("bad explicit id",
             self.plan(items=[{"config": "config/a.cfg", "id": "has.dot"}]),
             "id 'has.dot'"),
            ("duplicate ids",
             self.plan(items=[{"config": "config/a.cfg", "id": "x"},
                              {"config": "config/b.cfg", "id": "x"}]),
             "duplicate item id 'x'"),
            ("derived id collides with explicit",
             self.plan(items=[{"config": "config/a.cfg", "id": "a-1"},
                              {"config": "config/a.cfg"}]),
             "duplicate item id 'a-1'"),
            ("missing config",
             self.plan(items=[{"config": "config/nope.cfg"}]),
             "config not found"),
            ("no config key",
             self.plan(items=[{"max_hours": 1}]),
             "config is missing"),
            ("bad name",
             self.plan(name="fde eval"),
             "name 'fde eval'"),
            ("no name",
             {"items": [{"config": "config/a.cfg"}]},
             "name is missing"),
            ("bad clock",
             self.plan(clock="cpu"),
             "clock 'cpu'"),
            ("empty items",
             self.plan(items=[]),
             "non-empty list"),
            ("bad hours",
             self.plan(items=[{"config": "config/a.cfg", "max_hours": 0}]),
             "max_hours must be a positive number"),
            ("bool hours",
             self.plan(defaults={"max_hours": True}),
             "max_hours must be a positive number"),
        ]
        for label, p, expect in table:
            with self.subTest(label):
                with self.assertRaises(ValueError) as cm:
                    pl.normalize(p, self.root)
                self.assertIn(expect, str(cm.exception))

    def test_lists_every_problem_at_once(self):
        p = {"name": "bad name", "clock": "cpu",
             "items": [{"config": "config/nope.cfg", "id": "a.b"},
                       {"config": "config/a.cfg", "max_hours": -1}]}
        with self.assertRaises(pl.PlanError) as cm:
            pl.normalize(p, self.root)
        problems = cm.exception.problems
        self.assertEqual(len(problems), 5, problems)
        text = str(cm.exception)
        for expect in ("name 'bad name'", "clock 'cpu'", "config not found",
                       "id 'a.b'", "max_hours must be a positive number"):
            self.assertIn(expect, text)
        self.assertIsInstance(cm.exception, ValueError)


class NamesTest(unittest.TestCase):
    def test_item_dir(self):
        item = {"id": "AppleFDEKeyStore_gram-2",
                "config": "/tree/config/AppleFDEKeyStore_gram.cfg"}
        self.assertEqual(
            pl.item_dir("/tree", "fde_eval", item),
            Path("/tree/campaigns/fde_eval/AppleFDEKeyStore_gram/AppleFDEKeyStore_gram-2"))

    def test_effective_name_and_session_id(self):
        self.assertEqual(pl.session_id("fde_eval", "gram-1"), "fde_eval.gram-1")
        self.assertEqual(pl.effective_name("fde_eval", "gram-1"), "fde_eval.gram-1.cfg")


class RenderTest(unittest.TestCase):
    def test_box_keys_fill_in(self):
        eff, notes = pl.render(CLEAN_CFG, BOX, "/w")
        for key in ("target", "http", "syzkaller", "procs", "type", "sandbox", "reproduce"):
            self.assertEqual(eff[key], BOX[key])
        self.assertEqual(eff["cover"], True)
        self.assertEqual(eff["ring_buffer_size"], 5)
        self.assertEqual(notes, [])

    def test_kext_coverage_merged_one_level(self):
        eff, _ = pl.render(CLEAN_CFG, BOX, "/w")
        self.assertEqual(eff["kext_coverage"],
                         {"kcov_device": "/dev/pishi", "kext_id": 2, "cover_log": "cover.log"})

    def test_drift_noted_only_when_values_differ(self):
        same = dict(CLEAN_CFG, http=BOX["http"], procs=BOX["procs"])
        eff, notes = pl.render(same, BOX, "/w")
        self.assertEqual(notes, [])

        other = dict(CLEAN_CFG, http="127.0.0.1:1", procs=1,
                     kext_coverage={"kext_id": 2, "kcov_device": "/dev/other"})
        eff, notes = pl.render(other, BOX, "/w")
        # The config wins ...
        self.assertEqual(eff["http"], "127.0.0.1:1")
        self.assertEqual(eff["kext_coverage"]["kcov_device"], "/dev/other")
        # ... and says so, once per differing field, nested ones by dotted name.
        self.assertEqual(notes, [
            'drift: http: config says "127.0.0.1:1", box.json says "127.0.0.1:56741"',
            'drift: kext_coverage.kcov_device: config says "/dev/other", box.json says "/dev/pishi"',
        ])
        self.assertEqual(pl.drift(other, BOX), notes)

    def test_box_key_unknown_to_box_is_not_drift(self):
        """A field the box does not set has nothing to drift from; the config's
        value simply stands (an empty box runs every legacy config as-is)."""
        eff, notes = pl.render(dict(CLEAN_CFG, http="127.0.0.1:1"), {}, "/w")
        self.assertEqual(eff["http"], "127.0.0.1:1")
        self.assertEqual(notes, [])

    def test_runtime_keys_replaced_and_noted(self):
        cfg = dict(CLEAN_CFG, workdir="/old/workdir",
                   kext_coverage={"kext_id": 2, "cover_log": "/old/cover.log"})
        eff, notes = pl.render(cfg, BOX, Path("/tree/campaigns/e/a/a-1/workdir"))
        self.assertEqual(eff["workdir"], "/tree/campaigns/e/a/a-1/workdir")
        self.assertEqual(eff["kext_coverage"]["cover_log"], "cover.log")
        self.assertEqual(notes, ["ignored: workdir (rendered per item)",
                                 "ignored: kext_coverage.cover_log (rendered per item)"])

    def test_runtime_set_even_when_config_silent(self):
        eff, notes = pl.render(CLEAN_CFG, BOX, "/w")
        self.assertEqual(eff["workdir"], "/w")
        self.assertEqual(eff["kext_coverage"]["cover_log"], "cover.log")
        self.assertEqual(notes, [])

    def test_no_kext_coverage_means_no_cover_log(self):
        """A config without kext coverage must not gain the object just to hold
        a cover_log: that would switch the feature on."""
        cfg = {k: v for k, v in CLEAN_CFG.items() if k != "kext_coverage"}
        box = {k: v for k, v in BOX.items() if k != "kext_coverage"}
        eff, _ = pl.render(cfg, box, "/w")
        self.assertNotIn("kext_coverage", eff)

    def test_disable_syscalls_is_sorted_union_with_authored_kept(self):
        eff, _ = pl.render(CLEAN_CFG, BOX, "/w", benched=["b", "a", "syz_IOConnectCallMethod$A_9"])
        self.assertEqual(eff["disable_syscalls"], ["a", "b", "syz_IOConnectCallMethod$A_9"])
        # Nothing benched: the authored list, unchanged.
        eff, _ = pl.render(CLEAN_CFG, BOX, "/w")
        self.assertEqual(eff["disable_syscalls"], ["syz_IOConnectCallMethod$A_9"])
        # No authored list at all: still a list, so syz-manager sees the benches.
        cfg = {k: v for k, v in CLEAN_CFG.items() if k != "disable_syscalls"}
        eff, _ = pl.render(cfg, BOX, "/w", benched=["z"])
        self.assertEqual(eff["disable_syscalls"], ["z"])

    def test_inputs_not_mutated_and_not_shared(self):
        cfg = copy.deepcopy(CLEAN_CFG)
        cfg["workdir"] = "/old"
        box = copy.deepcopy(BOX)
        cfg_before, box_before = copy.deepcopy(cfg), copy.deepcopy(box)
        eff, _ = pl.render(cfg, box, "/w", benched=["q"])
        self.assertEqual(cfg, cfg_before)
        self.assertEqual(box, box_before)
        # Mutating the result must not reach back into either input.
        eff["kext_coverage"]["kext_id"] = 99
        eff["enable_syscalls"].append("extra")
        self.assertEqual(cfg, cfg_before)
        self.assertEqual(box, box_before)


class DefTest(TreeTest):
    def test_plan_to_def_shape(self):
        p = self.plan(clock="wall",
                      defaults={"max_hours": 2, "reuse_known_culprits": True},
                      limits={"max_crashes": 7},
                      items=[{"config": "config/a.cfg"},
                             {"config": "config/b.cfg", "max_hours": 1.5, "max_plateau_hours": 1}])
        d = pl.plan_to_def(pl.normalize(p, self.root))
        self.assertEqual(d["name"], "eval")
        self.assertEqual(d["budget_clock"], "wall")
        self.assertNotIn("loop", d)
        self.assertIs(d["watch_window"], True)
        # `new --no-watch-window` is stored in the plan and reaches the driver
        off = pl.plan_to_def(pl.normalize(dict(p, watch_window=False), self.root))
        self.assertIs(off["watch_window"], False)
        with self.assertRaises(ValueError):
            pl.normalize(dict(p, watch_window="no"), self.root)
        self.assertIs(d["reuse_known_culprits"], True)
        self.assertEqual(d["max_hours"], 2)
        # Limits sit at top level, where the breaker code already reads them.
        self.assertEqual(d["max_crashes"], 7)
        self.assertEqual(d["min_free_gb"], 20.0)
        self.assertEqual(d["crashloop_limit"], 15)
        self.assertEqual(d["items"], [
            {"id": "a-1", "config": str(self.root / "config" / "a.cfg"),
             "budget_seconds": 7200.0, "max_plateau_hours": None},
            {"id": "b-1", "config": str(self.root / "config" / "b.cfg"),
             "budget_seconds": 5400.0, "max_plateau_hours": 1},
        ])


class CheckTableTest(TreeTest):
    def test_rows(self):
        p = self.plan(items=[{"config": "config/a.cfg"},
                             {"config": "config/b.cfg", "max_hours": 1.5}])
        rows = pl.check_table(pl.normalize(p, self.root), BOX, self.root)
        self.assertEqual(rows, [
            ["a-1", "config/a.cfg", "6", "2", "-"],
            ["b-1", "config/b.cfg", "1.5", "3",
             'http: config says "127.0.0.1:1", box.json says "127.0.0.1:56741"'],
        ])

    def test_config_outside_root_shown_absolute(self):
        with tempfile.TemporaryDirectory() as other:
            path = write(Path(other) / "x.cfg", CLEAN_CFG)
            p = self.plan(items=[{"config": str(path)}])
            rows = pl.check_table(pl.normalize(p, self.root), {}, self.root)
            self.assertEqual(rows[0][1], str(path))


if __name__ == "__main__":
    unittest.main()
