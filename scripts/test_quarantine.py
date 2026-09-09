#!/usr/bin/env python3
"""Offline tests for the quarantine scheduler (no device needed)."""

import json
import os
import tempfile
import unittest

import quarantine as q


def fresh(**params):
    s = q.init_state(config="cfg")
    s["params"].update(params)
    return s


class Classification(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(q.classify(1, 1), q.HARD)
        self.assertEqual(q.classify(1, 3), q.REPETITION)
        self.assertEqual(q.classify(2, 3), q.SOFT)
        self.assertEqual(q.classify(3, 3), q.SOFT)

    def test_distinct_and_repeat(self):
        self.assertEqual(q.distinct_selectors(["A", "A", "B"]), ["A", "B"])
        self.assertEqual(q.max_repeat(["A", "A", "B"]), 2)
        self.assertEqual(q.max_repeat([]), 0)


class SuspectGate(unittest.TestCase):
    def test_first_crash_is_suspect_not_disabled(self):
        s = fresh(confirm=2)
        res = q.on_crash(s, "sigX", ["X"])
        self.assertEqual(res["decision"], "suspect")
        self.assertEqual(q.disabled_set(s), [])          # nothing benched on one-off
        self.assertEqual(s["catalog"]["sigX"]["disposition"], q.SUSPECTED)

    def test_suspect_never_recurs_stays_enabled(self):
        s = fresh(confirm=2)
        q.on_crash(s, "sigX", ["X"])
        self.assertEqual(q.disabled_set(s), [])


class Hard(unittest.TestCase):
    def test_single_call_confirms_to_hard(self):
        s = fresh(confirm=2)
        q.on_crash(s, "sigX", ["X"])                     # suspect
        res = q.on_crash(s, "sigX", ["X"])               # confirm
        self.assertEqual(res["decision"], "confirmed")
        self.assertEqual(res["category"], q.HARD)
        self.assertEqual(q.disabled_set(s), ["X"])       # permanently disabled


class Repetition(unittest.TestCase):
    def test_repetition_tolerated_then_escalates(self):
        s = fresh(confirm=2, tolerate_budget=4)
        seq = ["X", "X", "X"]                            # 1 selector, 3 calls
        self.assertEqual(q.on_crash(s, "sigR", seq)["decision"], "suspect")   # occ1
        r2 = q.on_crash(s, "sigR", seq)                  # occ2 -> confirm
        self.assertEqual(r2["category"], q.REPETITION)
        self.assertEqual(r2["disposition"], q.TOLERATED)
        self.assertEqual(q.disabled_set(s), [])          # tolerated: still enabled
        self.assertEqual(q.on_crash(s, "sigR", seq)["decision"], "tolerated")  # occ3
        r4 = q.on_crash(s, "sigR", seq)                  # occ4 >= budget
        self.assertEqual(r4["decision"], "escalated")
        self.assertEqual(q.disabled_set(s), ["X"])       # now disabled
        self.assertEqual(s["catalog"]["sigR"]["repetition_count"], 3)


class Soft(unittest.TestCase):
    def _confirm_group(self, s, sig, members):
        q.on_crash(s, sig, members)
        return q.on_crash(s, sig, members)

    def test_soft_disables_one_member_and_rotates(self):
        s = fresh(confirm=2, stall_threshold=100, rotate_cap=10 ** 9)
        res = self._confirm_group(s, "sigS", ["A", "B", "C"])
        self.assertEqual(res["category"], q.SOFT)
        self.assertEqual(q.disabled_set(s), ["A"])       # cursor 0 -> sorted[0]
        # Rotate: not due below threshold, due at/above it.
        self.assertFalse(q.maybe_rotate(s, exec_total=50, execs_since_cov=10))
        self.assertTrue(q.maybe_rotate(s, exec_total=200, execs_since_cov=100))
        self.assertEqual(q.disabled_set(s), ["B"])
        self.assertTrue(q.maybe_rotate(s, exec_total=400, execs_since_cov=100))
        self.assertEqual(q.disabled_set(s), ["C"])
        self.assertTrue(q.maybe_rotate(s, exec_total=600, execs_since_cov=100))
        self.assertEqual(q.disabled_set(s), ["A"])       # wraps

    def test_rotate_cap_triggers_without_stall(self):
        s = fresh(confirm=2, stall_threshold=10 ** 9, rotate_cap=1000)
        self._confirm_group(s, "sigS", ["A", "B", "C"])
        self.assertFalse(q.maybe_rotate(s, exec_total=500, execs_since_cov=0))
        self.assertTrue(q.maybe_rotate(s, exec_total=1000, execs_since_cov=0))


class GreedyCover(unittest.TestCase):
    def test_shared_selector_covers_both_groups(self):
        s = fresh()
        q.add_soft_group(s, ["A", "B", "C"], "s1", q.now_iso())
        q.add_soft_group(s, ["C", "D", "E"], "s2", q.now_iso())
        g1, g2 = s["soft_groups"]
        # Put group1's cursor on the shared C (members sorted: A,B,C -> index 2).
        g1["cursor"] = 2
        self.assertEqual(q.disabled_set(s), ["C"])       # C breaks both -> g2 adds nothing
        # Put group1 on A: g2 must then contribute one of its own.
        g1["cursor"] = 0
        self.assertEqual(q.disabled_set(s), ["A", "C"])  # A (g1) + C (g2 cursor 0)

    def test_hard_seeds_cover(self):
        s = fresh()
        q._add_hard(s, ["X"])
        q.add_soft_group(s, ["X", "Y", "Z"], "s1", q.now_iso())
        self.assertEqual(q.disabled_set(s), ["X"])       # group covered by HARD X


class Escape(unittest.TestCase):
    def _rotating_soft(self, s):
        q.on_crash(s, "sigS", ["A", "B", "C"])
        q.on_crash(s, "sigS", ["A", "B", "C"])           # -> rotating
        self.assertEqual(s["catalog"]["sigS"]["disposition"], q.ROTATING)

    def test_escape_adds_new_group(self):
        s = fresh(confirm=2)
        self._rotating_soft(s)
        res = q.on_crash(s, "sigS", ["D", "B", "C"])     # alternate path, same sig
        self.assertEqual(res["decision"], "escape")
        self.assertEqual(s["catalog"]["sigS"]["escaped_count"], 1)
        self.assertEqual(len(s["soft_groups"]), 2)       # new path -> another group

    def test_single_selector_escape_disables(self):
        s = fresh(confirm=2)
        self._rotating_soft(s)
        q.on_crash(s, "sigS", ["Z"])                     # single-selector escape path
        self.assertIn("Z", s["hard"])


class DiscoveryContext(unittest.TestCase):
    def test_context_records_currently_disabled(self):
        s = fresh(confirm=1)                             # act on first sight
        q.on_crash(s, "sigX", ["X"])                     # -> HARD X
        self.assertEqual(q.disabled_set(s), ["X"])
        q.on_crash(s, "sigY", ["A", "B"])                # discovered while X disabled
        self.assertEqual(s["catalog"]["sigY"]["discovery_context"], ["X"])


class Persistence(unittest.TestCase):
    def test_roundtrip(self):
        s = fresh(confirm=2)
        q.on_crash(s, "sigX", ["X"])
        q.on_crash(s, "sigX", ["X"])                     # HARD
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "q.json")
            q.save_state(path, s)
            s2 = q.load_state(path)
        self.assertEqual(q.disabled_set(s2), ["X"])
        self.assertEqual(s2["catalog"]["sigX"]["category"], q.HARD)


class ConfigWriteback(unittest.TestCase):
    """apply must make the manager config mirror the scheduler exactly -- the
    step that actually stops the fuzzer from re-hitting a quarantined crash."""

    def _cfg(self, d, **extra):
        path = os.path.join(d, "k.cfg")
        c = {"target": "darwin/arm64", "enable_syscalls": ["A", "B", "C"]}
        c.update(extra)
        with open(path, "w") as f:
            json.dump(c, f, indent=4)
        return path

    def test_writes_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = self._cfg(d)
            s = fresh(confirm=2)
            q.on_crash(s, "sigA", ["A"])
            q.on_crash(s, "sigA", ["A"])                 # HARD -> disable A
            self.assertTrue(q.write_disable_syscalls(cfg, q.disabled_set(s)))
            self.assertEqual(q.read_config(cfg)["disable_syscalls"], ["A"])
            self.assertFalse(q.write_disable_syscalls(cfg, q.disabled_set(s)))

    def test_write_is_exact_not_incremental(self):
        # A selector rotated back in must leave the config too.
        with tempfile.TemporaryDirectory() as d:
            cfg = self._cfg(d, disable_syscalls=["A", "B"])
            q.write_disable_syscalls(cfg, ["B"])
            self.assertEqual(q.read_config(cfg)["disable_syscalls"], ["B"])
            q.write_disable_syscalls(cfg, [])
            self.assertNotIn("disable_syscalls", q.read_config(cfg))

    def test_other_config_keys_survive(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = self._cfg(d, workdir="/w", procs=1)
            q.write_disable_syscalls(cfg, ["A"])
            c = q.read_config(cfg)
            self.assertEqual((c["workdir"], c["procs"], c["enable_syscalls"]),
                             ("/w", 1, ["A", "B", "C"]))


class SeqValidation(unittest.TestCase):
    """Guards the '$' shell-expansion footgun: --seq "...$Driver_5" in double
    quotes expands to the bare generic name and quarantines the wrong thing."""

    def _cfg(self, d, names):
        path = os.path.join(d, "k.cfg")
        with open(path, "w") as f:
            json.dump({"enable_syscalls": names}, f)
        return path

    def test_rejects_name_not_enabled(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = self._cfg(d, ["syz_IOConnectCallMethod$UC_5"])
            self.assertEqual(q.check_seq(["syz_IOConnectCallMethod"], cfg),
                             ["syz_IOConnectCallMethod"])

    def test_accepts_enabled_name(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = self._cfg(d, ["syz_IOConnectCallMethod$UC_5"])
            self.assertEqual(q.check_seq(["syz_IOConnectCallMethod$UC_5"], cfg), [])

    def test_no_enable_list_means_no_validation(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = self._cfg(d, [])
            self.assertEqual(q.check_seq(["anything"], cfg), [])
        self.assertEqual(q.check_seq(["anything"], None), [])


class CallCounting(unittest.TestCase):
    """count_calls drives HARD vs REPETITION, so a miscount changes the verdict."""

    SEL = "syz_IOConnectCallMethod$UC_1"

    def test_counts_plain_and_bound_calls(self):
        prog = ("r0 = syz_IOServiceOpen$Drv(&(0x7f0000000000), 0x0, &(0x7f10))\n"
                "syz_IOConnectCallMethod$UC_1(r0, 0x1, 0x0)\n"
                "r1 = syz_IOConnectCallMethod$UC_1(r0, 0x1, 0x0)\n")
        self.assertEqual(q.count_calls(prog, self.SEL), 2)

    def test_longer_selector_is_not_a_match(self):
        # ..._1 must not count ..._10, or a one-call culprit reads as REPETITION.
        prog = ("syz_IOConnectCallMethod$UC_1(r0, 0x1, 0x0)\n"
                "syz_IOConnectCallMethod$UC_10(r0, 0xa, 0x0)\n")
        self.assertEqual(q.count_calls(prog, self.SEL), 1)

    def test_name_inside_arguments_is_not_a_call(self):
        prog = "syz_IOServiceClose(r0)  # was syz_IOConnectCallMethod$UC_1(...)\n"
        self.assertEqual(q.count_calls(prog, self.SEL), 0)

    def test_single_call_classifies_hard_many_repetition(self):
        self.assertEqual(q.classify(1, 1), q.HARD)
        self.assertEqual(q.classify(1, 2), q.REPETITION)


class EscapePaths(unittest.TestCase):
    """A signature already benched against one selector fires again via another.

    This is the "same bug, second route" case: BUG-0002 reached through _5 when
    it is on record as a _7 bug.
    """

    def _disabled(self):
        st = q.init_state("cfg")
        for _ in range(2):                       # suspect -> confirmed HARD
            q.on_crash(st, "SIG", ["sel_A"])
        self.assertEqual(st["catalog"]["SIG"]["disposition"], q.DISABLED)
        return st

    def test_escape_benches_the_new_selector_on_the_first_occurrence(self):
        """No SUSPECT gate on an escape: the signature is already confirmed, so
        one crash through a new selector is enough to bench it."""
        st = self._disabled()
        res = q.on_crash(st, "SIG", ["sel_B"])
        self.assertEqual(res["decision"], "escape")
        self.assertIn("sel_B", res["disabled"])
        self.assertIn("sel_A", res["disabled"])

    def test_escape_is_recorded_not_just_applied(self):
        st = self._disabled()
        q.on_crash(st, "SIG", ["sel_B"])
        rec = st["catalog"]["SIG"]
        self.assertEqual(rec["escaped_count"], 1)
        self.assertEqual(rec["culprit_selectors"], ["sel_A"])   # original preserved
        self.assertEqual([p["selectors"] for p in rec["escape_paths"]], [["sel_B"]])

    def test_repeat_escape_by_the_same_selector_is_not_duplicated(self):
        st = self._disabled()
        q.on_crash(st, "SIG", ["sel_B"])
        q.on_crash(st, "SIG", ["sel_B"])
        rec = st["catalog"]["SIG"]
        self.assertEqual(rec["escaped_count"], 2)
        self.assertEqual(len(rec["escape_paths"]), 1)

    def test_multi_selector_escape_becomes_a_soft_group(self):
        st = self._disabled()
        res = q.on_crash(st, "SIG", ["sel_B", "sel_C"])
        self.assertEqual(res["decision"], "escape")
        self.assertTrue(st["soft_groups"], "a multi-selector path must rotate, not hard-bench")


if __name__ == "__main__":
    unittest.main()


class CommentedConfig(unittest.TestCase):
    """syzkaller strips whole-line '#' comments from a manager config before
    parsing (pkg/config/config.go, LoadData), and the campaign configs use them
    to record which selectors an experiment excluded. Reading one with a plain
    json.load() raises, and known_selectors() swallows that into None -- which
    reads as "no explicit list", silently disabling --seq validation for exactly
    the configs someone took the trouble to annotate."""

    def _write(self, text):
        fd, path = tempfile.mkstemp(suffix=".cfg")
        os.write(fd, text.encode())
        os.close(fd)
        self.addCleanup(os.unlink, path)
        return path

    def test_hash_comments_are_stripped(self):
        p = self._write('{\n'
                        '  "target": "darwin/arm64",\n'
                        '  "enable_syscalls": [\n'
                        '    "syz_IOConnectCallMethod$Foo_1",\n'
                        '    # "syz_IOConnectCallMethod$Foo_2",\n'
                        '    "syz_IOConnectTrap2$Foo_7"\n'
                        '  ]\n'
                        '}\n')
        cfg = q.read_config(p)
        self.assertEqual(cfg["enable_syscalls"],
                         ["syz_IOConnectCallMethod$Foo_1", "syz_IOConnectTrap2$Foo_7"])

    def test_commented_config_still_validates_seq(self):
        # The regression: a commented-out entry must not make every name look
        # plausible. The excluded selector is rejected, the live trap accepted.
        p = self._write('{\n'
                        '  "enable_syscalls": [\n'
                        '    # "syz_IOConnectCallMethod$Foo_2",\n'
                        '    "syz_IOConnectTrap2$Foo_7"\n'
                        '  ]\n'
                        '}\n')
        self.assertIsNotNone(q.known_selectors(p))
        self.assertEqual(q.check_seq(["syz_IOConnectTrap2$Foo_7"], p), [])
        self.assertEqual(q.check_seq(["syz_IOConnectCallMethod$Foo_2"], p),
                         ["syz_IOConnectCallMethod$Foo_2"])

    def test_plain_json_is_unchanged(self):
        p = self._write(json.dumps({"enable_syscalls": ["syz_IOServiceClose"]}))
        self.assertEqual(q.read_config(p), {"enable_syscalls": ["syz_IOServiceClose"]})
