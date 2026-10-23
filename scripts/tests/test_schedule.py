#!/usr/bin/env python3
"""Tests for the pure scheduler: id derivation, stop precedence, step choice.

These are the table tests the design calls for (campaign-planning.md §11): the
whole point of pulling scheduling out of the run loop was that every decision
could be checked here against plain data, without a box.
"""

import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib import schedule as sch  # noqa: E402


def obs(**kw):
    """An observations dict with the always-present budget keys defaulted.

    spent/budget and incidents/max_incidents are what stop_reason always reads;
    a test overrides only the ones it is about and leaves the rest harmless.
    """
    base = {"spent": 0, "budget": 100, "incidents": 0, "max_incidents": 100}
    base.update(kw)
    return base


class ItemIdsTest(unittest.TestCase):
    def test_repeats_are_numbered_in_order(self):
        """Running a config three times is listing it three times; the ids are
        how that list becomes three distinct, stable folder names."""
        configs = [
            "config/AppleFDEKeyStore_gram.cfg",
            "config/AppleFDEKeyStore_gram.cfg",
            "config/AppleFDEKeyStore_gram.cfg",
        ]
        self.assertEqual(
            sch.item_ids(configs),
            ["AppleFDEKeyStore_gram-1", "AppleFDEKeyStore_gram-2",
             "AppleFDEKeyStore_gram-3"],
        )

    def test_a_single_config_is_still_suffixed(self):
        """Always '-1', so the first sample's folder never repeats the bare
        config name."""
        self.assertEqual(
            sch.item_ids(["config/AppleFDEKeyStore_gram.cfg"]),
            ["AppleFDEKeyStore_gram-1"],
        )

    def test_counts_are_per_stem_not_global(self):
        cases = [
            # (configs, expected ids)
            ([], []),
            (["a.cfg", "b.cfg"], ["a-1", "b-1"]),
            (["a.cfg", "b.cfg", "a.cfg"], ["a-1", "b-1", "a-2"]),
            (["a.cfg", "a.cfg", "b.cfg", "a.cfg", "b.cfg"],
             ["a-1", "a-2", "b-1", "a-3", "b-2"]),
        ]
        for configs, expected in cases:
            with self.subTest(configs=configs):
                self.assertEqual(sch.item_ids(configs), expected)

    def test_stems_keep_their_dashes_and_underscores(self):
        """'-' and '_' are part of the name; only the dir and extension go. The
        id splits at its one trailing '-<n>', not at a dash inside the stem."""
        configs = [
            "config/AppleFDEKeyStore_gram-sel.cfg",
            "config/AppleFDEKeyStore_gram-sel.cfg",
            "config/IOHID-family_v2.cfg",
        ]
        self.assertEqual(
            sch.item_ids(configs),
            ["AppleFDEKeyStore_gram-sel-1", "AppleFDEKeyStore_gram-sel-2",
             "IOHID-family_v2-1"],
        )

    def test_a_bare_filename_has_the_same_stem_as_a_path(self):
        self.assertEqual(sch.item_ids(["foo.cfg", "config/foo.cfg"]),
                         ["foo-1", "foo-2"])


class StopReasonTest(unittest.TestCase):
    def test_none_when_nothing_is_exhausted(self):
        self.assertIsNone(sch.stop_reason(obs(), [], "x-1"))

    def test_budget_equality_counts_as_exhausted(self):
        """The budget is a ceiling: spent == budget ends the item."""
        self.assertEqual(
            sch.stop_reason(obs(spent=100, budget=100), [], "x-1"), "max_hours")

    def test_incident_equality_counts_as_exhausted(self):
        self.assertEqual(
            sch.stop_reason(obs(incidents=20, max_incidents=20), [], "x-1"),
            "max_crashes")

    def test_a_request_wins_over_an_exhausted_budget(self):
        """The operator is reacting to something the budget cannot see, so a
        pending verb outranks a budget that is already spent."""
        exhausted = obs(spent=100, budget=100, incidents=99, max_incidents=20)
        self.assertEqual(
            sch.stop_reason(exhausted, [{"verb": "next"}], "x-1"), "next")
        self.assertEqual(
            sch.stop_reason(exhausted, [{"verb": "skip", "item": "x-1"}], "x-1"),
            "skip")

    def test_skip_only_fires_for_the_targeted_item(self):
        """A skip aimed at another item must not end this one."""
        self.assertIsNone(
            sch.stop_reason(obs(), [{"verb": "skip", "item": "other-1"}], "x-1"))

    def test_budget_outranks_incidents_then_plateau(self):
        """Precedence order, each reason checked after the one above it is
        ruled out."""
        # budget before incidents
        self.assertEqual(
            sch.stop_reason(obs(spent=100, budget=100,
                                incidents=100, max_incidents=20), [], "x-1"),
            "max_hours")
        # incidents before plateau
        self.assertEqual(
            sch.stop_reason(obs(incidents=20, max_incidents=20,
                                plateau_seconds=10, since_new_block=10),
                            [], "x-1"),
            "max_crashes")

    def test_plateau_fires_only_when_both_keys_are_set(self):
        cases = [
            # (extra obs, expected)
            ({}, None),                                          # opt-out: no keys
            ({"plateau_seconds": 3600}, None),                   # no measurement
            ({"since_new_block": 9999}, None),                   # not opted in
            ({"plateau_seconds": None, "since_new_block": 10}, None),
            ({"plateau_seconds": 3600, "since_new_block": 3599}, None),
            ({"plateau_seconds": 3600, "since_new_block": 3600}, "plateau"),
            ({"plateau_seconds": 3600, "since_new_block": 7200}, "plateau"),
        ]
        for extra, expected in cases:
            with self.subTest(extra=extra):
                self.assertEqual(sch.stop_reason(obs(**extra), [], "x-1"),
                                 expected)


class NextStepTest(unittest.TestCase):
    def setUp(self):
        self.order = ["a-1", "a-2", "a-3"]
        self.items = {
            "a-1": {"status": "done"},
            "a-2": {"status": "pending"},
            "a-3": {"status": "pending"},
        }

    def test_halt_beats_everything(self):
        """Even with an item running and items pending, halt wins so the box can
        move to the next campaign."""
        items = dict(self.items, **{"a-2": {"status": "running"}})
        step = sch.next_step(self.order, items,
                             [{"verb": "skip", "item": "a-3"}, {"verb": "halt"}])
        self.assertEqual(step, sch.Step("halt", None, "halt by operator"))

    def test_a_running_item_continues(self):
        items = dict(self.items, **{"a-2": {"status": "running"}})
        self.assertEqual(sch.next_step(self.order, items, []),
                         sch.Step("run", "a-2", None))

    def test_running_outranks_a_pending_skip(self):
        """A skip targeting a later pending item does not pre-empt the run."""
        items = dict(self.items, **{"a-2": {"status": "running"}})
        self.assertEqual(
            sch.next_step(self.order, items, [{"verb": "skip", "item": "a-3"}]),
            sch.Step("run", "a-2", None))

    def test_first_pending_starts_when_none_running(self):
        self.assertEqual(sch.next_step(self.order, self.items, []),
                         sch.Step("run", "a-2", None))

    def test_skip_of_the_first_pending_ends_it(self):
        self.assertEqual(
            sch.next_step(self.order, self.items,
                          [{"verb": "skip", "item": "a-2"}]),
            sch.Step("end", "a-2", "skip"))

    def test_skip_of_a_later_pending_leaves_the_first_alone(self):
        """Skipping a-3 must not affect a-2, the item actually up next."""
        self.assertEqual(
            sch.next_step(self.order, self.items,
                          [{"verb": "skip", "item": "a-3"}]),
            sch.Step("run", "a-2", None))

    def test_done_when_nothing_is_pending(self):
        items = {
            "a-1": {"status": "done"},
            "a-2": {"status": "skipped"},
            "a-3": {"status": "abandoned"},
        }
        self.assertEqual(sch.next_step(self.order, items, []),
                         sch.Step("done", None, None))

    def test_inputs_are_never_mutated(self):
        order = list(self.order)
        items = copy.deepcopy(self.items)
        requests = [{"verb": "skip", "item": "a-2"}]
        order_before = copy.deepcopy(order)
        items_before = copy.deepcopy(items)
        requests_before = copy.deepcopy(requests)
        sch.next_step(order, items, requests)
        self.assertEqual(order, order_before)
        self.assertEqual(items, items_before)
        self.assertEqual(requests, requests_before)


class EndStatusTest(unittest.TestCase):
    def test_mapping(self):
        cases = [
            ("skip", "skipped"),
            ("max_crashes", "abandoned"),
            ("max_hours", "done"),
            ("plateau", "done"),
            ("next", "done"),
        ]
        for reason, expected in cases:
            with self.subTest(reason=reason):
                self.assertEqual(sch.end_status(reason), expected)


class RequestsForTest(unittest.TestCase):
    def test_item_scoped_and_item_less_verbs_are_included(self):
        requests = [
            {"verb": "skip", "item": "a-1"},
            {"verb": "skip", "item": "a-2"},
            {"verb": "next"},
            {"verb": "halt"},
        ]
        self.assertEqual(
            sch.requests_for(requests, "a-1"),
            [{"verb": "skip", "item": "a-1"}, {"verb": "next"}, {"verb": "halt"}])

    def test_nothing_for_an_unrelated_item(self):
        requests = [{"verb": "skip", "item": "a-2"}]
        self.assertEqual(sch.requests_for(requests, "a-1"), [])


if __name__ == "__main__":
    unittest.main(verbosity=1)
