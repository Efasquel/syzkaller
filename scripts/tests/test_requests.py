#!/usr/bin/env python3
"""Tests for the operator-verb request queue.

Two properties carry the design (see lib/requests): requests survive in order so
two verbs in one poll both land, and a damaged or missing file reads as empty
rather than stopping the runner.
"""

import multiprocessing
import os
import tempfile
import unittest

from lib import requests


def _append_worker(path, verb):
    """A writer in its own process. Module-level so it survives the pickling that
    the forkserver/spawn start methods do when handing it to a child."""
    requests.append(path, verb, now=0)


class RequestQueue(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "requests.json")

    def tearDown(self):
        # Remove the queue, its sibling lock, and the dir.
        for name in os.listdir(self.dir):
            os.unlink(os.path.join(self.dir, name))
        os.rmdir(self.dir)

    def test_append_then_pending_keeps_order_and_time(self):
        r1 = requests.append(self.path, "skip", "AppleSMC_gram-2", now=100)
        r2 = requests.append(self.path, "next", now=200)
        got = requests.pending(self.path)
        self.assertEqual(got, [r1, r2])
        # Oldest first, with the 'at' values we passed in, strictly increasing.
        self.assertEqual([r["verb"] for r in got], ["skip", "next"])
        self.assertEqual([r["item"] for r in got], ["AppleSMC_gram-2", None])
        self.assertLess(got[0]["at"], got[1]["at"])

    def test_append_record_shape(self):
        rec = requests.append(self.path, "halt", now=42)
        self.assertEqual(rec, {"verb": "halt", "item": None, "at": 42})

    def test_append_defaults_at_to_wall_clock(self):
        # No explicit now: 'at' is a real epoch value, not None.
        rec = requests.append(self.path, "next")
        self.assertIsInstance(rec["at"], float)
        self.assertGreater(rec["at"], 0)

    def test_take_returns_then_clears(self):
        requests.append(self.path, "skip", "B", now=1)
        requests.append(self.path, "next", now=2)
        taken = requests.take(self.path)
        self.assertEqual([r["verb"] for r in taken], ["skip", "next"])
        # A second poll finds nothing left.
        self.assertEqual(requests.pending(self.path), [])
        self.assertEqual(requests.take(self.path), [])

    def test_missing_file_is_empty(self):
        self.assertEqual(requests.pending(self.path), [])
        self.assertEqual(requests.take(self.path), [])

    def test_corrupt_file_is_empty_and_next_append_repairs(self):
        with open(self.path, "w") as f:
            f.write("{garbage not json")
        # A half-written file reads as empty, never raises.
        self.assertEqual(requests.pending(self.path), [])
        # The next append starts from scratch: a clean one-element list.
        requests.append(self.path, "next", now=5)
        got = requests.pending(self.path)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["verb"], "next")

    def test_non_list_json_is_empty(self):
        # Valid JSON of the wrong shape is as bad as garbage for our purposes.
        with open(self.path, "w") as f:
            f.write('{"verb": "next"}')
        self.assertEqual(requests.pending(self.path), [])

    def test_describe_empty(self):
        self.assertEqual(requests.describe([]), "")

    def test_describe_one(self):
        self.assertEqual(
            requests.describe([{"verb": "next", "item": None, "at": 1}]),
            "next")

    def test_describe_three(self):
        reqs = [
            {"verb": "next", "item": None, "at": 1},
            {"verb": "skip", "item": "AppleSMC_gram-2", "at": 2},
            {"verb": "halt", "item": None, "at": 3},
        ]
        self.assertEqual(requests.describe(reqs),
                         "next, skip AppleSMC_gram-2, halt")

    def test_concurrent_appends_from_two_processes_both_land(self):
        # The point of the advisory lock: two writers appending at once must not
        # clobber each other's record.
        procs = [multiprocessing.Process(target=_append_worker,
                                         args=(self.path, v))
                 for v in ("a", "b")]
        for p in procs:
            p.start()
        for p in procs:
            p.join()
            self.assertEqual(p.exitcode, 0)

        verbs = sorted(r["verb"] for r in requests.pending(self.path))
        self.assertEqual(verbs, ["a", "b"])


if __name__ == "__main__":
    unittest.main()
