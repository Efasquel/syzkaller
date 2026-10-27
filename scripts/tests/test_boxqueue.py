import json
import tempfile
import unittest
from pathlib import Path

from lib import boxqueue as bq


class BoxQueueTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "queue.json"

    def tearDown(self):
        self._tmp.cleanup()

    def test_a_missing_or_damaged_file_is_an_empty_queue(self):
        self.assertEqual(bq.load(self.path), {"queue": [], "history": []})
        self.assertIsNone(bq.head(self.path))
        self.path.write_text('{"queue": [')
        self.assertEqual(bq.load(self.path), {"queue": [], "history": []})
        # ... and the next change rewrites it whole
        bq.add(self.path, "a")
        self.assertEqual(bq.load(self.path)["queue"], ["a"])

    def test_add_appends_or_inserts_and_never_twice(self):
        bq.add(self.path, "a")
        bq.add(self.path, "b")
        self.assertEqual(bq.add(self.path, "c", at=0), 0)
        self.assertEqual(bq.load(self.path)["queue"], ["c", "a", "b"])
        self.assertEqual(bq.add(self.path, "d", at=99), 3)          # clamped
        with self.assertRaises(ValueError):
            bq.add(self.path, "a")
        self.assertEqual(bq.head(self.path), "c")

    def test_remove_and_move(self):
        for n in "abc":
            bq.add(self.path, n)
        self.assertTrue(bq.remove(self.path, "b"))
        self.assertFalse(bq.remove(self.path, "b"))
        bq.move(self.path, "c", 0)
        self.assertEqual(bq.load(self.path)["queue"], ["c", "a"])
        with self.assertRaises(ValueError):
            bq.move(self.path, "zz", 0)

    def test_finish_moves_the_campaign_to_history(self):
        bq.add(self.path, "a")
        bq.add(self.path, "b")
        bq.finish(self.path, "a", "done", None, "2026-10-27T17:00:00+01:00")
        q = bq.load(self.path)
        self.assertEqual(q["queue"], ["b"])
        self.assertEqual(q["history"], [{"name": "a", "ended": "2026-10-27T17:00:00+01:00",
                                         "status": "done", "reason": None}])
        # the file is plain JSON others can read
        self.assertEqual(json.loads(self.path.read_text())["queue"], ["b"])


if __name__ == "__main__":
    unittest.main()
