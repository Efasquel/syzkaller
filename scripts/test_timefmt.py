#!/usr/bin/env python3
"""Tests for timefmt: one clock, local storage, French display, tolerant reads."""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import timefmt as tf  # noqa: E402


class StoredFormTest(unittest.TestCase):
    def test_now_iso_carries_an_offset(self):
        """A bare 'Z' read two hours off the wall clock in Paris summer time."""
        s = tf.now_iso()
        self.assertFalse(s.endswith("Z"))
        self.assertTrue(s[-6] in "+-", s)
        self.assertEqual(s[-3], ":")            # +02:00, not +0200

    def test_now_iso_is_valid_iso8601(self):
        self.assertIsNotNone(datetime.fromisoformat(tf.now_iso()))

    def test_the_two_clocks_agree(self):
        """now_iso and now_ts were UTC and local respectively, so one event was
        logged at 15:41:48Z and filed under 20260831-174148."""
        iso, ts = tf.now_iso(), tf.now_ts()
        self.assertEqual(tf.parse_iso(iso).strftime("%Y%m%d-%H%M"), ts[:13])


class ParseTest(unittest.TestCase):
    def test_legacy_z_form_keeps_its_instant(self):
        """Old state files must not shift by the offset when re-read."""
        self.assertEqual(tf.to_epoch("2026-08-31T13:41:35Z"),
                         datetime(2026, 8, 31, 13, 41, 35,
                                  tzinfo=timezone.utc).timestamp())

    def test_offset_form_round_trips(self):
        s = tf.now_iso()
        self.assertAlmostEqual(tf.to_epoch(s), tf.parse_iso(s).timestamp())

    def test_z_and_offset_can_denote_one_instant(self):
        paris = timezone(timedelta(hours=2))
        a = tf.to_epoch("2026-08-31T13:41:35Z")
        b = tf.to_epoch(datetime(2026, 8, 31, 15, 41, 35, tzinfo=paris).isoformat())
        self.assertEqual(a, b)

    def test_naive_string_is_read_as_local(self):
        """Written before the offset form existed; it meant local time then."""
        dt = tf.parse_iso("2026-08-31T15:41:35")
        self.assertIsNotNone(dt.tzinfo)

    def test_compact_stamp_parses(self):
        self.assertIsNotNone(tf.parse_iso("20260831-154135"))

    def test_garbage_is_none_not_an_exception(self):
        """A malformed timestamp must never stop a campaign."""
        for bad in ("not a date", "", None, "2026-13-45T99:99:99Z", 12345):
            self.assertIsNone(tf.parse_iso(bad), bad)
            self.assertIsNone(tf.to_epoch(bad), bad)


class DisplayTest(unittest.TestCase):
    def test_day_comes_first(self):
        self.assertEqual(tf.fmt("2026-09-01T14:56:39+02:00"), "01/09/2026 14:56:39")

    def test_legacy_z_displays_in_local_time(self):
        """13:41:35Z is 15:41:35 in Paris -- and 15:41:35 is what the directory
        stamp for that same event already said."""
        paris = timezone(timedelta(hours=2))
        expect = datetime(2026, 8, 31, 13, 41, 35, tzinfo=timezone.utc) \
            .astimezone(paris).strftime("%d/%m/%Y %H:%M:%S")
        got = tf.fmt("2026-08-31T13:41:35Z")
        # Compare only if the machine is on Paris time; otherwise just assert the
        # shape, so the suite is not hostage to the runner's zone.
        if datetime.now().astimezone().utcoffset() == timedelta(hours=2):
            self.assertEqual(got, expect)
        self.assertRegex(got, r"^\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}$")

    def test_short_form_drops_the_year(self):
        self.assertRegex(tf.fmt("2026-09-01T14:56:39+02:00", short=True),
                         r"^\d{2}/\d{2} \d{2}:\d{2}:\d{2}$")

    def test_unparseable_renders_as_the_default(self):
        self.assertEqual(tf.fmt("rubbish"), "-")
        self.assertEqual(tf.fmt(None, default="unknown"), "unknown")

    def test_epoch_zero_is_the_default_not_1970(self):
        """0 means 'never recorded' everywhere in this codebase."""
        self.assertEqual(tf.fmt_epoch(0, default="never"), "never")

    def test_log_stamp_shape(self):
        self.assertRegex(tf.stamp(), r"^\d{2}/\d{2} \d{2}:\d{2}:\d{2}$")


class SortingTest(unittest.TestCase):
    def test_mixed_forms_sort_correctly_by_epoch(self):
        """Never sort these as strings: '2026-08-31T13:41:35Z' sorts after
        '2026-08-31T15:41:35+02:00' lexically, though they are the same instant,
        and a Z value can sort before an earlier local one."""
        rows = ["2026-08-31T15:41:35+02:00",   # 13:41:35 UTC
                "2026-08-31T14:00:00Z",        # later
                "2026-08-31T09:00:00Z"]        # earliest
        by_epoch = sorted(rows, key=tf.to_epoch)
        self.assertEqual(by_epoch[0], "2026-08-31T09:00:00Z")
        self.assertEqual(by_epoch[-1], "2026-08-31T14:00:00Z")
        self.assertNotEqual(by_epoch, sorted(rows))   # string sort disagrees


if __name__ == "__main__":
    unittest.main(verbosity=1)
