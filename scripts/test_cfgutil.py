#!/usr/bin/env python3
"""Tests for cfgutil: a manager config must parse exactly as syz-manager parses
it -- no more permissively, no less."""

import json
import os
import tempfile
import unittest

import cfgutil


class GoRuleParity(unittest.TestCase):
    def _write(self, text):
        fd, path = tempfile.mkstemp(suffix=".cfg")
        os.write(fd, text.encode())
        os.close(fd)
        self.addCleanup(os.unlink, path)
        return path

    def test_leading_hash_comment_is_stripped(self):
        cfg = cfgutil.load(self._write(
            '{\n'
            '  "enable_syscalls": [\n'
            '    "syz_IOConnectCallMethod$Foo_1",\n'
            '# "syz_IOConnectCallMethod$Foo_2",\n'
            '        # indented comments count too\n'
            '    "syz_IOConnectTrap2$Foo_7"\n'
            '  ]\n'
            '}\n'))
        self.assertEqual(cfg["enable_syscalls"],
                         ["syz_IOConnectCallMethod$Foo_1", "syz_IOConnectTrap2$Foo_7"])

    def test_hash_inside_a_string_survives(self):
        # The line-anchored rule needs no string-aware scanner to be safe: a '#'
        # can only start a line in valid JSON by opening a comment.
        cfg = cfgutil.load(self._write('{"note": "a#b", "n": "#lead"}'))
        self.assertEqual(cfg, {"note": "a#b", "n": "#lead"})

    def test_trailing_hash_comment_is_not_stripped(self):
        # Deliberate: syz-manager's regex is line-anchored, so a trailing comment
        # is a parse error there too. Accepting it here would let a config pass
        # our tooling and then fail at campaign launch.
        with self.assertRaises(ValueError):
            cfgutil.load(self._write('{"a": 1}   # trailing\n'))

    def test_slash_comments_are_not_stripped(self):
        # Same reason: syz-manager does not support // or /* */.
        with self.assertRaises(ValueError):
            cfgutil.load(self._write('{\n// nope\n"a": 1\n}\n'))
        with self.assertRaises(ValueError):
            cfgutil.load(self._write('{\n/* nope */\n"a": 1\n}\n'))

    def test_plain_json_is_untouched(self):
        d = {"target": "darwin/arm64", "enable_syscalls": ["syz_IOServiceClose"]}
        self.assertEqual(cfgutil.load(self._write(json.dumps(d))), d)

    def test_strip_comments_matches_the_go_replacement(self):
        # Go replaces the match (newline included) with nothing, joining nothing:
        # the newline that terminated the comment line is what survives.
        self.assertEqual(cfgutil.strip_comments('"a": 1,\n# c\n"b": 2'),
                         '"a": 1,\n"b": 2')


if __name__ == "__main__":
    unittest.main()
