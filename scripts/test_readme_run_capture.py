#!/usr/bin/env python3
"""Tests for the run commands and the passing-run capture at the top of README.md.

The README's first fenced block runs the verifiers and its second block shows
what a passing run prints. The capture's first entry must be the report line the
verifiers print for the first fixture in sorted order, and its summary line must
count every fixture under fixtures/. The README names no spec version: the version
the suite covers is `spec.version` in conformance.json, which the README links.

Usage:
    python3 scripts/test_readme_run_capture.py
    python3 -m unittest discover -s scripts -p 'test_*.py'
"""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"
FIXTURES = REPO_ROOT / "fixtures"
FENCE = re.compile(r"^[ \t]*(```|~~~)")
VERSION = re.compile(r"v?[0-9]+\.[0-9]+\.[0-9]+")


def fenced_blocks(text: str) -> list[list[str]]:
    """The lines inside each fenced block of `text`, in order."""
    blocks: list[list[str]] = []
    current: list[str] | None = None
    for line in text.splitlines():
        if FENCE.match(line):
            if current is None:
                current = []
            else:
                blocks.append(current)
                current = None
        elif current is not None:
            current.append(line)
    return blocks


class ReadmeRunCaptureTest(unittest.TestCase):
    def setUp(self) -> None:
        self.readme = README.read_text(encoding="utf-8")
        self.blocks = fenced_blocks(self.readme)
        self.fixtures = sorted(FIXTURES.glob("*.json"))

    def capture(self) -> list[str]:
        self.assertGreaterEqual(len(self.blocks), 2, "README.md needs a command block and a capture block")
        return [line for line in self.blocks[1] if line.strip()]

    def test_first_block_runs_both_verifiers(self) -> None:
        self.assertGreaterEqual(len(self.blocks), 1)
        commands = self.blocks[0]
        self.assertIn("node verifiers/node/verify.mjs fixtures", commands)
        self.assertIn("python3 verifiers/python/verify.py fixtures", commands)

    def test_capture_summary_counts_every_fixture(self) -> None:
        n = len(self.fixtures)
        self.assertEqual(self.capture()[-1], f"summary: {n} pass, 0 fail ({n} fixtures)")

    def test_capture_first_entry_is_the_first_fixture(self) -> None:
        first = self.fixtures[0]
        fixture = json.loads(first.read_text(encoding="utf-8"))
        expected = fixture["expected"]["verifyResult"]
        self.assertEqual(expected, "ACCEPT", "the capture shows an ACCEPT entry")
        self.assertEqual(
            self.capture()[:3],
            [
                f"PASS  fixtures/{first.name}  [{fixture['fixtureType']}]",
                f"       expected: {expected}",
                "       observed: ACCEPT",
            ],
        )

    def test_readme_names_no_spec_version(self) -> None:
        matches = [line for line in self.readme.splitlines() if VERSION.search(line)]
        self.assertEqual(matches, [])
        profile = json.loads((REPO_ROOT / "conformance.json").read_text(encoding="utf-8"))
        self.assertTrue(profile["spec"]["version"])
        self.assertIn("`spec.version`", self.readme)
        self.assertIn("](./conformance.json)", self.readme)


if __name__ == "__main__":
    unittest.main()
