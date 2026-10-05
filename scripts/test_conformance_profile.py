#!/usr/bin/env python3
"""Tests for the README table check in conformance_profile.py.

`--check` must hold the README's "What this suite verifies" table to exactly
one row per fixture: a missing row, a row for a fixture that does not exist,
and a fixture named in more than one row are each reported.

Usage:  python3 scripts/test_conformance_profile.py
"""
from __future__ import annotations

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import conformance_profile as cp  # noqa: E402

PROFILE = {"requirements": [{"fixture": "fixtures/a.json"}, {"fixture": "fixtures/b.json"}]}
ROW_A = "| Item A | `fixtures/a.json` |"
ROW_B = "| Item B | `fixtures/b.json` |"


def readme(*rows: str) -> str:
    lines = ["# Suite", "", cp.README_TABLE_MARKER, "", "| Item | Covered by |", "|---|---|", *rows, "", "Trailing text."]
    return "\n".join(lines) + "\n"


def duplicate_first_fixture_row(text: str) -> tuple[str, str]:
    """Copy the first fixture row of the table so it appears twice."""
    lines = text.splitlines(keepends=True)
    for i, line in enumerate(lines):
        refs = cp.README_FIXTURE_REF.findall(line)
        if line.startswith("|") and refs:
            return "".join(lines[: i + 1] + [line] + lines[i + 1 :]), refs[0]
    raise AssertionError("no fixture row found")


class ReadmeTableCheck(unittest.TestCase):
    @contextlib.contextmanager
    def readme_text(self, text: str):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "README.md"
            path.write_text(text)
            with mock.patch.object(cp, "README", path):
                yield

    def problems(self, text: str) -> list[str]:
        with self.readme_text(text):
            return cp.check_readme_table(PROFILE)

    def test_one_row_per_fixture_passes(self):
        self.assertEqual(self.problems(readme(ROW_A, ROW_B)), [])

    def test_missing_row_is_reported(self):
        self.assertEqual(self.problems(readme(ROW_A)), ["README.md table has no row for fixtures/b.json"])

    def test_unknown_fixture_is_reported(self):
        self.assertEqual(
            self.problems(readme(ROW_A, ROW_B, "| Item C | `fixtures/c.json` |")),
            ["README.md table names fixtures/c.json, which is not in fixtures/"],
        )

    def test_duplicated_row_is_reported(self):
        self.assertEqual(
            self.problems(readme(ROW_A, ROW_B, ROW_A)),
            ["README.md table names fixtures/a.json in 2 rows"],
        )

    def test_each_duplicated_fixture_is_reported_with_its_row_count(self):
        self.assertEqual(
            self.problems(readme(ROW_B, ROW_A, ROW_B, ROW_A, ROW_B)),
            [
                "README.md table names fixtures/a.json in 2 rows",
                "README.md table names fixtures/b.json in 3 rows",
            ],
        )

    def test_fixture_named_twice_in_one_row_is_one_row(self):
        row = "| Item A, see `fixtures/a.json` | `fixtures/a.json` |"
        self.assertEqual(self.problems(readme(row, ROW_B)), [])

    def test_committed_readme_passes(self):
        self.assertEqual(cp.check_readme_table(cp.build()), [])

    def test_check_exits_1_on_committed_readme_with_a_duplicated_row(self):
        text, fixture = duplicate_first_fixture_row(cp.README.read_text())
        out = io.StringIO()
        with self.readme_text(text), mock.patch.object(sys, "argv", ["conformance_profile.py", "--check"]):
            with contextlib.redirect_stdout(out):
                rc = cp.main()
        self.assertEqual(rc, 1)
        self.assertIn(f"README.md table names {fixture} in 2 rows", out.getvalue().splitlines())
        self.assertNotIn("README.md table names all", out.getvalue())


if __name__ == "__main__":
    unittest.main()
