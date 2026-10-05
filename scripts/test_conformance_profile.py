#!/usr/bin/env python3
"""Tests for scripts/conformance_profile.py --check.

`--check` must hold the README's "What this suite verifies" table to exactly
one row per fixture: a missing row, a row for a fixture that does not exist,
and a fixture named in more than one row are each reported.

The CheckReadmeTest tests run the script from a temporary copy of the files it
reads, so the repository's own README.md and conformance.json are never touched.

Usage:
    python3 scripts/test_conformance_profile.py
    python3 -m unittest discover -s scripts -p 'test_*.py'
"""
from __future__ import annotations

import contextlib
import io
import shutil
import subprocess
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


REPO_ROOT = Path(__file__).resolve().parent.parent


class CheckReadmeTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        (self.root / "scripts").mkdir()
        shutil.copy2(REPO_ROOT / "scripts" / "conformance_profile.py", self.root / "scripts")
        shutil.copytree(REPO_ROOT / "fixtures", self.root / "fixtures")
        shutil.copy2(REPO_ROOT / "conformance.json", self.root)
        shutil.copy2(REPO_ROOT / "README.md", self.root)

    def check(self) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(self.root / "scripts" / "conformance_profile.py"), "--check"],
            capture_output=True,
            text=True,
        )

    def test_current_repo_passes(self) -> None:
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("conformance.json is current", result.stdout)

    def test_missing_readme_is_a_one_line_problem(self) -> None:
        (self.root / "README.md").unlink()
        result = self.check()
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("README.md: cannot be read (No such file or directory)", result.stdout.splitlines())
        self.assertIn("conformance.json is current", result.stdout)

    def test_unreadable_readme_is_a_one_line_problem(self) -> None:
        (self.root / "README.md").unlink()
        (self.root / "README.md").mkdir()
        result = self.check()
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Traceback", result.stderr)
        problems = [line for line in result.stdout.splitlines() if line.startswith("README.md: cannot be read (")]
        self.assertEqual(len(problems), 1, result.stdout)


if __name__ == "__main__":
    unittest.main()
