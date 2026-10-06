#!/usr/bin/env python3
"""Tests for scripts/conformance_profile.py --check.

`--check` must hold the README's "What this suite verifies" table to exactly
one row per fixture: a missing row, a row for a fixture that does not exist,
and a fixture named in more than one row are each reported, indented rows
included. A file the script cannot read or decode, and a conformance.json it cannot
write, is a one-line problem, not a traceback, and an argument other than
`--check` writes nothing.

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
        return cp.check_readme_table(PROFILE, text)

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

    def test_indented_row_does_not_end_the_table(self):
        self.assertEqual(self.problems(readme(ROW_A, "   " + ROW_B)), [])

    def test_indented_duplicated_row_is_reported(self):
        self.assertEqual(
            self.problems(readme(ROW_A, ROW_B, "   " + ROW_A)),
            ["README.md table names fixtures/a.json in 2 rows"],
        )

    def test_indented_unknown_fixture_is_reported(self):
        self.assertEqual(
            self.problems(readme(ROW_A, ROW_B, "\t| Item C | `fixtures/c.json` |")),
            ["README.md table names fixtures/c.json, which is not in fixtures/"],
        )

    def test_fixture_named_twice_in_one_row_is_one_row(self):
        row = "| Item A, see `fixtures/a.json` | `fixtures/a.json` |"
        self.assertEqual(self.problems(readme(row, ROW_B)), [])

    def test_committed_readme_passes(self):
        self.assertEqual(cp.check_readme_table(cp.build(), cp.README.read_text()), [])

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

    def run_script(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(self.root / "scripts" / "conformance_profile.py"), *args],
            capture_output=True,
            text=True,
        )

    def check(self) -> subprocess.CompletedProcess:
        return self.run_script("--check")

    def assert_problems(self, result: subprocess.CompletedProcess, lines: list[str]) -> None:
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.stdout.splitlines(), lines)

    def test_current_repo_passes(self) -> None:
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("conformance.json is current", result.stdout)

    def test_missing_readme_is_a_one_line_problem(self) -> None:
        (self.root / "README.md").unlink()
        result = self.check()
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            ["conformance.json is current", "README.md: cannot be read (No such file or directory)"],
        )

    def test_unreadable_readme_is_a_one_line_problem(self) -> None:
        (self.root / "README.md").unlink()
        (self.root / "README.md").mkdir()
        result = self.check()
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Traceback", result.stderr)
        problems = [line for line in result.stdout.splitlines() if "README.md" in line]
        self.assertEqual(len(problems), 1, result.stdout)
        self.assertTrue(problems[0].startswith("README.md: cannot be read ("), result.stdout)

    def test_readme_not_utf8_is_a_one_line_problem(self) -> None:
        path = self.root / "README.md"
        path.write_bytes(b"\xff\xfe" + path.read_bytes())
        self.assert_problems(
            self.check(), ["conformance.json is current", "README.md: cannot be read (not valid UTF-8)"]
        )

    def test_unreadable_conformance_json_is_a_one_line_problem(self) -> None:
        (self.root / "conformance.json").unlink()
        (self.root / "conformance.json").mkdir()
        fixtures = len(list((self.root / "fixtures").glob("*.json")))
        self.assert_problems(
            self.check(),
            [
                "conformance.json: cannot be read (Is a directory)",
                f"README.md table names all {fixtures} fixtures",
                "README.md names every root file",
            ],
        )

    def test_unwritable_conformance_json_is_a_one_line_problem(self) -> None:
        (self.root / "conformance.json").unlink()
        (self.root / "conformance.json").mkdir()
        self.assert_problems(self.run_script(), ["conformance.json: cannot be written (Is a directory)"])

    def test_fixture_not_json_is_a_one_line_problem(self) -> None:
        (self.root / "fixtures" / "ait-compact-valid.json").write_text("{not json\n")
        self.assert_problems(
            self.check(),
            [
                "fixtures/ait-compact-valid.json: not valid JSON"
                " (Expecting property name enclosed in double quotes, line 1 column 2)"
            ],
        )

    def test_each_unusable_fixture_is_a_one_line_problem(self) -> None:
        fixtures = self.root / "fixtures"
        (fixtures / "ait-compact-valid.json").write_bytes(b"\xff{}")
        (fixtures / "zz-empty.json").write_text("{}")
        (fixtures / "zz-list.json").write_text("[]")
        self.assert_problems(
            self.check(),
            [
                "fixtures/ait-compact-valid.json: cannot be read (not valid UTF-8)",
                'fixtures/zz-empty.json: has no "expected" member',
                "fixtures/zz-list.json: is not a fixture object",
            ],
        )

    def test_unusable_fixture_writes_nothing(self) -> None:
        (self.root / "fixtures" / "ait-compact-valid.json").write_text("{not json\n")
        before = (self.root / "conformance.json").read_bytes()
        result = self.run_script()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual((self.root / "conformance.json").read_bytes(), before)

    def test_help_prints_usage_and_writes_nothing(self) -> None:
        (self.root / "conformance.json").write_text("{}\n")
        result = self.run_script("--help")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(result.stdout.startswith("usage: conformance_profile.py"), result.stdout)
        self.assertNotIn("wrote conformance.json", result.stdout)
        self.assertEqual((self.root / "conformance.json").read_text(), "{}\n")

    def test_unknown_argument_is_an_error_and_writes_nothing(self) -> None:
        for arg in ("--chek", "--ch", "check"):
            with self.subTest(arg=arg):
                (self.root / "conformance.json").write_text("{}\n")
                result = self.run_script(arg)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertTrue(result.stderr.startswith("usage: conformance_profile.py"), result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertEqual((self.root / "conformance.json").read_text(), "{}\n")


if __name__ == "__main__":
    unittest.main()
