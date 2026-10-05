#!/usr/bin/env python3
"""Tests for the root-file rule of scripts/conformance_profile.py --check.

Every file at the repository root must be named in the README, except the
files git and npm read by convention. In a git checkout the rule covers the
tracked root files; in a copy that is not a checkout it covers the root files
the root `.gitignore` does not exclude. Both cases are run here, each from a
temporary copy of the files the script reads, so the repository is never
touched.

Usage:
    python3 scripts/test_conformance_profile_root_files.py
    python3 -m unittest discover -s scripts -p 'test_*.py'
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import conformance_profile as cp  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
PASSED = "README.md names every root file"
UNNAMED = "NOTES.md is at the repository root but README.md does not name it"
# Git without the user's or the system's configuration, so a global excludes
# file or hook cannot change what the checkout tracks.
GIT_ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}


def copy_repo(root: Path) -> None:
    """Copy the files `--check` reads into `root`, which is not a git checkout."""
    (root / "scripts").mkdir(parents=True)
    shutil.copy2(REPO_ROOT / "scripts" / "conformance_profile.py", root / "scripts")
    shutil.copytree(REPO_ROOT / "fixtures", root / "fixtures")
    shutil.copy2(REPO_ROOT / "conformance.json", root)
    shutil.copy2(REPO_ROOT / "README.md", root)
    shutil.copy2(REPO_ROOT / ".gitignore", root)


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=root, env=GIT_ENV, capture_output=True, check=True)


class RootFileRuleTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name).resolve()
        self.root = self.tmp / "repo"
        copy_repo(self.root)

    def check(self) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(self.root / "scripts" / "conformance_profile.py"), "--check"],
            env=GIT_ENV,
            capture_output=True,
            text=True,
        )

    def assert_passes(self) -> None:
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(PASSED, result.stdout.splitlines())

    def assert_reports_unnamed_file(self) -> None:
        result = self.check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn(UNNAMED, result.stdout.splitlines())
        self.assertNotIn(PASSED, result.stdout)

    def test_non_git_copy_enforces_the_rule(self) -> None:
        self.assert_passes()
        (self.root / "NOTES.md").write_text("notes\n")
        self.assert_reports_unnamed_file()

    def test_non_git_copy_skips_files_the_gitignore_excludes(self) -> None:
        (self.root / "parity-report.json").write_text("{}\n")
        (self.root / ".DS_Store").write_text("")
        self.assert_passes()

    @unittest.skipUnless(shutil.which("git"), "git is not installed")
    def test_copy_inside_another_checkout_enforces_the_rule(self) -> None:
        git(self.tmp, "init", "-q")
        (self.root / "NOTES.md").write_text("notes\n")
        self.assert_reports_unnamed_file()

    @unittest.skipUnless(shutil.which("git"), "git is not installed")
    def test_checkout_enforces_the_rule_on_tracked_files(self) -> None:
        git(self.root, "init", "-q")
        git(self.root, "add", "--", ".gitignore", "README.md", "conformance.json", "fixtures", "scripts")
        self.assert_passes()
        (self.root / "NOTES.md").write_text("notes\n")
        self.assert_passes()  # untracked, so a checkout does not hold it to the rule
        git(self.root, "add", "--", "NOTES.md")
        self.assert_reports_unnamed_file()

    def test_unreadable_readme_is_one_problem(self) -> None:
        with mock.patch.object(cp, "README", self.tmp / "missing" / "README.md"):
            self.assertEqual(cp.check_root_files(), ["root files not checked: README.md cannot be read"])


class GitignoredTest(unittest.TestCase):
    def test_patterns_that_match_a_root_file(self) -> None:
        for name, pattern in [
            (".env.local", ".env.*"),
            ("parity-report.json", "/parity-report.json"),
            ("a.pyc", "**/*.py[cod]"),
        ]:
            with self.subTest(pattern=pattern):
                self.assertTrue(cp.gitignored(name, [pattern]))

    def test_patterns_that_do_not_match_a_root_file(self) -> None:
        for name, pattern in [
            ("node_modules", "node_modules/"),
            ("x.json", "fixtures/x.json"),
            ("README.md", "*.pem"),
        ]:
            with self.subTest(pattern=pattern):
                self.assertFalse(cp.gitignored(name, [pattern]))

    def test_last_matching_pattern_wins(self) -> None:
        self.assertFalse(cp.gitignored(".env.example", [".env.*", "!.env.example"]))
        self.assertTrue(cp.gitignored(".env.example", ["!.env.example", ".env.*"]))


if __name__ == "__main__":
    unittest.main()
