#!/usr/bin/env python3
"""Tests for the root-file rule of scripts/conformance_profile.py --check.

Every file at the repository root must be named in the README, as a backticked
name or a link target, except the files git and npm read by convention. In a
git checkout the rule covers the tracked root files; in a copy that is not a
checkout it covers the root files the root `.gitignore` does not exclude. Both
cases are run here, each from a temporary copy of the files the script reads,
with git's repository-locating variables (GIT_DIR, GIT_INDEX_FILE and the
others a git hook exports) dropped, so the repository is never touched.

Usage:
    python3 scripts/test_conformance_profile_root_files.py
    python3 -m unittest discover -s scripts -p 'test_*.py'
"""
from __future__ import annotations

import os
import re
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
HAS_GIT = shutil.which("git") is not None
# Git without the user's or the system's configuration, so a global excludes
# file or hook cannot change what the checkout tracks, and without the
# variables that point git at the repository these tests are run from.
GIT_ENV = {**cp.git_env(), "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
# (root file name, .gitignore line, whether git ignores the file); each row is
# also checked against `git check-ignore` when git is installed.
GITIGNORE_CASES = [
    ("#x", "#x", False),  # a comment
    ("#x", "\\#x", True),
    ("!x", "\\!x", True),
    ("x", "!x", False),
    ("x.txt", "\\x.txt", True),
    ("a.b", "a\\.b", True),  # an escaped regex metacharacter is literal
    ("axb", "a\\.b", False),
    ("*", "\\*", True),
    ("x", "\\*", False),
    ("?", "\\?", True),
    ("x", "\\?", False),
    ("[x]", "\\[x]", True),
    ("x", "\\[x]", False),
    ("b.txt", "[^a].txt", True),
    ("a.txt", "[^a].txt", False),
    ("^.txt", "[^a].txt", True),
    ("a", "[!]]", True),
    ("]", "[]]", True),
    ("-", "[a-]", True),
    ("z", "[z-a]", True),
    ("q", "[z-a]", False),
    ("-", "[a\\-z]", True),
    ("c", "[a\\-z]", False),
    ("B", "[[:upper:]]", True),
    ("b", "[[:upper:]]", False),
    ("a b", "a[[:space:]]b", True),
    ("x", "[[:bogus:]]", False),
    ("x", "[x", False),
    ("x", "x\t", False),  # git keeps a trailing tab
    ("x\t", "x\t", True),
    ("z", "z  ", True),
    ("y ", "y\\ ", True),
    ("y", "y\\ ", False),
    ("x.txt", "x.txt\r", True),
    ("x", "x\\", False),
    ("X.txt", "x.txt", False),  # case-sensitive, as git is without core.ignorecase
    ("x.txt", "x.txt/", False),  # directories only
    ("x", "/x", True),
    ("x", "**/x", True),
    ("x", "/**", True),
    ("x", "x/**", False),
    ("x", "a/x", False),
    ("aXb", "a**b", True),
    ("é", "?", False),  # "?" matches one byte, and this name is two
    ("é", "??", True),
]


def unnamed(name: str) -> str:
    return f"{name} is at the repository root but README.md does not name it"


def copy_repo(root: Path) -> None:
    """Copy the files `--check` reads into `root`, which is not a git checkout."""
    (root / "scripts").mkdir(parents=True)
    shutil.copy2(REPO_ROOT / "scripts" / "conformance_profile.py", root / "scripts")
    shutil.copytree(REPO_ROOT / "fixtures", root / "fixtures")
    shutil.copy2(REPO_ROOT / "conformance.json", root)
    shutil.copy2(REPO_ROOT / "README.md", root)
    shutil.copy2(REPO_ROOT / ".gitignore", root)


def git(root: Path, *args: str | bytes) -> bytes:
    return subprocess.run(["git", *args], cwd=root, env=GIT_ENV, capture_output=True, check=True).stdout


class RootFileRuleTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name).resolve()
        self.root = self.tmp / "repo"
        copy_repo(self.root)

    def check(self, **env: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(self.root / "scripts" / "conformance_profile.py"), "--check"],
            env={**GIT_ENV, **env},
            capture_output=True,
            text=True,
        )

    def assert_passes(self, **env: str) -> None:
        result = self.check(**env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(PASSED, result.stdout.splitlines())

    def assert_reports(self, problem: str) -> None:
        result = self.check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn(problem, result.stdout.splitlines())
        self.assertNotIn(PASSED, result.stdout)

    def track(self) -> None:
        git(self.root, "init", "-q")
        git(self.root, "add", "--", ".gitignore", "README.md", "conformance.json", "fixtures", "scripts")

    def other_repository(self) -> dict[str, str]:
        """A second repository with NOTES.md staged, as the variables a git hook exports name it."""
        other = self.tmp / "other"
        other.mkdir()
        git(other, "init", "-q")
        (other / "NOTES.md").write_text("notes\n")
        git(other, "add", "--", "NOTES.md")
        return {"GIT_DIR": str(other / ".git"), "GIT_INDEX_FILE": str(other / ".git" / "index")}

    def test_non_git_copy_enforces_the_rule(self) -> None:
        self.assert_passes()
        (self.root / "NOTES.md").write_text("notes\n")
        self.assert_reports(unnamed("NOTES.md"))

    def test_non_git_copy_skips_files_the_gitignore_excludes(self) -> None:
        (self.root / "parity-report.json").write_text("{}\n")
        (self.root / ".DS_Store").write_text("")
        self.assert_passes()

    def test_non_git_copy_reads_a_gitignore_that_starts_with_a_byte_order_mark(self) -> None:
        # Git skips a UTF-8 byte-order mark at the start of .gitignore, so its
        # first pattern still applies.
        (self.root / ".gitignore").write_bytes(b"\xef\xbb\xbfNOTES.md\n")
        (self.root / "NOTES.md").write_text("notes\n")
        with mock.patch.object(cp, "REPO_ROOT", self.root):
            self.assertNotIn("NOTES.md", cp.root_files())
        self.assert_passes()

    def test_name_inside_a_longer_path_does_not_name_the_root_file(self) -> None:
        self.assertIn("verify.py", (self.root / "README.md").read_text())
        (self.root / "verify.py").write_text("x\n")
        self.assert_reports(unnamed("verify.py"))

    def test_titled_and_reference_style_links_name_the_root_file(self) -> None:
        readme = self.root / "README.md"
        original = readme.read_text()
        (self.root / "Makefile").write_text("all:\n")
        for mention in ['See [build](./Makefile "Build").', "[build]: ./Makefile"]:
            with self.subTest(mention=mention):
                readme.write_text(f"{original}\n{mention}\n")
                self.assert_passes()

    def test_non_git_copy_skips_root_directories(self) -> None:
        (self.root / "extras").mkdir()
        (self.root / "extras" / "NOTES.md").write_text("notes\n")
        self.assert_passes()

    def test_non_git_copy_skips_a_dot_git_file(self) -> None:
        # A linked worktree's .git file whose git directory is gone: git fails,
        # so the .gitignore fallback runs, and .git is not a file to name.
        (self.root / ".git").write_text(f"gitdir: {self.tmp / 'missing'}\n")
        self.assert_passes()

    @unittest.skipUnless(HAS_GIT, "git is not installed")
    def test_copy_inside_another_checkout_enforces_the_rule(self) -> None:
        git(self.tmp, "init", "-q")
        (self.root / "NOTES.md").write_text("notes\n")
        self.assert_reports(unnamed("NOTES.md"))

    @unittest.skipUnless(HAS_GIT, "git is not installed")
    def test_checkout_enforces_the_rule_on_tracked_files(self) -> None:
        self.track()
        self.assert_passes()
        (self.root / "NOTES.md").write_text("notes\n")
        self.assert_passes()  # untracked, so a checkout does not hold it to the rule
        git(self.root, "add", "--", "NOTES.md")
        self.assert_reports(unnamed("NOTES.md"))

    @unittest.skipUnless(HAS_GIT, "git is not installed")
    def test_checkout_skips_tracked_files_below_the_root(self) -> None:
        self.track()
        (self.root / "docs").mkdir()
        (self.root / "docs" / "NOTES.md").write_text("notes\n")
        git(self.root, "add", "--", "docs/NOTES.md")
        self.assert_passes()

    @unittest.skipUnless(HAS_GIT, "git is not installed")
    def test_checkout_paths_that_are_not_utf8(self) -> None:
        self.track()
        blob = git(self.root, "hash-object", "-w", "README.md").decode().strip()
        git(self.root, "update-index", "--add", "--cacheinfo", f"100644,{blob},fixtures/bad\xff.txt".encode("latin-1"))
        self.assert_passes()  # below the root, so not held to the rule
        git(self.root, "update-index", "--add", "--cacheinfo", f"100644,{blob},bad\xff.txt".encode("latin-1"))
        self.assert_reports(
            "bad\\xff.txt is at the repository root but its name is not valid UTF-8, so README.md cannot name it"
        )

    @unittest.skipUnless(HAS_GIT, "git is not installed")
    def test_check_reads_its_own_checkout_when_git_variables_name_another(self) -> None:
        self.track()
        self.assert_passes(**self.other_repository())

    @unittest.skipUnless(HAS_GIT, "git is not installed")
    def test_these_tests_leave_the_repository_git_variables_name_alone(self) -> None:
        hook_env = self.other_repository()
        test = "RootFileRuleTest.test_checkout_enforces_the_rule_on_tracked_files"
        result = subprocess.run(
            [sys.executable, __file__, test], env={**GIT_ENV, **hook_env}, capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(git(self.tmp / "other", "ls-files"), b"NOTES.md\n")

    @unittest.skipUnless(HAS_GIT, "git is not installed")
    def test_git_env_drops_every_variable_git_names_as_repository_local(self) -> None:
        names = git(self.tmp, "rev-parse", "--local-env-vars").decode().split()
        self.assertIn("GIT_DIR", names)
        self.assertLessEqual(set(names), cp.GIT_LOCAL_ENV)
        with mock.patch.dict(os.environ, {name: "x" for name in names}):
            self.assertFalse(set(names) & set(cp.git_env()))

    def test_readme_lists_the_exempt_files(self) -> None:
        text = (REPO_ROOT / "README.md").read_text()
        exempt = re.search(r"read by convention\s*\(([^)]*)\)", text)
        self.assertIsNotNone(exempt, "README.md does not list the exempt root files")
        self.assertEqual(set(re.findall(r"`([^`]+)`", exempt.group(1))), cp.ROOT_CONVENTION_FILES)


class ReadmeNamesTest(unittest.TestCase):
    def test_names_that_count(self) -> None:
        for text in [
            "Build with `Makefile`.",
            "See [the guide](./Makefile).",
            "See [the guide](Makefile).",
            "See [the guide](./Makefile#targets).",
            'See [build](./Makefile "Build").',
            "See [build](Makefile 'Build').",
            "See [build](./Makefile (Build)).",
            'See [build](./Makefile#targets "Build").',
            "See [build](<./Makefile>).",
            "See [build](\n  ./Makefile\n  \"Build\"\n).",
            "[build]: ./Makefile",
            'Intro.\n\n[build]: Makefile "Build"\n',
            "   [build]: <./Makefile#targets>\n",
            "[build]:\n  ./Makefile\n  'Build'\n",
        ]:
            with self.subTest(text=text):
                self.assertTrue(cp.readme_names(text, "Makefile"))

    def test_names_that_do_not_count(self) -> None:
        for name, text in [
            ("Makefile", "The Makefile builds it."),
            ("verify.py", "Run `scripts/verify.py`."),
            ("verify.py", "See [it](./scripts/verify.py)."),
            ("main", "Pushes to `main-branch`."),
            ("a.md", "See [it](./a.md.bak)."),
            ("Makefile", 'See [it](./Makefile.bak "Build").'),
            ("Makefile", 'See [it](./Makefile "Build" extra).'),
            ("Makefile", "See [it](\n\n./Makefile)."),
            ("Makefile", "[it]: ./Makefile.bak"),
            ("Makefile", "[it]: ./scripts/Makefile"),
            ("Makefile", "[it]: ./Makefile and more words"),
            ("Makefile", "Text [it]: ./Makefile"),
            ("Makefile", "    [it]: ./Makefile"),
            ("Makefile", "[^1]: ./Makefile"),
        ]:
            with self.subTest(name=name, text=text):
                self.assertFalse(cp.readme_names(text, name))

    def test_undecodable_root_name_is_one_problem(self) -> None:
        with mock.patch.object(cp, "root_files", return_value=[os.fsdecode(b"bad\xff.txt")]):
            self.assertEqual(
                cp.check_root_files("README"),
                ["bad\\xff.txt is at the repository root but its name is not valid UTF-8, so README.md cannot name it"],
            )


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
            ("parity-report.json", "parity-report.json/"),
            ("x.json", "fixtures/x.json"),
            ("README.md", "*.pem"),
        ]:
            with self.subTest(pattern=pattern):
                self.assertFalse(cp.gitignored(name, [pattern]))

    def test_last_matching_pattern_wins(self) -> None:
        self.assertFalse(cp.gitignored(".env.example", [".env.*", "!.env.example"]))
        self.assertTrue(cp.gitignored(".env.example", ["!.env.example", ".env.*"]))

    def test_lines_are_read_as_git_reads_them(self) -> None:
        for name, line, ignored in GITIGNORE_CASES:
            with self.subTest(name=name, line=line):
                self.assertIs(cp.gitignored(name, [line]), ignored)

    @unittest.skipUnless(HAS_GIT, "git is not installed")
    def test_cases_agree_with_git_check_ignore(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git(root, "init", "-q")
            for name, line, ignored in GITIGNORE_CASES:
                with self.subTest(name=name, line=line):
                    (root / ".gitignore").write_bytes(os.fsencode(line) + b"\n")
                    (root / name).write_text("")
                    result = subprocess.run(
                        ["git", "-c", "core.ignorecase=false", "check-ignore", "-q", "--", name],
                        cwd=root,
                        env=GIT_ENV,
                    )
                    (root / name).unlink()
                    self.assertEqual(result.returncode, 0 if ignored else 1)


if __name__ == "__main__":
    unittest.main()
