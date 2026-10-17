#!/usr/bin/env python3
"""Tests that docs/continuous-verification.md says how the unit tests run.

The page lists the CI gates. The unit tests in scripts/test_*.py are not one of
them unless a workflow under .github/workflows/ runs them, so the page must give
the command that runs them and call them local-only exactly when no workflow
step runs that command.

Usage:
    python3 scripts/test_continuous_verification_doc.py
    python3 -m unittest discover -s scripts -p 'test_*.py'
"""
from __future__ import annotations

import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DOC = REPO_ROOT / "docs" / "continuous-verification.md"
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
COMMAND = "python3 -m unittest discover -s scripts -p 'test_*.py'"


def workflows_run_unit_tests() -> bool:
    """Whether a non-comment line of a workflow runs unittest discovery over scripts/."""
    for path in sorted(WORKFLOWS.iterdir()):
        if path.suffix not in {".yml", ".yaml"}:
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.lstrip().startswith("#") and "unittest discover -s scripts" in line:
                return True
    return False


class ContinuousVerificationDocTest(unittest.TestCase):
    def setUp(self) -> None:
        self.doc = DOC.read_text(encoding="utf-8")

    def test_doc_gives_the_unit_test_command(self) -> None:
        self.assertIn(COMMAND, self.doc)

    def test_doc_says_local_only_exactly_when_no_workflow_runs_them(self) -> None:
        in_ci = workflows_run_unit_tests()
        self.assertEqual(
            "local-only" in self.doc,
            not in_ci,
            "a workflow runs the unit tests, so the page must not call them local-only"
            if in_ci
            else "no workflow runs the unit tests, so the page must call them local-only",
        )


if __name__ == "__main__":
    unittest.main()
