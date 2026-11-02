#!/usr/bin/env python3
"""Tests of the Python reference verifier's verify_fixture and its CLI report.

verifiers/python/verify.py verifies each fixture with verify_fixture, which
presents the token `presentations` times (default 1) against a new jti cache
and returns the last result. These tests load the file as a module, as a
program would, run its CLI, and check that:

  - verify_fixture raises a ValueError ("presentations must be at least 1")
    instead of returning when `presentations` is an integer below 1, on an
    accepting and on two rejecting fixtures;
  - a `presentations` that is not an integer (a float, a string, None or a
    boolean) keeps the default of 1, and 2 presents the token twice;
  - the CLI reports a fixture whose `presentations` is an integer below 1 as
    one FAIL line with the error, counts it as a fail, judges the fixtures
    after it and exits 1;
  - the Node verifier's CLI prints the same report and exits with the same
    code.

They need the Python verifier's dependencies (verifiers/python/requirements.txt)
installed for the interpreter that runs them, and are skipped without them;
the comparison with the Node CLI also needs node on PATH and the Node
dependency installed (`npm install`), and is skipped without either.

Usage:
    python3 scripts/test_python_verifier_module.py
    python3 -m unittest discover -s scripts -p 'test_*.py'
"""
from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
VERIFY = REPO_ROOT / "verifiers" / "python" / "verify.py"
NODE_VERIFY = REPO_ROOT / "verifiers" / "node" / "verify.mjs"
FIXTURES = REPO_ROOT / "fixtures"
NODE = shutil.which("node")
NODE_DEPENDENCY = REPO_ROOT / "node_modules" / "@noble" / "post-quantum" / "package.json"
MISSING = [name for name in ("cryptography", "dilithium_py") if importlib.util.find_spec(name) is None]

# The error verify_fixture raises for an integer `presentations` below 1.
BELOW_ONE_MESSAGE = "presentations must be at least 1"
# One accepting and two rejecting fixtures, with the verdict each carries when
# `presentations` is absent.
VERDICT_FIXTURES = {
    "cgt-compact-valid": (True, None),
    "cgt-compact-bad-signature": (False, "BAD_SIGNATURE"),
    "cgt-compact-expired": (False, "EXPIRED"),
}
BELOW_ONE = (0, -1, -9007199254740991)
ABSENT = object()


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def with_presentations(fixture: dict, value: object) -> dict:
    """A copy of `fixture` with `presentations` set to `value`, or removed for ABSENT."""
    data = copy.deepcopy(fixture)
    data.pop("presentations", None)
    if value is not ABSENT:
        data["presentations"] = value
    return data


def write_copy(directory: Path, name: str, **fields: object) -> Path:
    """A copy of fixtures/<name>.json in `directory`, with `fields` set on it."""
    fixture = load_fixture(name)
    fixture.update(fields)
    target = directory / f"{name}.json"
    target.write_text(json.dumps(fixture, indent=2) + "\n", encoding="utf-8")
    return target


def run(*command: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command), cwd=REPO_ROOT, capture_output=True, text=True, encoding="utf-8", timeout=300
    )


def report(proc: subprocess.CompletedProcess[str]) -> str:
    return f"exit {proc.returncode}\nstdout:\n{proc.stdout[-2000:]}\nstderr:\n{proc.stderr[-2000:]}"


@unittest.skipIf(MISSING, f"the Python verifier's dependencies are not installed: {', '.join(MISSING)}")
class PythonVerifierModuleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        spec = importlib.util.spec_from_file_location("aap_conformance_python_verifier", VERIFY)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        cls.verifier = module

    @classmethod
    def tearDownClass(cls) -> None:
        sys.modules.pop("aap_conformance_python_verifier", None)

    def run_cli(self, path: Path | str) -> subprocess.CompletedProcess[str]:
        return run(sys.executable, str(VERIFY), str(path))

    def test_verify_fixture_raises_for_an_integer_presentations_below_one(self) -> None:
        for name, verdict in VERDICT_FIXTURES.items():
            fixture = load_fixture(name)
            absent = self.verifier.verify_fixture(with_presentations(fixture, ABSENT))
            self.assertEqual((absent.accepted, absent.category), verdict)
            for value in BELOW_ONE:
                with self.subTest(fixture=name, presentations=value):
                    try:
                        returned = self.verifier.verify_fixture(with_presentations(fixture, value))
                    except ValueError as exc:
                        self.assertEqual(str(exc), BELOW_ONE_MESSAGE)
                    else:
                        self.fail(f"verify_fixture returned {returned!r} instead of raising")

    def test_verify_fixture_keeps_the_default_for_presentations_that_is_not_an_integer(self) -> None:
        fixture = load_fixture("cgt-compact-valid")
        for value in (ABSENT, 1, 0.5, "0", None, True):
            with self.subTest(presentations="absent" if value is ABSENT else value):
                result = self.verifier.verify_fixture(with_presentations(fixture, value))
                self.assertEqual((result.accepted, result.category), (True, None))
        replayed = self.verifier.verify_fixture(with_presentations(fixture, 2))
        self.assertEqual((replayed.accepted, replayed.category), (False, "REPLAYED_JTI"))

    def test_cli_reports_a_presentations_below_one_fixture_as_one_fail_line(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            below_one = write_copy(Path(tmp), "cgt-compact-bad-signature", presentations=0)
            proc = self.run_cli(below_one)
        lines = proc.stdout.splitlines()
        self.assertEqual(
            [line for line in lines if line.startswith("FAIL ")],
            [f"FAIL  {below_one}  [cgt]  (verify error: {BELOW_ONE_MESSAGE})"],
            report(proc),
        )
        self.assertEqual([line for line in lines if line.startswith("PASS")], [], report(proc))
        self.assertEqual(lines[-1:], ["summary: 0 pass, 1 fail (1 fixtures)"], report(proc))
        self.assertEqual(proc.stderr, "", report(proc))
        self.assertEqual(proc.returncode, 1, report(proc))

    def test_cli_judges_the_fixtures_after_a_presentations_below_one_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            below_one = write_copy(Path(tmp), "cgt-compact-bad-signature", presentations=0)
            valid = write_copy(Path(tmp), "cgt-compact-valid")
            proc = self.run_cli(tmp)
        lines = proc.stdout.splitlines()
        fail_line = f"FAIL  {below_one}  [cgt]  (verify error: {BELOW_ONE_MESSAGE})"
        pass_line = f"PASS  {valid}  [cgt]"
        self.assertIn(fail_line, lines, report(proc))
        self.assertIn(pass_line, lines, report(proc))
        self.assertLess(lines.index(fail_line), lines.index(pass_line), report(proc))
        self.assertEqual(lines[lines.index(pass_line) + 2], "       observed: ACCEPT", report(proc))
        self.assertEqual(lines[-1:], ["summary: 1 pass, 1 fail (2 fixtures)"], report(proc))
        self.assertEqual(proc.returncode, 1, report(proc))

    def test_cli_report_matches_the_node_cli_on_a_presentations_below_one_fixture(self) -> None:
        if not NODE or not NODE_DEPENDENCY.is_file():
            self.skipTest("node is not on PATH or the Node dependency is not installed; run npm install")
        with tempfile.TemporaryDirectory() as tmp:
            write_copy(Path(tmp), "cgt-compact-bad-signature", presentations=0)
            write_copy(Path(tmp), "cgt-compact-valid")
            python = self.run_cli(tmp)
            node = run(NODE, str(NODE_VERIFY), tmp)
        for name, proc in (("python", python), ("node", node)):
            self.assertEqual(
                proc.stdout.splitlines()[-1:], ["summary: 1 pass, 1 fail (2 fixtures)"], f"{name}\n{report(proc)}"
            )
        self.assertEqual(python.stdout, node.stdout)
        self.assertEqual(python.returncode, node.returncode)


if __name__ == "__main__":
    unittest.main()
