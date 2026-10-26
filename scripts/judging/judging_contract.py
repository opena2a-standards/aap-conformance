#!/usr/bin/env python3
"""Judging contract check for both reference verifiers.

A fixture is judged against a verdict only when `expected` is an object whose
`verifyResult` is a string that, uppercased, is ACCEPT or REJECT. Any other
fixture is reported FAIL with a fixed reason on its status line, still prints
its observed verdict, and counts as a failure, so the run exits 1. A file
whose JSON value is not an object is reported as a load error.

The inputs are built at run time in a temporary directory from
fixtures/cgt-compact-bad-signature.json (rejected) and
fixtures/cgt-compact-valid.json (accepted); nothing is written under
fixtures/. Each verifier runs once per cell, with absolute paths. For every
cell the check asserts the exit code, the stdout line count, the status line,
the expected line, the start of the observed line and the summary line, and
that the two verifiers exit with the same code and print byte-identical
stdout.

Usage:  python3 scripts/judging/judging_contract.py
Exit code: 0 when every cell holds under both verifiers, else 1.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VERIFIERS = {
    "node": ["node", str(ROOT / "verifiers" / "node" / "verify.mjs")],
    "py": [sys.executable, str(ROOT / "verifiers" / "python" / "verify.py")],
}
REJECTED = ROOT / "fixtures" / "cgt-compact-bad-signature.json"
ACCEPTED = ROOT / "fixtures" / "cgt-compact-valid.json"
RUN_TIMEOUT_SECONDS = 120

# The two reasons the verifiers print. Every cell below reads them from here.
REASONS = {
    "notObject": "(load error: not a JSON object)",
    "noVerdict": "(no expected verdict: expected.verifyResult must be ACCEPT or REJECT)",
}

NO_VERDICT_STATUS = "FAIL  {path0}  [cgt]  " + REASONS["noVerdict"]
NOT_OBJECT_STATUS = "FAIL  {path0}  " + REASONS["notObject"]
PASS_STATUS = "PASS  {path0}  [cgt]"
EXPECTED_NOTHING = "       expected: "
OBSERVED_REJECT = "       observed: REJECT[BAD_SIGNATURE"
OBSERVED_ACCEPT = "       observed: ACCEPT"
ONE_FAILED = "summary: 0 pass, 1 fail (1 fixtures)"
ONE_PASSED = "summary: 1 pass, 0 fail (1 fixtures)"

# C1 runs the unchanged rejected fixture; its stdout is pinned to the base
# commit's, byte for byte.
UNCHANGED_REJECTED_STDOUT = [
    PASS_STATUS,
    "       expected: REJECT [BAD_SIGNATURE]",
    '       observed: REJECT[BAD_SIGNATURE: signature does not verify under kid "broker-key-1"]',
    "",
    ONE_PASSED,
]


def without_expected(fixture: dict) -> dict:
    return {key: value for key, value in fixture.items() if key != "expected"}


def with_expected(fixture: dict, expected: object) -> dict:
    out = dict(fixture)
    out["expected"] = expected
    return out


def build_inputs(directory: Path) -> None:
    """Write every cell's input file; the unchanged inputs are byte copies."""
    rejected = json.loads(REJECTED.read_text(encoding="utf-8"))
    accepted = json.loads(ACCEPTED.read_text(encoding="utf-8"))
    values = {
        "j1.json": without_expected(rejected),
        "j2.json": with_expected(rejected, {"verifyResult": ""}),
        "j3.json": with_expected(rejected, {"verifyResult": "ACCEPTED"}),
        "j3b.json": with_expected(accepted, {"verifyResult": " ACCEPT"}),
        "j4.json": with_expected(rejected, {"verifyResult": None}),
        "j5.json": with_expected(rejected, {"verifyResult": 5}),
        "j6.json": with_expected(rejected, "ACCEPT"),
        "j7.json": with_expected(rejected, None),
        "j8.json": without_expected(accepted),
        "j9-array.json": [],
        "j9-string.json": "ACCEPT",
        "j9-number.json": 5,
        "j9-true.json": True,
        "j9-null.json": None,
        "c2.json": with_expected(rejected, {"verifyResult": "reject"}),
        "c3.json": with_expected(accepted, {"verifyResult": "accept"}),
    }
    for name, value in values.items():
        (directory / name).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    shutil.copyfile(REJECTED, directory / "unchanged-rejected.json")
    shutil.copyfile(ACCEPTED, directory / "unchanged-accepted.json")


@dataclass
class Run:
    """One verifier invocation: input files, exit code, line count, line checks.

    A check is (line index, "is" or "begins", text); "{path0}" and "{path1}"
    in the text stand for the absolute paths of the first and second input.
    When `stdout` is set, the whole stdout must equal those lines, byte for
    byte.
    """

    label: str
    files: list[str]
    exit_code: int
    line_count: int
    checks: list[tuple[int, str, str]] = field(default_factory=list)
    stdout: list[str] | None = None


def no_verdict(expected_line: str, observed_begins: str) -> list[tuple[int, str, str]]:
    return [
        (0, "is", NO_VERDICT_STATUS),
        (1, "is", expected_line),
        (2, "begins", observed_begins),
        (-1, "is", ONE_FAILED),
    ]


def no_verdict_run(label: str, name: str, expected_line: str, observed_begins: str) -> Run:
    return Run(label, [name], 1, 5, no_verdict(expected_line, observed_begins))


def passed_run(label: str, name: str) -> Run:
    return Run(label, [name], 0, 5, [(0, "is", PASS_STATUS), (-1, "is", ONE_PASSED)])


CELLS: list[tuple[str, list[Run]]] = [
    ("J1", [no_verdict_run("J1", "j1.json", EXPECTED_NOTHING, OBSERVED_REJECT)]),
    ("J2", [no_verdict_run("J2", "j2.json", EXPECTED_NOTHING, OBSERVED_REJECT)]),
    ("J3", [no_verdict_run("J3", "j3.json", "       expected: ACCEPTED", OBSERVED_REJECT)]),
    ("J3b", [no_verdict_run("J3b", "j3b.json", "       expected:  ACCEPT", OBSERVED_ACCEPT)]),
    ("J4", [no_verdict_run("J4", "j4.json", EXPECTED_NOTHING, OBSERVED_REJECT)]),
    ("J5", [no_verdict_run("J5", "j5.json", EXPECTED_NOTHING, OBSERVED_REJECT)]),
    ("J6", [no_verdict_run("J6", "j6.json", EXPECTED_NOTHING, OBSERVED_REJECT)]),
    ("J7", [no_verdict_run("J7", "j7.json", EXPECTED_NOTHING, OBSERVED_REJECT)]),
    ("J8", [no_verdict_run("J8", "j8.json", EXPECTED_NOTHING, OBSERVED_ACCEPT)]),
    (
        "J9",
        [
            Run(label, [name], 1, 3, [(0, "is", NOT_OBJECT_STATUS), (-1, "is", ONE_FAILED)])
            for label, name in [
                ("J9 []", "j9-array.json"),
                ('J9 "ACCEPT"', "j9-string.json"),
                ("J9 5", "j9-number.json"),
                ("J9 true", "j9-true.json"),
                ("J9 null", "j9-null.json"),
            ]
        ],
    ),
    (
        "M1",
        [
            Run(
                "M1",
                ["j4.json", "unchanged-accepted.json"],
                1,
                8,
                no_verdict(EXPECTED_NOTHING, OBSERVED_REJECT)[:3]
                + [
                    (3, "is", "PASS  {path1}  [cgt]"),
                    (-1, "is", "summary: 1 pass, 1 fail (2 fixtures)"),
                ],
            )
        ],
    ),
    (
        "C1",
        [
            Run(
                "C1",
                ["unchanged-rejected.json"],
                0,
                len(UNCHANGED_REJECTED_STDOUT),
                [(i, "is", line) for i, line in enumerate(UNCHANGED_REJECTED_STDOUT)],
                stdout=UNCHANGED_REJECTED_STDOUT,
            )
        ],
    ),
    ("C2", [passed_run("C2", "c2.json")]),
    ("C3", [passed_run("C3", "c3.json")]),
]


def fill(text: str, paths: list[Path]) -> str:
    for i, path in enumerate(paths):
        text = text.replace("{path%d}" % i, str(path))
    return text


def quote(text: str) -> str:
    return json.dumps(text)


def error_line(stderr: bytes) -> str:
    text = stderr.decode("utf-8", "replace")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for line in lines:
        if re.match(r"^\w*Error\b", line):
            return line
    return lines[-1] if lines else ""


def invoke(argv: list[str]) -> tuple[int | None, bytes, str]:
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=RUN_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, b"", f"{type(exc).__name__}: {exc}"
    return proc.returncode, proc.stdout, error_line(proc.stderr)


def judge(run: Run, paths: list[Path], code: int | None, stdout: bytes, err: str) -> list[str]:
    """Return one message per assertion of `run` that the output does not meet."""
    problems: list[str] = []
    if code != run.exit_code:
        problems.append(f"exit {code}, want {run.exit_code}")
    if err and (code != run.exit_code or not stdout):
        problems.append(f"stderr: {err}")
    text = stdout.decode("utf-8", "replace")
    if run.stdout is not None:
        want_text = "".join(fill(line, paths) + "\n" for line in run.stdout)
        if stdout != want_text.encode("utf-8"):
            problems.append("stdout is not byte-identical to the pinned base output")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if len(lines) != run.line_count:
        problems.append(f"{len(lines)} stdout lines, want {run.line_count}")
    for index, op, template in run.checks:
        want = fill(template, paths)
        position = index if index >= 0 else len(lines) + index
        if not 0 <= position < len(lines):
            where = "last line" if index < 0 else f"line {index + 1}"
            problems.append(f"{where}: missing, want {quote(want)}")
            continue
        got = lines[position]
        if op == "is" and got != want:
            problems.append(f"line {position + 1}: {quote(got)}, want {quote(want)}")
        elif op == "begins" and not got.startswith(want):
            problems.append(f"line {position + 1}: {quote(got)}, want it to begin {quote(want)}")
    return problems


def main() -> int:
    failed: list[str] = []
    with tempfile.TemporaryDirectory(prefix="judging-contract-") as tmp:
        directory = Path(tmp).resolve()
        build_inputs(directory)
        for cell, runs in CELLS:
            cell_ok = True
            for run in runs:
                paths = [directory / name for name in run.files]
                outputs = {}
                for name, argv in VERIFIERS.items():
                    code, stdout, err = invoke(argv + [str(path) for path in paths])
                    outputs[name] = (code, stdout)
                    problems = judge(run, paths, code, stdout, err)
                    print(f"{run.label:<12} {name:<5} {'ok' if not problems else 'FAIL'}")
                    for problem in problems:
                        print(f"{'':<19}{problem}")
                    cell_ok = cell_ok and not problems
                (node_code, node_out), (py_code, py_out) = outputs["node"], outputs["py"]
                reading = "identical" if node_out == py_out else "differs"
                if node_code != py_code:
                    reading += f" (exit node {node_code}, py {py_code})"
                print(f"{run.label:<12} stdout node==py: {reading}")
                cell_ok = cell_ok and node_out == py_out and node_code == py_code
            if not cell_ok:
                failed.append(cell)
    print()
    if failed:
        print(f"judging contract: {len(CELLS)} cells, {len(failed)} failed: {' '.join(failed)}")
        return 1
    print(f"judging contract: {len(CELLS)} cells, 0 failed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
