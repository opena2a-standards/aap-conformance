#!/usr/bin/env python3
"""Tests that the Node reference verifier is a module its CLI wraps.

verifiers/node/verify.mjs exports verifyFixture and verifyPresentation, the
verification its CLI performs for each fixture, so a program can import the
file and verify tokens in-process instead of starting the CLI once per token.
These tests import it from a separate script, as such a program would, and
check that:

  - the import prints nothing and the importing script runs on after it, and
    both exports are functions;
  - verifyFixture returns, for every fixture under fixtures/, the observed
    result the CLI prints for that fixture, and that result carries the
    fixture's expected verdict and reject category;
  - verifyPresentation judges a repeated jti against the Map the caller passes
    in (AAP-SPEC §8.1), while verifyFixture starts a new one on each call;
  - the CLI still runs when it is started through a symbolic link.

They need node on PATH and the Node dependency installed (`npm install`), and
are skipped without either.

Usage:
    python3 scripts/test_node_verifier_module.py
    python3 -m unittest discover -s scripts -p 'test_*.py'
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
NODE_DIR = REPO_ROOT / "verifiers" / "node"
VERIFY = NODE_DIR / "verify.mjs"
FIXTURES = REPO_ROOT / "fixtures"
NODE = shutil.which("node")
DEPENDENCY = REPO_ROOT / "node_modules" / "@noble" / "post-quantum" / "package.json"

# `PASS  <path>  [type]` or `FAIL  <path>  [type]` opens a fixture's block in the CLI report.
BLOCK = re.compile(r"^(PASS|FAIL)  (\S+)  \[")
OBSERVED = re.compile(r"^       observed: (.*)$")

# A script that imports the verifier as another program would. Its arguments
# are the module URL, a mode, and the fixture paths the mode reads.
CONSUMER = r"""
const [moduleUrl, mode, ...paths] = process.argv.slice(2);
const verifier = await import(moduleUrl);
const { readFileSync } = await import("node:fs");
const load = (p) => JSON.parse(readFileSync(p, "utf8"));
if (mode === "exports") {
  const kinds = Object.fromEntries(Object.entries(verifier).map(([name, value]) => [name, typeof value]));
  console.log(JSON.stringify(kinds));
  console.log("after import");
} else if (mode === "verdicts") {
  for (const p of paths) console.log(JSON.stringify({ path: p, ...verifier.verifyFixture(load(p)) }));
} else if (mode === "replay") {
  const fixture = load(paths[0]);
  const cache = new Map();
  const shared = [verifier.verifyPresentation(fixture, cache), verifier.verifyPresentation(fixture, cache)];
  const fresh = [verifier.verifyFixture(fixture), verifier.verifyFixture(fixture)];
  console.log(JSON.stringify({ shared, fresh }));
}
"""


def cli_observed(stdout: str) -> dict[str, str]:
    """The text after `observed: ` in the CLI report, by fixture file name."""
    observed: dict[str, str] = {}
    current: str | None = None
    for line in stdout.splitlines():
        block = BLOCK.match(line)
        if block:
            current = Path(block.group(2)).name
            continue
        match = OBSERVED.match(line)
        if match and current is not None:
            observed[current] = match.group(1)
            current = None
    return observed


@unittest.skipUnless(NODE, "node is not on PATH")
@unittest.skipUnless(DEPENDENCY.is_file(), "the Node dependency is not installed; run npm install")
class NodeVerifierModuleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.consumer = Path(cls.tmp.name) / "consumer.mjs"
        cls.consumer.write_text(CONSUMER, encoding="utf-8")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def run_node(self, *args: str, cwd: Path = REPO_ROOT) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [NODE, *args], cwd=cwd, capture_output=True, text=True, encoding="utf-8", timeout=300
        )

    def consume(self, mode: str, *paths: Path) -> subprocess.CompletedProcess[str]:
        return self.run_node(str(self.consumer), VERIFY.as_uri(), mode, *(str(p) for p in paths))

    def test_import_runs_no_cli_and_exports_the_verification(self) -> None:
        proc = self.consume("exports", FIXTURES)
        report = f"exit {proc.returncode}\nstdout:\n{proc.stdout[-2000:]}\nstderr:\n{proc.stderr[-2000:]}"
        lines = proc.stdout.splitlines()
        self.assertEqual(lines[-1:], ["after import"], f"the import ended the importing script\n{report}")
        self.assertEqual(len(lines), 2, f"the import printed output of its own\n{report}")
        self.assertEqual(proc.stderr, "", report)
        self.assertEqual(proc.returncode, 0, report)
        kinds = json.loads(lines[0])
        self.assertEqual(kinds.get("verifyFixture"), "function", kinds)
        self.assertEqual(kinds.get("verifyPresentation"), "function", kinds)

    def test_verify_fixture_returns_what_the_cli_prints_on_every_fixture(self) -> None:
        fixtures = sorted(FIXTURES.glob("*.json"))
        self.assertTrue(fixtures, "no fixtures found")
        cli = self.run_node("verify.mjs", "../../fixtures", cwd=NODE_DIR)
        self.assertEqual(cli.returncode, 0, cli.stdout[-2000:] + cli.stderr[-2000:])
        observed = cli_observed(cli.stdout)
        self.assertEqual(sorted(observed), [p.name for p in fixtures])

        proc = self.consume("verdicts", *fixtures)
        self.assertEqual(proc.returncode, 0, proc.stdout[-2000:] + proc.stderr[-2000:])
        results = [json.loads(line) for line in proc.stdout.splitlines()]
        self.assertEqual([Path(r["path"]).name for r in results], [p.name for p in fixtures])
        for path, result in zip(fixtures, results):
            with self.subTest(fixture=path.name):
                if result["accepted"]:
                    shown = "ACCEPT"
                    self.assertEqual((result["category"], result["reason"]), (None, ""))
                else:
                    shown = f"REJECT[{result['category']}: {result['reason']}]"
                self.assertEqual(shown, observed[path.name])
                expected = json.loads(path.read_text(encoding="utf-8"))["expected"]
                self.assertEqual(result["accepted"], expected["verifyResult"].upper() == "ACCEPT")
                if not result["accepted"] and expected.get("rejectCategory"):
                    self.assertEqual(result["category"], expected["rejectCategory"])

    def test_verify_presentation_judges_replay_against_the_callers_map(self) -> None:
        proc = self.consume("replay", FIXTURES / "cgt-compact-valid.json")
        self.assertEqual(proc.returncode, 0, proc.stdout[-2000:] + proc.stderr[-2000:])
        runs = json.loads(proc.stdout)
        self.assertEqual([r["accepted"] for r in runs["shared"]], [True, False])
        self.assertEqual(runs["shared"][1]["category"], "REPLAYED_JTI")
        self.assertEqual([r["accepted"] for r in runs["fresh"]], [True, True])

    def test_cli_runs_through_a_symbolic_link(self) -> None:
        link = Path(self.tmp.name) / "verify-link.mjs"
        try:
            link.symlink_to(VERIFY)
        except OSError as exc:
            self.skipTest(f"cannot create a symbolic link here: {exc}")
        proc = self.run_node(str(link), str(FIXTURES / "ait-compact-valid.json"))
        self.assertEqual(proc.returncode, 0, proc.stdout[-2000:] + proc.stderr[-2000:])
        self.assertEqual(proc.stdout.splitlines()[-1:], ["summary: 1 pass, 0 fail (1 fixtures)"])


if __name__ == "__main__":
    unittest.main()
