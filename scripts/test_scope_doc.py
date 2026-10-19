#!/usr/bin/env python3
"""Tests that a docs/scope.md row cites the spec sections its fixture's rule rests on.

`scripts/conformance_profile.py --check` holds the "What this suite verifies"
table to one row per fixture and does not read the sections a row cites. A
row's citations are prose, so a row can keep naming the section a rule was
first inferred from after the spec states that rule in another section, and
nothing in `--check` notices. This file pins the rows that were checked
against the spec text: each row in REQUIRED_SECTIONS must cite every section
named for it, and each of those sections must be among the fixture's
specRefs in conformance.json, so that list cannot drift from the profile.

A section can also state a row's rule only in spec text later than the
version conformance.json declares. PENDING_SECTIONS lists such a section for
its row, and the row may name it only in a clause that marks it pending a
spec release. Both lists hold for the spec text they were checked against,
so conformance.json's spec.version and the AAP_SPEC_REF that
.github/workflows/conformance.yml pins must be the ones recorded here.

Usage:
    python3 scripts/test_scope_doc.py
    python3 -m unittest discover -s scripts -p 'test_*.py'
"""
from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import conformance_profile as cp  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
SCOPE = REPO_ROOT / "docs" / "scope.md"
PROFILE = REPO_ROOT / "conformance.json"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "conformance.yml"
SECTION = re.compile(r"§\d+(?:\.\d+)*")
SPEC_REF = re.compile(r"\s*AAP_SPEC_REF:\s*([0-9a-f]{40})\s*")
CLAUSE_BREAK = re.compile(r"[:;()]")

# The spec version, and the agent-authorization-protocol commit of that
# version, whose AAP-SPEC.md the two lists below were checked against.
CHECKED_SPEC_VERSION = "0.5.0-draft"
CHECKED_SPEC_REF = "b5f6011eded7a9f27cfcfda08ad1441abcb9a68f"

# Fixture path -> the AAP-SPEC sections its scope row must cite. In the
# checked text, the rule that a DA's `exp` is not later than its delegator's
# rests on the attenuation rule (§5.4: a DA can only carry less than the
# delegator's grant) and on the claims that carry the validity window
# (§4.2), as the fixture's specRefs do.
REQUIRED_SECTIONS = {
    "fixtures/da-compact-outlives-delegator.json": {"§5.4", "§4.2"},
}

# Fixture path -> sections that state the row's rule only in spec text later
# than the checked text. The sentence "A DA's `exp` MUST NOT be later than
# its delegator's `exp`" is not in AAP-SPEC.md at CHECKED_SPEC_REF;
# agent-authorization-protocol pull request #49 added it to §5.3 after that
# version.
PENDING_SECTIONS = {
    "fixtures/da-compact-outlives-delegator.json": {"§5.3"},
}
PENDING_MARK = "pending a spec release"


def scope_row(scope: str, fixture: str) -> str:
    """The one table row of docs/scope.md text `scope` that names `fixture`."""
    rows = [
        line
        for line in scope.splitlines()
        if line.lstrip().startswith("|") and fixture in cp.SCOPE_FIXTURE_REF.findall(line)
    ]
    if len(rows) != 1:
        raise AssertionError(f"docs/scope.md names {fixture} in {len(rows)} rows, expected 1")
    return rows[0]


def aap_sections(requirement: dict) -> set[str]:
    """The AAP-SPEC section numbers a conformance.json requirement's specRefs name."""
    sections: set[str] = set()
    for ref in requirement["specRefs"]:
        if ref["id"] == "AAP":
            sections.update(SECTION.findall(ref["section"]))
    return sections


def clauses(row: str) -> list[str]:
    """The clauses of a docs/scope.md row: its text split at colons, semicolons and parentheses."""
    return [clause.strip() for clause in CLAUSE_BREAK.split(row) if clause.strip()]


def pinned_spec_ref(workflow: str) -> str | None:
    """The commit an `AAP_SPEC_REF: <commit>` line of workflow text `workflow` pins."""
    for line in workflow.splitlines():
        match = SPEC_REF.fullmatch(line)
        if match:
            return match.group(1)
    return None


class ScopeRowCitationsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.scope = SCOPE.read_text(encoding="utf-8")
        self.profile = json.loads(PROFILE.read_text(encoding="utf-8"))
        self.requirements = {req["fixture"]: req for req in self.profile["requirements"]}

    def test_rows_cite_the_sections_their_rule_rests_on(self) -> None:
        for fixture, sections in REQUIRED_SECTIONS.items():
            with self.subTest(fixture=fixture):
                row = scope_row(self.scope, fixture)
                missing = sorted(sections - set(SECTION.findall(row)))
                self.assertEqual(missing, [], f"the docs/scope.md row for {fixture} does not cite {missing}: {row}")

    def test_required_sections_are_among_the_fixture_spec_refs(self) -> None:
        for fixture, sections in REQUIRED_SECTIONS.items():
            with self.subTest(fixture=fixture):
                self.assertIn(fixture, self.requirements)
                unlisted = sorted(sections - aap_sections(self.requirements[fixture]))
                self.assertEqual(unlisted, [], f"conformance.json specRefs for {fixture} do not name {unlisted}")

    def test_rows_mark_pending_sections_as_pending(self) -> None:
        for fixture, sections in PENDING_SECTIONS.items():
            with self.subTest(fixture=fixture):
                unmarked = [
                    clause
                    for clause in clauses(scope_row(self.scope, fixture))
                    if sections & set(SECTION.findall(clause)) and PENDING_MARK not in clause
                ]
                self.assertEqual(
                    unmarked,
                    [],
                    f'the docs/scope.md row for {fixture} names {sorted(sections)} without "{PENDING_MARK}"',
                )

    def test_lists_were_checked_against_the_declared_spec_text(self) -> None:
        recheck = "re-check REQUIRED_SECTIONS and PENDING_SECTIONS against that spec text, then record"
        self.assertEqual(
            self.profile["spec"]["version"],
            CHECKED_SPEC_VERSION,
            f"conformance.json declares another spec version: {recheck} it in CHECKED_SPEC_VERSION",
        )
        self.assertEqual(
            pinned_spec_ref(WORKFLOW.read_text(encoding="utf-8")),
            CHECKED_SPEC_REF,
            f"conformance.yml pins another AAP_SPEC_REF: {recheck} it in CHECKED_SPEC_REF",
        )


if __name__ == "__main__":
    unittest.main()
