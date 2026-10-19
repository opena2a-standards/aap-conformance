#!/usr/bin/env python3
"""Tests that a docs/scope.md row cites the spec sections its fixture's rule rests on.

`scripts/conformance_profile.py --check` holds the "What this suite verifies"
table to one row per fixture and does not read the sections a row cites. A
row's citations are prose, so a row can keep naming the section a rule was
first inferred from after the spec states that rule in another section, and
nothing in `--check` notices. This file pins the rows that were checked
against the spec text: each row listed below must cite every section named
for it, and each of those sections must be among the fixture's specRefs in
conformance.json, so the list here cannot drift from the profile.

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
SECTION = re.compile(r"§\d+(?:\.\d+)*")

# Fixture path -> the AAP-SPEC sections its scope row must cite. The DA
# expiry bound (a DA's `exp` MUST NOT be later than its delegator's) is
# stated in §5.3 Assertion Form; the row also cites the attenuation rule
# (§5.4) and the claims that carry the validity window (§4.2), as the
# fixture's specRefs do.
REQUIRED_SECTIONS = {
    "fixtures/da-compact-outlives-delegator.json": {"§5.3", "§5.4", "§4.2"},
}


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


class ScopeRowCitationsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.scope = SCOPE.read_text(encoding="utf-8")
        profile = json.loads(PROFILE.read_text(encoding="utf-8"))
        self.requirements = {req["fixture"]: req for req in profile["requirements"]}

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


if __name__ == "__main__":
    unittest.main()
