#!/usr/bin/env python3
"""Generate (or verify) the machine-readable conformance profile.

`conformance.json` maps every requirement this suite tests to the fixture
that tests it and the pinned expected outcome. The requirement entries are
DERIVED from the fixtures themselves (each fixture carries its spec
references and expected block), so the profile cannot drift from the fixture
set: regeneration is deterministic and CI verifies the committed file matches.

Usage:
    python3 scripts/conformance_profile.py            # (re)write conformance.json
    python3 scripts/conformance_profile.py --check    # exit 1 if committed file is stale
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT = REPO_ROOT / "conformance.json"

# --- suite metadata (hand-maintained; everything under `requirements` is derived) ---
SUITE = {
    "$schema": "https://specs.opena2a.org/schemas/conformance-profile-v1.json",
    "suite": "aap-conformance",
    "spec": {
        "id": "AAP",
        "name": "Agent Authorization Protocol",
        "version": "0.4.0-draft",
        "ref": "https://github.com/opena2a-standards/agent-authorization-protocol/blob/main/AAP-SPEC.md",
    },
    "fixtureManifest": "MANIFEST.sha256",
    "verifiers": [
        {
            "language": "node",
            "path": "verifiers/node",
            "coverage": "full fixture set; exercises the same primitives the TypeScript reference broker (Secretless) mints with — node:crypto Ed25519 plus @noble/post-quantum ML-DSA-65 (RFC 9964)",
        },
        {
            "language": "python",
            "path": "verifiers/python",
            "coverage": "full fixture set; mirrors the spec repo's Python fixture generator from the verification side (cryptography Ed25519 plus dilithium-py ML-DSA-65)",
        },
    ],
    "notCovered": [
        {
            "specSection": "§8.2 key exchange (hybrid X25519 + ML-KEM-768)",
            "reason": "transport key negotiation, not token wire form; ML-KEM has no final JOSE registration, so that row of §8.2 remains reserved",
        },
        {
            "specSection": "§7 cross-organizational federation and broker-profile runtime behavior (CPI endpoints, grant references, revocation propagation)",
            "reason": "runtime protocol flows, not token wire form; grant-reference-v1 is validated against the broker-profile ABNF in the spec repo's own CI",
        },
        {
            "specSection": "§8.3 intent verification and the optional CGT FGA members",
            "reason": "optional-to-ignore per the broker profile; the v1 reference does not mint them — the schemas accept them, but no fixture pins their semantics",
        },
    ],
}


def build() -> dict:
    requirements = []
    for path in sorted((REPO_ROOT / "fixtures").glob("*.json")):
        fx = json.loads(path.read_text())
        expected = fx["expected"]
        outcome = expected["verifyResult"]
        if expected.get("rejectCategory"):
            outcome = f"REJECT[{expected['rejectCategory']}]"
        requirements.append(
            {
                "fixture": f"fixtures/{path.name}",
                "name": fx["name"],
                "fixtureType": fx["fixtureType"],
                "tokenForm": fx["tokenForm"],
                "level": "MUST",
                "specRefs": fx["spec"],
                "expected": outcome,
                "description": fx["description"],
            }
        )
    profile = dict(SUITE)
    profile["requirements"] = requirements
    return profile


def main() -> int:
    rendered = json.dumps(build(), indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if not OUT.exists():
            print("conformance.json missing; run scripts/conformance_profile.py")
            return 1
        if OUT.read_text() != rendered:
            print("conformance.json is stale; run scripts/conformance_profile.py")
            return 1
        print("conformance.json is current")
        return 0
    OUT.write_text(rendered)
    print(f"wrote conformance.json ({len(build()['requirements'])} requirements)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
