#!/usr/bin/env python3
"""Validate fixture token contents against the vendored AAP-SPEC schemas.

The schemas are the machine-readable models published by
agent-authorization-protocol (schemas/*.schema.json), vendored under
schemas/vendor/agent-authorization-protocol/ and byte-drift-gated in CI
against the pinned AAP_SPEC_REF.

Unlike atp-conformance (where every REJECT is a crypto/state reject and all
fixtures are shape-valid), part of this suite's REJECT set consists of
claim-schema defects — that is the point of those fixtures. So each fixture
DECLARES its expected schema validity and this script asserts the observation
matches:

  - `schemaValid`:       decoded claim set vs the claim schema for its
                         fixtureType (ait/cgt/da/bac-claims-v1)
  - `headerSchemaValid`: decoded compact protected header vs
                         jose-header-v1 (compact fixtures only; general-form
                         per-signature headers are a different, smaller shape
                         that jose-header-v1 deliberately rejects)
  - general-form containers must always validate against jws-general-v1

Decoding here uses plain json.loads (RFC 8259 last-wins). The
duplicate-header fixture therefore validates as its LAST-wins reading —
{"alg": "none"} — which fails the enum; the strict-parse rejection itself
is the reference verifiers' job, not the schema's.

A mismatch between declared and observed validity means fixtures and schemas
have drifted apart.
"""

import base64
import json
import pathlib
import sys

try:
    from jsonschema import Draft202012Validator
except ImportError:
    print("error: the 'jsonschema' package is required (pip install jsonschema)")
    sys.exit(2)

ROOT = pathlib.Path(__file__).resolve().parent.parent
VENDOR = ROOT / "schemas" / "vendor" / "agent-authorization-protocol"

CLAIM_SCHEMAS = {
    "ait": "ait-claims-v1.schema.json",
    "cgt": "cgt-claims-v1.schema.json",
    "da": "da-claims-v1.schema.json",
    "bac": "bac-claims-v1.schema.json",
}


def load_validator(filename: str) -> Draft202012Validator:
    schema = json.loads((VENDOR / filename).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def b64url_json(segment: str):
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


def main() -> int:
    claim_validators = {t: load_validator(f) for t, f in CLAIM_SCHEMAS.items()}
    header_validator = load_validator("jose-header-v1.schema.json")
    general_validator = load_validator("jws-general-v1.schema.json")

    failures = 0
    fixtures = sorted((ROOT / "fixtures").glob("*.json"))
    if not fixtures:
        print("error: no fixtures found")
        return 1

    def check(path, what, validator, doc, declared):
        nonlocal failures
        observed = not list(validator.iter_errors(doc))
        if observed == declared:
            print(f"PASS  {path.name} ({what}: declared={'valid' if declared else 'invalid'}, observed matches)")
        else:
            print(f"FAIL  {path.name} ({what}: declared={'valid' if declared else 'invalid'}, observed={'valid' if observed else 'invalid'})")
            failures += 1

    for path in fixtures:
        fx = json.loads(path.read_text(encoding="utf-8"))
        fixture_type = fx["fixtureType"]

        if fx["tokenForm"] == "general":
            check(path, "jws-general container", general_validator, fx["tokenGeneral"], True)
            claims = b64url_json(fx["tokenGeneral"]["payload"])
        else:
            header = b64url_json(fx["token"].split(".")[0])
            check(path, "jose-header", header_validator, header, fx["headerSchemaValid"])
            claims = b64url_json(fx["token"].split(".")[1])

        check(path, f"{fixture_type}-claims", claim_validators[fixture_type], claims, fx["schemaValid"])

    print(f"\nsummary: {failures} mismatches ({len(fixtures)} fixtures)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
