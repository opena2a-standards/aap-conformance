#!/usr/bin/env python3
"""Assert the reuse contract with the spec repo: ACCEPT fixtures carry the
agent-authorization-protocol repo's published token bytes UNCHANGED.

The handed-down rule for this suite is "reuse, don't re-derive": the spec
repo's deterministic generator (scripts/generate_examples.py) is the source
of the ACCEPT token bytes, and this suite embeds them. CI checks out the
pinned AAP ref and this script byte-compares:

  - the five compact ACCEPT fixtures vs examples/tokens/{ait,cgt,da,bac}-v1.jwt
    and cgt-v1.mldsa65.jwt (the RFC 9964 PQ-interop lane)
  - the general-form ACCEPT fixtures vs examples/tokens/cgt-v1.general.json and
    cgt-v1.hybrid.general.json (structural equality of payload + signatures,
    the signed bytes)
  - cgt-compact-expired and cgt-compact-replayed, which reuse cgt-v1.jwt
    byte-for-byte (only the pinned clock / presentation count differ)
  - both DA fixtures' delegation.delegatorToken vs cgt-v1.jwt
  - vectors/test-keys.json vs examples/tokens/test-keys.json

Usage:  python3 scripts/spec_pin_check.py <path-to-spec-repo-checkout>
"""

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: spec_pin_check.py <path-to-agent-authorization-protocol-checkout>")
        return 2
    spec = pathlib.Path(sys.argv[1])
    tokens = spec / "examples" / "tokens"
    failures = 0

    def check(label: str, ok: bool) -> None:
        nonlocal failures
        print(f"{'PIN OK ' if ok else 'DRIFT  '} {label}")
        if not ok:
            failures += 1

    def fixture(name: str) -> dict:
        return json.loads((ROOT / "fixtures" / f"{name}.json").read_text(encoding="utf-8"))

    compact_pairs = [
        ("ait-compact-valid", "ait-v1.jwt"),
        ("cgt-compact-valid", "cgt-v1.jwt"),
        ("da-compact-valid", "da-v1.jwt"),
        ("bac-compact-valid", "bac-v1.jwt"),
        ("cgt-mldsa65-compact-valid", "cgt-v1.mldsa65.jwt"),
        ("cgt-compact-expired", "cgt-v1.jwt"),
        ("cgt-compact-replayed", "cgt-v1.jwt"),
    ]
    for fx_name, token_file in compact_pairs:
        want = (tokens / token_file).read_text(encoding="utf-8").strip()
        check(f"{fx_name} == {token_file}", fixture(fx_name)["token"] == want)

    general_pairs = [
        ("cgt-general-valid", "cgt-v1.general.json"),
        ("cgt-hybrid-general-valid", "cgt-v1.hybrid.general.json"),
    ]
    for fx_name, token_file in general_pairs:
        want_general = json.loads((tokens / token_file).read_text(encoding="utf-8"))
        check(
            f"{fx_name} == {token_file}",
            fixture(fx_name)["tokenGeneral"] == want_general,
        )

    cgt = (tokens / "cgt-v1.jwt").read_text(encoding="utf-8").strip()
    for fx_name in ("da-compact-valid", "da-compact-scope-superset"):
        check(
            f"{fx_name}.delegation.delegatorToken == cgt-v1.jwt",
            fixture(fx_name)["delegation"]["delegatorToken"] == cgt,
        )

    check(
        "vectors/test-keys.json == examples/tokens/test-keys.json",
        (ROOT / "vectors" / "test-keys.json").read_bytes()
        == (tokens / "test-keys.json").read_bytes(),
    )

    if failures:
        print(f"\nSPEC PIN: FAIL ({failures} drifted)")
        return 1
    print("\nSPEC PIN: PASS (all reused bytes match the pinned spec ref)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
