#!/usr/bin/env python3
"""Assert the reuse contract with the spec repo: ACCEPT fixtures carry the
agent-authorization-protocol repo's published token bytes UNCHANGED.

The handed-down rule for this suite is "reuse, don't re-derive": the spec
repo's deterministic generator (scripts/generate_examples.py) is the source
of the ACCEPT token bytes, and this suite embeds them. CI checks out the
pinned AAP ref and this script byte-compares:

  - the compact ACCEPT fixtures vs examples/tokens/{ait,cgt,da,bac}-v1.jwt,
    cgt-v1.mldsa65.jwt (the RFC 9964 PQ-interop lane) and the 0.5 tokens
    cgt-v1.fgc.jwt, da-v1.fgc.jwt, bac-v1.session.jwt
  - the general-form ACCEPT fixtures vs examples/tokens/cgt-v1.general.json and
    cgt-v1.hybrid.general.json (structural equality of payload + signatures,
    the signed bytes)
  - cgt-compact-expired and cgt-compact-replayed, which reuse cgt-v1.jwt
    byte-for-byte (only the pinned clock / presentation count differ);
    cgt-compact-cnf-mismatch and cgt-compact-cnf-no-proof, which reuse
    cgt-v1.fgc.jwt (only the presenter proof differs or is absent); and
    da-compact-delegator-mismatch and da-compact-depth-exceeds-peer-cap, which
    reuse da-v1.fgc.jwt (only the supplied delegator token differs)
  - cgt-hybrid-missing-mldsa65, whose payload and remaining Ed25519 entry are
    cgt-v1.hybrid.general.json's bytes with the ML-DSA-65 entry stripped
  - every DA fixture's delegation.delegatorToken that is a spec token
    (cgt-v1.jwt or cgt-v1.fgc.jwt)
  - the vendored claim/header/container schemas vs schemas/*.schema.json
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
        ("cgt-compact-fgc-valid", "cgt-v1.fgc.jwt"),
        ("da-compact-fgc-valid", "da-v1.fgc.jwt"),
        ("bac-compact-session-valid", "bac-v1.session.jwt"),
        ("cgt-compact-cnf-mismatch", "cgt-v1.fgc.jwt"),
        ("cgt-compact-cnf-no-proof", "cgt-v1.fgc.jwt"),
        ("da-compact-delegator-mismatch", "da-v1.fgc.jwt"),
        ("da-compact-depth-exceeds-peer-cap", "da-v1.fgc.jwt"),
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

    # The stripped hybrid: the payload and the surviving Ed25519 entry are the
    # published hybrid bytes; only the ML-DSA-65 entry is absent.
    hybrid = json.loads((tokens / "cgt-v1.hybrid.general.json").read_text(encoding="utf-8"))
    stripped = fixture("cgt-hybrid-missing-mldsa65")["tokenGeneral"]
    check(
        "cgt-hybrid-missing-mldsa65 == cgt-v1.hybrid.general.json minus its ML-DSA-65 entry",
        stripped["payload"] == hybrid["payload"]
        and stripped["signatures"] == [hybrid["signatures"][0]],
    )

    delegator_pairs = [
        ("da-compact-valid", "cgt-v1.jwt"),
        ("da-compact-scope-superset", "cgt-v1.jwt"),
        ("da-compact-terminal-depth-zero", "cgt-v1.jwt"),
        ("da-compact-trust-class-widened", "cgt-v1.jwt"),
        ("da-compact-fgc-valid", "cgt-v1.fgc.jwt"),
        ("da-compact-authorization-details-widened", "cgt-v1.fgc.jwt"),
        ("da-compact-outlives-delegator", "cgt-v1.fgc.jwt"),
    ]
    for fx_name, token_file in delegator_pairs:
        want = (tokens / token_file).read_text(encoding="utf-8").strip()
        check(
            f"{fx_name}.delegation.delegatorToken == {token_file}",
            fixture(fx_name)["delegation"]["delegatorToken"] == want,
        )

    vendored = ROOT / "schemas" / "vendor" / "agent-authorization-protocol"
    for schema_file in (
        "jose-header-v1.schema.json",
        "ait-claims-v1.schema.json",
        "cgt-claims-v1.schema.json",
        "da-claims-v1.schema.json",
        "bac-claims-v1.schema.json",
        "jws-general-v1.schema.json",
    ):
        check(
            f"schemas/vendor/agent-authorization-protocol/{schema_file} == schemas/{schema_file}",
            (vendored / schema_file).read_bytes() == (spec / "schemas" / schema_file).read_bytes(),
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
