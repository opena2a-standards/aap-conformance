#!/usr/bin/env python3
"""Reference Python verifier for aap-conformance fixtures.

Depends only on the `cryptography` package; Python stdlib for everything
else. Python is the second half of the deliberate verifier pair: the AAP
spec repo's fixture generator (agent-authorization-protocol
scripts/generate_examples.py) is Python, so this verifier re-checks the
same construction from the spec's side of the fence.

Check order is pinned and MUST match verifiers/node/verify.mjs exactly —
the parity gate compares reject categories, so both implementations must
discover the same defect first:

    MALFORMED_TOKEN > MALFORMED_HEADER > UNKNOWN_HEADER_PARAM > UNKNOWN_ALG >
    UNKNOWN_KEY > BAD_SIGNATURE > MALFORMED_PAYLOAD > CLAIM_SCHEMA >
    EXPIRED > TTL_WINDOW > (DELEGATOR_INVALID >) SCOPE_NOT_SUBSET

Parsing rules (AAP-SPEC §9.2, and the atx-conformance duplicate-key lesson):
  - the protected header is STRICT-parsed: duplicate members at any depth
    are MALFORMED_HEADER (v1 headers are closed; duplicates are the
    last-wins/first-wins smuggling split of RFC 8259 §4)
  - the claim set parses with standard last-wins JSON semantics, which
    RFC 7519 §4 permits; json.loads and JSON.parse agree natively

Usage:  python3 verify.py <fixture.json | directory> [...]
Exit code: 0 if every fixture's expected verdict (and reject category,
when pinned) is met, else 1.
"""

from __future__ import annotations

import base64
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
DID_RE = re.compile(r"^did:")
JTI_RE = re.compile(r"^[0-9a-f]{32}$")
TRUST_CLASS_RE = re.compile(r"^[a-z0-9_-]+:[a-z0-9_-]+$")
SHA256_REF_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SUITE_REGISTRY = ("EdDSA",)  # AAP-SPEC §9.5 (ML-DSA-65 reserved, unregistered)
BAC_TTL_SECONDS = 60  # AAP-SPEC §6.1


# --- reject plumbing -----------------------------------------------------------


class Reject(Exception):
    def __init__(self, category: str, reason: str):
        super().__init__(reason)
        self.category = category
        self.reason = reason


def _reject(category: str, reason: str) -> None:
    raise Reject(category, reason)


# --- strict JSON (protected headers only) ---------------------------------------


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f'duplicate member "{key}"')
        out[key] = value
    return out


def parse_strict_json(text: str) -> Any:
    """JSON parse that rejects duplicate object members at any depth."""
    return json.loads(text, object_pairs_hook=_strict_pairs)


def _is_plain_object(v: Any) -> bool:
    return isinstance(v, dict)


def _b64url_decode(segment: Any, what: str, category: str) -> bytes:
    if not isinstance(segment, str) or not B64URL_RE.match(segment):
        _reject(category, f"{what} is not unpadded base64url")
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


# --- key resolution ---------------------------------------------------------------


def build_key_set(verifier_state: dict) -> dict[str, Ed25519PublicKey]:
    keys: dict[str, Ed25519PublicKey] = {}
    for entry in verifier_state.get("keys", []):
        raw = base64.urlsafe_b64decode(
            entry["publicJwk"]["x"] + "=" * (-len(entry["publicJwk"]["x"]) % 4)
        )
        keys[entry["kid"]] = Ed25519PublicKey.from_public_bytes(raw)
    return keys


# --- protected header (compact: closed {alg, typ, kid}; general: {alg, kid}) ------


def check_header(
    header_bytes: bytes,
    keys: dict[str, Ed25519PublicKey],
    allowed_members: tuple[str, ...],
    where: str,
) -> dict:
    try:
        header = parse_strict_json(header_bytes.decode("utf-8"))
    except Exception as exc:
        _reject("MALFORMED_HEADER", f"{where}: {exc}")
    if not _is_plain_object(header):
        _reject("MALFORMED_HEADER", f"{where}: protected header is not a JSON object")
    for member in header:
        if member not in allowed_members:
            _reject(
                "UNKNOWN_HEADER_PARAM",
                f'{where}: unknown header parameter "{member}" (v1 headers are closed, AAP-SPEC §9.2)',
            )
    alg = header.get("alg")
    if not isinstance(alg, str):
        _reject("MALFORMED_HEADER", f"{where}: missing or non-string alg")
    if alg not in SUITE_REGISTRY:
        _reject(
            "UNKNOWN_ALG",
            f'{where}: unsupported alg "{alg}" — not in the AAP-SPEC §9.5 suite registry; refusing to downgrade',
        )
    if "typ" in allowed_members and header.get("typ") != "JWT":
        _reject("MALFORMED_HEADER", f'{where}: typ must be "JWT" in v1')
    kid = header.get("kid")
    if not isinstance(kid, str) or len(kid) == 0:
        _reject("MALFORMED_HEADER", f"{where}: missing or empty kid")
    if kid not in keys:
        _reject("UNKNOWN_KEY", f'{where}: kid "{kid}" not in the verifier\'s key set')
    return header


# --- claim-set rules (mirror the vendored claim schemas; same order as Node) ------


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _nonempty(v: Any) -> bool:
    return isinstance(v, str) and len(v) > 0


def _is_did(v: Any) -> bool:
    return isinstance(v, str) and bool(DID_RE.match(v))


def _check_actor(v: Any) -> bool:
    if not _is_plain_object(v) or not _is_did(v.get("sub")):
        return False
    if "act" in v:
        return _check_actor(v["act"])
    return True


CHECKS: dict[str, tuple[Callable[[Any], bool], str]] = {
    "issAny": (_nonempty, "must be a non-empty string"),
    "issDid": (_is_did, 'must be a string starting "did:"'),
    "did": (_is_did, 'must be a string starting "did:"'),
    "nonempty": (_nonempty, "must be a non-empty string"),
    "string": (lambda v: isinstance(v, str), "must be a string"),
    "trustClass": (
        lambda v: isinstance(v, str) and bool(TRUST_CLASS_RE.match(v)),
        "must match ^[a-z0-9_-]+:[a-z0-9_-]+$ (an abstract ATX trust class, not a scope)",
    ),
    "issuerChain": (
        lambda v: isinstance(v, list) and len(v) >= 1 and all(_is_did(x) for x in v),
        "must be a non-empty array of DID strings",
    ),
    "trustLevel": (lambda v: _is_int(v) and 0 <= v <= 4, "must be an integer 0..4"),
    "numericDate": (lambda v: _is_int(v) and v >= 0, "must be a NumericDate integer"),
    "jti": (
        lambda v: isinstance(v, str) and bool(JTI_RE.match(v)),
        "must be 16 random bytes as 32 lowercase hex characters (AAP-SPEC §8.1)",
    ),
    "aapVer": (lambda v: _is_int(v) and v >= 1, "must be an integer >= 1"),
    "sha256Ref": (
        lambda v: isinstance(v, str) and bool(SHA256_REF_RE.match(v)),
        "must match ^sha256:[0-9a-f]{64}$",
    ),
    "bacLevel": (lambda v: _is_int(v) and v in (1, 2, 3), "must be 1, 2, or 3"),
    "driftScore": (lambda v: _is_num(v) and 0 <= v <= 1, "must be a number in 0..1"),
    "bool": (lambda v: isinstance(v, bool), "must be a boolean"),
    "posInt": (lambda v: _is_int(v) and v >= 1, "must be an integer >= 1"),
    "actor": (_check_actor, 'must be an object with a DID "sub" (recursively)'),
}

CGT_MEMBERS: list[tuple[str, str, bool]] = [
    ("iss", "issAny", True),
    ("sub", "did", True),
    ("aud", "nonempty", True),
    ("scope", "nonempty", True),
    ("trust_class", "trustClass", True),
    ("issuer_chain", "issuerChain", True),
    ("trust_level", "trustLevel", True),
    ("iat", "numericDate", True),
    ("exp", "numericDate", True),
    ("jti", "jti", True),
    ("aap_ver", "aapVer", False),
    ("fga_constraints", "string", False),
    ("intent_verified", "bool", False),
    ("max_uses", "posInt", False),
    ("context_required", "bool", False),
]

CLAIM_MEMBERS: dict[str, list[tuple[str, str, bool]]] = {
    "ait": [
        ("iss", "issDid", True),
        ("sub", "did", True),
        ("agent_id", "nonempty", False),
        ("atx_reference", "sha256Ref", True),
        ("declared_purpose", "nonempty", False),
        ("trust_level", "trustLevel", True),
        ("iat", "numericDate", True),
        ("exp", "numericDate", True),
        ("jti", "jti", True),
        ("aap_ver", "aapVer", False),
    ],
    "cgt": CGT_MEMBERS,
    "da": [
        ("iss", "issAny", True),
        ("sub", "did", True),
        ("aud", "nonempty", True),
        ("scope", "nonempty", True),
        ("trust_class", "trustClass", True),
        ("issuer_chain", "issuerChain", True),
        ("trust_level", "trustLevel", True),
        ("act", "actor", True),
        ("max_depth", "posInt", True),
        ("delegator_atx", "sha256Ref", True),
        ("iat", "numericDate", True),
        ("exp", "numericDate", True),
        ("jti", "jti", True),
        ("aap_ver", "aapVer", False),
    ],
    "bac": [
        ("iss", "issDid", True),
        ("sub", "did", True),
        ("bac_level", "bacLevel", True),
        ("atx_reference", "sha256Ref", True),
        ("binary_hash", "sha256Ref", False),
        ("drift_score", "driftScore", False),
        ("anomaly_state", "nonempty", False),
        ("intent_verified", "bool", False),
        ("iat", "numericDate", True),
        ("exp", "numericDate", True),
        ("jti", "jti", True),
        ("aap_ver", "aapVer", False),
    ],
}


def check_claims(claims: dict, fixture_type: str) -> None:
    members = CLAIM_MEMBERS.get(fixture_type)
    if members is None:
        _reject("CLAIM_SCHEMA", f'unknown fixtureType "{fixture_type}"')
    for name, check_key, required in members:
        if name not in claims:
            if required:
                _reject("CLAIM_SCHEMA", f'missing required claim "{name}"')
            continue
        fn, msg = CHECKS[check_key]
        if not fn(claims[name]):
            _reject("CLAIM_SCHEMA", f'claim "{name}" {msg}')
    if fixture_type == "bac":
        # Cumulative levels (AAP-SPEC §6.4): L2 adds binary_hash; L3 adds the
        # behavioral-continuity members. Checked in this fixed order.
        level = claims["bac_level"]
        if level >= 3:
            needs = ["binary_hash", "drift_score", "anomaly_state", "intent_verified"]
        elif level >= 2:
            needs = ["binary_hash"]
        else:
            needs = []
        for name in needs:
            if name not in claims:
                _reject("CLAIM_SCHEMA", f'missing required claim "{name}" for bac_level {level}')


# --- token verification -------------------------------------------------------------


def verify_compact_structure(token: Any, keys: dict[str, Ed25519PublicKey]) -> dict:
    if not isinstance(token, str):
        _reject("MALFORMED_TOKEN", "token is not a string")
    segments = token.split(".")
    if len(segments) != 3:
        _reject("MALFORMED_TOKEN", f"compact serialization must have 3 segments, got {len(segments)}")
    h, p, s = segments
    header_bytes = _b64url_decode(h, "header segment", "MALFORMED_TOKEN")
    _b64url_decode(p, "payload segment", "MALFORMED_TOKEN")
    sig_bytes = _b64url_decode(s, "signature segment", "MALFORMED_TOKEN")

    header = check_header(header_bytes, keys, ("alg", "typ", "kid"), "header")

    try:
        keys[header["kid"]].verify(sig_bytes, f"{h}.{p}".encode("ascii"))
    except InvalidSignature:
        _reject("BAD_SIGNATURE", f'signature does not verify under kid "{header["kid"]}"')

    try:
        # Standard last-wins JSON semantics for the claim set (RFC 7519 §4).
        claims = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)).decode("utf-8"))
    except Exception as exc:
        _reject("MALFORMED_PAYLOAD", f"claim set is not valid JSON: {exc}")
    if not _is_plain_object(claims):
        _reject("MALFORMED_PAYLOAD", "claim set is not a JSON object")
    return claims


def verify_general_structure(token_general: Any, keys: dict[str, Ed25519PublicKey]) -> dict:
    if not _is_plain_object(token_general):
        _reject("MALFORMED_TOKEN", "general serialization is not a JSON object")
    payload = token_general.get("payload")
    signatures = token_general.get("signatures")
    _b64url_decode(payload, "payload", "MALFORMED_TOKEN")
    if not isinstance(signatures, list) or len(signatures) == 0:
        _reject("MALFORMED_TOKEN", "signatures must be a non-empty array")
    for index, entry in enumerate(signatures):
        if not _is_plain_object(entry):
            _reject("MALFORMED_TOKEN", f"signatures[{index}] is not an object")
        protected_bytes = _b64url_decode(
            entry.get("protected"), f"signatures[{index}].protected", "MALFORMED_TOKEN"
        )
        sig_bytes = _b64url_decode(
            entry.get("signature"), f"signatures[{index}].signature", "MALFORMED_TOKEN"
        )
        # General-form per-signature protected headers are exactly {alg, kid} (§9.4).
        header = check_header(protected_bytes, keys, ("alg", "kid"), f"signatures[{index}]")
        try:
            # Every declared entry MUST verify (§9.4) — no subset acceptance.
            keys[header["kid"]].verify(
                sig_bytes, f'{entry["protected"]}.{payload}'.encode("ascii")
            )
        except InvalidSignature:
            _reject(
                "BAD_SIGNATURE",
                f'signatures[{index}] does not verify under its declared kid "{header["kid"]}" — '
                f"every declared entry MUST verify (AAP-SPEC §9.4)",
            )
    try:
        claims = json.loads(
            base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)).decode("utf-8")
        )
    except Exception as exc:
        _reject("MALFORMED_PAYLOAD", f"claim set is not valid JSON: {exc}")
    if not _is_plain_object(claims):
        _reject("MALFORMED_PAYLOAD", "claim set is not a JSON object")
    return claims


@dataclass
class Result:
    accepted: bool
    category: str | None = None
    reason: str = ""

    def __str__(self) -> str:
        if self.accepted:
            return "ACCEPT"
        return f"REJECT[{self.category}: {self.reason}]"


def verify_fixture(fixture: dict) -> Result:
    verifier_state = fixture.get("verifierState", {})
    keys = build_key_set(verifier_state)
    clock = verifier_state.get("clockNumericDate")
    fixture_type = fixture.get("fixtureType")

    try:
        if fixture.get("tokenForm") == "general":
            claims = verify_general_structure(fixture.get("tokenGeneral"), keys)
        else:
            claims = verify_compact_structure(fixture.get("token"), keys)

        check_claims(claims, fixture_type)

        if _is_int(clock) and clock >= claims["exp"]:
            _reject("EXPIRED", f"token expired (exp {claims['exp']} <= clock {clock})")
        if fixture_type == "bac" and claims["exp"] - claims["iat"] > BAC_TTL_SECONDS:
            _reject(
                "TTL_WINDOW",
                f"BAC validity window exp - iat = {claims['exp'] - claims['iat']}s "
                f"exceeds the 60-second cap (AAP-SPEC §6.1)",
            )
        delegation = fixture.get("delegation") or {}
        if fixture_type == "da" and "delegatorToken" in delegation:
            try:
                delegator_claims = verify_compact_structure(delegation["delegatorToken"], keys)
            except Reject as exc:
                _reject("DELEGATOR_INVALID", f"delegator token: {exc.reason}")
            da_scopes = str(claims["scope"]).split(" ")
            delegator_scopes = set(str(delegator_claims["scope"]).split(" "))
            if not all(s in delegator_scopes for s in da_scopes):
                _reject(
                    "SCOPE_NOT_SUBSET",
                    f'DA scope "{claims["scope"]}" is not a subset of the delegator scope '
                    f'"{delegator_claims["scope"]}" (AAP-SPEC §5.2)',
                )

        return Result(accepted=True)
    except Reject as exc:
        return Result(accepted=False, category=exc.category, reason=exc.reason)


# --- CLI harness ---------------------------------------------------------------------


def expand_paths(args: list[str]) -> list[Path]:
    out: set[Path] = set()
    for a in args:
        p = Path(a)
        if not p.exists():
            raise FileNotFoundError(a)
        if p.is_dir():
            fixtures_dir = p / "fixtures"
            target = fixtures_dir if fixtures_dir.is_dir() else p
            out.update(target.glob("*.json"))
        else:
            out.add(p)
    return sorted(out)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        sys.stderr.write("usage: verify.py <fixture.json|dir>...\n")
        return 2
    try:
        paths = expand_paths(argv[1:])
    except FileNotFoundError as exc:
        sys.stderr.write(f"error: path not found: {exc}\n")
        return 2
    if not paths:
        sys.stderr.write("no fixture *.json files found\n")
        return 2

    total_pass = total_fail = 0
    for p in paths:
        try:
            fixture = json.loads(p.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"FAIL  {p}  (load error: {exc})")
            total_fail += 1
            continue

        got = verify_fixture(fixture)
        expected = fixture.get("expected", {})
        want_accept = expected.get("verifyResult", "").upper() == "ACCEPT"

        ok = want_accept == got.accepted
        if ok and not want_accept and expected.get("rejectCategory"):
            ok = got.category == expected["rejectCategory"]
        if ok and not want_accept and expected.get("reasonContains"):
            ok = expected["reasonContains"].lower() in got.reason.lower()

        status = "PASS" if ok else "FAIL"
        if ok:
            total_pass += 1
        else:
            total_fail += 1

        print(f"{status}  {p}  [{fixture.get('fixtureType', '?')}]")
        print(f"       expected: {expected.get('verifyResult', '')}", end="")
        if expected.get("rejectCategory"):
            print(f" [{expected['rejectCategory']}]")
        else:
            print()
        print(f"       observed: {got}")

    print()
    print(f"summary: {total_pass} pass, {total_fail} fail ({total_pass + total_fail} fixtures)")
    return 0 if total_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
