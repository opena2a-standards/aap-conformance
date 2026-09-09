#!/usr/bin/env python3
"""Reference Python verifier for aap-conformance fixtures.

Depends on exactly two third-party packages: `cryptography` for Ed25519 and
`dilithium-py` (pure-Python FIPS 204) for ML-DSA-65 (RFC 9964); Python
stdlib for everything else. Python is the second half of the deliberate
verifier pair: the AAP spec repo's fixture generator
(agent-authorization-protocol scripts/generate_examples.py) is Python, so
this verifier re-checks the same construction from the spec's side of the
fence.

Check order is pinned and MUST match verifiers/node/verify.mjs exactly —
the parity gate compares reject categories, so both implementations must
discover the same defect first:

    MALFORMED_TOKEN > MALFORMED_HEADER > UNKNOWN_HEADER_PARAM > UNKNOWN_ALG >
    UNKNOWN_KEY > BAD_SIGNATURE > HYBRID_INCOMPLETE > MALFORMED_PAYLOAD >
    CLAIM_SCHEMA > CRIT_UNLISTED > CRIT_NOT_UNDERSTOOD > EXPIRED > TTL_WINDOW >
    CNF_MISMATCH > (DELEGATOR_INVALID >) SCOPE_NOT_SUBSET > NOT_ATTENUATED >
    REPLAYED_JTI

HYBRID_INCOMPLETE sits after BAD_SIGNATURE: the family gate (AAP-SPEC §9.4:
every declared entry verifies; a general-form token declaring any ML-DSA-65
entry MUST carry ≥1 Ed25519 AND ≥1 ML-DSA-65 entry; a suite the verifier's
path policy requires — verifierState.requiredSuites, §8.2 — MUST be present,
so a stripped declared entry cannot degrade the token) is judged only once
every declared entry verifies.
CRIT_UNLISTED / CRIT_NOT_UNDERSTOOD (§4.5 mandatory-to-understand claims)
follow the claim-form checks: a mandatory-to-understand claim that is present
but not named in aap_crit is CRIT_UNLISTED; an aap_crit name this verifier
does not implement, a name naming no claim in the token, or an
authorization_details entry type outside the §4.4.1 registry is
CRIT_NOT_UNDERSTOOD. CNF_MISMATCH (§4.6 proof of possession) is judged for an
otherwise-valid token against the presenter proof the fixture carries.
NOT_ATTENUATED (§5.3/§5.4) covers the delegation members beyond the scope
string: trust_class, the end of the validity window (exp; the start is not
ordered by the spec and is bounded only by the family clock-skew bound),
authorization_details under the narrower-than-or-equal-to relation, and
max_depth (including delegating past a terminal, depth-0 delegator).
REPLAYED_JTI is last: replay is only decidable for an otherwise-acceptable
token (§8.1; a fixture presents the same token `presentations` times to one
verifier, and the expected verdict pins the final presentation).

Fixture inputs beyond the token: verifierState.keys (trusted signing keys),
verifierState.clockNumericDate, verifierState.requiredSuites (path policy,
general form), delegation.delegatorToken (the immediate delegator's CGT or
DA, for the §5.3/§5.4 re-check), presentation.proof (the presenter's
signed-challenge proof for cnf: broker profile §6.8, A2A/MCP row).

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
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from dilithium_py.ml_dsa import ML_DSA_65

B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
DID_RE = re.compile(r"^did:")
JTI_RE = re.compile(r"^[0-9a-f]{32}$")
TRUST_CLASS_RE = re.compile(r"^[a-z0-9_-]+:[a-z0-9_-]+$")
SHA256_REF_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
# AAP-SPEC §9.5: EdDSA (RFC 8037) + ML-DSA-65 (FIPS 204, JOSE registration
# RFC 9964). ML-DSA-44/87, though JOSE-registered, are NOT in the AAP registry.
SUITE_REGISTRY = ("EdDSA", "ML-DSA-65")
BAC_TTL_SECONDS = 60  # AAP-SPEC §6.1

# AAP-SPEC §4.4.1: the wire value of an authorization_details entry `type` is
# the registry URI; the short name is the registry key.
TYPE_URI_PREFIX = "https://specs.opena2a.org/aap/types/"
TYPE_URI_RE = re.compile(r"^https://specs\.opena2a\.org/aap/types/[a-z_]+$")
# RFC 7638 thumbprint as registered for cnf by RFC 9449 §6.1 (43 base64url chars).
JKT_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
DECIMAL_RE = re.compile(r"^[0-9]+(\.[0-9]+)?$")
CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
# The claims this verifier implements as mandatory-to-understand (§4.5). Any
# other name in aap_crit is not understood and rejects the token.
UNDERSTOOD_CRIT = ("authorization_details", "cnf")
# §4.4.1 entry type registry: short name -> members that are MUST for the type.
# budget is MUST-one-of (BUDGET_MEMBERS) and is checked separately.
ENTRY_TYPES: dict[str, tuple[str, ...]] = {
    "mcp_tool": ("serverId", "tools"),
    "skill": ("identifier", "version", "contentHash"),
    "peer_agent": ("peerDid", "direction", "subDelegationDepth"),
    "model": ("endpoint",),
    "network": ("destinations", "tlsRequired"),
    "data": ("locations", "actions"),
    "budget": (),
}
BUDGET_MEMBERS = ("spend", "rate", "maxUses", "concurrency", "tokenCap")
# §5.4 member kinds of the narrower-than-or-equal-to relation.
IDENTITY_MEMBERS = ("serverId", "serverAtx", "identifier", "version", "contentHash", "schemaHash", "peerDid", "endpoint")
ALLOW_SET_MEMBERS = ("locations", "actions", "datatypes", "privileges", "tools", "models", "destinations", "direction", "fieldsAllowed", "labelCeiling", "egressCeiling")
CEILING_MEMBERS = ("labelCeiling", "egressCeiling")  # absent means the empty set
DENY_SET_MEMBERS = ("fieldsDenied",)
FLAG_MEMBERS = ("tlsRequired", "requiresApproval")


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


@dataclass
class KeyEntry:
    suite: str
    key_object: Ed25519PublicKey | None = None
    ml_dsa_pub: bytes | None = None


def build_key_set(verifier_state: dict) -> dict[str, KeyEntry]:
    keys: dict[str, KeyEntry] = {}
    for entry in verifier_state.get("keys", []):
        jwk = entry["publicJwk"]
        if jwk["kty"] == "AKP":
            # RFC 9964 AKP JWK: `pub` is the base64url FIPS 204 public key;
            # `alg` is REQUIRED on AKP keys and names the suite.
            keys[entry["kid"]] = KeyEntry(
                suite=jwk["alg"],
                ml_dsa_pub=base64.urlsafe_b64decode(jwk["pub"] + "=" * (-len(jwk["pub"]) % 4)),
            )
            continue
        raw = base64.urlsafe_b64decode(jwk["x"] + "=" * (-len(jwk["x"]) % 4))
        keys[entry["kid"]] = KeyEntry(
            suite="EdDSA",
            key_object=Ed25519PublicKey.from_public_bytes(raw),
        )
    return keys


# --- suite dispatch (AAP-SPEC §9.5) -------------------------------------------------


def suite_verify(alg: str, key: KeyEntry, signing_input: bytes, sig_bytes: bytes) -> bool:
    if alg == "ML-DSA-65":
        try:
            # Empty context, pure ML-DSA (RFC 9964). Malformed signature bytes
            # (e.g. wrong length) count as a non-verifying signature, fail closed.
            return ML_DSA_65.verify(key.ml_dsa_pub, signing_input, sig_bytes)
        except Exception:
            return False
    try:
        key.key_object.verify(sig_bytes, signing_input)
        return True
    except InvalidSignature:
        return False


# --- protected header (compact: closed {alg, typ, kid}; general: {alg, kid}) ------


def check_header(
    header_bytes: bytes,
    keys: dict[str, KeyEntry],
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
    if keys[kid].suite != alg:
        # The kid must name a key of the declared suite: the verifier has no key
        # for this (kid, alg) pair, so the token is unverifiable, fail closed.
        _reject(
            "UNKNOWN_KEY",
            f'{where}: kid "{kid}" is not a key for the declared suite "{alg}"',
        )
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
    "nonNegInt": (
        lambda v: _is_int(v) and v >= 0,
        "must be an integer >= 0 (0 is a terminal delegation, AAP-SPEC §5.3)",
    ),
    "actor": (_check_actor, 'must be an object with a DID "sub" (recursively)'),
    "authorizationDetails": (
        lambda v: _check_authorization_details_form(v),
        "must be a non-empty array of entries, each an object whose type is a §4.4.1 registry URI with well-formed members",
    ),
    "aapCrit": (
        lambda v: isinstance(v, list) and len(v) >= 1 and all(_nonempty(x) for x in v) and len(set(v)) == len(v),
        "must be a non-empty array of unique claim names (AAP-SPEC §4.5)",
    ),
    "cnf": (
        lambda v: _check_cnf_form(v),
        "must be an object carrying exactly one of jwk or jkt (RFC 7800, AAP-SPEC §4.6)",
    ),
    "labelSet": (
        lambda v: _is_uniq_str_arr(v),
        "must be an array of unique non-empty strings (a label set, AAP-SPEC §4.4.2)",
    ),
}


def _is_str_arr(v: Any) -> bool:
    return isinstance(v, list) and all(_nonempty(x) for x in v)


def _is_uniq_str_arr(v: Any) -> bool:
    return _is_str_arr(v) and len(set(v)) == len(v)


def _is_sha256_ref(v: Any) -> bool:
    return isinstance(v, str) and bool(SHA256_REF_RE.match(v))


def _pos_int(v: Any) -> bool:
    return _is_int(v) and v >= 1


def _non_neg_int(v: Any) -> bool:
    return _is_int(v) and v >= 0


def _check_cnf_form(v: Any) -> bool:
    if not _is_plain_object(v) or (("jwk" in v) == ("jkt" in v)):
        return False
    if "jwk" in v and not (_is_plain_object(v["jwk"]) and _nonempty(v["jwk"].get("kty"))):
        return False
    if "jkt" in v and not (isinstance(v["jkt"], str) and JKT_RE.match(v["jkt"])):
        return False
    return True


# Member forms of the §4.4.1 table. Members are checked whatever the entry
# type (the table's spelling is unique per member); members the table does not
# name are ignored, and unknown types are judged by the aap_crit rule, not here.
ENTRY_MEMBER_FORMS: dict[str, Callable[[Any], bool]] = {
    "serverId": _nonempty,
    "serverAtx": _is_sha256_ref,
    "tools": _is_str_arr,
    "argumentConstraints": lambda v: _is_plain_object(v) and all(_is_plain_object(x) for x in v.values()),
    "schemaHash": _is_sha256_ref,
    "identifier": _nonempty,
    "version": _nonempty,
    "contentHash": _is_sha256_ref,
    "peerDid": _is_did,
    "direction": lambda v: _is_uniq_str_arr(v) and len(v) >= 1 and all(d in ("outbound", "inbound") for d in v),
    "subDelegationDepth": _non_neg_int,
    "endpoint": _nonempty,
    "models": _is_str_arr,
    "destinations": _is_str_arr,
    "tlsRequired": lambda v: isinstance(v, bool),
    "locations": _is_str_arr,
    "actions": _is_str_arr,
    "datatypes": _is_str_arr,
    "privileges": _is_str_arr,
    "fieldsAllowed": _is_str_arr,
    "fieldsDenied": _is_str_arr,
    "labelCeiling": _is_uniq_str_arr,
    "egressCeiling": _is_uniq_str_arr,
    "spend": lambda v: (
        _is_plain_object(v)
        and isinstance(v.get("amount"), str)
        and bool(DECIMAL_RE.match(v["amount"]))
        and isinstance(v.get("currency"), str)
        and bool(CURRENCY_RE.match(v["currency"]))
    ),
    "rate": lambda v: _is_plain_object(v) and _pos_int(v.get("max")) and _pos_int(v.get("windowSeconds")),
    "maxUses": _pos_int,
    "concurrency": _pos_int,
    "tokenCap": lambda v: (
        _is_plain_object(v)
        and ("input" not in v or _non_neg_int(v["input"]))
        and ("output" not in v or _non_neg_int(v["output"]))
    ),
    "requiresApproval": lambda v: isinstance(v, bool),
}


def _check_authorization_details_form(v: Any) -> bool:
    """Form of the authorization_details claim (the vendored schema's shape plus
    the §4.4.1 member forms for types this verifier implements). False on the
    first malformed entry; an unknown type passes here and is rejected by
    check_crit as not understood."""
    if not isinstance(v, list) or len(v) == 0:
        return False
    for entry in v:
        if not _is_plain_object(entry) or not isinstance(entry.get("type"), str) or not TYPE_URI_RE.match(entry["type"]):
            return False
        for member, form in ENTRY_MEMBER_FORMS.items():
            if member in entry and not form(entry[member]):
                return False
        short_name = entry["type"][len(TYPE_URI_PREFIX):]
        required = ENTRY_TYPES.get(short_name)
        if required is None:
            continue
        if not all(m in entry for m in required):
            return False
        if short_name == "budget" and not any(m in entry for m in BUDGET_MEMBERS):
            return False
    return True

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
    ("authorization_details", "authorizationDetails", False),
    ("aap_crit", "aapCrit", False),
    ("cnf", "cnf", False),
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
        ("max_depth", "nonNegInt", True),
        ("delegator_atx", "sha256Ref", True),
        ("iat", "numericDate", True),
        ("exp", "numericDate", True),
        ("jti", "jti", True),
        ("aap_ver", "aapVer", False),
        ("authorization_details", "authorizationDetails", False),
        ("aap_crit", "aapCrit", False),
        ("cnf", "cnf", False),
        ("fga_constraints", "string", False),
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
        ("session_label", "labelSet", False),
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
        # §6.4: session_label is an L3 member; it MUST NOT appear at L1 or L2.
        if level < 3 and "session_label" in claims:
            _reject(
                "CLAIM_SCHEMA",
                f'claim "session_label" MUST NOT appear at bac_level {level} (AAP-SPEC §6.4)',
            )


# --- §4.5 mandatory-to-understand claims -------------------------------------------


def check_crit(claims: dict) -> None:
    crit = claims.get("aap_crit", [])
    # A mandatory-to-understand claim that is present MUST be named in aap_crit;
    # a verifier that ignored it would accept a bearer, unconstrained token.
    for name in UNDERSTOOD_CRIT:
        if name in claims and name not in crit:
            _reject(
                "CRIT_UNLISTED",
                f'claim "{name}" is present but not named in aap_crit — it is mandatory to '
                f"understand and MUST be listed (AAP-SPEC §4.5)",
            )
    for name in crit:
        if name not in UNDERSTOOD_CRIT:
            _reject(
                "CRIT_NOT_UNDERSTOOD",
                f'aap_crit names "{name}", which this verifier does not implement as a '
                f"mandatory-to-understand claim (AAP-SPEC §4.5)",
            )
        if name not in claims:
            _reject(
                "CRIT_NOT_UNDERSTOOD",
                f'aap_crit names "{name}" but the token carries no such claim (AAP-SPEC §4.5)',
            )
    # §4.4.1: an unknown type inside a mandatory-to-understand claim is not understood.
    for index, entry in enumerate(claims.get("authorization_details", [])):
        short_name = entry["type"][len(TYPE_URI_PREFIX):]
        if short_name not in ENTRY_TYPES:
            _reject(
                "CRIT_NOT_UNDERSTOOD",
                f'authorization_details[{index}] type "{short_name}" is not in the AAP-SPEC '
                f"§4.4.1 entry type registry — not understood, the token is rejected",
            )


# --- §4.6 proof of possession (presenter binding) ----------------------------------


def jwk_thumbprint(jwk: Any) -> str | None:
    """RFC 7638 thumbprint of an Ed25519 OKP JWK (RFC 8037 §2 required members,
    lexicographic order, no whitespace, SHA-256, base64url). None if the key is
    not an Ed25519 OKP key."""
    if not _is_plain_object(jwk) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or not _nonempty(jwk.get("x")):
        return None
    canonical = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}, separators=(",", ":"), sort_keys=True)
    return base64.urlsafe_b64encode(hashlib.sha256(canonical.encode("utf-8")).digest()).rstrip(b"=").decode("ascii")


def check_presenter_binding(claims: dict, presentation: Any) -> None:
    if "cnf" not in claims:
        return
    proof = (presentation or {}).get("proof") if _is_plain_object(presentation) else None
    if not _is_plain_object(proof):
        _reject("CNF_MISMATCH", "token carries cnf but no presenter proof was presented (AAP-SPEC §4.6)")
    # The suite models the broker profile §6.8 A2A/MCP row: a fresh challenge of
    # at least 16 bytes, returned signed under the presenter's key.
    if proof.get("binding") != "signed-challenge":
        _reject("CNF_MISMATCH", f'unsupported presentation binding "{proof.get("binding")}" (broker profile §6.8)')
    presented = jwk_thumbprint(proof.get("jwk"))
    if presented is None:
        _reject("CNF_MISMATCH", "presenter proof key is not an Ed25519 OKP JWK")
    cnf = claims["cnf"]
    bound = cnf["jkt"] if "jkt" in cnf else jwk_thumbprint(cnf.get("jwk"))
    if bound is None:
        _reject("CNF_MISMATCH", "cnf.jwk is not an Ed25519 OKP JWK")
    if presented != bound:
        _reject(
            "CNF_MISMATCH",
            f'presenter key thumbprint "{presented}" does not match the cnf binding "{bound}" (AAP-SPEC §4.6)',
        )
    challenge = _b64url_decode(proof.get("challenge"), "proof.challenge", "CNF_MISMATCH")
    if len(challenge) < 16:
        _reject("CNF_MISMATCH", "presenter proof challenge is shorter than 16 bytes (broker profile §6.8)")
    sig = _b64url_decode(proof.get("signature"), "proof.signature", "CNF_MISMATCH")
    try:
        x = proof["jwk"]["x"]
        key = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(x + "=" * (-len(x) % 4)))
    except Exception:
        _reject("CNF_MISMATCH", "presenter proof key is not a valid Ed25519 public key")
    try:
        key.verify(sig, challenge)
    except InvalidSignature:
        _reject("CNF_MISMATCH", "presenter proof signature does not verify under the cnf-bound key (AAP-SPEC §4.6)")


# --- §5.4 attenuation (narrower than or equal to) ----------------------------------


def decimal_compare(a: str, b: str) -> int:
    """Compare two non-negative decimal strings; returns -1, 0, or 1."""
    ia, _, fa = a.partition(".")
    ib, _, fb = b.partition(".")
    na = ia.lstrip("0") or "0"
    nb = ib.lstrip("0") or "0"
    if len(na) != len(nb):
        return -1 if len(na) < len(nb) else 1
    if na != nb:
        return -1 if na < nb else 1
    width = max(len(fa), len(fb))
    pa = fa.ljust(width, "0")
    pb = fb.ljust(width, "0")
    if pa == pb:
        return 0
    return -1 if pa < pb else 1


def destination_covered(child: str, parent: str) -> bool:
    """network.destinations coverage (§5.4): an element equals an E element or
    matches an E `*.` pattern; an E' pattern is covered only by an equal or
    broader E pattern."""
    if child == parent:
        return True
    if not parent.startswith("*."):
        return False
    suffix = parent[1:]  # ".example.com"
    if child.startswith("*."):
        child_suffix = child[1:]
        return child_suffix != suffix and child_suffix.endswith(suffix)
    host = child.split(":")[0]
    return host.endswith(suffix) and host != suffix[1:]


def subset_of(child_set: list, parent_set: list, member: str) -> bool:
    if member == "destinations":
        return all(any(destination_covered(c, p) for p in parent_set) for c in child_set)
    parent = set(parent_set)
    return all(c in parent for c in child_set)


def narrower_or_equal(child: dict, parent: dict) -> str | None:
    """None when child (E') is narrower than or equal to parent (E) under the
    §5.4 member kinds, else a short reason. Entries share a type."""
    for m in IDENTITY_MEMBERS:
        if m in parent and not (m in child and child[m] == parent[m]):
            return f"{m} differs from the delegator's"
    for m in ALLOW_SET_MEMBERS:
        if m not in child:
            continue  # absent in E' inherits E's value
        if m in parent:
            if not subset_of(child[m], parent[m], m):
                return f"{m} is not a subset of the delegator's"
        elif m in CEILING_MEMBERS and len(child[m]) > 0:
            return f"{m} names labels the delegator did not carry"
    for m in DENY_SET_MEMBERS:
        parent_set = parent.get(m, [])
        child_set = set(child.get(m, []))
        if not all(x in child_set for x in parent_set):
            return f"{m} is not a superset of the delegator's"
    for m in ("maxUses", "concurrency"):
        if m in child and m in parent and child[m] > parent[m]:
            return f"{m} exceeds the delegator's"
    if "subDelegationDepth" in child and "subDelegationDepth" in parent:
        if child["subDelegationDepth"] >= parent["subDelegationDepth"]:
            return "subDelegationDepth is not strictly less than the delegator's"
    if "rate" in child and "rate" in parent:
        if child["rate"]["max"] > parent["rate"]["max"]:
            return "rate.max exceeds the delegator's"
        if child["rate"]["windowSeconds"] < parent["rate"]["windowSeconds"]:
            return "rate.windowSeconds is shorter than the delegator's"
    if "spend" in child and "spend" in parent:
        if child["spend"]["currency"] != parent["spend"]["currency"]:
            return "spend is in a currency the delegator does not carry"
        if decimal_compare(child["spend"]["amount"], parent["spend"]["amount"]) > 0:
            return "spend.amount exceeds the delegator's"
    if "tokenCap" in child and "tokenCap" in parent:
        for k in ("input", "output"):
            if k in child["tokenCap"] and k in parent["tokenCap"] and child["tokenCap"][k] > parent["tokenCap"][k]:
                return f"tokenCap.{k} exceeds the delegator's"
    for m in FLAG_MEMBERS:
        if parent.get(m) is True and child.get(m) is not True:
            return f"{m} is relaxed from the delegator's"
    if "argumentConstraints" in parent:
        for tool, args in parent["argumentConstraints"].items():
            for arg, constraint in args.items():
                child_constraint = child.get("argumentConstraints", {}).get(tool, {}).get(arg)
                if child_constraint != constraint:
                    return f"argumentConstraints for {tool}.{arg} is not carried unchanged"
    return None


def check_attenuation(claims: dict, delegator_claims: dict) -> None:
    if "authorization_details" not in claims:
        return
    parents = delegator_claims.get("authorization_details", [])
    for index, entry in enumerate(claims["authorization_details"]):
        short_name = entry["type"][len(TYPE_URI_PREFIX):]
        candidates = [p for p in parents if p["type"] == entry["type"]]
        if not candidates:
            _reject(
                "NOT_ATTENUATED",
                f"authorization_details[{index}] (type {short_name}) has no parent entry of the "
                f"same type in the delegator's grant — an orphan entry (AAP-SPEC §5.4)",
            )
        reasons = [narrower_or_equal(entry, p) for p in candidates]
        if None not in reasons:
            _reject(
                "NOT_ATTENUATED",
                f"authorization_details[{index}] (type {short_name}) is not narrower than or equal "
                f"to any delegator entry of the same type: {reasons[0]} (AAP-SPEC §5.4)",
            )


def check_delegation(claims: dict, delegator_claims: dict) -> None:
    delegator_is_da = "act" in delegator_claims
    # Linkage: the supplied token must be this DA's immediate delegator.
    if claims["act"]["sub"] != delegator_claims["sub"]:
        _reject(
            "DELEGATOR_INVALID",
            f'delegator token subject "{delegator_claims["sub"]}" is not the DA\'s act.sub "{claims["act"]["sub"]}"',
        )
    if delegator_is_da and claims["act"].get("act") != delegator_claims["act"]:
        _reject("DELEGATOR_INVALID", "the DA's act chain does not continue the delegator's act chain (RFC 8693 §4.1)")
    # §5.2/§5.3: scope and trust_class equal to or a subset of the delegator's.
    da_scopes = str(claims["scope"]).split(" ")
    delegator_scopes = set(str(delegator_claims["scope"]).split(" "))
    if not all(s in delegator_scopes for s in da_scopes):
        _reject(
            "SCOPE_NOT_SUBSET",
            f'DA scope "{claims["scope"]}" is not a subset of the delegator scope '
            f'"{delegator_claims["scope"]}" (AAP-SPEC §5.2)',
        )
    if claims["trust_class"] != delegator_claims["trust_class"]:
        _reject(
            "SCOPE_NOT_SUBSET",
            f'DA trust_class "{claims["trust_class"]}" is not equal to or a subset of the delegator '
            f'trust_class "{delegator_claims["trust_class"]}" (AAP-SPEC §5.3)',
        )
    # §5.4: a DA carries less than its delegator — it cannot outlive it, so its
    # validity window ends no later than the delegator's. The start of the
    # window is not ordered by the spec (it is bounded only by the family
    # clock-skew bound) and is not checked.
    if claims["exp"] > delegator_claims["exp"]:
        _reject(
            "NOT_ATTENUATED",
            f"DA validity window ends (exp {claims['exp']}) after the delegator's "
            f"(exp {delegator_claims['exp']}) (AAP-SPEC §5.4)",
        )
    check_attenuation(claims, delegator_claims)
    # §5.3: max_depth is the remaining depth below this assertion. A delegator
    # DA at depth 0 is terminal; below a delegator DA at depth d the DA may carry
    # at most d - 1; a delegator peer_agent entry for this DA's sub caps it too.
    if delegator_is_da:
        if delegator_claims["max_depth"] < 1:
            _reject(
                "NOT_ATTENUATED",
                "the delegator is a terminal delegation (max_depth 0); delegating past it is "
                "not permitted (AAP-SPEC §5.3)",
            )
        if claims["max_depth"] > delegator_claims["max_depth"] - 1:
            _reject(
                "NOT_ATTENUATED",
                f"max_depth {claims['max_depth']} exceeds the delegator's remaining depth "
                f"{delegator_claims['max_depth'] - 1} (AAP-SPEC §5.3)",
            )
    peer = next(
        (
            e
            for e in delegator_claims.get("authorization_details", [])
            if e["type"] == f"{TYPE_URI_PREFIX}peer_agent" and e.get("peerDid") == claims["sub"]
        ),
        None,
    )
    if peer is not None and claims["max_depth"] > peer["subDelegationDepth"]:
        _reject(
            "NOT_ATTENUATED",
            f"max_depth {claims['max_depth']} exceeds the delegator's peer_agent subDelegationDepth "
            f"{peer['subDelegationDepth']} for this delegatee (AAP-SPEC §5.4)",
        )


# --- token verification -------------------------------------------------------------


def verify_compact_structure(token: Any, keys: dict[str, KeyEntry]) -> dict:
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

    signing_input = f"{h}.{p}".encode("ascii")
    if not suite_verify(header["alg"], keys[header["kid"]], signing_input, sig_bytes):
        _reject("BAD_SIGNATURE", f'signature does not verify under kid "{header["kid"]}"')

    try:
        # Standard last-wins JSON semantics for the claim set (RFC 7519 §4).
        claims = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)).decode("utf-8"))
    except Exception as exc:
        _reject("MALFORMED_PAYLOAD", f"claim set is not valid JSON: {exc}")
    if not _is_plain_object(claims):
        _reject("MALFORMED_PAYLOAD", "claim set is not a JSON object")
    return claims


def verify_general_structure(
    token_general: Any, keys: dict[str, KeyEntry], required_suites: tuple[str, ...] = ()
) -> dict:
    if not _is_plain_object(token_general):
        _reject("MALFORMED_TOKEN", "general serialization is not a JSON object")
    payload = token_general.get("payload")
    signatures = token_general.get("signatures")
    _b64url_decode(payload, "payload", "MALFORMED_TOKEN")
    if not isinstance(signatures, list) or len(signatures) == 0:
        _reject("MALFORMED_TOKEN", "signatures must be a non-empty array")
    declared_algs: list[str] = []
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
        signing_input = f'{entry["protected"]}.{payload}'.encode("ascii")
        # Every declared entry MUST verify (§9.4) — no subset acceptance.
        if not suite_verify(header["alg"], keys[header["kid"]], signing_input, sig_bytes):
            _reject(
                "BAD_SIGNATURE",
                f'signatures[{index}] does not verify under its declared kid "{header["kid"]}" — '
                f"every declared entry MUST verify (AAP-SPEC §9.4)",
            )
        declared_algs.append(header["alg"])
    # Hybrid family gate (§8.2/§9.4): a general-form token declaring any
    # ML-DSA-65 entry is on the hybrid profile and MUST carry at least one
    # Ed25519 entry and at least one ML-DSA-65 entry — a stripped hybrid MUST
    # NOT degrade to single-family acceptance. Judged only after every declared
    # entry verifies, so a bad signature is always the earlier defect.
    if "ML-DSA-65" in declared_algs and "EdDSA" not in declared_algs:
        _reject(
            "HYBRID_INCOMPLETE",
            "general-form token declares ML-DSA-65 but carries no Ed25519 entry — "
            "the hybrid profile requires at least one entry of each family (AAP-SPEC §9.4)",
        )
    # Path policy (§8.2): suite acceptance is pinned by the verifier per path,
    # never selected by the token. A token missing a verifying entry of a suite
    # the path requires is a hybrid token with that declared entry stripped — it
    # MUST NOT degrade to acceptance on the remaining family (§9.4).
    for suite in required_suites:
        if suite not in declared_algs:
            _reject(
                "HYBRID_INCOMPLETE",
                f"verifier path policy requires a verifying {suite} entry but the token carries "
                f"only [{', '.join(declared_algs)}] — a declared entry stripped from a hybrid token "
                f"cannot degrade it to single-family acceptance (AAP-SPEC §8.2, §9.4)",
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
    # §8.1 replay prevention: one jti cache per verifier lifetime. A fixture may
    # present its token `presentations` times (default 1); the expected verdict
    # pins the final presentation.
    jti_cache: dict[str, int] = {}
    presentations = fixture.get("presentations")
    if not _is_int(presentations):
        presentations = 1
    result: Result | None = None
    for _ in range(presentations):
        result = verify_presentation(fixture, jti_cache)
    return result


def verify_presentation(fixture: dict, jti_cache: dict[str, int]) -> Result:
    verifier_state = fixture.get("verifierState", {})
    keys = build_key_set(verifier_state)
    clock = verifier_state.get("clockNumericDate")
    fixture_type = fixture.get("fixtureType")

    try:
        if fixture.get("tokenForm") == "general":
            required = verifier_state.get("requiredSuites")
            required_suites = tuple(required) if isinstance(required, list) else ()
            claims = verify_general_structure(fixture.get("tokenGeneral"), keys, required_suites)
        else:
            claims = verify_compact_structure(fixture.get("token"), keys)

        check_claims(claims, fixture_type)
        check_crit(claims)

        if _is_int(clock) and clock >= claims["exp"]:
            _reject("EXPIRED", f"token expired (exp {claims['exp']} <= clock {clock})")
        if fixture_type == "bac" and claims["exp"] - claims["iat"] > BAC_TTL_SECONDS:
            _reject(
                "TTL_WINDOW",
                f"BAC validity window exp - iat = {claims['exp'] - claims['iat']}s "
                f"exceeds the 60-second cap (AAP-SPEC §6.1)",
            )
        check_presenter_binding(claims, fixture.get("presentation"))
        delegation = fixture.get("delegation") or {}
        if fixture_type == "da" and "delegatorToken" in delegation:
            try:
                delegator_claims = verify_compact_structure(delegation["delegatorToken"], keys)
                # The immediate delegator is a CGT, or a DA when the chain is deeper.
                check_claims(delegator_claims, "da" if "act" in delegator_claims else "cgt")
                check_crit(delegator_claims)
            except Reject as exc:
                _reject("DELEGATOR_INVALID", f"delegator token: {exc.reason}")
            check_delegation(claims, delegator_claims)

        # §8.1: receivers MUST track used jti values for the token's TTL window
        # and MUST reject a repeated identifier. Judged last — replay is only
        # decidable for an otherwise-acceptable token. The identifier is scoped
        # per issuer and remembered until the token's exp.
        jti_key = f"{claims['iss']}\n{claims['jti']}"
        remembered_exp = jti_cache.get(jti_key)
        if remembered_exp is not None and (not _is_int(clock) or clock < remembered_exp):
            _reject(
                "REPLAYED_JTI",
                f'jti "{claims["jti"]}" was already presented and its TTL window '
                f"has not elapsed (AAP-SPEC §8.1)",
            )
        jti_cache[jti_key] = claims["exp"]

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
