#!/usr/bin/env node
// Deterministic fixture generator for aap-conformance.
//
// Every fixture in fixtures/ is produced by this script, never hand-authored.
// Token construction mirrors the AAP reference implementation (Secretless
// src/broker/cpi/assertion.ts) and the spec repo's generator
// (agent-authorization-protocol scripts/generate_examples.py) byte-for-byte:
//
//     signing input = BASE64URL(UTF8(JSON(header))) || "." || BASE64URL(UTF8(JSON(claims)))
//     signature     = Ed25519(signing input)
//     token         = signing input || "." || BASE64URL(signature)
//
// ACCEPT fixtures embed the spec repo's published token bytes unchanged
// (AAP-SPEC §9.7 fixtures, generated from the published test-key seeds in
// vectors/test-keys.json); CI drift-gates them against the pinned
// agent-authorization-protocol ref. REJECT fixtures are single-defect
// variants minted here with the same construction. Ed25519 signing is
// deterministic, so fixed seeds + fixed claims = fixed bytes.
//
// Usage:
//     node scripts/generate-fixtures.mjs        # (re)write fixtures/ + MANIFEST.sha256
//
// CI re-runs this and `git diff --exit-code` pins the bytes.

import { readFileSync, writeFileSync, mkdirSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  createPrivateKey,
  createPublicKey,
  createHash,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURES = join(ROOT, "fixtures");
const SPEC_URL =
  "https://github.com/opena2a-standards/agent-authorization-protocol/blob/main/AAP-SPEC.md";

// --- key material (published TEST seeds; vectors/test-keys.json is the source) ---

const TEST_KEYS = JSON.parse(
  readFileSync(join(ROOT, "vectors", "test-keys.json"), "utf8"),
);

const PKCS8_ED25519_PREFIX = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

const KEYS = new Map();
for (const entry of TEST_KEYS.keys) {
  const priv = createPrivateKey({
    key: Buffer.concat([
      PKCS8_ED25519_PREFIX,
      Buffer.from(entry.ed25519SeedHex, "hex"),
    ]),
    format: "der",
    type: "pkcs8",
  });
  const pub = createPublicKey(priv);
  // Seed <-> published JWK consistency: the public key derived from the seed
  // must be the published x, or the vendored key file has drifted.
  const rawPub = pub
    .export({ format: "der", type: "spki" })
    .subarray(SPKI_ED25519_PREFIX.length);
  const wantX = Buffer.from(entry.publicJwk.x, "base64url");
  if (!rawPub.equals(wantX)) {
    throw new Error(`test key ${entry.kid}: seed does not derive published JWK x`);
  }
  KEYS.set(entry.kid, { priv, pub, jwk: entry.publicJwk });
}

// --- fixed inputs (identical to the spec repo generator) ----------------------

const REGISTRY_ISSUER = "did:opena2a:authority:opena2a.org";
const BROKER_ISSUER = "https://broker.acme.example";
const AGENT_DID = "did:opena2a:agent:acme/orders-reader";
const DELEGATEE_DID = "did:opena2a:agent:acme/reporting-bot";

// 2026-06-01T12:00:00Z — the reference e2e test's fixed clock.
const IAT = 1780315200;
// Verifier clock for every fixture except the expiry fixture: 30s after iat,
// inside every token's validity window including the BAC 60-second TTL.
const CLOCK = IAT + 30;
// One second past the CGT exp (IAT + 300).
const CLOCK_PAST_CGT_EXP = IAT + 301;

const sha256hex = (s) => createHash("sha256").update(s).digest("hex");
const ATX_REFERENCE = "sha256:" + sha256hex("aap-example-atx");
const BINARY_HASH = "sha256:" + sha256hex("aap-example-binary");

// jti values: the four spec-repo fixture jtis, plus fresh deterministic
// constants for the reject-set tokens (16 bytes lowercase hex, AAP-SPEC §8.1).
const JTI = {
  ait: "1c9f2e8a7b6d5c4e3f2a1b0c9d8e7f6a",
  cgt: "9f8e7d6c5b4a39281706f5e4d3c2b1a0",
  da: "4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d",
  bac: "7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b",
  unknownAlg: "0a1b2c3d4e5f60718293a4b5c6d7e8f9",
  critHeader: "1a2b3c4d5e6f708192a3b4c5d6e7f809",
  dupHeader: "2b3c4d5e6f708192a3b4c5d6e7f8091a",
  missingTrustClass: "3c4d5e6f708192a3b4c5d6e7f8091a2b",
  trustClassScopeShaped: "5e6f708192a3b4c5d6e7f8091a2b3c4d",
  bacTtl: "6f708192a3b4c5d6e7f8091a2b3c4d5e",
  bacL3: "708192a3b4c5d6e7f8091a2b3c4d5e6f",
  daSuperset: "8192a3b4c5d6e7f8091a2b3c4d5e6f70",
};

// --- JWS primitives (mirror assertion.ts exactly) ------------------------------

const b64url = (buf) => Buffer.from(buf).toString("base64url");
const compactJson = (obj) => JSON.stringify(obj);

function signRaw(kid, data) {
  return cryptoSign(null, Buffer.from(data, "utf8"), KEYS.get(kid).priv);
}

function verifyRaw(kid, data, sig) {
  return cryptoVerify(null, Buffer.from(data, "utf8"), KEYS.get(kid).pub, sig);
}

/** Mint a compact token; headerJson may be a raw string for malformed-header
 *  fixtures (the signature is still a REAL signature over those exact bytes). */
function mintCompact(kid, header, claims, { expectValid = true } = {}) {
  const headerJson =
    typeof header === "string" ? header : compactJson(header);
  const signingInput = `${b64url(headerJson)}.${b64url(compactJson(claims))}`;
  const sig = signRaw(kid, signingInput);
  if (verifyRaw(kid, signingInput, sig) !== expectValid && expectValid) {
    throw new Error("self-verify failed for a token expected to verify");
  }
  return `${signingInput}.${b64url(sig)}`;
}

const compactHeader = (kid) => ({ alg: "EdDSA", typ: "JWT", kid });

/** JWS General JSON Serialization (RFC 7515 §7.2.1) — AAP-SPEC §9.4.
 *  signWithKid lets an entry declare one kid while signing with another
 *  (the every-declared-entry-MUST-verify reject fixture). */
function mintGeneral(entries, claims) {
  const payload = b64url(compactJson(claims));
  const signatures = entries.map(({ kid, signWithKid }) => {
    const protectedB64 = b64url(compactJson({ alg: "EdDSA", kid }));
    const sig = signRaw(signWithKid ?? kid, `${protectedB64}.${payload}`);
    const verifies = verifyRaw(kid, `${protectedB64}.${payload}`, sig);
    const shouldVerify = !signWithKid || signWithKid === kid;
    if (verifies !== shouldVerify) {
      throw new Error(`general entry ${kid}: unexpected self-verify result`);
    }
    return { protected: protectedB64, signature: b64url(sig) };
  });
  return { payload, signatures };
}

// --- claim sets (identical member values and order to the spec generator) ------

const aitClaims = () => ({
  iss: REGISTRY_ISSUER,
  sub: AGENT_DID,
  agent_id: "aim_orders_reader",
  atx_reference: ATX_REFERENCE,
  declared_purpose: "Reads order records for reporting",
  trust_level: 4,
  iat: IAT,
  exp: IAT + 3600,
  jti: JTI.ait,
});

const cgtClaims = (overrides = {}) => ({
  iss: BROKER_ISSUER,
  sub: AGENT_DID,
  aud: "https://api.orders.internal",
  scope: "orders.read",
  trust_class: "orders:read",
  issuer_chain: [REGISTRY_ISSUER],
  trust_level: 4,
  iat: IAT,
  exp: IAT + 300,
  jti: JTI.cgt,
  ...overrides,
});

const daClaims = (overrides = {}) => ({
  iss: BROKER_ISSUER,
  sub: DELEGATEE_DID,
  aud: "https://api.orders.internal",
  scope: "orders.read",
  trust_class: "orders:read",
  issuer_chain: [REGISTRY_ISSUER],
  trust_level: 4,
  act: { sub: AGENT_DID },
  max_depth: 1,
  delegator_atx: ATX_REFERENCE,
  iat: IAT,
  exp: IAT + 300,
  jti: JTI.da,
  ...overrides,
});

const bacClaims = (overrides = {}) => ({
  iss: REGISTRY_ISSUER,
  sub: AGENT_DID,
  bac_level: 3,
  atx_reference: ATX_REFERENCE,
  binary_hash: BINARY_HASH,
  drift_score: 0.04,
  anomaly_state: "nominal",
  intent_verified: true,
  iat: IAT,
  exp: IAT + 60,
  jti: JTI.bac,
  ...overrides,
});

// --- spec reference shorthands --------------------------------------------------

const ref = (section) => ({ id: "AAP", ref: SPEC_URL, section });
const RFC7515 = {
  id: "RFC 7515",
  ref: "https://datatracker.ietf.org/doc/html/rfc7515",
  section: "JSON Web Signature",
};
const RFC8032 = {
  id: "RFC 8032",
  ref: "https://datatracker.ietf.org/doc/html/rfc8032",
  section: "Ed25519 (published test-key seeds in vectors/test-keys.json)",
};

const keyRef = (kid) => ({ kid, publicJwk: KEYS.get(kid).jwk });

const state = (kids, clock = CLOCK) => ({
  clockNumericDate: clock,
  keys: kids.map(keyRef),
});

// --- fixtures -------------------------------------------------------------------

// The four spec-repo ACCEPT tokens (byte-identical to examples/tokens/*.jwt at
// the pinned ref; CI enforces this with scripts/spec_pin_check.py).
const AIT_TOKEN = mintCompact("registry-key-1", compactHeader("registry-key-1"), aitClaims());
const CGT_TOKEN = mintCompact("broker-key-1", compactHeader("broker-key-1"), cgtClaims());
const DA_TOKEN = mintCompact("broker-key-1", compactHeader("broker-key-1"), daClaims());
const BAC_TOKEN = mintCompact("registry-key-1", compactHeader("registry-key-1"), bacClaims());
const CGT_GENERAL = mintGeneral(
  [{ kid: "broker-key-1" }, { kid: "broker-key-2" }],
  cgtClaims(),
);

const fixtures = [];
function fixture(name, doc) {
  fixtures.push([name, { $schema: "https://aap.opena2a.org/schemas/fixture-v1.json", name: `aap-v1/${name}`, ...doc }]);
}

// -------- ACCEPT (the spec repo's published tokens, reused byte-for-byte) -------

fixture("ait-compact-valid", {
  description:
    "The spec repo's generated AIT (examples/tokens/ait-v1.jwt): a compact EdDSA JWT with the §3.2 claim set, signed by registry-key-1. Verifier MUST ACCEPT.",
  fixtureType: "ait",
  tokenForm: "compact",
  spec: [ref("§3.2 Token Structure"), ref("§9.3 Compact Serialization"), RFC7515, RFC8032],
  verifierState: state(["registry-key-1"]),
  expected: { verifyResult: "ACCEPT" },
  schemaValid: true,
  headerSchemaValid: true,
  token: AIT_TOKEN,
});

fixture("cgt-compact-valid", {
  description:
    "The spec repo's generated CGT (examples/tokens/cgt-v1.jwt), ratified byte-for-byte from the Secretless reference broker assertion: a compact EdDSA JWT with the §4.2 claim set, signed by broker-key-1. Verifier MUST ACCEPT.",
  fixtureType: "cgt",
  tokenForm: "compact",
  spec: [ref("§4.2 Token Structure"), ref("§9.1 Canonical Form"), ref("§9.3 Compact Serialization"), RFC7515, RFC8032],
  verifierState: state(["broker-key-1"]),
  expected: { verifyResult: "ACCEPT" },
  schemaValid: true,
  headerSchemaValid: true,
  token: CGT_TOKEN,
});

fixture("da-compact-valid", {
  description:
    "The spec repo's generated DA (examples/tokens/da-v1.jwt): the CGT claim set plus the RFC 8693 delegation members (act.sub, max_depth, delegator_atx), signed by broker-key-1. The delegation context carries the delegator's CGT; the DA scope (orders.read) is a subset of the delegator scope (orders.read). Verifier MUST ACCEPT.",
  fixtureType: "da",
  tokenForm: "compact",
  spec: [ref("§5.3 Assertion Form"), ref("§5.2 Constraints (scope subsetting)"), RFC7515, RFC8032],
  verifierState: state(["broker-key-1"]),
  delegation: { delegatorToken: CGT_TOKEN },
  expected: { verifyResult: "ACCEPT" },
  schemaValid: true,
  headerSchemaValid: true,
  token: DA_TOKEN,
});

fixture("bac-compact-valid", {
  description:
    "The spec repo's generated BAC (examples/tokens/bac-v1.jwt): a Level 3 behavioral attestation with the cumulative L1-L3 members and a 60-second validity window (exp - iat = 60), signed by registry-key-1. Verifier MUST ACCEPT.",
  fixtureType: "bac",
  tokenForm: "compact",
  spec: [ref("§6.4 Claim Set"), ref("§6.1 Purpose (60-second TTL)"), RFC7515, RFC8032],
  verifierState: state(["registry-key-1"]),
  expected: { verifyResult: "ACCEPT" },
  schemaValid: true,
  headerSchemaValid: true,
  token: BAC_TOKEN,
});

fixture("cgt-general-valid", {
  description:
    "The spec repo's generated multi-signature CGT (examples/tokens/cgt-v1.general.json): the §4.2 claim set as JWS General JSON Serialization with two Ed25519 entries (broker-key-1, broker-key-2), each protected header exactly {alg, kid} per §9.4. Both declared entries verify. Verifier MUST ACCEPT.",
  fixtureType: "cgt",
  tokenForm: "general",
  spec: [ref("§9.4 Multi-Signature Form"), ref("§8.2 Cryptographic Agility"), RFC7515, RFC8032],
  verifierState: state(["broker-key-1", "broker-key-2"]),
  expected: { verifyResult: "ACCEPT" },
  schemaValid: true,
  tokenGeneral: CGT_GENERAL,
});

// -------- REJECT ----------------------------------------------------------------

fixture("cgt-compact-bad-signature", {
  description:
    "The §4.2 CGT claim set with a header declaring kid broker-key-1, but the signature was produced by broker-key-2. The claims are schema-valid and unexpired; the signature is the sole defect. Verifier MUST REJECT with BAD_SIGNATURE.",
  fixtureType: "cgt",
  tokenForm: "compact",
  spec: [ref("§9.1 Canonical Form"), ref("§9.3 Compact Serialization"), RFC8032],
  verifierState: state(["broker-key-1"]),
  expected: { verifyResult: "REJECT", rejectCategory: "BAD_SIGNATURE", reasonContains: "signature" },
  schemaValid: true,
  headerSchemaValid: true,
  token: (() => {
    const signingInput = `${b64url(compactJson(compactHeader("broker-key-1")))}.${b64url(compactJson(cgtClaims()))}`;
    const sig = signRaw("broker-key-2", signingInput);
    if (verifyRaw("broker-key-1", signingInput, sig)) throw new Error("bad-signature fixture unexpectedly verifies");
    return `${signingInput}.${b64url(sig)}`;
  })(),
});

fixture("cgt-compact-unknown-alg", {
  description:
    "A CGT whose protected header declares alg ES256 — a suite absent from the §9.5 registry. The verifier MUST reject an alg it does not support rather than silently downgrade or guess (§8.2); rejection happens at the header stage, before any signature evaluation. Verifier MUST REJECT with UNKNOWN_ALG.",
  fixtureType: "cgt",
  tokenForm: "compact",
  spec: [ref("§9.5 Suite Registry (v1)"), ref("§8.2 Cryptographic Agility (no silent downgrade)")],
  verifierState: state(["broker-key-1"]),
  expected: { verifyResult: "REJECT", rejectCategory: "UNKNOWN_ALG", reasonContains: "ES256" },
  schemaValid: true,
  headerSchemaValid: false,
  token: mintCompact(
    "broker-key-1",
    { alg: "ES256", typ: "JWT", kid: "broker-key-1" },
    cgtClaims({ jti: JTI.unknownAlg }),
  ),
});

fixture("cgt-compact-crit-header", {
  description:
    'A CGT whose protected header carries crit: ["aap_ver"]. v1 headers are CLOSED (§9.2): a verifier MUST reject unknown header parameters, including crit — RFC 7515 §4.1.11 crit processing is exactly the extension channel a closed v1 header refuses. The signature is a valid Ed25519 signature over these exact header bytes. Verifier MUST REJECT with UNKNOWN_HEADER_PARAM.',
  fixtureType: "cgt",
  tokenForm: "compact",
  spec: [ref("§9.2 Protected Header (closed v1 header)"), RFC7515],
  verifierState: state(["broker-key-1"]),
  expected: { verifyResult: "REJECT", rejectCategory: "UNKNOWN_HEADER_PARAM", reasonContains: "crit" },
  schemaValid: true,
  headerSchemaValid: false,
  token: mintCompact(
    "broker-key-1",
    { alg: "EdDSA", typ: "JWT", kid: "broker-key-1", crit: ["aap_ver"] },
    cgtClaims({ jti: JTI.critHeader }),
  ),
});

fixture("cgt-compact-duplicate-header-member", {
  description:
    'A CGT whose protected header bytes contain the alg member twice: {"alg":"EdDSA",...,"alg":"none"}. A last-wins JSON parser sees alg none; a first-wins parser sees alg EdDSA and a signature that verifies — the classic duplicate-member smuggling split. A verifier MUST strict-parse the protected header and reject duplicate members (§9.2 closed header; RFC 8259 duplicate names are undefined behavior). Verifier MUST REJECT with MALFORMED_HEADER.',
  fixtureType: "cgt",
  tokenForm: "compact",
  spec: [ref("§9.2 Protected Header (strict parse)"), { id: "RFC 8259", ref: "https://datatracker.ietf.org/doc/html/rfc8259", section: "§4 (duplicate object names)" }],
  verifierState: state(["broker-key-1"]),
  expected: { verifyResult: "REJECT", rejectCategory: "MALFORMED_HEADER", reasonContains: "duplicate" },
  schemaValid: true,
  headerSchemaValid: false,
  token: mintCompact(
    "broker-key-1",
    '{"alg":"EdDSA","typ":"JWT","kid":"broker-key-1","alg":"none"}',
    cgtClaims({ jti: JTI.dupHeader }),
  ),
});

fixture("cgt-compact-expired", {
  description:
    "Byte-identical to cgt-compact-valid (the spec repo's cgt-v1.jwt; exp = iat + 300); only the pinned verifier clock differs — one second past exp. The signature IS valid; expiry is the sole defect. Verifier MUST REJECT with EXPIRED.",
  fixtureType: "cgt",
  tokenForm: "compact",
  spec: [ref("§4.3 TTL Tiers"), { id: "RFC 7519", ref: "https://datatracker.ietf.org/doc/html/rfc7519", section: "§4.1.4 (exp)" }],
  verifierState: state(["broker-key-1"], CLOCK_PAST_CGT_EXP),
  expected: { verifyResult: "REJECT", rejectCategory: "EXPIRED", reasonContains: "expired" },
  schemaValid: true,
  headerSchemaValid: true,
  token: CGT_TOKEN,
});

fixture("cgt-compact-missing-trust-class", {
  description:
    "A CGT missing the REQUIRED trust_class claim (§4.2). Everything else is valid, including the signature. Verifier MUST REJECT with CLAIM_SCHEMA.",
  fixtureType: "cgt",
  tokenForm: "compact",
  spec: [ref("§4.2 Token Structure")],
  verifierState: state(["broker-key-1"]),
  expected: { verifyResult: "REJECT", rejectCategory: "CLAIM_SCHEMA", reasonContains: "trust_class" },
  schemaValid: false,
  headerSchemaValid: true,
  token: (() => {
    const claims = cgtClaims({ jti: JTI.missingTrustClass });
    delete claims.trust_class;
    return mintCompact("broker-key-1", compactHeader("broker-key-1"), claims);
  })(),
});

fixture("cgt-compact-jti-uppercase", {
  description:
    "A CGT whose jti is uppercase hex. §8.1 pins jti as 16 random bytes LOWERCASE hex (^[0-9a-f]{32}$); a case-insensitive validator lets two encodings of the same replay id through dedup. The signature is valid. Verifier MUST REJECT with CLAIM_SCHEMA.",
  fixtureType: "cgt",
  tokenForm: "compact",
  spec: [ref("§8.1 Replay Prevention (jti form)")],
  verifierState: state(["broker-key-1"]),
  expected: { verifyResult: "REJECT", rejectCategory: "CLAIM_SCHEMA", reasonContains: "jti" },
  schemaValid: false,
  headerSchemaValid: true,
  token: mintCompact(
    "broker-key-1",
    compactHeader("broker-key-1"),
    cgtClaims({ jti: JTI.cgt.toUpperCase() }),
  ),
});

fixture("cgt-compact-trust-class-scope-shaped", {
  description:
    "A CGT whose trust_class carries a scope-shaped value (orders.read) instead of an abstract ATX trust class (orders:read) — it fails the ^[a-z0-9_-]+:[a-z0-9_-]+$ pattern. This is the regression fixture for the reference-broker bug fixed in secretless-ai#92 (trust_class minted from the binding scope instead of the matched policy clause). Verifier MUST REJECT with CLAIM_SCHEMA.",
  fixtureType: "cgt",
  tokenForm: "compact",
  spec: [ref("§4.2 Token Structure (trust_class)")],
  verifierState: state(["broker-key-1"]),
  expected: { verifyResult: "REJECT", rejectCategory: "CLAIM_SCHEMA", reasonContains: "trust_class" },
  schemaValid: false,
  headerSchemaValid: true,
  token: mintCompact(
    "broker-key-1",
    compactHeader("broker-key-1"),
    cgtClaims({ trust_class: "orders.read", jti: JTI.trustClassScopeShaped }),
  ),
});

fixture("bac-compact-ttl-exceeded", {
  description:
    "A BAC with exp - iat = 300. The BAC validity window is normatively capped at 60 seconds (§6.1); a longer window turns a point-in-time behavioral attestation into a bearer credential. The claim set is schema-valid (the cap is a prose rule, not a schema rule) and the token is unexpired at the pinned clock; the window is the sole defect. Verifier MUST REJECT with TTL_WINDOW.",
  fixtureType: "bac",
  tokenForm: "compact",
  spec: [ref("§6.1 Purpose (60-second TTL)"), ref("§6.4 Claim Set")],
  verifierState: state(["registry-key-1"]),
  expected: { verifyResult: "REJECT", rejectCategory: "TTL_WINDOW", reasonContains: "60" },
  schemaValid: true,
  headerSchemaValid: true,
  token: mintCompact(
    "registry-key-1",
    compactHeader("registry-key-1"),
    bacClaims({ exp: IAT + 300, jti: JTI.bacTtl }),
  ),
});

fixture("bac-compact-l3-missing-drift-score", {
  description:
    "A BAC declaring bac_level 3 without drift_score. Levels are cumulative (§6.2/§6.4): L3 requires binary_hash, drift_score, anomaly_state, and intent_verified; the other three are present, drift_score is the sole omission. Verifier MUST REJECT with CLAIM_SCHEMA.",
  fixtureType: "bac",
  tokenForm: "compact",
  spec: [ref("§6.4 Claim Set (cumulative levels)"), ref("§6.2 Three Levels")],
  verifierState: state(["registry-key-1"]),
  expected: { verifyResult: "REJECT", rejectCategory: "CLAIM_SCHEMA", reasonContains: "drift_score" },
  schemaValid: false,
  headerSchemaValid: true,
  token: (() => {
    const claims = bacClaims({ jti: JTI.bacL3 });
    delete claims.drift_score;
    return mintCompact("registry-key-1", compactHeader("registry-key-1"), claims);
  })(),
});

fixture("cgt-general-one-bad-signature", {
  description:
    "The multi-signature CGT with the first entry (broker-key-1) verifying and the second entry declaring kid broker-key-2 but carrying a signature produced by broker-key-1. §9.4: every declared entry MUST verify; a verifier MUST NOT accept a token on a subset of its declared signatures — accepting one-of-two silently drops the post-quantum half of a hybrid credential. Verifier MUST REJECT with BAD_SIGNATURE.",
  fixtureType: "cgt",
  tokenForm: "general",
  spec: [ref("§9.4 Multi-Signature Form (every declared entry MUST verify)"), ref("§8.2 Cryptographic Agility")],
  verifierState: state(["broker-key-1", "broker-key-2"]),
  expected: { verifyResult: "REJECT", rejectCategory: "BAD_SIGNATURE", reasonContains: "signature" },
  schemaValid: true,
  tokenGeneral: mintGeneral(
    [{ kid: "broker-key-1" }, { kid: "broker-key-2", signWithKid: "broker-key-1" }],
    cgtClaims(),
  ),
});

fixture("da-compact-scope-superset", {
  description:
    "A DA whose scope (orders.read orders.write) is a SUPERSET of the delegator's CGT scope (orders.read) — delegation widened authority. §5.2: the delegatee scope MUST be a subset of the delegator's scope; the minting broker enforces it and verifiers re-check it. Both tokens carry valid signatures and schema-valid claims; the subset relation is the sole defect. Verifier MUST REJECT with SCOPE_NOT_SUBSET.",
  fixtureType: "da",
  tokenForm: "compact",
  spec: [ref("§5.2 Constraints (scope subsetting)"), ref("§5.3 Assertion Form")],
  verifierState: state(["broker-key-1"]),
  delegation: { delegatorToken: CGT_TOKEN },
  expected: { verifyResult: "REJECT", rejectCategory: "SCOPE_NOT_SUBSET", reasonContains: "subset" },
  schemaValid: true,
  headerSchemaValid: true,
  token: mintCompact(
    "broker-key-1",
    compactHeader("broker-key-1"),
    daClaims({ scope: "orders.read orders.write", jti: JTI.daSuperset }),
  ),
});

// --- write ----------------------------------------------------------------------

mkdirSync(FIXTURES, { recursive: true });
for (const [name, doc] of fixtures) {
  const path = join(FIXTURES, `${name}.json`);
  writeFileSync(path, JSON.stringify(doc, null, 2) + "\n");
  console.log(`wrote fixtures/${name}.json`);
}

// MANIFEST.sha256 over the byte-pinned inputs: fixtures + the vendored test keys.
const manifestEntries = [];
for (const f of readdirSync(FIXTURES).sort()) {
  if (!f.endsWith(".json")) continue;
  const digest = createHash("sha256").update(readFileSync(join(FIXTURES, f))).digest("hex");
  manifestEntries.push(`${digest}  fixtures/${f}`);
}
const keysDigest = createHash("sha256")
  .update(readFileSync(join(ROOT, "vectors", "test-keys.json")))
  .digest("hex");
manifestEntries.push(`${keysDigest}  vectors/test-keys.json`);
writeFileSync(join(ROOT, "MANIFEST.sha256"), manifestEntries.join("\n") + "\n");
console.log(`wrote MANIFEST.sha256 (${manifestEntries.length} entries)`);
