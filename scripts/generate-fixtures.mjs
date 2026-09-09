#!/usr/bin/env node
// Deterministic fixture generator for aap-conformance.
//
// Every fixture in fixtures/ is produced by this script, never hand-authored.
// Token construction mirrors the AAP reference implementation (Secretless
// src/broker/cpi/assertion.ts) and the spec repo's generator
// (agent-authorization-protocol scripts/generate_examples.py) byte-for-byte:
//
//     signing input = BASE64URL(UTF8(JSON(header))) || "." || BASE64URL(UTF8(JSON(claims)))
//     signature     = Ed25519(signing input)          suite "EdDSA"
//                   | ML-DSA-65(signing input)        suite "ML-DSA-65" (RFC 9964)
//     token         = signing input || "." || BASE64URL(signature)
//
// ACCEPT fixtures embed the spec repo's published token bytes unchanged
// (AAP-SPEC §9.7 fixtures, generated from the published test-key seeds in
// vectors/test-keys.json); CI drift-gates them against the pinned
// agent-authorization-protocol ref. REJECT fixtures are single-defect
// variants minted here with the same construction. Ed25519 signing is
// deterministic, and ML-DSA-65 signing uses the FIPS 204 deterministic
// variant with empty context (AAP-SPEC §9.7), so fixed seeds + fixed
// claims = fixed bytes. ML-DSA-65 comes from @noble/post-quantum (the
// generator's single third-party dependency, shared with the Node verifier);
// the byte-identity of its deterministic signatures with the spec repo's
// dilithium-py generator is what the spec-pin CI gate proves.
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
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

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
  if (entry.mlDsa65SeedHex) {
    // ML-DSA-65 key (RFC 9964 AKP JWK; the seed is the FIPS 204 xi input).
    const { publicKey, secretKey } = ml_dsa65.keygen(
      Buffer.from(entry.mlDsa65SeedHex, "hex"),
    );
    const wantPub = Buffer.from(entry.publicJwk.pub, "base64url");
    if (!Buffer.from(publicKey).equals(wantPub)) {
      throw new Error(`test key ${entry.kid}: seed does not derive published AKP pub`);
    }
    KEYS.set(entry.kid, { suite: "ML-DSA-65", secretKey, publicKey, jwk: entry.publicJwk });
    continue;
  }
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
  KEYS.set(entry.kid, { suite: "EdDSA", priv, pub, jwk: entry.publicJwk });
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
  // The spec repo's PQ-interop compact CGT (generate_examples.py JTI["cgt_pq"]).
  cgtPq: "b1c2d3e4f5a60718293a4b5c6d7e8f90",
  mldsa44: "4d5e6f708192a3b4c5d6e7f8091a2b3c",
  critHeader: "1a2b3c4d5e6f708192a3b4c5d6e7f809",
  dupHeader: "2b3c4d5e6f708192a3b4c5d6e7f8091a",
  missingTrustClass: "3c4d5e6f708192a3b4c5d6e7f8091a2b",
  trustClassScopeShaped: "5e6f708192a3b4c5d6e7f8091a2b3c4d",
  bacTtl: "6f708192a3b4c5d6e7f8091a2b3c4d5e",
  bacL3: "708192a3b4c5d6e7f8091a2b3c4d5e6f",
  daSuperset: "8192a3b4c5d6e7f8091a2b3c4d5e6f70",
  // The three spec-repo 0.5 fixture jtis (generate_examples.py JTI["cgt_fgc"],
  // JTI["da_fgc"], JTI["bac_session"]).
  cgtFgc: "c3d4e5f6a7b8091a2b3c4d5e6f708192",
  daFgc: "d4e5f6a7b8c9012b3c4d5e6f70819203",
  bacSession: "e5f6a7b8c9d0123c4d5e6f7081920314",
  // Fresh deterministic constants for the 0.5 reject-set and minted-ACCEPT tokens.
  critUnknownEntryType: "92a3b4c5d6e7f8091a2b3c4d5e6f7081",
  critUnsupportedClaim: "a3b4c5d6e7f8091a2b3c4d5e6f708192",
  cnfUnlisted: "b4c5d6e7f8091a2b3c4d5e6f70819203",
  daWidened: "c5d6e7f8091a2b3c4d5e6f7081920314",
  daTerminal: "d6e7f8091a2b3c4d5e6f708192031425",
  daPastTerminal: "e7f8091a2b3c4d5e6f70819203142536",
  daOutlives: "f8091a2b3c4d5e6f7081920314253647",
  cgtAuditBot: "091a2b3c4d5e6f708192031425364758",
  critNamesAbsent: "1a2b3c4d5e6f70819203142536475869",
  critEmpty: "2b3c4d5e6f7081920314253647586970",
};

// AAP-SPEC §4.4.1: entry `type` values are URIs under the family prefix.
const TYPE_URI = "https://specs.opena2a.org/aap/types/";
// A third agent, delegatee of the past-terminal-depth chain.
const AUDIT_BOT_DID = "did:opena2a:agent:acme/audit-bot";
// The delegator ATX hash carried by a DA whose delegator is reporting-bot
// (a fixture constant with the same construction as ATX_REFERENCE).
const REPORTING_BOT_ATX = "sha256:" + sha256hex("aap-conformance reporting-bot atx");

// --- JWS primitives (mirror assertion.ts exactly) ------------------------------

const b64url = (buf) => Buffer.from(buf).toString("base64url");
const compactJson = (obj) => JSON.stringify(obj);

function signRaw(kid, data) {
  const key = KEYS.get(kid);
  if (key.suite === "ML-DSA-65") {
    // FIPS 204 deterministic variant, empty context (AAP-SPEC §9.7 / RFC 9964).
    return Buffer.from(
      ml_dsa65.sign(Buffer.from(data, "utf8"), key.secretKey, { extraEntropy: false }),
    );
  }
  return cryptoSign(null, Buffer.from(data, "utf8"), key.priv);
}

function verifyRaw(kid, data, sig) {
  const key = KEYS.get(kid);
  if (key.suite === "ML-DSA-65") {
    try {
      return ml_dsa65.verify(sig, Buffer.from(data, "utf8"), key.publicKey);
    } catch {
      return false;
    }
  }
  return cryptoVerify(null, Buffer.from(data, "utf8"), key.pub, sig);
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

const compactHeader = (kid, alg = "EdDSA") => ({ alg, typ: "JWT", kid });

/** JWS General JSON Serialization (RFC 7515 §7.2.1) — AAP-SPEC §9.4.
 *  Per-entry alg defaults to the kid's suite (the hybrid profile is one EdDSA
 *  entry + one ML-DSA-65 entry over the same payload). signWithKid lets an
 *  entry declare one kid while signing with another, and tamperSig
 *  deterministically corrupts the produced signature (first byte XOR 0xff) —
 *  the every-declared-entry-MUST-verify reject fixtures. */
function mintGeneral(entries, claims) {
  const payload = b64url(compactJson(claims));
  const signatures = entries.map(({ kid, signWithKid, tamperSig }) => {
    const alg = KEYS.get(kid).suite;
    const protectedB64 = b64url(compactJson({ alg, kid }));
    const sig = signRaw(signWithKid ?? kid, `${protectedB64}.${payload}`);
    if (tamperSig) sig[0] ^= 0xff;
    const verifies = verifyRaw(kid, `${protectedB64}.${payload}`, sig);
    const shouldVerify = (!signWithKid || signWithKid === kid) && !tamperSig;
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

// --- 0.5 claim sets (AAP-SPEC §4.7, §5.5, §6.5; member order as the spec generator) --

// RFC 7638 thumbprint of an Ed25519 OKP JWK: the RFC 8037 required members
// in lexicographic order, compact JSON, SHA-256, base64url.
const jwkThumbprint = (jwk) =>
  createHash("sha256")
    .update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x }))
    .digest("base64url");

// RFC 7800 cnf bound to a presenter test key by thumbprint (jkt). The
// published thumbprint in vectors/test-keys.json must agree, or the key file
// has drifted from its seeds.
function cnfClaim(kid) {
  const entry = TEST_KEYS.keys.find((k) => k.kid === kid);
  const jkt = jwkThumbprint(entry.publicJwk);
  if (jkt !== entry.jkt) throw new Error(`test key ${kid}: published jkt does not match the derived thumbprint`);
  return { jkt };
}

// The §4.7 grant: one data entry and one budget entry.
const cgtAuthorizationDetails = () => [
  {
    type: `${TYPE_URI}data`,
    locations: ["https://api.orders.internal/orders"],
    actions: ["read"],
    fieldsAllowed: ["id", "status", "total"],
    fieldsDenied: ["customer.email"],
    labelCeiling: ["internal"],
  },
  { type: `${TYPE_URI}budget`, maxUses: 100, rate: { max: 60, windowSeconds: 60 } },
];

// The §5.5 attenuated delegation: fewer fields, a smaller budget.
const daAuthorizationDetails = () => [
  {
    type: `${TYPE_URI}data`,
    locations: ["https://api.orders.internal/orders"],
    actions: ["read"],
    fieldsAllowed: ["id", "status"],
    fieldsDenied: ["customer.email"],
    labelCeiling: ["internal"],
  },
  { type: `${TYPE_URI}budget`, maxUses: 10, rate: { max: 10, windowSeconds: 60 } },
];

// The 0.5 members sit after the baseline members and before the validity
// window (§4.7), so the baseline byte order is unchanged.
const cgtFgcClaims = (overrides = {}) => ({
  iss: BROKER_ISSUER,
  sub: AGENT_DID,
  aud: "https://api.orders.internal",
  scope: "orders.read",
  trust_class: "orders:read",
  issuer_chain: [REGISTRY_ISSUER],
  trust_level: 4,
  authorization_details: cgtAuthorizationDetails(),
  aap_crit: ["authorization_details", "cnf"],
  cnf: cnfClaim("agent-key-1"),
  iat: IAT,
  exp: IAT + 300,
  jti: JTI.cgtFgc,
  ...overrides,
});

const daFgcClaims = (overrides = {}) => ({
  iss: BROKER_ISSUER,
  sub: DELEGATEE_DID,
  aud: "https://api.orders.internal",
  scope: "orders.read",
  trust_class: "orders:read",
  issuer_chain: [REGISTRY_ISSUER],
  trust_level: 4,
  authorization_details: daAuthorizationDetails(),
  aap_crit: ["authorization_details", "cnf"],
  cnf: cnfClaim("agent-key-2"),
  act: { sub: AGENT_DID },
  max_depth: 1,
  delegator_atx: ATX_REFERENCE,
  iat: IAT,
  exp: IAT + 300,
  jti: JTI.daFgc,
  ...overrides,
});

// §6.5: the L3 attestation for a session that has admitted one `internal`
// labeled field; session_label sits after intent_verified, before iat.
const bacSessionClaims = () => ({
  iss: REGISTRY_ISSUER,
  sub: AGENT_DID,
  bac_level: 3,
  atx_reference: ATX_REFERENCE,
  binary_hash: BINARY_HASH,
  drift_score: 0.04,
  anomaly_state: "nominal",
  intent_verified: true,
  session_label: ["internal"],
  iat: IAT,
  exp: IAT + 60,
  jti: JTI.bacSession,
});

// --- presenter proof (AAP-SPEC §4.6; broker profile §6.8, A2A/MCP row) ------------

// The spec defines the proof formats per binding in prose and publishes no
// example proof, so the suite models the signed-challenge binding
// deterministically: the challenge is SHA-256 of a fixed label (32 bytes,
// above the 16-byte floor), and the proof is the presenter key's Ed25519
// signature over those challenge bytes. The proof carries the presenter's
// public JWK; a verifier binds it to the token by comparing its RFC 7638
// thumbprint with cnf.jkt and then verifying the signature under it.
function presenterProof(kid, label) {
  const challenge = createHash("sha256").update(`aap-conformance presenter challenge ${label}`).digest();
  const key = KEYS.get(kid);
  const signature = cryptoSign(null, challenge, key.priv);
  if (!cryptoVerify(null, challenge, key.pub, signature)) throw new Error(`presenter proof ${kid}: self-verify failed`);
  return {
    proof: {
      binding: "signed-challenge",
      challenge: b64url(challenge),
      jwk: key.jwk,
      signature: b64url(signature),
    },
  };
}

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
const RFC9964 = {
  id: "RFC 9964",
  ref: "https://datatracker.ietf.org/doc/html/rfc9964",
  section: "ML-DSA for JOSE and COSE (the ML-DSA-65 alg and AKP key type)",
};
const RFC9396 = {
  id: "RFC 9396",
  ref: "https://datatracker.ietf.org/doc/html/rfc9396",
  section: "OAuth 2.0 Rich Authorization Requests (the authorization_details claim)",
};
const RFC7800 = {
  id: "RFC 7800",
  ref: "https://datatracker.ietf.org/doc/html/rfc7800",
  section: "Proof-of-Possession Key Semantics for JWTs (the cnf claim)",
};
const RFC7638 = {
  id: "RFC 7638",
  ref: "https://datatracker.ietf.org/doc/html/rfc7638",
  section: "JSON Web Key (JWK) Thumbprint (the jkt confirmation method, RFC 9449 §6.1)",
};
const BROKER_PROFILE_6_8 = {
  id: "AAP-BROKER-PROFILE",
  ref: "https://github.com/opena2a-standards/agent-authorization-protocol/blob/main/AAP-BROKER-PROFILE.md",
  section: "§6.8 Presentation binding (signed challenge)",
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
// The two spec-repo PQ tokens (byte-identical to examples/tokens/
// cgt-v1.mldsa65.jwt and cgt-v1.hybrid.general.json at the pinned ref).
const CGT_MLDSA65_TOKEN = mintCompact(
  "broker-pqc-1",
  compactHeader("broker-pqc-1", "ML-DSA-65"),
  cgtClaims({ jti: JTI.cgtPq }),
);
const CGT_HYBRID = mintGeneral(
  [{ kid: "broker-key-1" }, { kid: "broker-pqc-1" }],
  cgtClaims(),
);
// The three spec-repo 0.5 tokens (byte-identical to examples/tokens/
// cgt-v1.fgc.jwt, da-v1.fgc.jwt and bac-v1.session.jwt at the pinned ref).
const CGT_FGC_TOKEN = mintCompact("broker-key-1", compactHeader("broker-key-1"), cgtFgcClaims());
const DA_FGC_TOKEN = mintCompact("broker-key-1", compactHeader("broker-key-1"), daFgcClaims());
const BAC_SESSION_TOKEN = mintCompact("registry-key-1", compactHeader("registry-key-1"), bacSessionClaims());
// A terminal delegation (max_depth 0, §5.3). The spec repo publishes no
// depth-0 example, so this token is minted here with the §5.3 claim set.
const DA_TERMINAL_TOKEN = mintCompact(
  "broker-key-1",
  compactHeader("broker-key-1"),
  daClaims({ max_depth: 0, jti: JTI.daTerminal }),
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

fixture("cgt-mldsa65-compact-valid", {
  description:
    "The spec repo's generated PQ-interop CGT (examples/tokens/cgt-v1.mldsa65.jwt): a compact ML-DSA-65 JWT (RFC 9964 suite, FIPS 204 deterministic signature, empty context) with the §4.2 claim shape and its own jti, signed by broker-pqc-1 (RFC 9964 AKP test key). Verifier MUST ACCEPT.",
  fixtureType: "cgt",
  tokenForm: "compact",
  spec: [ref("§9.3 Compact Serialization (PQ-interop lane)"), ref("§9.5 Suite Registry (v1)"), ref("§8.2 Cryptographic Agility"), RFC7515, RFC9964],
  verifierState: state(["broker-pqc-1"]),
  expected: { verifyResult: "ACCEPT" },
  schemaValid: true,
  headerSchemaValid: true,
  token: CGT_MLDSA65_TOKEN,
});

fixture("cgt-hybrid-general-valid", {
  description:
    "The spec repo's generated hybrid CGT (examples/tokens/cgt-v1.hybrid.general.json): the §4.2 claim set as JWS General JSON Serialization with one Ed25519 entry (broker-key-1) and one ML-DSA-65 entry (broker-pqc-1) over the same payload — the §8.2 hybrid post-quantum profile. Both declared entries verify and both suite families are present. Verifier MUST ACCEPT.",
  fixtureType: "cgt",
  tokenForm: "general",
  spec: [ref("§9.4 Multi-Signature Form (hybrid profile)"), ref("§8.2 Cryptographic Agility"), RFC7515, RFC8032, RFC9964],
  // Path policy (§8.2): this path requires both families; the token carries both.
  verifierState: { ...state(["broker-key-1", "broker-pqc-1"]), requiredSuites: ["EdDSA", "ML-DSA-65"] },
  expected: { verifyResult: "ACCEPT" },
  schemaValid: true,
  tokenGeneral: CGT_HYBRID,
});

fixture("cgt-compact-fgc-valid", {
  description:
    "The spec repo's generated 0.5 CGT (examples/tokens/cgt-v1.fgc.jwt, AAP-SPEC §4.7): the §4.2 claim set plus authorization_details (one data entry, one budget entry, registry-URI types), aap_crit naming both mandatory-to-understand claims, and cnf bound by RFC 7638 thumbprint (jkt) to the presenter test key agent-key-1. The presentation carries agent-key-1's signed-challenge proof, so the presenter binding of §4.6 holds. Verifier MUST ACCEPT.",
  fixtureType: "cgt",
  tokenForm: "compact",
  spec: [ref("§4.7 Example with authorization details"), ref("§4.4 Authorization details"), ref("§4.5 Mandatory to understand claims"), ref("§4.6 Proof of possession"), BROKER_PROFILE_6_8, RFC9396, RFC7800, RFC7638],
  verifierState: state(["broker-key-1"]),
  presentation: presenterProof("agent-key-1", JTI.cgtFgc),
  expected: { verifyResult: "ACCEPT" },
  schemaValid: true,
  headerSchemaValid: true,
  token: CGT_FGC_TOKEN,
});

fixture("da-compact-fgc-valid", {
  description:
    "The spec repo's generated 0.5 DA (examples/tokens/da-v1.fgc.jwt, AAP-SPEC §5.5): orders-reader delegates to reporting-bot with fewer fields (fieldsAllowed id, status) and a smaller budget (maxUses 10, rate.max 10) than the §4.7 grant, which the delegation context carries as the delegator token. Every entry is narrower than or equal to a delegator entry of the same type (§5.4), scope and trust_class are equal, max_depth 1, and cnf binds the delegatee's presenter key agent-key-2, whose signed-challenge proof is presented. Verifier MUST ACCEPT.",
  fixtureType: "da",
  tokenForm: "compact",
  spec: [ref("§5.5 Example of an attenuated delegation"), ref("§5.4 Attenuation"), ref("§5.3 Assertion Form"), ref("§4.6 Proof of possession"), BROKER_PROFILE_6_8, RFC9396, RFC7800],
  verifierState: state(["broker-key-1"]),
  delegation: { delegatorToken: CGT_FGC_TOKEN },
  presentation: presenterProof("agent-key-2", JTI.daFgc),
  expected: { verifyResult: "ACCEPT" },
  schemaValid: true,
  headerSchemaValid: true,
  token: DA_FGC_TOKEN,
});

fixture("bac-compact-session-valid", {
  description:
    "The spec repo's generated 0.5 BAC (examples/tokens/bac-v1.session.jwt, AAP-SPEC §6.5): the L3 attestation carrying session_label [internal] — the set of labels the session has admitted so far (§4.4.2) — with the 60-second window unchanged. Verifier MUST ACCEPT.",
  fixtureType: "bac",
  tokenForm: "compact",
  spec: [ref("§6.5 Example with a session label"), ref("§6.4 Claim Set (session_label, L3 only)"), ref("§4.4.2 Label semantics")],
  verifierState: state(["registry-key-1"]),
  expected: { verifyResult: "ACCEPT" },
  schemaValid: true,
  headerSchemaValid: true,
  token: BAC_SESSION_TOKEN,
});

fixture("da-compact-terminal-depth-zero", {
  description:
    "A DA with max_depth 0 — a terminal delegation (§5.3: max_depth is an integer >= 0 and 0 is expressible; the 0.5 da-claims-v1 schema lowers the floor from 1 to 0). Delegator is the spec repo's cgt-v1.jwt; scope and trust_class are equal and the validity window is the delegator's. Minted here (the spec repo publishes no depth-0 example). A verifier that still floors max_depth at 1 wrongly rejects it. Verifier MUST ACCEPT.",
  fixtureType: "da",
  tokenForm: "compact",
  spec: [ref("§5.3 Assertion Form (max_depth >= 0; 0 is a terminal delegation)"), ref("§5.2 Constraints")],
  verifierState: state(["broker-key-1"]),
  delegation: { delegatorToken: CGT_TOKEN },
  expected: { verifyResult: "ACCEPT" },
  schemaValid: true,
  headerSchemaValid: true,
  token: DA_TERMINAL_TOKEN,
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

fixture("cgt-hybrid-mldsa-bad-signature", {
  description:
    "The hybrid CGT with the Ed25519 entry verifying and the ML-DSA-65 entry carrying a deterministically corrupted signature (first byte flipped). §9.4: every declared entry MUST verify — accepting the classical half alone silently drops the post-quantum half of a hybrid credential. Verifier MUST REJECT with BAD_SIGNATURE.",
  fixtureType: "cgt",
  tokenForm: "general",
  spec: [ref("§9.4 Multi-Signature Form (every declared entry MUST verify)"), ref("§8.2 Cryptographic Agility"), RFC9964],
  verifierState: state(["broker-key-1", "broker-pqc-1"]),
  expected: { verifyResult: "REJECT", rejectCategory: "BAD_SIGNATURE", reasonContains: "signature" },
  schemaValid: true,
  tokenGeneral: mintGeneral(
    [{ kid: "broker-key-1" }, { kid: "broker-pqc-1", tamperSig: true }],
    cgtClaims(),
  ),
});

fixture("cgt-hybrid-ed25519-bad-signature", {
  description:
    "The hybrid CGT with the ML-DSA-65 entry verifying and the Ed25519 entry declaring kid broker-key-1 but carrying a signature produced by broker-key-2. The post-quantum half alone MUST NOT carry the token: every declared entry verifies or the token rejects (§9.4). Verifier MUST REJECT with BAD_SIGNATURE.",
  fixtureType: "cgt",
  tokenForm: "general",
  spec: [ref("§9.4 Multi-Signature Form (every declared entry MUST verify)"), ref("§8.2 Cryptographic Agility"), RFC8032, RFC9964],
  verifierState: state(["broker-key-1", "broker-pqc-1"]),
  expected: { verifyResult: "REJECT", rejectCategory: "BAD_SIGNATURE", reasonContains: "signature" },
  schemaValid: true,
  tokenGeneral: mintGeneral(
    [{ kid: "broker-key-1", signWithKid: "broker-key-2" }, { kid: "broker-pqc-1" }],
    cgtClaims(),
  ),
});

fixture("cgt-hybrid-missing-ed25519", {
  description:
    "A general-form CGT carrying ONLY an ML-DSA-65 entry (which verifies). A general-form token that declares any ML-DSA-65 entry is on the §8.2 hybrid profile and MUST carry at least one Ed25519 entry and at least one ML-DSA-65 entry — a stripped hybrid MUST NOT degrade to single-family acceptance (§9.4). Verifier MUST REJECT with HYBRID_INCOMPLETE.",
  fixtureType: "cgt",
  tokenForm: "general",
  spec: [ref("§9.4 Multi-Signature Form (hybrid family gate)"), ref("§8.2 Cryptographic Agility"), RFC9964],
  verifierState: state(["broker-key-1", "broker-pqc-1"]),
  expected: { verifyResult: "REJECT", rejectCategory: "HYBRID_INCOMPLETE", reasonContains: "ed25519" },
  schemaValid: true,
  tokenGeneral: mintGeneral([{ kid: "broker-pqc-1" }], cgtClaims()),
});

fixture("cgt-mldsa44-compact-unknown-alg", {
  description:
    "A compact CGT whose protected header declares alg ML-DSA-44 — registered for JOSE by RFC 9964 but absent from the AAP §9.5 registry (only ML-DSA-65 is). The signature is a real ML-DSA-65 signature over these exact bytes; the verifier MUST reject the unregistered suite at the header stage rather than downgrade or guess (§8.2). Verifier MUST REJECT with UNKNOWN_ALG.",
  fixtureType: "cgt",
  tokenForm: "compact",
  spec: [ref("§9.5 Suite Registry (v1)"), ref("§8.2 Cryptographic Agility (no silent downgrade)"), RFC9964],
  verifierState: state(["broker-pqc-1"]),
  expected: { verifyResult: "REJECT", rejectCategory: "UNKNOWN_ALG", reasonContains: "ML-DSA-44" },
  schemaValid: true,
  headerSchemaValid: false,
  token: mintCompact(
    "broker-pqc-1",
    { alg: "ML-DSA-44", typ: "JWT", kid: "broker-pqc-1" },
    cgtClaims({ jti: JTI.mldsa44 }),
  ),
});

fixture("cgt-compact-replayed", {
  description:
    "The spec repo's cgt-v1.jwt presented TWICE to the same verifier (presentations: 2). §8.1: receivers MUST track used jti values for the token's TTL window and MUST reject a repeated identifier. The first presentation is accepted; the expected verdict pins the second. Verifier MUST REJECT with REPLAYED_JTI.",
  fixtureType: "cgt",
  tokenForm: "compact",
  spec: [ref("§8.1 Replay Prevention"), ref("§4.2 Token Structure")],
  verifierState: state(["broker-key-1"]),
  presentations: 2,
  expected: { verifyResult: "REJECT", rejectCategory: "REPLAYED_JTI", reasonContains: "jti" },
  schemaValid: true,
  headerSchemaValid: true,
  token: CGT_TOKEN,
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

// -------- REJECT: AAP-SPEC 0.5 (§4.4-§4.6, §5.3-§5.4, §9.4 path policy) ---------

fixture("cgt-compact-crit-unknown-entry-type", {
  description:
    "The §4.7 CGT claim set with the data entry's type replaced by https://specs.opena2a.org/aap/types/payment — a type absent from the §4.4.1 entry type registry — while aap_crit names authorization_details. §4.4.1: a verifier that meets an entry type it does not implement MUST reject the token, because an unknown type inside a mandatory-to-understand claim is not understood. The signature, the presenter proof (agent-key-1) and every other member are valid; the entry type is the sole defect. Verifier MUST REJECT with CRIT_NOT_UNDERSTOOD.",
  fixtureType: "cgt",
  tokenForm: "compact",
  spec: [ref("§4.4.1 Entry type registry (unknown type MUST reject)"), ref("§4.5 Mandatory to understand claims"), RFC9396],
  verifierState: state(["broker-key-1"]),
  presentation: presenterProof("agent-key-1", JTI.critUnknownEntryType),
  expected: { verifyResult: "REJECT", rejectCategory: "CRIT_NOT_UNDERSTOOD", reasonContains: "payment" },
  schemaValid: true,
  headerSchemaValid: true,
  token: (() => {
    const details = cgtAuthorizationDetails();
    details[0].type = `${TYPE_URI}payment`;
    return mintCompact(
      "broker-key-1",
      compactHeader("broker-key-1"),
      cgtFgcClaims({ authorization_details: details, jti: JTI.critUnknownEntryType }),
    );
  })(),
});

fixture("cgt-compact-crit-unsupported-claim", {
  description:
    "The §4.7 CGT claim set plus a private claim x_tenant, with aap_crit naming authorization_details, cnf and x_tenant. §4.5: a verifier that encounters a name in aap_crit that it does not implement MUST reject the token — the reference verifiers implement authorization_details and cnf as mandatory to understand and nothing else. The claim set is schema-valid (unknown claims are optional to ignore unless named in aap_crit, §9.6), the signature and the presenter proof are valid; the unsupported aap_crit name is the sole defect. Verifier MUST REJECT with CRIT_NOT_UNDERSTOOD.",
  fixtureType: "cgt",
  tokenForm: "compact",
  spec: [ref("§4.5 Mandatory to understand claims"), ref("§9.6 Claim Conventions (unknown claims)")],
  verifierState: state(["broker-key-1"]),
  presentation: presenterProof("agent-key-1", JTI.critUnsupportedClaim),
  expected: { verifyResult: "REJECT", rejectCategory: "CRIT_NOT_UNDERSTOOD", reasonContains: "x_tenant" },
  schemaValid: true,
  headerSchemaValid: true,
  token: (() => {
    const claims = cgtFgcClaims({ aap_crit: ["authorization_details", "cnf", "x_tenant"], jti: JTI.critUnsupportedClaim });
    // x_tenant sits with the 0.5 members, before the validity window.
    const { iat, exp, jti, ...head } = claims;
    return mintCompact("broker-key-1", compactHeader("broker-key-1"), { ...head, x_tenant: "acme", iat, exp, jti });
  })(),
});

fixture("cgt-compact-cnf-unlisted", {
  description:
    "The §4.7 CGT claim set with aap_crit naming only authorization_details while cnf is present. §4.5: cnf MUST be listed whenever it is present, because a verifier that ignores cnf accepts the token as a bearer token — the downgrade §4.6 exists to prevent. The signature and the presenter proof (agent-key-1) are valid; the missing aap_crit entry is the sole defect. Verifier MUST REJECT with CRIT_UNLISTED.",
  fixtureType: "cgt",
  tokenForm: "compact",
  spec: [ref("§4.5 Mandatory to understand claims (cnf MUST be listed)"), ref("§4.6 Proof of possession"), ref("§8.6 Presentation is not possession")],
  verifierState: state(["broker-key-1"]),
  presentation: presenterProof("agent-key-1", JTI.cnfUnlisted),
  expected: { verifyResult: "REJECT", rejectCategory: "CRIT_UNLISTED", reasonContains: "cnf" },
  schemaValid: true,
  headerSchemaValid: true,
  token: mintCompact(
    "broker-key-1",
    compactHeader("broker-key-1"),
    cgtFgcClaims({ aap_crit: ["authorization_details"], jti: JTI.cnfUnlisted }),
  ),
});

fixture("cgt-compact-cnf-mismatch", {
  description:
    "Byte-identical to cgt-compact-fgc-valid (the spec repo's cgt-v1.fgc.jwt, cnf bound to agent-key-1); only the presentation differs — the signed-challenge proof is produced by agent-key-2, whose RFC 7638 thumbprint is not the token's cnf.jkt. §4.6: a verifier that receives a token with cnf MUST verify the presenter's proof against the bound key and MUST reject the token otherwise. The token signature is valid; the presenter binding is the sole defect. Verifier MUST REJECT with CNF_MISMATCH.",
  fixtureType: "cgt",
  tokenForm: "compact",
  spec: [ref("§4.6 Proof of possession"), ref("§8.6 Presentation is not possession"), BROKER_PROFILE_6_8, RFC7800, RFC7638],
  verifierState: state(["broker-key-1"]),
  presentation: presenterProof("agent-key-2", JTI.cgtFgc),
  expected: { verifyResult: "REJECT", rejectCategory: "CNF_MISMATCH", reasonContains: "cnf" },
  schemaValid: true,
  headerSchemaValid: true,
  token: CGT_FGC_TOKEN,
});

fixture("da-compact-authorization-details-widened", {
  description:
    "The §5.5 DA claim set with the data entry's fieldsAllowed widened to [id, status, total, customer.name] against the §4.7 delegator grant, whose data entry allows [id, status, total]. §5.4: fieldsAllowed is an allow set member, so the delegatee's set MUST be a subset of the delegator's; an entry with no delegator entry it is narrower than or equal to makes the DA invalid. Scope, trust_class, the budget entry, max_depth and the presenter proof (agent-key-2) are all valid; the widened allow set is the sole defect. Verifier MUST REJECT with NOT_ATTENUATED.",
  fixtureType: "da",
  tokenForm: "compact",
  spec: [ref("§5.4 Attenuation (allow set members)"), ref("§5.3 Assertion Form"), ref("§5.1 Purpose (scope cannot exceed the delegator's)")],
  verifierState: state(["broker-key-1"]),
  delegation: { delegatorToken: CGT_FGC_TOKEN },
  presentation: presenterProof("agent-key-2", JTI.daWidened),
  expected: { verifyResult: "REJECT", rejectCategory: "NOT_ATTENUATED", reasonContains: "fieldsAllowed" },
  schemaValid: true,
  headerSchemaValid: true,
  token: (() => {
    const details = daAuthorizationDetails();
    details[0].fieldsAllowed = ["id", "status", "total", "customer.name"];
    return mintCompact(
      "broker-key-1",
      compactHeader("broker-key-1"),
      daFgcClaims({ authorization_details: details, jti: JTI.daWidened }),
    );
  })(),
});

fixture("da-compact-past-terminal-depth", {
  description:
    "A DA delegated FROM a terminal delegation: the delegator token is the depth-0 DA of da-compact-terminal-depth-zero (reporting-bot, max_depth 0), and this DA delegates onward to audit-bot with act nesting the chain (act.sub reporting-bot, act.act.sub orders-reader) and max_depth 0. §5.3: max_depth is the remaining delegation depth below an assertion and 0 is terminal, so no delegation below it is permitted. Scope, trust_class and the validity window equal the delegator's; the depth is the sole defect. Verifier MUST REJECT with NOT_ATTENUATED.",
  fixtureType: "da",
  tokenForm: "compact",
  spec: [ref("§5.3 Assertion Form (max_depth: 0 is a terminal delegation)"), ref("§5.4 Attenuation (checked link by link)"), { id: "RFC 8693", ref: "https://datatracker.ietf.org/doc/html/rfc8693", section: "§4.1 (nested act)" }],
  verifierState: state(["broker-key-1"]),
  delegation: { delegatorToken: DA_TERMINAL_TOKEN },
  expected: { verifyResult: "REJECT", rejectCategory: "NOT_ATTENUATED", reasonContains: "max_depth" },
  schemaValid: true,
  headerSchemaValid: true,
  token: mintCompact(
    "broker-key-1",
    compactHeader("broker-key-1"),
    daClaims({
      sub: AUDIT_BOT_DID,
      act: { sub: DELEGATEE_DID, act: { sub: AGENT_DID } },
      max_depth: 0,
      delegator_atx: REPORTING_BOT_ATX,
      jti: JTI.daPastTerminal,
    }),
  ),
});

fixture("da-compact-outlives-delegator", {
  description:
    "The §5.5 DA claim set with exp = iat + 600, later than the delegator's exp = iat + 300 (the §4.7 grant, carried as the delegator token). §5.4: a DA can only carry less than the delegator's grant, and iat/exp are the token's validity window (§4.2), so a DA that outlives its delegator carries authority after the delegator's has lapsed. The pinned clock (iat + 30) is inside both windows, the signature, the presenter proof (agent-key-2), scope, trust_class, authorization_details and max_depth are all valid; the later exp is the sole defect. Verifier MUST REJECT with NOT_ATTENUATED.",
  fixtureType: "da",
  tokenForm: "compact",
  spec: [ref("§5.4 Attenuation (a DA carries less than the delegator's grant)"), ref("§4.2 Token Structure (iat/exp: the validity window)"), ref("§5.3 Assertion Form")],
  verifierState: state(["broker-key-1"]),
  delegation: { delegatorToken: CGT_FGC_TOKEN },
  presentation: presenterProof("agent-key-2", JTI.daOutlives),
  expected: { verifyResult: "REJECT", rejectCategory: "NOT_ATTENUATED", reasonContains: "exp" },
  schemaValid: true,
  headerSchemaValid: true,
  token: mintCompact(
    "broker-key-1",
    compactHeader("broker-key-1"),
    daFgcClaims({ exp: IAT + 600, jti: JTI.daOutlives }),
  ),
});

fixture("da-compact-delegator-mismatch", {
  description:
    "The spec repo's da-v1.fgc.jwt unchanged (act.sub orders-reader), presented with a delegator token that is NOT its delegator: a CGT minted here for audit-bot carrying the same scope, trust_class and authorization_details as the §4.7 grant. §5.3 defines act as the delegating agent ({sub: delegator DID}) and §5.4 checks each DA against its immediate delegator, so a supplied token whose sub is not the DA's act.sub is not that delegator and re-checks nothing. Both tokens carry valid signatures and schema-valid claims, the presenter proof (agent-key-2) is valid, and every attenuation member would pass against this grant; the linkage is the sole defect. Verifier MUST REJECT with DELEGATOR_INVALID.",
  fixtureType: "da",
  tokenForm: "compact",
  spec: [ref("§5.3 Assertion Form (act: the delegating agent)"), ref("§5.4 Attenuation (each DA against its immediate delegator)"), { id: "RFC 8693", ref: "https://datatracker.ietf.org/doc/html/rfc8693", section: "§4.1 (act)" }],
  verifierState: state(["broker-key-1"]),
  delegation: {
    delegatorToken: mintCompact(
      "broker-key-1",
      compactHeader("broker-key-1"),
      cgtFgcClaims({ sub: AUDIT_BOT_DID, jti: JTI.cgtAuditBot }),
    ),
  },
  presentation: presenterProof("agent-key-2", JTI.daFgc),
  expected: { verifyResult: "REJECT", rejectCategory: "DELEGATOR_INVALID", reasonContains: "act.sub" },
  schemaValid: true,
  headerSchemaValid: true,
  token: DA_FGC_TOKEN,
});

fixture("cgt-compact-crit-names-absent-claim", {
  description:
    "The §4.7 CGT claim set without cnf, while aap_crit still names authorization_details and cnf. §4.5: a verifier MUST reject a token whose aap_crit names a claim that is not present in the token (the vendored schema marks this a verifier check, so the claim set is schema-valid). No presentation is carried because the token binds no presenter. The signature and every other member are valid; the absent named claim is the sole defect. Verifier MUST REJECT with CRIT_NOT_UNDERSTOOD.",
  fixtureType: "cgt",
  tokenForm: "compact",
  spec: [ref("§4.5 Mandatory to understand claims (aap_crit MUST NOT name an absent claim)")],
  verifierState: state(["broker-key-1"]),
  expected: { verifyResult: "REJECT", rejectCategory: "CRIT_NOT_UNDERSTOOD", reasonContains: "no such claim" },
  schemaValid: true,
  headerSchemaValid: true,
  token: (() => {
    const claims = cgtFgcClaims({ jti: JTI.critNamesAbsent });
    delete claims.cnf;
    return mintCompact("broker-key-1", compactHeader("broker-key-1"), claims);
  })(),
});

fixture("cgt-compact-crit-empty", {
  description:
    "The §4.2 baseline CGT claim set plus aap_crit: [] and nothing else. §4.5: a verifier MUST reject a token whose aap_crit is present but empty; the vendored cgt-claims-v1 schema pins it as minItems 1, so the claim set is schema-invalid. The signature is valid; the empty array is the sole defect. Verifier MUST REJECT with CLAIM_SCHEMA.",
  fixtureType: "cgt",
  tokenForm: "compact",
  spec: [ref("§4.5 Mandatory to understand claims (aap_crit present but empty)"), ref("§4.2 Token Structure")],
  verifierState: state(["broker-key-1"]),
  expected: { verifyResult: "REJECT", rejectCategory: "CLAIM_SCHEMA", reasonContains: "aap_crit" },
  schemaValid: false,
  headerSchemaValid: true,
  token: (() => {
    // aap_crit sits where the 0.5 members sit (§4.7): before the validity window.
    const { iat, exp, jti, ...head } = cgtClaims({ jti: JTI.critEmpty });
    return mintCompact("broker-key-1", compactHeader("broker-key-1"), { ...head, aap_crit: [], iat, exp, jti });
  })(),
});

fixture("cgt-compact-cnf-no-proof", {
  description:
    "Byte-identical to cgt-compact-fgc-valid (the spec repo's cgt-v1.fgc.jwt, cnf bound to agent-key-1) presented with NO presenter proof (no presentation member). §4.6: a verifier that receives a token with cnf MUST verify the presenter's proof against the bound key and MUST reject the token otherwise — a verifier that treats a missing proof as nothing to verify accepts the token as a bearer token, the downgrade §4.5 lists cnf to prevent. The token signature is valid; the absent proof is the sole defect. Verifier MUST REJECT with CNF_MISMATCH.",
  fixtureType: "cgt",
  tokenForm: "compact",
  spec: [ref("§4.6 Proof of possession (MUST reject the token otherwise)"), ref("§8.6 Presentation is not possession"), BROKER_PROFILE_6_8, RFC7800],
  verifierState: state(["broker-key-1"]),
  expected: { verifyResult: "REJECT", rejectCategory: "CNF_MISMATCH", reasonContains: "proof" },
  schemaValid: true,
  headerSchemaValid: true,
  token: CGT_FGC_TOKEN,
});

fixture("cgt-hybrid-missing-mldsa65", {
  description:
    "The spec repo's hybrid CGT (cgt-v1.hybrid.general.json) with its declared ML-DSA-65 entry stripped: the payload and the Ed25519 entry (broker-key-1) are the published bytes unchanged, and that entry verifies. The verifier's path policy (verifierState.requiredSuites) pins the §8.2 hybrid profile for this path — EdDSA and ML-DSA-65 — and §9.4 requires every declared entry to verify: a hybrid token stripped to one family MUST NOT degrade to single-family acceptance. Without the policy an Ed25519-only general-form token is a legal co-signature form, so the policy is what makes the stripped entry visible. Verifier MUST REJECT with HYBRID_INCOMPLETE.",
  fixtureType: "cgt",
  tokenForm: "general",
  spec: [ref("§9.4 Multi-Signature Form (family signature gate)"), ref("§8.2 Cryptographic Agility (no fallback to classical-only on a hybrid path)"), RFC8032, RFC9964],
  verifierState: { ...state(["broker-key-1", "broker-pqc-1"]), requiredSuites: ["EdDSA", "ML-DSA-65"] },
  expected: { verifyResult: "REJECT", rejectCategory: "HYBRID_INCOMPLETE", reasonContains: "ML-DSA-65" },
  schemaValid: true,
  tokenGeneral: { payload: CGT_HYBRID.payload, signatures: [CGT_HYBRID.signatures[0]] },
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
