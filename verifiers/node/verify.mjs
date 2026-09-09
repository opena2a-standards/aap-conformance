#!/usr/bin/env node
// Reference Node.js verifier for aap-conformance fixtures.
// Node stdlib plus exactly one third-party dependency: @noble/post-quantum
// for ML-DSA-65 (FIPS 204 / RFC 9964) — Ed25519 verification stays on
// node:crypto/OpenSSL. Runs on Node ≥ 18 (`npm install` first).
//
// Node is one half of the deliberate verifier pair: the AAP reference broker
// (Secretless) is TypeScript, so this verifier exercises the same JOSE
// primitives (node:crypto Ed25519 + noble ML-DSA-65 over the JWS Signing
// Input) the reference mints with.
//
// Check order is pinned and MUST match verifiers/python/verify.py exactly —
// the parity gate compares reject categories, so both implementations must
// discover the same defect first:
//
//   MALFORMED_TOKEN > MALFORMED_HEADER > UNKNOWN_HEADER_PARAM > UNKNOWN_ALG >
//   UNKNOWN_KEY > BAD_SIGNATURE > HYBRID_INCOMPLETE > MALFORMED_PAYLOAD >
//   CLAIM_SCHEMA > CRIT_UNLISTED > CRIT_NOT_UNDERSTOOD > EXPIRED > TTL_WINDOW >
//   CNF_MISMATCH > (DELEGATOR_INVALID >) SCOPE_NOT_SUBSET > NOT_ATTENUATED >
//   REPLAYED_JTI
//
// HYBRID_INCOMPLETE sits after BAD_SIGNATURE: the family gate (AAP-SPEC §9.4:
// every declared entry verifies; a general-form token declaring any ML-DSA-65
// entry MUST carry ≥1 Ed25519 AND ≥1 ML-DSA-65 entry; a suite the verifier's
// path policy requires — verifierState.requiredSuites, §8.2 — MUST be present,
// so a stripped declared entry cannot degrade the token) is judged only once
// every declared entry verifies.
// CRIT_UNLISTED / CRIT_NOT_UNDERSTOOD (§4.5 mandatory-to-understand claims)
// follow the claim-form checks: a mandatory-to-understand claim that is present
// but not named in aap_crit is CRIT_UNLISTED; an aap_crit name this verifier
// does not implement, a name naming no claim in the token, or an
// authorization_details entry type outside the §4.4.1 registry is
// CRIT_NOT_UNDERSTOOD. CNF_MISMATCH (§4.6 proof of possession) is judged for an
// otherwise-valid token against the presenter proof the fixture carries.
// NOT_ATTENUATED (§5.3/§5.4) covers the delegation members beyond the scope
// string: trust_class, the validity window, authorization_details under the
// narrower-than-or-equal-to relation, and max_depth (including delegating past
// a terminal, depth-0 delegator).
// REPLAYED_JTI is last: replay is only decidable for an otherwise-acceptable
// token (§8.1; a fixture presents the same token `presentations` times to one
// verifier, and the expected verdict pins the final presentation).
//
// Fixture inputs beyond the token: verifierState.keys (trusted signing keys),
// verifierState.clockNumericDate, verifierState.requiredSuites (path policy,
// general form), delegation.delegatorToken (the immediate delegator's CGT or
// DA, for the §5.3/§5.4 re-check), presentation.proof (the presenter's
// signed-challenge proof for cnf: broker profile §6.8, A2A/MCP row).
//
// Parsing rules (AAP-SPEC §9.2, and the atx-conformance duplicate-key lesson):
//   - the protected header is STRICT-parsed: duplicate members at any depth
//     are MALFORMED_HEADER (v1 headers are closed; duplicates are the
//     last-wins/first-wins smuggling split of RFC 8259 §4)
//   - the claim set parses with standard last-wins JSON semantics, which
//     RFC 7519 §4 permits; JSON.parse and Python json.loads agree natively
//
// Usage:  node verify.mjs <fixture.json | directory> [...]
// Exit code: 0 if every fixture's expected verdict (and reject category,
// when pinned) is met, else 1.

import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join } from "node:path";
import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

const B64URL_RE = /^[A-Za-z0-9_-]+$/;
const DID_RE = /^did:/;
const JTI_RE = /^[0-9a-f]{32}$/;
const TRUST_CLASS_RE = /^[a-z0-9_-]+:[a-z0-9_-]+$/;
const SHA256_REF_RE = /^sha256:[0-9a-f]{64}$/;
// AAP-SPEC §9.5: EdDSA (RFC 8037) + ML-DSA-65 (FIPS 204, JOSE registration
// RFC 9964). ML-DSA-44/87, though JOSE-registered, are NOT in the AAP registry.
const SUITE_REGISTRY = ["EdDSA", "ML-DSA-65"];
const BAC_TTL_SECONDS = 60; // AAP-SPEC §6.1

// AAP-SPEC §4.4.1: the wire value of an authorization_details entry `type` is
// the registry URI; the short name is the registry key.
const TYPE_URI_PREFIX = "https://specs.opena2a.org/aap/types/";
const TYPE_URI_RE = /^https:\/\/specs\.opena2a\.org\/aap\/types\/[a-z_]+$/;
// RFC 7638 thumbprint as registered for cnf by RFC 9449 §6.1 (43 base64url chars).
const JKT_RE = /^[A-Za-z0-9_-]{43}$/;
const DECIMAL_RE = /^[0-9]+(\.[0-9]+)?$/;
const CURRENCY_RE = /^[A-Z]{3}$/;
// The claims this verifier implements as mandatory-to-understand (§4.5). Any
// other name in aap_crit is not understood and rejects the token.
const UNDERSTOOD_CRIT = ["authorization_details", "cnf"];
// §4.4.1 entry type registry: short name -> members that are MUST for the type.
// budget is MUST-one-of (BUDGET_MEMBERS) and is checked separately.
const ENTRY_TYPES = {
  mcp_tool: ["serverId", "tools"],
  skill: ["identifier", "version", "contentHash"],
  peer_agent: ["peerDid", "direction", "subDelegationDepth"],
  model: ["endpoint"],
  network: ["destinations", "tlsRequired"],
  data: ["locations", "actions"],
  budget: [],
};
const BUDGET_MEMBERS = ["spend", "rate", "maxUses", "concurrency", "tokenCap"];
// §5.4 member kinds of the narrower-than-or-equal-to relation.
const IDENTITY_MEMBERS = ["serverId", "serverAtx", "identifier", "version", "contentHash", "schemaHash", "peerDid", "endpoint"];
const ALLOW_SET_MEMBERS = ["locations", "actions", "datatypes", "privileges", "tools", "models", "destinations", "direction", "fieldsAllowed", "labelCeiling", "egressCeiling"];
const CEILING_MEMBERS = ["labelCeiling", "egressCeiling"]; // absent means the empty set
const DENY_SET_MEMBERS = ["fieldsDenied"];
const FLAG_MEMBERS = ["tlsRequired", "requiresApproval"];

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

// --- strict JSON (protected headers only) -------------------------------------

// Minimal recursive-descent JSON parser that rejects duplicate object members
// at any depth. JSON.parse silently keeps the last duplicate, which is exactly
// the divergence the duplicate-header fixture pins.
function parseStrictJson(text) {
  let i = 0;
  const fail = (msg) => {
    throw new Error(msg);
  };
  const ws = () => {
    while (i < text.length && " \t\n\r".includes(text[i])) i++;
  };
  function parseString() {
    if (text[i] !== '"') fail("expected string");
    let j = i + 1;
    while (j < text.length && text[j] !== '"') {
      if (text[j] === "\\") j++;
      j++;
    }
    if (j >= text.length) fail("unterminated string");
    const s = JSON.parse(text.slice(i, j + 1));
    i = j + 1;
    return s;
  }
  function parseObject() {
    i++; // consume {
    const obj = {};
    const seen = new Set();
    ws();
    if (text[i] === "}") {
      i++;
      return obj;
    }
    for (;;) {
      ws();
      const key = parseString();
      if (seen.has(key)) fail(`duplicate member "${key}"`);
      seen.add(key);
      ws();
      if (text[i] !== ":") fail("expected ':'");
      i++;
      obj[key] = parseValue();
      ws();
      if (text[i] === ",") {
        i++;
        continue;
      }
      if (text[i] === "}") {
        i++;
        return obj;
      }
      fail("expected ',' or '}'");
    }
  }
  function parseArray() {
    i++; // consume [
    const arr = [];
    ws();
    if (text[i] === "]") {
      i++;
      return arr;
    }
    for (;;) {
      arr.push(parseValue());
      ws();
      if (text[i] === ",") {
        i++;
        continue;
      }
      if (text[i] === "]") {
        i++;
        return arr;
      }
      fail("expected ',' or ']'");
    }
  }
  function parseValue() {
    ws();
    const c = text[i];
    if (c === "{") return parseObject();
    if (c === "[") return parseArray();
    if (c === '"') return parseString();
    const start = i;
    while (i < text.length && !",}] \t\n\r".includes(text[i])) i++;
    if (start === i) fail("unexpected end of input");
    return JSON.parse(text.slice(start, i)); // strict scalar (number/true/false/null)
  }
  const value = parseValue();
  ws();
  if (i !== text.length) fail("trailing characters");
  return value;
}

const isPlainObject = (v) =>
  typeof v === "object" && v !== null && !Array.isArray(v);

// --- reject plumbing ------------------------------------------------------------

class Reject extends Error {
  constructor(category, reason) {
    super(reason);
    this.category = category;
  }
}
const reject = (category, reason) => {
  throw new Reject(category, reason);
};

function b64urlDecode(segment, what, category) {
  if (typeof segment !== "string" || !B64URL_RE.test(segment)) {
    reject(category, `${what} is not unpadded base64url`);
  }
  return Buffer.from(segment, "base64url");
}

// --- key resolution ---------------------------------------------------------------

function buildKeySet(verifierState) {
  const keys = new Map();
  for (const entry of verifierState.keys ?? []) {
    if (entry.publicJwk.kty === "AKP") {
      // RFC 9964 AKP JWK: `pub` is the base64url FIPS 204 public key; `alg`
      // is REQUIRED on AKP keys and names the suite.
      keys.set(entry.kid, {
        suite: entry.publicJwk.alg,
        mlDsaPub: Buffer.from(entry.publicJwk.pub, "base64url"),
      });
      continue;
    }
    const raw = Buffer.from(entry.publicJwk.x, "base64url");
    keys.set(entry.kid, {
      suite: "EdDSA",
      keyObject: createPublicKey({
        key: Buffer.concat([SPKI_ED25519_PREFIX, raw]),
        format: "der",
        type: "spki",
      }),
    });
  }
  return keys;
}

// --- suite dispatch (AAP-SPEC §9.5) -----------------------------------------------

function suiteVerify(alg, key, signingInput, sigBytes) {
  if (alg === "ML-DSA-65") {
    try {
      // Empty context, pure ML-DSA (RFC 9964). Malformed signature bytes
      // (e.g. wrong length) count as a non-verifying signature, fail closed.
      return ml_dsa65.verify(sigBytes, signingInput, key.mlDsaPub);
    } catch {
      return false;
    }
  }
  return cryptoVerify(null, signingInput, key.keyObject, sigBytes);
}

// --- protected header (compact: closed {alg, typ, kid}; general: {alg, kid}) -----

function checkHeader(headerBytes, keys, allowedMembers, where) {
  let text;
  let header;
  try {
    text = headerBytes.toString("utf8");
    header = parseStrictJson(text);
  } catch (err) {
    reject("MALFORMED_HEADER", `${where}: ${err.message}`);
  }
  if (!isPlainObject(header)) {
    reject("MALFORMED_HEADER", `${where}: protected header is not a JSON object`);
  }
  for (const member of Object.keys(header)) {
    if (!allowedMembers.includes(member)) {
      reject(
        "UNKNOWN_HEADER_PARAM",
        `${where}: unknown header parameter "${member}" (v1 headers are closed, AAP-SPEC §9.2)`,
      );
    }
  }
  if (typeof header.alg !== "string") {
    reject("MALFORMED_HEADER", `${where}: missing or non-string alg`);
  }
  if (!SUITE_REGISTRY.includes(header.alg)) {
    reject(
      "UNKNOWN_ALG",
      `${where}: unsupported alg "${header.alg}" — not in the AAP-SPEC §9.5 suite registry; refusing to downgrade`,
    );
  }
  if (allowedMembers.includes("typ") && header.typ !== "JWT") {
    reject("MALFORMED_HEADER", `${where}: typ must be "JWT" in v1`);
  }
  if (typeof header.kid !== "string" || header.kid.length === 0) {
    reject("MALFORMED_HEADER", `${where}: missing or empty kid`);
  }
  if (!keys.has(header.kid)) {
    reject("UNKNOWN_KEY", `${where}: kid "${header.kid}" not in the verifier's key set`);
  }
  if (keys.get(header.kid).suite !== header.alg) {
    // The kid must name a key of the declared suite: the verifier has no key
    // for this (kid, alg) pair, so the token is unverifiable, fail closed.
    reject(
      "UNKNOWN_KEY",
      `${where}: kid "${header.kid}" is not a key for the declared suite "${header.alg}"`,
    );
  }
  return header;
}

// --- claim-set rules (mirror the vendored claim schemas; same order as Python) ----

const isInt = (v) => Number.isInteger(v);
const isBool = (v) => typeof v === "boolean";
const isNum = (v) => typeof v === "number" && Number.isFinite(v);
const nonempty = (v) => typeof v === "string" && v.length > 0;
const isDid = (v) => typeof v === "string" && DID_RE.test(v);

const CHECKS = {
  issAny: [(v) => nonempty(v), "must be a non-empty string"],
  issDid: [(v) => isDid(v), 'must be a string starting "did:"'],
  did: [(v) => isDid(v), 'must be a string starting "did:"'],
  nonempty: [(v) => nonempty(v), "must be a non-empty string"],
  string: [(v) => typeof v === "string", "must be a string"],
  trustClass: [
    (v) => typeof v === "string" && TRUST_CLASS_RE.test(v),
    "must match ^[a-z0-9_-]+:[a-z0-9_-]+$ (an abstract ATX trust class, not a scope)",
  ],
  issuerChain: [
    (v) => Array.isArray(v) && v.length >= 1 && v.every(isDid),
    "must be a non-empty array of DID strings",
  ],
  trustLevel: [(v) => isInt(v) && v >= 0 && v <= 4, "must be an integer 0..4"],
  numericDate: [(v) => isInt(v) && v >= 0, "must be a NumericDate integer"],
  jti: [
    (v) => typeof v === "string" && JTI_RE.test(v),
    "must be 16 random bytes as 32 lowercase hex characters (AAP-SPEC §8.1)",
  ],
  aapVer: [(v) => isInt(v) && v >= 1, "must be an integer >= 1"],
  sha256Ref: [
    (v) => typeof v === "string" && SHA256_REF_RE.test(v),
    "must match ^sha256:[0-9a-f]{64}$",
  ],
  bacLevel: [(v) => isInt(v) && [1, 2, 3].includes(v), "must be 1, 2, or 3"],
  driftScore: [(v) => isNum(v) && v >= 0 && v <= 1, "must be a number in 0..1"],
  bool: [(v) => isBool(v), "must be a boolean"],
  posInt: [(v) => isInt(v) && v >= 1, "must be an integer >= 1"],
  nonNegInt: [(v) => isInt(v) && v >= 0, "must be an integer >= 0 (0 is a terminal delegation, AAP-SPEC §5.3)"],
  actor: [checkActor, 'must be an object with a DID "sub" (recursively)'],
  authorizationDetails: [
    checkAuthorizationDetailsForm,
    "must be a non-empty array of entries, each an object whose type is a §4.4.1 registry URI with well-formed members",
  ],
  aapCrit: [
    (v) => Array.isArray(v) && v.length >= 1 && v.every(nonempty) && new Set(v).size === v.length,
    "must be a non-empty array of unique claim names (AAP-SPEC §4.5)",
  ],
  cnf: [
    (v) =>
      isPlainObject(v) &&
      ("jwk" in v) !== ("jkt" in v) &&
      (!("jwk" in v) || (isPlainObject(v.jwk) && nonempty(v.jwk.kty))) &&
      (!("jkt" in v) || (typeof v.jkt === "string" && JKT_RE.test(v.jkt))),
    "must be an object carrying exactly one of jwk or jkt (RFC 7800, AAP-SPEC §4.6)",
  ],
  labelSet: [
    (v) => isStrArr(v) && new Set(v).size === v.length,
    "must be an array of unique non-empty strings (a label set, AAP-SPEC §4.4.2)",
  ],
};

function checkActor(v) {
  if (!isPlainObject(v) || !isDid(v.sub)) return false;
  if ("act" in v) return checkActor(v.act);
  return true;
}

const isStrArr = (v) => Array.isArray(v) && v.every(nonempty);
const isUniqStrArr = (v) => isStrArr(v) && new Set(v).size === v.length;
const isSha256Ref = (v) => typeof v === "string" && SHA256_REF_RE.test(v);
const posInt = (v) => isInt(v) && v >= 1;
const nonNegInt = (v) => isInt(v) && v >= 0;

// Member forms of the §4.4.1 table. Members are checked whatever the entry
// type (the table's spelling is unique per member); members the table does not
// name are ignored, and unknown types are judged by the aap_crit rule, not here.
const ENTRY_MEMBER_FORMS = {
  serverId: nonempty,
  serverAtx: isSha256Ref,
  tools: isStrArr,
  argumentConstraints: (v) => isPlainObject(v) && Object.values(v).every(isPlainObject),
  schemaHash: isSha256Ref,
  identifier: nonempty,
  version: nonempty,
  contentHash: isSha256Ref,
  peerDid: isDid,
  direction: (v) =>
    isUniqStrArr(v) && v.length >= 1 && v.every((d) => d === "outbound" || d === "inbound"),
  subDelegationDepth: nonNegInt,
  endpoint: nonempty,
  models: isStrArr,
  destinations: isStrArr,
  tlsRequired: isBool,
  locations: isStrArr,
  actions: isStrArr,
  datatypes: isStrArr,
  privileges: isStrArr,
  fieldsAllowed: isStrArr,
  fieldsDenied: isStrArr,
  labelCeiling: isUniqStrArr,
  egressCeiling: isUniqStrArr,
  spend: (v) =>
    isPlainObject(v) &&
    typeof v.amount === "string" &&
    DECIMAL_RE.test(v.amount) &&
    typeof v.currency === "string" &&
    CURRENCY_RE.test(v.currency),
  rate: (v) => isPlainObject(v) && posInt(v.max) && posInt(v.windowSeconds),
  maxUses: posInt,
  concurrency: posInt,
  tokenCap: (v) =>
    isPlainObject(v) &&
    (v.input === undefined || nonNegInt(v.input)) &&
    (v.output === undefined || nonNegInt(v.output)),
  requiresApproval: isBool,
};

/** Form of the authorization_details claim (the vendored schema's shape plus
 *  the §4.4.1 member forms for types this verifier implements). Returns false
 *  on the first malformed entry; an unknown type passes here and is rejected
 *  by checkCrit as not understood. */
function checkAuthorizationDetailsForm(v) {
  if (!Array.isArray(v) || v.length === 0) return false;
  for (const entry of v) {
    if (!isPlainObject(entry) || typeof entry.type !== "string" || !TYPE_URI_RE.test(entry.type)) {
      return false;
    }
    for (const [member, form] of Object.entries(ENTRY_MEMBER_FORMS)) {
      if (member in entry && !form(entry[member])) return false;
    }
    const shortName = entry.type.slice(TYPE_URI_PREFIX.length);
    const required = ENTRY_TYPES[shortName];
    if (required === undefined) continue;
    if (!required.every((m) => m in entry)) return false;
    if (shortName === "budget" && !BUDGET_MEMBERS.some((m) => m in entry)) return false;
  }
  return true;
}

// Ordered member lists per token type: [name, checkKey, required].
const CGT_MEMBERS = [
  ["iss", "issAny", true],
  ["sub", "did", true],
  ["aud", "nonempty", true],
  ["scope", "nonempty", true],
  ["trust_class", "trustClass", true],
  ["issuer_chain", "issuerChain", true],
  ["trust_level", "trustLevel", true],
  ["iat", "numericDate", true],
  ["exp", "numericDate", true],
  ["jti", "jti", true],
  ["aap_ver", "aapVer", false],
  ["authorization_details", "authorizationDetails", false],
  ["aap_crit", "aapCrit", false],
  ["cnf", "cnf", false],
  ["fga_constraints", "string", false],
  ["intent_verified", "bool", false],
  ["max_uses", "posInt", false],
  ["context_required", "bool", false],
];

const CLAIM_MEMBERS = {
  ait: [
    ["iss", "issDid", true],
    ["sub", "did", true],
    ["agent_id", "nonempty", false],
    ["atx_reference", "sha256Ref", true],
    ["declared_purpose", "nonempty", false],
    ["trust_level", "trustLevel", true],
    ["iat", "numericDate", true],
    ["exp", "numericDate", true],
    ["jti", "jti", true],
    ["aap_ver", "aapVer", false],
  ],
  cgt: CGT_MEMBERS,
  da: [
    ["iss", "issAny", true],
    ["sub", "did", true],
    ["aud", "nonempty", true],
    ["scope", "nonempty", true],
    ["trust_class", "trustClass", true],
    ["issuer_chain", "issuerChain", true],
    ["trust_level", "trustLevel", true],
    ["act", "actor", true],
    ["max_depth", "nonNegInt", true],
    ["delegator_atx", "sha256Ref", true],
    ["iat", "numericDate", true],
    ["exp", "numericDate", true],
    ["jti", "jti", true],
    ["aap_ver", "aapVer", false],
    ["authorization_details", "authorizationDetails", false],
    ["aap_crit", "aapCrit", false],
    ["cnf", "cnf", false],
    ["fga_constraints", "string", false],
  ],
  bac: [
    ["iss", "issDid", true],
    ["sub", "did", true],
    ["bac_level", "bacLevel", true],
    ["atx_reference", "sha256Ref", true],
    ["binary_hash", "sha256Ref", false],
    ["drift_score", "driftScore", false],
    ["anomaly_state", "nonempty", false],
    ["intent_verified", "bool", false],
    ["session_label", "labelSet", false],
    ["iat", "numericDate", true],
    ["exp", "numericDate", true],
    ["jti", "jti", true],
    ["aap_ver", "aapVer", false],
  ],
};

function checkClaims(claims, fixtureType) {
  const members = CLAIM_MEMBERS[fixtureType];
  if (!members) reject("CLAIM_SCHEMA", `unknown fixtureType "${fixtureType}"`);
  for (const [name, checkKey, required] of members) {
    if (!(name in claims)) {
      if (required) reject("CLAIM_SCHEMA", `missing required claim "${name}"`);
      continue;
    }
    const [fn, msg] = CHECKS[checkKey];
    if (!fn(claims[name])) {
      reject("CLAIM_SCHEMA", `claim "${name}" ${msg}`);
    }
  }
  if (fixtureType === "bac") {
    // Cumulative levels (AAP-SPEC §6.4): L2 adds binary_hash; L3 adds the
    // behavioral-continuity members. Checked in this fixed order.
    const level = claims.bac_level;
    const needs =
      level >= 3
        ? ["binary_hash", "drift_score", "anomaly_state", "intent_verified"]
        : level >= 2
          ? ["binary_hash"]
          : [];
    for (const name of needs) {
      if (!(name in claims)) {
        reject("CLAIM_SCHEMA", `missing required claim "${name}" for bac_level ${level}`);
      }
    }
    // §6.4: session_label is an L3 member; it MUST NOT appear at L1 or L2.
    if (level < 3 && "session_label" in claims) {
      reject("CLAIM_SCHEMA", `claim "session_label" MUST NOT appear at bac_level ${level} (AAP-SPEC §6.4)`);
    }
  }
}

// --- §4.5 mandatory-to-understand claims ------------------------------------------

function checkCrit(claims) {
  const crit = claims.aap_crit ?? [];
  // A mandatory-to-understand claim that is present MUST be named in aap_crit;
  // a verifier that ignored it would accept a bearer, unconstrained token.
  for (const name of UNDERSTOOD_CRIT) {
    if (name in claims && !crit.includes(name)) {
      reject(
        "CRIT_UNLISTED",
        `claim "${name}" is present but not named in aap_crit — it is mandatory to understand and MUST be listed (AAP-SPEC §4.5)`,
      );
    }
  }
  for (const name of crit) {
    if (!UNDERSTOOD_CRIT.includes(name)) {
      reject(
        "CRIT_NOT_UNDERSTOOD",
        `aap_crit names "${name}", which this verifier does not implement as a mandatory-to-understand claim (AAP-SPEC §4.5)`,
      );
    }
    if (!(name in claims)) {
      reject(
        "CRIT_NOT_UNDERSTOOD",
        `aap_crit names "${name}" but the token carries no such claim (AAP-SPEC §4.5)`,
      );
    }
  }
  // §4.4.1: an unknown type inside a mandatory-to-understand claim is not understood.
  for (const [index, entry] of (claims.authorization_details ?? []).entries()) {
    const shortName = entry.type.slice(TYPE_URI_PREFIX.length);
    if (!(shortName in ENTRY_TYPES)) {
      reject(
        "CRIT_NOT_UNDERSTOOD",
        `authorization_details[${index}] type "${shortName}" is not in the AAP-SPEC §4.4.1 entry type registry — not understood, the token is rejected`,
      );
    }
  }
}

// --- §4.6 proof of possession (presenter binding) ---------------------------------

/** RFC 7638 thumbprint of an Ed25519 OKP JWK (RFC 8037 §2 required members,
 *  lexicographic order, no whitespace, SHA-256, base64url). null if the key is
 *  not an Ed25519 OKP key. */
function jwkThumbprint(jwk) {
  if (!isPlainObject(jwk) || jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || !nonempty(jwk.x)) {
    return null;
  }
  return createHash("sha256")
    .update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x }))
    .digest("base64url");
}

function checkPresenterBinding(claims, presentation) {
  if (!("cnf" in claims)) return;
  const proof = presentation?.proof;
  if (!isPlainObject(proof)) {
    reject("CNF_MISMATCH", "token carries cnf but no presenter proof was presented (AAP-SPEC §4.6)");
  }
  // The suite models the broker profile §6.8 A2A/MCP row: a fresh challenge of
  // at least 16 bytes, returned signed under the presenter's key.
  if (proof.binding !== "signed-challenge") {
    reject("CNF_MISMATCH", `unsupported presentation binding "${proof.binding}" (broker profile §6.8)`);
  }
  const presented = jwkThumbprint(proof.jwk);
  if (presented === null) {
    reject("CNF_MISMATCH", "presenter proof key is not an Ed25519 OKP JWK");
  }
  const bound = "jkt" in claims.cnf ? claims.cnf.jkt : jwkThumbprint(claims.cnf.jwk);
  if (bound === null) {
    reject("CNF_MISMATCH", "cnf.jwk is not an Ed25519 OKP JWK");
  }
  if (presented !== bound) {
    reject(
      "CNF_MISMATCH",
      `presenter key thumbprint "${presented}" does not match the cnf binding "${bound}" (AAP-SPEC §4.6)`,
    );
  }
  const challenge = b64urlDecode(proof.challenge, "proof.challenge", "CNF_MISMATCH");
  if (challenge.length < 16) {
    reject("CNF_MISMATCH", "presenter proof challenge is shorter than 16 bytes (broker profile §6.8)");
  }
  const sig = b64urlDecode(proof.signature, "proof.signature", "CNF_MISMATCH");
  let keyObject;
  try {
    keyObject = createPublicKey({
      key: Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(proof.jwk.x, "base64url")]),
      format: "der",
      type: "spki",
    });
  } catch {
    reject("CNF_MISMATCH", "presenter proof key is not a valid Ed25519 public key");
  }
  if (!cryptoVerify(null, challenge, keyObject, sig)) {
    reject("CNF_MISMATCH", "presenter proof signature does not verify under the cnf-bound key (AAP-SPEC §4.6)");
  }
}

// --- §5.4 attenuation (narrower than or equal to) ---------------------------------

function deepEqual(a, b) {
  if (a === b) return true;
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((x, i) => deepEqual(x, b[i]));
  }
  if (isPlainObject(a) && isPlainObject(b)) {
    const ka = Object.keys(a).sort();
    const kb = Object.keys(b).sort();
    return deepEqual(ka, kb) && ka.every((k) => deepEqual(a[k], b[k]));
  }
  return false;
}

/** Compare two non-negative decimal strings; returns -1, 0, or 1. */
function decimalCompare(a, b) {
  const [ia, fa = ""] = a.split(".");
  const [ib, fb = ""] = b.split(".");
  const na = ia.replace(/^0+(?=\d)/, "");
  const nb = ib.replace(/^0+(?=\d)/, "");
  if (na.length !== nb.length) return na.length < nb.length ? -1 : 1;
  if (na !== nb) return na < nb ? -1 : 1;
  const width = Math.max(fa.length, fb.length);
  const pa = fa.padEnd(width, "0");
  const pb = fb.padEnd(width, "0");
  if (pa === pb) return 0;
  return pa < pb ? -1 : 1;
}

/** network.destinations coverage (§5.4): an element equals an E element or
 *  matches an E `*.` pattern; an E' pattern is covered only by an equal or
 *  broader E pattern. */
function destinationCovered(child, parent) {
  if (child === parent) return true;
  if (!parent.startsWith("*.")) return false;
  const suffix = parent.slice(1); // ".example.com"
  if (child.startsWith("*.")) {
    const childSuffix = child.slice(1);
    return childSuffix !== suffix && childSuffix.endsWith(suffix);
  }
  const host = child.split(":")[0];
  return host.endsWith(suffix) && host !== suffix.slice(1);
}

function subsetOf(childSet, parentSet, member) {
  if (member === "destinations") {
    return childSet.every((c) => parentSet.some((p) => destinationCovered(c, p)));
  }
  const parent = new Set(parentSet);
  return childSet.every((c) => parent.has(c));
}

/** Returns null when child (E') is narrower than or equal to parent (E) under
 *  the §5.4 member kinds, else a short reason. Entries share a type. */
function narrowerOrEqual(child, parent) {
  for (const m of IDENTITY_MEMBERS) {
    if (m in parent && !(m in child && deepEqual(child[m], parent[m]))) {
      return `${m} differs from the delegator's`;
    }
  }
  for (const m of ALLOW_SET_MEMBERS) {
    if (!(m in child)) continue; // absent in E' inherits E's value
    if (m in parent) {
      if (!subsetOf(child[m], parent[m], m)) return `${m} is not a subset of the delegator's`;
    } else if (CEILING_MEMBERS.includes(m) && child[m].length > 0) {
      return `${m} names labels the delegator did not carry`;
    }
  }
  for (const m of DENY_SET_MEMBERS) {
    const parentSet = parent[m] ?? [];
    const childSet = new Set(child[m] ?? []);
    if (!parentSet.every((x) => childSet.has(x))) return `${m} is not a superset of the delegator's`;
  }
  for (const m of ["maxUses", "concurrency"]) {
    if (m in child && m in parent && child[m] > parent[m]) return `${m} exceeds the delegator's`;
  }
  if ("subDelegationDepth" in child && "subDelegationDepth" in parent) {
    if (child.subDelegationDepth >= parent.subDelegationDepth) {
      return "subDelegationDepth is not strictly less than the delegator's";
    }
  }
  if ("rate" in child && "rate" in parent) {
    if (child.rate.max > parent.rate.max) return "rate.max exceeds the delegator's";
    if (child.rate.windowSeconds < parent.rate.windowSeconds) {
      return "rate.windowSeconds is shorter than the delegator's";
    }
  }
  if ("spend" in child && "spend" in parent) {
    if (child.spend.currency !== parent.spend.currency) {
      return "spend is in a currency the delegator does not carry";
    }
    if (decimalCompare(child.spend.amount, parent.spend.amount) > 0) {
      return "spend.amount exceeds the delegator's";
    }
  }
  if ("tokenCap" in child && "tokenCap" in parent) {
    for (const k of ["input", "output"]) {
      if (k in child.tokenCap && k in parent.tokenCap && child.tokenCap[k] > parent.tokenCap[k]) {
        return `tokenCap.${k} exceeds the delegator's`;
      }
    }
  }
  for (const m of FLAG_MEMBERS) {
    if (parent[m] === true && child[m] !== true) return `${m} is relaxed from the delegator's`;
  }
  if ("argumentConstraints" in parent) {
    for (const [tool, args] of Object.entries(parent.argumentConstraints)) {
      for (const [arg, constraint] of Object.entries(args)) {
        if (!deepEqual(child.argumentConstraints?.[tool]?.[arg], constraint)) {
          return `argumentConstraints for ${tool}.${arg} is not carried unchanged`;
        }
      }
    }
  }
  return null;
}

function checkAttenuation(claims, delegatorClaims) {
  if (!("authorization_details" in claims)) return;
  const parents = delegatorClaims.authorization_details ?? [];
  claims.authorization_details.forEach((entry, index) => {
    const shortName = entry.type.slice(TYPE_URI_PREFIX.length);
    const candidates = parents.filter((p) => p.type === entry.type);
    if (candidates.length === 0) {
      reject(
        "NOT_ATTENUATED",
        `authorization_details[${index}] (type ${shortName}) has no parent entry of the same type in the delegator's grant — an orphan entry (AAP-SPEC §5.4)`,
      );
    }
    const reasons = candidates.map((p) => narrowerOrEqual(entry, p));
    if (!reasons.includes(null)) {
      reject(
        "NOT_ATTENUATED",
        `authorization_details[${index}] (type ${shortName}) is not narrower than or equal to any delegator entry of the same type: ${reasons[0]} (AAP-SPEC §5.4)`,
      );
    }
  });
}

function checkDelegation(claims, delegatorClaims) {
  const delegatorIsDa = "act" in delegatorClaims;
  // Linkage: the supplied token must be this DA's immediate delegator.
  if (claims.act.sub !== delegatorClaims.sub) {
    reject(
      "DELEGATOR_INVALID",
      `delegator token subject "${delegatorClaims.sub}" is not the DA's act.sub "${claims.act.sub}"`,
    );
  }
  if (delegatorIsDa && !deepEqual(claims.act.act, delegatorClaims.act)) {
    reject("DELEGATOR_INVALID", "the DA's act chain does not continue the delegator's act chain (RFC 8693 §4.1)");
  }
  // §5.2/§5.3: scope and trust_class equal to or a subset of the delegator's.
  const daScopes = String(claims.scope).split(" ");
  const delegatorScopes = new Set(String(delegatorClaims.scope).split(" "));
  if (!daScopes.every((s) => delegatorScopes.has(s))) {
    reject(
      "SCOPE_NOT_SUBSET",
      `DA scope "${claims.scope}" is not a subset of the delegator scope "${delegatorClaims.scope}" (AAP-SPEC §5.2)`,
    );
  }
  if (claims.trust_class !== delegatorClaims.trust_class) {
    reject(
      "SCOPE_NOT_SUBSET",
      `DA trust_class "${claims.trust_class}" is not equal to or a subset of the delegator trust_class "${delegatorClaims.trust_class}" (AAP-SPEC §5.3)`,
    );
  }
  // §5.4: a DA carries less than its delegator — its validity window lies
  // inside the delegator's.
  if (claims.iat < delegatorClaims.iat) {
    reject("NOT_ATTENUATED", `DA validity window starts (iat ${claims.iat}) before the delegator's (iat ${delegatorClaims.iat}) (AAP-SPEC §5.4)`);
  }
  if (claims.exp > delegatorClaims.exp) {
    reject("NOT_ATTENUATED", `DA validity window ends (exp ${claims.exp}) after the delegator's (exp ${delegatorClaims.exp}) (AAP-SPEC §5.4)`);
  }
  checkAttenuation(claims, delegatorClaims);
  // §5.3: max_depth is the remaining depth below this assertion. A delegator
  // DA at depth 0 is terminal; below a delegator DA at depth d the DA may carry
  // at most d - 1; a delegator peer_agent entry for this DA's sub caps it too.
  if (delegatorIsDa) {
    if (delegatorClaims.max_depth < 1) {
      reject(
        "NOT_ATTENUATED",
        "the delegator is a terminal delegation (max_depth 0); delegating past it is not permitted (AAP-SPEC §5.3)",
      );
    }
    if (claims.max_depth > delegatorClaims.max_depth - 1) {
      reject(
        "NOT_ATTENUATED",
        `max_depth ${claims.max_depth} exceeds the delegator's remaining depth ${delegatorClaims.max_depth - 1} (AAP-SPEC §5.3)`,
      );
    }
  }
  const peer = (delegatorClaims.authorization_details ?? []).find(
    (e) => e.type === `${TYPE_URI_PREFIX}peer_agent` && e.peerDid === claims.sub,
  );
  if (peer !== undefined && claims.max_depth > peer.subDelegationDepth) {
    reject(
      "NOT_ATTENUATED",
      `max_depth ${claims.max_depth} exceeds the delegator's peer_agent subDelegationDepth ${peer.subDelegationDepth} for this delegatee (AAP-SPEC §5.4)`,
    );
  }
}

// --- token verification ------------------------------------------------------------

function verifyCompactStructure(token, keys) {
  if (typeof token !== "string") reject("MALFORMED_TOKEN", "token is not a string");
  const segments = token.split(".");
  if (segments.length !== 3) {
    reject("MALFORMED_TOKEN", `compact serialization must have 3 segments, got ${segments.length}`);
  }
  const [h, p, s] = segments;
  const headerBytes = b64urlDecode(h, "header segment", "MALFORMED_TOKEN");
  b64urlDecode(p, "payload segment", "MALFORMED_TOKEN");
  const sigBytes = b64urlDecode(s, "signature segment", "MALFORMED_TOKEN");

  const header = checkHeader(headerBytes, keys, ["alg", "typ", "kid"], "header");

  const signingInput = Buffer.from(`${h}.${p}`, "ascii");
  if (!suiteVerify(header.alg, keys.get(header.kid), signingInput, sigBytes)) {
    reject("BAD_SIGNATURE", `signature does not verify under kid "${header.kid}"`);
  }

  let claims;
  try {
    // Standard last-wins JSON semantics for the claim set (RFC 7519 §4).
    claims = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
  } catch (err) {
    reject("MALFORMED_PAYLOAD", `claim set is not valid JSON: ${err.message}`);
  }
  if (!isPlainObject(claims)) reject("MALFORMED_PAYLOAD", "claim set is not a JSON object");
  return { header, claims };
}

function verifyGeneralStructure(tokenGeneral, keys, requiredSuites = []) {
  if (!isPlainObject(tokenGeneral)) reject("MALFORMED_TOKEN", "general serialization is not a JSON object");
  const { payload, signatures } = tokenGeneral;
  b64urlDecode(payload, "payload", "MALFORMED_TOKEN");
  if (!Array.isArray(signatures) || signatures.length === 0) {
    reject("MALFORMED_TOKEN", "signatures must be a non-empty array");
  }
  const declaredAlgs = [];
  signatures.forEach((entry, index) => {
    if (!isPlainObject(entry)) reject("MALFORMED_TOKEN", `signatures[${index}] is not an object`);
    const protectedBytes = b64urlDecode(entry.protected, `signatures[${index}].protected`, "MALFORMED_TOKEN");
    const sigBytes = b64urlDecode(entry.signature, `signatures[${index}].signature`, "MALFORMED_TOKEN");
    // General-form per-signature protected headers are exactly {alg, kid} (§9.4).
    const header = checkHeader(protectedBytes, keys, ["alg", "kid"], `signatures[${index}]`);
    const signingInput = Buffer.from(`${entry.protected}.${payload}`, "ascii");
    // Every declared entry MUST verify (§9.4) — no subset acceptance.
    if (!suiteVerify(header.alg, keys.get(header.kid), signingInput, sigBytes)) {
      reject(
        "BAD_SIGNATURE",
        `signatures[${index}] does not verify under its declared kid "${header.kid}" — every declared entry MUST verify (AAP-SPEC §9.4)`,
      );
    }
    declaredAlgs.push(header.alg);
  });
  // Hybrid family gate (§8.2/§9.4): a general-form token declaring any
  // ML-DSA-65 entry is on the hybrid profile and MUST carry at least one
  // Ed25519 entry and at least one ML-DSA-65 entry — a stripped hybrid MUST
  // NOT degrade to single-family acceptance. Judged only after every declared
  // entry verifies, so a bad signature is always the earlier defect.
  if (declaredAlgs.includes("ML-DSA-65") && !declaredAlgs.includes("EdDSA")) {
    reject(
      "HYBRID_INCOMPLETE",
      "general-form token declares ML-DSA-65 but carries no Ed25519 entry — the hybrid profile requires at least one entry of each family (AAP-SPEC §9.4)",
    );
  }
  // Path policy (§8.2): suite acceptance is pinned by the verifier per path,
  // never selected by the token. A token missing a verifying entry of a suite
  // the path requires is a hybrid token with that declared entry stripped — it
  // MUST NOT degrade to acceptance on the remaining family (§9.4).
  for (const suite of requiredSuites) {
    if (!declaredAlgs.includes(suite)) {
      reject(
        "HYBRID_INCOMPLETE",
        `verifier path policy requires a verifying ${suite} entry but the token carries only [${declaredAlgs.join(", ")}] — a declared entry stripped from a hybrid token cannot degrade it to single-family acceptance (AAP-SPEC §8.2, §9.4)`,
      );
    }
  }
  let claims;
  try {
    claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  } catch (err) {
    reject("MALFORMED_PAYLOAD", `claim set is not valid JSON: ${err.message}`);
  }
  if (!isPlainObject(claims)) reject("MALFORMED_PAYLOAD", "claim set is not a JSON object");
  return { claims };
}

function verifyFixture(fixture) {
  // §8.1 replay prevention: one jti cache per verifier lifetime. A fixture may
  // present its token `presentations` times (default 1); the expected verdict
  // pins the final presentation.
  const jtiCache = new Map();
  const presentations = Number.isInteger(fixture.presentations) ? fixture.presentations : 1;
  let result = null;
  for (let n = 0; n < presentations; n++) {
    result = verifyPresentation(fixture, jtiCache);
  }
  return result;
}

function verifyPresentation(fixture, jtiCache) {
  const keys = buildKeySet(fixture.verifierState ?? {});
  const clock = fixture.verifierState?.clockNumericDate;
  const fixtureType = fixture.fixtureType;

  try {
    let claims;
    if (fixture.tokenForm === "general") {
      const requiredSuites = Array.isArray(fixture.verifierState?.requiredSuites)
        ? fixture.verifierState.requiredSuites
        : [];
      ({ claims } = verifyGeneralStructure(fixture.tokenGeneral, keys, requiredSuites));
    } else {
      ({ claims } = verifyCompactStructure(fixture.token, keys));
    }

    checkClaims(claims, fixtureType);
    checkCrit(claims);

    if (isInt(clock) && clock >= claims.exp) {
      reject("EXPIRED", `token expired (exp ${claims.exp} <= clock ${clock})`);
    }
    if (fixtureType === "bac" && claims.exp - claims.iat > BAC_TTL_SECONDS) {
      reject(
        "TTL_WINDOW",
        `BAC validity window exp - iat = ${claims.exp - claims.iat}s exceeds the 60-second cap (AAP-SPEC §6.1)`,
      );
    }
    checkPresenterBinding(claims, fixture.presentation);
    if (fixtureType === "da" && fixture.delegation?.delegatorToken !== undefined) {
      let delegatorClaims;
      try {
        ({ claims: delegatorClaims } = verifyCompactStructure(fixture.delegation.delegatorToken, keys));
        // The immediate delegator is a CGT, or a DA when the chain is deeper.
        checkClaims(delegatorClaims, "act" in delegatorClaims ? "da" : "cgt");
        checkCrit(delegatorClaims);
      } catch (err) {
        if (err instanceof Reject) {
          reject("DELEGATOR_INVALID", `delegator token: ${err.message}`);
        }
        throw err;
      }
      checkDelegation(claims, delegatorClaims);
    }

    // §8.1: receivers MUST track used jti values for the token's TTL window
    // and MUST reject a repeated identifier. Judged last — replay is only
    // decidable for an otherwise-acceptable token. The identifier is scoped
    // per issuer and remembered until the token's exp.
    const jtiKey = `${claims.iss}\n${claims.jti}`;
    const rememberedExp = jtiCache.get(jtiKey);
    if (rememberedExp !== undefined && (!isInt(clock) || clock < rememberedExp)) {
      reject(
        "REPLAYED_JTI",
        `jti "${claims.jti}" was already presented and its TTL window has not elapsed (AAP-SPEC §8.1)`,
      );
    }
    jtiCache.set(jtiKey, claims.exp);

    return { accepted: true, category: null, reason: "" };
  } catch (err) {
    if (err instanceof Reject) {
      return { accepted: false, category: err.category, reason: err.message };
    }
    throw err;
  }
}

// --- CLI harness -------------------------------------------------------------------

function expandPaths(args) {
  const out = new Set();
  for (const a of args) {
    const st = statSync(a); // throws if missing
    if (st.isDirectory()) {
      const fixturesDir = join(a, "fixtures");
      const target = existsSync(fixturesDir) && statSync(fixturesDir).isDirectory() ? fixturesDir : a;
      for (const f of readdirSync(target).sort()) {
        if (f.endsWith(".json")) out.add(join(target, f));
      }
    } else {
      out.add(a);
    }
  }
  return [...out].sort();
}

function main(argv) {
  if (argv.length < 1) {
    process.stderr.write("usage: verify.mjs <fixture.json|dir>...\n");
    return 2;
  }
  let paths;
  try {
    paths = expandPaths(argv);
  } catch (err) {
    process.stderr.write(`error: ${err.message}\n`);
    return 2;
  }
  if (paths.length === 0) {
    process.stderr.write("no fixture *.json files found\n");
    return 2;
  }

  let totalPass = 0;
  let totalFail = 0;
  for (const p of paths) {
    let fixture;
    try {
      fixture = JSON.parse(readFileSync(p, "utf8"));
    } catch (err) {
      console.log(`FAIL  ${p}  (load error: ${err.message})`);
      totalFail++;
      continue;
    }

    const got = verifyFixture(fixture);
    const expected = fixture.expected ?? {};
    const wantAccept = (expected.verifyResult ?? "").toUpperCase() === "ACCEPT";

    let ok = wantAccept === got.accepted;
    if (ok && !wantAccept && expected.rejectCategory) {
      ok = got.category === expected.rejectCategory;
    }
    if (ok && !wantAccept && expected.reasonContains) {
      ok = got.reason.toLowerCase().includes(expected.reasonContains.toLowerCase());
    }

    const status = ok ? "PASS" : "FAIL";
    if (ok) totalPass++;
    else totalFail++;

    const observed = got.accepted ? "ACCEPT" : `REJECT[${got.category}: ${got.reason}]`;
    console.log(`${status}  ${p}  [${fixture.fixtureType ?? "?"}]`);
    process.stdout.write(`       expected: ${expected.verifyResult ?? ""}`);
    if (expected.rejectCategory) process.stdout.write(` [${expected.rejectCategory}]`);
    process.stdout.write("\n");
    console.log(`       observed: ${observed}`);
  }

  console.log();
  console.log(`summary: ${totalPass} pass, ${totalFail} fail (${totalPass + totalFail} fixtures)`);
  return totalFail === 0 ? 0 : 1;
}

process.exit(main(process.argv.slice(2)));
