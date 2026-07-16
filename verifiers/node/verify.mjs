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
//   CLAIM_SCHEMA > EXPIRED > TTL_WINDOW > (DELEGATOR_INVALID >)
//   SCOPE_NOT_SUBSET > REPLAYED_JTI
//
// HYBRID_INCOMPLETE sits after BAD_SIGNATURE: the family gate (AAP-SPEC §9.4:
// a general-form token declaring any ML-DSA-65 entry MUST carry ≥1 Ed25519
// AND ≥1 ML-DSA-65 entry) is judged only once every declared entry verifies.
// REPLAYED_JTI is last: replay is only decidable for an otherwise-acceptable
// token (§8.1; a fixture presents the same token `presentations` times to one
// verifier, and the expected verdict pins the final presentation).
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
import { createPublicKey, verify as cryptoVerify } from "node:crypto";
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
  actor: [checkActor, 'must be an object with a DID "sub" (recursively)'],
};

function checkActor(v) {
  if (!isPlainObject(v) || !isDid(v.sub)) return false;
  if ("act" in v) return checkActor(v.act);
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
    ["max_depth", "posInt", true],
    ["delegator_atx", "sha256Ref", true],
    ["iat", "numericDate", true],
    ["exp", "numericDate", true],
    ["jti", "jti", true],
    ["aap_ver", "aapVer", false],
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

function verifyGeneralStructure(tokenGeneral, keys) {
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
      ({ claims } = verifyGeneralStructure(fixture.tokenGeneral, keys));
    } else {
      ({ claims } = verifyCompactStructure(fixture.token, keys));
    }

    checkClaims(claims, fixtureType);

    if (isInt(clock) && clock >= claims.exp) {
      reject("EXPIRED", `token expired (exp ${claims.exp} <= clock ${clock})`);
    }
    if (fixtureType === "bac" && claims.exp - claims.iat > BAC_TTL_SECONDS) {
      reject(
        "TTL_WINDOW",
        `BAC validity window exp - iat = ${claims.exp - claims.iat}s exceeds the 60-second cap (AAP-SPEC §6.1)`,
      );
    }
    if (fixtureType === "da" && fixture.delegation?.delegatorToken !== undefined) {
      let delegatorClaims;
      try {
        ({ claims: delegatorClaims } = verifyCompactStructure(fixture.delegation.delegatorToken, keys));
      } catch (err) {
        if (err instanceof Reject) {
          reject("DELEGATOR_INVALID", `delegator token: ${err.message}`);
        }
        throw err;
      }
      const daScopes = String(claims.scope).split(" ");
      const delegatorScopes = new Set(String(delegatorClaims.scope).split(" "));
      if (!daScopes.every((s) => delegatorScopes.has(s))) {
        reject(
          "SCOPE_NOT_SUBSET",
          `DA scope "${claims.scope}" is not a subset of the delegator scope "${delegatorClaims.scope}" (AAP-SPEC §5.2)`,
        );
      }
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
