# aap-conformance: continuous verification

The CI gates behind the suite's claims. Back to the [README](../README.md).

## Continuous verification

[`.github/workflows/conformance.yml`](../.github/workflows/conformance.yml)
enforces every claim in the [README](../README.md) and the
[scope page](scope.md) on each push and pull request:

1. Both reference verifiers run against `fixtures/` and must report
   `44 pass, 0 fail`.
2. Schema validation
   ([`scripts/schema_validation.py`](../scripts/schema_validation.py)): every
   fixture's decoded header/claims/container must match its DECLARED schema
   validity against the AAP-SPEC schemas, vendored under
   `schemas/vendor/agent-authorization-protocol/` (some REJECT fixtures are
   claim-schema defects by design, so validity is declared per fixture, both
   directions gated).
3. Spec drift gate: the vendored schemas, the reused ACCEPT token bytes, and
   `vectors/test-keys.json` are byte-compared against a pinned
   agent-authorization-protocol ref
   ([`scripts/spec_pin_check.py`](../scripts/spec_pin_check.py)).
4. The fixture generator re-runs and the committed fixture bytes plus
   `MANIFEST.sha256` must reproduce exactly (byte-pin).
5. The cross-implementation parity gate
   ([`scripts/parity/parity.py`](../scripts/parity/parity.py)) asserts the
   Node and Python verifiers agree per fixture on gate status, verdict, and
   reject category, and publishes `parity-report.json` as a CI artifact.
6. `conformance.json` must match the fixture set, the Scope table in
   [`docs/scope.md`](scope.md) must have exactly one row for every fixture,
   and every tracked file at the repository root must be named in the
   README, backticked or as a
   link target, except the ones git and npm read by convention
   (`.gitignore`, `LICENSE`, `README.md`, `package.json`,
   `package-lock.json`).
7. On every push to `main`, CI keyless-signs `MANIFEST.sha256` with Sigstore
   cosign (Rekor is the durable record) — see
   [`COSIGNERS.md`](../COSIGNERS.md) for how second parties cosign.
