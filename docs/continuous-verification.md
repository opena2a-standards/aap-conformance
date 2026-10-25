# aap-conformance: continuous verification

The CI gates behind the suite's claims. Back to the [README](../README.md).

## Continuous verification

[`.github/workflows/conformance.yml`](../.github/workflows/conformance.yml)
runs these gates on each push to `main` and on each pull request:

1. Both reference verifiers run against `fixtures/` and must report
   `0 fail`: each exits non-zero when any fixture fails and 0 otherwise.
   They do not check how many fixtures there are; the
   fixture count the README shows is checked by gate 6.
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
   the summary line of the README's sample run must be the one a passing run
   over `fixtures/` prints (`summary: N pass, 0 fail (N fixtures)`, N the
   number of fixtures), and every tracked file at the repository root must be named in the
   README, backticked or as a
   link target, except the ones git and npm read by convention
   (`.gitignore`, `LICENSE`, `README.md`, `package.json`,
   `package-lock.json`).
7. On every push to `main`, CI keyless-signs `MANIFEST.sha256` with Sigstore
   cosign (Rekor is the durable record) — see
   [`COSIGNERS.md`](../COSIGNERS.md) for how second parties cosign.
8. The judging contract check runs both verifiers on inputs built from two fixtures, with the expected verdict removed, misspelled or of the wrong type, and on files whose JSON value is not an object. It asserts that each is reported FAIL, that the run exits 1, and that the two verifiers print the same report.

## Local-only unit tests

The unit tests in `scripts/test_*.py` are local-only: no step of
[`conformance.yml`](../.github/workflows/conformance.yml) or
[`spec-drift.yml`](../.github/workflows/spec-drift.yml) runs them, so a
failing unit test does not block a merge. Run them before opening a pull
request:

```bash
python3 -m unittest discover -s scripts -p 'test_*.py'
```

They cover the scope-table rule, the README summary-line rule, the root-file
rule and the error reporting of `scripts/conformance_profile.py`, the
README's run commands, passing-run capture and spec-version pointer
(`scripts/test_readme_run_capture.py`), the spec sections the scope page's
DA expiry row cites and the one it marks pending a spec release
(`scripts/test_scope_doc.py`), and this page's account of how they run.
Gate 6 checks the capture's summary line in CI as well; the README's run
commands, the capture's first entry and the spec-version pointer are
checked only by these tests.
