# aap-conformance

Conformance fixtures and reference verifiers for the
[Agent Authorization Protocol (AAP)](https://github.com/opena2a-standards/agent-authorization-protocol)
token canonical form (AAP-SPEC §9: JWTs over JWS, where serialization is
canonicalization).

The AAP version the suite covers is the `spec.version` field of
[`conformance.json`](./conformance.json).

Two SDK-independent reference verifiers (Node and Python) walk the fixture
set and report PASS or FAIL per vector. Fixture bytes are pinned in
[`MANIFEST.sha256`](./MANIFEST.sha256).

Run it:

```bash
npm install   # @noble/post-quantum, for the ML-DSA-65 fixtures (RFC 9964)
node verifiers/node/verify.mjs fixtures

pip install -r verifiers/python/requirements.txt
python3 verifiers/python/verify.py fixtures
```

A passing run prints an entry per fixture, then a summary line (first entry
shown; the two verifiers print the same lines):

```text
PASS  fixtures/ait-compact-valid.json  [ait]
       expected: ACCEPT
       observed: ACCEPT
...

summary: 44 pass, 0 fail (44 fixtures)
```

This suite is the fifth in the family, alongside
[atx-conformance](https://github.com/opena2a-standards/atx-conformance),
[atp-conformance](https://github.com/opena2a-standards/atp-conformance),
[aip-conformance](https://github.com/opena2a-standards/aip-conformance), and
[a2a-idf-conformance](https://github.com/opena2a-standards/a2a-idf-conformance).

License: Apache 2.0. All key seeds in this repository
([`vectors/test-keys.json`](./vectors/test-keys.json)) are PUBLISHED TEST
KEYS for fixture reproduction only — never production use.

## Scope

The [scope page](docs/scope.md) maps each fixture to the requirement it
tests: the valid AIT, CGT, DA and BAC tokens and single-defect must-reject
variants, in compact, JWS General JSON and hybrid Ed25519 + ML-DSA-65 forms.
Protocol flows and broker state (CPI endpoints, revocation), §8.2 key
exchange and the other items listed there are not verified.

## Using the fixtures against your own implementation

The fixtures are implementation-neutral: read a fixture, feed
`token` (compact) or `tokenGeneral` (JWS General JSON Serialization) to your
verifier configured with `verifierState.keys` (Ed25519 OKP and ML-DSA-65
AKP public JWKs) and `verifierState.clockNumericDate`, and compare your
verdict with `expected`.

[Using the fixtures](docs/using-the-fixtures.md) covers the optional inputs
(suite policy, delegator token, presenter proof) and the reject category a
conforming verifier must match.

## Documentation

- [Scope and fixture provenance](docs/scope.md): what a fixture holds, the
  requirement-to-fixture table, the reject categories, and what the suite
  does not verify.
- [Using the fixtures](docs/using-the-fixtures.md): the fixture fields a
  verifier reads.
- [Continuous verification](docs/continuous-verification.md): the CI gates
  that enforce these claims on pushes to `main` and on pull requests.
- [How it works](docs/how-it-works.md): why the reference verifiers are a
  Node and Python pair.
- [`conformance.json`](./conformance.json): the machine-readable
  requirement-to-fixture mapping.
- [`COSIGNERS.md`](./COSIGNERS.md): how second parties cosign
  `MANIFEST.sha256`.
