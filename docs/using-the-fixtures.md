# aap-conformance: using the fixtures against your own implementation

What each fixture carries and what a conforming verifier must match. Back to
the [README](../README.md); the fixture inventory is in the
[scope page](scope.md).

## Using the fixtures against your own implementation

The fixtures are implementation-neutral: read a fixture, feed
`token` (compact) or `tokenGeneral` (JWS General JSON Serialization) to your
verifier configured with `verifierState.keys` (Ed25519 OKP and ML-DSA-65
AKP public JWKs) and `verifierState.clockNumericDate`, and compare your
verdict with `expected`.
`expected.verifyResult` is `ACCEPT` or `REJECT`; the reference verifiers report a fixture without one as FAIL.
Where present, `verifierState.requiredSuites` is
the path's suite policy (§8.2) for a general-form token;
`delegation.delegatorToken` carries the immediate delegator's token (a CGT,
or a DA deeper in a chain) for the §5.2-§5.4 re-check — it is the delegator
only if its `sub` equals the DA's `act.sub` and, for a DA delegator, its
`act` equals the DA's `act.act` (RFC 8693 §4.1); a token that is not that
grant rejects `DELEGATOR_INVALID`, since checking it would re-check nothing;
and `presentation.proof` carries the presenter's signed-challenge proof
(`binding`, `challenge`, `jwk`, `signature`) for a token with `cnf`, which
rejects `CNF_MISMATCH` when the proof is absent or does not bind. A
conforming verifier matches the expected verdict on every fixture in `fixtures/` — and
rejects for the pinned reason, not just any reason.
