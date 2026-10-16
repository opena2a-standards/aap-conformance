# aap-conformance: how it works

Why the reference verifiers are a Node and Python pair. Back to the
[README](../README.md).

## The reference verifiers

The verifier pair is Node + Python deliberately (the
[a2a-idf-conformance](https://github.com/opena2a-standards/a2a-idf-conformance)
precedent, not the Go pair of atp-conformance): the AAP reference broker
([Secretless](https://github.com/opena2a-org/secretless-ai), `src/broker/cpi/assertion.ts`)
is TypeScript, so the Node verifier exercises the same `node:crypto` JOSE
primitives the reference mints with, and the Python verifier mirrors the
spec repo's fixture generator from the verification side.
