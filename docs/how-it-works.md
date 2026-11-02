# aap-conformance: how it works

Why the reference verifiers are a Node and Python pair, and how a program
calls the Node verifier in-process. Back to the [README](../README.md).

## The reference verifiers

The verifier pair is Node + Python deliberately (the
[a2a-idf-conformance](https://github.com/opena2a-standards/a2a-idf-conformance)
precedent, not the Go pair of atp-conformance): the AAP reference broker
([Secretless](https://github.com/opena2a-org/secretless-ai), `src/broker/cpi/assertion.ts`)
is TypeScript, so the Node verifier exercises the same `node:crypto` JOSE
primitives the reference mints with, and the Python verifier mirrors the
spec repo's fixture generator from the verification side.

## Calling the Node verifier from code

`verifiers/node/verify.mjs` is a module as well as the CLI. It exports
`verifyFixture` and `verifyPresentation`, the verification the CLI performs
for each fixture, and importing it from another script does not start the
CLI. Saved as a `.mjs` file at the repository root and run with `node` after
`npm install`, this script:

```js
import { readFileSync } from "node:fs";
import { verifyFixture } from "./verifiers/node/verify.mjs";

for (const name of ["cgt-compact-valid", "cgt-compact-expired"]) {
  const input = JSON.parse(readFileSync(`fixtures/${name}.json`, "utf8"));
  const { accepted, category, reason } = verifyFixture(input);
  console.log(name, accepted ? "ACCEPT" : `REJECT ${category}: ${reason}`);
}
```

prints:

```text
cgt-compact-valid ACCEPT
cgt-compact-expired REJECT EXPIRED: token expired (exp 1780315500 <= clock 1780315501)
```

The input carries the fields [Using the fixtures](using-the-fixtures.md)
lists, plus the token's type in `fixtureType` (`ait`, `cgt`, `da` or `bac`)
and its form in `tokenForm` (`compact` or `general`); `expected` is not
read. The result is `{ accepted, category, reason }`, with `category` `null`
and `reason` empty on ACCEPT. The verifier reads no clock: pass the
verification time as `verifierState.clockNumericDate`, since without an
integer clock it does not judge expiry. `verifyFixture` starts a new jti
cache on each call; to detect a jti replayed across calls (AAP-SPEC §8.1),
keep one `Map` and pass it as `verifyPresentation(input, jtiCache)`.
