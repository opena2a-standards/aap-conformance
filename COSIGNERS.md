# Cosigners

Second-party cosigners attest that they have independently:

1. Cloned this repository at a specific commit SHA
2. Run BOTH reference verifiers against the published fixture set
3. Observed `summary: N pass, 0 fail (N fixtures)` from each verifier
4. Produced a Sigstore keyless cosign signature over [`MANIFEST.sha256`](./MANIFEST.sha256)

The signature attests to the fixture bytes; the entry below attests that
the verifiers were actually run.

## How to cosign

```bash
# Clone and verify
git clone https://github.com/opena2a-standards/aap-conformance
cd aap-conformance

# Run both verifiers and record exit summaries
(cd verifiers/node && node verify.mjs ../../fixtures)
(cd verifiers/python && pip install -r requirements.txt && python verify.py ../../fixtures)

# Sigstore keyless cosign over MANIFEST.sha256
cosign sign-blob MANIFEST.sha256 \
    --output-signature MANIFEST.sha256.sig \
    --output-certificate MANIFEST.sha256.crt

# Open a PR that:
#   - Adds your cosignature + certificate under .sigstore/<your-org>/
#   - Appends an entry to the table below
```

## CI self-cosignature (baseline)

Every push to `main` keyless-signs the current `MANIFEST.sha256` in CI
(`sign-manifest` job in
[`conformance.yml`](./.github/workflows/conformance.yml)), after the full
conformance job has passed. The signature bundle is uploaded as a workflow
artifact and the signing event is durably recorded in the public Rekor
transparency log. This is a first-party attestation — it proves the fixture
bytes passed CI at a given commit, not independent review.

## Second-party cosigners

| Organization | Commit SHA | Date | Verifier summaries | Signature |
|---|---|---|---|---|
| _none yet_ | | | | |
