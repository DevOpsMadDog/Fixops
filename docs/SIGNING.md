# Release Signing and Verification

The `release-sign.yml` GitHub Actions workflow builds FixOps release archives, signs them with
[Cosign](https://github.com/sigstore/cosign), and uploads the resulting signatures and
attestations alongside the release. Local helper scripts under `scripts/signing/` wrap Cosign to
make consistent signing and verification easier for engineers.

## Workflow summary

1. Create a source archive with `git archive` and generate a SLSA v1 predicate via
   `cli/fixops-provenance`.
2. Install Cosign using `sigstore/cosign-installer@v3` and hydrate the private key from the
   `COSIGN_PRIVATE_KEY` secret (protected by `COSIGN_PASSWORD`).
3. Run `scripts/signing/sign-artifact.sh` to:
   - produce a detached signature (`cosign sign-blob`),
   - emit a DSSE attestation (`cosign attest-blob`) around the provenance predicate, and
   - capture an optional verification bundle for offline validation.
4. Validate the outputs with `cosign verify-blob` before publishing, and finally upload the
   signed archive plus attestation materials as release assets.

The workflow lives at `.github/workflows/release-sign.yml`. Secrets required for the pipeline are
documented in [`docs/CI-SECRETS.md`](CI-SECRETS.md).

## Local signing helpers

* `scripts/signing/sign-artifact.sh` — wraps `cosign sign-blob`/`cosign attest-blob` to generate
  detached signatures and DSSE envelopes.
* `scripts/signing/verify-artifact.sh` — wraps `cosign verify-blob` to validate either a detached
  signature or an attestation bundle against the release artifact.

Both scripts accept `--help` for usage details and honour the `COSIGN_PASSWORD`/`COSIGN_KEY_PATH`
(and `COSIGN_PUBLIC_KEY`) environment variables.

## Verifying release downloads

1. Download the release tarball, detached signature, and bundle files from the GitHub release
   page. Rename them as needed:

   ```bash
   export TAG=v1.2.3
   curl -LO https://github.com/DevOpsMadDog/Fixops/releases/download/${TAG}/fixops-${TAG}.tar.gz
   curl -LO https://github.com/DevOpsMadDog/Fixops/releases/download/${TAG}/fixops-${TAG}.tar.gz.sig
   curl -LO https://github.com/DevOpsMadDog/Fixops/releases/download/${TAG}/fixops-${TAG}.bundle
   ```

2. Verify the detached signature with `cosign verify-blob`:

   ```bash
   cosign verify-blob \
     --key cosign.pub \
     --signature fixops-${TAG}.tar.gz.sig \
     fixops-${TAG}.tar.gz
   ```

3. Validate the DSSE attestation bundle and provenance payload with Cosign (also via
   `verify-blob`):

   ```bash
   cosign verify-blob \
     --key cosign.pub \
     --bundle fixops-${TAG}.bundle \
     fixops-${TAG}.tar.gz
   ```

4. If the provenance attestation is mirrored to an OCI registry (for example GHCR), use
   `cosign verify-attestation` to inspect the attached SLSA predicate:

   ```bash
   cosign verify-attestation \
     --key cosign.pub \
     --type slsaprovenance \
     ghcr.io/devopsmaddog/fixops/fixops-release:${TAG}
   ```

   The `--local-image` flag can be used with a local OCI layout produced via `cosign save` if you
   prefer offline verification.

These checks ensure the downloaded artifacts match the official FixOps release and that the build
metadata has not been tampered with.
