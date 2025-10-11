# Security Playbook

This playbook equips the security engineering pod with actionable steps to govern the FixOps provenance, signing, and risk
surfaces introduced across Phases 1–10.

## Daily posture checks

1. **Verify CI attestation uploads** – On each tagged release download the attestation bundle from the provenance workflow
   artefacts (`artifacts/attestations/`) and run:
   ```bash
   cli/fixops-provenance verify --artifact dist/<artifact> --attestation artifacts/attestations/<artifact>.json
   ```
2. **Confirm cosign signatures** – After provenance verification, validate that `.sig` files attached to the release match the
   published artefacts:
   ```bash
   cosign verify-blob \
     --certificate-identity "https://github.com/DevOpsMadDog/Fixops/.github/workflows/release-sign.yml@refs/tags/<tag>" \
     --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
     --signature release-artifacts/<asset>.sig \
     dist/<asset>
   ```
3. **Monitor KEV-linked risk** – Query the provenance graph API for the latest release to ensure KEV components are mitigated:
   ```bash
   http GET :8000/api/graph/kev-components?releases=5
   ```

## Incident response triggers

- **Reproducibility failure** – If `.github/workflows/repro-verify.yml` reports a mismatch, consume the attestation under
  `artifacts/repro/attestations/<tag>.json` to identify the differing digest, lock new releases, and coordinate with engineering
  for remediation.
- **Evidence bundle warning** – When the CI agent emits `warn` or `fail` evaluations inside `evidence/manifests/<tag>.yaml`, halt
  release promotion and open a security review ticket that references the manifest and associated SBOM/risk payloads.
- **Graph anomalies** – Use the provenance graph anomaly query (`/api/graph/anomalies`) to spot unexpected downgrades or version
  drifts. Confirm the downgrade was intentional via changelog context before re-enabling delivery.

## Secrets management

- GH secrets consumed by provenance, signing, and evidence workflows are listed in `docs/CI-SECRETS.md`. Rotate them quarterly
  and before adding new maintainers.
- Never store signing keys or cosign passwords in the repository. Use GitHub’s OIDC support for keyless signing where possible.

## Hardening checklist for releases

- [ ] Coverage summary at or above 70% committed under `reports/coverage/summary.txt`.
- [ ] CHANGELOG entry referencing risk, provenance, repro, and evidence changes for the release cycle.
- [ ] Screenshots of the demo dashboard archived in the release notes for investor-ready storytelling.
- [ ] Branch protections and signed commits enforced on the default branch (documented in `docs/SECURITY-POSTURE.md`).

## Communications

- Page the security engineering on-call before rotating secrets or introducing new CI workflows touching signing.
- Capture incident post-mortems in `audit/SECURITY.md` and link them from the next `CHANGELOG.md` section.
- Share weekly summaries of EPSS/KEV deltas with stakeholders using `cli/fixops-risk score` outputs to inform patch cadence.

