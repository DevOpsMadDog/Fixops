# Security Posture

This document captures the security guardrails configured for the FixOps investor demo branch after Phase 10 hardening. It
complements `docs/PLAYBOOK-SEC.md` and `docs/PLAYBOOK-AUDIT.md` with policy-level expectations.

## Branch protection & commit integrity

- The default branch requires pull requests with at least one approving review. Direct pushes are disabled for maintainers.
- Status checks enforced:
  - `qa` workflow (`.github/workflows/qa.yml`) covering linting, type checking, tests, and coverage ≥70%.
  - `provenance` workflow on tags to ensure attestations are produced and uploaded.
  - `release-sign` workflow to guarantee cosign signatures exist for every release artefact.
- Signed commits are mandatory. Contributors configure local Git with GPG or Sigstore signing before merging. Unsigned commits
  are rejected by branch protections.

## Dependency hygiene

- Dependabot is enabled for GitHub Actions, pip dependencies, and Dockerfiles. Review windows are capped at 48 hours for security
  patches and 7 days for general updates.
- Use the SBOM normaliser (`cli/fixops-sbom`) to cross-check new dependencies. Licensing and generator variance metrics are
  tracked in `reports/sbom_quality_report.html`.

## Secrets governance

- Secrets required for CI flows are enumerated in `docs/CI-SECRETS.md`. Only the security operations group manages their
  rotation.
- GitHub’s OIDC token is leveraged for cosign keyless signing. No long-lived signing keys or passwords are stored in the
  repository.
- Release evidence bundles are signed using the CI-managed key and published under `evidence/` for audit consumption.

## Monitoring & observability

- OpenTelemetry traces and metrics are emitted by provenance, risk, graph, and repro services. The demo stack forwards telemetry
  to the collector defined in `config/otel-collector-demo.yaml`.
- Dashboard panels in `ui/dashboard/` display SBOM quality, FixOpsRisk, provenance lineage, and reproducibility status so
  stakeholders can monitor control health in real time.

## Compliance artefacts

- Coverage, provenance, signing, SBOM, risk, reproducibility, and evidence outputs are preserved in git-tracked directories so
  releases can be replayed.
- `CHANGELOG.md` summarises the security-impacting changes across Phases 1–10 and must be updated before each release cut.
- Playbooks (`docs/PLAYBOOK-DEV.md`, `docs/PLAYBOOK-SEC.md`, `docs/PLAYBOOK-AUDIT.md`) describe operational procedures for
  engineering, security, and auditors respectively.

