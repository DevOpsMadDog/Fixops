# Audit Playbook

The audit team consumes FixOps artefacts to validate releases for compliance demonstrations. This guide maps each control to the
supporting evidence surfaces.

## Artefact collection

1. **Download evidence bundle** – Use the CLI to pull the signed bundle and manifest for the target release:
   ```bash
   cli/fixops-ci evidence bundle --tag vX.Y.Z --out audit_artifacts/
   ```
   Bundles land under `audit_artifacts/bundles/` and signed manifests under `audit_artifacts/manifests/`.
2. **Retrieve provenance attestations** – Copy `artifacts/attestations/*.json` and store them alongside the bundle for the audit
   package. Each attestation is SLSA v1 compliant and references the corresponding git commit.
3. **Capture reproducibility proofs** – Archive the matching entries from `artifacts/repro/attestations/` to show binary/source
   equivalence.
4. **Export coverage summary** – Include `reports/coverage/summary.txt` and `reports/coverage/coverage.xml` so auditors can verify
   the ≥70% threshold.

## Control verification checklist

| Control | Evidence | How to verify |
| --- | --- | --- |
| Build provenance | `artifacts/attestations/<artifact>.json` | Run `cli/fixops-provenance verify` against the release artefact. |
| Signing | Release `.sig` files | Execute `cosign verify-blob` with the release identity documented in `docs/SIGNING.md`. |
| SBOM quality | `reports/sbom_quality_report.html` | Review coverage, licence completeness, and generator variance gauges. |
| Risk scoring | `artifacts/risk.json` | Confirm FixOpsRisk values align with policy thresholds in `config/policy.yml`. |
| Reproducibility | `artifacts/repro/attestations/<tag>.json` | Ensure `match: true` and digests match the bundle manifest. |
| Evidence packaging | `evidence/manifests/<tag>.yaml` | Inspect the signed manifest for policy outcomes and included artefacts. |
| Coverage | `reports/coverage/summary.txt` | Check that TOTAL coverage is ≥70% and note deltas from previous release. |

## Interview preparation

- Review `docs/PROVENANCE-GRAPH.md`, `docs/REPRO-BUILDS.md`, and `docs/EVIDENCE-BUNDLES.md` to explain how data flows from source
  control to compliance outputs.
- Bring the investor/demo dashboard screenshot (captured from `ui/dashboard/`) to illustrate telemetry coverage.
- Summarise release history using `CHANGELOG.md` with emphasis on controls tightened during Phases 6–10.

## Storage & retention

- Store collected bundles and attestations in the secured audit bucket with immutable retention (minimum 12 months).
- Record verification commands and hashes in the audit ticket so the review is reproducible by third parties.
- Delete local copies after transfer to avoid stale artefacts drifting from the canonical release.

