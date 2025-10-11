# Changelog

All notable changes to the FixOps investor demo branch are documented here. The project followed a ten-phase roadmap focused on
provenance, signing, SBOM normalisation, risk scoring, evidence, observability, and hardening.

## Phase 10 – Hardening & Coverage (2024-09-XX)
- Added developer, security, and audit playbooks plus the overarching security posture guide.
- Introduced the `qa` workflow enforcing lint, type-check, tests, and coverage ≥70% before merge.
- Captured coverage artefacts (`reports/coverage/coverage.xml`, `reports/coverage/summary.txt`) and tightened release
  expectations.

## Phase 9 – Observability & Demo Stack
- Instrumented provenance, risk, graph, and repro services with OpenTelemetry fallbacks for offline environments.
- Added `docker-compose.demo.yml`, the OTEL collector config, and a dashboard UI surface for investor-ready demos.
- Introduced the graph worker to keep the provenance database fresh for the dashboard queries.

## Phase 8 – CI Agent & Evidence Bundles
- Delivered the `cli/fixops-ci` orchestrator that chains SBOM, risk, provenance, and repro actions.
- Packaged signed evidence bundles and manifests, exposed via the `backend/api/evidence` endpoints.
- Documented bundle structure, policy thresholds, and added tests for manifest integrity.

## Phase 7 – Reproducible Builds Verifier
- Created the hermetic rebuild service, CLI wrapper, and GitHub Actions workflow to confirm source/binary equivalence.
- Stored reproducibility attestations under `artifacts/repro/attestations/` and published operator documentation.
- Added targeted tests covering success and failure scenarios for the verifier.

## Phase 6 – Provenance Graph MVP
- Built the SQLite + NetworkX graph service ingesting git commits, attestations, SBOMs, risk outputs, and releases.
- Exposed lineage, KEV component, and anomaly queries through `backend/api/graph/*` and documented usage patterns.
- Added fixtures and tests to validate ingestion edge cases and query accuracy.

## Phase 5 – Risk Scoring
- Fetched EPSS and CISA KEV feeds, fused them with version lag/exposure hints, and stored the composite FixOpsRisk score.
- Delivered CLI/API surfaces plus documentation for the scoring formula and validation steps.
- Added regression tests for feed parsing and risk scoring heuristics.

## Phase 4 – SBOM Normalisation & Quality
- Normalised CycloneDX/SPDX inputs, deduplicated components, computed quality metrics, and rendered JSON/HTML reports.
- Shipped the `cli/fixops-sbom` command and documentation describing normalization and scoring outputs.
- Added deterministic tests to guarantee reproducible SBOM processing.

## Phase 3 – Cosign-based Signing
- Wrapped cosign in helper scripts, added the signing workflow, and documented verification procedures.
- Ensured release artefacts ship with detached signatures or bundles alongside the provenance attestations.

## Phase 2 – Provenance & SLSA Attestations
- Implemented attestation generation/verification helpers, CLI commands, API endpoints, and release automation.
- Captured the provenance schema, CLI/API usage, and tests covering digest validation flows.

## Phase 1 – Architecture Inventory & Roadmap
- Produced the authoritative architecture inventory (`docs/ARCH-INVENTORY.md`) and the detailed phase plan
  (`docs/TASK-PLAN.md`).
- Updated project documentation to link the new references for reviewer onboarding.

