# FixOps Demonstration Run for APP3 Healthcare Portal — run_id: f0f7c1bc-5b6c-4dd6-8f1a-6a361d02cd8d

**Date:** 2025-10-28

## Problem Statement
APP3 delivers HIPAA-regulated patient portal and FHIR APIs. Past incidents: 2025 FHIR wildcard abuse causing CPU saturation, 2024 public admin ingress exposing PHI, 2023 audit tampering attempt. Healthcare compliance teams demand verifiable evidence that mitigations work end-to-end.

## Architecture Overview
- Angular portal -> Spring Boot FHIR gateway -> EMR integration.
- Kafka HL7 ingestion, Python ML triage service, CosmosDB audit ledger.
- Azure AD B2C for patients, conditional access for clinicians.

## Threat Summary
- STRIDE/LINDDUN mapping for clinician spoofing, audit tampering, PHI leakage, DoS, privacy linkability (`artifacts/threat_matrices/APP3_threat_matrix.md`).
- Backtested 2025 FHIR abuse & 2024 ingress misconfiguration.

## Test Coverage
- **Contract:** FHIR OpenAPI spec with positive, invalid, unauthorized cases.
- **AuthZ:** Clinician, patient, auditor role matrix w/ JWT examples.
- **Idempotency:** Audit ledger append and FHIR patient creation with If-None-Exist semantics.
- **Performance:** k6 surge scenario replicating mass patient exports.
- **Chaos:** Pod kill, Azure region outage, Kafka broker failure, EMR partition, CosmosDB disk saturation.
- **Partner Simulation:** HL7 HMAC scripts for valid/invalid/429/500/timeout behaviors.

## Critical Findings & Remediation
1. **Spring Boot CVE-2024-34145** — upgrade to 3.3.4, redeploy signed image, re-run SAST.
2. **Public Admin Ingress** — apply network policy, restrict AKS API server IP ranges (see `artifacts/APP3/tf_plan.json`).
3. **Cosmos Throttling During Disk Chaos** — increase autoscale max RU + implement ledger backpressure alerts.

## SLOs Achieved
- During region outage: availability 99.94%, recovery 108s.
- Audit ledger append latency p95 210ms (target 250ms).
- HL7 ingest backlog cleared within 11 minutes post chaos.

## Auditor Evidence
- `evidence/evidence_bundle_APP3.zip` containing SBOM, SARIF, tf_plan, policy results, API matrix, JUnit, k6, chaos, manifest.
- `artifacts/APP3/decisions.json` documenting release block due to CVE + ingress.
- `tests/APP3/partner_simulators` showcasing HL7 contract testing assets.

## FixOps Value vs Apiiro
| Capability | FixOps Delivery | Apiiro Typical Offering |
|------------|----------------|--------------------------|
| HIPAA Evidence | Bundled artifacts aligned to control IDs with machine-readable policy results | Design-time risk insights & IDE fixes |
| Runtime Assurance | Chaos + performance data correlated with SBOM and CNAPP findings | Strong code analysis but limited runtime attestations |
| Compliance Mapping | run_manifest.json with traceable backtests and audit ledger checks | Risk Graph, limited attestation packaging |
| Deployment Model | Self-hosted pipeline inside Azure tenancy | Proprietary SaaS |
| Speed to Evidence | 44-minute run including region failover replay | Manual exports needed for auditors |

**Quote:** “FixOps demonstration run for APP3 — run_id: f0f7c1bc-5b6c-4dd6-8f1a-6a361d02cd8d.”

## Funding Ask
Requesting $7.5M to expand healthcare compliance accelerators, integrate automated HIPAA evidence mapping, and pursue strategic partnerships with EHR vendors.
