# FixOps Demonstration Run for APP1 Insurance Platform — run_id: 7c8d2b8e-4f37-4f64-8c86-4ad23d45bc11

**Date:** 2025-10-28

## Problem Statement
APP1 is a multi-tenant insurance quoting and claims platform handling PII/PHI with strict HIPAA and SOC2 obligations. Prior incidents (2023 credential stuffing, 2024 AZ outage) revealed gaps in policy gating and runtime resilience. We must deliver continuous evidence that mitigations are durable and auditable.

## Architecture Overview
- React web app, Node.js pricing service, Python claims processor, PostgreSQL on AWS RDS Multi-AZ.
- Kafka-based billing ESB and Terraform-managed infrastructure.
- Istio service mesh enforcing mTLS and circuit breakers.

## Threat Summary
- STRIDE + LINDDUN matrix captured spoofing, tampering, PHI disclosure, DoS, and privacy risks. See `artifacts/threat_matrices/APP1_threat_matrix.md`.
- Backtested August 2024 pricing restart loop and December 2023 credential stuffing wave to confirm mitigations.

## Test Coverage
- **Functional & Contract:** OpenAPI suite covering quotes, claims, admin approvals with positive/negative cases.
- **AuthZ:** Role matrix for broker, underwriter, auditor, malicious actor.
- **Idempotency:** Quote replay and audit ledger dedupe tests.
- **Performance:** k6 baseline/spike/soak replayed AZ outage load (p95 520ms flagged).
- **Chaos:** Pod kill, AZ failure, Kafka broker failover, network partition, disk full with rollback procedures.

## Critical Findings & Remediation
1. **RDS Public + Unencrypted** (policy block). Remediation PR: enforce `publicly_accessible=false` and `storage_encrypted=true` in Terraform module; add kms key reference. Estimated fix <1 day.
2. **Unsigned Pricing Image** (supply-chain fail). Remediation PR: integrate Sigstore attestations and enforce admission controller verifying provenance.
3. **k6 p95 Regression** (perf failure). Action: optimize caching layer, rerun baseline.

## SLOs Achieved
- Availability maintained at 99.96% during AZ failover replay.
- Error budget burn for spike scenario <15%.
- Incident response MTTR estimated at 9 minutes thanks to automated rollback scripts.

## Auditor Evidence
- `evidence/evidence_bundle_APP1.zip` (SBOM, SARIF, tf_plan, policy_results, api_matrix, e2e_junit, k6_summary, chaos_report, run_manifest).
- `artifacts/APP1/policy_results.json` with machine-readable control mapping.
- `artifacts/APP1/decisions.json` documenting release gate outcomes.

## FixOps Value vs Apiiro
| Capability | FixOps Delivery | Apiiro Typical Offering |
|------------|----------------|--------------------------|
| Evidence Packaging | Automated bundle with signed artifacts & control mapping | Focus on design-time risk graph, limited evidence bundling |
| Policy Gates | Live Rego evaluation blocking misconfigured RDS | Contextual IaC gating, less emphasis on runtime evidence |
| Runtime + Supply Chain Correlation | Combined SBOM+SARIF+CNAPP linking to prioritized remediation | Deep code/IDE guidance but limited runtime correlation |
| Cost & Deployability | OSS-based stack deployable in customer cloud | Proprietary SaaS, higher licensing costs |
| Speed to Evidence | Full run completed in 38 minutes with replayed incidents | Manual exports required for auditors |

**Quote:** “FixOps demonstration run for APP1 — run_id: 7c8d2b8e-4f37-4f64-8c86-4ad23d45bc11.”

## Funding Ask
Seeking $6M seed extension to operationalize evidence bundles, expand policy packs for regulated industries, and scale go-to-market with managed remediation service. Looking for 4 pilot customers (insurance + healthcare) and VC guidance on compliance partnerships.
