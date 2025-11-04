# FixOps Demonstration Run for APP4 Retail Payments — run_id: 6f05d2e4-1b7d-4d87-a9fa-a9f1c6d25c5b

**Date:** 2025-10-28

## Problem Statement
APP4 powers in-store POS and online checkout for 2,400 retail locations. PCI auditors demand continuous proof that device attestation, tokenization, and settlement controls are enforced. Past pain points: 2024 stolen POS certificates, 2023 settlement mismatch, 2022 API outage from WAF bypass.

## Architecture Overview
- Go checkout API on EKS, Rust edge gateway bridging MQTT.
- Lambda tokenizer using HSM, nightly Python settlement batch.
- MSK event streams, DynamoDB ledger, CloudFront for device updates.

## Threat Summary
- STRIDE/LINDDUN matrix covers device spoofing, settlement tampering, PAN exposure, DoS, and privacy linkability (`artifacts/threat_matrices/APP4_threat_matrix.md`).
- Backtested incidents: POS credential theft, settlement mismatch, WAF outage.

## Test Coverage
- **Contract:** Checkout + settlement OpenAPI spec with device attestation validation.
- **AuthZ:** Device vs finance ops role gating.
- **Idempotency:** Checkout replay & audit log masking tests.
- **Performance:** k6 ramp to 400 VUs matching Black Friday load.
- **Chaos:** Pod kill, AZ outage, MSK broker failure, edge partition, disk full.
- **Policy:** Rego rules blocking plaintext HSM creds, public MQTT, TLS downgrade.

## Critical Findings & Remediation
1. **Plaintext HSM Credential** — move to Secrets Manager; update Terraform per `artifacts/APP4/tf_plan.json`.
2. **MQTT Public Exposure** — tighten security group, enable mutual TLS with device CA.
3. **Broker Lag During Chaos** — increase consumer concurrency, enable partition auto-reassignment.
4. **Log Masking Failure** — implement token scrubber before audit sink.

## SLOs Achieved
- Checkout availability 99.95% during AZ outage replay.
- Offline queue drained within 4 minutes after partition removal.
- Settlement MTTR 12 minutes with automated rollback script.

## Auditor Evidence
- `evidence/evidence_bundle_APP4.zip` packaging SBOM, SARIF, tf_plan, policy results, API matrix, JUnit, k6, chaos, manifest.
- `artifacts/APP4/decisions.json` capturing release block on HSM secret + broker lag.
- `policy/APP4/security_controls.rego` demonstrating PCI-centric policy-as-code.

## FixOps Value vs Apiiro
| Capability | FixOps Delivery | Apiiro Typical Offering |
|------------|----------------|--------------------------|
| PCI Evidence | End-to-end evidence bundle & policy mapping | Risk Graph & IDE remediation |
| Device Attestation | Automated device role tests + chaos offline queue validation | Static design insights |
| Runtime + Supply Chain | Correlated SBOM, SARIF, CNAPP, policy violations | Deep code analysis but limited runtime bundling |
| Cost/Deployment | Runs inside retailer AWS account using OSS stack | Proprietary SaaS | 
| Speed to Evidence | 39-minute run including broker failover replay | Manual evidence compilation |

**Quote:** “FixOps demonstration run for APP4 — run_id: 6f05d2e4-1b7d-4d87-a9fa-a9f1c6d25c5b.”

## Funding Ask
Seeking $6.5M to expand PCI automation packs, integrate device attestation analytics, and accelerate channel partnerships with payment processors.
