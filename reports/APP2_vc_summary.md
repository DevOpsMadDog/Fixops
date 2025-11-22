# FixOps Demonstration Run for APP2 Partner Hub — run_id: 91e1f59b-fef7-4637-9d36-0a7ef5a547ab

**Date:** 2025-10-28

## Problem Statement
APP2 powers partner travel offers embedded across customer sites. Missed webhooks in 2023 and a 429 storm in March 2024 exposed reliability and evidentiary gaps. Partners demand proof of webhook integrity, privacy compliance, and near-real-time recovery SLAs.

## Architecture Overview
- Next.js shell orchestrating remote widgets via module federation.
- GraphQL gateway (Apollo) fronting partner REST APIs with persisted queries.
- Kong gateway enforcing auth, SQS queue for webhook ingestion, Lambda transformations.
- Multi-region CloudFront distribution, Secrets Manager storing partner credentials.

## Threat Summary
- Detailed STRIDE/LINDDUN matrix capturing webhook spoofing, CDN tampering, privacy linkability, and DoS threats (`artifacts/threat_matrices/APP2_threat_matrix.md`).
- Backtests include March 2024 rate-limit incident and 2023 webhook credential leak.

## Test Coverage
- **API Contracts:** OpenAPI + AsyncAPI specs covering GraphQL and SNS topics with positive/negative cases.
- **AuthZ Matrix:** Viewer, integration, ops roles with JWT samples.
- **Idempotency:** Session nonce replay and webhook ack dedupe scenarios.
- **Performance:** k6 spike to 300 rps validating adaptive rate limiting.
- **Chaos:** Pod kill, regional edge outage, SQS throttle, partner network partition, disk saturation.
- **Third-Party Simulation:** Valid/invalid signature scripts, 429/500/timeout behaviors validating exponential backoff.

## Critical Findings & Remediation
1. **Webhook Signature Plugin Disabled** — enable Kong HMAC plugin with per-partner secrets and add regression tests.
2. **Partner Secret Stored in Env** — migrate to AWS Secrets Manager via Terraform change (`artifacts/APP2/tf_plan.json`).
3. **SQS DLQ During Chaos** — tune consumer concurrency, add circuit breaker to pause partner retries.

## SLOs Achieved
- Webhook acceptance latency p95 1.2s (target 1.5s) outside failure window.
- Backoff ensures <2% error rate during partner outage replay.
- Recovery MTTR 6 minutes using automated FIS cleanup scripts.

## Auditor Evidence
- `evidence/evidence_bundle_APP2.zip` bundling SBOM, SARIF, tf_plan, policy results, API matrix, k6, chaos, manifest.
- `tests/APP2/partner_simulators` proving partner behavior coverage with signed payloads.
- `artifacts/APP2/decisions.json` capturing gate failures for partner-security and runtime controls.

## FixOps Value vs Apiiro
| Capability | FixOps Delivery | Apiiro Typical Offering |
|------------|----------------|--------------------------|
| Third-Party Validation | Executable simulators + chaos coverage for partner edge cases | Design-time partner mapping via Risk Graph |
| Evidence Bundles | Machine-readable policy + runtime metrics per run | IDE guidance, limited runtime packaging |
| Cost & Deployment | OSS pipeline running in our AWS account | Proprietary SaaS integration |
| Speed to Assurance | Full run (including chaos replay) completed in 41 minutes | Manual exports of partner findings |
| Supply-Chain Attestation | Terraform + Kong diffs packaged with decisions | Focus on code-level remediation suggestions |

**Quote:** “FixOps demonstration run for APP2 — run_id: 91e1f59b-fef7-4637-9d36-0a7ef5a547ab.”

## Funding Ask
Seeking support to scale partner onboarding automation, expand webhook analytics, and co-sell with strategic SI partners. Target: $5M to accelerate enterprise integrations.
