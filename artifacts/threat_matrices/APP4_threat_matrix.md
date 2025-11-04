# APP4 Retail Payments - Threat & Attack Matrix

| Threat | Framework | Objective | Vector | Mitigation | Test |
|--------|-----------|-----------|--------|------------|------|
| APP4-T1 | STRIDE (Spoofing) | Submit fraudulent transactions | Stolen device certificates | Mutual TLS, device attestation, revocation lists | `tests/APP4/authz_tests/matrix.csv` |
| APP4-T2 | STRIDE (Tampering) | Modify settlement totals | Compromise batch job container | Signed pipelines, runtime attestation | `policy/APP4/security_controls.rego` |
| APP4-T3 | STRIDE (Information Disclosure) | Exfiltrate PAN tokens | Plaintext HSM credentials | Secrets manager, KMS envelope encryption | `artifacts/APP4/tf_plan.json` |
| APP4-T4 | STRIDE (DoS) | Checkout outage | API flooding | WAF rules, adaptive rate limiting | `tests/APP4/perf_k6.js` |
| APP4-L1 | LINDDUN (Linkability) | Link purchases to individuals | Combine receipt + inventory events | Pseudonymization, minimal logging | `tests/APP4/contract_tests/openapi.yaml` |
| APP4-L2 | LINDDUN (Non-compliance) | Breach PCI logging | Unmasked tokens in logs | Log scrubbers, audit tests | `tests/APP4/idempotency_tests/audit_logs.yaml` |

Backtests: 2024 POS credential theft, 2023 settlement mismatch, 2022 WAF bypass outage.
