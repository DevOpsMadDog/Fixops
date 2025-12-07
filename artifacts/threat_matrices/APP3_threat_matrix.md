# APP3 Healthcare Portal - Threat & Attack Matrix

| Threat | Framework | Objective | Attack Vector | Mitigation | Test |
|--------|-----------|-----------|---------------|------------|------|
| APP3-T1 | STRIDE (Spoofing) | Gain access to PHI via clinician impersonation | Compromised Azure AD credentials | Conditional access, hardware MFA | `tests/APP3/authz_tests/matrix.csv` |
| APP3-T2 | STRIDE (Tampering) | Modify patient record to falsify history | Exploit FHIR search injection | Signed audit ledger, parameterized queries | `tests/APP3/idempotency_tests/audit_append.yaml` |
| APP3-T3 | STRIDE (Information Disclosure) | Leak remote monitoring telemetry | Public admin ingress | Network policies, WAF, TLS 1.2+ | `policy/APP3/security_controls.rego` |
| APP3-T4 | STRIDE (DoS) | Exhaust FHIR gateway resources | Wildcard queries, patient export loops | Query throttles, caching | `tests/APP3/perf_k6.js` |
| APP3-L1 | LINDDUN (Linkability) | Link wearable metrics to identity | Cross-service correlation | Noise injection + pseudonyms | `tests/APP3/contract_tests/openapi.yaml` |
| APP3-L2 | LINDDUN (Non-compliance) | Break HIPAA audit logging | Unsigned audit entries | Hardware signing & immutable ledger | `tests/APP3/idempotency_tests/audit_append.yaml` |
| APP3-L3 | LINDDUN (Detectability) | Detect mental health visits | Timing side-channels | Uniform response times | `tests/APP3/perf_k6.js` |

Backtests: March 2025 FHIR wildcard abuse incident, 2024 admin ingress misconfiguration, 2023 audit ledger tampering attempt.
