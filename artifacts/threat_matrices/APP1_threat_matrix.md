# APP1 Insurance Platform - Threat & Attack Matrix

| Threat ID | Framework | Category | Attacker Objective | Attack Vector | Mitigations | Validation |
|-----------|-----------|----------|--------------------|---------------|------------|-----------|
| APP1-T1 | STRIDE (Spoofing) | Identity Abuse | Steal competitor quotes by impersonating brokers | Credential stuffing via leaked broker emails | Enforce MFA, rate-limit login, anomaly detection | `tests/APP1/authz_tests/matrix.csv` |
| APP1-T2 | STRIDE (Tampering) | Code Integrity | Manipulate pricing model to offer fraudulent discounts | Supply chain compromise of pricing container image | Signed builds, admission controller, provenance attestation | `tests/APP1/chaos_playbooks/pipeline_supply_chain.md` |
| APP1-T3 | STRIDE (Repudiation) | Audit Evasion | Remove approval records to hide insider fraud | Abuse admin API to delete audit entries | Write-once audit store, approval workflow ledger | `tests/APP1/idempotency_tests/audit_replay.yaml` |
| APP1-T4 | STRIDE (Information Disclosure) | PHI Exposure | Exfiltrate policyholder SSNs | Public LoadBalancer on postgres service | Private subnets, service mesh mtls, network policies | `policy/APP1/deny_public_db.rego` |
| APP1-T5 | STRIDE (DoS) | Availability | Disrupt quote generation before renewal deadlines | Botnet API flooding | Global rate-limits, autoscaling, WAF challenge | `tests/APP1/perf_k6.js` |
| APP1-P1 | LINDDUN (Linkability) | Privacy | Link anonymized claims to individuals | Cross-correlation of analytics exports | Tokenization, aggregated reporting windows | `tests/APP1/contract_tests/openapi.yaml` |
| APP1-P2 | LINDDUN (Detectability) | Timing | Infer claim approval status by timing responses | Response time side-channels | Constant-time risk scoring, caching | `tests/APP1/perf_k6.js` |
| APP1-P3 | LINDDUN (Non-compliance) | Governance | Fail HIPAA retention obligations | Improper logging pipeline | Centralized logging, retention policy tests | `artifacts/APP1/run_manifest.json` |

## Test Mapping

- **Functional**: Contract tests cover quote, claim, billing flows with positive & negative cases.
- **Security**: AuthZ matrix covers broker, admin, auditor, and malicious roles.
- **Performance**: k6 scenarios for steady, spike, and failover loads with backtesting from Q2 incidents.
- **Chaos**: Pod kill, AZ failure, and DB failover validated with automated rollback scripts.

## Backtesting Notes

- Replayed the August 2024 outage (pricing pod restart loop) to confirm autoscaler mitigation.
- Simulated 2023 credential stuffing incident; MFA coverage prevented replay success.
