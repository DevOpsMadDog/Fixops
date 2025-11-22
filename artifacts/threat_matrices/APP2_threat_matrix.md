# APP2 Partner Hub - Threat & Attack Matrix

| Threat | Framework | Objective | Attack Vector | Mitigations | Tests |
|--------|-----------|-----------|---------------|-------------|-------|
| APP2-T1 | STRIDE (Spoofing) | Inject fraudulent bookings via fake webhook | HMAC forged using leaked secret | Rotate partner secrets, strict timestamp drift, replay cache | `tests/APP2/partner_simulators/valid_signature.py` |
| APP2-T2 | STRIDE (Tampering) | Modify offer payload to include malicious URLs | CDN MITM / compromised edge worker | TLS 1.3 enforcement, signed payloads | `tests/APP2/contract_tests/openapi.yaml` |
| APP2-T3 | STRIDE (Information Disclosure) | Leak embargoed offers | Misconfigured Kong route with wildcard path | Zero-trust route policies, authz regression | `tests/APP2/authz_tests/matrix.csv` |
| APP2-T4 | STRIDE (DoS) | Overload GraphQL gateway | Botnet hitting persisted query IDs | Adaptive rate limiting, circuit breakers | `tests/APP2/perf_k6.js` |
| APP2-L1 | LINDDUN (Linkability) | Associate partner user IDs across campaigns | Analytics token re-use | Token rotation, privacy budget enforcement | `tests/APP2/idempotency_tests/session_replay.yaml` |
| APP2-L2 | LINDDUN (Detectability) | Infer partner contract tier | Response size/time differences | Response padding, caching | `tests/APP2/perf_k6.js` |
| APP2-L3 | LINDDUN (Non-compliance) | Miss GDPR deletion SLA | Queue backlog delaying delete events | Queue drain monitors, deletion tests | `artifacts/APP2/run_manifest.json` |

## Backtesting
- Replayed March 2024 partner outage (HTTP 429 storm) verifying new exponential backoff.
- Simulated 2023 webhook credential leak; secret rotation + signature validation blocked forged requests.
