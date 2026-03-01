# Security Analyst Agent Memory

## Key File Locations
- **Crypto module**: `suite-core/core/crypto.py` (583 LOC) — RSAKeyManager, RSASigner, RSAVerifier
- **Evidence router**: `suite-evidence-risk/api/evidence_router.py` (~1700 LOC) — export, verify, status endpoints
- **SAST engine**: `suite-core/core/sast_engine.py` (~1500 LOC) — 110 rules, OWASP coverage
- **Compliance engine router**: `suite-evidence-risk/api/compliance_engine_router.py`
- **App entry**: `suite-api/apps/api/app.py` — evidence_router mounted at `/api/v1`

## DEMO-011 Status
- Evidence export is COMPLETE and VERIFIED (24/24 tests pass)
- Endpoints: POST /evidence/export, POST /evidence/export/verify, GET /evidence/export/status
- Signing: RSA-SHA256 PKCS1v15 via core.crypto module
- Frameworks: SOC2 (22 controls), PCI-DSS (13 reqs), HIPAA (11 safeguards) + ISO27001, NIST-CSF, NIST-800-53

## Bandit Scan Patterns
- B608 (SQL injection) is the top finding (27 hits) — mostly string-based SQL in exposure_case.py and connectors.py
- .env files are NOT tracked by git (gitignore covers *.env)
- Previous run fixed all HIGH findings (MD5 usedforsecurity=False)

## Security Fixes Applied
- mpte_router.py:45 — hardcoded `api_key="change-me"` → `os.getenv("MPTE_API_KEY", "")`
- crypto.py — Path() guard in _load_or_generate_keys (fixed in earlier run)

## Test Patterns
- Evidence export tests: `tests/test_evidence_export_signed.py` (24 tests, ~16s to run)
- SAST tests: `tests/test_sast_rules_expanded.py` (75 tests) + `tests/test_sast_engine_unit.py` (33 tests)
- App creation takes ~3s (loads all 50+ routers)
