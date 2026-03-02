# Security Analyst Agent Memory

## Key File Locations
- **Crypto module**: `suite-core/core/crypto.py` (583 LOC) — RSAKeyManager, RSASigner, RSAVerifier
- **Evidence router**: `suite-evidence-risk/api/evidence_router.py` (~1700 LOC) — export, verify, status endpoints
- **SAST engine**: `suite-core/core/sast_engine.py` (~1500 LOC) — 110 rules, OWASP coverage
- **Compliance engine router**: `suite-evidence-risk/api/compliance_engine_router.py`
- **App entry**: `suite-api/apps/api/app.py` — evidence_router mounted at `/api/v1`
- **PersistentDict**: `suite-core/core/persistent_store.py` — table name validation added 2026-03-02
- **Scanner parsers**: `suite-core/core/scanner_parsers.py` — defusedxml.defuse_stdlib() at module load

## DEMO-011 Status
- Evidence export is COMPLETE and VERIFIED (24/24 tests pass)
- Endpoints: POST /evidence/export, POST /evidence/export/verify, GET /evidence/export/status
- Signing: RSA-SHA256 PKCS1v15 via core.crypto module
- Frameworks: SOC2 (22 controls), PCI-DSS (13 reqs), HIPAA (11 safeguards) + ISO27001, NIST-CSF, NIST-800-53

## Bandit Scan Patterns (477 total as of 2026-03-02)
- B608 (SQL injection) — 27 hits — ALL false positives (parameterized queries with ?)
- B310 (url open) — 15 hits — intentional URL opens in CLI/single_agent
- B108 (temp file) — 14 hits — sandbox/test code, acceptable
- B314 (XML) — 1 hit — false positive, defusedxml.defuse_stdlib() at module load
- .env files are NOT tracked by git (gitignore covers *.env)
- All HIGH findings fixed: MD5 usedforsecurity=False in id_allocator.py:23 (2026-03-02)

## Native SAST Dogfooding (1990 findings, 2026-03-02)
- SASTEngine API: `get_rule_count()`, `scan_code()`, `scan_files()`, `get_owasp_coverage()`
- SastFinding uses enum attributes (SastSeverity.HIGH), not strings — use `.value` for comparison
- 38 CRITICAL all false positives: SAST rule pattern strings, defensive code, auth at mount level
- 3 actionable HIGH: SAST-020 (file upload), SAST-039 (CRLF), SAST-103 (entropy)
- False positives tracked in `.claude/team-state/false-positives.json`

## Dependency Management
- Always check cryptography, pypdf, black for CVEs — they update frequently
- pip-audit is the primary dependency scanner
- defusedxml v0.7.1 installed but NOT in requirements.txt — consider adding

## Security Fixes Applied
- id_allocator.py:23 — MD5 usedforsecurity=False added (2026-03-02)
- mpte_router.py:45 — hardcoded api_key removed, uses os.getenv
- crypto.py — Path() guard in _load_or_generate_keys
- persistent_store.py — table name regex validation (defense-in-depth)
- requirements.txt — cryptography minimum bumped to >=46.0.5
- Docker: non-root user, .dockerignore excludes .env, entrypoint random tokens

## Test Patterns
- Evidence export: `tests/test_evidence_export_signed.py` (24 tests, ~17s)
- SAST: `tests/test_sast_rules_expanded.py` (75) + `tests/test_sast_engine_unit.py` (33)
- App creation ~3s (loads all 50+ routers)
- Coverage gate 25%, currently ~19% — not our problem to fix

## Docker Security Findings (2026-03-02)
- Dockerfile, Dockerfile.enterprise: USER aldeci ✅, non-root
- Dockerfile.aldeci-ui: USER nginx ✅
- Sidecar Dockerfiles: demo tokens hardcoded (FIXOPS_API_TOKEN=demo-token) — acceptable, overridden at runtime
- No privileged containers, no cap_add, no Docker socket mounts
- .dockerignore excludes .env files

## Advisory 001 Status (2026-03-02)
- .env excluded from git: ✅ | .env.example created: ✅
- Docker random tokens: ✅ | Non-root container: ✅
- OpenAI key rotation: ⚠️ Pending CEO | JWT secret: ⚠️ Mitigated
