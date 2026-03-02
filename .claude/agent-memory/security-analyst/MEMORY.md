# Security Analyst Agent Memory

## Key File Locations
- **Crypto module**: `suite-core/core/crypto.py` (583 LOC) — RSAKeyManager, RSASigner, RSAVerifier
- **Evidence router**: `suite-evidence-risk/api/evidence_router.py` (~1700 LOC) — export, verify, status endpoints
- **SAST engine**: `suite-core/core/sast_engine.py` (~1500 LOC) — 110 rules, OWASP coverage
- **Compliance engine router**: `suite-evidence-risk/api/compliance_engine_router.py`
- **App entry**: `suite-api/apps/api/app.py` — evidence_router mounted at `/api/v1`
- **Middleware**: `suite-api/apps/api/middleware.py` — CorrelationId, RequestLogging, SecurityHeaders
- **PersistentDict**: `suite-core/core/persistent_store.py` — table name validation added 2026-03-02
- **Scanner parsers**: `suite-core/core/scanner_parsers.py` — defusedxml.defuse_stdlib() at module load

## DEMO-011 Status
- Evidence export is COMPLETE and VERIFIED (24/24 tests pass, last verified 2026-03-03)
- Endpoints: POST /evidence/export, POST /evidence/export/verify, GET /evidence/export/status
- Signing: RSA-SHA256 PKCS1v15 via core.crypto module
- Frameworks: SOC2 (22 controls), PCI-DSS (13 reqs), HIPAA (11 safeguards) + ISO27001, NIST-CSF, NIST-800-53

## Bandit Scan Patterns (477 total, STABLE since 2026-03-02)
- B608 (SQL injection) — 27 hits — ALL false positives (parameterized queries with ?)
- B310 (url open) — 15 hits — intentional URL opens in CLI/single_agent
- B108 (temp file) — 14 hits — sandbox/test code, acceptable
- B314 (XML) — 1 hit — false positive, defusedxml.defuse_stdlib() at module load
- B113 (no timeout) — 1 hit — in test file only
- .env files are NOT tracked by git (gitignore covers *.env)
- All HIGH findings fixed: MD5 usedforsecurity=False in id_allocator.py:23 (2026-03-02)

## Native SAST Dogfooding API
- SASTEngine API: `get_rule_count()`, `scan_code()`, `scan_files()`, `get_owasp_coverage()`
- scan_code() returns `SastScanResult` object with `.findings` list
- SastFinding uses: `.severity.name` for string, `.severity.value` for lowercase, `.line_number` (NOT `.line`)
- Finding attributes: rule_id, title, severity, cwe_id, language, file_path, line_number, column, snippet, message, fix_suggestion, confidence, finding_id, timestamp
- 38 CRITICAL/HIGH all false positives: SAST rule pattern strings, defensive code, auth at mount level
- False positives tracked in `.claude/team-state/false-positives.json`

## Dependency Management
- pip-audit is the primary dependency scanner — 4th consecutive clean day as of 2026-03-03
- Always check cryptography, pypdf, black for CVEs — they update frequently
- defusedxml v0.7.1 installed but NOT in requirements.txt — consider adding

## Security Fixes Applied
- SecurityHeadersMiddleware added (2026-03-03) — 7 OWASP headers on all responses, 9 tests
- docker-compose.aldeci-complete.yml hardened (2026-03-03) — weak defaults removed
- id_allocator.py:23 — MD5 usedforsecurity=False added (2026-03-02)
- mpte_router.py:45 — hardcoded api_key removed, uses os.getenv
- crypto.py — Path() guard in _load_or_generate_keys
- persistent_store.py — table name regex validation (defense-in-depth)
- requirements.txt — cryptography minimum bumped to >=46.0.5
- Docker: non-root user, .dockerignore excludes .env, entrypoint random tokens

## Test Patterns
- Evidence export: `tests/test_evidence_export_signed.py` (24 tests, ~17s)
- Security headers: `tests/test_security_headers.py` (9 tests, <1s)
- SAST: `tests/test_sast_rules_expanded.py` (75) + `tests/test_sast_engine_unit.py` (33)
- App creation ~3s (loads all 50+ routers)
- Coverage gate 25%, currently ~16-19% depending on scope — not our problem to fix

## Docker Security (2026-03-03)
- Dockerfile, Dockerfile.enterprise: USER aldeci, non-root
- Dockerfile.aldeci-ui: USER nginx
- MPTE containers: Docker socket mount + root — ACCEPTED RISK (required for micro-pentest)
- docker-compose.aldeci-complete.yml: weak defaults REMOVED (SECRET_KEY, JWT_SECRET, ADMIN_PASSWORD)
- .dockerignore excludes .env files

## Advisory Status
- Advisory 001 (env secrets): .env excluded from git, Docker random tokens. OpenAI key rotation pending CEO.
- Advisory 002 (Docker hardening): Weak defaults removed. Docker socket accepted risk. Published 2026-03-03.
