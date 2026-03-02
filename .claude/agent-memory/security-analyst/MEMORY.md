# Security Analyst Agent Memory

## Key File Locations
- **Crypto module**: `suite-core/core/crypto.py` (583 LOC) — RSAKeyManager, RSASigner, RSAVerifier
- **Evidence router**: `suite-evidence-risk/api/evidence_router.py` (~1700 LOC) — export, verify, status endpoints
- **SAST engine**: `suite-core/core/sast_engine.py` (~1500 LOC) — 110 rules, OWASP coverage
- **Compliance engine router**: `suite-evidence-risk/api/compliance_engine_router.py`
- **App entry**: `suite-api/apps/api/app.py` — evidence_router mounted at `/api/v1`, global exception handler added
- **Middleware**: `suite-api/apps/api/middleware.py` — CorrelationId, RequestLogging, SecurityHeaders (9 headers)
- **PersistentDict**: `suite-core/core/persistent_store.py` — table name validation added 2026-03-02
- **Scanner parsers**: `suite-core/core/scanner_parsers.py` — defusedxml.defuse_stdlib() at module load
- **Trend analyzer**: `suite-core/core/ml/trend_analyzer.py` — MD5 fixed 2026-03-03

## DEMO-011 Status
- Evidence export is COMPLETE and VERIFIED (24/24 tests pass, last verified 2026-03-03 Run 7)
- Endpoints: POST /evidence/export, POST /evidence/export/verify, GET /evidence/export/status
- Signing: RSA-SHA256 PKCS1v15 via core.crypto module
- Frameworks: SOC2 (22 controls), PCI-DSS (13 reqs), HIPAA (11 safeguards) + ISO27001, NIST-CSF, NIST-800-53

## Bandit Scan Patterns (477 total, 0 HIGH — STABLE since 2026-03-03)
- B608 (SQL injection) — 27 hits — ALL false positives (parameterized queries with ?)
- B310 (url open) — 15 hits — intentional URL opens in CLI/single_agent
- B108 (temp file) — 14 hits — sandbox/test code, acceptable
- B314 (XML) — 1 hit — false positive, defusedxml.defuse_stdlib() at module load
- B113 (no timeout) — 1 hit — in test file only
- .env files are NOT tracked by git (gitignore covers *.env)
- **Bandit progress bar pollutes stdout JSON** — redirect stderr separately, use `tail -n +2` to strip

## Bandit Gotcha: Progress Bar in JSON Output
- `bandit -f json > out.json 2>/dev/null` still puts progress bar on line 1 of stdout
- Fix: `tail -n +2 out.json` to strip the progress bar before JSON parsing
- Alternative: pipe through `python3 -c` with `data.find('{')` to skip prefix

## Native SAST Dogfooding API
- SASTEngine API: `get_rule_count()`, `scan_code()`, `scan_files()`, `get_owasp_coverage()`
- **scan_code() signature**: `(code: str, filename: str = 'input.py')` — NO `language` param
- scan_code() returns `SastScanResult` object with `.findings` list
- SastFinding uses: `.severity.name` for string, `.severity.value` for lowercase, `.line_number` (NOT `.line`)
- 35 CRITICAL/HIGH all false positives: SAST rule pattern strings, defensive code, auth at mount level

## Dependency Management
- pip-audit is the primary dependency scanner — 5th consecutive clean day as of 2026-03-03
- Always check cryptography, pypdf, black for CVEs — they update frequently
- defusedxml v0.7.1 NOW in requirements.txt (added 2026-03-03)

## Security Fixes Applied
- SecurityHeadersMiddleware enhanced (2026-03-03) — 9 OWASP headers (+CSP, +X-XSS-Protection), 11 tests
- Global exception handler added (2026-03-03) — prevents info leakage in 500s
- trend_analyzer.py — 6x MD5 usedforsecurity=False (2026-03-03)
- defusedxml added to requirements.txt (2026-03-03)
- docker-compose.aldeci-complete.yml hardened (2026-03-03) — weak defaults removed
- id_allocator.py:23 — MD5 usedforsecurity=False added (2026-03-02)
- mpte_router.py:45 — hardcoded api_key removed, uses os.getenv
- crypto.py — Path() guard in _load_or_generate_keys
- persistent_store.py — table name regex validation (defense-in-depth)
- requirements.txt — cryptography minimum bumped to >=46.0.5
- Docker: non-root user, .dockerignore excludes .env, entrypoint random tokens

## Test Patterns
- Evidence export: `tests/test_evidence_export_signed.py` (24 tests, ~17s)
- Security headers: `tests/test_security_headers.py` (11 tests, <1s)
- SAST: `tests/test_sast_rules_expanded.py` (75) + `tests/test_sast_engine_unit.py` (33)
- App creation ~3s (loads all 50+ routers), 782 routes
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

## SSRF Protections (verified 2026-03-03)
- dast_router.py has comprehensive SSRF blocklist: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16, fc00::/7
- Blocked hosts include: localhost, metadata.google.internal, 169.254.169.254
- URL validation: must start with http/https, checked via `_is_safe_url()`
