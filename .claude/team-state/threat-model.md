# ALdeci Threat Model — 2026-03-03

> **Updated by**: security-analyst
> **Methodology**: STRIDE + Risk Matrix (Likelihood x Impact, 1-5 scale)
> **Scope**: ALdeci CTEM+ platform (all suites)
> **Pillars Served**: [V3] Decision Intelligence, [V5] MPTE, [V7] MCP, [V10] Evidence

## Executive Summary

| Metric | Value | Trend |
|--------|-------|-------|
| Total attack surfaces | 8 | Stable |
| CRITICAL risks | 0 (was 2) | ↓ Improving |
| HIGH risks | 2 | ↓ Improving |
| MEDIUM risks | 4 | Stable |
| LOW risks | 2 | Stable |
| Dependency CVEs | 0 (4th clean day) | ✅ Fixed |
| Bandit HIGH findings | 0 | ✅ Clean |
| Security headers | 7 (NEW) | ✅ Added |

## Attack Surfaces

### 1. API Gateway (suite-api, 769 endpoints) [V3][V7]
| Threat (STRIDE) | Description | L | I | Risk | Mitigation | Status |
|-----------------|-------------|---|---|------|------------|--------|
| Spoofing | API key / JWT bypass | 2 | 5 | 10/HIGH | JWT + X-API-Key auth on all routes | ✅ Mitigated |
| Tampering | Request body manipulation | 3 | 4 | 12/HIGH | Pydantic v2 input validation + type coercion | ✅ Mitigated |
| Tampering | Clickjacking via iframe embed | 1 | 3 | 3/LOW | X-Frame-Options: DENY + SecurityHeadersMiddleware | ✅ Mitigated (NEW) |
| Repudiation | Action denial | 2 | 3 | 6/MED | Audit logging via Event Bus + structlog | ✅ Mitigated |
| Info Disclosure | Error messages leak internals | 2 | 3 | 6/MED | Custom error handlers (backend-hardener) | ✅ Mitigated |
| Info Disclosure | MIME sniffing attacks | 1 | 3 | 3/LOW | X-Content-Type-Options: nosniff | ✅ Mitigated (NEW) |
| DoS | Rate limiting bypass | 2 | 4 | 8/MED | Rate limiter middleware (120 req/min) | ✅ Mitigated |
| Elevation | Scope escalation | 2 | 5 | 10/HIGH | Scope-based access control | ✅ Mitigated |

### 2. Evidence Export (/api/v1/evidence/export) [V10]
| Threat | Description | L | I | Risk | Mitigation | Status |
|--------|-------------|---|---|------|------------|--------|
| Tampering | Bundle content modification | 1 | 5 | 5/MED | RSA-SHA256 PKCS1v15 signing + SHA-256 hash | ✅ Mitigated |
| Repudiation | Signing key dispute | 1 | 4 | 4/LOW | Key fingerprint in metadata + bundle_id tracking | ✅ Mitigated |
| Info Disclosure | Sensitive data in bundle | 2 | 4 | 8/MED | Scope-based evidence filtering | ✅ Mitigated |
| **VERIFIED**: 24/24 tests pass, RSA-SHA256 signing E2E verified | | | | | |

### 3. Scanner Engines (SAST/DAST/Secrets/Container/CSPM) [V3][V7]
| Threat | Description | L | I | Risk | Mitigation | Status |
|--------|-------------|---|---|------|------------|--------|
| Tampering | Scan result injection via XML | 1 | 4 | 4/LOW | defusedxml.defuse_stdlib() + size limits | ✅ Mitigated |
| Tampering | Scan result injection via JSON | 1 | 3 | 3/LOW | JSON size limit (100MB) + schema validation | ✅ Mitigated |
| Info Disclosure | Source code in SAST results | 2 | 3 | 6/MED | Line-level excerpts only | ✅ Mitigated |

### 4. Scanner Ingest API (POST /api/v1/scanner-ingest/upload) [V7]
| Threat | Description | L | I | Risk | Mitigation | Status |
|--------|-------------|---|---|------|------------|--------|
| Tampering | Path traversal via filename | 2 | 5 | 10/HIGH | `_sanitize_bundle_id()` + `verify_allowlisted_path()` | ✅ Mitigated |
| DoS | Billion-laughs XML attack | 2 | 3 | 6/MED | XML size limit (100MB) + defusedxml | ✅ Mitigated |
| DoS | Large file upload | 3 | 3 | 9/MED | FastAPI body size limits configured | ⚠️ Verify limit |

### 5. Secrets in Repository
| Threat | Description | L | I | Risk | Mitigation | Status |
|--------|-------------|---|---|------|------------|--------|
| Info Disclosure | API keys in .env | 2 | 4 | 8/MED | .env git-ignored, not in index, Docker generates random tokens | ⚠️ Pending key rotation |
| Elevation | JWT secret weak | 2 | 4 | 8/MED | Docker entrypoint generates random if not set; "demo-secret" in local .env only | ⚠️ Pending rotation |
| **IMPROVED**: Was CRITICAL (25/25), now MEDIUM (8/25) after .gitignore + Docker fixes |

### 6. Database Layer (SQLite WAL, 56 .db files)
| Threat | Description | L | I | Risk | Mitigation | Status |
|--------|-------------|---|---|------|------------|--------|
| Injection | SQL injection via raw queries | 1 | 5 | 5/MED | Parameterized queries verified in all modules + PersistentDict table name validation | ✅ Mitigated |
| Info Disclosure | DB files readable | 3 | 3 | 9/MED | File permissions (0600) needed | ⚠️ Review needed |
| DoS | WAL lock contention | 2 | 3 | 6/MED | WAL mode enables concurrent reads | ✅ Mitigated |

### 7. Docker Deployment [V9]
| Threat | Description | L | I | Risk | Mitigation | Status |
|--------|-------------|---|---|------|------------|--------|
| Elevation | Container runs as root | 1 | 4 | 4/LOW | ✅ Dockerfile uses `USER aldeci` (non-root) | ✅ Mitigated |
| Info Disclosure | Secrets in Docker env | 1 | 4 | 4/LOW | ✅ .dockerignore excludes .env, entrypoint generates random tokens | ✅ Mitigated |
| Spoofing | Weak default passwords | 1 | 4 | 4/LOW | ✅ Removed weak defaults from compose (SECRET_KEY, JWT_SECRET, ADMIN_PASSWORD) | ✅ Mitigated (NEW) |
| Elevation | Docker socket mount | 2 | 5 | 10/HIGH | MPTE design requirement — accepted risk with network isolation | ⚠️ Accepted |

### 8. MPTE Micro-Pentest Engine [V5]
| Threat | Description | L | I | Risk | Mitigation | Status |
|--------|-------------|---|---|------|------------|--------|
| Elevation | Sandbox escape during PoC | 2 | 5 | 10/HIGH | Docker sandbox isolation in sandbox_verifier.py | ✅ Mitigated |
| Info Disclosure | Target system data leakage | 2 | 4 | 8/MED | Scoped test execution with cleanup | ✅ Mitigated |
| DoS | Resource exhaustion during pentest | 2 | 3 | 6/MED | Timeout controls (10s default) | ✅ Mitigated |

## Risk Heat Map (2026-03-03)
```
Impact 5 |  .  ■  .  .  .     ■=Mitigated HIGH (API auth, path traversal, sandbox)
Impact 4 |  ■  ■  .  .  .     ■=Mitigated MEDIUM (secrets pending rotation)
Impact 3 |  .  ■  ■  .  .     ■=Mitigated LOW
Impact 2 |  .  .  .  .  .
Impact 1 |  .  .  .  .  .
           L1  L2  L3  L4  L5
           Likelihood →
```

## Changes Since Last Session (2026-03-03)
1. **SecurityHeadersMiddleware ADDED**: 7 OWASP-recommended security headers on ALL API responses (9 tests pass)
   - X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Referrer-Policy, Permissions-Policy, Cache-Control, Pragma, X-Permitted-Cross-Domain-Policies
2. **Docker compose hardened**: Removed weak default passwords (ADMIN_PASSWORD:"admin", weak SECRET_KEY/JWT_SECRET defaults) from docker-compose.aldeci-complete.yml
3. **Bandit scan STABLE**: 477 findings, 0 HIGH, 0 CRITICAL (unchanged from 2026-03-02)
4. **Dependency scan CLEAN**: 171 packages, 0 vulnerable (4th consecutive clean day)
5. **Native SAST dogfooding**: 476 findings, 38 CRITICAL/HIGH all triaged as false positives (pattern strings in SAST rules)
6. **DEMO-011 regression verified**: 24/24 evidence export tests pass
7. **SAST engine tests verified**: 108/108 tests pass
8. **Security Advisory 002 published**: Docker hardening recommendations

## Changes Since Last Session (2026-03-02 Afternoon)
1. **B324 HIGH fixed**: MD5 usedforsecurity=False added to id_allocator.py:23 — 0 HIGH bandit findings
2. **Native SAST dogfooding**: 1990 findings (38 CRITICAL, 57 HIGH). All 38 CRITICAL triaged as FALSE POSITIVE (detection rule patterns, defensive code, auth at mount level)
3. **3 actionable HIGH**: SAST-020 (file upload validation), SAST-039 (CRLF injection), SAST-103 (token entropy) — flagged for review
4. **Dependency scan clean**: 171 packages, 0 vulnerable
5. **DEMO-011 verified**: 24/24 tests passing, RSA-SHA256 evidence export E2E confirmed
6. **Docker review**: Non-root verified, no privileged containers, demo tokens acceptable

## Changes Since 2026-03-01
1. **Secrets risk DOWNGRADED** CRITICAL→MEDIUM: .env excluded from git, Docker generates random tokens, non-root container
2. **Docker risk DOWNGRADED** HIGH→LOW: Non-root user, .dockerignore excludes secrets
3. **Dependency risk ELIMINATED**: 3 CVEs fixed (cryptography, pypdf, black)
4. **SQL injection risk DOWNGRADED**: All B608 findings confirmed as false positives (parameterized queries), PersistentDict table names now validated
5. **XML XXE risk CONFIRMED mitigated**: defusedxml.defuse_stdlib() active at module load

## Open Items (Ordered by Risk)
1. ⚠️ OpenAI API key rotation — pending CEO action (Advisory 001)
2. ⚠️ JWT secret rotation — Docker handles this for new deployments, local .env needs manual update
3. ⚠️ DB file permissions — verify 0600 on production deployments
4. ⚠️ Scanner ingest upload size limit — verify FastAPI body size config

## Mitigations Linked to Other Agents
- **Security Analyst** (self): SecurityHeadersMiddleware, Docker compose hardening, daily scans
- **Backend Hardener**: Path traversal fix, input validation, XXE protection, 11 security hardening fixes
- **DevOps Engineer**: .gitignore, .dockerignore, non-root container, Docker entrypoint token generation — verify compose changes
- **Agent Doctor**: Remediation audit on Advisory 001
- **Threat Architect**: MITRE ATT&CK mapping, threat intelligence feed integration — confirm MPTE Docker socket requirement
- **QA Engineer**: Postman collection security verification (401 enforcement confirmed)
