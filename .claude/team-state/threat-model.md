# ALdeci Threat Model — 2026-03-01

> **Updated by**: security-analyst
> **Methodology**: STRIDE + Risk Matrix (Likelihood x Impact, 1-5 scale)
> **Scope**: ALdeci CTEM+ platform (all suites)

## Attack Surfaces

### 1. API Gateway (suite-api, 704 endpoints)
| Threat (STRIDE) | Description | Likelihood | Impact | Risk | Mitigation | Status |
|-----------------|-------------|-----------|--------|------|------------|--------|
| Spoofing | API key / JWT bypass | 2 | 5 | 10/HIGH | JWT + X-API-Key auth on all routes | ✅ Mitigated |
| Tampering | Request body manipulation | 3 | 4 | 12/HIGH | Pydantic v2 input validation | ✅ Mitigated |
| Repudiation | Action denial | 2 | 3 | 6/MEDIUM | Audit logging via Event Bus | ✅ Mitigated |
| Info Disclosure | Error messages leak internals | 3 | 3 | 9/MEDIUM | Custom error handlers | ⚠️ Partial |
| DoS | Rate limiting bypass | 2 | 4 | 8/MEDIUM | Rate limiter middleware | ✅ Mitigated |
| Elevation | Scope escalation | 2 | 5 | 10/HIGH | Scope-based access control | ✅ Mitigated |

### 2. Evidence Export (/api/v1/evidence/export)
| Threat | Description | Likelihood | Impact | Risk | Mitigation | Status |
|--------|-------------|-----------|--------|------|------------|--------|
| Tampering | Bundle content modification | 2 | 5 | 10/HIGH | RSA-SHA256 signing + SHA-256 hash | ✅ Mitigated |
| Repudiation | Signing key dispute | 1 | 4 | 4/LOW | Key fingerprint + metadata tracking | ✅ Mitigated |
| Info Disclosure | Sensitive data in bundle | 2 | 4 | 8/MEDIUM | Scope-based evidence filtering | ✅ Mitigated |

### 3. Scanner Engines (SAST/DAST/Secrets/Container/CSPM)
| Threat | Description | Likelihood | Impact | Risk | Mitigation | Status |
|--------|-------------|-----------|--------|------|------------|--------|
| Tampering | Scan result injection | 1 | 4 | 4/LOW | Input validation on ingest API | ✅ Mitigated |
| Info Disclosure | Source code in SAST results | 2 | 3 | 6/MEDIUM | Line-level excerpts only | ✅ Mitigated |

### 4. File Uploads (Scanner Ingest)
| Threat | Description | Likelihood | Impact | Risk | Mitigation | Status |
|--------|-------------|-----------|--------|------|------------|--------|
| Tampering | Path traversal via filename | 3 | 5 | 15/CRITICAL | `_sanitize_bundle_id()` + `verify_allowlisted_path()` | ✅ Mitigated |
| DoS | Large file upload | 3 | 3 | 9/MEDIUM | Size limits in FastAPI | ⚠️ Needs config |

### 5. Secrets in Repository
| Threat | Description | Likelihood | Impact | Risk | Mitigation | Status |
|--------|-------------|-----------|--------|------|------------|--------|
| Info Disclosure | API keys in .env committed | 5 | 5 | 25/CRITICAL | **ACTIVE FINDING** — See Advisory 001 | ❌ OPEN |
| Elevation | JWT secret = "demo-secret" | 5 | 5 | 25/CRITICAL | **ACTIVE FINDING** — token forgery possible | ❌ OPEN |

### 6. Database (SQLite WAL, 54 .db files)
| Threat | Description | Likelihood | Impact | Risk | Mitigation | Status |
|--------|-------------|-----------|--------|------|------------|--------|
| Injection | SQL injection via raw queries | 2 | 5 | 10/HIGH | Parameterized queries in most places | ⚠️ Review needed |
| Info Disclosure | DB files readable | 3 | 3 | 9/MEDIUM | File permissions (0600) | ⚠️ Partial |
| DoS | WAL file lock contention | 3 | 3 | 9/MEDIUM | WAL mode enables concurrent reads | ✅ Mitigated |

### 7. Docker Deployment
| Threat | Description | Likelihood | Impact | Risk | Mitigation | Status |
|--------|-------------|-----------|--------|------|------------|--------|
| Elevation | Container runs as root | 3 | 4 | 12/HIGH | Needs non-root user in Dockerfile | ⚠️ Review needed |
| Info Disclosure | Secrets in Docker env | 3 | 4 | 12/HIGH | Docker secrets / env injection needed | ⚠️ Review needed |

## Risk Heat Map
```
Impact 5 |  ■  .  .  ■  ■     ■=CRITICAL (Secrets in .env)
Impact 4 |  .  ■  ■  .  .     ■=HIGH
Impact 3 |  .  ■  ■  .  .     ■=MEDIUM
Impact 2 |  .  .  .  .  .     .=LOW
Impact 1 |  .  .  .  .  .
           L1  L2  L3  L4  L5
           Likelihood →
```

## Critical Findings Summary
1. **CRITICAL**: Real API keys in `.env` (Risk: 25/25) — See Advisory 001
2. **HIGH**: 12 weak MD5 hash usages (Risk: 10/25) — Being fixed
3. **MEDIUM**: Error messages may leak internals (Risk: 9/25) — Monitor
4. **LOW**: No pip-audit vulnerabilities found (Risk: 0) — Clean

## Mitigations Linked to Backend Hardener
- Path traversal: Fixed in evidence_router.py (verified)
- Input validation: Pydantic v2 models throughout
- Auth: JWT + API key on all routes
- Rate limiting: Middleware active

## Next Steps
1. Rotate OpenAI API key (CRITICAL — TODAY)
2. Fix MD5 → add usedforsecurity=False (IN PROGRESS)
3. Review Docker configs for privilege escalation
4. Add CSP headers for frontend (flag to Frontend Craftsman)
5. Audit SQL queries for parameterization
