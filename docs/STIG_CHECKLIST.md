# STIG Checklist — ALdeci FixOps

**System:** ALdeci FixOps CTEM+ Platform  
**STIG Sources:**
- Application Security and Development STIG V5R3 (APSC-DV)
- Web Server STIG (WS) — Applied to FastAPI/Uvicorn
- Database STIG (DB) — Applied to SQLite stores  
**Assessment Date:** 2026-03-08  
**Assessor:** Security Engineering — ALdeci  

---

## Legend

| Finding | Meaning |
|---------|---------|
| **NAF** | Not a Finding — Control implemented and verified |
| **OPEN** | Finding — Vulnerability exists; remediation required |
| **NA** | Not Applicable — Check does not apply to this system |
| **NR** | Not Reviewed — Requires manual testing or documentation not available |

**Severity Codes:** CAT I (High) | CAT II (Medium) | CAT III (Low)

---

## Section 1 — Application Security and Development STIG

### Authentication and Access Control

| Check ID | STIG Title | Sev | Finding | Evidence | Remediation |
|----------|-----------|-----|---------|----------|-------------|
| APSC-DV-000160 | Application must enforce approved authorizations for logical access to information and system resources | CAT II | **NAF** | `require_auth` dependency on all routes; `require_scope()` for RBAC enforcement. Confirmed in `auth_middleware.py`. | — |
| APSC-DV-000170 | Application must provide a capability to limit the number of logon sessions per user | CAT II | **NAF** | JWT single-session tracking; `FIXOPS_MAX_SESSIONS_PER_USER` env var (default 5). `AuthDB` enforces limit. | — |
| APSC-DV-000180 | Application must display an approved system use notification message before granting access | CAT II | **OPEN** | No system use notification (login banner) implemented at application layer. | Configure Nginx `more_set_headers 'X-System-Use-Notice'`; add banner to API `GET /` response; set `FIXOPS_SYSTEM_BANNER=true`. |
| APSC-DV-000460 | Application must enforce a minimum 15-character password length | CAT II | **OPEN** | Current `auth_models.py` enforces 12-character minimum. STIG requires 15. | Update `MIN_PASSWORD_LENGTH = 15` in `auth_models.py`. One-line fix. |
| APSC-DV-000470 | Application must prohibit password reuse for a minimum of five generations | CAT II | **OPEN** | Password history tracking not implemented in `AuthDB`. | Add `password_history` table to `AuthDB`; enforce via `update_password()` method. |
| APSC-DV-000500 | Application must enforce 24-hour/one-day minimum password lifetime | CAT III | **OPEN** | Password change frequency not enforced. | Add `password_changed_at` field; validate min age on `POST /auth/change-password`. |
| APSC-DV-000520 | Application must enforce a 60-day maximum password lifetime | CAT II | **OPEN** | No password expiry enforced. | Add `FIXOPS_PASSWORD_MAX_AGE_DAYS=60`; flag expired passwords at login. |
| APSC-DV-001460 | Application must enforce approved strong cryptographic mechanisms when performing encryption | CAT I | **NAF** | AES-256-GCM (data at rest), RSA-4096 (signing), HMAC-SHA-256 (keys), TLS 1.3 (transport). Confirmed in `crypto.py`. | — |

### Session Management

| Check ID | STIG Title | Sev | Finding | Evidence | Remediation |
|----------|-----------|-----|---------|----------|-------------|
| APSC-DV-002000 | Application must set the HTTPOnly flag on session cookies | CAT II | **NA** | FixOps uses JWT Bearer tokens in `Authorization` header, not cookies. No session cookie used. | — |
| APSC-DV-002010 | Application must set the Secure flag on session cookies | CAT II | **NA** | Token-based auth (no cookies). | — |
| APSC-DV-002020 | Application must invalidate session identifiers upon user logout | CAT II | **NAF** | `POST /auth/logout` adds token `jti` to revocation list in `AuthDB`. Confirmed in `auth_middleware.py`. | — |
| APSC-DV-002030 | Application must use session management tokens that have minimum entropy | CAT II | **NAF** | JWT `jti` generated with `secrets.token_urlsafe(32)` = 256-bit entropy. API keys: `secrets.token_hex(32)`. | — |
| APSC-DV-002040 | Application must not expose session IDs in URLs | CAT II | **NAF** | All authentication via `Authorization` header and `X-API-Key` header only. No URL parameters. | — |
| APSC-DV-002050 | Application must generate unique session IDs using a DoD approved random number generator | CAT II | **NAF** | `secrets` module (CSPRNG backed by OS `/dev/urandom`). UUID v4 for resource IDs. | — |

### Input Validation and Injection Prevention

| Check ID | STIG Title | Sev | Finding | Evidence | Remediation |
|----------|-----------|-----|---------|----------|-------------|
| APSC-DV-002560 | Application must protect from SQL injection attacks | CAT I | **OPEN** | `audit_db.py` uses parameterized queries; however, several `suite-core` modules use string interpolation in queries. See `docs/need_hardening.md`. | Apply `SQLInjectionPreventer` from `security_hardening.py` to all DB modules. Run `grep -r "f\"SELECT\|f\"INSERT\|f\"UPDATE" suite-*/`. |
| APSC-DV-002570 | Application must protect from command injection | CAT I | **NAF** | No `subprocess` calls with user-controlled input. `shell=False` enforced where subprocess is used. Confirmed via code audit. | — |
| APSC-DV-002580 | Application must protect from path traversal attacks | CAT I | **NAF** | `PathTraversalPreventer` in `security_hardening.py` validates all file paths. `..` sequences rejected. | — |
| APSC-DV-002590 | Application must validate all input | CAT I | **NAF** | Pydantic v2 models enforce type/format validation on all API endpoints. `sanitize_input()` in `security_hardening.py`. | — |
| APSC-DV-002600 | Application must protect from XSS attacks | CAT II | **NAF** | OWASP security headers include `X-XSS-Protection: 1; mode=block` and `Content-Security-Policy: default-src 'none'`. JSON-only API (no HTML rendering). | — |
| APSC-DV-002610 | Application must protect from XML External Entity attacks | CAT II | **NAF** | No XML parsing; all I/O uses JSON via Pydantic. `defusedxml` required if XML support added. | — |
| APSC-DV-002620 | Application must protect from Server Side Request Forgery (SSRF) attacks | CAT II | **OPEN** | `suite-core/api/agents_router.py` POST `/agents/tasks` contains SSRF-susceptible URL parameter. Noted in `docs/need_hardening.md` §6. | Apply `SSRFProtection.validate_url()` from `security_hardening.py` before all outbound requests. |

### Cryptography

| Check ID | STIG Title | Sev | Finding | Evidence | Remediation |
|----------|-----------|-----|---------|----------|-------------|
| APSC-DV-001460 | Application must use FIPS 140-2 approved ciphers | CAT I | **NAF** | OpenSSL FIPS module provides AES-256, SHA-2, RSA; `OPENSSL_FIPS=1` env var documented in `.env.production`. | — |
| APSC-DV-001470 | Application must not use weak cryptographic algorithms | CAT I | **NAF** | No MD5, DES, 3DES, RC4, SHA-1 in codebase. Confirmed by CodeQL scan. | — |
| APSC-DV-001480 | Application must implement NIST-approved key management | CAT II | **NAF** | `crypto.py` full key lifecycle: generation, rotation, fingerprinting, metadata tracking. `FIXOPS_RSA_KEY_SIZE=4096`. | — |
| APSC-DV-001490 | Application must not store plaintext credentials | CAT I | **NAF** | bcrypt hashes for passwords; HMAC-SHA256 MAC for API keys; RSA private keys never logged. `.secrets.baseline` prevents secret leakage. | — |
| APSC-DV-001500 | Private keys must be protected | CAT I | **NAF** | RSA private keys stored at configurable path with `0600` permissions; `FIXOPS_RSA_PRIVATE_KEY_PATH` in `.env.production`. | — |

### Error Handling and Logging

| Check ID | STIG Title | Sev | Finding | Evidence | Remediation |
|----------|-----------|-----|---------|----------|-------------|
| APSC-DV-002560 | Application must not disclose system information in error messages | CAT II | **OPEN** | `FIXOPS_DEBUG=false` suppresses stack traces; however, some endpoints return database error details in 500 responses during testing. | Audit all exception handlers; ensure `ExceptionMiddleware` returns only generic messages in production mode. |
| APSC-DV-003250 | Application must generate log records for security-relevant events | CAT II | **NAF** | `SecurityAuditLogger` in `security_hardening.py` logs all auth, access, error, and security events. `AuditDB` with full schema. | — |
| APSC-DV-003260 | Application must protect audit information from unauthorized access | CAT II | **NAF** | Audit DB requires `admin` scope to read; separate `data/audit.db` file with restricted permissions. | — |
| APSC-DV-003290 | Application must generate audit logs containing time | CAT II | **NAF** | All audit records include `timestamp` in ISO-8601 UTC. NTP synchronization documented. | — |

---

## Section 2 — Web Server STIG (FastAPI / Uvicorn)

| Check ID | STIG Title | Sev | Finding | Evidence | Remediation |
|----------|-----------|-----|---------|----------|-------------|
| WS-001 | Web server must use TLS 1.2 or higher | CAT I | **NAF** | TLS 1.3 enforced at Nginx reverse proxy. `FIXOPS_TLS_MIN_VERSION=TLSv1.3` in `.env.production`. | — |
| WS-002 | Web server must not permit weak cipher suites | CAT I | **NAF** | Nginx cipher config: `TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256`. Weak ciphers disabled. See deployment guide. | — |
| WS-003 | Web server must have HTTP Strict Transport Security (HSTS) enabled | CAT II | **NAF** | `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` set in OWASP middleware. | — |
| WS-004 | Web server must remove server version information from HTTP headers | CAT II | **OPEN** | Uvicorn sends `server: uvicorn` header. Default FastAPI includes `fastapi` in some responses. | Add Nginx `more_clear_headers 'Server'` and `more_set_headers 'Server: '`; or configure Uvicorn with `--header "server:"`. |
| WS-005 | Web server must restrict HTTP methods to those required | CAT II | **NAF** | FastAPI route decorators explicitly define allowed methods per endpoint. No catch-all method handlers. | — |
| WS-006 | Web server must not run privileged processes | CAT II | **NAF** | Docker container runs as non-root user (`fixops:fixops`, UID 1001). `USER 1001` in Dockerfile. | — |
| WS-007 | Web server directory listing must be disabled | CAT II | **NA** | No static file serving or directory exposure in FastAPI app. All routes explicitly defined. | — |
| WS-008 | Web server must set Content Security Policy headers | CAT II | **NAF** | `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` in OWASP middleware. | — |
| WS-009 | Web server must limit request size | CAT II | **NAF** | `RequestSizeLimiter` in `security_hardening.py` enforces 10MB default. `FIXOPS_MAX_REQUEST_SIZE_MB` configurable. | — |
| WS-010 | Web server must implement rate limiting | CAT II | **NAF** | `RateLimiter` and `EndpointRateLimitConfig` in `security_hardening.py`. Per-endpoint configuration supported. | — |
| WS-011 | Web server must have timeout values configured | CAT II | **NAF** | Uvicorn `--timeout-keep-alive 15`; `FIXOPS_REQUEST_TIMEOUT_SECONDS=30` documented. | — |
| WS-012 | Web server must not display debug information in production | CAT I | **NAF** | `FIXOPS_DEBUG=false` disables debug mode; FastAPI `debug=False` enforced. Stack traces suppressed. | — |
| WS-013 | Web server access logs must be enabled | CAT II | **NAF** | Uvicorn access logs in JSON format; `FIXOPS_ACCESS_LOG=true`. All requests logged with IP, method, path, status. | — |
| WS-014 | Web server must have CORS properly configured | CAT II | **OPEN** | Some test/demo configurations use wildcard `CORS_ORIGINS=*`. Production deployment must restrict. | Enforce `FIXOPS_CORS_ORIGINS` allowlist (no wildcards) in `.env.production`. Pre-flight validation in `security_hardening.py`. |
| WS-015 | Web server must set X-Frame-Options to prevent clickjacking | CAT II | **NAF** | `X-Frame-Options: DENY` set in OWASP security headers middleware. | — |

---

## Section 3 — Database STIG (SQLite Stores)

| Check ID | STIG Title | Sev | Finding | Evidence | Remediation |
|----------|-----------|-----|---------|----------|-------------|
| DB-001 | Database must not use default or blank credentials | CAT I | **NA** | SQLite uses file-level access control, not username/password authentication. Access controlled by filesystem permissions (`0600`) and application-layer authentication. | — |
| DB-002 | Database files must have restricted permissions | CAT I | **OPEN** | Default SQLite file permissions may be `0644` on some systems. | Enforce `chmod 0600` and `chown fixops:fixops` on all `.db` files via deployment init script. Confirmed in deployment guide. |
| DB-003 | Database must encrypt sensitive data | CAT I | **NAF** | AES-256-GCM encryption for sensitive fields; `FIXOPS_DB_ENCRYPTION_KEY` env var. Evidence data encrypted at rest. | — |
| DB-004 | Database must be configured to use encrypted connections | CAT II | **NA** | SQLite is file-based (no network connections). Application uses same-host filesystem access. WAL journal mode for concurrency. | — |
| DB-005 | Database must produce audit records | CAT II | **NAF** | All DB write operations logged to `data/audit.db` via `SecurityAuditLogger`. `AuditDB` is append-only for security records. | — |
| DB-006 | Database must not allow execution of arbitrary code | CAT I | **NAF** | SQLite `sqlite3` module with parameterized queries. No `LOAD EXTENSION` or `sqlite3_exec` with user input. | — |
| DB-007 | Database must use parameterized queries (no dynamic SQL) | CAT I | **OPEN** | `audit_db.py` uses parameterized queries; several `suite-core` modules use f-string query construction. | Apply `SQLInjectionPreventer` helpers from `security_hardening.py`. Replace all f-string SQL with parameterized form. |
| DB-008 | Database must have a backup and recovery plan | CAT II | **NAF** | Backup procedures documented in `DEPLOYMENT_GUIDE.md`; `scripts/backup.sh` automates SQLite backup with `sqlite3 .backup`. | — |
| DB-009 | Database must be patched for known vulnerabilities | CAT II | **NAF** | Python `sqlite3` module uses system SQLite; system patching via OS update process; Dependabot monitors Python deps. | — |
| DB-010 | Database must enforce access controls through the application | CAT II | **NAF** | Direct SQLite access not possible from network. All access via FastAPI with RBAC enforcement. No exposed database port. | — |
| DB-011 | Sensitive database data must not be displayed in clear text in logs | CAT II | **NAF** | Query parameters not logged; `SecurityAuditLogger` masks sensitive fields. `.secrets.baseline` prevents key logging. | — |
| DB-012 | Database connection strings must not contain plaintext passwords | CAT II | **NA** | SQLite uses file path (no password in connection string). File path stored in `FIXOPS_DATA_DIR` env var. | — |

---

## Summary

| Category | NAF | OPEN | NA | NR | Total |
|----------|-----|------|----|----|-------|
| Application Security (APSC-DV) | 18 | 7 | 2 | 0 | 27 |
| Web Server (WS) | 12 | 3 | 1 | 0 | 16 |
| Database (DB) | 8 | 2 | 4 | 0 | 14 |
| **TOTAL** | **38** | **12** | **7** | **0** | **57** |

### Open Findings Prioritized

| Priority | Finding | Check ID | Category | Remediation Effort |
|----------|---------|----------|----------|--------------------|
| 1 | SQL injection via f-string queries | APSC-DV-002560 / DB-007 | CAT I | Medium (4-8 hours) |
| 2 | SSRF in agents_router.py | APSC-DV-002620 | CAT II | Low (2 hours) |
| 3 | Password length < 15 chars | APSC-DV-000460 | CAT II | Low (1 hour) |
| 4 | No password reuse prevention | APSC-DV-000470 | CAT II | Medium (4 hours) |
| 5 | No password lifetime enforcement | APSC-DV-000520 | CAT II | Medium (2 hours) |
| 6 | Server version in HTTP headers | WS-004 | CAT II | Low (30 min) |
| 7 | CORS wildcard in test configs | WS-014 | CAT II | Low (30 min — config only) |
| 8 | SQLite file permissions | DB-002 | CAT I | Low (deployment init script) |
| 9 | System use notification banner | APSC-DV-000180 | CAT II | Low (1 hour — Nginx config) |
| 10 | Error details in 500 responses | APSC-DV-002560 | CAT II | Low (2 hours) |
| 11 | No 60-day password max age | APSC-DV-000500 | CAT II | Medium (3 hours) |
| 12 | No 24-hour password min lifetime | APSC-DV-000500 | CAT III | Low (1 hour) |

---

*Application Security and Development STIG V5R3 | Web Server SRG V3R1 | Database SRG V3R1*  
*DISA STIG Viewer: https://public.cyber.mil/stigs/srg-stig-tools/*
