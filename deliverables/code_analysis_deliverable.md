# Code Analysis Deliverable — Aldeci CTEM+ Platform

**Assessment Date:** 2026-04-16
**Target:** Aldeci/FixOps CTEM+ (Continuous Threat Exposure Management) Platform
**Analyst Role:** Pre-Recon Code Intelligence Agent

---

# Penetration Test Scope & Boundaries

**Primary Directive:** This analysis is strictly limited to the **network-accessible attack surface** of the Aldeci CTEM+ application platform. All findings adhere to the scope criteria below.

### In-Scope: Network-Reachable Components
- **FastAPI REST API** on port 8000 — the main application server with 500+ endpoints across 6 modular suites
- **Express.js Bridge** on port 3000 — Node.js server providing SQLite direct access and SPA proxy
- **React SPA** served via Nginx on port 80/3000 — frontend consuming the API
- **WebSocket endpoints** at `/ws/alerts` and `/ws/events` — real-time event streaming
- **SSE endpoints** at `/api/v1/stream/sse/{channel}` — Server-Sent Events
- **Webhook receivers** — unauthenticated endpoints for Jira, GitHub, GitLab, ServiceNow, Azure DevOps, Okta
- **Nginx reverse proxy** — security headers, rate limiting, TLS termination
- **n8n workflow engine** on port 5678 — optional orchestration service (basic auth disabled by default)
- **Dependency-Track** on ports 8080/8081 — optional SBOM analysis (separate Docker profile)

### Out-of-Scope: Locally Executable Only
- CLI scripts in `/scripts/` — database seeding, migration, diagnostics (require shell access)
- Alembic migration runner — `alembic upgrade head` (CLI-only)
- Test suites in `/tests/` — pytest harnesses, e2e test scripts
- Build tooling — Dockerfile build stages, Makefile targets, Vite build
- Seed scripts — `seed_*.py` files for demo data population
- Integration test scripts — `integration_test*.sh` (shell execution required)
- Debug/diagnostic scripts — `diag*.sh`, `debug_pipeline.py`

---

## 1. Executive Summary

The Aldeci CTEM+ platform is a comprehensive security decision intelligence application built as a **modular monolith** with Python FastAPI (backend), React 19 (frontend), and an Express.js bridge layer. The application exposes an extraordinarily large attack surface with an estimated **750+ network-accessible API endpoints** across 6 specialized suites: suite-api (orchestration), suite-core (AI/ML decision engine), suite-attack (offensive security tooling), suite-evidence-risk (compliance evidence), suite-feeds (vulnerability intelligence), and suite-integrations (external connectors). Authentication relies on JWT tokens (HS256), API keys, and optional SSO/OIDC/SAML, with a role-based access control system implementing 28 granular permissions across 6 hierarchical roles.

The most critical security concerns identified during this code analysis are: **(1)** Cross-tenant data access vulnerabilities (IDOR) in the backup engine and several core services where `org_id` filtering is missing, enabling one tenant to access another's data; **(2)** Weak cryptography in the backup encryption system which uses XOR cipher with a hardcoded key instead of proper AES/Fernet encryption; **(3)** Unsafe deserialization via `pickle.load()` in ML model loading paths that could enable remote code execution; **(4)** SSRF vectors in OIDC discovery, SAML metadata fetching, and the DAST scanner engine where user-supplied URLs lack proper private IP validation; **(5)** A development/demo authentication bypass that returns admin-level access when `FIXOPS_MODE` is set to demo/dev values.

The platform's architectural decision to use 40+ separate SQLite database files with world-readable (644) permissions creates significant data exposure risk. The codebase contains robust security patterns in some areas (webhook HMAC verification, rate limiting, security headers middleware, Pydantic input validation) but exhibits critical gaps in tenant isolation, encryption key management (SHA-256 single-iteration key derivation), and JWT claim validation (missing `sub`, `aud`, `iss` verification). The Express.js bridge provides direct read-only SQLite access without its own authentication layer, relying entirely on upstream Nginx/CORS for protection. For an external attacker, the highest-value targets are the unauthenticated webhook receivers, the login endpoint, the public security scorecard, and any path that triggers SSRF through integration configuration.

---

## 2. Architecture & Technology Stack

### Framework & Language

The platform's primary backend is **Python 3.11 with FastAPI ≥0.115** running on Uvicorn (ASGI), with Gunicorn as the production multi-worker orchestrator. The choice of FastAPI provides automatic request validation via Pydantic models, auto-generated OpenAPI documentation, and async request handling — all positive for security. However, the massive scale of the codebase (686+ core engine files, 559+ router files) makes comprehensive security coverage challenging. The frontend is **React 19 with Vite 6** and TypeScript, served as a static SPA through Nginx. A secondary **Express.js 5.2.1** bridge server (Node.js 20) provides supplementary API endpoints with direct SQLite read-only access via `better-sqlite3`, creating a parallel data access path that bypasses the Python authentication layer.

Key dependencies with security implications include: `PyJWT ≥2.8` (JWT handling — algorithm confusion risks if misconfigured), `bcrypt ≥4.0` and `passlib[bcrypt] ≥1.7.4` (password hashing — properly using bcrypt with 12 rounds), `cryptography ≥46.0.5` (TLS/cert handling), `httpx ≥0.27` / `requests ≥2.32` / `aiohttp ≥3.9` (multiple HTTP clients creating diverse SSRF attack surface), `defusedxml ≥0.7.1` (XXE protection — used in SAML but not consistently for all XML parsing), `scikit-learn ≥1.3` and PyTorch (ML model inference — pickle deserialization risks), and `pyotp ≥2.9` (TOTP 2FA support). The application uses **SQLite** as its primary database with 40+ separate `.db` files, **SQLAlchemy ≥2.0** as ORM, and **DuckDB** for analytics queries.

### Architectural Pattern

The application follows a **modular monolith** pattern where all 6 suites are bundled into a single FastAPI process, with optional microservice deployment possible via separate Docker services (ports 8000-8005). The Docker Compose topology exposes the FastAPI API (port 8000), React SPA via Nginx (port 3000/80), optional n8n workflow engine (port 5678), and optional Dependency-Track (ports 8080/8081). Trust boundaries exist at: (1) External client ↔ Nginx (TLS, rate limiting, security headers), (2) Nginx ↔ FastAPI (internal HTTP, proxy headers), (3) FastAPI ↔ SQLite databases (parameterized SQL, file permissions), (4) FastAPI ↔ External services (API key authenticated, TLS), and (5) Frontend ↔ FastAPI (CORS-validated, JWT/API key authenticated). The Express.js bridge creates an additional trust boundary concern since it directly accesses SQLite databases in read-only mode without its own authentication middleware.

### Critical Security Components

The middleware chain processes requests in order: CORS validation → Security headers injection → Rate limiting (token bucket, 100 req/min default) → Correlation ID generation → Authentication (JWT/API key/SSO) → Authorization (RBAC with scope validation) → Request handler. Security headers include `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy` restricting camera/microphone/geolocation, and a Content-Security-Policy that allows `unsafe-inline` for styles (XSS risk). The Nginx layer adds HSTS (`max-age=31536000; includeSubDomains`) and additional rate limiting (10 req/s per IP with burst 20). The Docker entrypoint auto-generates `JWT_SECRET` and `API_TOKEN` using `secrets.token_urlsafe(48)` if not provided, which provides strong randomness but means container restarts without persistent secrets invalidate all sessions.

---

## 3. Authentication & Authorization Deep Dive

### Authentication Mechanisms

The platform supports four authentication methods: **(1) JWT tokens** — issued at login via `POST /api/v1/users/login`, signed with HS256 using `FIXOPS_JWT_SECRET` (minimum 32 characters enforced), with configurable expiry (default 24 hours via `FIXOPS_JWT_EXPIRY_HOURS`). Token length is capped at 4096 bytes to prevent parsing attacks. **(2) API keys** — format `fixops_<32hex>` or `aldeci_<32hex>`, stored as bcrypt hashes (in `auth_middleware.py`) or SHA-256 hashes (in `api_key_manager.py` — inconsistency), looked up by 8-character prefix, with optional expiration and granular scopes. **(3) SSO/OIDC** — supporting Okta, Azure AD, Google, and generic OIDC providers via `OIDCProvider` class with RS256 token validation using `PyJWKClient`, automatic discovery document fetching, and state/nonce parameters for CSRF protection. **(4) SAML 2.0** — via `SAMLProvider` class with IdP metadata XML parsing using `defusedxml`, AuthnRequest generation, and Response processing — though signature verification is noted as "limited to stdlib scope" and production should integrate `xmlsec1`.

**Authentication Endpoints:**
- `POST /api/v1/users/login` — Primary login, returns JWT (public, unauthenticated)
- `GET /api/v1/auth/sso` — List SSO configurations
- `POST /api/v1/auth/sso` — Create SSO configuration
- `GET /api/v1/auth/sso/{id}` — Get SSO config by ID
- SSO login/callback endpoints via `sso_router.py`
- `POST /api/v1/api-keys/` — Create API key (authenticated)
- `GET /api/v1/api-keys/` — List API keys (authenticated)
- `DELETE /api/v1/api-keys/{key_id}` — Revoke API key (authenticated)

**CRITICAL FINDING — Dev/Demo Auth Bypass:** When `FIXOPS_AUTH_MODE=dev` or `FIXOPS_MODE` is set to `demo`, `dev`, `development`, or `local`, the authentication layer returns a default admin context when no credentials are provided (`suite-api/apps/api/auth_deps.py` lines 93-120, `suite-core/core/auth_middleware.py` lines 192-201). This grants full administrative access without any authentication. If this mode is accidentally left enabled in production, the entire application is completely unprotected.

### Session Management and Token Security

Sessions are managed via `SessionManager` in `suite-core/core/session_manager.py` using SQLite-backed storage. Session IDs use the format `sess_<16-byte-hex>` generated via Python's `secrets` module (cryptographically secure). Sessions track `ip_address`, `user_agent`, `org_id`, `is_active`, and `expires_at` with configurable TTL (default 24 hours via `FIXOPS_SESSION_TTL_HOURS`). Suspicious activity detection flags sessions with 3+ distinct IP addresses.

**Cookie Configuration:** No explicit `HttpOnly`, `Secure`, or `SameSite` cookie flags were found in the codebase. The application primarily uses header-based JWT/API key authentication rather than cookies, which mitigates CSRF risks but means session tokens are stored in browser localStorage/sessionStorage (vulnerable to XSS exfiltration). The n8n service explicitly sets `N8N_SECURE_COOKIE=false` in docker-compose.yml.

### Authorization Model

RBAC is implemented in `suite-core/core/rbac.py` with 6 hierarchical roles: `viewer` (read-only, 6 permissions) → `developer` (triage + autofix) → `security_analyst` (investigation) → `compliance_officer` (compliance + evidence) → `admin` (all except system_config) → `super_admin` (all 28 permissions including system_config). Custom roles with inheritance are supported. Data classification levels (public < internal < confidential < restricted) add an additional access control dimension. API key scopes provide 13 granular permissions (e.g., `read:sbom`, `write:findings`, `attack:execute`, `admin:all`).

**Potential Bypass Scenarios:** (1) The `admin:all` scope grants universal access — API key compromise with this scope is equivalent to full admin access. (2) JWT claims only require `exp` and `iat` — missing `sub`, `aud`, and `iss` validation means forged tokens with valid signatures could be accepted without proper user context binding (`suite-api/apps/api/auth_deps.py` line 151-165). (3) The inconsistency between bcrypt (auth_middleware.py) and SHA-256 (api_key_manager.py) for API key hashing suggests parallel implementations that may not be consistently protected.

### SSO/OAuth/OIDC Flows

The OIDC flow is implemented in `suite-core/core/sso_provider.py` (lines 199-439). The `get_authorization_url()` method (line 249-267) generates authorization URLs with both `state` and `nonce` parameters for CSRF protection. The callback endpoint in `suite-api/apps/api/sso_router.py` processes the response and calls `exchange_code()` for the token exchange. **State and nonce validation:** The state parameter is generated and included in the authorization URL, and the nonce is embedded in the request. However, the `relay_state` redirect parameter is properly protected via `sanitize_redirect_url()` with domain allowlist validation (line 200-202).

---

## 4. Data Security & Storage

### Database Security

The application uses **40+ SQLite database files** distributed across `/data/` and `/.fixops_data/` directories. This is an unusual architecture — rather than a single relational database, each domain has its own SQLite file (auth.db, audit.db, analytics.db, attack_paths.db, compliance.db, evidence_chain.db, etc.). While this provides some data isolation by domain, it creates significant operational security challenges. **Database file permissions are world-readable (644)**, meaning any user on the host system can read all databases including `auth.db` which contains user emails, names, SAML assertions, SSO configuration metadata, and API key hashes. In the Docker container, files are owned by the `aldeci` non-root user, but the permissions still allow read access to any process in the container.

**SQL Injection Risk:** The codebase primarily uses SQLAlchemy ORM with parameterized queries, which is secure. However, **133+ files** contain f-string SQL patterns (e.g., `suite-core/core/vuln_scanner_engine.py` line 436: `f"SELECT * FROM vuln_findings WHERE {where} ORDER BY cvss_score DESC"`). While many of these use parameterized WHERE clauses (safe), the pattern of dynamic SQL construction via string formatting is architecturally risky. Dynamic ORDER BY clauses and table names cannot be parameterized and remain vulnerable.

### Critical Data Protection Gaps

**CRITICAL — Backup Encryption Uses XOR:** The backup engine (`suite-core/core/backup_engine.py` lines 66-75, 470-483) implements "encryption" using a simple XOR cipher with a **hardcoded key** (`_DEFAULT_KEY = b"aldeci-backup-key-2026"`). XOR is not a cryptographic cipher — it is trivially reversible. Any backup file can be decrypted by an attacker who reads the source code. This is especially dangerous because the backup endpoints are network-accessible (`GET /api/v1/backups/{backup_id}`, `POST /api/v1/backups/{backup_id}/restore`).

**CRITICAL — Cross-Tenant IDOR in Backups:** The `get_backup()` method (line 325-333) queries by `backup_id` without checking `org_id`, allowing any authenticated user to access, restore, or delete another tenant's backups. The `delete_backup()` method (line 335-348) has the same vulnerability.

**Encryption at Rest:** The enterprise security module (`suite-core/core/enterprise/security.py` lines 84-92) uses Fernet (AES-128-CBC + HMAC-SHA256) for sensitive data encryption, but the encryption key is derived via single-iteration SHA-256 of `SECRET_KEY` — insufficient for key derivation. No key rotation mechanism exists. PII fields (email, name) in `auth.db` are stored **unencrypted**. SAML assertions and SSO certificates are stored as plaintext in the `sso_configs` table.

### Multi-tenant Data Isolation

The platform's tenant isolation auditor (`suite-core/core/tenant_isolation_auditor.py`) documents known isolation failures: (1) `redis_queue.py` — all tenants share queue namespace `aldeci:queue:{priority}`, (2) `sso_bridge.py` — `sso_sessions` table has no `org_id` column, (3) `insider_threat_engine.py` — `resolve_alert()` resolves by ID only without org_id guard, (4) `attack_path_engine.py` — `get_node()` and `remove_node()` query by node_id without org_id filter. These documented issues represent confirmed cross-tenant data access vulnerabilities.
