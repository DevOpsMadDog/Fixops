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

---

## 5. Attack Surface Analysis

### External Entry Points (In-Scope, Network-Reachable)

The application exposes an estimated **750+ endpoints** across 6 FastAPI services and 1 Express.js bridge. The highest-risk external entry points are organized by attack priority:

**Unauthenticated Endpoints (Highest Priority):**
- `POST /api/v1/users/login` — Authentication entry point, returns JWT. Target for credential stuffing, brute force. Located in `suite-api/apps/api/users_router.py`.
- `GET /api/v1/security-scorecard/public/{org_id}` — Public security scorecard view. Exposes org security posture data without authentication. Located in `suite-api/apps/api/security_scorecard_router.py`.
- `POST /api/v1/webhooks/jira` — Jira webhook receiver, signature-verified (Atlassian HMAC). Located in `suite-integrations/api/webhooks_router.py`.
- `POST /api/v1/webhooks/github` — GitHub webhook receiver, HMAC-SHA256 verification. Located in `suite-integrations/api/webhooks_router.py`.
- `POST /api/v1/webhooks/gitlab` — GitLab webhook receiver, X-Gitlab-Token verification. Located in `suite-integrations/api/webhooks_router.py`.
- `POST /api/v1/webhooks/servicenow` — ServiceNow webhook receiver. Located in `suite-integrations/api/webhooks_router.py`.
- `POST /api/v1/webhooks/azure-devops` — Azure DevOps webhook receiver. Located in `suite-integrations/api/webhooks_router.py`.
- `GET /api/v1/webhooks/okta/verify` — Okta one-time verification challenge. Located in `suite-api/apps/api/webhook_router.py`.
- `POST /api/v1/webhooks/okta/events` — Okta event webhook, signature-verified. Located in `suite-api/apps/api/webhook_router.py`.
- `POST /api/v1/webhooks/generic/{source}` — Generic webhook with custom validation. Located in `suite-api/apps/api/webhook_router.py`.
- `POST /api/v1/scanner-ingest/webhook/{scanner_type}` — Scanner output webhook, raw body ingestion (up to 50MB). Located in `suite-api/apps/api/scanner_ingest_router.py`.
- `GET /health`, `GET /status` — Health check endpoints available on all services.

**WebSocket/SSE Endpoints (Token in Query Parameter):**
- `WS /ws/alerts?token=<key>` — Real-time security alerts. Token passed in query parameter (visible in logs/proxies). Located in `suite-api/apps/api/websocket_alerts_router.py`.
- `WS /ws/events?token=<key>` — Event stream subscription. Located in `suite-api/apps/api/websocket_routes.py`.
- `WS /api/v1/stream/ws/{channel}?api_key=<key>` — Bidirectional event stream. Located in `suite-api/apps/api/stream_router.py`.
- `GET /api/v1/stream/sse/{channel}?api_key=<key>` — Server-Sent Events. Located in `suite-api/apps/api/stream_router.py`.

**File Upload Endpoints (Authenticated — High Value Targets):**
- `POST /api/v1/scanner-ingest/upload` — Scanner JSON output upload. Located in `suite-api/apps/api/scanner_ingest_router.py`.
- `POST /api/v1/validation/upload` and `/upload/batch` — Validation data upload (10MB limit). Located in `suite-api/apps/api/validation_router.py`.
- `POST /api/v1/dtrack/sbom/upload` and `/upload-file` — SBOM upload (CycloneDX/SPDX, unlimited size). Located in `suite-core/api/dtrack_router.py`.
- `POST /api/v1/dtrack/vex/upload` — VEX upload. Located in `suite-core/api/dtrack_router.py`.
- `POST /api/v1/sast/scan/files` — Source code file upload for analysis. Located in `suite-attack/api/sast_router.py`.
- `POST /api/v1/container/scan/dockerfile` — Dockerfile upload for security scanning. Located in `suite-attack/api/container_router.py`.
- `POST /api/v1/container/scan/image` — Container image upload. Located in `suite-attack/api/container_router.py`.
- `POST /api/v1/iac/scan/content` — Infrastructure-as-Code content upload. Located in `suite-integrations/api/iac_router.py`.
- `POST /api/v1/evidence/upload` — Evidence bundle upload. Located in `suite-evidence-risk/api/evidence_router.py`.
- `POST /api/v1/business-context-enhanced/upload` — Business context file upload. Located in `suite-evidence-risk/api/business_context_enhanced.py`.
- `POST /api/v1/gap/upload` — Gap analysis data upload. Located in `suite-api/apps/api/gap_router.py`.

**Admin/Privileged Endpoints (Require admin:all scope):**
- `GET/POST/PUT/DELETE /api/v1/admin/users/*` — Full CRUD on user accounts. Located in `suite-api/apps/api/admin_router.py`.
- `GET/POST/PUT/DELETE /api/v1/admin/teams/*` — Full CRUD on team management. Located in `suite-api/apps/api/admin_router.py`.
- `POST /api/v1/self-learning/demo/seed` — Seed demo data (tagged as admin/demo). Located in `suite-core/api/self_learning_router.py`.
- `POST /api/v1/self-learning/demo/reset` — Reset demo state. Located in `suite-core/api/self_learning_router.py`.

**Code Execution Pathways (Authenticated — Critical Risk):**
- `POST /api/v1/sast/scan` and `/scan/code` — Static analysis of user-provided code. Located in `suite-attack/api/sast_router.py`.
- `POST /api/v1/dast/scan` — Dynamic application security testing (triggers outbound requests). Located in `suite-attack/api/dast_router.py`.
- `POST /api/v1/mpte/scan/comprehensive` — Comprehensive penetration testing. Located in `suite-attack/api/mpte_router.py`.
- `POST /api/v1/copilot/agents/pentest/simulate` — AI-powered pentest simulation. Located in `suite-core/api/agents_router.py`.
- `POST /api/v1/copilot/agents/remediation/generate-fix` — AI fix generation. Located in `suite-core/api/agents_router.py`.
- `POST /api/v1/attack-sim/scenarios/generate` — Attack simulation generation. Located in `suite-attack/api/attack_sim_router.py`.
- `POST /api/v1/attack-sim/campaigns/run` — Execute attack campaigns. Located in `suite-attack/api/attack_sim_router.py`.

### Internal Service Communication

All 6 FastAPI services (ports 8000-8005) communicate over the Docker bridge network `aldeci-net` using service DNS names. Internal communication between services does not appear to require additional authentication beyond the shared network boundary. The Express.js bridge (port 3000) proxies API requests to the Python backend (port 8000) and directly accesses SQLite databases in read-only mode without its own authentication layer. The n8n workflow engine (port 5678) is configured with `N8N_BASIC_AUTH_ACTIVE=false`, meaning it has no authentication if network-accessible.

### Input Validation Patterns

The codebase uses **Pydantic ≥2.6** for request/response model validation across FastAPI endpoints, providing strong type checking and constraint enforcement. Pydantic models define required fields, types, and validation rules, automatically rejecting malformed input with 422 Unprocessable Entity responses. The `email-validator` package validates email fields. `python-multipart` handles multipart form parsing for file uploads. However, validation depth varies by endpoint — some routers define comprehensive Pydantic models while others accept loosely-typed `Dict[str, Any]` payloads. The webhook receiver endpoints accept raw JSON bodies with minimal schema validation, relying on signature verification rather than content validation.

### Background Processing

Background jobs are managed via **APScheduler ≥3.10** for scheduled tasks and an optional Redis queue for async processing. Feed refresh jobs (NVD, EPSS, KEV, ExploitDB) run on configurable schedules. The `redis_queue.py` module uses a shared namespace without tenant isolation, meaning background jobs from different tenants share the same queue. Jobs triggered by network requests (e.g., `POST /api/v1/feeds/refresh/all`) execute with the requesting user's context but may not maintain strict authorization boundaries during async processing.

### Notable Out-of-Scope Components
- **CLI scripts** (`scripts/ctem_*.py`, `seed_*.py`) — require shell access, not network-routable
- **Alembic migrations** (`alembic/`) — database migration tool, CLI-only
- **Test suites** (`tests/`) — pytest harnesses, not served by application
- **Build tooling** (`Makefile`, `Dockerfile` build stages) — CI/CD only
- **Playwright e2e tests** (`suite-ui/aldeci-ui-new/e2e/`) — test automation, not served

---

## 6. Infrastructure & Operational Security

### Secrets Management

Secrets are managed via **environment variables** following 12-factor app principles. The Docker entrypoint (`scripts/docker-entrypoint.sh`) auto-generates `JWT_SECRET` and `API_TOKEN` using `secrets.token_urlsafe(48)` if not provided — this provides 384 bits of entropy but means container restarts without volume-persisted secrets invalidate all sessions. The `.env.example` file documents 30+ environment variables including: `FIXOPS_API_TOKEN`, `FIXOPS_JWT_SECRET`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET`, `GCP_PROJECT_ID`, `GOOGLE_CREDENTIALS_JSON`, `JIRA_TOKEN`, `GITHUB_TOKEN`, `SNYK_TOKEN`, `SLACK_TOKEN`, `SLACK_WEBHOOK_URL`, `SMTP_PASSWORD`, `N8N_API_KEY`. No secrets manager (Vault, AWS KMS) integration was identified. The `.gitleaks.toml` configuration and `.secrets.baseline` file indicate secret detection tooling is in place for the development workflow.

**Tracked files with potential secrets:** The `.env` file is git-ignored. A `.env.bak` file exists in the repo root but is untracked. The file `mytoken.txt` (94 bytes) exists in the repo root — its git tracking status should be verified. The `docker-compose.yml` contains a default API token value: `FIXOPS_API_TOKEN: aldeci-demo-token`.

### Configuration Security

**Nginx Configuration** (`docker/nginx-ui.conf`, `docker/nginx-aldeci.conf`):
- **HSTS:** `Strict-Transport-Security: max-age=31536000; includeSubDomains` — properly configured
- **Rate Limiting:** Zone `api_limit` — 10 req/s per IP, burst 20, applied to `/api/*`
- **Security Headers:** X-Frame-Options: SAMEORIGIN, X-Content-Type-Options: nosniff, X-XSS-Protection: 1; mode=block
- **Cache-Control:** Not explicitly configured at Nginx level for API responses; FastAPI middleware adds `no-store, no-cache, must-revalidate` for sensitive endpoints
- **Missing:** No explicit HTTP→HTTPS redirect in Nginx config; TLS termination assumed to be handled by upstream load balancer
- **WebSocket:** `/ws/` routes have 86400s timeout (24h), no buffering
- **SSE:** `/api/v1/mcp-protocol/sse` has 86400s timeout, chunked encoding disabled

**Kubernetes/Helm** (`docker/kubernetes/`, `docker/helm/`): Kubernetes manifests and Helm charts are present for production deployment, suggesting the platform is designed for containerized deployment with orchestration.

### External Dependencies

The platform integrates with numerous external services, each representing a trust boundary:
- **LLM Providers:** OpenAI, Anthropic, OpenRouter — API keys stored in environment
- **SCM/DevOps:** GitHub, GitLab, Azure DevOps — OAuth tokens and webhook secrets
- **Issue Trackers:** Jira, ServiceNow — instance URLs and API tokens (user-configurable, SSRF risk)
- **Communication:** Slack (API + webhooks), SMTP (email relay)
- **Security Tools:** Snyk, SonarQube, Dependency-Track — API tokens
- **Cloud Providers:** AWS, Azure, GCP — full credential sets for cloud security posture management
- **Workflow Engine:** n8n — 400+ integration capabilities, no auth enabled by default

### Monitoring & Logging

Observability is implemented via **OpenTelemetry SDK ≥1.25** with OTLP export, **Prometheus** metrics, and **structlog** for structured logging. The `PerformanceMiddleware` in `suite-core/core/enterprise/middleware.py` generates correlation IDs for request tracing, logs slow requests (>1ms threshold), and tracks request/response metrics. An audit trail system (`suite-core/core/audit_log.py`) records CREATE, UPDATE, DELETE, EXECUTE, LOGIN, LOGOUT, EXPORT actions with user context, IP addresses, and correlation IDs in a SQLite `audit.db`. CSV export capability exists for audit logs. **Security concern:** Request URLs may contain API keys when passed as query parameters, and these could be logged. Log files in `/logs/` are not encrypted.

---

## 7. Overall Codebase Indexing

The Aldeci CTEM+ codebase is organized as a monorepo with 6 specialized suite directories, each containing its own `api/` subdirectory for route definitions and domain-specific logic. The `suite-api/` directory serves as the main orchestration layer with 90+ router files in `apps/api/`, housing the primary FastAPI application factory (`apps/api/app.py`) and all middleware configurations. `suite-core/` is the largest module with 686+ Python files spanning `core/` (engine implementations), `api/` (supplementary endpoints), `agents/` (AI agent definitions), `connectors/` (external service connectors), `services/` (domain services), `config/` (configuration management), and `schemas/` (Pydantic models). `suite-attack/` contains offensive security tooling (SAST, DAST, container scanning, attack simulation, MPTE), while `suite-evidence-risk/` handles compliance evidence chains, risk scoring, provenance tracking, and business context enrichment. `suite-feeds/` manages vulnerability intelligence feed ingestion from NVD, EPSS, CISA KEV, ExploitDB, and OSV. `suite-integrations/` provides connectors for external systems (Jira, GitHub, Slack, SIEM, MCP, IDE plugins, IaC scanning, OSS tools).

The frontend lives in `suite-ui/aldeci-ui-new/` (React 19 + Vite 6 + TypeScript) with Playwright e2e tests. An older frontend exists in `suite-ui/aldeci/` and `frontend/`. The `docker/` directory contains Docker Compose, Nginx configs, Kubernetes manifests, Helm charts, Terraform configurations, and PostgreSQL setup. The `scripts/` directory (169 files) contains operational scripts, enterprise utilities, and signing tools. The `tests/` directory is extensive with 831+ files organized by test type (APP1-APP4 contract tests, e2e, load tests, risk tests, fixtures, harnesses). The `alembic/` directory manages database migrations. Build orchestration uses `Makefile` for common tasks and `pyproject.toml` for Python project configuration. The `docs/schemas/` directory contains SARIF, SBOM, and CVE JSON schema definitions. Code generation patterns are not evident; the codebase appears to be hand-written. The large number of files (especially in `suite-core/core/` and `suite-api/apps/api/`) means security-relevant code is distributed across hundreds of files, making comprehensive manual review challenging without automated tooling.

---

## 8. Critical File Paths

### Configuration
- `docker-compose.yml` — Service topology, exposed ports, environment variables, default API token
- `Dockerfile` — 3-stage build, non-root user, entrypoint configuration
- `docker/nginx-ui.conf` — Nginx reverse proxy, rate limiting, security headers, HSTS
- `docker/nginx-aldeci.conf` — Alternate Nginx configuration
- `docker/kubernetes/` — Kubernetes deployment manifests
- `docker/helm/` — Helm chart for production deployment
- `docker/terraform/` — Terraform infrastructure configuration
- `.env.example` — Documents all environment variables and secrets
- `.gitleaks.toml` — Secret detection configuration
- `.secrets.baseline` — Secret detection baseline
- `pyproject.toml` — Python project configuration, dependency pinning
- `requirements.txt` — Python dependency manifest
- `package.json` — Node.js dependency manifest
- `alembic.ini` — Database migration configuration
- `scripts/docker-entrypoint.sh` — Container entrypoint, auto-generates JWT_SECRET/API_TOKEN

### Authentication & Authorization
- `suite-core/core/auth_middleware.py` — JWT create/decode, API key verification, password hashing, AuthContext, dev-mode bypass
- `suite-core/core/auth_db.py` — User/credential storage schema, SSO configs, SAML assertions, API keys
- `suite-core/core/auth_models.py` — APIKeyScope enum, User model, role-scope mappings
- `suite-core/core/sso_provider.py` — OIDCProvider (Okta/Azure/Google), SAMLProvider, token validation, state/nonce
- `suite-core/core/rbac.py` — RBACEngine, 28 permissions, 6 roles, custom roles, data classification
- `suite-core/core/session_manager.py` — SQLite-backed sessions, suspicious activity detection
- `suite-core/core/api_key_manager.py` — API key creation/validation/revocation (SHA-256 hashing)
- `suite-core/core/password_policy_engine.py` — Password complexity enforcement
- `suite-api/apps/api/auth_deps.py` — FastAPI auth dependencies, JWT validation, dev-mode bypass, query param auth
- `suite-api/apps/api/auth_router.py` — SSO configuration endpoints
- `suite-api/apps/api/sso_router.py` — Enterprise SSO login/callback, relay_state sanitization
- `suite-api/apps/api/apikey_router.py` — API key CRUD endpoints
- `suite-api/apps/api/users_router.py` — Login endpoint, user management
- `suite-api/apps/api/admin_router.py` — Admin user/team CRUD
- `suite-core/core/enterprise/security.py` — Fernet encryption, bcrypt (12 rounds), SecurityManager
- `suite-core/core/tenant_isolation_auditor.py` — Documents known tenant isolation failures

### API & Routing
- `suite-api/apps/api/app.py` — Main FastAPI application factory, middleware chain, router registration, CORS config
- `suite-core/api/app.py` — Suite-core FastAPI application (port 8001)
- `suite-attack/api/app.py` — Suite-attack FastAPI application (port 8002)
- `suite-integrations/api/app.py` — Suite-integrations FastAPI application (port 8003)
- `suite-feeds/api/app.py` — Suite-feeds FastAPI application (port 8004)
- `suite-evidence-risk/api/app.py` — Suite-evidence-risk FastAPI application (port 8005)
- `serve.js` — Express.js bridge server, SPA proxy, static file serving
- `api-bridge.js` — Express.js SQLite direct access routes
- `suite-api/apps/api/webhook_router.py` — Okta webhook receiver, generic webhooks
- `suite-api/apps/api/webhook_subscriptions_router.py` — Webhook subscription management, SSRF validation
- `suite-api/apps/api/scanner_ingest_router.py` — Scanner webhook ingest (50MB)
- `suite-api/apps/api/stream_router.py` — WebSocket and SSE streaming
- `suite-api/apps/api/websocket_alerts_router.py` — WebSocket alerts
- `suite-api/apps/api/websocket_routes.py` — WebSocket events
- `suite-integrations/api/webhooks_router.py` — Jira/GitHub/GitLab/ServiceNow/Azure DevOps webhook receivers

### Data Models & DB Interaction
- `suite-core/core/auth_db.py` — Users, SSO configs, SAML assertions, API keys schema
- `suite-core/core/backup_engine.py` — Backup CRUD (IDOR vulnerability), XOR "encryption"
- `suite-core/core/access_anomaly_engine.py` — Dynamic SQL patterns
- `suite-core/core/vuln_scanner_engine.py` — Vulnerability findings, f-string SQL
- `suite-core/core/audit_log.py` — Audit trail, AuditAction enum, SQLite persistence
- `suite-core/core/audit_analytics.py` — Audit analytics with dynamic SQL
- `alembic/` — Database migration scripts

### Dependency Manifests
- `requirements.txt` — Python dependencies (FastAPI, SQLAlchemy, PyJWT, bcrypt, cryptography, httpx, etc.)
- `requirements-test.txt` — Test dependencies
- `package.json` — Node.js dependencies (Express, better-sqlite3, http-proxy-middleware)
- `package-lock.json` — Locked Node.js dependency versions
- `pyproject.toml` — Python project metadata and extended dependency specifications

### Sensitive Data & Secrets Handling
- `suite-core/core/enterprise/security.py` — Fernet encryption, weak key derivation (SHA-256 single iteration)
- `suite-core/core/utils/enterprise/crypto.py` — Enterprise crypto utilities
- `suite-core/core/backup_engine.py` — XOR cipher with hardcoded key `aldeci-backup-key-2026`
- `.env.example` — Documents all secret environment variables
- `mytoken.txt` — Token file in repo root (94 bytes, verify tracking status)

### Middleware & Input Validation
- `suite-api/apps/api/middleware.py` — Security headers middleware (CSP, X-Frame-Options, Cache-Control)
- `suite-api/apps/api/rate_limiter.py` — Token bucket rate limiter, RateLimitMiddleware
- `suite-api/apps/api/rate_limit_middleware.py` — Additional rate limiting (admin 1000/min, default 100/min)
- `suite-core/core/rate_limiter_v2.py` — Tiered rate limiting (SCAN/QUERY/WRITE/ADMIN/WEBHOOK)
- `suite-core/core/enterprise/middleware.py` — PerformanceMiddleware, correlation IDs, slow request logging
- `suite-core/core/webhook_verifier.py` — Webhook HMAC verification (GitHub, GitLab, Jira, Slack, etc.)
- `suite-core/core/api_gateway.py` — API key management, IP allowlisting/blocklisting, request validation

### Logging & Monitoring
- `suite-core/core/audit_log.py` — Audit trail with SQLite persistence
- `suite-core/core/audit_logger.py` — Enterprise event logger
- `suite-core/core/enterprise/middleware.py` — Request/response tracking, metrics collection
- `suite-core/telemetry/` — OpenTelemetry configuration

### Infrastructure & Deployment
- `docker-compose.yml` — Full service topology (API, UI, n8n, Dependency-Track)
- `Dockerfile` — 3-stage build (Node UI → Python deps → runtime)
- `docker/nginx-ui.conf` — Nginx proxy config with rate limiting and security headers
- `docker/kubernetes/` — K8s deployment manifests
- `docker/helm/` — Helm charts
- `docker/terraform/` — Terraform IaC
- `docker/postgres/` — PostgreSQL configuration (optional)
- `scripts/docker-entrypoint.sh` — Container entrypoint with secret auto-generation

### SSRF-Relevant Files
- `suite-core/core/sso_provider.py` — OIDC discovery fetch, SAML metadata fetch, JWKS URI fetch
- `suite-core/core/real_scanner.py` — DAST engine scanning user-supplied URLs
- `suite-core/connectors/n8n_connector.py` — Webhook delivery without SSRF validation
- `suite-core/core/webhook_notifier.py` — Webhook delivery via urllib
- `suite-core/connectors/sdlc_connectors.py` — GitHub API with user-configurable base_url
- `suite-core/core/jira_sync.py` — Jira API with user-supplied instance URL
- `suite-core/core/servicenow_sync.py` — ServiceNow API with user-supplied instance URL
- `suite-core/core/slack_integration.py` — Slack API calls (hardcoded, low risk)
- `suite-core/core/snyk_integration.py` — Snyk API calls (hardcoded, low risk)
- `suite-api/apps/api/webhook_subscriptions_router.py` — Webhook URL validation with private IP blocking

### XSS/Injection-Relevant Files
- `suite-core/core/bn_lr.py` — pickle.load() for ML model deserialization
- `suite-core/core/zero_gravity.py` — pickle.load() for online learning models
- `suite-core/core/posture_advisor.py` — eval() with restricted builtins (bypassable)
- `suite-core/connectors/normalizer_bridge.py` — xml.etree.ElementTree (not defusedxml)
- `suite-ui/aldeci-ui-new/src/pages/mission-control/SOCDashboard.tsx` — dangerouslySetInnerHTML reference
- `suite-ui/aldeci-ui-new/src/components/layout/CopilotSidebar.tsx` — dangerouslySetInnerHTML with LLM output

### API Schema Files (copied to outputs/schemas/)
- `docs/schemas/facts.sarif.json` — SARIF report schema
- `docs/schemas/facts.sbom.json` — SBOM schema
- `docs/schemas/facts.cve.json` — CVE data schema

---

## 9. XSS Sinks and Render Contexts

**Network Surface Focus:** The following XSS sinks are found in the web application frontend and server-rendered content served to browsers via the network. CLI scripts and test utilities are excluded.

### Frontend React XSS Sinks

**1. dangerouslySetInnerHTML — CopilotSidebar Component (HIGH)**
- **File:** `suite-ui/aldeci-ui-new/src/components/layout/CopilotSidebar.tsx`
- **Context:** The SOC Dashboard (`suite-ui/aldeci-ui-new/src/pages/mission-control/SOCDashboard.tsx`, lines 298-299, 316) explicitly documents this as a vulnerability: *"React XSS via dangerouslySetInnerHTML in Copilot Sidebar"* with description *"dangerouslySetInnerHTML used with unsanitized LLM response content"*.
- **Render Context:** HTML Body Context — LLM-generated responses rendered directly as HTML without sanitization.
- **Attack Vector:** If an attacker can influence LLM output (prompt injection) or if LLM responses contain malicious HTML/JavaScript, the content will execute in the user's browser.
- **Risk:** HIGH — LLM outputs are inherently untrusted and may contain user-influenced content.
- **Remediation:** Use DOMPurify.sanitize() before rendering, or use a markdown renderer with HTML stripping.

**2. innerHTML Assignment Patterns (HIGH)**
- **File:** `suite-ui/aldeci-ui-new/e2e/helpers/endpoints.ts`, line 103
- **Pattern:** `code_context: "innerHTML = userInput"` — test endpoint defining innerHTML assignment pattern.
- **File:** `suite-ui/aldeci-ui-new/e2e/real-world-persona-flows.spec.ts`, line 123
- **Pattern:** `code_context: "document.innerHTML = userInput;"` — test specification for DOM injection.
- **Render Context:** HTML Body Context — direct DOM manipulation with user input.
- **Note:** These are in e2e test files but reference actual application patterns that should be verified in the production component code.

### Server-Side Injection Sinks

**3. Python eval() — Posture Advisor (HIGH)**
- **File:** `suite-core/core/posture_advisor.py`, line 104
- **Pattern:** `eval(condition, {"__builtins__": {}}, posture_data)`
- **Function:** `_eval_trigger(condition: str, posture_data: Dict[str, Any])`
- **Render Context:** JavaScript-equivalent context — Python code evaluation with restricted builtins.
- **Attack Vector:** The `__builtins__: {}` restriction can be bypassed via `posture_data.__class__.__bases__[0].__subclasses__()` to access arbitrary Python classes and execute code.
- **Network Reachable:** Yes — posture data comes from API endpoints that process vulnerability/compliance data; if trigger conditions are user-configurable, this is exploitable.
- **Risk:** HIGH

**4. Pickle Deserialization — ML Models (CRITICAL)**
- **File:** `suite-core/core/bn_lr.py`, line 60
- **Pattern:** `pickle.load(handle)` — Loading trained Bayesian/LR models.
- **File:** `suite-core/core/zero_gravity.py`, line 1325
- **Pattern:** `_pickle.load(f)` — Loading online learning model states.
- **Render Context:** N/A (server-side code execution, not browser rendering).
- **Attack Vector:** Pickle can execute arbitrary Python code during deserialization. If an attacker can control model files (e.g., via file upload endpoints or model update workflows), they achieve RCE on the server.
- **Network Reachable:** Potentially — if model files can be influenced via upload endpoints or supply chain attacks.
- **Risk:** CRITICAL

**5. XML External Entity (XXE) — Normalizer Bridge (MEDIUM)**
- **File:** `suite-core/connectors/normalizer_bridge.py`, line 35
- **Pattern:** `import xml.etree.ElementTree as ET` — Standard library XML parser (not defusedxml).
- **Render Context:** Server-side XML parsing.
- **Attack Vector:** If user-supplied XML data reaches this parser (e.g., via SBOM/SARIF upload), XXE payloads could read local files or trigger SSRF.
- **Network Reachable:** Yes — if normalizer bridge processes uploaded scanner output containing XML.
- **Risk:** MEDIUM (the SAML parser in sso_provider.py correctly uses defusedxml, but this module does not).

**6. SQL Injection — Dynamic WHERE Clauses (MEDIUM)**
- **File:** `suite-core/core/vuln_scanner_engine.py`, line 436
- **Pattern:** `f"SELECT * FROM vuln_findings WHERE {where} ORDER BY cvss_score DESC"`
- **Render Context:** SQL execution context.
- **Additional Files:** 133+ files in `suite-core/core/` use f-string SQL patterns including `access_anomaly_engine.py:455`, `access_matrix.py:466`, `ai_orchestrator.py:562,584`, `api_abuse_detector.py:190`, `api_analytics.py:259`, `api_gateway.py:805`, `audit_analytics.py:852,858,920,923`.
- **Network Reachable:** Yes — these engines are called by API endpoint handlers.
- **Risk:** MEDIUM — most instances use parameterized WHERE clauses, but the architectural pattern is risky.

### CSP Configuration Impact

The Content-Security-Policy configured in `suite-api/apps/api/middleware.py` (lines 16-80) for SPA pages allows `style-src 'self' 'unsafe-inline'`, which permits style-based injection attacks. The API endpoint CSP is more restrictive: `default-src 'none'; frame-ancestors 'none'`. The `unsafe-inline` for styles is a known weakness that could enable CSS-based data exfiltration in certain scenarios.

---

## 10. SSRF Sinks

**Network Surface Focus:** The following SSRF sinks are in network-accessible server-side components. CLI utilities, build scripts, and test files are excluded.

### HTTP(S) Clients — User-Controllable Destinations

**1. OIDC Discovery Document Fetching (HIGH)**
- **File:** `suite-core/core/sso_provider.py`, lines 219-234
- **Function:** `OIDCProvider.fetch_discovery()`
- **HTTP Client:** `httpx.Client`
- **User-Controllable:** YES — `issuer_url` comes from `FIXOPS_OIDC_ISSUER_URL` environment variable, configurable via SSO admin endpoints
- **Validation:** Requires HTTPS scheme only — **NO private IP/DNS validation**
- **Attack Vector:** Admin sets `FIXOPS_OIDC_ISSUER_URL=https://169.254.169.254/` to probe cloud metadata, or points to internal service
- **Risk:** HIGH

**2. SAML IdP Metadata Fetching (HIGH)**
- **File:** `suite-core/core/sso_provider.py`, lines 464-487
- **Function:** `SAMLProvider.fetch_idp_metadata()`
- **HTTP Client:** `httpx.Client`
- **User-Controllable:** YES — `idp_metadata_url` from `FIXOPS_SAML_IDP_METADATA_URL`
- **Validation:** HTTPS scheme required only — **NO SSRF protection**
- **Line 472:** `resp = client.get(self.config.idp_metadata_url)`
- **XXE Protection:** ✓ Uses `defusedxml.ElementTree` for response parsing
- **Risk:** HIGH

**3. JWKS URI Fetching (CRITICAL — Cascading SSRF)**
- **File:** `suite-core/core/sso_provider.py`, lines 306-323
- **Function:** `OIDCProvider.validate_token()`
- **HTTP Client:** PyJWT's `PyJWKClient` (wraps httpx internally)
- **User-Controllable:** INDIRECT — `jwks_uri` extracted from OIDC discovery response
- **Validation:** Discovery requires HTTPS, but **discovery endpoint itself is unvalidated**
- **Attack Vector:** Attacker controls OIDC provider → returns malicious `jwks_uri` → PyJWKClient fetches attacker-controlled URL
- **Cache:** `cache_jwk_set=True, lifespan=300` — 5 min cache, unbounded cache size
- **Risk:** CRITICAL — cascading SSRF via compromised/malicious OIDC provider

**4. DAST Scanner Engine (HIGH)**
- **File:** `suite-core/core/real_scanner.py`, lines 463-590
- **Function:** `scan_url()` — Performs dynamic security testing
- **HTTP Client:** `httpx.AsyncClient`
- **User-Controllable:** YES — user provides target `url` parameter
- **Validation:** Lines 435-437 check scheme must be http/https — **NO private IP blocking**
- **Attack Vector:** User registers scan against `http://10.0.0.1:8080/` or `http://169.254.169.254/latest/meta-data/`
- **Risk:** HIGH — scanner can probe internal network services

### Webhook Delivery Mechanisms

**5. Webhook Subscription Delivery (MEDIUM — Has SSRF Protection)**
- **File:** `suite-api/apps/api/webhook_subscriptions_router.py`, lines 289-291
- **HTTP Client:** `urllib.request`
- **User-Controllable:** YES — webhook URL provided at subscription creation
- **Validation:** ✓ GOOD — `_validate_webhook_url()` (line 113-130) enforces HTTPS, `_is_private_ip()` (line 97-110) resolves DNS and blocks RFC1918, loopback, link-local, cloud metadata ranges
- **Blocked Networks:** 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16
- **Bypass Risk:** DNS rebinding — DNS resolved once at creation time, not re-validated at delivery time
- **Risk:** MEDIUM

**6. n8n Connector Webhook Delivery (MEDIUM — No SSRF Protection)**
- **File:** `suite-core/connectors/n8n_connector.py`, lines 128-150
- **Function:** `N8nConnector.trigger_webhook()`
- **HTTP Client:** `urllib.request`
- **User-Controllable:** YES — `webhook_url` from `register_webhook()`
- **Validation:** **NONE — No DNS/IP validation on webhook URLs**
- **Line 143-149:** Direct POST to user-supplied URL
- **Risk:** MEDIUM

**7. Generic Webhook Notifier (MEDIUM)**
- **File:** `suite-core/core/webhook_notifier.py`, lines 233-270
- **Function:** `_post_json()`
- **HTTP Client:** `urllib.request.urlopen()`
- **User-Controllable:** YES — URL from webhook subscription
- **Line 256:** `req = urllib.request.Request(url, data=body, ...)`
- **Risk:** MEDIUM — depends on upstream URL validation

### Integration Connectors — User-Configurable Destinations

**8. GitHub API with Custom Base URL (MEDIUM)**
- **File:** `suite-core/connectors/sdlc_connectors.py`, line 152
- **Pattern:** `base_url = self._settings.get("base_url", "https://api.github.com")`
- **HTTP Client:** `httpx.AsyncClient`
- **User-Controllable:** YES — admin can set custom GitHub Enterprise base_url
- **Risk:** MEDIUM — GitHub Enterprise URLs could point to internal servers

**9. Jira API with User-Supplied Instance URL (MEDIUM)**
- **File:** `suite-core/core/jira_sync.py`, line 130
- **Pattern:** `jira_url: str` — user-supplied Jira instance URL
- **HTTP Client:** `requests.Session()` with retry adapter
- **URL Construction:** Line 479-481 uses `urljoin(base, path)`
- **Risk:** MEDIUM — could target internal Jira instance or non-Jira services

**10. ServiceNow API with User-Supplied Instance URL (MEDIUM)**
- **File:** `suite-core/core/servicenow_sync.py`, line 149
- **Pattern:** `instance_url: str` — user-supplied ServiceNow instance URL
- **HTTP Client:** `requests.Session()` with retry adapter
- **URL Construction:** Line 548-553 via `urljoin()`
- **Risk:** MEDIUM — could target internal services

### Feed Fetching — Hardcoded Destinations (LOW RISK)

**11. Vulnerability Feed Fetchers**
- **File:** `suite-evidence-risk/risk/feeds/base.py`, lines 21-24
- **HTTP Client:** `urllib.request.urlopen()`
- **User-Controllable:** NO — URLs hardcoded to official sources
- **Destinations:** NVD (`services.nvd.nist.gov`), EPSS (`api.first.org`), CISA KEV (`cisa.gov`), OSV (`api.osv.dev`)
- **Risk:** LOW — hardcoded endpoints, not user-controllable

### Redirect Handlers

**12. SSO Relay State Redirect (LOW — Protected)**
- **File:** `suite-api/apps/api/sso_router.py`, lines 192-204
- **Parameter:** `relay_state: Optional[str]` — redirect target after SSO
- **Validation:** ✓ `sanitize_redirect_url(relay_state, allowed)` with domain allowlist
- **Risk:** LOW — properly protected

### Missing SSRF Protections Summary

| Component | File | Has Private IP Blocking | Has DNS Rebinding Protection | Risk |
|-----------|------|:-:|:-:|------|
| OIDC Discovery | sso_provider.py | ✗ | ✗ | HIGH |
| SAML Metadata | sso_provider.py | ✗ | ✗ | HIGH |
| JWKS URI | sso_provider.py | ✗ | ✗ | CRITICAL |
| DAST Scanner | real_scanner.py | ✗ | ✗ | HIGH |
| Webhook Subscriptions | webhook_subscriptions_router.py | ✓ | ✗ | MEDIUM |
| n8n Connector | n8n_connector.py | ✗ | ✗ | MEDIUM |
| GitHub Connector | sdlc_connectors.py | ✗ | ✗ | MEDIUM |
| Jira Sync | jira_sync.py | ✗ | ✗ | MEDIUM |
| ServiceNow Sync | servicenow_sync.py | ✗ | ✗ | MEDIUM |

**Recommended Mitigation:** Apply the existing SSRF validation logic from `webhook_subscriptions_router.py` (`_is_private_ip()`, `_validate_webhook_url()`) to all user-configurable URL destinations, especially SSO/OIDC/SAML configuration endpoints and the DAST scanner engine.
