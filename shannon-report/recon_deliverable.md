# Reconnaissance Deliverable: Aldeci CTEM+ Platform

**Assessment Date:** 2026-04-16
**Target:** http://host.docker.internal:8000
**Analyst Role:** Attack Surface Reconnaissance Specialist

---

## 0) HOW TO READ THIS

This reconnaissance report provides a comprehensive map of the application's attack surface, with special emphasis on authorization and privilege escalation opportunities for the Authorization Analysis Specialist.

**Key Sections for Authorization Analysis:**
- **Section 4 (API Endpoint Inventory):** Contains authorization details for each endpoint — focus on "Required Role" and "Object ID Parameters" columns to identify IDOR candidates.
- **Section 6.4 (Guards Directory):** Catalog of authorization controls — understand what each guard means before analyzing vulnerabilities.
- **Section 7 (Role & Privilege Architecture):** Complete role hierarchy and privilege mapping — use this to understand the privilege lattice and identify escalation targets.
- **Section 8 (Authorization Vulnerability Candidates):** Pre-prioritized lists of endpoints for horizontal, vertical, and context-based authorization testing.

**How to Use the Network Mapping (Section 6):** The entity/flow mapping shows system boundaries and data sensitivity levels. Pay special attention to flows marked with authorization guards and entities handling PII/sensitive data.

**Priority Order for Testing:** Start with Section 8's High-priority horizontal candidates (especially the unauthenticated findings endpoints and Express bridge), then vertical escalation through auth bypass modes, finally context-based workflow bypasses.

---

## 1. Executive Summary

The **Aldeci CTEM+** (Continuous Threat Exposure Management) platform is a comprehensive enterprise security decision-intelligence application built as a modular Python FastAPI monolith with a React 19 frontend. The platform provides security orchestration, vulnerability management, attack simulation, compliance evidence management, threat intelligence aggregation, and AI-assisted security operations across an estimated **750+ network-accessible API endpoints**.

**Primary Attack Surface Components:**
- **FastAPI REST API** on port 8000 — main application server, 750+ endpoints, serving the React SPA and API together
- **React 19 SPA** — served via Nginx/FastAPI on port 8000, client-side routing
- **WebSocket/SSE Streams** — real-time event and alert channels at `/ws/alerts`, `/ws/events`, `/api/v1/stream/`
- **Unauthenticated Webhook Receivers** — inbound Jira, GitHub, GitLab, ServiceNow, Azure DevOps webhooks
- **Scanner Ingest Pipeline** — 50 MB scanner output ingest at `/api/v1/scanner-ingest/`
- **Express.js Bridge** (port 3000, internal-only) — ~100 unauthenticated SQLite-direct routes; **NOT accessible from external network at port 3000** but shared Docker network may expose it

**Critical Security Context:** The application defaults `FIXOPS_AUTH_MODE` to `"dev"` which activates an authentication bypass granting full admin access to any unauthenticated request. The running instance shows `environment: enterprise` but auth is bypassed by default unless explicitly set to `"enforced"`. The browser session confirmed admin-level access with no credentials required.

---

## 2. Technology & Service Map

- **Frontend:** React 19 + Vite 6 + TypeScript; SPA client-side router (hash-based `#/route`); auth.tsx manages token storage in `localStorage` (`aldeci.authToken`, `aldeci.authStrategy`); components include `dangerouslySetInnerHTML` sinks (CopilotSidebar.tsx)
- **Backend:** Python 3.11, FastAPI ≥0.115, Uvicorn (ASGI), Gunicorn (production), SQLAlchemy ≥2.0, Pydantic ≥2.6; modular monolith across 6 suites (suite-api, suite-core, suite-attack, suite-evidence-risk, suite-feeds, suite-integrations)
- **Bridge:** Express.js 5.2.1 + Node.js 20 (`serve.js`, `api-bridge.js`); `better-sqlite3` for direct SQLite read-only access; **zero authentication** on all ~100 bridge routes
- **Database:** 40+ SQLite `.db` files in `/data/` and `/.fixops_data/`; DuckDB for analytics; world-readable (644) file permissions
- **Authentication:** JWT (HS256, PyJWT ≥2.8), bcrypt (passlib, 12 rounds), API keys (`fixops_<32hex>` or `aldeci_<32hex>` format), SSO/OIDC (pyJWKClient, RS256), SAML 2.0 (defusedxml), TOTP 2FA (pyotp ≥2.9)
- **Infrastructure:** Docker + Docker Compose; Nginx reverse proxy (rate limiting 10 req/s, HSTS, security headers); optional n8n (port 5678, no auth by default); optional Dependency-Track (ports 8080/8081)
- **Dependencies (security-relevant):** httpx ≥0.27, requests ≥2.32, aiohttp ≥3.9 (HTTP clients for SSRF), scikit-learn + PyTorch (pickle deserialization risk), APScheduler ≥3.10, OpenTelemetry SDK ≥1.25, structlog
- **Identified Subdomains:** None — single-host deployment at `host.docker.internal:8000`
- **Open Ports & Services:**
  - Port 8000 — FastAPI + React SPA (primary target)
  - Port 3000 — Express.js bridge + Nginx/SPA (internal, same host, separate Docker service)
  - Port 5678 — n8n workflow engine (optional, no auth by default)
  - Ports 8080/8081 — Dependency-Track (optional, separate Docker profile)

---

## 3. Authentication & Session Management Flow

### Entry Points
- `POST /api/v1/users/login` — primary credential-based login (public, unauthenticated)
- `GET /api/v1/auth/sso/providers` — list SSO providers (public)
- `GET /api/v1/auth/sso/{provider}/login` — initiate SSO flow (public, OIDC/SAML)
- `GET /api/v1/auth/sso/{provider}/callback` — OIDC callback (public, accepts `code`+`state`)
- `POST /api/v1/auth/sso/{provider}/callback` — SAML POST binding (public, accepts `SAMLResponse`+`RelayState`)
- `GET /api/v1/auth/sso/{provider}/metadata` — SAML SP metadata (public)
- No registration endpoint visible (users created via admin endpoint)

### Mechanism (Credential Login)
1. Client POSTs `{"email": "<EmailStr>", "password": "<str>"}` to `/api/v1/users/login`
2. Rate limit checked: 5 failed attempts per 5-minute window per email address
3. `UserDB.get_user_by_email()` queries `auth.db` SQLite
4. `bcrypt.verify()` compares password against stored hash
5. Account status checked: must be `UserStatus.ACTIVE`
6. JWT issued with claims: `user_id`, `email`, `role`, `scopes`, `jti`, `iat`, `exp` (2-hour TTL via HS256)
7. Token returned as `{"access_token": "...", "token_type": "bearer", "user": {...}}`
8. Client stores token in `localStorage` as `aldeci.authToken`
9. Subsequent requests send `Authorization: Bearer <token>` header

### API Key Authentication (Primary Method for API Consumers)
- Format: `fixops_<32hex>` or `aldeci_<32hex>` (8-char prefix for DB lookup)
- Sent via `Authorization: Bearer` or `X-API-Key` header
- Hash stored with bcrypt (auth_middleware.py) OR SHA-256 (api_key_manager.py — inconsistency)
- Optional expiration, optional IP allowlist, granular scopes

### Code Pointers
- `suite-api/apps/api/users_router.py` lines 182–243 — login handler, rate limiting, JWT issuance
- `suite-core/core/auth_middleware.py` lines 39–201 — JWT decode, API key verification, **dev bypass** (`FIXOPS_AUTH_MODE` defaults `"dev"`, returns admin context when no credentials)
- `suite-api/apps/api/auth_deps.py` lines 93–196 — FastAPI dependency, second dev bypass (`FIXOPS_MODE=demo/dev/development/local` → admin without credentials)
- `suite-core/core/session_manager.py` — SQLite-backed sessions, `sess_<16hex>` format
- `suite-core/core/sso_provider.py` — OIDC/SAML providers, JWKS fetching, state/nonce generation

### 3.1 Role Assignment Process
- **Role Determination:** Set explicitly in `UserCreate.role` field during user creation via `POST /api/v1/users` or `POST /api/v1/admin/users`; JWT login encodes role from `user.role` DB field
- **Default Role:** `UserRole.VIEWER` — but any role including `admin` can be specified by the creator (no privilege-level validation on assigned role)
- **Role Upgrade Path:** Admin must update user via `PUT /api/v1/admin/users/{user_id}` with new role; no self-service elevation; `RBACEngine.assign_role()` is the programmatic path
- **Code Implementation:** `suite-api/apps/api/users_router.py` line 105–113 (UserCreate model), `suite-core/core/rbac.py` lines 374–415 (RBACEngine.assign_role)

### 3.2 Privilege Storage & Validation
- **Storage Location:** JWT claims (`role`, `scopes`) for stateless auth; SQLite `users` table in `auth.db` for persistent role; `request.state.user_role` + `request.state.user_scopes` for request lifetime
- **Validation Points:** `auth_middleware.py` `require_auth()` dependency (validates JWT/API key, sets AuthContext); `require_scope(scope)` dependency (checks AuthContext.has_scope); `rbac.py` `require_permission()` and `require_role()` RBAC engine dependencies
- **Cache/Session Persistence:** RBAC permission results cached via LRU cache in `rbac.py`; cache cleared on role change via `assign_role()`; JWT TTL default 2 hours; no refresh token endpoint found; session SQLite-backed with 24h TTL
- **Code Pointers:** `suite-core/core/auth_middleware.py` lines 133–249 (require_auth, require_scope), `suite-core/core/rbac.py` lines 786–832 (require_permission, require_role)

### 3.3 Role Switching & Impersonation
- **Impersonation Features:** None identified in public API endpoints
- **Role Switching:** Dev bypass mechanisms function as implicit full-admin impersonation for any unauthenticated caller when `FIXOPS_AUTH_MODE != "enforced"` (the default) or when `FIXOPS_MODE` is `demo/dev/development/local`
- **Audit Trail:** Mutating operations in `admin_router.py` log via `audit_logger.create_audit_logger()`; login events logged to `audit.db`
- **Code Implementation:** Dev bypass #1 in `auth_middleware.py` lines 192–201 (`"dev-bypass"` auth_method tag); Dev bypass #2 in `auth_deps.py` lines 190–196 (`demo_mode=True` flag)

---

## 4. API Endpoint Inventory

**Network Surface Focus:** Only network-accessible endpoints via port 8000 are listed. The Express.js bridge routes on port 3000 are separately documented in Section 6 (internal service), as port 3000 is not the primary target port but may be reachable within the Docker network.

| Method | Endpoint Path | Required Role | Object ID Parameters | Authorization Mechanism | Description & Code Pointer |
|---|---|---|---|---|---|
| **UNAUTHENTICATED — Public** |
| GET | `/api/v1/health` | anon | None | None | Health probe. `suite-api/apps/api/health.py` |
| GET | `/api/v1/health/deep` | anon | None | None | Deep health check with DB/scanner status. `health.py` |
| GET | `/api/v1/ready` | anon | None | None | Readiness probe. `health.py` |
| GET | `/api/v1/version` | anon | None | None | Version info (leaks Python version, environment). `health.py` |
| GET | `/api/v1/metrics` | anon | None | None | Prometheus metrics. `health.py` |
| POST | `/api/v1/users/login` | anon | None | None (rate-limited: 5/5min per email) | Login, returns JWT. `users_router.py` L182 |
| GET | `/api/v1/auth/sso/providers` | anon | None | None | List SSO providers. `sso_router.py` |
| GET | `/api/v1/auth/sso/{provider}/login` | anon | provider | None | Initiate SSO. `sso_router.py` |
| GET | `/api/v1/auth/sso/{provider}/callback` | anon | provider | None (state/nonce validated) | OIDC callback. `sso_router.py` |
| POST | `/api/v1/auth/sso/{provider}/callback` | anon | provider | None (SAML signature) | SAML POST binding. `sso_router.py` |
| GET | `/api/v1/auth/sso/{provider}/metadata` | anon | provider | None | SAML SP metadata. `sso_router.py` |
| GET | `/api/v1/auth/sso` | anon | None | **MISSING** (no auth dependency) | List SSO configs — **UNAUTHENTICATED CRUD**. `auth_router.py` |
| POST | `/api/v1/auth/sso` | anon | None | **MISSING** | Create SSO config. `auth_router.py` |
| GET | `/api/v1/auth/sso/{id}` | anon | id | **MISSING** | Get SSO config by ID. `auth_router.py` |
| PUT | `/api/v1/auth/sso/{id}` | anon | id | **MISSING** | Update SSO config. `auth_router.py` |
| POST | `/api/v1/auth/keys` | anon | None | **MISSING** | Create API key — **UNAUTHENTICATED KEY CREATION**. `auth_router.py` |
| POST | `/api/v1/auth/keys/{key_id}/rotate` | anon | key_id | **MISSING** | Rotate API key. `auth_router.py` |
| DELETE | `/api/v1/auth/keys/{key_id}` | anon | key_id | **MISSING** | Revoke API key. `auth_router.py` |
| GET | `/api/v1/auth/keys` | anon | None | **MISSING** | List API keys. `auth_router.py` |
| GET | `/api/v1/auth/keys/expiring` | anon | None | **MISSING** | Get expiring keys. `auth_router.py` |
| POST | `/api/v1/auth/keys/cleanup` | anon | None | **MISSING** | Clean up expired keys. `auth_router.py` |
| GET | `/api/v1/auth/keys/{key_id}/audit` | anon | key_id | **MISSING** | Key audit log. `auth_router.py` |
| GET | `/api/v1/findings` | anon | None | **MISSING** | List all findings — **NO AUTH, NO TENANT ISOLATION**. `findings_routes.py` |
| GET | `/api/v1/findings/summary` | anon | None | **MISSING** | Findings summary. `findings_routes.py` |
| GET | `/api/v1/findings/sla` | anon | None | **MISSING** | SLA status. `findings_routes.py` |
| GET | `/api/v1/findings/{finding_id}` | anon | finding_id | **MISSING** | Get finding by ID — **IDOR, NO AUTH**. `findings_routes.py` |
| PUT | `/api/v1/findings/{finding_id}/status` | anon | finding_id | **MISSING** | Update finding status — **WRITE, NO AUTH**. `findings_routes.py` |
| PUT | `/api/v1/findings/{finding_id}/assign` | anon | finding_id | **MISSING** | Assign finding — **WRITE, NO AUTH**. `findings_routes.py` |
| POST | `/api/v1/findings/{finding_id}/comment` | anon | finding_id | **MISSING** | Add comment — **WRITE, NO AUTH**. `findings_routes.py` |
| GET | `/api/v1/findings/{finding_id}/timeline` | anon | finding_id | **MISSING** | Finding timeline — **NO AUTH**. `findings_routes.py` |
| POST | `/api/v1/findings/bulk/status` | anon | None | **MISSING** | Bulk status update — **WRITE, NO AUTH**. `findings_routes.py` |
| POST | `/api/v1/findings/export` | anon | None | **MISSING** | Export findings — **DATA EXFIL, NO AUTH**. `findings_routes.py` |
| POST | `/api/v1/webhooks/jira` | anon | None | HMAC signature (Atlassian) | Jira webhook receiver. `webhooks_router.py` |
| POST | `/api/v1/webhooks/github` | anon | None | HMAC-SHA256 | GitHub webhook. `webhooks_router.py` |
| POST | `/api/v1/webhooks/gitlab` | anon | None | X-Gitlab-Token | GitLab webhook. `webhooks_router.py` |
| POST | `/api/v1/webhooks/servicenow` | anon | None | HMAC | ServiceNow webhook. `webhooks_router.py` |
| POST | `/api/v1/webhooks/azure-devops` | anon | None | HMAC | Azure DevOps webhook. `webhooks_router.py` |
| GET | `/api/v1/webhooks/okta/verify` | anon | None | X-Okta-Verification-Challenge | Okta verification. `webhook_router.py` |
| POST | `/api/v1/webhooks/okta/events` | anon | None | Okta HMAC signature | Okta events. `webhook_router.py` |
| POST | `/api/v1/webhooks/generic/{source}` | anon | source | Optional custom validation | Generic webhook. `webhook_router.py` |
| POST | `/api/v1/scanner-ingest/webhook/{scanner_type}` | anon | scanner_type | None (type validation only) | Scanner output ingest (50MB). `scanner_ingest_router.py` |
| POST | `/api/v1/scanner-ingest/detect` | anon | None | **MISSING** | File type detection (100MB). `scanner_ingest_router.py` |
| GET | `/api/v1/scanner-ingest/stats` | anon | None | **MISSING** | Scanner stats. `scanner_ingest_router.py` |
| GET | `/api/v1/scanner-ingest/health` | anon | None | None | Scanner health. `scanner_ingest_router.py` |
| GET | `/api/v1/security-scorecard/public/{org_id}` | anon | org_id | None | Public scorecard. `security_scorecard_router.py` |
| WS | `/api/v1/ws/events` | anon (stub) | None | **STUB — accepts any connection** | WebSocket events. `websocket_routes.py` L88 |
| WS | `/api/v1/ws/pipeline/{stage}` | anon (stub) | stage | **STUB** | Pipeline stage events. `websocket_routes.py` |
| GET | `/api/v1/events/recent` | anon (optional) | None | Optional token (query param `api_key`) | Recent events. `websocket_routes.py` |
| GET | `/api/v1/stream/sse/{channel}` | anon (optional) | channel | Optional `api_key` query param | SSE stream. `stream_router.py` |
| WS | `/api/v1/stream/ws/{channel}` | anon (optional) | channel | Optional `api_key` query param | WebSocket stream. `stream_router.py` |
| GET | `/api/v1/triage/health` | anon | None | None | Triage health. `triage_router.py` |
| GET | `/api/v1/triage/status` | anon | None | None | Triage status. `triage_router.py` |
| **AUTHENTICATED — Bearer Token / API Key Required** |
| GET | `/api/v1/users` | user | None | Bearer + `get_org_id` dep | List users. `users_router.py` L282 |
| POST | `/api/v1/users` | **anon?** | None | **POSSIBLE MISSING AUTH** | Create user with any role. `users_router.py` L262 |
| GET | `/api/v1/users/{id}` | user | id | Bearer + org_id dep | Get user — **IDOR candidate**. `users_router.py` L282 |
| PUT | `/api/v1/users/{id}` | user | id | Bearer + org_id dep | Update user. `users_router.py` |
| DELETE | `/api/v1/users/{id}` | user | id | Bearer + org_id dep | Delete user. `users_router.py` |
| GET | `/api/v1/admin/users` | admin | None | Bearer + app-level guard | List users (admin). `admin_router.py` L137 |
| POST | `/api/v1/admin/users` | admin | None | Bearer + app-level guard | Create user. `admin_router.py` L153 |
| GET | `/api/v1/admin/users/{user_id}` | admin | user_id | Bearer + app-level guard | Get user — **IDOR candidate**. `admin_router.py` L186 |
| PUT | `/api/v1/admin/users/{user_id}` | admin | user_id | Bearer + app-level guard | Update user role/status. `admin_router.py` L195 |
| DELETE | `/api/v1/admin/users/{user_id}` | admin | user_id | Bearer + app-level guard | Delete user. `admin_router.py` L226 |
| GET | `/api/v1/admin/teams` | admin | None | Bearer + app-level guard | List teams. `admin_router.py` L249 |
| POST | `/api/v1/admin/teams` | admin | None | Bearer + app-level guard | Create team. `admin_router.py` L265 |
| GET | `/api/v1/admin/teams/{team_id}` | admin | team_id | Bearer + app-level guard | Get team — **IDOR**. `admin_router.py` L292 |
| PUT | `/api/v1/admin/teams/{team_id}` | admin | team_id | Bearer + app-level guard | Update team. `admin_router.py` L301 |
| DELETE | `/api/v1/admin/teams/{team_id}` | admin | team_id | Bearer + app-level guard | Delete team. `admin_router.py` L332 |
| GET | `/api/v1/auth/sso/session` | user | None | Bearer token | SSO session info. `sso_router.py` |
| POST | `/api/v1/auth/sso/logout` | user | None | Bearer token | SSO logout. `sso_router.py` |
| POST | `/api/v1/auth/keys` (apikey_router) | admin | None | Bearer + `admin:all` scope | Create API key. `apikey_router.py` |
| GET | `/api/v1/auth/keys` (apikey_router) | admin | None | Bearer + `admin:all` scope | List API keys. `apikey_router.py` |
| GET | `/api/v1/auth/keys/{key_id}` | admin | key_id | Bearer + `admin:all` scope | Get key — **IDOR**. `apikey_router.py` |
| PUT | `/api/v1/auth/keys/{key_id}` | admin | key_id | Bearer + `admin:all` scope | Update key. `apikey_router.py` |
| POST | `/api/v1/auth/keys/{key_id}/rotate` | admin | key_id | Bearer + `admin:all` scope | Rotate key. `apikey_router.py` |
| POST | `/api/v1/auth/keys/{key_id}/revoke` | admin | key_id | Bearer + `admin:all` scope | Revoke key. `apikey_router.py` |
| GET | `/api/v1/auth/keys/{key_id}/usage` | admin | key_id | Bearer + `admin:all` scope | Key usage. `apikey_router.py` |
| GET | `/api/v1/tenants/current` | user | None | Bearer + API key | Current tenant. `tenant_router.py` |
| GET | `/api/v1/tenants` | admin | None | Bearer + `admin:all` | List tenants. `tenant_router.py` |
| GET | `/api/v1/tenants/{org_id}/stats` | user/admin | org_id | Bearer + admin-or-self check | Tenant stats — **IDOR candidate**. `tenant_router.py` |
| DELETE | `/api/v1/tenants/{org_id}` | admin | org_id | Bearer + `admin:all` | Delete tenant (destructive). `tenant_router.py` |
| GET | `/api/v1/teams` | user | None | Bearer | List teams. `teams_router.py` |
| POST | `/api/v1/teams` | user | None | Bearer | Create team. `teams_router.py` |
| GET | `/api/v1/teams/{id}` | user | id | Bearer | Get team — **IDOR candidate**. `teams_router.py` |
| PUT | `/api/v1/teams/{id}` | user | id | Bearer | Update team. `teams_router.py` |
| DELETE | `/api/v1/teams/{id}` | user | id | Bearer | Delete team. `teams_router.py` |
| GET | `/api/v1/teams/{id}/members` | user | id | Bearer | List members — **IDOR**. `teams_router.py` |
| POST | `/api/v1/teams/{id}/members` | user | id | Bearer | Add member. `teams_router.py` |
| DELETE | `/api/v1/teams/{id}/members/{user_id}` | user | id, user_id | Bearer | Remove member — **IDOR**. `teams_router.py` |
| POST | `/api/v1/triage/enrich` | user | None | Bearer + org_id dep | Enrich findings (200 max). `triage_router.py` |
| POST | `/api/v1/triage/feedback` | user | None | Bearer + org_id dep | Submit triage feedback. `triage_router.py` |
| GET | `/api/v1/triage/stats` | user | None | Bearer + org_id dep | Triage stats. `triage_router.py` |
| GET | `/api/v1/triage/queue` | user | None | Bearer + org_id dep | Triage queue. `triage_router.py` |
| GET | `/api/v1/audit/logs` | user | None | Bearer + READ_AUDIT_LOG perm | Audit logs. `audit_router.py` |
| GET | `/api/v1/audit/logs/export` | user | None | Bearer + READ_AUDIT_LOG | Export logs (json/csv/siem). `audit_router.py` |
| GET | `/api/v1/audit/logs/{id}` | user | id | Bearer + READ_AUDIT_LOG | Get audit log — **IDOR**. `audit_router.py` |
| GET | `/api/v1/audit/logs/user/{email}` | user | email | Bearer + READ_AUDIT_LOG | User activity by email. `audit_router.py` |
| GET | `/api/v1/audit/logs/resource/{resource_type}/{resource_id}` | user | resource_id | Bearer + READ_AUDIT_LOG | Resource history — **IDOR candidate**. `audit_router.py` |
| GET | `/api/v1/audit/export` | user | None | Bearer + READ_AUDIT_LOG | Export audit CSV. `audit_router.py` |
| GET | `/api/v1/analytics/dashboard/overview` | user | None | Bearer + org_id dep | Dashboard overview. `analytics_router.py` |
| GET | `/api/v1/analytics/executive` | user | None | Bearer + org_id dep | Executive dashboard. `analytics_router.py` |
| POST | `/api/v1/analytics/custom-query` | user | None | Bearer + org_id dep | Custom analytics query. `analytics_router.py` |
| GET | `/api/v1/analytics/export` | user | None | Bearer + org_id dep | Export analytics. `analytics_router.py` |
| GET | `/api/v1/analytics/findings/{id}` | user | id | Bearer + org_id dep | Get finding — **IDOR**. `analytics_router.py` |
| GET | `/api/v1/connectors` | user | None | Bearer | List connectors. `connectors_router.py` |
| POST | `/api/v1/connectors/register` | user | None | Bearer | Register connector (Jira/GitHub URL — SSRF). `connectors_router.py` |
| POST | `/api/v1/connectors/{name}/test` | user | name | Bearer | Test connector — **SSRF via connector URL**. `connectors_router.py` |
| DELETE | `/api/v1/connectors/{name}` | user | name | Bearer | Remove connector. `connectors_router.py` |
| GET | `/api/v1/inventory/applications/{id}` | user | id | Bearer | Get application — **IDOR candidate**. `inventory_router.py` |
| POST | `/api/v1/inventory/applications/{id}/dependencies` | user | id | Bearer | Add dependencies. `inventory_router.py` |
| GET | `/api/v1/inventory/applications/{id}/sbom` | user | id | Bearer | Get SBOM (cyclonedx/spdx). `inventory_router.py` |
| POST | `/api/v1/inventory/sbom/ingest` | user | None | Bearer | Ingest CycloneDX/SPDX JSON. `inventory_router.py` |
| POST | `/api/v1/inventory/sbom/analyze` | user | None | Bearer | Analyze SBOM. `inventory_router.py` |
| POST | `/api/v1/events/webhooks` | user | None | Bearer + org_id dep | Register webhook (URL validation). `webhook_events_router.py` |
| DELETE | `/api/v1/events/webhooks/{webhook_id}` | user | webhook_id | Bearer | Unregister webhook — **IDOR**. `webhook_events_router.py` |
| POST | `/api/v1/events/test/{webhook_id}` | user | webhook_id | Bearer | Test webhook delivery — **SSRF if IDOR**. `webhook_events_router.py` |
| POST | `/api/v1/scanner-ingest/upload` | user | None | Bearer + org_id dep | Scanner file upload (100MB). `scanner_ingest_router.py` |
| POST | `/api/v1/stream/publish` | user | None | Bearer | Publish event to stream. `stream_router.py` |
| GET | `/api/v1/stream/stats` | user | None | Bearer | Stream stats. `stream_router.py` |
| GET | `/api/v1/stream/recent/{channel}` | user | channel | Bearer | Recent events by channel. `stream_router.py` |
| GET | `/api/v1/bulk/exports/{filename}` | user | filename | Bearer | Download export file — **path traversal checked**. `bulk_router.py` L988 |
| POST | `/api/v1/bulk/export` | user | None | Bearer | Generate export. `bulk_router.py` |
| GET | `/api/v1/bulk/jobs/{job_id}` | user | job_id | Bearer | Job status — **IDOR**. `bulk_router.py` |
| DELETE | `/api/v1/bulk/jobs/{job_id}` | user | job_id | Bearer | Delete job — **IDOR**. `bulk_router.py` |
| POST | `/api/v1/workflows/{id}/execute` | user | id | Bearer | Execute workflow — **IDOR**. `workflows_router.py` |
| GET | `/api/v1/workflows/{id}` | user | id | Bearer | Get workflow — **IDOR**. `workflows_router.py` |
| GET | `/api/v1/backups/{backup_id}` | user | backup_id | Bearer | Get backup — **CROSS-TENANT IDOR (org_id=None path)**. `backup_engine.py` L362 |
| POST | `/api/v1/backups/{backup_id}/restore` | user | backup_id | Bearer | Restore backup — **CROSS-TENANT IDOR**. `backup_engine.py` |
| DELETE | `/api/v1/backups/{backup_id}` | user | backup_id | Bearer | Delete backup — **CROSS-TENANT IDOR**. `backup_engine.py` L378 |
| POST | `/api/v1/autofix/generate` | user | None | Bearer + org_id dep | Generate fix (accepts source_code). `autofix_router.py` |
| GET | `/api/v1/autofix/fixes/{fix_id}` | user | fix_id | Bearer + org_id dep | Get fix — **IDOR**. `autofix_router.py` |
| POST | `/api/v1/dast/scan` | user | None | Bearer | DAST scan (user-supplied URL — **SSRF**). `dast_router.py` |
| POST | `/api/v1/app-security/scans` | user | None | Bearer | App security scan (DAST SSRF). `dast_scanner.py` |
| POST | `/api/v1/attack-sim/scenarios/generate` | user | None | Bearer | Generate attack scenario. `attack_sim_router.py` |
| POST | `/api/v1/attack-sim/campaigns/run` | user | None | Bearer | Run attack campaign. `attack_sim_router.py` |
| GET | `/api/v1/attack-sim/campaigns/{campaign_id}` | user | campaign_id | Bearer | Get campaign — **IDOR**. `attack_sim_router.py` |
| POST | `/api/v1/sast/scan` | user | None | Bearer | SAST scan (user code). `sast_router.py` |
| POST | `/api/v1/sast/scan/files` | user | None | Bearer | Upload files for SAST. `sast_router.py` |
| POST | `/api/v1/container/scan/dockerfile` | user | None | Bearer | Dockerfile scan. `container_router.py` |
| POST | `/api/v1/mpte/scan/comprehensive` | user | None | Bearer | Comprehensive pentest. `mpte_router.py` |
| POST | `/api/v1/copilot/agents/pentest/simulate` | user | None | Bearer | AI pentest simulation. `agents_router.py` |
| POST | `/api/v1/copilot/agents/remediation/generate-fix` | user | None | Bearer | AI fix generation. `agents_router.py` |
| POST | `/api/v1/graphql` | user | None | Bearer | GraphQL endpoint (queries/mutations). `graphql_router.py` |
| GET | `/api/v1/graphql/schema` | anon | None | None | GraphQL schema (introspection). `graphql_router.py` |
| GET | `/api/v1/posture-advisor/analyze` | user | None | Bearer | Posture analysis (eval()). `posture_advisor.py` L104 |
| GET/POST | `/api/v1/self-learning/demo/seed` | admin | None | Bearer + admin scope | Seed demo data. `self_learning_router.py` |
| GET/POST | `/api/v1/self-learning/demo/reset` | admin | None | Bearer + admin scope | Reset demo. `self_learning_router.py` |
| GET | `/evidence/bundles/{bundle_id}/download` | user | bundle_id | Bearer | Download evidence bundle — **IDOR**. `evidence_router.py` |
| GET | `/evidence/{release}` | user | release | Bearer | Get evidence by release — **IDOR**. `evidence_router.py` |
| POST | `/evidence/export` | user | None | Bearer | Export evidence. `evidence_router.py` |
| GET | `/api/v1/feeds/nvd/{cve_id}` | user | cve_id | Bearer | NVD CVE data. `feeds_router.py` |
| POST | `/api/v1/feeds/refresh/all` | user | None | Bearer | Refresh all feeds. `feeds_router.py` |
| POST | `/api/v1/gate/check` | user | None | Bearer + API key | Security gate check (SARIF/SBOM). `gate_router.py` |
| GET | `/api/v1/scim/v2/Users/{id}` | admin | id | Bearer + SCIM auth | SCIM user — **IDOR**. `scim_router.py` |
| PUT | `/api/v1/scim/v2/Users/{id}` | admin | id | Bearer + SCIM auth | Update SCIM user. `scim_router.py` |
| DELETE | `/api/v1/scim/v2/Users/{id}` | admin | id | Bearer + SCIM auth | Delete SCIM user. `scim_router.py` |
| GET | `/docs` | anon | None | None | Swagger UI. FastAPI built-in |
| GET | `/api/v1/openapi.json` | anon | None | None | OpenAPI schema. FastAPI built-in |

---

## 5. Potential Input Vectors for Vulnerability Analysis

**Network Surface Focus:** All vectors are reachable via network requests to port 8000.

### URL Parameters
- `?limit=`, `?offset=` — pagination params on all list endpoints (integer type, validated by Pydantic ge/le)
- `?severity=`, `?status=`, `?connector=`, `?cve_id=`, `?asset_id=`, `?assigned_to=` — finding filter params at `GET /api/v1/findings` (plain strings, no strict allowlisting for `assigned_to`) — `findings_routes.py`
- `?sort_by=` — controlled by regex `^(severity|created_at|risk_score|last_seen)$` — `findings_routes.py`
- `?date_from=`, `?date_to=` — plain `Optional[str]` with no format validation — `findings_routes.py`
- `?org_id=` — stream channel org_id — `stream_router.py`
- `?api_key=`, `?token=` — authentication via query string (logged in access logs) — `stream_router.py`, `websocket_routes.py`
- `?format=` — export format (`json|csv|siem`) — `audit_router.py`
- `?scan_type=` — DAST/SAST scan type selector — `dast_router.py`
- `?pipeline=` (boolean) — enables BrainPipeline processing on ingested scanner data — `scanner_ingest_router.py`
- `?replay=` — SSE channel replay parameter — `stream_router.py`

### POST Body Fields (JSON)
- `{"email": "EmailStr", "password": "str"}` — login — `users_router.py` L90
- `{"email": "EmailStr", "password": "str (min 8)", "role": "UserRole", "department": "str (no max)"}` — user creation — `users_router.py` L105
- `{"findings": [...], "trigger_condition": "str"}` — posture analysis — eval() sink — `posture_advisor.py`
- `{"url": "str", "target": "str", "scan_type": "dast"}` — DAST scan (SSRF via target_url) — `dast_router.py`, `dast_scanner.py` L1565
- `{"source_code": "str", "language": "str", "fix_type": "str"}` — autofix generate — `autofix_router.py`
- `{"channel": "str", "event_type": "str", "data": "Any", "org_id": "str"}` — stream publish — `stream_router.py`
- `{"name": "str", "type": "str", "jira": {"instance_url": "str", "token": "str"}}` — connector register (SSRF via instance_url) — `connectors_router.py`
- `{"idp_metadata_url": "str"}` / `{"issuer_url": "str"}` — SSO config (SSRF) — `auth_router.py`, `sso_provider.py`
- `{"url": "str", "event_types": [...], "secret": "str"}` — webhook subscription (SSRF, URL validated) — `webhook_events_router.py`
- `{"finding_id": "str", "analyst_verdict": "str", "reason": "str"}` — triage feedback — `triage_router.py`
- `{"finding_ids": ["str"], "status": "str"}` — bulk status update (status has no pattern validation) — `findings_routes.py` L194
- `{"sarif": {...}, "sbom": {...}, "diff": "str"}` — gate check (large data structures) — `gate_router.py`
- `{"query": "str", "variables": {...}}` — GraphQL (arbitrary query + variable injection) — `graphql_router.py`
- `{"text": "str (max 5000)", "tags": [...]}` — finding comment — `findings_routes.py`
- SAML `SAMLResponse` form field (base64-encoded XML) — `sso_router.py`
- `RelayState` form field (URL redirect after SAML) — validated by `sanitize_redirect_url()` — `sso_router.py` L192

### File Uploads (Multipart Form Data)
- Scanner output files at `POST /api/v1/scanner-ingest/upload` — extensions: `.json`, `.xml`, `.html`, `.csv`, `.sarif`, `.nessus`, `.nmap`, `.txt`, `.log`, `.yaml`, `.yml`, `.cdx`, `.spdx`, `.vex` (100MB limit) — `scanner_ingest_router.py`
- SBOM at `POST /api/v1/dtrack/sbom/upload` and `/upload-file` — CycloneDX/SPDX, unlimited size — `dtrack_router.py`
- VEX at `POST /api/v1/dtrack/vex/upload` — `dtrack_router.py`
- Source code files at `POST /api/v1/sast/scan/files` — `sast_router.py`
- Dockerfile at `POST /api/v1/container/scan/dockerfile` — `container_router.py`
- Evidence bundle at `POST /api/v1/evidence/upload` — `evidence_router.py`
- Business context at `POST /api/v1/business-context-enhanced/upload` — `business_context_enhanced.py`
- Gap analysis at `POST /api/v1/gap/upload` — `gap_router.py`
- IaC content at `POST /api/v1/iac/scan/content` — `iac_router.py`
- Container image at `POST /api/v1/container/scan/image` — `container_router.py`

### HTTP Headers
- `Authorization: Bearer <token>` — JWT or API key; also accepted in `X-API-Key` header
- `X-API-Key: <token>` — alternate API key header
- `X-Forwarded-For` — not found to be trusted by app (Nginx forwards real IP)
- `X-Okta-Verification-Challenge` — required by Okta verify endpoint
- `X-Hub-Signature-256` — GitHub webhook signature
- `X-Gitlab-Token` — GitLab webhook token
- `Content-Type` — controls parser selection (JSON vs form vs multipart)
- Correlation ID header generated by `PerformanceMiddleware` (not user-influenced)

### Cookie Values
- No cookie-based authentication found (app uses localStorage + Authorization header)
- `N8N_SECURE_COOKIE=false` in docker-compose for n8n service

### WebSocket / SSE Query Parameters
- `?api_key=<token>` — auth token in query string at `/api/v1/stream/sse/{channel}`, `/api/v1/stream/ws/{channel}`, `/api/v1/ws/events`, `/api/v1/ws/pipeline/{stage}` — **tokens visible in server logs**
- `?token=<token>` — alternative token param for websocket events
- `?last_event_id=<id>` — event replay from this ID — `websocket_routes.py`
- `?channel=<name>` — channel/topic name in path param for SSE/WS

### Path Parameters (Object IDs — IDOR Vectors)
- `{finding_id}` — UUID/integer, **NO AUTH on findings endpoints** — `findings_routes.py`
- `{user_id}` — user UUID — `admin_router.py`, `users_router.py`
- `{team_id}` — team UUID — `admin_router.py`, `teams_router.py`
- `{backup_id}` — backup record ID, **NO ORG FILTER** — `backup_engine.py`
- `{org_id}` — organization ID in tenant endpoints — `tenant_router.py`
- `{scenario_id}`, `{campaign_id}` — attack simulation objects — `attack_sim_router.py`
- `{fix_id}` — autofix record — `autofix_router.py`
- `{bundle_id}` — evidence bundle — `evidence_router.py`
- `{webhook_id}` — webhook subscription — `webhook_events_router.py`
- `{job_id}` — bulk job — `bulk_router.py`
- `{filename}` — export filename (path traversal mitigated) — `bulk_router.py` L988
- `{resource_type}/{resource_id}` — audit resource history — `audit_router.py`
- `{key_id}` — API key — `apikey_router.py`
- `{provider}` — SSO provider name — `sso_router.py`
- `{scanner_type}` — scanner webhook type (regex-validated) — `scanner_ingest_router.py`

---

## 6. Network & Interaction Map

### 6.1 Entities

| Title | Type | Zone | Tech | Data | Notes |
|---|---|---|---|---|---|
| UserBrowser | Identity | Internet | Browser/JS | Tokens | External attacker entry point; auth token stored in localStorage |
| ALdeci-API | Service | App | Python 3.11 / FastAPI 0.115 | PII, Tokens, Secrets | Main application backend; 750+ endpoints; port 8000; also serves React SPA |
| ExpressBridge | Service | App | Node.js 20 / Express 5.2.1 | PII, Secrets | SQLite-direct bridge; ~100 unauthenticated routes; port 3000; internal Docker network only |
| NginxProxy | ExternAsset | Edge | Nginx | Public | Rate limiting (10 req/s), HSTS, security headers; proxies to ALdeci-API |
| SQLite-Auth | DataStore | Data | SQLite 3 | PII, Tokens | `auth.db` — users, API key hashes, SSO configs, SAML assertions; world-readable (644) |
| SQLite-Audit | DataStore | Data | SQLite 3 | PII | `audit.db` — audit trail; all mutating events |
| SQLite-Findings | DataStore | Data | SQLite 3 | PII | `fixops_exposure_cases.db` — vulnerability findings; no tenant isolation in findings_routes |
| SQLite-Backups | DataStore | Data | SQLite 3 | PII, Secrets | `backup_engine` DB — backup records; cross-tenant IDOR via get_backup(org_id=None) |
| SQLite-Sessions | DataStore | Data | SQLite 3 | Tokens | `session_manager` — active sessions; 24h TTL |
| SQLite-AttackPaths | DataStore | Data | SQLite 3 | PII | `attack_paths.db` — attack path nodes/edges; org_id isolation partially applied |
| SQLite-SSO | DataStore | Data | SQLite 3 | Tokens, Secrets | SSO sessions/providers; no org_id column on `sso_sessions` table |
| SQLite-Analytics | DataStore | Data | DuckDB / SQLite | PII | `analytics.db` + DuckDB for complex queries |
| n8nEngine | Service | App | n8n (Node.js) | Secrets | Port 5678; 400+ integrations; `N8N_BASIC_AUTH_ACTIVE=false` — **NO AUTH by default** |
| DependencyTrack | Service | App | Java / DependencyTrack | Public | Ports 8080/8081; optional Docker profile; SBOM analysis |
| OIDCProvider | ThirdParty | ThirdParty | Okta / Azure AD / Google | Tokens | External identity provider; OIDC RS256; JWKS URI fetched via PyJWKClient |
| SAMLProvider | ThirdParty | ThirdParty | SAML 2.0 IdP | Tokens | External SAML IdP; metadata fetched via httpx (no SSRF validation) |
| JiraInstance | ThirdParty | ThirdParty | Jira (user-configurable) | Secrets | User-supplied instance_url — SSRF vector; `jira_sync.py` L130 |
| ServiceNowInstance | ThirdParty | ThirdParty | ServiceNow (user-configurable) | Secrets | User-supplied instance_url — SSRF vector; `servicenow_sync.py` L149 |
| GitHubAPI | ThirdParty | ThirdParty | GitHub API (user-configurable base_url) | Secrets | Custom Enterprise base_url — SSRF vector; `sdlc_connectors.py` L152 |
| LLMProviders | ThirdParty | ThirdParty | OpenAI / Anthropic / OpenRouter | Secrets | AI/ML inference; API keys in env |
| CloudProviders | ThirdParty | ThirdParty | AWS / Azure / GCP | Secrets | CSPM cloud credentials; full credential sets in env |

### 6.2 Entity Metadata

| Title | Metadata Key: Value; Key: Value |
|---|---|
| ALdeci-API | Hosts: `http://host.docker.internal:8000`; Auth: JWT HS256 (`FIXOPS_JWT_SECRET`), API key (`fixops_/aldeci_ prefix`), SSO OIDC/SAML; AuthBypass: `FIXOPS_AUTH_MODE` defaults to `"dev"` → admin context without credentials; DefaultToken: `aldeci-demo-token` (docker-compose); JWTSecret: hardcoded fallback `"fixops-dev-secret-change-in-production"` in `auth_middleware.py:39`; Suites: suite-api(8000), suite-core(8001), suite-attack(8002), suite-integrations(8003), suite-feeds(8004), suite-evidence-risk(8005) |
| ExpressBridge | Hosts: `http://localhost:3000`; Auth: None (zero auth on all ~100 routes); DB Access: read-only SQLite via `better-sqlite3`; Routes: cases, secrets, compliance, brain, nerve-center, attack-sim, autofix, playbooks, integrations, algorithms, copilot; Exposure: Internal Docker network only (not directly accessible via port 8000) |
| SQLite-Auth | Path: `.fixops_data/auth.db`; Permissions: 644 (world-readable in container); Tables: users, api_keys, sso_configs, saml_assertions, sessions; Consumers: ALdeci-API, ExpressBridge (read-only) |
| SQLite-Backups | Path: `.fixops_data/backup.db`; IDOR: `get_backup(backup_id, org_id=None)` omits tenant filter; Encryption: XOR cipher with hardcoded key `aldeci-backup-key-2026` |
| OIDCProvider | Issuers: Okta, Azure AD, Google, Generic; Token Format: RS256 JWT; JWKS URI: fetched via `PyJWKClient` (SSRF if discovery endpoint compromised); State/Nonce: generated per-request; File: `suite-core/core/sso_provider.py` |
| n8nEngine | Port: 5678; Auth: `N8N_BASIC_AUTH_ACTIVE=false`; Capabilities: 400+ integrations including HTTP requests, database queries, file operations; Risk: unauthenticated n8n = RCE via workflow creation |

### 6.3 Flows (Connections)

| FROM → TO | Channel | Path/Port | Guards | Touches |
|---|---|---|---|---|
| UserBrowser → ALdeci-API | HTTP | `:8000 /api/v1/users/login` | None (rate-limited) | PII (credentials) |
| UserBrowser → ALdeci-API | HTTP | `:8000 /api/v1/auth/sso/{provider}/login` | None | Tokens |
| UserBrowser → ALdeci-API | HTTP | `:8000 /api/v1/findings/*` | **None — MISSING AUTH** | PII (security findings) |
| UserBrowser → ALdeci-API | HTTP | `:8000 /api/v1/auth/sso (CRUD)` | **None — MISSING AUTH** | Secrets (SSO configs) |
| UserBrowser → ALdeci-API | HTTP | `:8000 /api/v1/auth/keys (auth_router)` | **None — MISSING AUTH** | Tokens (API keys) |
| UserBrowser → ALdeci-API | HTTP | `:8000 /api/v1/users` | auth:user (via get_org_id dep) | PII |
| UserBrowser → ALdeci-API | HTTP | `:8000 /api/v1/admin/*` | auth:admin (app-level dep, not inline) | PII, Secrets |
| UserBrowser → ALdeci-API | HTTP | `:8000 /api/v1/backups/{id}` | auth:user (no org_id isolation) | PII, Secrets |
| UserBrowser → ALdeci-API | HTTP | `:8000 /api/v1/dast/scan` | auth:user | Public (target URL) |
| UserBrowser → ALdeci-API | WS | `:8000 /api/v1/ws/events` | **None (stub auth)** | PII (security events) |
| UserBrowser → ALdeci-API | HTTP | `:8000 /api/v1/scanner-ingest/webhook/{type}` | scanner type validation only | PII (scanner data) |
| UserBrowser → ALdeci-API | HTTP | `:8000 /docs` | None | Public (API schema) |
| ExternalWebhook → ALdeci-API | HTTP | `:8000 /api/v1/webhooks/jira,github,gitlab,...` | HMAC signature | Public (webhook payloads) |
| ALdeci-API → SQLite-Auth | File | local | vpc-only | PII, Tokens, Secrets |
| ALdeci-API → SQLite-Findings | File | local | vpc-only | PII |
| ALdeci-API → SQLite-Backups | File | local | vpc-only (IDOR risk) | PII, Secrets |
| ALdeci-API → OIDCProvider | HTTPS | `:443` (ext.) | https-only, no private IP check | Tokens |
| ALdeci-API → SAMLProvider | HTTPS | `:443` (ext.) | https-only, no private IP check | Tokens |
| ALdeci-API → JiraInstance | HTTPS | user-supplied | **No SSRF protection** | Secrets |
| ALdeci-API → ServiceNowInstance | HTTPS | user-supplied | **No SSRF protection** | Secrets |
| ALdeci-API → GitHubAPI | HTTPS | user-supplied base_url | **No SSRF protection** | Secrets |
| ALdeci-API → DAST-Target | HTTP/HTTPS | user-supplied | scheme check only (no private IP block) | Public |
| ALdeci-API → n8nEngine | HTTP | `:5678` (internal) | vpc-only, no auth on n8n | Secrets |
| ALdeci-API → LLMProviders | HTTPS | `:443` (ext.) | API key auth | Secrets |
| ExpressBridge → SQLite-* | File | local (read-only) | **None** | PII, Tokens, Secrets |

### 6.4 Guards Directory

| Guard Name | Category | Statement |
|---|---|---|
| auth:user | Auth | Requires valid JWT or API key (`require_auth` dep in `auth_middleware.py`); dev bypass active if `FIXOPS_AUTH_MODE!="enforced"` |
| auth:admin | Authorization | Requires `admin:all` scope; enforced at app-factory mount level for `/api/v1/admin/*`; NOT enforced inline in `admin_router.py` handlers |
| auth:super_admin | Authorization | Requires `super_admin` role with `system:config` permission; only in `rbac.py` `require_role` dep |
| auth:dev-bypass | Auth | Active when `FIXOPS_AUTH_MODE` is not `"enforced"` (default) — grants admin context to any unauthenticated request; `auth_middleware.py` L192 |
| auth:demo-bypass | Auth | Active when `FIXOPS_MODE=demo/dev/development/local` AND no token/key configured; `auth_deps.py` L190 |
| scope:admin_all | Authorization | Checks `"admin:all"` in JWT/API key scopes via `require_scope("admin:all")` dep; `auth_middleware.py` L238 |
| scope:api_key | Authorization | `api_key_auth` dep in `auth_deps.py` L174; sets `request.state.user_role/scopes`; used by `apikey_router.py` and `gate_router.py` |
| rbac:permission | Authorization | `require_permission(RBACPermission.X)` dep maps to 28-permission RBAC model; `rbac.py` L786 |
| rbac:minimum_role | Authorization | `require_role(minimum=RBACRole.X)` dep checks role hierarchy; `rbac.py` L820 |
| ownership:org_id | ObjectOwnership | Tenant isolation via `org_id` parameter on SQLite queries; **frequently missing** (backup, findings, attack-path engines) |
| ownership:user | ObjectOwnership | Some endpoints check user ownership of resource; inconsistently applied |
| sig:hmac_github | Protocol | SHA-256 HMAC of request body using `GITHUB_WEBHOOK_SECRET`; `webhook_verifier.py` |
| sig:hmac_jira | Protocol | HMAC-SHA256 of request body using Atlassian webhook secret; `webhook_verifier.py` |
| sig:x_gitlab_token | Protocol | Header comparison of `X-Gitlab-Token`; `webhook_verifier.py` |
| sig:okta | Protocol | Okta HMAC signature verification; `webhook_router.py` |
| ssrf:private_ip | Network | `_is_private_ip()` DNS resolution + RFC1918 check; applied to webhook subscriptions only; `webhook_subscriptions_router.py` L97 |
| ssrf:https_only | Protocol | Scheme must be `https`; applied to OIDC/SAML discovery, webhook subscriptions |
| rate_limit:login | RateLimit | 5 failed attempts per 5 minutes per email; `users_router.py` L192 |
| rate_limit:api | RateLimit | Nginx: 10 req/s per IP, burst 20; Python middleware: 100 req/min default, 1000 req/min admin |
| rate_limit:sso | RateLimit | 10 req/min per IP on SSO callback; `sso_router.py` |
| cors:restricted | Protocol | Origin allowlist via `FIXOPS_CORS_ORIGINS` env var; FastAPI CORS middleware |
| no-guard | Auth | **Endpoint has zero authentication** — see all findings_routes.py endpoints, auth_router.py SSO CRUD, auth_router.py API key management, scanner-ingest detect, websocket stub auth |
| tenant:missing | Authorization | Documented isolation failures: backup_engine (org_id=None path), findings_routes (no org_id), sso_sessions (no org_id column), redis_queue (shared namespace) |

---

## 7. Role & Privilege Architecture

### 7.1 Discovered Roles

The application has **two parallel role systems** that are not fully integrated:

**System 1: `auth_models.py` UserRole** (used by JWT claims, API key validation, `auth_middleware.py`):

| Role Name | Privilege Level | Scope/Domain | Code Implementation |
|---|---|---|---|
| viewer | 1 | Global | 6 scopes: read:sbom, read:findings, read:graph, read:feeds, read:evidence, read:integrations — `auth_models.py` L31 |
| analyst | 2 | Global | 10 scopes: above + write:sbom, write:findings, read/write:evidence + attack:execute — `auth_models.py` L31 |
| admin | 5 | Global | All 13 scopes including admin:all, attack:execute — `auth_models.py` L31 |
| service | 5 | Global | All 13 scopes (same as admin) — `auth_models.py` L31 |

**System 2: `rbac.py` RBACRole / BuiltinRoles** (used by `require_permission`, `require_role` RBAC engine deps):

| Role Name | Privilege Level | Scope/Domain | Code Implementation |
|---|---|---|---|
| viewer | 1 | Org (org-scoped) | 5 perms: findings:read, connectors:read, reports:read, users:read, compliance:read — `rbac.py` L141 |
| developer | 2 | Org | Viewer + findings:triage, autofix:view — `rbac.py` L157 |
| security_analyst | 3 | Org | Developer + findings:write, council:view, attack_sim:read, compliance:read — `rbac.py` L175 |
| compliance_officer | 4 | Org | Analyst + compliance:manage, compliance:evidence, reports:create, reports:export — `rbac.py` L193 |
| admin | 5 | Org | All 25 permissions except system:config — `rbac.py` L211 |
| super_admin | 6 | **System-wide** | All 28 permissions including system:config — `rbac.py` L249 |
| SRE | 2 | Org | read:findings, read/run:pipeline, read:connectors, read:dashboard — `rbac.py` L673 |
| dev-user (bypass) | 5 | default org | Full admin context when dev bypass active — `auth_middleware.py` L196 |

### 7.2 Privilege Lattice

```
Privilege Ordering (→ means "can access resources of"):
anon → viewer → developer → security_analyst → compliance_officer → admin → super_admin

Parallel Isolation (|| means "not ordered relative to each other"):
developer || SRE (both at level 2, different permission sets)
analyst (auth_models) ≠ security_analyst (rbac) — DIFFERENT ROLE SYSTEMS

Role System Mismatch:
auth_models.UserRole: viewer | analyst | admin | service
rbac.RBACRole: viewer | developer | security_analyst | compliance_officer | admin | super_admin | SRE

JWT claims use auth_models roles; RBAC engine checks use rbac.RBACRole
→ A JWT claiming "analyst" may not map correctly to rbac checks expecting "security_analyst"

Dev Bypass Modes (bypass normal privilege lattice entirely):
FIXOPS_AUTH_MODE != "enforced" → any unauthenticated request gets admin context
FIXOPS_MODE = demo/dev/development/local → same effect
```

### 7.3 Role Entry Points

| Role | Default Landing Page | Accessible Route Patterns | Authentication Method |
|---|---|---|---|
| anon (bypass active) | `/` (full dashboard) | ALL routes (dev bypass grants admin) | None required when bypass active |
| anon (bypass off) | `/login` | `/login`, `/api/v1/users/login`, `/api/v1/auth/sso/*`, `/api/v1/findings/*` (no auth on findings) | None |
| viewer | `/#/mission-control` | `/api/v1/findings` (read), `/api/v1/audit/logs` (READ_AUDIT_LOG perm), `/api/v1/analytics/*`, `/api/v1/triage/*` | Bearer JWT / API key |
| security_analyst | `/#/discover` | Viewer routes + `/api/v1/findings/{id}/status` (write), `/api/v1/attack-sim/*` (read) | Bearer JWT |
| admin | `/#/mission-control` (all sections) | All user routes + `/api/v1/admin/*`, `/api/v1/auth/keys`, `/api/v1/tenants`, `/api/v1/self-learning/demo/*` | Bearer JWT + `admin:all` scope |
| super_admin | Full admin + system config | All admin routes + `/api/v1/system/config`, `system:config` permission | Bearer JWT + `super_admin` role |
| API User (demo) | `/#/mission-control` | All routes (authenticated as admin with `aldeci.authToken` in localStorage) | API key from localStorage |

### 7.4 Role-to-Code Mapping

| Role | Middleware/Guards | Permission Checks | Storage Location |
|---|---|---|---|
| viewer | `require_auth()` in `auth_middleware.py` | `has_scope("read:findings")` etc. | JWT `role`+`scopes` claims; SQLite `users.role` |
| analyst | `require_auth()` | `has_scope("write:findings")`, `has_scope("attack:execute")` | JWT claims |
| admin | `require_auth()` + `require_scope("admin:all")` OR app-mount dep | `auth.has_scope("admin:all")` returns True for any admin:all bearer | JWT claims; `admin:all` scope |
| super_admin | `require_role(RBACRole.SUPER_ADMIN)` RBAC dep | `rbac_engine.check_permission(user, "system:config")` | JWT claims + rbac.py ROLE_PERMISSIONS |
| SRE | `require_role(RBACRole.SRE)` | RBAC permission subset | JWT claims |
| dev-bypass | None (bypass skips all checks) | Returns `AuthContext(role="admin", scopes=ALL)` | Not stored — runtime only; `auth_method="dev-bypass"` |

---

## 8. Authorization Vulnerability Candidates

### 8.1 Horizontal Privilege Escalation Candidates

| Priority | Endpoint Pattern | Object ID Parameter | Data Type | Sensitivity | Notes |
|---|---|---|---|---|---|
| **CRITICAL** | `GET /api/v1/findings/{finding_id}` | finding_id | security_findings | HIGH — security posture, CVEs, assets | **NO AUTH AT ALL** — any unauthenticated caller; `findings_routes.py` |
| **CRITICAL** | `GET /api/v1/findings` | None | security_findings | HIGH | **NO AUTH, NO TENANT ISOLATION** — returns all findings across all orgs |
| **CRITICAL** | `GET /api/v1/backups/{backup_id}` | backup_id | backup_data | HIGH — full DB dumps | Cross-tenant IDOR: `get_backup(backup_id)` omits org_id when org_id=None; `backup_engine.py` L362 |
| **CRITICAL** | `DELETE /api/v1/backups/{backup_id}` | backup_id | backup_data | HIGH | Cross-tenant delete; `backup_engine.py` L378 |
| **CRITICAL** | `POST /api/v1/backups/{backup_id}/restore` | backup_id | backup_data | HIGH | Cross-tenant restore (data overwrite) |
| High | `GET /api/v1/users/{id}` | id | user_data | HIGH — PII, credentials | Requires auth; check if org_id isolation enforced; `users_router.py` |
| High | `GET /api/v1/admin/users/{user_id}` | user_id | user_data | HIGH | Admin endpoint; check if cross-tenant access possible; `admin_router.py` L186 |
| High | `GET /api/v1/admin/teams/{team_id}` | team_id | team_data | MEDIUM | Admin endpoint; `admin_router.py` L292 |
| High | `GET /api/v1/tenants/{org_id}/stats` | org_id | tenant_data | HIGH | Tenant stats by org_id — should be self-only; `tenant_router.py` |
| High | `GET /api/v1/auth/sso/{id}` | id | sso_config | HIGH — SSO certs/secrets | **NO AUTH** on SSO config CRUD; `auth_router.py` |
| High | `GET /api/v1/auth/keys/{key_id}` | key_id | api_key | HIGH — credentials | Admin endpoint; `apikey_router.py` |
| Medium | `GET /api/v1/autofix/fixes/{fix_id}` | fix_id | code_fix | MEDIUM | `autofix_router.py` |
| Medium | `GET /api/v1/attack-sim/scenarios/{scenario_id}` | scenario_id | attack_data | MEDIUM | `attack_sim_router.py` |
| Medium | `GET /api/v1/attack-sim/campaigns/{campaign_id}` | campaign_id | attack_data | MEDIUM | `attack_sim_router.py` |
| Medium | `GET /evidence/bundles/{bundle_id}/download` | bundle_id | evidence_files | MEDIUM — compliance data | File download; `evidence_router.py` |
| Medium | `GET /evidence/{release}` | release | evidence_data | MEDIUM | `evidence_router.py` |
| Medium | `GET /api/v1/audit/logs/resource/{resource_type}/{resource_id}` | resource_id | audit_data | MEDIUM | Resource audit history; `audit_router.py` |
| Medium | `GET /api/v1/bulk/jobs/{job_id}` | job_id | job_data | LOW-MEDIUM | Bulk job results; `bulk_router.py` |
| Medium | `GET /api/v1/teams/{id}` | id | team_data | MEDIUM | Team membership/data; `teams_router.py` |
| Low | `GET /api/v1/workflows/{id}` | id | workflow_config | LOW-MEDIUM | `workflows_router.py` |
| Low | `GET /api/v1/inventory/applications/{id}` | id | app_inventory | MEDIUM | `inventory_router.py` |
| Low | `GET /api/v1/analytics/findings/{id}` | id | finding_analytics | MEDIUM | `analytics_router.py` |

### 8.2 Vertical Privilege Escalation Candidates

| Target Role | Endpoint Pattern | Functionality | Risk Level |
|---|---|---|---|
| admin (via auth bypass) | All endpoints | Full access when `FIXOPS_AUTH_MODE != "enforced"` (default) — no credentials needed | **CRITICAL** |
| admin (via no-auth) | `POST /api/v1/auth/keys` (auth_router) | Create API key with any role including admin:all — **NO AUTH REQUIRED** | **CRITICAL** |
| admin (via no-auth) | `POST /api/v1/users` | Create user with role=admin — **possible missing auth** on create_user endpoint | **CRITICAL** |
| admin | `/api/v1/admin/users` | Full user CRUD — role assignment, status control | High |
| admin | `/api/v1/admin/teams` | Team management | High |
| admin | `/api/v1/tenants` | Multi-tenant management | High |
| admin | `/api/v1/auth/keys` (apikey_router) | API key lifecycle management | High |
| admin | `/api/v1/self-learning/demo/seed` | Seed demo data (data manipulation) | High |
| admin | `/api/v1/self-learning/demo/reset` | Reset application state | High |
| admin | `DELETE /api/v1/tenants/{org_id}` | Delete entire tenant | High |
| super_admin | System config endpoints | `system:config` permission — infrastructure control | High |
| any role (via default) | All authenticated endpoints | When bypass active, dev-user="admin" context returned without credentials | **CRITICAL** |

### 8.3 Context-Based Authorization Candidates

| Workflow | Endpoint | Expected Prior State | Bypass Potential |
|---|---|---|---|
| SSO Login | `GET /api/v1/auth/sso/{provider}/callback` | SSO auth initiated via `/login`, state/nonce generated | State parameter reuse; direct callback with crafted state |
| SAML Response | `POST /api/v1/auth/sso/{provider}/callback` | SAML AuthnRequest sent, response expected | Replay attack on SAMLResponse (check if replay protection exists) |
| API Key Create (auth_router) | `POST /api/v1/auth/keys` | Admin authentication expected (not enforced) | Direct key creation without any auth — unlimited keys with any scope |
| SSO Config Create | `POST /api/v1/auth/sso` | Admin authentication expected (not enforced) | Create malicious SSO provider pointing to attacker-controlled IdP |
| Backup Restore | `POST /api/v1/backups/{backup_id}/restore` | Backup existence, org ownership | Cross-tenant restore via IDOR (backup_id without org check) |
| Scanner Ingest | `POST /api/v1/scanner-ingest/webhook/{type}` | Valid scanner type | Inject malicious scanner data with `pipeline=true` to poison findings DB |
| DAST Scan | `POST /api/v1/dast/scan` | Authenticated user, valid target URL | Supply `http://169.254.169.254/` to trigger SSRF to cloud metadata |
| Webhook Registration | `POST /api/v1/events/webhooks` | Authenticated user, valid HTTPS URL | DNS rebinding attack post-registration to bypass SSRF checks |
| Triage Enrich | `POST /api/v1/triage/enrich` | Authenticated user | Submit up to 200 findings with arbitrary content for pipeline ingestion |
| GraphQL Mutation | `POST /api/v1/graphql` | Authenticated user | Access arbitrary data fields; custom parser may be bypassable |

---

## 9. Injection Sources

### SQL Injection Sources

**Assessment:** The primary SQL injection patterns in this codebase use f-string interpolation for SQL clause *structure* (column names, keywords) but parameterized queries for *values*. After careful analysis, the examined instances do NOT have confirmed user-controlled input reaching unparameterized SQL fragments. However, the architectural pattern is high-risk.

| Source | File | Line | Pattern | User Input Path | HTTP Endpoint | Risk |
|---|---|---|---|---|---|---|
| Dynamic WHERE (structure only) | `suite-core/core/vuln_scanner_engine.py` | 436 | `f"SELECT * FROM vuln_findings WHERE {where}"` | Hardcoded clauses; parameterized values | Vulnerability findings API | LOW |
| Dynamic WHERE (structure only) | `suite-core/core/access_anomaly_engine.py` | 455 | `f"SELECT * FROM access_anomalies WHERE {' AND '.join(clauses)}"` | Hardcoded clauses; parameterized values | Anomaly API | LOW |
| Dynamic WHERE (structure only) | `suite-core/core/audit_analytics.py` | 852, 858, 920, 923 | `f"SELECT COUNT(*) FROM audit_entries WHERE {base_clause}"` | Hardcoded clauses; parameterized values | `GET /api/v1/audit/logs` | LOW |
| Dynamic WHERE (structure only) | `suite-core/core/ai_orchestrator.py` | 562, 584 | `f"SELECT * FROM agent_tasks {where}"` | Hardcoded clauses; parameterized values | AI orchestrator API | LOW |
| Static IN clause | `suite-core/core/api_gateway.py` | 805 | `f"SELECT * FROM client_versions WHERE api_version IN ({version_list})"` | `DEPRECATED_VERSIONS` is static frozenset | `GET /api/v1/api-gateway/deprecation-alerts` | LOW |
| GraphQL variable injection | `suite-core/core/graphql_schema.py` | resolver functions | Custom GraphQL parser merges `variables` into resolver `args` | `{"query": "...", "variables": {...}}` body | `POST /api/v1/graphql` | MEDIUM — depends on resolver SQL construction |

### Command Injection Sources

| Source | File | Line | Pattern | User Input Path | HTTP Endpoint | Risk |
|---|---|---|---|---|---|---|
| shlex.split + subprocess | `suite-core/services/repro/verifier.py` | 143-156 | `subprocess.run(shlex.split(command), shell=False)` | YAML plan `steps[].command` field | No confirmed HTTP route found (local CLI only) | OUT-OF-SCOPE (no HTTP surface) |
| subprocess + handler_path | `suite-core/connectors/trustgraph_mcp_bridge.py` | 130, 451 | `subprocess.run(["tg-set-mcp-tool", ..., "--handler", handler_path])` | `handler_path` from connector registration body | `POST /api/v1/connectors/register` (if TrustGraph connector type) | MEDIUM — shell=False but arbitrary binary path |

### Server-Side Code Execution (eval/exec)

| Source | File | Line | Pattern | User Input Path | HTTP Endpoint | Risk |
|---|---|---|---|---|---|---|
| eval() with incomplete sandbox | `suite-core/core/posture_advisor.py` | 104 | `eval(condition, {"__builtins__": {}}, posture_data)` | `posture_data` dict from request body (locals); `condition` string is hardcoded templates | `POST /api/v1/posture-advisor/analyze` | MEDIUM — condition currently hardcoded; sandbox bypassable via `__class__.__mro__` |

### Deserialization Sources

| Source | File | Line | Pattern | User Input Path | HTTP Endpoint | Risk |
|---|---|---|---|---|---|---|
| pickle.load() — ML model | `suite-core/core/bn_lr.py` | 74 | `pickle.load(handle)` — model loading | Internal model path; SHA-256 sidecar hash verification | No direct HTTP route found | LOW (hash-verified) |
| _pickle.load() — online learning | `suite-core/core/zero_gravity.py` | 1338 | `_pickle.load(f)` — model state | Internal model path; optional `path` override | No direct HTTP route found | LOW-MEDIUM (optional path param risk) |
| pickle.load() — regression | `suite-core/core/ml/regression_predictor.py` | 1269 | `pickle.load()` | Internal model path; SHA-256 sidecar | No direct HTTP route found | LOW |

### LFI/Path Traversal Sources

| Source | File | Line | Pattern | User Input Path | HTTP Endpoint | Risk |
|---|---|---|---|---|---|---|
| File download by filename | `suite-api/apps/api/bulk_router.py` | 988 | `filepath = _EXPORTS_DIR / filename` | `filename` URL path param | `GET /api/v1/bulk/exports/{filename}` | LOW (triple defense: `..`/`/`/`\` check + extension allowlist + symlink-resolved `relative_to()`) |

### SSRF Sources (detailed in Section 10)

| Source | File | Line | User-Controllable Input | Validation | HTTP Endpoint | Risk |
|---|---|---|---|---|---|---|
| OIDC discovery | `suite-core/core/sso_provider.py` | 219-234 | `issuer_url` from SSO config | HTTPS scheme only, no private IP | `POST /api/v1/auth/sso` (admin) | HIGH |
| SAML IdP metadata | `suite-core/core/sso_provider.py` | 464-487 | `idp_metadata_url` from SSO config | HTTPS scheme only, no private IP | `POST /api/v1/auth/sso` (admin) | HIGH |
| JWKS URI (cascading) | `suite-core/core/sso_provider.py` | 306-323 | Extracted from OIDC discovery | None — derived from potentially malicious provider | Discovery endpoints | CRITICAL |
| DAST scanner target | `suite-core/core/dast_scanner.py` | 1565 | `target_url` request body | Scheme + netloc only, no private IP | `POST /api/v1/dast/scan`, `POST /api/v1/app-security/scans` | HIGH |
| Webhook delivery | `suite-api/apps/api/webhook_subscriptions_router.py` | 289-291 | `url` at subscription creation | Full SSRF validation at creation; DNS rebinding at delivery | `POST /api/v1/events/webhooks` | MEDIUM |
| n8n connector webhook | `suite-core/connectors/n8n_connector.py` | 128-150 | `webhook_url` from registration | **NONE** | `POST /api/v1/connectors/register` | MEDIUM |
| Jira instance URL | `suite-core/core/jira_sync.py` | 130 | `jira_url` from connector config | **NONE** | `POST /api/v1/connectors/register` (Jira type) | MEDIUM |
| ServiceNow instance URL | `suite-core/core/servicenow_sync.py` | 149 | `instance_url` from connector config | **NONE** | `POST /api/v1/connectors/register` (ServiceNow type) | MEDIUM |
| GitHub Enterprise base_url | `suite-core/connectors/sdlc_connectors.py` | 152 | `base_url` from connector settings | **NONE** | Connector registration/test endpoints | MEDIUM |
| Webhook generic notifier | `suite-core/core/webhook_notifier.py` | 256 | URL from webhook subscription | Depends on upstream validation | Webhook delivery paths | MEDIUM |

### XSS Sinks

| Source | File | Line | Context | Attack Vector | Risk |
|---|---|---|---|---|---|
| dangerouslySetInnerHTML — LLM output | `suite-ui/aldeci-ui-new/src/components/layout/CopilotSidebar.tsx` | referenced | HTML body | LLM response content rendered as raw HTML; prompt injection → XSS | HIGH |
| innerHTML assignment | `suite-ui/aldeci-ui-new/e2e/helpers/endpoints.ts` | 103 | HTML body | `innerHTML = userInput` — test reference to production pattern | HIGH (verify in prod code) |
| dangerouslySetInnerHTML — SOC Dashboard | `suite-ui/aldeci-ui-new/src/pages/mission-control/SOCDashboard.tsx` | 298-316 | HTML body | Documented as XSS vulnerability — "React XSS via dangerouslySetInnerHTML in Copilot Sidebar" | HIGH |
| CSP unsafe-inline | `suite-api/apps/api/middleware.py` | 16-80 | Style context | `style-src 'self' 'unsafe-inline'` in SPA CSP — enables CSS-based data exfiltration | MEDIUM |

### XML/XXE Sources

| Source | File | Line | Pattern | User Input Path | HTTP Endpoint | Risk |
|---|---|---|---|---|---|---|
| XML scanner output parsing | `suite-core/core/scanner_parsers.py` | 92 | `defusedxml.ElementTree.fromstring()` (primary); `ET.fromstring()` with regex strip (fallback) | Scanner file content | `POST /api/v1/scanner-ingest/upload`, `POST /api/v1/scanner-ingest/webhook/{type}` | LOW (defusedxml primary; fallback regex has theoretical bypass with crafted encoding) |
| SAML XML parsing | `suite-core/core/sso_provider.py` | SAMLProvider | `defusedxml.ElementTree` | SAMLResponse form field | `POST /api/v1/auth/sso/{provider}/callback` | LOW (defusedxml) |
| Normalizer bridge | `suite-core/connectors/normalizer_bridge.py` | 35 | `import xml.etree.ElementTree as ET` | Scanner output XML | `POST /api/v1/scanner-ingest/*` | LOW (delegates to scanner_parsers.py which uses defusedxml) |

