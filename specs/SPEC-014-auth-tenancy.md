# SPEC-014 — Auth + Tenancy

- **Status**: BACKFILL
- **Owner family**: Platform / Auth / Tenancy
- **Routers**:
  - `suite-api/apps/api/auth_router.py` (prefix `/api/v1/auth`)
  - `suite-api/apps/api/auth0_router.py` (prefix varies)
- **Engines / modules**:
  - `suite-api/apps/api/auth_deps.py` — `api_key_auth`, `verify_api_key`, `require_role`, `require_scope`
  - `suite-api/apps/api/org_middleware.py` — `OrgIdMiddleware`, `get_org_id`, `get_current_org_id`
  - `suite-core/core/tenant_isolation.py` — `TenantContext` (ContextVar, SPEC-007)
  - `suite-core/core/key_manager.py` — `KeyManager` (managed key DB)
  - `suite-core/core/user_db.py` — `UserDB` (bcrypt user store)
  - `suite-core/core/rbac_engine.py` — `RBACEngine` (disposable tokens, role-view)
  - `suite-api/apps/api/billing_router.py` — `requires_tier` (billing gate, tier enforcement)
- **Stores**:
  - `data/key_management.db` — managed API keys (SHA-256 hashed, WAL)
  - `data/dev_token_audit.db` — dev-token mint audit log
  - `data/users.db` — user accounts (bcrypt password hashes)
  - per-feature SQLite for email verification, password reset tokens
- **Depends on**: SPEC-005 (air-gap), SPEC-006b (ephemeral dev JWT secret), SPEC-007 (tenancy ContextVar / OrgIdMiddleware), SPEC-008 (HA)
- **Last updated**: 2026-06-01

---

## 1. Intent

Auth + Tenancy is the security perimeter for every API call on ALDECI. It establishes who is calling (authentication), what they may do (authorisation via roles + scopes), and which tenant's data they see (org_id isolation). The surface is intentionally small and load-bearing: all 8 300+ mounted routes depend on one of two auth dependency callables (`api_key_auth` or `verify_api_key`). Tenancy is enforced via `OrgIdMiddleware` + `TenantContext` (ContextVar, fixed from `threading.local` in SPEC-007). The billing gate (`requires_tier`) layers on top for feature-tier enforcement.

---

## 2. Scope — endpoints

### 2a. Auth router (`/api/v1/auth`)

| Method | Path | Purpose | Auth | Notes |
|--------|------|---------|------|-------|
| POST | /api/v1/auth/signup | Self-service signup → managed API key (returned once) + email verification | none | Rate-limited 5/min per IP |
| POST | /api/v1/auth/login | Email+password → JWT access (2h) + refresh (7d) | none | Rate-limited 10/min per IP; per-email lockout 5 attempts/15 min |
| POST | /api/v1/auth/refresh | Refresh token → new access token | none | Validates refresh token type; re-checks user active |
| GET | /api/v1/auth/verify-email/{token} | Consume email-verification UUID token | none | 400 on expired/used |
| POST | /api/v1/auth/forgot-password | Request password reset link | none | Always 200 (no enumeration); rate-limited 5/min |
| POST | /api/v1/auth/reset-password | Consume reset token + set new password | none | Rate-limited 10/min; min 12-char password |
| POST | /api/v1/auth/dev-token | Mint short-lived JWT for dev/Playwright (FIXOPS_DEV_MODE=true required) | none | 403 in production; audit-logged; rate-limited 10/min |
| GET | /api/v1/auth/sso | List SSO configs (caller's org) | api_key_auth + admin:all scope | Admin-only |
| POST | /api/v1/auth/sso | Create SSO config | api_key_auth + admin:all scope | Admin-only |
| GET | /api/v1/auth/sso/{id} | Get SSO config | api_key_auth + admin:all scope | 404 on cross-org (no existence leak) |
| PUT | /api/v1/auth/sso/{id} | Update SSO config | api_key_auth + admin:all scope | 404 on cross-org |
| POST | /api/v1/auth/keys | Create managed API key | api_key_auth + admin:all scope | Returns plaintext once |
| POST | /api/v1/auth/keys/{id}/rotate | Rotate API key (grace period) | api_key_auth + admin:all scope | |
| DELETE | /api/v1/auth/keys/{id} | Revoke API key | api_key_auth + admin:all scope | |
| GET | /api/v1/auth/keys | List managed keys | api_key_auth + admin:all scope | |
| GET | /api/v1/auth/keys/expiring | Keys expiring within N days | api_key_auth + admin:all scope | |
| POST | /api/v1/auth/keys/cleanup | Deactivate expired keys | api_key_auth + admin:all scope | |
| GET | /api/v1/auth/keys/{id}/audit | Key audit trail | api_key_auth + admin:all scope | |
| POST | /api/v1/auth/disposable-token | Mint disposable scoped token | api_key_auth | |
| DELETE | /api/v1/auth/disposable-token/{id} | Revoke disposable token | api_key_auth | |
| GET | /api/v1/auth/disposable-tokens | List disposable tokens | api_key_auth | Cross-org blocked unless admin:all |
| POST | /api/v1/auth/role-view | Switch role view (temporary override) | api_key_auth | |
| GET | /api/v1/auth/role-view | Get active role-view override | api_key_auth | |
| DELETE | /api/v1/auth/role-view/{id} | End role-view override | api_key_auth | |
| POST | /api/v1/auth/oauth/{provider}/start | OAuth2 PKCE flow start (google, github) | none (pre-auth) | Returns redirect_url + state |
| GET | /api/v1/auth/oauth/{provider}/callback | OAuth2 code exchange → JWT pair | none (pre-auth) | CSRF-state validated |

**Out of scope**: SAML SP-initiated flows (`/auth/saml/{idp}/initiate`, `/auth/saml/{idp}/callback`) — these routes exist in auth_router but the SAML library integration is not fully wired to a real IdP. OAuth2 providers (Google, GitHub) are gated on `FIXOPS_OAUTH_{PROVIDER}_CLIENT_ID/SECRET` env vars.

---

## 3. Data contracts

### Strategy 1 — Managed API key (primary, `api_key_auth`)

Keys are minted via `POST /auth/signup` (auto-issued, `admin` role) or `POST /auth/keys` (admin-only). All managed keys carry the `fixops_` prefix; `auth_deps._validate_managed_key` fast-paths on prefix before DB lookup.

```
Request:  X-API-Key: fixops_<random>
          OR ?api_key=fixops_<random>

Validation pipeline (api_key_auth):
  1. fast-path: check FIXOPS_API_TOKEN static set (comma-separated) — O(1), no DB
  2. if token starts with "fixops_": KeyManager.validate_key(raw) → ManagedKey or None
     ManagedKey carries: user_id, role, scopes, is_active, expires_at
  3. if matched: request.state.user_role = key.role
                 request.state.user_scopes = key.scopes (or all scopes for admin)
                 request.state.user_id = key.user_id

Success: no HTTP response body change; downstream handlers read request.state.*
Failure: 403 {"detail": "Invalid API token"}  (token present but not valid)
Missing: 401 {"detail": "Authentication required..."}
```

### Strategy 2 — JWT Bearer (`api_key_auth` + `verify_api_key`)

Issued by `POST /auth/login` (HS256, `FIXOPS_JWT_SECRET`). TTL: access 2h (`FIXOPS_JWT_EXPIRE_HOURS`), refresh 7d (`FIXOPS_JWT_REFRESH_DAYS`).

```
Request:  Authorization: Bearer <jwt>

JWT claims (access token):
  { "sub": "<user_id>", "email": "...", "role": "admin|security_analyst|developer|viewer",
    "org_id": "<org>", "scopes": ["read:findings", ...],
    "token_type": "access", "iat": ..., "exp": ..., "jti": "<random>" }

Validation (auth_deps._decode_jwt):
  - HS256 with FIXOPS_JWT_SECRET (min 32 chars)
  - requires exp, iat, sub claims
  - optional issuer check via FIXOPS_JWT_ISSUER
  - max token size 4 096 bytes (guard against parsing attacks)
  - claims.sub must be non-empty after decode

On success: request.state.user_role, .user_scopes, .org_id, .user_id populated
Failure:    401 {"detail": "Token expired"}
            401 {"detail": "Invalid token"}
            401 {"detail": "JWT auth not configured"}  (FIXOPS_JWT_SECRET absent)
```

### Strategy 3 — Dev-mode passthrough (`FIXOPS_MODE=dev`)

```
Condition: FIXOPS_MODE in {demo, dev, development, local}
           AND no FIXOPS_API_TOKEN AND no FIXOPS_JWT_SECRET configured
           AND server bound to loopback (127.0.0.1 / localhost / ::1)

Effect:    request.state.user_role = "admin"
           request.state.user_scopes = ["admin:all"]
           request.state.demo_mode = True

Safety guard: auth_deps._check_dev_mode_host_binding() runs at import time.
  If FIXOPS_MODE=dev AND host binding is non-loopback → RuntimeError at startup
  (process fails fast, never silently exposes unauthenticated admin API).

Production: FIXOPS_MODE must NOT be "dev"/"demo". With FIXOPS_API_TOKEN or
            FIXOPS_JWT_SECRET configured, dev-mode passthrough is never reached.
```

### Signup → managed key

```
POST /api/v1/auth/signup
  body: { "email": "...", "password": "<min 12 chars>",
          "first_name": "...", "last_name": "..." }
  → 201 {
      "user_id": "<uuid>",
      "email": "...",
      "org_id": "org-<user_id>"  (or X-Org-ID header / ?org_id= param if supplied),
      "message": "Account created. Your API key is in the `api_key` field...",
      "email_verified": false,
      "api_key": "fixops_<random>",   # plaintext — returned ONCE, never retrievable
      "api_key_id": "<uuid>"
    }
  | 409 {"detail": "Email already registered"}
  | 422 email format / blank name validation failures
```

### Login → JWT pair

```
POST /api/v1/auth/login
  body: { "email": "...", "password": "..." }
  → 200 {
      "access_token": "<hs256-jwt>",
      "refresh_token": "<hs256-jwt>",
      "token_type": "bearer",
      "expires_in": 7200    # 2h default; FIXOPS_JWT_EXPIRE_HOURS controls
    }
  | 401 {"detail": "Invalid credentials"}   # uniform — no enumeration
  | 403 {"detail": "Account is not active"}
  | 429 {"detail": "Too many login attempts. Retry in Ns."}
  | 503 {"detail": "JWT auth not configured (FIXOPS_JWT_SECRET missing or too short)"}
```

### Dev-token

```
POST /api/v1/auth/dev-token
  body: { "org_id": "default", "role": "admin", "email": "dev@verify" }
  → 200 {
      "access_token": "<hs256-jwt signed with FIXOPS_JWT_SECRET or ephemeral secret>",
      "token_type": "Bearer",
      "expires_in": 3600,
      "user": { "sub": "dev-dev@verify", "email": "...", "role": "admin",
                "org_id": "default", "scopes": ["admin:all"] }
    }
  | 403 {"detail": "dev mode disabled"}  when FIXOPS_DEV_MODE != true
```

Ephemeral secret: when `FIXOPS_JWT_SECRET` is absent, `auth_router._EPHEMERAL_DEV_JWT_SECRET` (generated once at process start via `secrets.token_hex(32)`) is used. Tokens are invalid after a process restart. This is the per SPEC-006b design: a static hardcoded constant is explicitly NOT used — that would allow source-readers to forge tokens. (Cross-ref: SPEC-006b §8 PIV-CAC / crypto-hardening.)

---

## 4. Functional requirements

- **REQ-014-01**: Every protected endpoint uses one of `Depends(api_key_auth)` or `Depends(verify_api_key)`. No protected route may be mounted without one of these dependencies.
- **REQ-014-02**: `api_key_auth` validates in order: (1) static `FIXOPS_API_TOKEN` set, (2) managed key via `KeyManager` (`fixops_` prefix gate), (3) JWT Bearer. All three populate `request.state.user_role` and `request.state.user_scopes`. Dev-mode passthrough only activates when all configured strategies are absent AND mode is dev/demo AND server is loopback-bound.
- **REQ-014-03**: `verify_api_key` (the `create_app`-era closure replacement) mirrors `api_key_auth` behaviour including managed-key (`fixops_` prefix) validation so that routers mounted with either dependency accept the same credential types consistently.
- **REQ-014-04**: `POST /auth/signup` mints a real, persisted, revocable managed API key via `KeyManager` (SHA-256 hashed; `fixops_` prefix; org-scoped). The plaintext key is returned exactly once and never stored.
- **REQ-014-05**: `POST /auth/login` returns a generic 401 for bad credentials regardless of whether the email exists (prevents enumeration). Per-email lockout triggers at 5 failed attempts in a 15-minute window, returning 429.
- **REQ-014-06**: `POST /auth/dev-token` is gated by `FIXOPS_DEV_MODE=true`. In production (default) it returns 403. Every successful mint is audit-logged to `dev_token_audit.db` with org_id, role, email, IP.
- **REQ-014-07**: SSO config management (`GET/POST/PUT /auth/sso`) enforces `admin:all` scope via `_require_sso_admin()`. Cross-org access returns 404 (not 403) to avoid leaking the existence of another org's SSO config.
- **REQ-014-08**: API key management (`POST/DELETE/GET /auth/keys`) enforces `admin:all` scope via `_require_admin()`. Returns 403 for non-admin callers.
- **REQ-014-09**: `OrgIdMiddleware` resolves `org_id` per-request in priority order: (1) JWT claim `org_id` from `request.state.org_id` (set by auth layer), (2) `X-Org-ID` header, (3) `org_id` query parameter, (4) literal `"default"`. The resolved value is stored in `_org_id_var` (ContextVar) for the duration of the request task and reset in a `finally` block.
- **REQ-014-10**: `TenantContext` uses `contextvars.ContextVar` (not `threading.local`) so concurrent asyncio coroutines never read each other's `org_id`. SPEC-007 AC-007-01 test proves this.
- **REQ-014-11**: `requires_tier(min_tier)` returns `org_id` to the caller. When `STRIPE_SECRET_KEY` is absent it default-allows all orgs (self-hosted behaviour). When Stripe is configured, it enforces `starter < pro < enterprise`; insufficient tier → 402 with `{"error":"tier_required","required_tier":...,"current_tier":...}`.
- **REQ-014-12**: `POST /auth/forgot-password` always returns 200 regardless of whether the email is registered. No email enumeration. Token is UUID4, 60-minute TTL, single-use.
- **REQ-014-13**: Password minimum is 12 characters (NIST SP 800-63B) enforced at the Pydantic field level on both `POST /auth/signup` and `POST /auth/reset-password`.

---

## 5. Non-functional requirements

- **Latency**: `api_key_auth` for static token is O(1) (set membership). Managed-key path involves one SQLite read (KeyManager); JWT decode is pure-CPU. All three paths must complete in < 10ms per request excluding application logic.
- **Tenancy**: `org_id` is resolved per-request via ContextVar. Cross-org data access returns empty lists or 404 depending on the endpoint — never leaks existence of another org's resources. The SPEC-007 lint gate blocks new `Query(default="default")` org_id params and new shadow `def get_org_id` definitions.
- **Security**:
  - Dev-mode auth bypass is structurally blocked on non-loopback binds (startup `RuntimeError`).
  - JWT secret minimum 32 chars enforced; short secret produces 503 with explicit error.
  - Managed key plaintext never stored (SHA-256 in DB).
  - API key prefix `fixops_` enables fast pre-DB rejection of non-managed tokens.
  - Login brute-force: per-IP rate limit (10/min) + per-email lockout (5 attempts / 15 min).
- **Failure mode**: When `FIXOPS_JWT_SECRET` is absent and dev-mode is off, JWT-only requests return 401 `"JWT auth not configured"`. When no auth strategy is configured and dev-mode is off, all protected endpoints return 401.

---

## 6. Acceptance criteria (executable)

- **AC-014-01**: `pytest tests/test_api_auth.py tests/test_auth_api.py tests/test_auth_public_endpoints.py -q` — all pass.
- **AC-014-02**: `pytest tests/test_tenant_context_asyncio.py -q` — 7/7 pass (concurrent tasks keep separate org_id; threading.local bug absent per SPEC-007 AC-007-01).
- **AC-014-03**: `pytest tests/test_tenancy_lint.py -q` — 11/11 pass (gate bites on new violations per SPEC-007 AC-007-02).
- **AC-014-04**: `pytest tests/test_multi_tenant_isolation.py tests/test_cross_tenant_isolation_wave2.py -q` — 45 pass, 16 skip (engine-not-configured, known).
- **AC-014-05**: `curl -X POST http://localhost:8000/api/v1/auth/signup -d '{"email":"x@x.com","password":"12charpasswd","first_name":"A","last_name":"B"}' -H "Content-Type: application/json"` → 201 with `api_key` field containing a `fixops_` prefixed string.
- **AC-014-06**: `curl -X POST http://localhost:8000/api/v1/auth/login -d '{"email":"bad@bad.com","password":"wrong"}' -H "Content-Type: application/json"` → 401 `"Invalid credentials"` (not 404, not 422).
- **AC-014-07**: `curl -X POST http://localhost:8000/api/v1/auth/dev-token` without `FIXOPS_DEV_MODE=true` → 403 `"dev mode disabled"`.
- **AC-014-08**: `curl -X GET http://localhost:8000/api/v1/auth/sso -H "X-API-Key: <viewer-key>"` → 403 `"Insufficient permissions: SSO configuration management requires admin:all scope"`.
- **AC-014-09**: `curl -X GET http://localhost:8000/api/v1/auth/sso/<other-org-id> -H "X-API-Key: <valid-admin-key>"` → 404 (cross-org existence not leaked).
- **AC-014-10**: With `STRIPE_SECRET_KEY` set and org on `starter` tier: `GET /api/v1/executive-reporting/...` (requires pro) → 402 `{"error":"tier_required","required_tier":"pro","current_tier":"starter"}`.
- **AC-014-11**: `pytest tests/test_tenant_isolation.py tests/test_tenant_lease_b2.py tests/test_tenant_rbac.py -q` — pass.

---

## 7. Debate log

| Date | Mode | Verdict / change |
|------|------|-----------------|
| 2026-06-01 | Backfill review | Two dependency callables (`api_key_auth` and `verify_api_key`) exist for historical reasons: `verify_api_key` is the replacement for the old `create_app` closure; `api_key_auth` is the newer, simpler callable. Both accept the same 3 credential types and must stay in sync. This is a known maintenance burden — a future cleanup could unify to one callable. Documented as-is. |
| 2026-06-01 | Red-Team | Dev-mode host-binding guard (`_check_dev_mode_host_binding`) runs at import time. A container that starts with `HOST=0.0.0.0` and `FIXOPS_MODE=dev` will crash at startup rather than silently expose admin access. This is correct and intentional. |
| 2026-06-01 | Backfill review | `requires_tier` default-allow when Stripe unconfigured is intentional for self-hosted deployments. Documented so operators know to set `STRIPE_SECRET_KEY` to enforce tier gates. |

---

## 8. Implementation notes

### Three auth strategies in detail

| Strategy | Trigger condition | request.state outcome |
|----------|------------------|----------------------|
| Static token | `FIXOPS_API_TOKEN` env var set AND token matches | `user_role="admin"`, `user_scopes=["admin:all"]` |
| Managed key | Token has `fixops_` prefix; matches `KeyManager` DB | `user_role=key.role`, `user_scopes=key.scopes` (or all for admin) |
| JWT Bearer | `Authorization: Bearer <jwt>` AND `FIXOPS_JWT_SECRET` >= 32 chars | `user_role=claims.role`, `user_scopes=claims.scopes`, `org_id=claims.org_id` |
| Dev passthrough | `FIXOPS_MODE=dev`, no auth configured, loopback bind | `user_role="admin"`, `user_scopes=["admin:all"]`, `demo_mode=True` |

### Org_id resolution chain (OrgIdMiddleware + get_org_id)

Priority (highest first):
1. `request.state.org_id` — set by JWT decode in `api_key_auth` (from `claims["org_id"]`)
2. `X-Org-ID` HTTP header
3. `?org_id=` query parameter
4. Literal `"default"` (single-tenant / dev fallback)

The resolved value is written to:
- `_org_id_var` ContextVar (per asyncio task — asyncio-safe)
- `request.state.org_id` (for middleware/handlers that read it)
- `TenantContext` (ContextVar-backed since SPEC-007 — not `threading.local`)
- structlog context bind (all log lines carry `org_id=`)

### Tenancy lint gate (SPEC-007)

Current allowlist: 1730 frozen violations at 2026-06-01:
- V1 (1724): `org_id` param with `Query(default="default")` — in routers including `cloud_posture_router.py`, etc.
- V2 (1): non-canonical `get_org_id` import
- V3 (5): shadow `def get_org_id` in `analytics_routes.py`, `exposure_case_router.py` (x2), `mcp_routes.py`, `trustgraph_routes.py`

The lint gate (`scripts/tenancy_lint.py`) blocks new violations. Existing V1 violations do not create cross-tenant data leaks at the engine layer because all engines enforce `WHERE org_id = ?` internally, but the API layer does not validate caller-org match for these params. Mass V1 remediation is a separate effort.

### Scopes catalogue

```python
_ALL_SCOPES = (
    "read:sbom", "write:sbom",
    "read:findings", "write:findings",
    "read:graph", "write:graph",
    "read:feeds",
    "read:evidence", "write:evidence",
    "read:integrations", "write:integrations",
    "attack:execute",
    "admin:all",
)
```

Role → scopes mapping (from `auth_router.py`):
- `admin` → `["admin:all"]`
- `security_analyst` → `["read:findings","write:findings","read:sbom","read:evidence","write:evidence"]`
- `developer` → `["read:findings","read:sbom"]`
- `viewer` → `["read:findings","read:sbom"]`

### Billing tier order

```
starter (0) < pro (1) < enterprise (2)
```

`requires_tier("pro")` enforced on: `/api/v1/executive-reporting/` (most endpoints), `/api/v1/risk-quantifier/` (some endpoints).
`requires_tier("enterprise")` enforced on: `/api/v1/executive-reporting/` (board-level endpoints).

When `STRIPE_SECRET_KEY` is absent: all orgs pass the gate (default-allow). When present: tier is looked up per org; insufficient tier → HTTP 402.

### Key files

- `suite-api/apps/api/auth_router.py` — 2002 lines, all auth/SSO/keys/OAuth/SAML routes
- `suite-api/apps/api/auth_deps.py` — 622 lines, `api_key_auth` + `verify_api_key` + `require_role` + `require_scope`
- `suite-api/apps/api/org_middleware.py` — 267 lines, `OrgIdMiddleware` + `get_org_id` dependency
- `suite-core/core/tenant_isolation.py` — `TenantContext` ContextVar (SPEC-007 fix)
- `suite-api/apps/api/billing_router.py` — `requires_tier` factory at line 347
- `scripts/tenancy_lint.py` — lint gate scanner
- `specs/tenancy_allowlist.txt` — 1730 frozen violations

### Cross-references

- SPEC-005: Air-gap enforced default — auth layer must operate without outbound network (JWT validation is pure-CPU; managed key is SQLite-local).
- SPEC-006b: Crypto hardening — ephemeral dev JWT secret (`_EPHEMERAL_DEV_JWT_SECRET`) is the correct design: process-scoped random, never a static constant, tokens invalidated on restart.
- SPEC-007: Systemic tenancy — `TenantContext` ContextVar fix; lint gate; canonical `Depends(get_org_id)` pattern.
