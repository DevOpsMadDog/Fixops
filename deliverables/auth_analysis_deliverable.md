# Authentication Analysis Report

**Assessment Date:** 2026-04-16
**Target:** http://host.docker.internal:8000 (Aldeci CTEM+ Platform)
**Analyst Role:** Authentication Analysis Specialist

---

## 1. Executive Summary

- **Analysis Status:** Complete
- **Key Outcome:** Twelve authentication flaws were identified spanning authentication bypass, token management weaknesses, SSO logic failures, missing abuse defenses, and transport exposure. The most critical findings center on three independent authentication bypass mechanisms hardcoded into the application, a hardcoded default JWT secret enabling token forgery, and a missing OIDC nonce validation enabling ID-token replay attacks against SSO-enabled deployments.
- **Purpose of this Document:** This report provides strategic context on the Aldeci CTEM+ platform's authentication mechanisms, including dominant flaw patterns and precise code-level root causes. It is designed to guide the exploitation specialist in weaponizing the vulnerabilities listed in the companion `auth_exploitation_queue.json`.

**Live Instance State:** At analysis time, the live instance at `http://host.docker.internal:8000` returns `HTTP 401` for unauthenticated requests, with the message `"Invalid or missing API token"`. This indicates `FIXOPS_API_TOKEN` is set and `auth_strategy="token"` is active. The dev-bypass mechanisms are *not currently active* on the live instance, but they exist as deterministic code paths that can be triggered through environment misconfiguration or by reaching a second deployment of this codebase. All vulnerability findings are code-grounded and exploitation-ready under the documented conditions.

---

## 2. Dominant Vulnerability Patterns

### Pattern 1: Multiple Independent Authentication Bypass Mechanisms

- **Description:** The application contains three separate, independently-triggered pathways that bypass all authentication and grant full admin access. Two are controlled by environment variables with insecure defaults, and one is a fallback code path executed when the auth strategy variable is empty.
- **Implication:** A single misconfiguration (an unset environment variable, a deployment using default config) renders the entire application completely unauthenticated. These bypasses are not edge cases; they are the code's default behavior.
- **Representative Findings:** `AUTH-VULN-01`, `AUTH-VULN-02`, `AUTH-VULN-03`

### Pattern 2: Credential & Token Hardcoding

- **Description:** The application ships with a well-known, hardcoded fallback JWT secret (`"fixops-dev-secret-change-in-production"`) and a default API token (`"aldeci-demo-token"`) in `docker-compose.yml`. If either is used in production without being overridden, attackers can forge arbitrary admin-level JWTs or authenticate with the default token.
- **Implication:** Any deployment that does not explicitly override these defaults is fully compromised from day one.
- **Representative Findings:** `AUTH-VULN-04`, `AUTH-VULN-05`

### Pattern 3: SSO/OIDC Logic Failures

- **Description:** The OIDC callback flow fails to validate the `nonce` claim (stored at authorization time, never compared at callback time), and the SSO user account-linking logic falls back from the immutable `sub` claim to the mutable `email` claim when `sub` is absent. These are independent flaws in the same flow.
- **Implication:** The nonce failure enables ID-token replay attacks. The email-based account linking enables an nOAuth-style account takeover where an attacker controls an OIDC provider and sets their email to match a victim's.
- **Representative Findings:** `AUTH-VULN-09`, `AUTH-VULN-10`

### Pattern 4: Stateless Token Management Without Revocation

- **Description:** JWTs are issued with a 24-hour TTL and include a `jti` (JWT ID) field marked for revocation, but no server-side blocklist or denylist is implemented. Logging out only marks the SQLite session as inactive; the JWT itself remains cryptographically valid for the remainder of its TTL.
- **Implication:** Stolen or compromised tokens remain usable for up to 24 hours after a user logs out. An attacker who obtains a JWT (e.g., via XSS against the `localStorage`-stored token) has a 24-hour exploitation window regardless of the victim logging out.
- **Representative Finding:** `AUTH-VULN-06`

---

## 3. Strategic Intelligence for Exploitation

### Authentication Architecture

The platform implements a four-layer authentication model:

1. **Global `_verify_api_key` FastAPI Dependency** (`suite-api/apps/api/app.py` lines 2097–2188): Applied at router-include time via `dependencies=[Depends(_verify_api_key)]`. This is the primary gate. It dispatches to one of three sub-strategies: `"token"` (API token), `"jwt"` (JWT Bearer), or empty string (admin bypass).

2. **`auth_middleware.py` `require_auth()` Dependency** (`suite-core/core/auth_middleware.py` lines 133–201): A second, independent FastAPI dependency used on some route-level handlers. Has its own dev bypass: `if _AUTH_MODE != "enforced": return admin context`. Default `_AUTH_MODE = "dev"`.

3. **`auth_deps.py` `api_key_auth` Dependency** (`suite-api/apps/api/auth_deps.py` lines 174–251): A third auth implementation, used by select routers (apikey_router, gate_router). Also has a dev bypass: `if _DEV_MODE and not _HAS_TOKEN_AUTH and not _HAS_JWT_AUTH: return admin`.

4. **Route-Level Guards:** RBAC scope checks (`_require_scope("admin:all")`) applied on top of successful auth.

### Token & Credential Details

| Credential Type | Format | Storage | Default/Fallback Value |
|---|---|---|---|
| JWT | HS256, 24h TTL | `localStorage` as `aldeci.authToken` | Secret: `"fixops-dev-secret-change-in-production"` |
| API Token (global) | Arbitrary string | Env var `FIXOPS_API_TOKEN` | `"aldeci-demo-token"` (docker-compose default) |
| API Keys (app-managed) | `fixops_<32hex>` | bcrypt hash in `auth.db` | N/A |
| API Keys (key manager) | `aldeci_<32hex>` | SHA-256 (no salt) in `auth.db` | N/A |
| Session ID | `sess_<16hex>` | SQLite `sessions` table | New ID generated on each login |

### JWT Claims & Validation

Issued payload (from `auth_middleware.py:create_jwt()` lines 58–77):
```json
{
  "user_id": "<uuid>",
  "email": "<email>",
  "role": "<role>",
  "scopes": ["<scope1>", ...],
  "jti": "<uuid>",
  "iat": <timestamp>,
  "exp": <timestamp+24h>
}
```

Decode call (`auth_middleware.py` line 80):
```python
jwt.decode(token, _JWT_SECRET, algorithms=["RS256"])
```
- **`aud` is NOT validated** — no audience check
- **`iss` is NOT validated** — no issuer check
- **`sub` is NOT validated** — no subject binding
- Only `exp` and `iat` are validated (PyJWT defaults)

### Environment Variables That Control Auth Behavior

| Variable | Default | Effect When Default Used |
|---|---|---|
| `FIXOPS_AUTH_MODE` | `"dev"` | Auth bypass active; any request gets admin |
| `FIXOPS_MODE` | (not set) | If `demo/dev/development/local` AND no tokens: admin bypass |
| `FIXOPS_API_TOKEN` | `""` | If set, auth_strategy="token"; if empty AND no JWT secret: bypass |
| `FIXOPS_JWT_SECRET` | `"fixops-dev-secret-change-in-production"` | Known-secret JWT forgery possible |
| `FIXOPS_JWT_EXPIRY_HOURS` | `"24"` | 24h token lifetime |

### SSO/OIDC Flow Summary

- Providers: Okta, Azure AD, Google, generic OIDC
- Authorization URL generated with `state` and `nonce` parameters
- State IS validated in callback (one-time use, provider mismatch check)
- **Nonce is NOT validated** — stored at `sso_router.py:231` but never compared in callback
- Account linking: `sub || email` fallback at `sso_provider.py:686`
- Redirect URI: dynamically constructed from `request.base_url` (Host header influence)
- `RelayState` post-login redirect IS validated via `sanitize_redirect_url()`

### Login Rate Limiting

- **Login endpoint** (`/api/v1/users/login`): 5 failed attempts per 5 minutes **per email** (no per-IP limit at app level)
- **SSO callback**: 10 attempts per minute **per IP** (in-memory only, cleared on restart)
- **Nginx**: 10 req/s per IP with burst 20 (global across all endpoints)
- **No rate limiting** at the auth_router level for SSO config CRUD or API key management (but these are protected by `admin:all` scope in the live deployment)

### Password Storage

- bcrypt with 12 rounds (`passlib.context.CryptContext`) for user passwords — **secure**
- API keys in `auth_middleware.py`: bcrypt — **secure**
- API keys in `api_key_manager.py`: SHA-256 single round, no salt — **weak** (only exploitable with DB access, out of external scope)

---

## 4. Findings Detail

### AUTH-VULN-01: Auth Strategy Fallback Grants Admin Without Credentials

**File:** `suite-api/apps/api/app.py:2186–2188`

```python
# Fallback — no auth strategy → admin (dev mode)
request.state.user_role = "admin"
request.state.user_scopes = _ALL_SCOPES
```

The `_verify_api_key` global dependency has a catch-all `else` branch that executes when `auth_strategy` is neither `"token"` nor `"jwt"`. The strategy defaults to `""` (empty string) if `FIXOPS_API_TOKEN` is unset and no overlay config specifies a strategy (`app.py:2063`). Under this condition, **every request** to every protected endpoint receives admin-level access with no credential check.

---

### AUTH-VULN-02: FIXOPS_AUTH_MODE Defaults to "dev" — Admin Bypass

**File:** `suite-core/core/auth_middleware.py:39,192–201`

```python
_AUTH_MODE = os.getenv("FIXOPS_AUTH_MODE", "dev")  # line 39

# lines 192-201
if _AUTH_MODE != "enforced":
    return AuthContext(
        user_id="dev-user",
        email="dev@fixops.local",
        role="admin",
        org_id="default",
        scopes=ROLE_SCOPES[UserRole.ADMIN],
        auth_method="dev-bypass",
    )
```

When `FIXOPS_AUTH_MODE` is not explicitly set to `"enforced"`, any request that reaches `require_auth()` — even with zero credentials — is granted a full admin `AuthContext`. This is the **default behavior** of the application.

---

### AUTH-VULN-03: Demo Bypass in auth_deps.py — Admin Without Credentials

**File:** `suite-api/apps/api/auth_deps.py:94–101,189–196`

```python
_DEV_MODE = os.getenv("FIXOPS_MODE", "").lower() in {"demo", "dev", "development", "local"}
_HAS_TOKEN_AUTH = bool(_env_api_token)
_HAS_JWT_AUTH = bool(_jwt_secret and len(_jwt_secret) >= 32)

# lines 189-196
if _DEV_MODE and not _HAS_TOKEN_AUTH and not _HAS_JWT_AUTH:
    request.state.user_role = "admin"
    request.state.user_scopes = ["admin:all"]
    request.state.demo_mode = True
    return
```

Active when `FIXOPS_MODE=demo|dev|development|local` AND no API token AND no JWT secret are configured.

---

### AUTH-VULN-04: Hardcoded Default JWT Secret

**File:** `suite-core/core/auth_middleware.py:39`

```python
_JWT_SECRET = os.getenv("FIXOPS_JWT_SECRET", "fixops-dev-secret-change-in-production")
```

The fallback secret `"fixops-dev-secret-change-in-production"` is publicly known (committed to source code). Any deployment that fails to set `FIXOPS_JWT_SECRET` will use this secret, enabling an attacker to craft arbitrary, fully-valid admin-level JWTs.

---

### AUTH-VULN-05: Default API Token "aldeci-demo-token" in docker-compose

**File:** `docker-compose.yml:20`

```yaml
- FIXOPS_API_TOKEN=${FIXOPS_API_TOKEN:-aldeci-demo-token}
```

The well-known token `"aldeci-demo-token"` is used when `FIXOPS_API_TOKEN` is not overridden. Any deployment using this docker-compose file without setting the variable grants global admin access via `Authorization: Bearer aldeci-demo-token`.

---

### AUTH-VULN-06: No JWT Revocation — 24h Post-Logout Token Validity

**File:** `suite-core/core/auth_middleware.py:58–77` (JWT creation), `suite-api/apps/api/session_router.py:241–248` (session termination)

JWTs include a `jti` field (line 74: `"jti": token_id`) described as "for token revocation," but no revocation blocklist is implemented anywhere in the codebase. The logout flow at `session_router.py` only marks the SQLite session record as `is_active = 0`; the corresponding JWT remains cryptographically valid for the remainder of its 24-hour TTL.

---

### AUTH-VULN-07: User Enumeration via Differential HTTP Status Codes

**File:** `suite-api/apps/api/users_router.py:195–205`

```python
# Non-existent user OR wrong password:
raise HTTPException(status_code=401, detail="Invalid credentials")

# Inactive user:
raise HTTPException(status_code=403, detail="Account is not active")
```

An attacker can distinguish between non-existent accounts and existing-but-inactive accounts by observing the HTTP status code (401 vs. 403). This enables account enumeration without triggering the email-based rate limit.

---

### AUTH-VULN-08: Missing IP-Based Rate Limiting on Login (Password Spraying)

**File:** `suite-api/apps/api/users_router.py:150–167`

```python
_login_attempts = get_persistent_store("login_attempts")  # keyed by EMAIL
```

The login rate limit is keyed by email address (5 attempts / 5 minutes per email). No per-IP limit exists at the application layer. An attacker can spray a single common password across thousands of different email accounts, staying within the per-email limit while making unlimited cross-account attempts. Nginx's global 10 req/s limit provides partial mitigation but is insufficient against a slow-and-low spray.

---

### AUTH-VULN-09: OIDC Nonce Not Validated in SSO Callback

**File:** `suite-api/apps/api/sso_router.py:231` (nonce stored), callback handler (nonce never compared)

The nonce is generated and stored at authorization time:
```python
_STATE_STORE[state] = {"nonce": nonce, "provider": provider}  # sso_router.py:231
```

In the OIDC callback handler, the stored nonce is never retrieved or compared against the `nonce` claim in the returned ID token. This means a previously captured ID token can be replayed against the callback endpoint.

---

### AUTH-VULN-10: SSO Account Linking by Mutable Email Claim (nOAuth)

**File:** `suite-core/core/sso_provider.py:686`

```python
"sub": user_info.sub or user_info.email,  # Fallback to email if sub is empty
```

When constructing the local JWT after OIDC authentication, if `sub` is empty, the system falls back to `email` for user identification. An attacker who controls an OIDC provider (e.g., creates their own tenant on a multi-tenant IdP) can configure their account with a target victim's email address. If the application accepts this provider's tokens and the `sub` claim is absent or empty, account takeover results.

---

### AUTH-VULN-11: Weak Password Policy — No Complexity or Common-Password Check

**File:** `suite-api/apps/api/users_router.py:109`

```python
password: str = Field(..., min_length=8, description="User password")
```

The only server-side password enforcement is a minimum length of 8 characters. No complexity requirements (uppercase, numbers, special characters), no dictionary/common-password rejection. Users can set passwords like `"password"`, `"12345678"`, or `"qwertyui"`.

---

### AUTH-VULN-12: No HTTPS — Auth Tokens Transmitted in Cleartext

**File:** `docker/nginx-ui.conf:11` (`listen 80;`), `docker/nginx-aldeci.conf:5` (`listen 3001;`)

The application is HTTP-only. Neither Nginx config implements TLS termination or HTTP→HTTPS redirect. The `Strict-Transport-Security` header is present in `nginx-aldeci.conf:21` but is **ignored by browsers when served over HTTP**. All `Authorization: Bearer` tokens, `X-API-Key` headers, and login credentials are transmitted in cleartext, enabling interception by network-positioned attackers.

---

## 5. Secure by Design: Validated Components

These components were analyzed and found to have robust defenses. They are low-priority for further testing.

| Component/Flow | Endpoint/File Location | Defense Mechanism Implemented | Verdict |
|---|---|---|---|
| Password Hashing | `suite-core/core/auth_middleware.py` | `bcrypt` with 12 rounds via `passlib.CryptContext` for user passwords | SAFE |
| Session ID Generation | `suite-core/core/session_manager.py:87–88` | `secrets.token_hex(16)` — cryptographically random, `sess_` prefix | SAFE |
| Session Rotation on Login | `suite-core/core/session_manager.py:205` | New session ID generated on every `create_session()` call — no reuse | SAFE |
| Session Invalidation on Logout | `suite-core/core/session_manager.py:307–323` | `terminate_session()` marks `is_active=0` in SQLite — server-side invalidation | SAFE |
| OAuth2 State Parameter | `suite-api/apps/api/sso_router.py:293–298` | State validated as one-time-use with provider binding; removed from store on use | SAFE |
| OIDC Token Signature | `suite-core/core/sso_provider.py:362–419` | RS256 validation with `PyJWKClient`, `aud`, `iss`, `exp` all validated | SAFE |
| SAML XML Parsing | `suite-core/core/sso_provider.py` | `defusedxml` used for XXE-safe XML parsing | SAFE |
| RelayState Redirect Validation | `suite-api/apps/api/sso_router.py:261–267` | `sanitize_redirect_url()` with domain allowlist check | SAFE |
| API Key Entropy (auth_middleware) | `suite-core/core/auth_middleware.py:88–94` | `secrets.token_urlsafe(32)` + bcrypt storage | SAFE |
| Login Rate Limit (per-account) | `suite-api/apps/api/users_router.py:150–167` | 5 attempts / 5 min per email, persisted to SQLite | SAFE |
| SSO Rate Limit | `suite-api/apps/api/sso_router.py:50–72` | 10 requests / 60s per IP, thread-safe | SAFE |
| Security Response Headers | `suite-api/apps/api/app.py` middleware | `Cache-Control: no-store`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, etc. | SAFE |
| Cache-Control on Auth Responses | Live HTTP response headers | `cache-control: no-store, no-cache, must-revalidate` confirmed on auth endpoints | SAFE |
| SAML HMAC Webhooks | `suite-api/apps/api/webhook_verifier.py` | HMAC-SHA256 signatures on Jira, GitHub, ServiceNow webhooks | SAFE |
