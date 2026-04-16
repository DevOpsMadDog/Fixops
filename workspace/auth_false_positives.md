# Authentication False Positives Log

## AUTH-VULN-04: JWT Forgery with Hardcoded Secret
**Status:** FALSE POSITIVE on live instance
**What was attempted:**
- Forged JWT with `HS256` algorithm, secret `fixops-dev-secret-change-in-production`
- Payload: `{user_id: "forgeduser99", role: "admin", scopes: ["admin:all"], exp: +24h}`
- Tested against `/api/v1/users/me`, `/api/v1/tenants`, `/api/v1/admin/users`
**Why FALSE POSITIVE:**
- `app.py:1718-1758` (`_load_or_generate_jwt_secret`) generates a random 256-bit key via `secrets.token_hex(32)` when `FIXOPS_JWT_SECRET` is not set
- The hardcoded fallback is ONLY in `auth_middleware.py:39` which is a library, not the running application's JWT validator
- Live test result: all forged JWTs returned `401 Invalid token`
**Root cause note:** `auth_middleware.py` fallback exists but is not used by `app.py`'s `decode_access_token()` function

## AUTH-VULN-01 (on this instance): No-Credential Bypass via Missing auth_strategy
**Status:** NOT EXPLOITABLE on live instance (code vulnerability exists for default deployments)
**What was attempted:**
- Unauthenticated GET/POST to all admin and user endpoints
- No Authorization headers, empty headers, partial headers
**Why NOT EXPLOITABLE HERE:**
- Overlay config at `suite-core/config/fixops.overlay.yml` sets `auth.strategy: token`
- `auth_strategy = "token"` prevents reaching the fallback code at app.py:2186
- All unauthenticated requests returned `401 Invalid or missing API token`

## AUTH-VULN-03 (on this instance): Demo Mode Bypass
**Status:** NOT EXPLOITABLE on live instance
**What was attempted:**
- Unauthenticated requests to all endpoints
**Why NOT EXPLOITABLE HERE:**
- `FIXOPS_MODE=enterprise` is set in docker-compose.yml
- `_DEV_MODE = False` → bypass condition never triggers
