"""
auth_deps.py — Shared authentication dependency for ALdeci/FixOps FastAPI routers.

This module provides a standalone, importable ``api_key_auth`` FastAPI dependency
that validates incoming requests using either:

  * ``X-API-Key`` header (preferred for service-to-service calls)
  * ``Authorization: Bearer <token>`` header (JWT — issued by /api/v1/auth/token)
  * ``?api_key=<token>`` query param (browser-opened URLs / report downloads)

Usage
-----
Import this at the top of any router file and pass it as a dependency:

    from apps.api.auth_deps import api_key_auth
    from fastapi import APIRouter, Depends

    router = APIRouter(prefix="/api/v1/my-feature", dependencies=[Depends(api_key_auth)])

Or on individual endpoints:

    @router.get("/sensitive", dependencies=[Depends(api_key_auth)])
    async def sensitive_endpoint(): ...

Configuration
-------------
The dependency reads the following environment variables at **import time** so it
can be used outside of the ``create_app()`` factory without circular imports:

    FIXOPS_API_TOKEN      — Bearer token for X-API-Key validation (may be
                            comma-separated for multiple tokens).
    FIXOPS_JWT_SECRET     — HMAC-SHA256 secret for JWT validation (>= 32 chars).
    FIXOPS_MODE           — If "demo" or "dev", auth is relaxed so the API
                            starts up even without credentials configured.

Security
--------
- Returns 401 if the credential is missing entirely.
- Returns 403 if the credential is present but invalid/expired.
- Brute-force protection is handled upstream by RateLimitMiddleware.
- This module intentionally has NO imports from apps.api.app to prevent
  circular dependency issues.
"""

from __future__ import annotations

import logging
import os
import secrets as _secrets
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import APIKeyHeader

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_JWT_ALGORITHM = "HS256"
_MAX_TOKEN_LENGTH = 4096  # bytes — guard against parsing attacks
_MIN_JWT_SECRET_LENGTH = 32

# ---------------------------------------------------------------------------
# Load configuration at module import time (once, not per-request)
# ---------------------------------------------------------------------------

def _load_api_tokens() -> tuple[str, ...]:
    """Load expected API tokens from environment."""
    raw = os.getenv("FIXOPS_API_TOKEN", "").strip()
    if not raw:
        return ()
    # Support comma-separated multi-token strings (e.g. CI + dev tokens)
    return tuple(t.strip() for t in raw.split(",") if t.strip())


def _load_jwt_secret() -> Optional[str]:
    """The one JWT key this process signs AND verifies with.

    THREE resolvers used to generate their own key independently —
    ``auth_router._get_dev_jwt_secret``, ``app._load_or_generate_jwt_secret``
    and this one — so with FIXOPS_JWT_SECRET unset, login signed a token with
    one random key while verification used another. Measured end to end:

        POST /api/v1/auth/login    -> 200, a 436-char JWT
        GET  /api/v1/findings      -> 403 with that exact token
        POST /api/v1/scanner-ingest/upload -> 401

    A customer logs in successfully and every screen stays empty. Signing with
    key A and verifying with key B is the same class of defect as writing
    ``rule_id`` and reading ``cve_id``.

    An unset secret now yields ONE process-wide ephemeral key, shared by signer
    and verifier. This does not weaken anything: the key is 64 random hex chars,
    so tokens remain unforgeable, and every endpoint still demands a credential.
    What it costs is persistence — sessions end at the next restart — which is
    why the warning is loud. Following app.py, it is deliberately NOT written to
    disk.

    A secret that IS set but is too short still returns None. That is an
    operator error which would genuinely weaken signing, and silently upgrading
    it to a strong random key would hide the misconfiguration instead of
    surfacing it.
    """
    secret = os.getenv("FIXOPS_JWT_SECRET", "").strip()
    if secret and len(secret) < _MIN_JWT_SECRET_LENGTH:
        logger.warning(
            "JWT signing key is only %d chars (minimum %d) — JWT auth disabled.",
            len(secret),
            _MIN_JWT_SECRET_LENGTH,
        )
        return None
    if secret:
        return secret
    generated = _secrets.token_hex(32)
    # PUBLISH it into the process environment.
    #
    # Generating into a module-level constant is not enough: under uvicorn this
    # module is executed TWICE (the ephemeral-key warning was observed logged
    # twice in a single server run), so each instance minted its own key and
    # login still signed with one while verification used the other — the exact
    # symptom this fallback was added to cure, 200 on /auth/login and 403 on
    # every data endpoint.
    #
    # Writing it back to the environment makes the FIRST generation win for
    # every later reader, including the two other resolvers
    # (auth_router._get_dev_jwt_secret and app._load_or_generate_jwt_secret)
    # which already read this variable. One key, process-wide, still never
    # written to disk.
    os.environ["FIXOPS_JWT_SECRET"] = generated
    logger.warning(
        "FIXOPS_JWT_SECRET is not set — signing and verifying JWTs with an "
        "ephemeral process-scoped key. Logins work, but every session ends at "
        "the next restart. Set FIXOPS_JWT_SECRET to a random 32+ char string "
        "for persistent sessions."
    )
    return generated


def _is_dev_mode() -> bool:
    """Return True when running in demo/dev mode (auth is relaxed)."""
    mode = os.getenv("FIXOPS_MODE", "").lower().strip()
    return mode in ("demo", "dev", "development", "local")


_JWT_SECRET: Optional[str] = _load_jwt_secret()
_DEV_MODE: bool = _is_dev_mode()

# ---------------------------------------------------------------------------
# SECURITY GUARD: refuse to enable dev-mode auth-bypass on non-loopback hosts
#
# Dev-mode grants admin access to EVERY request with no credentials.  If the
# process is bound to a non-loopback address (0.0.0.0, a public IP, etc.) this
# would expose the admin API to any network reachable by that interface.
#
# We check FIXOPS_HOST / HOST / UVICORN_HOST in priority order.  The check
# runs at module-import time (i.e. before any request is served) so the
# process fails fast rather than silently serving an open admin API.
# ---------------------------------------------------------------------------

def _check_dev_mode_host_binding() -> None:
    """Raise RuntimeError when dev-mode auth-bypass is active on a non-loopback bind."""
    if not _DEV_MODE:
        return
    # Loopback addresses that are safe for dev-mode
    _LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1", ""})
    host = (
        os.getenv("FIXOPS_HOST", "")
        or os.getenv("HOST", "")
        or os.getenv("UVICORN_HOST", "")
        or ""
    ).strip().lower()
    # Empty host means the framework default (127.0.0.1 for uvicorn) — safe.
    if host in _LOOPBACK:
        return
    # Any other binding (0.0.0.0, a public IP, a hostname) is unsafe with dev-mode.
    raise RuntimeError(
        f"SECURITY: FIXOPS_MODE=dev (auth-bypass) is enabled but the server "
        f"appears to be bound to a non-loopback address ({host!r}). "
        "Dev-mode auth-bypass must never be enabled on a publicly reachable interface. "
        "Either set FIXOPS_MODE=production (and configure FIXOPS_API_TOKEN / "
        "FIXOPS_JWT_SECRET), or restrict the bind address to 127.0.0.1."
    )


_check_dev_mode_host_binding()

# NOTE: _EXPECTED_TOKENS is intentionally NOT cached at module level.
# Calling _load_api_tokens() per-request allows test fixtures to mutate
# FIXOPS_API_TOKEN between test modules without stale-constant failures.
# Production cost: one os.getenv() call per authenticated request (negligible).

# Determine effective auth strategy (JWT and dev-mode are still boot-time)
_HAS_JWT_AUTH: bool = bool(_JWT_SECRET)

if not _load_api_tokens() and not _HAS_JWT_AUTH:
    if _DEV_MODE:
        logger.warning(
            "SECURITY WARNING: auth_deps is running in %s mode. "
            "All API endpoints are UNAUTHENTICATED — any request receives admin access. "
            "Do NOT expose this service to untrusted networks. "
            "Set FIXOPS_API_TOKEN or FIXOPS_JWT_SECRET to enable real authentication.",
            os.getenv("FIXOPS_MODE", "dev").upper(),
        )
    else:
        logger.error(
            "auth_deps: No FIXOPS_API_TOKEN or FIXOPS_JWT_SECRET configured "
            "and FIXOPS_MODE is not 'demo'/'dev'. All authenticated endpoints "
            "will return 401. Set FIXOPS_API_TOKEN or FIXOPS_JWT_SECRET."
        )

# ---------------------------------------------------------------------------
# Header extractor (auto_error=False so we can return a structured 401)
# ---------------------------------------------------------------------------
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


# ---------------------------------------------------------------------------
# JWT decode helper
# ---------------------------------------------------------------------------
def _decode_jwt(token: str) -> dict:
    """Decode and validate a JWT.  Raises HTTPException on failure.

    Args:
        token: Raw JWT string (without "Bearer " prefix).

    Returns:
        Decoded claims dict.

    Raises:
        HTTPException(401): Token expired, malformed, or missing required claims.
        HTTPException(403): Token valid but insufficient (reserved for future use).
    """
    # Resolve the secret at CALL time, not import time.
    #
    # auth_router mints with os.getenv(...) read live, falling back to a
    # process-scoped ephemeral secret. auth_deps verified against _JWT_SECRET,
    # a snapshot taken when the module was first imported. Whenever those two
    # disagree — the env var arriving after import, a secret loaded at runtime,
    # a test suite configuring it per-case — login succeeds and then every
    # authenticated request 401s "Invalid token". Valid session, total denial,
    # no error that names the cause.
    #
    # Reading the same source the minter reads makes the two sides agree by
    # construction. The import-time value stays as the fallback so behaviour is
    # unchanged in the normal case where the env is set before boot.
    secret = _load_jwt_secret() or _JWT_SECRET
    if not secret:
        try:
            from apps.api.auth_router import _EPHEMERAL_DEV_JWT_SECRET as _dev_secret
            secret = _dev_secret
        except Exception:  # pragma: no cover — router may not be importable here
            secret = None
    if not secret:
        raise HTTPException(status_code=401, detail="JWT auth not configured")

    # Guard: reject oversized tokens before any parsing
    if len(token.encode("utf-8", errors="replace")) > _MAX_TOKEN_LENGTH:
        logger.warning("auth_deps: JWT rejected — exceeds max length (%d bytes)", _MAX_TOKEN_LENGTH)
        raise HTTPException(status_code=401, detail="Invalid token")

    try:
        claims = jwt.decode(
            token,
            secret,
            algorithms=[_JWT_ALGORITHM],
            options={"require": ["exp", "iat", "sub"]},
        )
        # AUTH-VULN-04/05: Validate required claims are non-empty after decode
        if not claims.get("sub"):
            raise HTTPException(status_code=401, detail="Invalid token: missing sub claim")
        if not claims.get("iss") and os.getenv("FIXOPS_JWT_ISSUER"):
            expected_iss = os.getenv("FIXOPS_JWT_ISSUER", "")
            if expected_iss and claims.get("iss") != expected_iss:
                raise HTTPException(status_code=401, detail="Invalid token: issuer mismatch")
        return claims
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=401, detail="Token expired") from exc
    except jwt.MissingRequiredClaimError as exc:
        logger.warning("auth_deps: JWT missing required claim: %s", getattr(exc, "claim", exc))
        raise HTTPException(status_code=401, detail="Invalid token") from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


# ---------------------------------------------------------------------------
# Managed-key DB validation helper
# ---------------------------------------------------------------------------

def _bind_managed_key(request: Request, record) -> None:
    """Attach a validated managed key's role, scopes, user and TENANT to the request.

    Bind the credential's OWN tenant. Only the JWT branch used to do this, so
    an API-key request reached _extract_org_id with no state to read — and
    fell through its otherwise-correct precedence chain to the client-supplied
    X-Org-ID header / ?org_id= query param. That is what let a customer key
    read and write any other tenant.

    Extracted so the X-API-Key path and the Authorization: Bearer path bind
    identically. They did not: a fixops_ key sent as a Bearer token was handed
    to the JWT decoder, which raised 401 before any managed-key check ran.
    """
    key_role = getattr(record, "role", "viewer") or "viewer"
    raw_scopes = getattr(record, "scopes", [])
    key_scopes = raw_scopes if isinstance(raw_scopes, list) else []
    request.state.user_role = key_role
    request.state.user_scopes = key_scopes if key_scopes else [
        s for s in _ALL_SCOPES
    ] if key_role in ("admin", "super_admin") else ["read:findings"]
    if getattr(record, "user_id", None):
        request.state.user_id = record.user_id
    request.state.org_id = getattr(record, "org_id", None) or "default"


def _validate_managed_key(raw_key: str):
    """Try to validate *raw_key* against the KeyManager SQLite DB.

    Returns a ``ManagedKey`` record if the key is active and not expired,
    or ``None`` if the key is unknown / invalid.  Never raises — failures
    are caught and logged so they do not block the auth pipeline.

    The KeyManager stores keys minted via POST /auth/keys and POST /auth/signup.
    Keys are identified by a ``fixops_`` prefix (generated by
    ``core.key_manager._generate_key``).
    """
    if not raw_key or not raw_key.startswith("fixops_"):
        # Fast-path: skip DB lookup for tokens that can't be managed keys
        return None
    try:
        from core.key_manager import KeyManager as _KeyManager
        km = _KeyManager()
        return km.validate_key(raw_key)
    except Exception as exc:  # pragma: no cover
        logger.warning("auth_deps: managed key validation error: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Core dependency callable
# ---------------------------------------------------------------------------
async def api_key_auth(
    request: Request,
    x_api_key: Optional[str] = Depends(_api_key_header),
) -> None:
    """FastAPI dependency that enforces API key or JWT authentication.

    Accepts credentials in three ways (checked in order):
    1. ``X-API-Key: <token>`` header
    2. ``Authorization: Bearer <jwt>`` header
    3. ``?api_key=<token>`` query parameter (browser fallback)

    Raises:
        HTTPException(401): Missing or clearly invalid credential.
        HTTPException(403): Credential present but invalid/rejected.
    """
    # Resolve tokens fresh on every request so env-var changes (e.g. between
    # pytest modules) are reflected immediately without a stale module-level
    # constant.
    expected_tokens: tuple[str, ...] = _load_api_tokens()
    has_token_auth: bool = bool(expected_tokens)

    # Dev/demo mode pass-through when no auth is configured
    if _DEV_MODE and not has_token_auth and not _HAS_JWT_AUTH:
        request.state.user_role = "admin"
        request.state.user_scopes = ["admin:all"]
        # Add a visible header so clients/proxies can detect demo mode is active.
        # This is intentional for development but must never reach production.
        request.state.demo_mode = True
        return

    # Collect the credential from the three possible locations
    token: Optional[str] = x_api_key

    # Also try query parameter fallback
    if not token:
        token = request.query_params.get("api_key") or None

    # Extract Authorization header for JWT
    auth_header: str = request.headers.get("Authorization", "")
    bearer_token: Optional[str] = None
    if auth_header.lower().startswith("bearer "):
        bearer_token = auth_header[7:].strip() or None

    # ── Step 1: Check X-API-Key / ?api_key= ──────────────────────────────
    if token:
        # 1a. Static token from FIXOPS_API_TOKEN (fastest path, no DB I/O)
        if has_token_auth and token in expected_tokens:
            request.state.user_role = "admin"
            request.state.user_scopes = ["admin:all"]
            # Deliberately does NOT pin an org. FIXOPS_API_TOKEN is the platform
            # OPERATOR credential, and targeting a named tenant with it is
            # legitimate administration (migrations, support, cross-tenant
            # reporting). Customer credentials get pinned above; this exception
            # is explicit so it cannot be mistaken for the same oversight.
            return

        # 1b. Managed key — validated against KeyManager DB (fixops_ prefix)
        #     This covers keys minted via POST /auth/keys or POST /auth/signup.
        managed_record = _validate_managed_key(token)
        if managed_record is not None:
            _bind_managed_key(request, managed_record)
            return

        # Token was present but not valid — log and reject
        logger.warning(
            "auth_deps: Invalid API key from %s",
            getattr(request.client, "host", "unknown"),
        )
        raise HTTPException(status_code=403, detail="Invalid API token")

    # ── Step 2: Check Authorization: Bearer <token> ──────────────────────
    #
    # A managed key may arrive here rather than in X-API-Key. Plenty of CI
    # tooling only knows how to send `Authorization: Bearer <token>`, and a
    # fixops_ key sent that way used to be passed to the JWT decoder, which
    # cannot parse it and raises 401 — so the key worked on every endpoint via
    # one header and on none via the other, with an error that blamed the
    # credential rather than the header.
    #
    # Checked BEFORE the JWT branch and gated on the fixops_ prefix, so this
    # cannot shadow JWT handling: the two token shapes are unambiguous.
    if bearer_token and bearer_token.startswith("fixops_"):
        managed_record = _validate_managed_key(bearer_token)
        if managed_record is not None:
            _bind_managed_key(request, managed_record)
            return
        logger.warning(
            "auth_deps: Invalid managed key presented as Bearer from %s",
            getattr(request.client, "host", "unknown"),
        )
        raise HTTPException(status_code=403, detail="Invalid API token")

    if bearer_token and _HAS_JWT_AUTH:
        try:
            claims = _decode_jwt(bearer_token)
            request.state.user_role = claims.get("role", "viewer")
            request.state.user_scopes = claims.get("scopes", ["read:findings"])
            # Propagate org_id and user_id from JWT claims so OrgIdMiddleware
            # can resolve the correct tenant without requiring X-Org-ID header.
            if claims.get("org_id"):
                request.state.org_id = claims["org_id"]
            if claims.get("sub"):
                request.state.user_id = claims["sub"]
            return
        except HTTPException:
            raise  # Re-raise 401/403 directly

    # ── Step 3: If we have an API key but no JWT secret, check token ──────
    if bearer_token and has_token_auth:
        # Caller may send their API key as a Bearer token (common client error)
        if bearer_token in expected_tokens:
            request.state.user_role = "admin"
            request.state.user_scopes = ["admin:all"]
            return
        raise HTTPException(status_code=403, detail="Invalid API token")

    # ── Step 4: No valid credential found ────────────────────────────────
    if not token and not bearer_token:
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Provide X-API-Key header or Authorization: Bearer <token>.",
        )

    # We have a credential but no matching auth backend configured
    raise HTTPException(status_code=401, detail="Authentication not configured on server")


# ---------------------------------------------------------------------------
# Role-based access control dependency
# ---------------------------------------------------------------------------

def require_role(*roles: str) -> "Depends":
    """Return a FastAPI dependency that enforces role membership.

    Layers on top of ``api_key_auth`` — the caller still needs a valid
    credential; this dependency additionally checks that the authenticated
    user's role is in the *roles* allow-list.

    The string ``"admin"`` is produced by API-key auth and dev-mode and is
    treated as equivalent to ``super_admin`` (full access).

    Usage (router-level):
        router = APIRouter(
            dependencies=[require_role("org_admin", "super_admin")]
        )

    Usage (per-endpoint):
        @router.delete("/{id}", dependencies=[require_role("org_admin")])

    Raises:
        HTTPException(401): No valid credential (from api_key_auth).
        HTTPException(403): Credential valid but role not in the allow-list.
    """
    allowed: frozenset[str] = frozenset(roles)

    async def _check(request: Request, _auth: None = Depends(api_key_auth)) -> None:
        role: Optional[str] = getattr(request.state, "user_role", None)
        if role in allowed:
            return
        raise HTTPException(
            status_code=403,
            detail=f"Role '{role}' is not permitted for this endpoint. Required: {sorted(allowed)}",
        )

    return Depends(_check)


# ---------------------------------------------------------------------------
# Wave-0 extraction: verify_api_key + require_scope
# ---------------------------------------------------------------------------
# These replace the _verify_api_key / _require_scope closures that previously
# lived inside create_app().  The closures captured:
#   - auth_strategy    → re-resolved per-request from FIXOPS_MODE / env
#   - expected_tokens  → re-resolved per-request via _load_api_tokens() (commit 435b54d1 pattern)
#   - api_key_header   → already exists as module-level _api_key_header above
#   - _security_audit, _check_auth_rate_limit, _record_auth_failure,
#     _clear_auth_failures, decode_access_token
#                      → imported lazily from apps.api.app (module-level there)
#
# Circular-import guard: we import from apps.api.app inside the async function
# body (not at module level) to avoid the circular dependency chain.
# apps.api.app imports auth_deps — importing auth_deps from apps.api.app at
# module level would create a cycle.  Per-call import is safe because Python
# caches modules in sys.modules after the first load.
# ---------------------------------------------------------------------------

_ALL_SCOPES: tuple[str, ...] = (
    "read:sbom",
    "write:sbom",
    "read:findings",
    "write:findings",
    "read:graph",
    "write:graph",
    "read:feeds",
    "read:evidence",
    "write:evidence",
    "read:integrations",
    "write:integrations",
    "attack:execute",
    "admin:all",
)


def _get_auth_strategy() -> str:
    """Resolve auth strategy from environment on every call (zero-cache, test-safe)."""
    import os as _os
    # Mirror the logic in create_app(): if FIXOPS_API_TOKEN is set and no
    # explicit strategy override exists, auto-promote to 'token'.
    strategy = _os.getenv("FIXOPS_AUTH_STRATEGY", "").lower().strip()
    if not strategy and _os.getenv("FIXOPS_API_TOKEN", "").strip():
        strategy = "token"
    return strategy


async def verify_api_key(
    request: Request,
    api_key: Optional[str] = Depends(_api_key_header),
) -> None:
    """Module-level replacement for the _verify_api_key closure in create_app().

    Preserves exact behaviour of the original closure:
    - per-request token resolution (commit 435b54d1 pattern)
    - brute-force rate-limit check via _check_auth_rate_limit
    - dual auth: API key + JWT Bearer
    - security audit logging
    - dev-mode fallback when no strategy configured
    """
    import sys as _sys
    # Lazy-import from apps.api.app avoids circular import at module level.
    # On first call this is a cache hit (module already loaded by the time
    # any request arrives); subsequent calls are O(1) dict lookups.
    _app_mod = _sys.modules.get("apps.api.app")
    if _app_mod is not None:
        _check_rl = getattr(_app_mod, "_check_auth_rate_limit", None)
        _record_fail = getattr(_app_mod, "_record_auth_failure", None)
        _clear_fail = getattr(_app_mod, "_clear_auth_failures", None)
        _decode = getattr(_app_mod, "decode_access_token", None)
        _sec_audit = getattr(_app_mod, "_security_audit", None)
    else:
        _check_rl = _record_fail = _clear_fail = _decode = _sec_audit = None

    client_ip = request.client.host if request.client else "unknown"

    # Brute-force gate
    if _check_rl and _check_rl(client_ip):
        logger.warning(
            "Auth rate limit exceeded for IP %s — rejecting request", client_ip
        )
        raise HTTPException(
            status_code=429,
            detail="Too many failed authentication attempts. Try again later.",
        )

    # Accept token via ?api_key= query param (browser fallback)
    if not api_key:
        api_key = request.query_params.get("api_key")

    auth_header = request.headers.get("Authorization", "")

    auth_strategy = _get_auth_strategy()
    expected_tokens: tuple[str, ...] = _load_api_tokens()

    if auth_strategy == "token":
        # Path 1: X-API-Key / ?api_key= (static FIXOPS_API_TOKEN — fastest path)
        if api_key and api_key in expected_tokens:
            request.state.user_role = "admin"
            request.state.user_scopes = list(_ALL_SCOPES)
            if _clear_fail:
                _clear_fail(client_ip)
            return
        # Path 1b: Managed key minted via POST /auth/signup or /auth/keys (KeyManager DB).
        # Without this, signup-issued customer keys (fixops_...) were rejected by every router
        # mounted with verify_api_key (analytics/risk/compliance dashboards → "failed to load"),
        # while api_key_auth-mounted routers (findings/billing) accepted them — inconsistent auth.
        if api_key:
            _managed = _validate_managed_key(api_key)
            if _managed is not None:
                _role = getattr(_managed, "role", "viewer") or "viewer"
                _scopes = getattr(_managed, "scopes", None)
                request.state.user_role = _role
                if isinstance(_scopes, list) and _scopes:
                    request.state.user_scopes = _scopes
                elif _role in ("admin", "super_admin"):
                    request.state.user_scopes = list(_ALL_SCOPES)
                else:
                    request.state.user_scopes = ["read:findings"]
                if getattr(_managed, "user_id", None):
                    request.state.user_id = _managed.user_id
                # Bind the credential's tenant — same rule as api_key_auth.
                # This is a SECOND, parallel auth implementation, and routers
                # mounted with _verify_api_key never went through the other one.
                # Fixing only api_key_auth left every such router — including
                # /api/v1/scanner-ingest/upload, the product's front door —
                # writing every customer's findings into the shared "default"
                # tenant. Two implementations of one rule; the fix has to land
                # in both or it has not landed.
                request.state.org_id = getattr(_managed, "org_id", None) or "default"
                if _clear_fail:
                    _clear_fail(client_ip)
                return
        # Path 1c: a managed key presented as `Authorization: Bearer <key>`.
        #
        # This file's own note a few lines up says it: two implementations of
        # one rule, and the fix has to land in both. Accepting a fixops_ key
        # via Bearer was added to api_key_auth and NOT here, so the key worked
        # on /api/v1/findings and returned 401 on /api/v1/playbooks and
        # /api/v1/compliance/templates — the same credential, the same header,
        # a different answer depending on which of the two auth paths the
        # router happened to be mounted with.
        #
        # Gated on the fixops_ prefix and checked before the JWT branch, so it
        # cannot shadow JWT handling: the two token shapes are unambiguous.
        if auth_header.lower().startswith("bearer "):
            _bearer = auth_header[7:].strip()
            if _bearer.startswith("fixops_"):
                _managed = _validate_managed_key(_bearer)
                if _managed is not None:
                    _bind_managed_key(request, _managed)
                    if _clear_fail:
                        _clear_fail(client_ip)
                    return

        # Path 2: JWT Bearer (dual auth)
        if auth_header.lower().startswith("bearer ") and _decode:
            jwt_token = auth_header[7:].strip()
            try:
                claims = _decode(jwt_token)
                request.state.user_role = claims.get("role", "viewer")
                request.state.user_scopes = claims.get("scopes", ["read:findings"])
                # api_key_auth's JWT branch binds the org claim; this one did
                # not, so a session token reaching a _verify_api_key router
                # resolved to "default" too.
                if claims.get("org_id"):
                    request.state.org_id = claims["org_id"]
                if _clear_fail:
                    _clear_fail(client_ip)
                return
            except HTTPException:
                pass  # fall through to failure
        if _record_fail:
            _record_fail(client_ip)
        logger.warning("Failed token auth attempt from IP %s", client_ip)
        if _sec_audit:
            _sec_audit.log_login_attempt(
                client_ip=client_ip,
                success=False,
                auth_method="token",
                correlation_id=getattr(request.state, "correlation_id", None),
            )
        raise HTTPException(status_code=401, detail="Invalid or missing API token")

    if auth_strategy == "jwt":
        if not api_key:
            if _record_fail:
                _record_fail(client_ip)
            logger.warning("Missing Authorization header from IP %s", client_ip)
            if _sec_audit:
                _sec_audit.log_login_attempt(
                    client_ip=client_ip,
                    success=False,
                    auth_method="jwt",
                    correlation_id=getattr(request.state, "correlation_id", None),
                    details={"reason": "missing_authorization_header"},
                )
            raise HTTPException(status_code=401, detail="Missing Authorization header")
        token = api_key
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
        if _decode is None:
            raise HTTPException(status_code=401, detail="JWT auth not configured")
        try:
            claims = _decode(token)
        except HTTPException:
            if _record_fail:
                _record_fail(client_ip)
            logger.warning("Failed JWT auth attempt from IP %s", client_ip)
            if _sec_audit:
                _sec_audit.log_login_attempt(
                    client_ip=client_ip,
                    success=False,
                    auth_method="jwt",
                    correlation_id=getattr(request.state, "correlation_id", None),
                    details={"reason": "invalid_jwt"},
                )
            raise
        request.state.user_role = claims.get("role", "viewer")
        request.state.user_scopes = claims.get("scopes", ["read:findings"])
        if _clear_fail:
            _clear_fail(client_ip)
        return

    # Fallback — no auth strategy → dev/admin passthrough
    request.state.user_role = "admin"
    request.state.user_scopes = list(_ALL_SCOPES)
    if _clear_fail:
        _clear_fail(client_ip)


def require_scope(scope: str):
    """Module-level replacement for the _require_scope closure in create_app().

    Factory returning a FastAPI dependency that enforces a required OAuth-style
    scope.  Preserves exact behaviour of the original closure including security
    audit logging.
    """

    async def _check(request: Request) -> None:
        import sys as _sys
        _app_mod = _sys.modules.get("apps.api.app")
        _sec_audit = getattr(_app_mod, "_security_audit", None) if _app_mod else None

        user_scopes = getattr(request.state, "user_scopes", [])
        if scope not in user_scopes and "admin:all" not in user_scopes:
            if _sec_audit:
                _sec_audit.log_permission_denied(
                    client_ip=request.client.host if request.client else None,
                    resource=request.url.path,
                    required_scope=scope,
                    correlation_id=getattr(request.state, "correlation_id", None),
                )
            raise HTTPException(
                status_code=403,
                detail=f"Forbidden — missing required scope: {scope}",
            )

    return _check
