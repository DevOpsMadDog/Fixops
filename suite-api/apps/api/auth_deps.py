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
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.responses import Response
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
    """Load JWT secret from environment.  Returns None if absent or too short."""
    secret = os.getenv("FIXOPS_JWT_SECRET", "").strip()
    if not secret:
        return None
    if len(secret) < _MIN_JWT_SECRET_LENGTH:
        logger.warning(
            "JWT signing key is only %d chars (minimum %d) — JWT auth disabled.",
            len(secret),
            _MIN_JWT_SECRET_LENGTH,
        )
        return None
    return secret


def _is_dev_mode() -> bool:
    """Return True when running in demo/dev mode (auth is relaxed)."""
    mode = os.getenv("FIXOPS_MODE", "").lower().strip()
    return mode in ("demo", "dev", "development", "local")


_EXPECTED_TOKENS: tuple[str, ...] = _load_api_tokens()
_JWT_SECRET: Optional[str] = _load_jwt_secret()
_DEV_MODE: bool = _is_dev_mode()

# Determine effective auth strategy
_HAS_TOKEN_AUTH: bool = bool(_EXPECTED_TOKENS)
_HAS_JWT_AUTH: bool = bool(_JWT_SECRET)

if not _HAS_TOKEN_AUTH and not _HAS_JWT_AUTH:
    if _DEV_MODE:
        logger.warning(
            "⚠️  SECURITY WARNING: auth_deps is running in %s mode. "
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
    if not _JWT_SECRET:
        raise HTTPException(status_code=401, detail="JWT auth not configured")

    # Guard: reject oversized tokens before any parsing
    if len(token.encode("utf-8", errors="replace")) > _MAX_TOKEN_LENGTH:
        logger.warning("auth_deps: JWT rejected — exceeds max length (%d bytes)", _MAX_TOKEN_LENGTH)
        raise HTTPException(status_code=401, detail="Invalid token")

    try:
        claims = jwt.decode(
            token,
            _JWT_SECRET,
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
    # Dev/demo mode pass-through when no auth is configured
    if _DEV_MODE and not _HAS_TOKEN_AUTH and not _HAS_JWT_AUTH:
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
    if token and _HAS_TOKEN_AUTH:
        if token in _EXPECTED_TOKENS:
            request.state.user_role = "admin"
            request.state.user_scopes = ["admin:all"]
            return
        # Token present but not in the valid set
        logger.warning(
            "auth_deps: Invalid API key from %s",
            getattr(request.client, "host", "unknown"),
        )
        raise HTTPException(status_code=403, detail="Invalid API token")

    # ── Step 2: Check Authorization: Bearer <jwt> ────────────────────────
    if bearer_token and _HAS_JWT_AUTH:
        try:
            claims = _decode_jwt(bearer_token)
            request.state.user_role = claims.get("role", "viewer")
            request.state.user_scopes = claims.get("scopes", ["read:findings"])
            return
        except HTTPException:
            raise  # Re-raise 401/403 directly

    # ── Step 3: If we have an API key but no JWT secret, check token ──────
    if bearer_token and _HAS_TOKEN_AUTH:
        # Caller may send their API key as a Bearer token (common client error)
        if bearer_token in _EXPECTED_TOKENS:
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
