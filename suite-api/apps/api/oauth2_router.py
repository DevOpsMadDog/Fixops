"""
OAuth2 Client Credentials Token Endpoint — ALDECI Enterprise API Access.

Implements RFC 6749 §4.4 (Client Credentials Grant) to provide CrowdStrike-parity
for enterprise integrations.

Prefix: /api/v1/oauth2
Auth:   Public (this IS the auth endpoint)

Routes:
  POST /api/v1/oauth2/token   — issue a 30-min JWT from client_id + client_secret

Token Usage:
  The returned JWT is accepted by all ALDECI endpoints via:
    Authorization: Bearer <access_token>
  (handled by auth_deps.api_key_auth → _decode_jwt)

Client Credentials:
  client_id     = the APIKey.id  (e.g. "ak_a1b2c3d4")
  client_secret = the raw API key (e.g. "aldeci_...")

  These are stored/validated via the existing APIKeyManager — no new credential
  store required.

Environment:
  FIXOPS_JWT_SECRET   — HMAC-SHA256 signing secret (>= 32 chars, required)
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from core.api_key_manager import APIKeyManager
from fastapi import APIRouter, Form, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/oauth2",
    tags=["OAuth2"],
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_JWT_ALGORITHM = "HS256"
_TOKEN_TTL_SECONDS = 1800  # 30 minutes
_MIN_SECRET_LEN = 32


# ---------------------------------------------------------------------------
# Response model
# ---------------------------------------------------------------------------

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = _TOKEN_TTL_SECONDS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_jwt_secret() -> str:
    """Return FIXOPS_JWT_SECRET or raise 503 if not configured."""
    secret = os.getenv("FIXOPS_JWT_SECRET", "").strip()
    if len(secret) < _MIN_SECRET_LEN:
        _logger.error("oauth2: FIXOPS_JWT_SECRET not configured or too short")
        raise HTTPException(
            status_code=503,
            detail="OAuth2 token endpoint not configured: FIXOPS_JWT_SECRET must be >= 32 chars",
        )
    return secret


def _issue_jwt(key_id: str, org_id: str, role: str, scopes: list[str], secret: str) -> str:
    """Sign and return a JWT for the validated API key."""
    now = datetime.now(timezone.utc)
    exp = now + timedelta(seconds=_TOKEN_TTL_SECONDS)
    payload = {
        "sub": key_id,
        "iss": "aldeci/oauth2",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "org_id": org_id,
        "role": role,
        "scopes": scopes,
    }
    return jwt.encode(payload, secret, algorithm=_JWT_ALGORITHM)


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@router.post(
    "/token",
    response_model=TokenResponse,
    summary="Issue OAuth2 client credentials JWT",
    description=(
        "RFC 6749 §4.4 Client Credentials Grant. "
        "Supply `client_id` (APIKey.id) and `client_secret` (raw API key) "
        "as application/x-www-form-urlencoded. "
        "Returns a 30-minute Bearer JWT accepted by all ALDECI endpoints."
    ),
)
async def token(
    client_id: str = Form(..., description="API Key ID (ak_…)"),
    client_secret: str = Form(..., description="Raw API key (aldeci_…)"),
    grant_type: Optional[str] = Form(None, description="Must be 'client_credentials' if provided"),
) -> JSONResponse:
    """Issue an OAuth2 access token via the client credentials flow."""

    # RFC 6749 §3.3: reject unsupported grant types
    if grant_type is not None and grant_type != "client_credentials":
        raise HTTPException(
            status_code=400,
            detail="unsupported_grant_type",
        )

    secret = _get_jwt_secret()

    # Validate client_secret (raw key) against the stored hash
    mgr = APIKeyManager()
    key_record = mgr.validate_key(client_secret)

    if key_record is None:
        _logger.warning("oauth2: invalid client_secret presented (no matching active key)")
        raise HTTPException(
            status_code=401,
            detail="invalid_client",
            headers={"WWW-Authenticate": 'error="invalid_client"'},
        )

    # Verify client_id matches the record returned by the secret lookup
    if key_record.id != client_id:
        _logger.warning(
            "oauth2: client_id mismatch — presented=%s, expected=%s",
            client_id, key_record.id,
        )
        raise HTTPException(
            status_code=401,
            detail="invalid_client",
            headers={"WWW-Authenticate": 'error="invalid_client"'},
        )

    access_token = _issue_jwt(
        key_id=key_record.id,
        org_id=key_record.org_id,
        role=key_record.role.value,
        scopes=key_record.scopes,
        secret=secret,
    )

    _logger.info(
        "oauth2: issued token for client_id=%s org=%s role=%s",
        client_id, key_record.org_id, key_record.role.value,
    )

    # Return as application/json per RFC 6749 §5.1
    return JSONResponse(
        content={
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": _TOKEN_TTL_SECONDS,
        },
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )
