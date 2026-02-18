"""
FixOps Authentication Middleware — JWT + Scoped API Keys.

Provides:
- JWT token validation (Authorization: Bearer <token>)
- Scoped API key validation (X-API-Key: fixops_<prefix>.<secret>)
- Role-based access control via scopes
- Dev-mode bypass (FIXOPS_AUTH_MODE=dev)

Usage in FastAPI:
    from core.auth_middleware import require_auth, require_scope

    @app.get("/api/v1/protected", dependencies=[Depends(require_auth)])
    async def protected(): ...

    @app.get("/api/v1/admin", dependencies=[Depends(require_scope("admin:all"))])
    async def admin_only(): ...
"""
from __future__ import annotations

import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from core.auth_db import AuthDB
from core.auth_models import ROLE_SCOPES, User, UserRole

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
_JWT_SECRET = os.getenv("FIXOPS_JWT_SECRET", "fixops-dev-secret-change-in-production")
_JWT_ALGORITHM = "HS256"
_JWT_EXPIRY_HOURS = int(os.getenv("FIXOPS_JWT_EXPIRY_HOURS", "24"))
_AUTH_MODE = os.getenv("FIXOPS_AUTH_MODE", "dev")  # "dev" | "enforced"
_db: Optional[AuthDB] = None

_bearer_scheme = HTTPBearer(auto_error=False)
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _get_db() -> AuthDB:
    global _db
    if _db is None:
        _db = AuthDB()
    return _db


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------


def create_jwt(user: User, extra_claims: Optional[Dict[str, Any]] = None) -> str:
    """Create a signed JWT for a user."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user.id,
        "email": user.email,
        "role": user.role.value,
        "org_id": user.org_id,
        "scopes": ROLE_SCOPES.get(user.role, []),
        "iat": now,
        "exp": now + timedelta(hours=_JWT_EXPIRY_HOURS),
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, _JWT_SECRET, algorithm=_JWT_ALGORITHM)


def decode_jwt(token: str) -> Dict[str, Any]:
    """Decode and validate a JWT. Raises on invalid/expired."""
    return jwt.decode(token, _JWT_SECRET, algorithms=[_JWT_ALGORITHM])


# ---------------------------------------------------------------------------
# API Key helpers
# ---------------------------------------------------------------------------


def generate_api_key() -> tuple[str, str, str]:
    """Generate a new API key. Returns (full_key, prefix, bcrypt_hash)."""
    raw = secrets.token_urlsafe(32)
    prefix = raw[:8]
    full_key = f"fixops_{raw}"
    key_hash = bcrypt.hashpw(full_key.encode(), bcrypt.gensalt()).decode()
    return full_key, prefix, key_hash


def verify_api_key_hash(plain_key: str, hashed: str) -> bool:
    """Verify an API key against its bcrypt hash."""
    return bcrypt.checkpw(plain_key.encode(), hashed.encode())


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------


class AuthContext:
    """Holds authenticated user context for the current request."""

    __slots__ = ("user_id", "email", "role", "org_id", "scopes", "auth_method")

    def __init__(
        self,
        user_id: str,
        email: str,
        role: str,
        org_id: str,
        scopes: List[str],
        auth_method: str,
    ):
        self.user_id = user_id
        self.email = email
        self.role = role
        self.org_id = org_id
        self.scopes = scopes
        self.auth_method = auth_method


async def require_auth(
    request: Request,
    bearer: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
    api_key: Optional[str] = Depends(_api_key_header),
) -> AuthContext:
    """Authenticate via JWT Bearer token or X-API-Key header.

    In dev mode (FIXOPS_AUTH_MODE=dev), returns a default admin context
    when no credentials are provided — matches existing behaviour.
    """
    # --- Try JWT first ---
    if bearer and bearer.credentials:
        try:
            claims = decode_jwt(bearer.credentials)
            return AuthContext(
                user_id=claims["sub"],
                email=claims.get("email", ""),
                role=claims.get("role", "viewer"),
                org_id=claims.get("org_id", "default"),
                scopes=claims.get("scopes", []),
                auth_method="jwt",
            )
        except jwt.ExpiredSignatureError:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token expired")
        except jwt.InvalidTokenError as exc:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"Invalid token: {exc}")

    # --- Try API Key ---
    if api_key:
        ctx = _validate_api_key(api_key)
        if ctx:
            return ctx
        if _AUTH_MODE == "enforced":
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid API key")

    # --- Dev-mode fallback ---
    if _AUTH_MODE != "enforced":
        return AuthContext(
            user_id="dev-user",
            email="dev@fixops.local",
            role="admin",
            org_id="default",
            scopes=ROLE_SCOPES[UserRole.ADMIN],
            auth_method="dev-bypass",
        )

    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")


def _validate_api_key(raw_key: str) -> Optional[AuthContext]:
    """Validate an API key and return context, or None."""
    if not raw_key.startswith("fixops_"):
        return None
    prefix = raw_key[7:15]  # 8 chars after "fixops_"
    db = _get_db()
    stored = db.get_api_key_by_prefix(prefix)
    if not stored:
        return None
    if not verify_api_key_hash(raw_key, stored.key_hash):
        return None
    if stored.expires_at and stored.expires_at < datetime.utcnow():
        return None
    # Touch last_used_at (fire-and-forget)
    try:
        db.touch_api_key(stored.id)
    except Exception:
        pass
    # Look up user
    user = db.get_user(stored.user_id)
    if not user or not user.is_active:
        return None
    return AuthContext(
        user_id=user.id,
        email=user.email,
        role=user.role.value,
        org_id=user.org_id,
        scopes=stored.scopes,
        auth_method="api_key",
    )


def require_scope(scope: str):
    """Factory that returns a dependency requiring a specific scope."""

    async def _check(auth: AuthContext = Depends(require_auth)):
        if not auth.has_scope(scope):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Missing required scope: {scope}",
            )
        return auth

    return _check


# ---------------------------------------------------------------------------
# Password helpers (for local users)
# ---------------------------------------------------------------------------


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())
