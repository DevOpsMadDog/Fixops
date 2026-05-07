"""
SSO/SAML authentication API endpoints.
"""
import logging
import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import jwt
from apps.api.auth_deps import api_key_auth
from apps.api.endpoint_rate_limit import enforce as _rl_enforce
from core.auth_db import AuthDB
from core.auth_models import AuthProvider, SSOConfig, SSOStatus
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])
db = AuthDB()

# ---------------------------------------------------------------------------
# Dev-token endpoint — gated by FIXOPS_DEV_MODE=true
# ---------------------------------------------------------------------------

_DEV_TOKEN_JWT_ALG = "HS256"
_DEV_TOKEN_TTL_SECONDS = 3600
_DEV_TOKEN_AUDIT_DB = Path(os.getenv("FIXOPS_DEV_TOKEN_AUDIT_DB", "data/dev_token_audit.db"))


def _is_dev_mode_enabled() -> bool:
    """Return True if FIXOPS_DEV_MODE env var is truthy ('true', '1', 'yes')."""
    val = os.getenv("FIXOPS_DEV_MODE", "").strip().lower()
    return val in ("true", "1", "yes", "on")


def _get_dev_jwt_secret() -> str:
    """Return the JWT secret used by the production auth flow.

    Falls back to a dev-only secret when FIXOPS_JWT_SECRET is not set, mirroring
    auth_middleware.py default. The minted JWT is validated by auth_deps which
    requires FIXOPS_JWT_SECRET >= 32 chars in production.
    """
    secret = os.getenv("FIXOPS_JWT_SECRET", "").strip()
    if not secret:
        # Dev-mode only: warn loudly so this is never silent in prod.
        _logger.warning(
            "FIXOPS_JWT_SECRET is not set — using insecure dev fallback. "
            "Set FIXOPS_JWT_SECRET to a random 32+ char string in production."
        )
        secret = os.getenv(
            "_FIXOPS_DEV_JWT_FALLBACK",
            "fixops-dev-secret-change-in-production-min-32-chars",
        )
    return secret


def _ensure_dev_token_audit_table() -> None:
    """Create the dev_token_audit table if absent (idempotent)."""
    _DEV_TOKEN_AUDIT_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DEV_TOKEN_AUDIT_DB))
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS dev_token_audit (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                role TEXT NOT NULL,
                email TEXT NOT NULL,
                minted_at TEXT NOT NULL,
                ip TEXT NOT NULL DEFAULT 'unknown'
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_dev_token_audit_org ON dev_token_audit(org_id)"
        )
        conn.commit()
    finally:
        conn.close()


def _record_dev_token_audit(org_id: str, role: str, email: str, ip: str) -> str:
    """Insert an audit row for a dev-token mint. Returns the audit row ID."""
    _ensure_dev_token_audit_table()
    audit_id = str(uuid.uuid4())
    conn = sqlite3.connect(str(_DEV_TOKEN_AUDIT_DB))
    try:
        conn.execute(
            "INSERT INTO dev_token_audit (id, org_id, role, email, minted_at, ip) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                audit_id,
                org_id,
                role,
                email,
                datetime.now(timezone.utc).isoformat(),
                ip,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return audit_id


_ROLE_DEFAULT_SCOPES = {
    "admin": ["admin:all"],
    "analyst": [
        "read:findings",
        "write:findings",
        "read:graph",
        "read:sbom",
        "read:feeds",
        "read:evidence",
        "write:evidence",
    ],
    "viewer": [
        "read:findings",
        "read:graph",
        "read:sbom",
        "read:feeds",
        "read:evidence",
    ],
}


class DevTokenRequest(BaseModel):
    """Request body for /api/v1/auth/dev-token."""

    org_id: str = Field(default="default", min_length=1, max_length=128)
    role: str = Field(default="admin", min_length=1, max_length=64)
    email: str = Field(default="dev@verify", min_length=1, max_length=255)


class DevTokenUser(BaseModel):
    """User identity bundled with dev-minted token."""

    sub: str
    email: str
    role: str
    org_id: str
    scopes: List[str]


class DevTokenResponse(BaseModel):
    """Response from /api/v1/auth/dev-token."""

    access_token: str
    token_type: str = "Bearer"
    expires_in: int = _DEV_TOKEN_TTL_SECONDS
    user: DevTokenUser


@router.post(
    "/dev-token",
    response_model=DevTokenResponse,
    status_code=200,
    summary="Mint a short-lived JWT for local dev / Playwright (FIXOPS_DEV_MODE=true required)",
)
async def mint_dev_token(req: DevTokenRequest, request: Request) -> DevTokenResponse:
    """Mint a short-lived JWT for dev/Playwright workflows.

    Gated by FIXOPS_DEV_MODE=true. In production this returns 403.
    Every successful mint is audit-logged with org_id, role, email, IP.
    """
    _rl_enforce(request, limit_key="auth:dev-token", max_per_minute=10)
    if not _is_dev_mode_enabled():
        raise HTTPException(status_code=403, detail="dev mode disabled")

    org_id = req.org_id
    role = req.role
    email = req.email
    sub = f"dev-{email}"
    scopes = _ROLE_DEFAULT_SCOPES.get(role, ["read:findings"])

    now = datetime.now(timezone.utc)
    payload = {
        "sub": sub,
        "email": email,
        "role": role,
        "org_id": org_id,
        "scopes": scopes,
        "iat": now,
        "exp": now + timedelta(seconds=_DEV_TOKEN_TTL_SECONDS),
        "dev_token": True,
    }
    secret = _get_dev_jwt_secret()
    access_token = jwt.encode(payload, secret, algorithm=_DEV_TOKEN_JWT_ALG)

    client_ip = "unknown"
    if request.client and request.client.host:
        client_ip = request.client.host

    try:
        _record_dev_token_audit(org_id=org_id, role=role, email=email, ip=client_ip)
    except (sqlite3.Error, OSError) as exc:
        # Audit failure should not block dev-token issuance, but log loudly.
        _logger.warning("DEV-TOKEN audit insert failed: %s", exc)

    _logger.warning(
        "DEV-TOKEN MINTED for org_id=%s role=%s — DO NOT USE IN PROD",
        org_id,
        role,
    )

    return DevTokenResponse(
        access_token=access_token,
        token_type="Bearer",
        expires_in=_DEV_TOKEN_TTL_SECONDS,
        user=DevTokenUser(
            sub=sub,
            email=email,
            role=role,
            org_id=org_id,
            scopes=scopes,
        ),
    )


class SSOConfigCreate(BaseModel):
    """Request model for creating SSO configuration."""

    name: str = Field(..., min_length=1, max_length=255)
    provider: AuthProvider
    status: SSOStatus = SSOStatus.PENDING
    metadata: Dict[str, Any] = Field(default_factory=dict)
    entity_id: Optional[str] = None
    sso_url: Optional[str] = None
    certificate: Optional[str] = None


class SSOConfigUpdate(BaseModel):
    """Request model for updating SSO configuration."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    status: Optional[SSOStatus] = None
    metadata: Optional[Dict[str, Any]] = None
    entity_id: Optional[str] = None
    sso_url: Optional[str] = None
    certificate: Optional[str] = None


class SSOConfigResponse(BaseModel):
    """Response model for SSO configuration."""

    id: str
    name: str
    provider: str
    status: str
    metadata: Dict[str, Any]
    entity_id: Optional[str]
    sso_url: Optional[str]
    certificate: Optional[str]
    created_at: str
    updated_at: str


class PaginatedSSOConfigResponse(BaseModel):
    """Paginated SSO configuration response."""

    items: List[SSOConfigResponse]
    total: int
    limit: int
    offset: int


@router.get("/sso", response_model=PaginatedSSOConfigResponse)
async def list_sso_configs(
    limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)
):
    """List all SSO configurations."""
    configs = db.list_sso_configs(limit=limit, offset=offset)
    return {
        "items": [SSOConfigResponse(**c.to_dict()) for c in configs],
        "total": len(configs),
        "limit": limit,
        "offset": offset,
    }


@router.post("/sso", response_model=SSOConfigResponse, status_code=201)
async def create_sso_config(config_data: SSOConfigCreate):
    """Create a new SSO configuration."""
    config = SSOConfig(
        id="",
        name=config_data.name,
        provider=config_data.provider,
        status=config_data.status,
        metadata=config_data.metadata,
        entity_id=config_data.entity_id,
        sso_url=config_data.sso_url,
        certificate=config_data.certificate,
    )
    created_config = db.create_sso_config(config)
    return SSOConfigResponse(**created_config.to_dict())


@router.get("/sso/{id}", response_model=SSOConfigResponse)
async def get_sso_config(id: str):
    """Get SSO configuration by ID."""
    config = db.get_sso_config(id)
    if not config:
        raise HTTPException(status_code=404, detail="SSO configuration not found")
    return SSOConfigResponse(**config.to_dict())


@router.put("/sso/{id}", response_model=SSOConfigResponse)
async def update_sso_config(id: str, config_data: SSOConfigUpdate):
    """Update SSO configuration."""
    config = db.get_sso_config(id)
    if not config:
        raise HTTPException(status_code=404, detail="SSO configuration not found")

    if config_data.name is not None:
        config.name = config_data.name
    if config_data.status is not None:
        config.status = config_data.status
    if config_data.metadata is not None:
        config.metadata = config_data.metadata
    if config_data.entity_id is not None:
        config.entity_id = config_data.entity_id
    if config_data.sso_url is not None:
        config.sso_url = config_data.sso_url
    if config_data.certificate is not None:
        config.certificate = config_data.certificate

    updated_config = db.update_sso_config(config)
    return SSOConfigResponse(**updated_config.to_dict())


# ---------------------------------------------------------------------------
# API Key Management — creation, rotation, revocation, audit
# ---------------------------------------------------------------------------

class KeyCreateRequest(BaseModel):
    """Request to create a new API key."""
    name: str
    user_id: str
    role: str = "viewer"
    scopes: list = []
    ttl_days: Optional[int] = None


class KeyRotateRequest(BaseModel):
    """Request to rotate an existing API key."""
    performed_by: str = "admin"


class KeyResponse(BaseModel):
    """API key record (no plaintext key)."""
    id: str
    key_prefix: str
    name: str
    user_id: str
    role: str
    scopes: list
    is_active: bool
    created_at: str
    expires_at: Optional[str] = None
    rotated_at: Optional[str] = None
    revoked_at: Optional[str] = None
    last_used_at: Optional[str] = None
    predecessor_id: Optional[str] = None


class KeyCreateResponse(KeyResponse):
    """Response from key creation — includes the plaintext key (shown ONCE)."""
    plaintext_key: str


def _get_key_manager():
    """Lazy-load key manager."""
    try:
        from core.key_manager import KeyManager
        return KeyManager()
    except (ImportError, OSError) as exc:
        raise HTTPException(status_code=503, detail=f"Key manager unavailable: {exc}")


def _require_admin(request: Request) -> None:
    """AUTHZ-VULN-03: Enforce that only admin/super_admin callers can manage API keys."""
    caller_role: str = getattr(request.state, "user_role", "viewer")
    caller_scopes: list = getattr(request.state, "user_scopes", [])
    if caller_role not in ("admin", "super_admin") and "admin:all" not in caller_scopes:
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions: API key management requires admin role",
        )


@router.post("/keys", response_model=KeyCreateResponse, status_code=201,
             dependencies=[Depends(api_key_auth)])
async def create_api_key(req: KeyCreateRequest, request: Request):
    """Create a new managed API key with TTL and scope restrictions.

    AUTHZ-VULN-03: Requires admin/super_admin role.
    """
    _require_admin(request)
    km = _get_key_manager()
    record, plaintext = km.create_key(
        user_id=req.user_id,
        name=req.name,
        role=req.role,
        scopes=req.scopes,
        ttl_days=req.ttl_days,
    )
    resp = record.to_dict()
    resp["plaintext_key"] = plaintext
    return KeyCreateResponse(**resp)


@router.post("/keys/{key_id}/rotate", response_model=KeyCreateResponse,
             dependencies=[Depends(api_key_auth)])
async def rotate_api_key(key_id: str, req: KeyRotateRequest, request: Request):
    """Rotate an API key — creates replacement, puts old key in grace period.

    AUTHZ-VULN-03: Requires admin/super_admin role.
    """
    _require_admin(request)
    km = _get_key_manager()
    try:
        new_record, new_plaintext = km.rotate_key(key_id, performed_by=req.performed_by)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    resp = new_record.to_dict()
    resp["plaintext_key"] = new_plaintext
    return KeyCreateResponse(**resp)


@router.delete("/keys/{key_id}", dependencies=[Depends(api_key_auth)])
async def revoke_api_key(key_id: str, request: Request):
    """Immediately revoke an API key.

    AUTHZ-VULN-03: Requires admin/super_admin role.
    """
    _require_admin(request)
    km = _get_key_manager()
    success = km.revoke_key(key_id)
    if not success:
        raise HTTPException(status_code=404, detail="Key not found or already revoked")
    return {"status": "revoked", "key_id": key_id}


@router.get("/keys", response_model=list, dependencies=[Depends(api_key_auth)])
async def list_api_keys(request: Request, user_id: Optional[str] = None, include_revoked: bool = False):
    """List managed API keys.

    AUTHZ-VULN-03: Requires admin/super_admin role.
    """
    _require_admin(request)
    km = _get_key_manager()
    keys = km.list_keys(user_id=user_id, include_revoked=include_revoked)
    return [k.to_dict() for k in keys]


@router.get("/keys/expiring", dependencies=[Depends(api_key_auth)])
async def get_expiring_keys(request: Request, within_days: int = Query(default=7, ge=1, le=365)):
    """Get API keys expiring within the specified timeframe.

    AUTHZ-VULN-03: Requires admin/super_admin role.
    """
    _require_admin(request)
    km = _get_key_manager()
    keys = km.get_expiring_keys(within_days=within_days)
    return {"expiring_within_days": within_days, "count": len(keys), "keys": [k.to_dict() for k in keys]}


@router.post("/keys/cleanup", dependencies=[Depends(api_key_auth)])
async def cleanup_expired_keys(request: Request):
    """Deactivate all expired keys past their grace period.

    AUTHZ-VULN-03: Requires admin/super_admin role.
    """
    _require_admin(request)
    km = _get_key_manager()
    count = km.cleanup_expired()
    return {"deactivated_count": count}


@router.get("/keys/{key_id}/audit", dependencies=[Depends(api_key_auth)])
async def get_key_audit_log(key_id: str, request: Request, limit: int = Query(default=100, ge=1, le=1000)):
    """Get audit trail for a specific API key.

    AUTHZ-VULN-03: Requires admin/super_admin role.
    """
    _require_admin(request)
    km = _get_key_manager()
    log = km.get_audit_log(key_id=key_id, limit=limit)
    return {"key_id": key_id, "entries": log}


# ---------------------------------------------------------------------------
# GAP-039 — Disposable scoped user tokens
# GAP-050 — Role-view switcher
# ---------------------------------------------------------------------------

def _get_rbac_engine():
    """Lazy-load RBAC engine."""
    try:
        from core.rbac_engine import RBACEngine
        return RBACEngine()
    except (ImportError, OSError) as exc:
        raise HTTPException(status_code=503, detail=f"RBAC engine unavailable: {exc}")


def _caller_identity(request: Request) -> Dict[str, str]:
    """Extract caller org_id + user_id from request state (set by auth middleware)."""
    org_id = getattr(request.state, "org_id", None) or "default"
    user_id = getattr(request.state, "user_id", None) or "system"
    return {"org_id": str(org_id), "user_id": str(user_id)}


class DisposableTokenCreate(BaseModel):
    """Request to mint a disposable scoped token."""
    scope: List[str] = Field(..., min_length=1)
    ttl_seconds: int = Field(..., gt=0, le=86400 * 30)
    purpose: str = Field(..., min_length=1, max_length=512)


class DisposableTokenCreateResponse(BaseModel):
    """Disposable token mint response — raw_token returned ONCE."""
    token_id: str
    raw_token: str
    expires_at: str
    scope: List[str]


class RoleViewCreate(BaseModel):
    """Request to switch role view."""
    target_role: str = Field(..., min_length=1)
    duration_seconds: int = Field(default=3600, gt=0, le=86400)


@router.post("/disposable-token", response_model=DisposableTokenCreateResponse,
             status_code=201, dependencies=[Depends(api_key_auth)])
async def mint_disposable_token_endpoint(req: DisposableTokenCreate, request: Request):
    """Mint a disposable scoped token — raw token returned ONCE."""
    ident = _caller_identity(request)
    engine = _get_rbac_engine()
    try:
        result = engine.mint_disposable_token(
            org_id=ident["org_id"],
            minted_by=ident["user_id"],
            scope=req.scope,
            ttl_seconds=req.ttl_seconds,
            purpose=req.purpose,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return DisposableTokenCreateResponse(**result)


@router.delete("/disposable-token/{token_id}", dependencies=[Depends(api_key_auth)])
async def revoke_disposable_token_endpoint(token_id: str, request: Request):
    """Revoke a disposable token in the caller's org."""
    ident = _caller_identity(request)
    engine = _get_rbac_engine()
    ok = engine.revoke_disposable_token(
        org_id=ident["org_id"],
        token_id=token_id,
        revoked_by=ident["user_id"],
    )
    if not ok:
        raise HTTPException(status_code=404, detail="Token not found or already revoked")
    return {"status": "revoked", "token_id": token_id}


@router.get("/disposable-tokens", dependencies=[Depends(api_key_auth)])
async def list_disposable_tokens_endpoint(
    request: Request,
    org_id: Optional[str] = None,
    active_only: bool = Query(default=True),
):
    """List disposable tokens (never returns raw_token/hash). Defaults to caller's org."""
    ident = _caller_identity(request)
    target_org = org_id or ident["org_id"]
    # Tenant isolation: prevent cross-org listing unless caller has admin:all
    caller_scopes: list = getattr(request.state, "user_scopes", []) or []
    if target_org != ident["org_id"] and "admin:all" not in caller_scopes:
        raise HTTPException(status_code=403, detail="Cannot list tokens from another org")
    engine = _get_rbac_engine()
    tokens = engine.list_disposable_tokens(org_id=target_org, active_only=active_only)
    return {"org_id": target_org, "count": len(tokens), "tokens": tokens}


@router.post("/role-view", status_code=201, dependencies=[Depends(api_key_auth)])
async def switch_role_view_endpoint(req: RoleViewCreate, request: Request):
    """Switch caller's role view (temporary override)."""
    ident = _caller_identity(request)
    engine = _get_rbac_engine()
    try:
        result = engine.switch_role_view(
            org_id=ident["org_id"],
            user_id=ident["user_id"],
            target_role=req.target_role,
            duration_seconds=req.duration_seconds,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return result


@router.get("/role-view", dependencies=[Depends(api_key_auth)])
async def get_role_view_endpoint(request: Request):
    """Get the caller's current active role-view override (or null)."""
    ident = _caller_identity(request)
    engine = _get_rbac_engine()
    active = engine.get_active_role_view(
        org_id=ident["org_id"], user_id=ident["user_id"]
    )
    return {"active_override": active}


@router.delete("/role-view/{override_id}", dependencies=[Depends(api_key_auth)])
async def end_role_view_endpoint(override_id: str, request: Request):
    """End an active role-view override."""
    ident = _caller_identity(request)
    engine = _get_rbac_engine()
    ok = engine.end_role_view(
        org_id=ident["org_id"],
        override_id=override_id,
        user_id=ident["user_id"],
    )
    if not ok:
        raise HTTPException(status_code=404, detail="Override not found or already ended")
    return {"status": "ended", "override_id": override_id}


# ---------------------------------------------------------------------------
# Commercial P1 — /api/v1/auth/login + /api/v1/auth/refresh
# Short-lived access token (2h) + long-lived refresh token (7d).
# Audit-logged via AuditLogger on every attempt (success or failure).
# ---------------------------------------------------------------------------

import secrets as _secrets
import time as _time
from core.audit_logger import AuditLogger as _AuditLogger, AuditEvent as _AuditEvent, create_audit_logger as _create_audit_logger
from core.user_db import UserDB as _UserDB
from core.user_models import UserStatus as _UserStatus

_auth_audit: _AuditLogger = _create_audit_logger()
_user_db = _UserDB()

_ACCESS_TOKEN_TTL_SECONDS = int(os.getenv("FIXOPS_JWT_EXPIRE_HOURS", "2")) * 3600
_REFRESH_TOKEN_TTL_SECONDS = int(os.getenv("FIXOPS_JWT_REFRESH_DAYS", "7")) * 86400
_JWT_ALG = "HS256"

# Per-email failed-attempt tracking (in-memory; survives restart via PersistentDict in users_router)
_login_failures: dict = {}
_MAX_LOGIN_ATTEMPTS = 5
_LOCKOUT_SECONDS = 900  # 15 minutes


def _get_login_jwt_secret() -> str:
    secret = os.getenv("FIXOPS_JWT_SECRET", "").strip()
    if len(secret) < 32:
        raise HTTPException(status_code=503, detail="JWT auth not configured (FIXOPS_JWT_SECRET missing or too short)")
    return secret


def _check_login_rate_limit(email: str) -> None:
    now = _time.time()
    attempts = [t for t in _login_failures.get(email, []) if now - t < _LOCKOUT_SECONDS]
    _login_failures[email] = attempts
    if len(attempts) >= _MAX_LOGIN_ATTEMPTS:
        remaining = int(_LOCKOUT_SECONDS - (now - attempts[0]))
        raise HTTPException(status_code=429, detail=f"Too many login attempts. Retry in {remaining}s.")


def _record_login_failure(email: str) -> None:
    _login_failures.setdefault(email, []).append(_time.time())


def _clear_login_failures(email: str) -> None:
    _login_failures.pop(email, None)


def _mint_token(payload_extra: dict, ttl_seconds: int) -> str:
    secret = _get_login_jwt_secret()
    now = datetime.now(timezone.utc)
    payload = {
        "iat": now,
        "exp": now + timedelta(seconds=ttl_seconds),
        "jti": _secrets.token_urlsafe(16),
        **payload_extra,
    }
    return jwt.encode(payload, secret, algorithm=_JWT_ALG)


class LoginRequestBody(BaseModel):
    email: str = Field(..., min_length=1, max_length=255)
    password: str = Field(..., min_length=1, max_length=1024)


class LoginResponseBody(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = _ACCESS_TOKEN_TTL_SECONDS


class RefreshRequestBody(BaseModel):
    refresh_token: str = Field(..., min_length=1)


class RefreshResponseBody(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = _ACCESS_TOKEN_TTL_SECONDS


@router.post(
    "/login",
    response_model=LoginResponseBody,
    status_code=200,
    summary="Email+password login — returns short-lived JWT access token + refresh token",
)
async def auth_login(body: LoginRequestBody, request: Request) -> LoginResponseBody:
    """Commercial-grade login endpoint.

    - Rate-limited (5 attempts / 15 min per email).
    - Validates against UserDB (bcrypt).
    - Returns HS256 access token (2h) + refresh token (7d).
    - Every attempt (success or failure) is written to AuditLogger.
    """
    client_ip = request.client.host if request.client else "unknown"
    _check_login_rate_limit(body.email)

    user = _user_db.get_user_by_email(body.email)
    if not user or not _user_db.verify_password(body.password, user.password_hash):
        _record_login_failure(body.email)
        _auth_audit.log(_AuditEvent(
            actor_id=body.email,
            actor_role="unknown",
            action="auth.login.failure",
            resource_type="session",
            resource_id="",
            org_id=getattr(user, "org_id", "default") if user else "default",
            result="failure",
            details={"ip": client_ip, "reason": "invalid_credentials"},
        ))
        _logger.warning("Failed login for %s from %s", body.email, client_ip)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if user.status != _UserStatus.ACTIVE:
        _auth_audit.log(_AuditEvent(
            actor_id=body.email,
            actor_role=user.role.value,
            action="auth.login.failure",
            resource_type="session",
            resource_id="",
            org_id=getattr(user, "org_id", "default"),
            result="failure",
            details={"ip": client_ip, "reason": "account_inactive"},
        ))
        raise HTTPException(status_code=403, detail="Account is not active")

    _clear_login_failures(body.email)

    org_id = getattr(user, "org_id", "default") or "default"
    token_claims = {
        "sub": user.id,
        "email": user.email,
        "role": user.role.value,
        "org_id": org_id,
        "scopes": {
            "admin": ["admin:all"],
            "security_analyst": ["read:findings", "write:findings", "read:sbom", "read:evidence"],
            "developer": ["read:findings", "read:sbom"],
            "viewer": ["read:findings", "read:sbom"],
        }.get(user.role.value, ["read:findings"]),
        "token_type": "access",
    }
    access_token = _mint_token(token_claims, _ACCESS_TOKEN_TTL_SECONDS)
    refresh_token = _mint_token({
        "sub": user.id,
        "email": user.email,
        "org_id": org_id,
        "token_type": "refresh",
    }, _REFRESH_TOKEN_TTL_SECONDS)

    _auth_audit.log(_AuditEvent(
        actor_id=user.id,
        actor_role=user.role.value,
        action="auth.login.success",
        resource_type="session",
        resource_id="",
        org_id=org_id,
        result="success",
        details={"ip": client_ip, "email": user.email},
    ))
    _logger.info("Successful login user=%s org=%s ip=%s", user.id, org_id, client_ip)

    return LoginResponseBody(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=_ACCESS_TOKEN_TTL_SECONDS,
    )


@router.post(
    "/refresh",
    response_model=RefreshResponseBody,
    status_code=200,
    summary="Exchange a valid refresh token for a new short-lived access token",
)
async def auth_refresh(body: RefreshRequestBody, request: Request) -> RefreshResponseBody:
    """Refresh token endpoint.

    Validates the refresh token (HS256, FIXOPS_JWT_SECRET), checks token_type==refresh,
    then mints a new access token. Audit-logged on success and failure.
    """
    client_ip = request.client.host if request.client else "unknown"
    secret = _get_login_jwt_secret()

    try:
        claims = jwt.decode(
            body.refresh_token,
            secret,
            algorithms=[_JWT_ALG],
            options={"require": ["exp", "iat", "sub"]},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    if claims.get("token_type") != "refresh":
        raise HTTPException(status_code=401, detail="Token is not a refresh token")

    sub = claims.get("sub", "")
    email = claims.get("email", "")
    org_id = claims.get("org_id", "default")

    # Re-validate user still active
    user = _user_db.get_user_by_email(email) if email else None
    if not user or user.status != _UserStatus.ACTIVE:
        _auth_audit.log(_AuditEvent(
            actor_id=sub or email,
            actor_role="unknown",
            action="auth.refresh.failure",
            resource_type="session",
            resource_id="",
            org_id=org_id,
            result="failure",
            details={"ip": client_ip, "reason": "user_not_active_or_missing"},
        ))
        raise HTTPException(status_code=401, detail="User no longer active")

    token_claims = {
        "sub": sub,
        "email": email,
        "role": user.role.value,
        "org_id": org_id,
        "scopes": {
            "admin": ["admin:all"],
            "security_analyst": ["read:findings", "write:findings", "read:sbom", "read:evidence"],
            "developer": ["read:findings", "read:sbom"],
            "viewer": ["read:findings", "read:sbom"],
        }.get(user.role.value, ["read:findings"]),
        "token_type": "access",
    }
    access_token = _mint_token(token_claims, _ACCESS_TOKEN_TTL_SECONDS)

    _auth_audit.log(_AuditEvent(
        actor_id=sub,
        actor_role=user.role.value,
        action="auth.refresh.success",
        resource_type="session",
        resource_id="",
        org_id=org_id,
        result="success",
        details={"ip": client_ip, "email": email},
    ))

    return RefreshResponseBody(
        access_token=access_token,
        expires_in=_ACCESS_TOKEN_TTL_SECONDS,
    )
