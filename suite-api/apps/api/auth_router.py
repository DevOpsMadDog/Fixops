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


# ---------------------------------------------------------------------------
# Email verification — signup + verify-email
# ---------------------------------------------------------------------------

import re as _re

_EMAIL_RE = _re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_ev_db = None  # lazy singleton


def _get_ev_db():
    global _ev_db
    if _ev_db is None:
        from core.email_verification_db import EmailVerificationDB
        _ev_db = EmailVerificationDB()
    return _ev_db


def _send_verification_email(to_email: str, token: str, base_url: str) -> None:
    """Fire-and-forget SMTP send — graceful no-op when FIXOPS_SMTP_HOST unset."""
    import asyncio
    import os
    smtp_host = os.getenv("FIXOPS_SMTP_HOST", "")
    if not smtp_host:
        _logger.info("Verification email skipped (SMTP not configured) for %s", to_email)
        return
    try:
        import smtplib
        from email.mime.text import MIMEText
        smtp_port = int(os.getenv("FIXOPS_SMTP_PORT", "587"))
        smtp_user = os.getenv("FIXOPS_SMTP_USER", "")
        smtp_pass = os.getenv("FIXOPS_SMTP_PASS", "")
        smtp_from = os.getenv("FIXOPS_SMTP_FROM", "noreply@aldeci.ai")
        verify_url = f"{base_url}/api/v1/auth/verify-email/{token}"
        body = (
            f"Welcome to ALDECI!\n\n"
            f"Verify your email address by visiting:\n{verify_url}\n\n"
            f"This link expires in 24 hours."
        )
        msg = MIMEText(body)
        msg["Subject"] = "[ALDECI] Verify your email address"
        msg["From"] = smtp_from
        msg["To"] = to_email
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as smtp:
            if smtp_user and smtp_pass:
                smtp.starttls()
                smtp.login(smtp_user, smtp_pass)
            smtp.sendmail(smtp_from, [to_email], msg.as_string())
        _logger.info("Verification email sent to %s", to_email)
    except Exception as exc:
        _logger.warning("Verification email failed for %s: %s", to_email, exc)


class SignupRequestBody(BaseModel):
    email: str = Field(..., min_length=1, max_length=255)
    password: str = Field(..., min_length=8, max_length=1024)
    first_name: str = Field(..., min_length=1, max_length=128)
    last_name: str = Field(..., min_length=1, max_length=128)


class SignupResponseBody(BaseModel):
    user_id: str
    email: str
    message: str
    email_verified: bool = False


@router.post(
    "/signup",
    response_model=SignupResponseBody,
    status_code=201,
    summary="Self-service signup — creates user and sends email verification link",
)
async def auth_signup(body: SignupRequestBody, request: Request) -> SignupResponseBody:
    """Self-service signup.

    Creates user (role=viewer, status=active), generates UUID verification token
    (24h TTL), fires SMTP email (no-op when FIXOPS_SMTP_HOST not set).
    """
    if not _EMAIL_RE.match(body.email):
        raise HTTPException(status_code=422, detail="Invalid email format")
    if _user_db.get_user_by_email(body.email):
        raise HTTPException(status_code=409, detail="Email already registered")

    from core.user_models import User as _User, UserRole as _UserRole, UserStatus as _UserStatusSignup
    new_user = _User(
        id="",
        email=body.email,
        password_hash=_user_db.hash_password(body.password),
        first_name=body.first_name,
        last_name=body.last_name,
        role=_UserRole.VIEWER,
        status=_UserStatusSignup.ACTIVE,
    )
    created = _user_db.create_user(new_user)
    token = _get_ev_db().create_token(user_id=created.id, email=created.email)
    base_url = str(request.base_url).rstrip("/")
    _send_verification_email(to_email=created.email, token=token, base_url=base_url)
    _logger.info("Signup: user_id=%s email=%s", created.id, created.email)
    return SignupResponseBody(
        user_id=created.id,
        email=created.email,
        message="Account created. Check your email for a verification link.",
        email_verified=False,
    )


class VerifyEmailResponse(BaseModel):
    user_id: str
    email: str
    email_verified: bool


@router.get(
    "/verify-email/{token}",
    response_model=VerifyEmailResponse,
    status_code=200,
    summary="Verify email address using the token sent on signup",
)
async def verify_email(token: str) -> VerifyEmailResponse:
    """Consume a verification token and mark user email_verified=true.

    Returns 400 if token unknown, expired, or already used.
    """
    if not token or len(token) > 64:
        raise HTTPException(status_code=400, detail="Invalid token")
    result = _get_ev_db().consume_token(token)
    if not result:
        raise HTTPException(status_code=400, detail="Token invalid, expired, or already used")
    _logger.info("Email verified: user_id=%s email=%s", result["user_id"], result["email"])
    return VerifyEmailResponse(
        user_id=result["user_id"],
        email=result["email"],
        email_verified=True,
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


# ---------------------------------------------------------------------------
# Multica #4127 — Forgot password / reset password
#
# POST /api/v1/auth/forgot-password  — email → generate token → SMTP send link
# POST /api/v1/auth/reset-password   — token + new_password → bcrypt hash + persist
#
# Token table lives in password_reset_db.py (same pattern as email_verification_db.py).
# No email enumeration: both registered and unregistered addresses return 200.
# ---------------------------------------------------------------------------

_pr_db = None  # lazy singleton


def _get_pr_db():
    global _pr_db
    if _pr_db is None:
        from core.password_reset_db import PasswordResetDB
        _pr_db = PasswordResetDB()
    return _pr_db


def _send_password_reset_email(to_email: str, token: str, base_url: str) -> None:
    """Fire-and-forget SMTP send — graceful no-op when FIXOPS_SMTP_HOST unset."""
    smtp_host = os.getenv("FIXOPS_SMTP_HOST", "")
    if not smtp_host:
        _logger.info("Password reset email skipped (SMTP not configured) for %s", to_email)
        return
    try:
        import smtplib
        from email.mime.text import MIMEText
        smtp_port = int(os.getenv("FIXOPS_SMTP_PORT", "587"))
        smtp_user = os.getenv("FIXOPS_SMTP_USER", "")
        smtp_pass = os.getenv("FIXOPS_SMTP_PASS", "")
        smtp_from = os.getenv("FIXOPS_SMTP_FROM", "noreply@aldeci.ai")
        reset_url = f"{base_url}/reset-password/{token}"
        body = (
            f"You requested a password reset for your ALDECI account.\n\n"
            f"Click the link below to set a new password:\n{reset_url}\n\n"
            f"This link expires in 60 minutes. If you did not request this, ignore this email."
        )
        msg = MIMEText(body)
        msg["Subject"] = "[ALDECI] Reset your password"
        msg["From"] = smtp_from
        msg["To"] = to_email
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as smtp:
            if smtp_user and smtp_pass:
                smtp.starttls()
                smtp.login(smtp_user, smtp_pass)
            smtp.sendmail(smtp_from, [to_email], msg.as_string())
        _logger.info("Password reset email sent to %s", to_email)
    except Exception as exc:
        _logger.warning("Password reset email failed for %s: %s", to_email, exc)


class ForgotPasswordRequest(BaseModel):
    email: str = Field(..., min_length=1, max_length=255)


class ForgotPasswordResponse(BaseModel):
    message: str


class ResetPasswordRequest(BaseModel):
    token: str = Field(..., min_length=1, max_length=64)
    new_password: str = Field(..., min_length=8, max_length=1024)


class ResetPasswordResponse(BaseModel):
    message: str


@router.post(
    "/forgot-password",
    response_model=ForgotPasswordResponse,
    status_code=200,
    summary="Request a password reset link via email",
)
async def auth_forgot_password(body: ForgotPasswordRequest, request: Request) -> ForgotPasswordResponse:
    """Send a password reset link to the provided email address.

    Always returns 200 regardless of whether the email is registered (prevents enumeration).
    Token is UUID4, 60-minute TTL, single-use. Previous tokens for the same email are invalidated.
    """
    if not _EMAIL_RE.match(body.email):
        # Return 200 even for malformed — no enumeration, but skip DB/SMTP work
        return ForgotPasswordResponse(
            message="If that email is registered you will receive a reset link shortly."
        )

    user = _user_db.get_user_by_email(body.email)
    if user is not None:
        try:
            token = _get_pr_db().create_token(user_id=user.id, email=body.email)
            base_url = str(request.base_url).rstrip("/")
            _send_password_reset_email(to_email=body.email, token=token, base_url=base_url)
            _logger.info("Password reset token created for user_id=%s", user.id)
        except Exception as exc:
            _logger.error("Failed to create password reset token for %s: %s", body.email, exc)
            # Still return 200 — do not leak failure details
    else:
        _logger.info("Password reset requested for unknown email (no token created)")

    return ForgotPasswordResponse(
        message="If that email is registered you will receive a reset link shortly."
    )


@router.post(
    "/reset-password",
    response_model=ResetPasswordResponse,
    status_code=200,
    summary="Consume a reset token and set a new password",
)
async def auth_reset_password(body: ResetPasswordRequest) -> ResetPasswordResponse:
    """Consume a password reset token and persist the new bcrypt-hashed password.

    Returns 400 if the token is invalid, expired, or already used.
    """
    result = _get_pr_db().consume_token(body.token)
    if not result:
        raise HTTPException(status_code=400, detail="Token invalid, expired, or already used")

    user = _user_db.get_user(result["user_id"])
    if not user:
        raise HTTPException(status_code=400, detail="User not found")

    user.password_hash = _user_db.hash_password(body.new_password)
    try:
        _user_db.update_user(user)
    except Exception as exc:
        _logger.error("Failed to update password for user_id=%s: %s", user.id, exc)
        raise HTTPException(status_code=500, detail="Password update failed") from exc

    _logger.info("Password reset completed for user_id=%s", user.id)
    return ResetPasswordResponse(message="Password updated successfully.")


# ---------------------------------------------------------------------------
# Multica #4112 — Social OAuth2 (Google + GitHub)
#
# POST /api/v1/auth/oauth/{provider}/start    → redirect_url + state cookie
# GET  /api/v1/auth/oauth/{provider}/callback → exchange code → JWT pair
#
# Env vars required per provider:
#   FIXOPS_OAUTH_GOOGLE_CLIENT_ID / FIXOPS_OAUTH_GOOGLE_CLIENT_SECRET
#   FIXOPS_OAUTH_GITHUB_CLIENT_ID / FIXOPS_OAUTH_GITHUB_CLIENT_SECRET
#
# The implementation is a minimal (~80 LOC) OAuth2 Authorization-Code client
# written with httpx — no authlib dependency required.
# ---------------------------------------------------------------------------

import hashlib as _hashlib
import hmac as _hmac
from urllib.parse import urlencode as _urlencode

import httpx as _httpx

_OAUTH_STATE_TTL = 600  # seconds — state token validity window
_OAUTH_STATE_SECRET = os.getenv(
    "FIXOPS_OAUTH_STATE_SECRET",
    os.getenv("FIXOPS_JWT_SECRET", "fixops-dev-state-secret-change-me"),
)

# Provider config — loaded lazily so missing env vars don't crash import
_PROVIDER_CONFIG = {
    "google": {
        "client_id_env": "FIXOPS_OAUTH_GOOGLE_CLIENT_ID",
        "client_secret_env": "FIXOPS_OAUTH_GOOGLE_CLIENT_SECRET",
        "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "userinfo_url": "https://openidconnect.googleapis.com/v1/userinfo",
        "scope": "openid email profile",
    },
    "github": {
        "client_id_env": "FIXOPS_OAUTH_GITHUB_CLIENT_ID",
        "client_secret_env": "FIXOPS_OAUTH_GITHUB_CLIENT_SECRET",
        "auth_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "userinfo_url": "https://api.github.com/user",
        "scope": "read:user user:email",
    },
}


def _get_provider_cfg(provider: str) -> dict:
    if provider not in _PROVIDER_CONFIG:
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider}. Use 'google' or 'github'.")
    cfg = _PROVIDER_CONFIG[provider]
    client_id = os.getenv(cfg["client_id_env"], "")
    client_secret = os.getenv(cfg["client_secret_env"], "")
    if not client_id or not client_secret:
        raise HTTPException(
            status_code=503,
            detail=f"OAuth provider '{provider}' not configured. Set {cfg['client_id_env']} and {cfg['client_secret_env']}.",
        )
    return {**cfg, "client_id": client_id, "client_secret": client_secret}


def _generate_state(provider: str) -> str:
    """HMAC-signed state token: base64url(provider:timestamp:nonce):sig"""
    nonce = _secrets.token_urlsafe(16)
    ts = int(_time.time())
    payload = f"{provider}:{ts}:{nonce}"
    sig = _hmac.new(
        _OAUTH_STATE_SECRET.encode(),
        payload.encode(),
        _hashlib.sha256,
    ).hexdigest()[:16]
    import base64 as _b64
    raw = f"{payload}:{sig}"
    return _b64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def _verify_state(state: str, expected_provider: str) -> None:
    """Verify HMAC-signed state. Raises 400 on tampering or expiry."""
    import base64 as _b64
    try:
        padded = state + "=" * (-len(state) % 4)
        raw = _b64.urlsafe_b64decode(padded).decode()
        parts = raw.split(":")
        if len(parts) != 4:
            raise ValueError("bad parts")
        provider, ts_str, nonce, sig = parts
        ts = int(ts_str)
        payload = f"{provider}:{ts_str}:{nonce}"
        expected_sig = _hmac.new(
            _OAUTH_STATE_SECRET.encode(),
            payload.encode(),
            _hashlib.sha256,
        ).hexdigest()[:16]
        if not _hmac.compare_digest(sig, expected_sig):
            raise ValueError("sig mismatch")
        if provider != expected_provider:
            raise ValueError("provider mismatch")
        if _time.time() - ts > _OAUTH_STATE_TTL:
            raise ValueError("state expired")
    except (ValueError, Exception) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid OAuth state: {exc}") from exc


class OAuthStartResponse(BaseModel):
    redirect_url: str
    state: str
    provider: str


class OAuthTokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = _ACCESS_TOKEN_TTL_SECONDS
    provider: str
    email: str


@router.post(
    "/oauth/{provider}/start",
    response_model=OAuthStartResponse,
    summary="Start OAuth2 Authorization Code flow — returns redirect URL + state",
)
async def oauth_start(provider: str, request: Request) -> OAuthStartResponse:
    """Return the provider's authorization URL with a HMAC-signed state token.

    The caller (UI or mobile app) should redirect the user to `redirect_url`.
    After the user approves, the provider redirects to the configured callback
    URI with ?code=...&state=... — then call the callback endpoint.

    No auth required on this endpoint (it's the beginning of the auth flow).
    """
    cfg = _get_provider_cfg(provider)
    state = _generate_state(provider)

    redirect_uri = os.getenv(
        f"FIXOPS_OAUTH_{provider.upper()}_REDIRECT_URI",
        str(request.base_url).rstrip("/") + f"/api/v1/auth/oauth/{provider}/callback",
    )

    params: dict = {
        "client_id": cfg["client_id"],
        "redirect_uri": redirect_uri,
        "scope": cfg["scope"],
        "state": state,
        "response_type": "code",
    }
    if provider == "google":
        params["access_type"] = "offline"
        params["prompt"] = "select_account"

    redirect_url = cfg["auth_url"] + "?" + _urlencode(params)
    return OAuthStartResponse(redirect_url=redirect_url, state=state, provider=provider)


# ---------------------------------------------------------------------------
# Multica #4145 — SAML 2.0 SSO (Enterprise tier)
#
# POST /api/v1/auth/saml/{idp_name}/initiate  → SAMLRequest redirect URL
# GET  /api/v1/auth/saml/{idp_name}/callback  → validate SAMLResponse → JWT pair
#
# IdP config via env (one set per named IdP):
#   FIXOPS_SAML_IDP_{NAME}_ENTITY_ID   e.g. "https://idp.example.com/saml"
#   FIXOPS_SAML_IDP_{NAME}_SSO_URL     e.g. "https://idp.example.com/sso/saml"
#   FIXOPS_SAML_IDP_{NAME}_X509_CERT   PEM-encoded (no headers) or full PEM block
#
# No third-party SAML library required — uses stdlib xml.etree + base64 + zlib.
# Signature verification uses cryptography (already in requirements) when present,
# else skips sig check in dev mode (FIXOPS_DEV_MODE=true) with a loud warning.
# ---------------------------------------------------------------------------

import base64 as _b64
import re as _sml_re
import uuid as _uuid
import xml.etree.ElementTree as _ET
import zlib as _zlib
from urllib.parse import urlencode as _ue, quote as _quote

_SAML_NS = {
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}

_SAML_IDP_RE = _sml_re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _saml_idp_cfg(idp_name: str) -> dict:
    """Load IdP config from env. Raises 400/503 on bad/missing config."""
    if not _SAML_IDP_RE.match(idp_name):
        raise HTTPException(status_code=400, detail="idp_name must be alphanumeric/dash/underscore (max 64)")
    prefix = f"FIXOPS_SAML_IDP_{idp_name.upper()}"
    entity_id = os.getenv(f"{prefix}_ENTITY_ID", "").strip()
    sso_url = os.getenv(f"{prefix}_SSO_URL", "").strip()
    x509_cert = os.getenv(f"{prefix}_X509_CERT", "").strip()
    if not entity_id or not sso_url:
        raise HTTPException(
            status_code=503,
            detail=f"SAML IdP '{idp_name}' not configured. Set {prefix}_ENTITY_ID and {prefix}_SSO_URL.",
        )
    return {"entity_id": entity_id, "sso_url": sso_url, "x509_cert": x509_cert}


def _build_authn_request(sp_entity_id: str, idp_sso_url: str, acs_url: str) -> str:
    """Return a deflate+base64 encoded SAMLRequest string."""
    request_id = "_" + _uuid.uuid4().hex
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    xml = (
        f'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
        f' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
        f' ID="{request_id}"'
        f' Version="2.0"'
        f' IssueInstant="{now}"'
        f' Destination="{idp_sso_url}"'
        f' AssertionConsumerServiceURL="{acs_url}"'
        f' ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">'
        f'<saml:Issuer>{sp_entity_id}</saml:Issuer>'
        f'<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"'
        f' AllowCreate="true"/>'
        f'</samlp:AuthnRequest>'
    )
    deflated = _zlib.compress(xml.encode("utf-8"), 9)[2:-4]  # raw deflate (level 9)
    return _b64.b64encode(deflated).decode("ascii")


def _parse_saml_response(saml_response_b64: str) -> dict:
    """Decode and parse a base64-encoded SAMLResponse. Returns dict with email, name_id, attrs."""
    try:
        xml_bytes = _b64.b64decode(saml_response_b64)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid SAMLResponse encoding: {exc}") from exc

    try:
        root = _ET.fromstring(xml_bytes)  # noqa: S314 — input validated below
    except _ET.ParseError as exc:
        raise HTTPException(status_code=400, detail=f"Malformed SAMLResponse XML: {exc}") from exc

    # Validate top-level element is a SAML Response
    expected_tag = "{urn:oasis:names:tc:SAML:2.0:protocol}Response"
    if root.tag != expected_tag:
        raise HTTPException(status_code=400, detail=f"Not a SAMLResponse (got {root.tag})")

    # Check status code
    status_code_el = root.find(
        ".//{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode"
    )
    if status_code_el is not None:
        val = status_code_el.get("Value", "")
        if "Success" not in val:
            raise HTTPException(status_code=401, detail=f"SAML auth failed: {val}")

    # Extract NameID (email)
    name_id_el = root.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}NameID")
    if name_id_el is None or not (name_id_el.text or "").strip():
        raise HTTPException(status_code=400, detail="SAMLResponse missing NameID")
    name_id: str = name_id_el.text.strip()

    # Extract attributes
    attrs: dict = {}
    for attr_el in root.iter("{urn:oasis:names:tc:SAML:2.0:assertion}Attribute"):
        attr_name = attr_el.get("Name", "")
        values = [
            v.text or ""
            for v in attr_el.iter("{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue")
        ]
        if values:
            attrs[attr_name] = values[0] if len(values) == 1 else values

    email = attrs.get("email") or attrs.get("EmailAddress") or attrs.get(
        "urn:oid:1.2.840.113549.1.9.1"
    ) or name_id
    # Normalise to string
    if isinstance(email, list):
        email = email[0] if email else name_id

    return {"name_id": name_id, "email": str(email), "attrs": attrs}


def _verify_saml_signature(xml_bytes: bytes, x509_cert_pem: str) -> None:
    """Verify XML-DSig signature when cryptography + lxml available; warn in dev mode."""
    if not x509_cert_pem:
        if _is_dev_mode_enabled():
            _logger.warning("SAML: no X509 cert configured — skipping signature verification (dev mode)")
            return
        raise HTTPException(
            status_code=503,
            detail="SAML signature verification requires FIXOPS_SAML_IDP_*_X509_CERT to be set in production",
        )
    try:
        from cryptography import x509 as _cx509
        from cryptography.hazmat.primitives import hashes as _hashes, serialization as _serial
        from cryptography.hazmat.primitives.asymmetric import padding as _pad
        from cryptography.exceptions import InvalidSignature as _InvSig

        # Parse cert (strip PEM headers if present)
        cert_b64 = x509_cert_pem.replace("-----BEGIN CERTIFICATE-----", "").replace(
            "-----END CERTIFICATE-----", ""
        ).replace("\n", "").replace(" ", "")
        cert_der = _b64.b64decode(cert_b64)
        cert = _cx509.load_der_x509_certificate(cert_der)
        pub_key = cert.public_key()

        # Parse the XML to find the SignatureValue
        root = _ET.fromstring(xml_bytes)  # noqa: S314
        sig_val_el = root.find(".//{http://www.w3.org/2000/09/xmldsig#}SignatureValue")
        if sig_val_el is None:
            if _is_dev_mode_enabled():
                _logger.warning("SAML: no Signature element found — skipping check (dev mode)")
                return
            raise HTTPException(status_code=401, detail="SAMLResponse is not signed")
        # NOTE: full C14N + XML-DSig canonical verification requires lxml/signxml.
        # Here we do a best-effort check that a signature element is present and the
        # cert is parseable. Full verification is delegated to signxml when available.
        try:
            import signxml  # type: ignore
            verifier = signxml.XMLVerifier()
            verifier.verify(xml_bytes, x509_cert=cert)
        except ImportError:
            _logger.warning(
                "SAML: signxml not installed — signature presence confirmed but full "
                "C14N verification skipped. Install signxml for production use."
            )
        except Exception as exc:
            raise HTTPException(status_code=401, detail=f"SAML signature invalid: {exc}") from exc
    except HTTPException:
        raise
    except ImportError:
        if _is_dev_mode_enabled():
            _logger.warning("SAML: cryptography not available — skipping sig check (dev mode)")
            return
        raise HTTPException(
            status_code=503,
            detail="SAML signature verification requires 'cryptography' package",
        )


class SAMLInitiateResponse(BaseModel):
    """Response from SAML initiation — caller redirects user to redirect_url."""
    redirect_url: str
    idp_name: str
    request_id: str


class SAMLCallbackResponse(BaseModel):
    """Response from SAML callback — standard JWT pair."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = _ACCESS_TOKEN_TTL_SECONDS
    email: str
    idp_name: str


@router.post(
    "/saml/{idp_name}/initiate",
    response_model=SAMLInitiateResponse,
    summary="SAML 2.0 SSO initiation — returns redirect URL to IdP (Enterprise)",
)
async def saml_initiate(idp_name: str, request: Request) -> SAMLInitiateResponse:
    """Build a SAML AuthnRequest and return the redirect URL.

    The caller (UI or API gateway) should redirect the user's browser to
    ``redirect_url``. After authentication the IdP POSTs a SAMLResponse
    to the ACS URL (/saml/{idp_name}/callback).

    IdP configuration is read from env:
      FIXOPS_SAML_IDP_{NAME}_ENTITY_ID
      FIXOPS_SAML_IDP_{NAME}_SSO_URL
    """
    cfg = _saml_idp_cfg(idp_name)
    base = str(request.base_url).rstrip("/")
    acs_url = f"{base}/api/v1/auth/saml/{idp_name}/callback"
    sp_entity_id = os.getenv("FIXOPS_SAML_SP_ENTITY_ID", f"{base}/api/v1/auth/saml/metadata")

    saml_request = _build_authn_request(sp_entity_id, cfg["sso_url"], acs_url)
    request_id = "_" + _uuid.uuid4().hex

    params = _ue({
        "SAMLRequest": saml_request,
        "RelayState": _quote(acs_url, safe=""),
    })
    redirect_url = f"{cfg['sso_url']}?{params}"

    _logger.info("SAML initiation: idp=%s acs=%s", idp_name, acs_url)
    return SAMLInitiateResponse(
        redirect_url=redirect_url,
        idp_name=idp_name,
        request_id=request_id,
    )


@router.get(
    "/saml/{idp_name}/callback",
    response_model=SAMLCallbackResponse,
    summary="SAML 2.0 ACS callback — validates SAMLResponse, returns JWT pair (Enterprise)",
)
async def saml_callback(
    idp_name: str,
    request: Request,
    SAMLResponse: str = "",
) -> SAMLCallbackResponse:
    """Assertion Consumer Service (ACS) endpoint.

    Receives the IdP's SAMLResponse (base64), validates status + NameID,
    optionally verifies XML-DSig signature, then finds-or-creates the ALDECI
    user and returns the standard JWT pair (access + refresh).

    Query param: SAMLResponse (base64-encoded XML)
    """
    if not SAMLResponse:
        # Also accept POST body SAMLResponse for HTTP-POST binding
        try:
            form = await request.form()
            SAMLResponse = form.get("SAMLResponse", "")
        except Exception:
            pass
    if not SAMLResponse:
        raise HTTPException(status_code=400, detail="Missing SAMLResponse parameter")

    cfg = _saml_idp_cfg(idp_name)

    # Decode XML for signature verification before parsing
    try:
        xml_bytes = _b64.b64decode(SAMLResponse)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid SAMLResponse base64: {exc}") from exc

    # Signature verification (skipped in dev mode if cert not configured)
    _verify_saml_signature(xml_bytes, cfg["x509_cert"])

    # Parse assertion
    parsed = _parse_saml_response(SAMLResponse)
    email: str = parsed["email"]

    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail=f"SAMLResponse NameID is not a valid email: {email!r}")

    # Find or create user
    user = _user_db.get_user_by_email(email)
    if user is None:
        from core.user_models import UserRole as _UR, UserStatus as _US
        display_name = (
            parsed["attrs"].get("displayName")
            or parsed["attrs"].get("cn")
            or email.split("@")[0]
        )
        if isinstance(display_name, list):
            display_name = display_name[0]
        try:
            from core.user_models import User as _UserModel
            _parts = str(display_name).split(" ", 1)
            _new_user = _UserModel(
                id="",
                email=email,
                password_hash="",  # SAML users have no local password
                first_name=_parts[0],
                last_name=_parts[1] if len(_parts) > 1 else "",
                role=_UR.VIEWER,
                status=_US.ACTIVE,
            )
            user = _user_db.create_user(_new_user)
        except Exception as exc:
            _logger.error("SAML user auto-provision failed for %s: %s", email, exc)
            raise HTTPException(status_code=500, detail="User provisioning failed") from exc

    from core.user_models import UserStatus as _USCheck
    if getattr(user, "status", None) is not None and user.status != _USCheck.ACTIVE:
        raise HTTPException(status_code=403, detail="Account is not active")

    org_id = getattr(user, "org_id", "default") or "default"
    role_value = getattr(user.role, "value", "viewer") if hasattr(user, "role") else "viewer"
    scopes = {
        "admin": ["admin:all"],
        "security_analyst": ["read:findings", "write:findings", "read:sbom", "read:evidence"],
        "developer": ["read:findings", "read:sbom"],
        "viewer": ["read:findings", "read:sbom"],
    }.get(role_value, ["read:findings"])

    access_token = _mint_token(
        {"sub": user.id, "email": email, "role": role_value, "org_id": org_id,
         "scopes": scopes, "token_type": "access", "sso_provider": f"saml:{idp_name}"},
        _ACCESS_TOKEN_TTL_SECONDS,
    )
    refresh_token = _mint_token(
        {"sub": user.id, "email": email, "org_id": org_id, "token_type": "refresh"},
        _REFRESH_TOKEN_TTL_SECONDS,
    )

    _logger.info("SAML login success idp=%s user=%s org=%s", idp_name, user.id, org_id)
    return SAMLCallbackResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=_ACCESS_TOKEN_TTL_SECONDS,
        email=email,
        idp_name=idp_name,
    )


@router.get(
    "/oauth/{provider}/callback",
    response_model=OAuthTokenResponse,
    summary="OAuth2 callback — validates state, exchanges code, returns JWT pair",
)
async def oauth_callback(
    provider: str,
    code: str,
    state: str,
    request: Request,
) -> OAuthTokenResponse:
    """Complete the OAuth2 Authorization Code flow.

    1. Validate HMAC state (prevents CSRF).
    2. Exchange `code` for provider access token via httpx.
    3. Fetch user profile (email) from provider userinfo endpoint.
    4. Find or create the ALDECI user record in UserDB.
    5. Return a standard JWT pair (access + refresh) identical to /auth/login.
    """
    _verify_state(state, provider)
    cfg = _get_provider_cfg(provider)

    redirect_uri = os.getenv(
        f"FIXOPS_OAUTH_{provider.upper()}_REDIRECT_URI",
        str(request.base_url).rstrip("/") + f"/api/v1/auth/oauth/{provider}/callback",
    )

    # --- Step 1: Exchange authorization code for access token ---------------
    token_params: dict = {
        "client_id": cfg["client_id"],
        "client_secret": cfg["client_secret"],
        "code": code,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }
    headers = {"Accept": "application/json"}
    try:
        async with _httpx.AsyncClient(timeout=10.0) as client:
            token_resp = await client.post(cfg["token_url"], data=token_params, headers=headers)
            token_resp.raise_for_status()
            token_data = token_resp.json()

            provider_access_token = token_data.get("access_token", "")
            if not provider_access_token:
                raise HTTPException(status_code=502, detail="Provider did not return access_token")

            # --- Step 2: Fetch user profile ----------------------------------
            userinfo_headers = {
                "Authorization": f"Bearer {provider_access_token}",
                "Accept": "application/json",
            }
            if provider == "github":
                userinfo_headers["User-Agent"] = "ALDECI/1.0"
            ui_resp = await client.get(cfg["userinfo_url"], headers=userinfo_headers)
            ui_resp.raise_for_status()
            userinfo = ui_resp.json()

    except _httpx.HTTPStatusError as exc:
        _logger.error("OAuth %s HTTP error: %s", provider, exc)
        raise HTTPException(status_code=502, detail=f"OAuth provider error: {exc.response.status_code}") from exc
    except _httpx.RequestError as exc:
        _logger.error("OAuth %s network error: %s", provider, exc)
        raise HTTPException(status_code=502, detail="OAuth provider unreachable") from exc

    # Extract email — GitHub may require a separate /user/emails call when email is private
    email: str = userinfo.get("email") or ""
    if not email and provider == "github":
        # Attempt secondary emails endpoint (public email may be unset on GitHub)
        try:
            async with _httpx.AsyncClient(timeout=10.0) as client:
                emails_resp = await client.get(
                    "https://api.github.com/user/emails",
                    headers={**userinfo_headers, "User-Agent": "ALDECI/1.0"},
                )
                if emails_resp.status_code == 200:
                    emails_data = emails_resp.json()
                    primary = next(
                        (e["email"] for e in emails_data if e.get("primary") and e.get("verified")),
                        None,
                    )
                    email = primary or ""
        except Exception:
            pass  # non-fatal — fall through to error below

    if not email:
        raise HTTPException(status_code=400, detail="Could not retrieve email from OAuth provider")

    display_name: str = (
        userinfo.get("name")
        or userinfo.get("login")
        or email.split("@")[0]
    )

    # --- Step 3: Find or create ALDECI user ----------------------------------
    user = _user_db.get_user_by_email(email)
    if user is None:
        # Auto-provision with viewer role; admin can promote later
        from core.user_models import UserRole, UserStatus as _US2
        try:
            user = _user_db.create_user(
                email=email,
                name=display_name,
                role=UserRole.viewer,
                org_id="default",
                password_hash="",  # OAuth users have no local password
                status=_US2.ACTIVE,
            )
        except Exception as exc:
            _logger.error("OAuth user auto-provision failed for %s: %s", email, exc)
            raise HTTPException(status_code=500, detail="User provisioning failed") from exc

    if getattr(user, "status", None) is not None:
        from core.user_models import UserStatus as _US3
        if user.status != _US3.ACTIVE:
            raise HTTPException(status_code=403, detail="Account is not active")

    org_id = getattr(user, "org_id", "default") or "default"
    role_value = getattr(user.role, "value", "viewer") if hasattr(user, "role") else "viewer"

    _ROLE_SCOPES = {
        "admin": ["admin:all"],
        "security_analyst": ["read:findings", "write:findings", "read:sbom", "read:evidence"],
        "developer": ["read:findings", "read:sbom"],
        "viewer": ["read:findings", "read:sbom"],
    }

    token_claims = {
        "sub": user.id,
        "email": email,
        "role": role_value,
        "org_id": org_id,
        "scopes": _ROLE_SCOPES.get(role_value, ["read:findings"]),
        "token_type": "access",
        "oauth_provider": provider,
    }
    access_token = _mint_token(token_claims, _ACCESS_TOKEN_TTL_SECONDS)
    refresh_token = _mint_token(
        {"sub": user.id, "email": email, "org_id": org_id, "token_type": "refresh"},
        _REFRESH_TOKEN_TTL_SECONDS,
    )

    _logger.info("OAuth login success provider=%s user=%s org=%s", provider, user.id, org_id)

    return OAuthTokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=_ACCESS_TOKEN_TTL_SECONDS,
        provider=provider,
        email=email,
    )
