"""
SSO/SAML authentication API endpoints.
"""
from typing import Any, Dict, List, Optional

from core.auth_db import AuthDB
from core.auth_models import AuthProvider, SSOConfig, SSOStatus
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])
db = AuthDB()


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


@router.post("/keys", response_model=KeyCreateResponse, status_code=201)
async def create_api_key(req: KeyCreateRequest):
    """Create a new managed API key with TTL and scope restrictions."""
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


@router.post("/keys/{key_id}/rotate", response_model=KeyCreateResponse)
async def rotate_api_key(key_id: str, req: KeyRotateRequest):
    """Rotate an API key — creates replacement, puts old key in grace period."""
    km = _get_key_manager()
    try:
        new_record, new_plaintext = km.rotate_key(key_id, performed_by=req.performed_by)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    resp = new_record.to_dict()
    resp["plaintext_key"] = new_plaintext
    return KeyCreateResponse(**resp)


@router.delete("/keys/{key_id}")
async def revoke_api_key(key_id: str):
    """Immediately revoke an API key."""
    km = _get_key_manager()
    success = km.revoke_key(key_id)
    if not success:
        raise HTTPException(status_code=404, detail="Key not found or already revoked")
    return {"status": "revoked", "key_id": key_id}


@router.get("/keys", response_model=list)
async def list_api_keys(user_id: Optional[str] = None, include_revoked: bool = False):
    """List managed API keys."""
    km = _get_key_manager()
    keys = km.list_keys(user_id=user_id, include_revoked=include_revoked)
    return [k.to_dict() for k in keys]


@router.get("/keys/expiring")
async def get_expiring_keys(within_days: int = Query(default=7, ge=1, le=365)):
    """Get API keys expiring within the specified timeframe."""
    km = _get_key_manager()
    keys = km.get_expiring_keys(within_days=within_days)
    return {"expiring_within_days": within_days, "count": len(keys), "keys": [k.to_dict() for k in keys]}


@router.post("/keys/cleanup")
async def cleanup_expired_keys():
    """Deactivate all expired keys past their grace period."""
    km = _get_key_manager()
    count = km.cleanup_expired()
    return {"deactivated_count": count}


@router.get("/keys/{key_id}/audit")
async def get_key_audit_log(key_id: str, limit: int = Query(default=100, ge=1, le=1000)):
    """Get audit trail for a specific API key."""
    km = _get_key_manager()
    log = km.get_audit_log(key_id=key_id, limit=limit)
    return {"key_id": key_id, "entries": log}
