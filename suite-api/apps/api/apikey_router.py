"""
API Key management endpoints — create, list, get, update, rotate, revoke, usage.

All endpoints are admin-only (require ``admin:all`` scope or ADMIN role).
The plaintext key is returned ONCE on creation; it cannot be retrieved later.

Prefix: /api/v1/auth/keys
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from core.api_key_manager import APIKey, APIKeyManager
from core.auth_middleware import AuthContext, require_scope
from core.rbac import RBACRole
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/auth/keys", tags=["api-key-management"])


# ---------------------------------------------------------------------------
# Dependency
# ---------------------------------------------------------------------------


def _mgr() -> APIKeyManager:
    """Lazy-load the singleton APIKeyManager."""
    try:
        return APIKeyManager()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"APIKeyManager unavailable: {exc}",
        )


_admin = Depends(require_scope("admin:all"))


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class CreateKeyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    org_id: str = Field(..., min_length=1)
    role: str = "viewer"
    scopes: List[str] = Field(default_factory=list)
    expires_at: Optional[datetime] = None
    rate_limit: int = Field(60, ge=1, le=100_000)
    description: str = ""


class UpdateKeyRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    scopes: Optional[List[str]] = None
    rate_limit: Optional[int] = Field(None, ge=1, le=100_000)


class APIKeyResponse(BaseModel):
    """Safe key response — no key_hash exposed."""

    id: str
    name: str
    prefix: str
    org_id: str
    created_by: str
    created_at: datetime
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]
    use_count: int
    rate_limit: int
    scopes: List[str]
    role: str
    is_active: bool
    description: str


class CreateKeyResponse(APIKeyResponse):
    """One-time creation response that includes the plaintext key."""

    raw_key: str = Field(..., description="Store this securely — shown only once")


def _to_response(key: APIKey) -> APIKeyResponse:
    return APIKeyResponse(
        id=key.id,
        name=key.name,
        prefix=key.prefix,
        org_id=key.org_id,
        created_by=key.created_by,
        created_at=key.created_at,
        expires_at=key.expires_at,
        last_used_at=key.last_used_at,
        use_count=key.use_count,
        rate_limit=key.rate_limit,
        scopes=key.scopes,
        role=key.role.value,
        is_active=key.is_active,
        description=key.description,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("", response_model=CreateKeyResponse, status_code=status.HTTP_201_CREATED)
async def create_key(
    body: CreateKeyRequest,
    auth: AuthContext = _admin,
    mgr: APIKeyManager = Depends(_mgr),
) -> CreateKeyResponse:
    """Create a new API key. The plaintext key is returned ONCE."""
    try:
        role = RBACRole(body.role)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid role: {body.role!r}",
        )

    key, raw = mgr.create_key(
        name=body.name,
        org_id=body.org_id,
        role=role,
        scopes=body.scopes,
        expires_at=body.expires_at,
        rate_limit=body.rate_limit,
        description=body.description,
        created_by=auth.user_id,
    )
    resp = _to_response(key)
    return CreateKeyResponse(**resp.model_dump(), raw_key=raw)


@router.get("", response_model=List[APIKeyResponse])
async def list_keys(
    org_id: str,
    auth: AuthContext = _admin,
    mgr: APIKeyManager = Depends(_mgr),
) -> List[APIKeyResponse]:
    """List all API keys for an org (no secrets exposed)."""
    return [_to_response(k) for k in mgr.list_keys(org_id=org_id)]


@router.get("/{key_id}", response_model=APIKeyResponse)
async def get_key(
    key_id: str,
    auth: AuthContext = _admin,
    mgr: APIKeyManager = Depends(_mgr),
) -> APIKeyResponse:
    """Get a single API key by ID."""
    key = mgr.get_key(key_id)
    if key is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key not found")
    return _to_response(key)


@router.put("/{key_id}", response_model=APIKeyResponse)
async def update_key(
    key_id: str,
    body: UpdateKeyRequest,
    auth: AuthContext = _admin,
    mgr: APIKeyManager = Depends(_mgr),
) -> APIKeyResponse:
    """Update mutable key metadata: name, description, scopes, rate_limit."""
    updates: Dict[str, Any] = {
        k: v for k, v in body.model_dump().items() if v is not None
    }
    try:
        key = mgr.update_key(key_id, updates)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    return _to_response(key)


@router.post("/{key_id}/rotate", response_model=CreateKeyResponse)
async def rotate_key(
    key_id: str,
    auth: AuthContext = _admin,
    mgr: APIKeyManager = Depends(_mgr),
) -> CreateKeyResponse:
    """Rotate a key — deactivates old, returns new key (plaintext shown once)."""
    try:
        new_key, new_raw = mgr.rotate_key(key_id, created_by=auth.user_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    resp = _to_response(new_key)
    return CreateKeyResponse(**resp.model_dump(), raw_key=new_raw)


@router.post("/{key_id}/revoke", response_model=Dict[str, Any])
async def revoke_key(
    key_id: str,
    auth: AuthContext = _admin,
    mgr: APIKeyManager = Depends(_mgr),
) -> Dict[str, Any]:
    """Revoke a key immediately."""
    try:
        mgr.revoke_key(key_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    return {"status": "revoked", "key_id": key_id}


@router.get("/{key_id}/usage", response_model=Dict[str, Any])
async def get_usage(
    key_id: str,
    auth: AuthContext = _admin,
    mgr: APIKeyManager = Depends(_mgr),
) -> Dict[str, Any]:
    """Get usage statistics for a key."""
    try:
        return mgr.get_usage_stats(key_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
