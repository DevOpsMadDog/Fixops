"""
SSO/SAML authentication API endpoints.
"""
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from core.auth_db import AuthDB
from core.auth_models import AuthProvider, SSOConfig, SSOStatus

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
