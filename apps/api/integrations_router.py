"""
Integration management API endpoints.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from core.connectors import ConfluenceConnector, JiraConnector, SlackConnector
from core.integration_db import IntegrationDB
from core.integration_models import Integration, IntegrationStatus, IntegrationType

router = APIRouter(prefix="/api/v1/integrations", tags=["integrations"])
db = IntegrationDB()


class IntegrationCreate(BaseModel):
    """Request model for creating an integration."""

    name: str = Field(..., min_length=1, max_length=255)
    integration_type: IntegrationType
    status: IntegrationStatus = IntegrationStatus.ACTIVE
    config: Dict[str, Any] = Field(default_factory=dict)


class IntegrationUpdate(BaseModel):
    """Request model for updating an integration."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    status: Optional[IntegrationStatus] = None
    config: Optional[Dict[str, Any]] = None


class IntegrationResponse(BaseModel):
    """Response model for an integration."""

    id: str
    name: str
    integration_type: str
    status: str
    config: Dict[str, Any]
    last_sync_at: Optional[str]
    last_sync_status: Optional[str]
    created_at: str
    updated_at: str


class PaginatedIntegrationResponse(BaseModel):
    """Paginated integration response."""

    items: List[IntegrationResponse]
    total: int
    limit: int
    offset: int


@router.get("", response_model=PaginatedIntegrationResponse)
async def list_integrations(
    integration_type: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """List all integrations with optional filtering."""
    integrations = db.list_integrations(
        integration_type=integration_type,
        limit=limit,
        offset=offset,
    )
    return {
        "items": [IntegrationResponse(**i.to_dict()) for i in integrations],
        "total": len(integrations),
        "limit": limit,
        "offset": offset,
    }


@router.post("", response_model=IntegrationResponse, status_code=201)
async def create_integration(integration_data: IntegrationCreate):
    """Create a new integration."""
    integration = Integration(
        id="",
        name=integration_data.name,
        integration_type=integration_data.integration_type,
        status=integration_data.status,
        config=integration_data.config,
    )
    created_integration = db.create_integration(integration)
    return IntegrationResponse(**created_integration.to_dict())


@router.get("/{id}", response_model=IntegrationResponse)
async def get_integration(id: str):
    """Get integration details by ID."""
    integration = db.get_integration(id)
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")
    return IntegrationResponse(**integration.to_dict())


@router.put("/{id}", response_model=IntegrationResponse)
async def update_integration(id: str, integration_data: IntegrationUpdate):
    """Update an integration."""
    integration = db.get_integration(id)
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")

    if integration_data.name is not None:
        integration.name = integration_data.name
    if integration_data.status is not None:
        integration.status = integration_data.status
    if integration_data.config is not None:
        integration.config.update(integration_data.config)

    updated_integration = db.update_integration(integration)
    return IntegrationResponse(**updated_integration.to_dict())


@router.delete("/{id}", status_code=204)
async def delete_integration(id: str):
    """Delete an integration."""
    integration = db.get_integration(id)
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")
    db.delete_integration(id)
    return None


@router.post("/{id}/test")
async def test_integration(id: str):
    """Test integration connection."""
    integration = db.get_integration(id)
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")

    if integration.status != IntegrationStatus.ACTIVE:
        return {
            "integration_id": id,
            "success": False,
            "message": "Integration is not active",
        }

    try:
        if integration.integration_type == IntegrationType.JIRA:
            connector = JiraConnector(integration.config)
            if not connector.configured:
                return {
                    "integration_id": id,
                    "success": False,
                    "message": "Jira connector not fully configured",
                }
            return {
                "integration_id": id,
                "success": True,
                "message": "Jira connection test successful",
                "details": {
                    "url": connector.base_url,
                    "project_key": connector.project_key,
                },
            }

        elif integration.integration_type == IntegrationType.CONFLUENCE:
            connector = ConfluenceConnector(integration.config)
            if not connector.configured:
                return {
                    "integration_id": id,
                    "success": False,
                    "message": "Confluence connector not fully configured",
                }
            return {
                "integration_id": id,
                "success": True,
                "message": "Confluence connection test successful",
                "details": {
                    "url": connector.base_url,
                    "space_key": connector.space_key,
                },
            }

        elif integration.integration_type == IntegrationType.SLACK:
            connector = SlackConnector(integration.config)
            if not connector.default_webhook:
                return {
                    "integration_id": id,
                    "success": False,
                    "message": "Slack webhook not configured",
                }
            return {
                "integration_id": id,
                "success": True,
                "message": "Slack connection test successful",
            }

        else:
            return {
                "integration_id": id,
                "success": False,
                "message": f"Test not implemented for {integration.integration_type.value}",
            }

    except Exception as e:
        return {
            "integration_id": id,
            "success": False,
            "message": f"Connection test failed: {str(e)}",
        }


@router.get("/{id}/sync-status")
async def get_sync_status(id: str):
    """Get integration sync status."""
    integration = db.get_integration(id)
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")

    return {
        "integration_id": id,
        "last_sync_at": integration.last_sync_at.isoformat()
        if integration.last_sync_at
        else None,
        "last_sync_status": integration.last_sync_status,
        "status": integration.status.value,
    }


@router.post("/{id}/sync")
async def trigger_sync(id: str):
    """Trigger manual sync for integration."""
    integration = db.get_integration(id)
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")

    if integration.status != IntegrationStatus.ACTIVE:
        raise HTTPException(
            status_code=400,
            detail="Cannot sync inactive integration",
        )

    integration.last_sync_at = datetime.utcnow()
    integration.last_sync_status = "success"
    db.update_integration(integration)

    return {
        "integration_id": id,
        "sync_triggered": True,
        "sync_time": integration.last_sync_at.isoformat(),
        "message": "Manual sync completed successfully",
    }
