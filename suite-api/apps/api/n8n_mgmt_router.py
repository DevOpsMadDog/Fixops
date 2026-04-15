"""n8n workflow management router.

Endpoints:
    POST   /api/v1/n8n/provision          -- Create + activate a security workflow
    GET    /api/v1/n8n/workflows          -- List all workflows in n8n
    GET    /api/v1/n8n/executions         -- Recent executions
    DELETE /api/v1/n8n/workflows/{id}     -- Delete a workflow
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/n8n", tags=["n8n"])


# ---------------------------------------------------------------------------
# Lazy import helper — avoids circular imports
# ---------------------------------------------------------------------------

def _client():
    from connectors.n8n_connector import N8nAPIClient
    return N8nAPIClient()


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class ProvisionRequest(BaseModel):
    event_type: str = Field(..., min_length=1, max_length=64, description="Security event type")
    integrations: List[str] = Field(
        default_factory=list,
        description='Output integrations, e.g. ["slack", "jira", "pagerduty"]',
    )


class ProvisionResponse(BaseModel):
    workflow_id: str
    webhook_url: str
    active: bool


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/provision", response_model=Dict[str, Any], summary="Provision a security workflow")
def provision_workflow(body: ProvisionRequest):
    """Create and activate an n8n workflow for the given event type and integrations."""
    result = _client().provision_security_workflow(
        event_type=body.event_type,
        integrations=body.integrations,
    )
    if "error" in result:
        raise HTTPException(status_code=502, detail=result)
    return result


@router.get("/workflows", response_model=List[Any], summary="List n8n workflows")
def list_workflows():
    """Return all workflows registered in n8n."""
    result = _client().list_workflows()
    if isinstance(result, dict) and "error" in result:
        raise HTTPException(status_code=502, detail=result)
    return result


@router.get("/executions", response_model=List[Any], summary="List recent executions")
def list_executions(workflow_id: Optional[str] = None):
    """Return recent workflow executions, optionally filtered by workflow ID."""
    result = _client().list_executions(workflow_id=workflow_id)
    if isinstance(result, dict) and "error" in result:
        raise HTTPException(status_code=502, detail=result)
    return result


@router.delete("/workflows/{workflow_id}", summary="Delete a workflow")
def delete_workflow(workflow_id: str):
    """Delete a workflow from n8n by ID."""
    client = _client()
    success = client.delete_workflow(workflow_id)
    if not success:
        raise HTTPException(status_code=502, detail={"error": "Delete failed or workflow not found"})
    return {"deleted": True, "workflow_id": workflow_id}
