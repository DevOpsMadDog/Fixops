"""Security Tool Inventory Router — ALDECI.

Security tool inventory management endpoints.

Prefix: /api/v1/tool-inventory
Auth: api_key_auth dependency

Routes:
  POST /api/v1/tool-inventory/tools                        register_tool
  GET  /api/v1/tool-inventory/tools                        list_tools
  GET  /api/v1/tool-inventory/tools/{tool_id}              get_tool
  PUT  /api/v1/tool-inventory/tools/{tool_id}/status       update_tool_status
  POST /api/v1/tool-inventory/integrations                 add_integration
  GET  /api/v1/tool-inventory/integrations                 list_integrations
  POST /api/v1/tool-inventory/assessments                  record_assessment
  GET  /api/v1/tool-inventory/assessments                  list_assessments
  GET  /api/v1/tool-inventory/stats                        get_inventory_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/tool-inventory",
    tags=["Security Tool Inventory"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_tool_inventory_engine import SecurityToolInventoryEngine
        _engine = SecurityToolInventoryEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class RegisterToolRequest(BaseModel):
    name: str = Field(..., description="Tool name")
    vendor: Optional[str] = Field(default="", description="Vendor name")
    version: Optional[str] = Field(default="", description="Tool version")
    tool_category: str = Field(
        ...,
        description=(
            "siem | edr | dlp | firewall | waf | sca | dast | sast | "
            "iam | pam | soar | threat_intel | vulnerability_scanner | "
            "network_monitor | other"
        ),
    )
    license_type: str = Field(
        ..., description="perpetual | subscription | open_source | trial"
    )
    license_expiry: Optional[str] = Field(default=None, description="ISO expiry")
    status: Optional[str] = Field(
        default="active",
        description="active | inactive | deprecated | evaluating",
    )
    deployment_type: str = Field(
        ..., description="cloud | on_prem | hybrid | saas"
    )
    owner_team: Optional[str] = Field(default="", description="Owning team")
    cost_annual: Optional[float] = Field(default=0.0, description="Annual cost")


class UpdateToolStatusRequest(BaseModel):
    status: str = Field(
        ..., description="active | inactive | deprecated | evaluating"
    )


class AddIntegrationRequest(BaseModel):
    tool_id: str = Field(..., description="Source tool ID")
    integrated_with: str = Field(..., description="Target tool or system name")
    integration_type: str = Field(
        ..., description="api | syslog | webhook | agent | manual"
    )
    status: Optional[str] = Field(
        default="pending",
        description="active | inactive | broken | pending",
    )


class RecordAssessmentRequest(BaseModel):
    tool_id: str = Field(..., description="Tool being assessed")
    assessed_by: Optional[str] = Field(default="", description="Assessor")
    coverage_score: Optional[float] = Field(default=0.0, description="0-100")
    effectiveness_score: Optional[float] = Field(default=0.0, description="0-100")
    utilization_pct: Optional[float] = Field(default=0.0, description="0-100")
    findings: Optional[str] = Field(default="", description="Assessment findings")
    assessed_at: Optional[str] = Field(default=None, description="ISO assessment timestamp")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/tools", dependencies=[Depends(api_key_auth)], status_code=201)
def register_tool(
    body: RegisterToolRequest,
    org_id: str = Query(default="default"),
):
    """Register a new security tool in the inventory."""
    try:
        return _get_engine().register_tool(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error registering tool")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/tools", dependencies=[Depends(api_key_auth)])
def list_tools(
    org_id: str = Query(default="default"),
    tool_category: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
):
    """List security tools, optionally filtered by category or status."""
    return _get_engine().list_tools(org_id, tool_category=tool_category, status=status)


@router.get("/tools/{tool_id}", dependencies=[Depends(api_key_auth)])
def get_tool(
    tool_id: str,
    org_id: str = Query(default="default"),
):
    """Get a specific tool by ID."""
    result = _get_engine().get_tool(org_id, tool_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Tool not found")
    return result


@router.put("/tools/{tool_id}/status", dependencies=[Depends(api_key_auth)])
def update_tool_status(
    tool_id: str,
    body: UpdateToolStatusRequest,
    org_id: str = Query(default="default"),
):
    """Update a tool's status."""
    try:
        return _get_engine().update_tool_status(org_id, tool_id, body.status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error updating tool status")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/integrations", dependencies=[Depends(api_key_auth)], status_code=201)
def add_integration(
    body: AddIntegrationRequest,
    org_id: str = Query(default="default"),
):
    """Add an integration between security tools."""
    try:
        return _get_engine().add_integration(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error adding integration")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/integrations", dependencies=[Depends(api_key_auth)])
def list_integrations(
    org_id: str = Query(default="default"),
    tool_id: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
):
    """List integrations, optionally filtered by tool_id or status."""
    return _get_engine().list_integrations(org_id, tool_id=tool_id, status=status)


@router.post("/assessments", dependencies=[Depends(api_key_auth)], status_code=201)
def record_assessment(
    body: RecordAssessmentRequest,
    org_id: str = Query(default="default"),
):
    """Record a security tool assessment."""
    try:
        return _get_engine().record_assessment(org_id, body.model_dump())
    except Exception as exc:
        _logger.exception("Error recording assessment")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/assessments", dependencies=[Depends(api_key_auth)])
def list_assessments(
    org_id: str = Query(default="default"),
    tool_id: Optional[str] = Query(default=None),
):
    """List assessments, optionally filtered by tool_id."""
    return _get_engine().list_assessments(org_id, tool_id=tool_id)


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_inventory_stats(
    org_id: str = Query(default="default"),
):
    """Return aggregated security tool inventory statistics."""
    return _get_engine().get_inventory_stats(org_id)
