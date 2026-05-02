"""Cloud Cost Optimization Router — ALDECI.

Endpoints for the Cloud Cost Optimization engine.

Prefix: /api/v1/cost-optimization
Auth:   api_key_auth dependency

Routes:
  POST   /api/v1/cost-optimization/tools                         register_tool
  GET    /api/v1/cost-optimization/tools                         list_tools
  GET    /api/v1/cost-optimization/tools/{id}/roi                get_tool_roi
  PATCH  /api/v1/cost-optimization/tools/{id}/utilization        update_utilization
  POST   /api/v1/cost-optimization/tools/{id}/optimizations      add_optimization
  POST   /api/v1/cost-optimization/optimizations/{id}/implement  implement_optimization
  POST   /api/v1/cost-optimization/tools/{id}/roi-assessment     add_roi_assessment
  GET    /api/v1/cost-optimization/underutilized                 get_underutilized_tools
  GET    /api/v1/cost-optimization/portfolio                     get_portfolio_summary
  GET    /api/v1/cost-optimization/cost-per-risk                 get_cost_per_risk
"""

from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/cost-optimization",
    tags=["Cloud Cost Optimization"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.cloud_cost_optimization_engine import CloudCostOptimizationEngine
        _engine = CloudCostOptimizationEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ToolCreate(BaseModel):
    tool_name: str
    tool_category: str = "detection"
    vendor: str = ""
    cloud_provider: str = "multi-cloud"
    monthly_cost: float = 0.0
    licenses: int = 0


class UtilizationUpdate(BaseModel):
    utilization_pct: float
    risk_coverage: Optional[List[str]] = None


class OptimizationCreate(BaseModel):
    optimization_type: str
    description: str = ""
    estimated_savings: float = 0.0


class ImplementOptimization(BaseModel):
    actual_savings: float


class ROIAssessmentCreate(BaseModel):
    assessment_period: str
    incidents_prevented: int = 0
    avg_incident_cost: float = 0.0
    risk_reduction_pct: float = 0.0


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/")
def list_cost_optimization(org_id: str = Query("default")):
    """Get cloud cost optimization portfolio summary for the org."""
    return _get_engine().get_portfolio_summary(org_id=org_id)


@router.post("/tools", status_code=201)
def register_tool(body: ToolCreate, org_id: str = Query(default="default")):
    """Register a new security tool for cost tracking."""
    try:
        return _get_engine().register_tool(
            org_id=org_id,
            tool_name=body.tool_name,
            tool_category=body.tool_category,
            vendor=body.vendor,
            cloud_provider=body.cloud_provider,
            monthly_cost=body.monthly_cost,
            licenses=body.licenses,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/tools")
def list_tools(org_id: str = Query(default="default")):
    """List all security tools for an org."""
    return _get_engine().list_tools(org_id=org_id)


@router.get("/tools/{tool_id}/roi")
def get_tool_roi(tool_id: str, org_id: str = Query(default="default")):
    """Return tool ROI details with assessments and optimizations."""
    try:
        return _get_engine().get_tool_roi(tool_id=tool_id, org_id=org_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.patch("/tools/{tool_id}/utilization")
def update_utilization(tool_id: str, body: UtilizationUpdate, org_id: str = Query(default="default")):
    """Update tool utilization percentage and risk coverage."""
    try:
        return _get_engine().update_utilization(
            tool_id=tool_id,
            org_id=org_id,
            utilization_pct=body.utilization_pct,
            risk_coverage=body.risk_coverage,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/tools/{tool_id}/optimizations", status_code=201)
def add_optimization(tool_id: str, body: OptimizationCreate, org_id: str = Query(default="default")):
    """Identify a cost optimization opportunity for a tool."""
    try:
        return _get_engine().add_optimization(
            tool_id=tool_id,
            org_id=org_id,
            optimization_type=body.optimization_type,
            description=body.description,
            estimated_savings=body.estimated_savings,
        )
    except (ValueError, KeyError) as exc:
        status = 400 if isinstance(exc, ValueError) else 404
        raise HTTPException(status_code=status, detail=str(exc)) from exc


@router.post("/optimizations/{optimization_id}/implement")
def implement_optimization(
    optimization_id: str, body: ImplementOptimization, org_id: str = Query(default="default")
):
    """Mark an optimization as implemented with actual savings."""
    try:
        return _get_engine().implement_optimization(
            optimization_id=optimization_id,
            org_id=org_id,
            actual_savings=body.actual_savings,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/tools/{tool_id}/roi-assessment", status_code=201)
def add_roi_assessment(tool_id: str, body: ROIAssessmentCreate, org_id: str = Query(default="default")):
    """Add a ROI assessment for a security tool."""
    try:
        return _get_engine().add_roi_assessment(
            tool_id=tool_id,
            org_id=org_id,
            assessment_period=body.assessment_period,
            incidents_prevented=body.incidents_prevented,
            avg_incident_cost=body.avg_incident_cost,
            risk_reduction_pct=body.risk_reduction_pct,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/underutilized")
def get_underutilized_tools(
     org_id: str = Query(default="default"),
    max_utilization: float = Query(30.0),
):
    """Return active tools with low utilization."""
    return _get_engine().get_underutilized_tools(
        org_id=org_id, max_utilization=max_utilization
    )


@router.get("/portfolio")
def get_portfolio_summary(org_id: str = Query(default="default")):
    """Return aggregate portfolio cost summary."""
    return _get_engine().get_portfolio_summary(org_id=org_id)


@router.get("/cost-per-risk")
def get_cost_per_risk(org_id: str = Query(default="default")):
    """Return cost per risk reduction percentage, ordered ASC."""
    return _get_engine().get_cost_per_risk(org_id=org_id)
