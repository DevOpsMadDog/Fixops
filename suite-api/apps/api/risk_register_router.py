"""Risk Register API Router.

8 endpoints under /api/v1/risks covering full risk lifecycle management:
CRUD, control mapping, treatment plans, KRI tracking, heat map, and
board-level reporting.

Auth is applied centrally by app.py (Depends(_verify_api_key)).

Route ordering: ALL static-path routes are registered BEFORE /{risk_id}
parameterized routes so FastAPI does not swallow them as path parameters.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import structlog
from core.risk_register import (
    KRIRecord,
    Risk,
    RiskAppetite,
    RiskCategory,
    RiskControl,
    RiskStatus,
    RiskTreatmentPlan,
    TreatmentAction,
    get_risk_register,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/api/v1/risks", tags=["risk-register"])


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CreateRiskRequest(BaseModel):
    title: str = Field(..., description="Short descriptive title")
    description: str = Field("", description="Detailed description")
    category: RiskCategory = Field(..., description="Risk category")
    owner: str = Field("", description="Risk owner (name or email)")
    likelihood: int = Field(3, ge=1, le=5, description="Likelihood 1-5")
    impact: int = Field(3, ge=1, le=5, description="Impact 1-5")
    tags: List[str] = Field(default_factory=list)
    related_finding_ids: List[str] = Field(default_factory=list)
    org_id: str = Field("default")


class UpdateRiskRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    category: Optional[RiskCategory] = None
    owner: Optional[str] = None
    likelihood: Optional[int] = Field(None, ge=1, le=5)
    impact: Optional[int] = Field(None, ge=1, le=5)
    status: Optional[RiskStatus] = None
    tags: Optional[List[str]] = None
    related_finding_ids: Optional[List[str]] = None


class CreateControlRequest(BaseModel):
    name: str = Field(..., description="Control name")
    description: str = Field("", description="Control description")
    control_type: str = Field("preventive",
                               description="preventive | detective | corrective")
    effectiveness: float = Field(0.0, ge=0.0, le=5.0,
                                  description="Effectiveness 0-5 subtracted from inherent risk")
    owner: str = Field("")
    implemented: bool = Field(False)
    org_id: str = Field("default")


class CreateTreatmentRequest(BaseModel):
    risk_id: str = Field(..., description="ID of the risk being treated")
    action: TreatmentAction = Field(..., description="accept | mitigate | transfer | avoid")
    description: str = Field(..., description="Treatment description")
    owner: str = Field("")
    target_date: str = Field("", description="ISO date string for target completion")
    notes: str = Field("")


class UpdateTreatmentStatusRequest(BaseModel):
    status: str = Field(..., description="planned | in_progress | completed | overdue")
    completion_date: str = Field("", description="ISO date when completed")


class CreateKRIRequest(BaseModel):
    risk_id: str = Field(..., description="ID of the associated risk")
    name: str = Field(..., description="KRI name")
    description: str = Field("")
    unit: str = Field("", description="Measurement unit, e.g. 'count', '%'")
    current_value: float = Field(0.0, description="Current measured value")
    warning_threshold: float = Field(..., description="Warning level threshold")
    breach_threshold: float = Field(..., description="Breach level threshold")
    direction: str = Field("higher_is_worse",
                            description="higher_is_worse | lower_is_worse")
    org_id: str = Field("default")


class UpdateKRIValueRequest(BaseModel):
    current_value: float = Field(..., description="New measured value")


class SetAppetiteRequest(BaseModel):
    category: RiskCategory
    appetite_score: float = Field(..., ge=0.0, le=25.0,
                                   description="Maximum acceptable residual risk score")
    tolerance_score: float = Field(..., ge=0.0, le=25.0,
                                    description="Escalation threshold")
    description: str = Field("")
    updated_by: str = Field("")
    org_id: str = Field("default")


class MapControlRequest(BaseModel):
    ctrl_id: str = Field(..., description="Control ID to map to this risk")


# ===========================================================================
# STATIC ROUTES — registered first so they are not matched as /{risk_id}
# ===========================================================================

# ---------------------------------------------------------------------------
# Endpoint: Collection-level risk operations (no path param)
# ---------------------------------------------------------------------------

@router.post("", summary="Create a risk", response_model=Dict[str, Any])
async def create_risk(body: CreateRiskRequest) -> Dict[str, Any]:
    register = get_risk_register()
    risk = Risk(
        title=body.title,
        description=body.description,
        category=body.category,
        owner=body.owner,
        org_id=body.org_id,
        likelihood=body.likelihood,
        impact=body.impact,
        tags=body.tags,
        related_finding_ids=body.related_finding_ids,
    )
    created = register.create_risk(risk)
    return created.model_dump()


@router.get("", summary="List risks", response_model=List[Dict[str, Any]])
async def list_risks(
    org_id: str = Query("default"),
    category: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    min_score: Optional[float] = Query(None),
) -> List[Dict[str, Any]]:
    register = get_risk_register()
    risks = register.list_risks(org_id, category, status, min_score)
    return [r.model_dump() for r in risks]


# ---------------------------------------------------------------------------
# Endpoint 2 — Control operations (static prefix /controls)
# ---------------------------------------------------------------------------

@router.post("/controls", summary="Create a control", response_model=Dict[str, Any])
async def create_control(body: CreateControlRequest) -> Dict[str, Any]:
    register = get_risk_register()
    ctrl = RiskControl(
        name=body.name,
        description=body.description,
        control_type=body.control_type,
        effectiveness=body.effectiveness,
        owner=body.owner,
        implemented=body.implemented,
        org_id=body.org_id,
    )
    created = register.create_control(ctrl)
    return created.model_dump()


@router.get("/controls/list", summary="List controls", response_model=List[Dict[str, Any]])
async def list_controls(org_id: str = Query("default")) -> List[Dict[str, Any]]:
    register = get_risk_register()
    return [c.model_dump() for c in register.list_controls(org_id)]


# ---------------------------------------------------------------------------
# Endpoint 3 — Treatment plan collection operations (static prefix /treatments)
# ---------------------------------------------------------------------------

@router.post("/treatments", summary="Create a treatment plan",
             response_model=Dict[str, Any])
async def create_treatment(body: CreateTreatmentRequest) -> Dict[str, Any]:
    register = get_risk_register()
    plan = RiskTreatmentPlan(
        risk_id=body.risk_id,
        action=body.action,
        description=body.description,
        owner=body.owner,
        target_date=body.target_date,
        notes=body.notes,
    )
    created = register.create_treatment(plan)
    return created.model_dump()


@router.patch("/treatments/{plan_id}/status",
              summary="Update treatment plan status",
              response_model=Dict[str, Any])
async def update_treatment_status(
    plan_id: str, body: UpdateTreatmentStatusRequest
) -> Dict[str, Any]:
    register = get_risk_register()
    updated = register.update_treatment_status(
        plan_id, body.status, body.completion_date
    )
    if not updated:
        raise HTTPException(status_code=404,
                            detail=f"Treatment plan '{plan_id}' not found")
    return updated.model_dump()


# ---------------------------------------------------------------------------
# Endpoint 4 — KRI collection operations (static prefix /kris)
# ---------------------------------------------------------------------------

@router.post("/kris", summary="Create a KRI", response_model=Dict[str, Any])
async def create_kri(body: CreateKRIRequest) -> Dict[str, Any]:
    register = get_risk_register()
    kri = KRIRecord(
        risk_id=body.risk_id,
        name=body.name,
        description=body.description,
        unit=body.unit,
        current_value=body.current_value,
        warning_threshold=body.warning_threshold,
        breach_threshold=body.breach_threshold,
        direction=body.direction,
        org_id=body.org_id,
    )
    created = register.create_kri(kri)
    return created.model_dump()


@router.get("/kris/list", summary="List KRIs", response_model=List[Dict[str, Any]])
async def list_kris(
    org_id: str = Query("default"),
    risk_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    register = get_risk_register()
    return [k.model_dump() for k in register.list_kris(org_id, risk_id, status)]


@router.patch("/kris/{kri_id}/value", summary="Update KRI current value",
              response_model=Dict[str, Any])
async def update_kri_value(kri_id: str, body: UpdateKRIValueRequest) -> Dict[str, Any]:
    register = get_risk_register()
    updated = register.update_kri_value(kri_id, body.current_value)
    if not updated:
        raise HTTPException(status_code=404, detail=f"KRI '{kri_id}' not found")
    return updated.model_dump()


# ---------------------------------------------------------------------------
# Endpoint 5 — Risk appetite (static prefix /appetite)
# ---------------------------------------------------------------------------

@router.post("/appetite", summary="Set risk appetite for a category",
             response_model=Dict[str, Any])
async def set_appetite(body: SetAppetiteRequest) -> Dict[str, Any]:
    register = get_risk_register()
    appetite = RiskAppetite(
        org_id=body.org_id,
        category=body.category,
        appetite_score=body.appetite_score,
        tolerance_score=body.tolerance_score,
        description=body.description,
        updated_by=body.updated_by,
    )
    created = register.set_appetite(appetite)
    return created.model_dump()


@router.get("/appetite/list", summary="List risk appetites",
            response_model=List[Dict[str, Any]])
async def list_appetites(org_id: str = Query("default")) -> List[Dict[str, Any]]:
    register = get_risk_register()
    return [a.model_dump() for a in register.list_appetites(org_id)]


# ---------------------------------------------------------------------------
# Endpoint 6 — Heat map (static path /heatmap)
# ---------------------------------------------------------------------------

@router.get("/heatmap", summary="Get risk heat map data",
            response_model=List[Dict[str, Any]])
async def get_heat_map(org_id: str = Query("default")) -> List[Dict[str, Any]]:
    register = get_risk_register()
    cells = register.get_heat_map(org_id)
    return [c.model_dump() for c in cells]


# ---------------------------------------------------------------------------
# Endpoint 7 — Board report (static path /report/board)
# ---------------------------------------------------------------------------

@router.get("/report/board", summary="Board-level risk report",
            response_model=Dict[str, Any])
async def board_report(org_id: str = Query("default")) -> Dict[str, Any]:
    register = get_risk_register()
    report = register.get_board_report(org_id)
    return report.model_dump()


# ===========================================================================
# PARAMETERIZED ROUTES — registered last to avoid swallowing static paths
# ===========================================================================

# ---------------------------------------------------------------------------
# Endpoint 1 — Risk CRUD with /{risk_id}
# ---------------------------------------------------------------------------

@router.get("/{risk_id}", summary="Get a risk", response_model=Dict[str, Any])
async def get_risk(risk_id: str) -> Dict[str, Any]:
    register = get_risk_register()
    risk = register.get_risk(risk_id)
    if not risk:
        raise HTTPException(status_code=404, detail=f"Risk '{risk_id}' not found")
    return risk.model_dump()


@router.patch("/{risk_id}", summary="Update a risk", response_model=Dict[str, Any])
async def update_risk(risk_id: str, body: UpdateRiskRequest) -> Dict[str, Any]:
    register = get_risk_register()
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    updated = register.update_risk(risk_id, updates)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Risk '{risk_id}' not found")
    return updated.model_dump()


@router.delete("/{risk_id}", summary="Delete a risk")
async def delete_risk(risk_id: str) -> Dict[str, Any]:
    register = get_risk_register()
    ok = register.delete_risk(risk_id)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Risk '{risk_id}' not found")
    return {"deleted": True, "risk_id": risk_id}


@router.post("/{risk_id}/controls/map", summary="Map a control to a risk",
             response_model=Dict[str, Any])
async def map_control(risk_id: str, body: MapControlRequest) -> Dict[str, Any]:
    register = get_risk_register()
    updated = register.map_control_to_risk(risk_id, body.ctrl_id)
    if not updated:
        raise HTTPException(
            status_code=404,
            detail=f"Risk '{risk_id}' or control '{body.ctrl_id}' not found",
        )
    return updated.model_dump()


@router.delete("/{risk_id}/controls/{ctrl_id}", summary="Unmap a control from a risk",
               response_model=Dict[str, Any])
async def unmap_control(risk_id: str, ctrl_id: str) -> Dict[str, Any]:
    register = get_risk_register()
    updated = register.unmap_control_from_risk(risk_id, ctrl_id)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Risk '{risk_id}' not found")
    return updated.model_dump()


@router.get("/{risk_id}/treatments", summary="List treatment plans for a risk",
            response_model=List[Dict[str, Any]])
async def list_treatments(risk_id: str) -> List[Dict[str, Any]]:
    register = get_risk_register()
    return [p.model_dump() for p in register.list_treatments(risk_id)]
