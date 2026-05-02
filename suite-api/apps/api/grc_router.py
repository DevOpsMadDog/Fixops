"""GRC (Governance, Risk & Compliance) API Router — ALDECI.

Endpoints (all under /api/v1/grc):

  Frameworks:
    GET  /frameworks          — list frameworks for org
    POST /frameworks          — add a framework

  Controls:
    GET  /controls            — list controls (filter: framework_id, status)
    POST /controls            — add a control
    PATCH /controls/{id}/status — update control status

  Risks:
    GET  /risks               — list risks (filter: status, category)
    POST /risks               — add a risk
    PATCH /risks/{id}         — update a risk

  Assessments:
    GET  /assessments         — list assessments
    POST /assessments         — create an assessment

  Stats:
    GET  /stats               — aggregated GRC statistics

Auth: Depends(_verify_api_key) injected at app.include_router() level.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.grc_engine import GRCEngine
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/grc", tags=["grc"])

# Module-level singleton
_engine = None  # lazy-initialised on first request


def _get_engine() -> GRCEngine:
    global _engine
    if _engine is None:
        _engine = GRCEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class FrameworkCreate(BaseModel):
    name: str = Field(..., description="Framework name, e.g. SOC2, ISO27001")
    version: str = Field("1.0", description="Framework version")
    total_controls: int = Field(0, ge=0)
    implemented_controls: int = Field(0, ge=0)
    compliance_score: float = Field(0.0, ge=0.0, le=100.0)
    last_assessed: Optional[str] = None


class ControlCreate(BaseModel):
    framework_id: str
    control_ref: str = Field("", description="e.g. CC6.1, A.9.1.1")
    title: str = ""
    description: str = ""
    category: str = ""
    status: str = Field("not_implemented", description="implemented|partial|not_implemented|not_applicable")
    evidence_count: int = Field(0, ge=0)
    owner: str = ""
    due_date: Optional[str] = None


class ControlStatusUpdate(BaseModel):
    status: str = Field(..., description="implemented|partial|not_implemented|not_applicable")
    evidence_note: Optional[str] = None


class RiskCreate(BaseModel):
    title: str
    category: str = Field("operational", description="strategic|operational|compliance|financial|reputational")
    likelihood: int = Field(3, ge=1, le=5)
    impact: int = Field(3, ge=1, le=5)
    treatment: str = Field("mitigate", description="accept|mitigate|transfer|avoid")
    owner: str = ""
    status: str = Field("open", description="open|mitigated|accepted|closed")
    notes: str = ""


class RiskUpdate(BaseModel):
    title: Optional[str] = None
    category: Optional[str] = None
    likelihood: Optional[int] = Field(None, ge=1, le=5)
    impact: Optional[int] = Field(None, ge=1, le=5)
    treatment: Optional[str] = None
    owner: Optional[str] = None
    status: Optional[str] = None
    notes: Optional[str] = None


class AssessmentCreate(BaseModel):
    framework_id: str
    assessor: str = ""
    assessment_date: Optional[str] = None
    scope: str = ""
    overall_score: float = Field(0.0, ge=0.0, le=100.0)
    findings_count: int = Field(0, ge=0)
    status: str = Field("draft", description="draft|in_progress|completed|approved")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DEFAULT_ORG = "default"


def _org(org_id: Optional[str]) -> str:
    return org_id or _DEFAULT_ORG


# ---------------------------------------------------------------------------
# Framework endpoints
# ---------------------------------------------------------------------------


@router.get("/frameworks", response_model=List[Dict[str, Any]])
async def list_frameworks(org_id: Optional[str] = Query(None)) -> List[Dict[str, Any]]:
    """List all GRC frameworks for an organisation."""
    return _get_engine().list_frameworks(_org(org_id))


@router.post("/frameworks", response_model=Dict[str, Any], status_code=201)
async def add_framework(
    payload: FrameworkCreate,
    org_id: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """Register a new compliance framework."""
    return _get_engine().add_framework(_org(org_id), payload.model_dump())


# ---------------------------------------------------------------------------
# Control endpoints
# ---------------------------------------------------------------------------


@router.get("/controls", response_model=List[Dict[str, Any]])
async def list_controls(
    org_id: Optional[str] = Query(None),
    framework_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """List controls, optionally filtered by framework and/or status."""
    return _get_engine().list_controls(_org(org_id), framework_id=framework_id, status=status)


@router.post("/controls", response_model=Dict[str, Any], status_code=201)
async def add_control(
    payload: ControlCreate,
    org_id: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """Add a control to a framework."""
    data = payload.model_dump()
    framework_id = data.pop("framework_id")
    return _get_engine().add_control(_org(org_id), framework_id, data)


@router.patch("/controls/{control_id}/status", response_model=Dict[str, Any])
async def update_control_status(
    control_id: str,
    payload: ControlStatusUpdate,
    org_id: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """Update a control's implementation status."""
    ok = _get_engine().update_control_status(
        _org(org_id),
        control_id,
        payload.status,
        evidence_note=payload.evidence_note,
    )
    if not ok:
        raise HTTPException(status_code=404, detail=f"Control {control_id} not found")
    return {"control_id": control_id, "status": payload.status, "updated": True}


# ---------------------------------------------------------------------------
# Risk endpoints
# ---------------------------------------------------------------------------


@router.get("/risks", response_model=List[Dict[str, Any]])
async def list_risks(
    org_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """List risks, optionally filtered by status and/or category."""
    return _get_engine().list_risks(_org(org_id), status=status, category=category)


@router.post("/risks", response_model=Dict[str, Any], status_code=201)
async def add_risk(
    payload: RiskCreate,
    org_id: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """Register a new risk in the risk register."""
    return _get_engine().add_risk(_org(org_id), payload.model_dump())


@router.patch("/risks/{risk_id}", response_model=Dict[str, Any])
async def update_risk(
    risk_id: str,
    payload: RiskUpdate,
    org_id: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """Partially update a risk record."""
    data = {k: v for k, v in payload.model_dump().items() if v is not None}
    ok = _get_engine().update_risk(_org(org_id), risk_id, data)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Risk {risk_id} not found")
    return {"risk_id": risk_id, "updated": True}


# ---------------------------------------------------------------------------
# Assessment endpoints
# ---------------------------------------------------------------------------


@router.get("/assessments", response_model=List[Dict[str, Any]])
async def list_assessments(
    org_id: Optional[str] = Query(None),
    framework_id: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """List GRC assessments for an org."""
    return _get_engine().list_assessments(_org(org_id), framework_id=framework_id)


@router.post("/assessments", response_model=Dict[str, Any], status_code=201)
async def create_assessment(
    payload: AssessmentCreate,
    org_id: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """Create a new GRC assessment."""
    return _get_engine().create_assessment(_org(org_id), payload.model_dump())


# ---------------------------------------------------------------------------
# Stats endpoint
# ---------------------------------------------------------------------------


@router.get("/stats", response_model=Dict[str, Any])
async def get_grc_stats(org_id: Optional[str] = Query(None)) -> Dict[str, Any]:
    """Return aggregated GRC statistics for an org."""
    return _get_engine().get_grc_stats(_org(org_id))
