"""
FixOps Exposure Case REST API — Step 4 of the ALdeci Brain Data Flow.

Collapses noisy findings into actionable Exposure Cases with full lifecycle
management: OPEN → TRIAGING → FIXING → RESOLVED → CLOSED.

Endpoints:
  POST   /api/v1/cases                — create case
  GET    /api/v1/cases                — list/filter cases
  GET    /api/v1/cases/{case_id}      — get single case
  PATCH  /api/v1/cases/{case_id}      — update fields
  POST   /api/v1/cases/{case_id}/transition — transition lifecycle state
  POST   /api/v1/cases/{case_id}/clusters   — add clusters
  GET    /api/v1/cases/stats/summary  — aggregated statistics
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from core.exposure_case import (
    VALID_TRANSITIONS,
    CasePriority,
    CaseStatus,
    ExposureCase,
    get_case_manager,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/cases", tags=["exposure-cases"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------
class CreateCaseRequest(BaseModel):
    title: str
    description: str = ""
    org_id: str = ""
    priority: str = Field("medium", description="critical|high|medium|low|info")
    root_cve: Optional[str] = None
    root_cwe: Optional[str] = None
    root_component: Optional[str] = None
    affected_assets: List[str] = []
    cluster_ids: List[str] = []
    finding_count: int = 0
    risk_score: float = 0.0
    epss_score: Optional[float] = None
    in_kev: bool = False
    blast_radius: int = 0
    assigned_to: Optional[str] = None
    assigned_team: Optional[str] = None
    sla_due: Optional[str] = None
    tags: List[str] = []
    metadata: Dict[str, Any] = {}


class UpdateCaseRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    priority: Optional[str] = None
    assigned_to: Optional[str] = None
    assigned_team: Optional[str] = None
    sla_due: Optional[str] = None
    remediation_plan: Optional[str] = None
    playbook_id: Optional[str] = None
    autofix_pr_url: Optional[str] = None
    risk_score: Optional[float] = None
    tags: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None


class TransitionRequest(BaseModel):
    new_status: str = Field(..., description="Target lifecycle state")
    actor: str = Field("system", description="Who initiated the transition")


class AddClustersRequest(BaseModel):
    cluster_ids: List[str]
    finding_count_delta: int = 0


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.get("/stats/summary")
async def case_stats(org_id: Optional[str] = Query(None)):
    """Get aggregated exposure case statistics."""
    mgr = get_case_manager()
    return mgr.stats(org_id=org_id)


@router.post("")
async def create_case(req: CreateCaseRequest):
    """Create a new Exposure Case."""
    mgr = get_case_manager()
    case = ExposureCase(
        case_id="",
        title=req.title,
        description=req.description,
        org_id=req.org_id,
        priority=CasePriority(req.priority),
        root_cve=req.root_cve,
        root_cwe=req.root_cwe,
        root_component=req.root_component,
        affected_assets=req.affected_assets,
        cluster_ids=req.cluster_ids,
        finding_count=req.finding_count,
        risk_score=req.risk_score,
        epss_score=req.epss_score,
        in_kev=req.in_kev,
        blast_radius=req.blast_radius,
        assigned_to=req.assigned_to,
        assigned_team=req.assigned_team,
        sla_due=req.sla_due,
        tags=req.tags,
        metadata=req.metadata,
    )
    created = mgr.create_case(case)
    return created.to_dict()


@router.get("")
async def list_cases(
    org_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    priority: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """List Exposure Cases with optional filtering."""
    mgr = get_case_manager()
    return mgr.list_cases(
        org_id=org_id, status=status, priority=priority, limit=limit, offset=offset
    )


@router.get("/{case_id}")
async def get_case(case_id: str):
    """Get a single Exposure Case by ID."""
    mgr = get_case_manager()
    case = mgr.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    return case.to_dict()


@router.patch("/{case_id}")
async def update_case(case_id: str, req: UpdateCaseRequest):
    """Update Exposure Case fields (not lifecycle state)."""
    mgr = get_case_manager()
    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    try:
        updated = mgr.update_case(case_id, updates)
        return updated.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/{case_id}/transition")
async def transition_case(case_id: str, req: TransitionRequest):
    """Transition an Exposure Case to a new lifecycle state."""
    mgr = get_case_manager()
    try:
        new_status = CaseStatus(req.new_status)
    except ValueError:
        valid = [s.value for s in CaseStatus]
        raise HTTPException(status_code=400, detail=f"Invalid status. Valid: {valid}")
    try:
        case = mgr.transition(case_id, new_status, actor=req.actor)
        return case.to_dict()
    except ValueError as e:
        raise HTTPException(
            status_code=400 if "Invalid transition" in str(e) else 404, detail=str(e)
        )


@router.post("/{case_id}/clusters")
async def add_clusters(case_id: str, req: AddClustersRequest):
    """Add deduplication clusters to an existing Exposure Case."""
    mgr = get_case_manager()
    try:
        case = mgr.add_clusters(case_id, req.cluster_ids, req.finding_count_delta)
        return case.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/{case_id}/transitions")
async def get_valid_transitions(case_id: str):
    """Get valid transitions for the current state of a case."""
    mgr = get_case_manager()
    case = mgr.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    allowed = VALID_TRANSITIONS.get(case.status, set())
    return {
        "case_id": case_id,
        "current_status": case.status.value,
        "valid_transitions": [s.value for s in allowed],
    }
