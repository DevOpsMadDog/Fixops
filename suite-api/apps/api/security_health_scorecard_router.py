"""Security Health Scorecard Router — ALDECI.

Unified security health scorecard aggregating scores across all security
domains. Provides weighted composite scoring, snapshots, grade trends,
and target tracking.

Prefix: /api/v1/health-scorecard
Auth: api_key_auth dependency
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/health-scorecard",
    tags=["Security Health Scorecard"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_health_scorecard_engine import SecurityHealthScorecardEngine
        _engine = SecurityHealthScorecardEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class UpsertDomainRequest(BaseModel):
    domain_name: str = Field(..., description="Domain identifier e.g. 'Vulnerability Management'")
    domain_category: str = Field(
        ...,
        description="vulnerability | compliance | identity | network | endpoint | cloud | data | physical",
    )
    weight: float = Field(..., ge=0.0, le=1.0, description="Domain weight (0-1), clamped automatically")
    score: float = Field(..., description="Current raw score")
    max_score: float = Field(..., description="Maximum possible score")


class SetTargetRequest(BaseModel):
    domain_name: str = Field(..., description="Domain name to set target for")
    target_score: float = Field(..., description="Target score to achieve")
    current_score: float = Field(..., description="Current score baseline")
    deadline: str = Field(..., description="Target deadline (YYYY-MM-DD)")
    owner: str = Field(default="", description="Owner responsible for achieving target")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/domains", dependencies=[Depends(api_key_auth)])
def upsert_domain(
    req: UpsertDomainRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Upsert a scorecard domain. Status auto-computed from score/max_score ratio."""
    try:
        return _get_engine().upsert_domain(
            org_id=org_id,
            domain_name=req.domain_name,
            domain_category=req.domain_category,
            weight=req.weight,
            score=req.score,
            max_score=req.max_score,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/snapshots", dependencies=[Depends(api_key_auth)])
def take_snapshot(
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Compute and persist a scorecard snapshot from current domain scores."""
    return _get_engine().take_snapshot(org_id)


@router.post("/targets", dependencies=[Depends(api_key_auth)])
def set_target(
    req: SetTargetRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Upsert a score target for a domain."""
    return _get_engine().set_target(
        org_id=org_id,
        domain_name=req.domain_name,
        target_score=req.target_score,
        current_score=req.current_score,
        deadline=req.deadline,
        owner=req.owner,
    )


@router.get("/current", dependencies=[Depends(api_key_auth)])
def get_current_scorecard(
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Return the latest snapshot plus all domains and targets."""
    return _get_engine().get_current_scorecard(org_id)


@router.get("/history", dependencies=[Depends(api_key_auth)])
def get_snapshot_history(
    org_id: str = Query(..., description="Organization ID"),
    days: int = Query(default=90, ge=1, le=730, description="Number of days to look back"),
) -> List[Dict[str, Any]]:
    """Return scorecard snapshots within the past N days."""
    return _get_engine().get_snapshot_history(org_id, days=days)


@router.get("/grade-trend", dependencies=[Depends(api_key_auth)])
def get_grade_trend(
    org_id: str = Query(..., description="Organization ID"),
) -> List[Dict[str, Any]]:
    """Return chronological grade trend (date, grade, overall_score) per snapshot."""
    return _get_engine().get_grade_trend(org_id)


@router.get("", dependencies=[Depends(api_key_auth)])
def get_root(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Root endpoint — returns current scorecard for dashboard health-checks."""
    return _get_engine().get_current_scorecard(org_id)


@router.get("/domains", dependencies=[Depends(api_key_auth)])
def get_domains(
    org_id: str = Query(..., description="Organization ID"),
    status: Optional[str] = Query(default=None, description="Filter by status: green | amber | red"),
) -> List[Dict[str, Any]]:
    """List scorecard domains, optionally filtered by status."""
    try:
        return _get_engine().get_domains(org_id, status=status)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
