"""
Vulnerability Prioritization Router — ALDECI.

Endpoints:
  POST /api/v1/vuln-prioritization/score?org_id=default
  POST /api/v1/vuln-prioritization/batch-score?org_id=default
  GET  /api/v1/vuln-prioritization/scored?org_id=default
  GET  /api/v1/vuln-prioritization/scored/{vuln_id}?org_id=default
  POST /api/v1/vuln-prioritization/scored/{vuln_id}/sla?org_id=default
  GET  /api/v1/vuln-prioritization/sla?org_id=default
  GET  /api/v1/vuln-prioritization/runs?org_id=default
  GET  /api/v1/vuln-prioritization/stats?org_id=default
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "vuln_prioritization_router: auth_deps not available"
    )
    _AUTH_DEP = []

from core.vuln_prioritization_engine import VulnerabilityPrioritizationEngine

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/vuln-prioritization",
    tags=["vuln-prioritization"],
    dependencies=_AUTH_DEP,
)

# Lazy singleton per org_id
_engines: Dict[str, VulnerabilityPrioritizationEngine] = {}


def _get_engine(org_id: str) -> VulnerabilityPrioritizationEngine:
    if org_id not in _engines:
        _engines[org_id] = VulnerabilityPrioritizationEngine(org_id=org_id)
    return _engines[org_id]


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class VulnScoreCreate(BaseModel):
    cve_id: str
    asset_id: str
    asset_criticality: str = "medium"
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    epss_score: float = Field(default=0.0, ge=0.0, le=1.0)
    kev_listed: bool = False
    exploitability: str = "theoretical"
    exposure: str = "internal"


class BatchScoreRequest(BaseModel):
    vulnerabilities: List[Dict[str, Any]]


class SLAAssignRequest(BaseModel):
    assigned_team: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/score", status_code=201)
async def score_vulnerability(
    payload: VulnScoreCreate,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Score a single vulnerability and store the result."""
    engine = _get_engine(org_id)
    try:
        return engine.score_vulnerability(org_id, payload.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/batch-score", status_code=201)
async def batch_score(
    payload: BatchScoreRequest,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Score multiple vulnerabilities in one call and create a run record."""
    engine = _get_engine(org_id)
    return engine.batch_score(org_id, payload.vulnerabilities)


@router.get("/scored")
async def list_scored(
    org_id: str = Query(default="default"),
    priority_tier: Optional[str] = Query(default=None),
    kev_only: bool = Query(default=False),
    limit: int = Query(default=50, ge=1, le=500),
) -> List[Dict[str, Any]]:
    """List scored vulnerabilities, optionally filtered by tier or KEV flag."""
    engine = _get_engine(org_id)
    return engine.list_scored(org_id, priority_tier=priority_tier, kev_only=kev_only, limit=limit)


@router.get("/scored/{vuln_id}")
async def get_scored(
    vuln_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Get a single scored vulnerability by ID."""
    engine = _get_engine(org_id)
    result = engine.get_score(org_id, vuln_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Vulnerability '{vuln_id}' not found")
    return result


@router.post("/scored/{vuln_id}/sla", status_code=201)
async def assign_sla(
    vuln_id: str,
    payload: SLAAssignRequest,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Assign SLA tracking to a scored vulnerability."""
    engine = _get_engine(org_id)
    try:
        return engine.assign_sla(org_id, vuln_id, payload.assigned_team)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/sla")
async def list_sla_assignments(
    org_id: str = Query(default="default"),
    status: Optional[str] = Query(default=None),
    team: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List SLA assignments, optionally filtered by status or team."""
    engine = _get_engine(org_id)
    return engine.list_sla_assignments(org_id, status=status, team=team)


@router.get("/runs")
async def list_runs(
    org_id: str = Query(default="default"),
) -> List[Dict[str, Any]]:
    """List all prioritization batch runs for an org."""
    engine = _get_engine(org_id)
    return engine.list_runs(org_id)


@router.get("/stats")
async def get_stats(
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Get high-level prioritization stats: totals, by_tier, KEV count, SLA breaches."""
    engine = _get_engine(org_id)
    return engine.get_stats(org_id)


__all__ = ["router"]
