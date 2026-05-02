"""Vulnerability Trend Analyzer REST API — ALDECI.

Endpoints:
  POST   /api/v1/vuln-trends/snapshots              -- Record daily snapshot
  GET    /api/v1/vuln-trends/snapshots               -- List snapshots
  GET    /api/v1/vuln-trends/analysis                -- Trend analysis (last 2 snapshots)
  POST   /api/v1/vuln-trends/sla                     -- Track vuln SLA
  GET    /api/v1/vuln-trends/sla/breaches            -- List breached SLAs
  POST   /api/v1/vuln-trends/sla/{sla_id}/resolve    -- Resolve SLA
  POST   /api/v1/vuln-trends/cohorts                 -- Create cohort
  GET    /api/v1/vuln-trends/cohorts                 -- List cohorts
  GET    /api/v1/vuln-trends/stats                   -- Aggregate stats

Security: Bearer token / API key required on all endpoints.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from core.vuln_trend_engine import VulnTrendEngine
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/vuln-trends", tags=["vuln-trends"])

_engine = None  # lazy-initialised on first request


def _get_engine():
    global _engine
    if _engine is None:
        _engine = VulnTrendEngine()
    return _engine


# ============================================================================
# REQUEST MODELS
# ============================================================================


class SnapshotRequest(BaseModel):
    total_vulns: Optional[int] = Field(None, ge=0)
    critical: int = Field(0, ge=0)
    high: int = Field(0, ge=0)
    medium: int = Field(0, ge=0)
    low: int = Field(0, ge=0)
    info: int = Field(0, ge=0)
    mttr_days: float = Field(0.0, ge=0.0)
    new_this_week: int = Field(0, ge=0)
    resolved_this_week: int = Field(0, ge=0)
    sla_breached: int = Field(0, ge=0)
    taken_at: Optional[str] = None


class SlaTrackRequest(BaseModel):
    vuln_id: str = Field(..., min_length=1)
    severity: str = Field("medium", pattern="^(critical|high|medium|low|info)$")
    discovered_at: Optional[str] = None


class CohortRequest(BaseModel):
    cohort_name: str = Field(..., min_length=1)
    vuln_ids: List[str] = Field(default_factory=list)
    avg_age_days: float = Field(0.0, ge=0.0)
    avg_cvss: float = Field(0.0, ge=0.0, le=10.0)


# ============================================================================
# ENDPOINTS
# ============================================================================


@router.post("/snapshots", summary="Record a daily vulnerability snapshot")
async def record_snapshot(
    body: SnapshotRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    try:
        return _get_engine().record_snapshot(org_id, body.model_dump(exclude_none=True))
    except Exception as exc:
        logger.error("record_snapshot failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/snapshots", summary="List vulnerability snapshots")
async def list_snapshots(
    limit: int = Query(30, ge=1, le=365),
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    return _get_engine().list_snapshots(org_id, limit=limit)


@router.get("/analysis", summary="Get trend analysis comparing last 2 snapshots")
async def get_trend_analysis(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    return _get_engine().get_trend_analysis(org_id)


@router.post("/sla", summary="Track a vulnerability SLA")
async def track_sla(
    body: SlaTrackRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    try:
        return _get_engine().track_sla(org_id, body.model_dump(exclude_none=True))
    except Exception as exc:
        logger.error("track_sla failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/sla/breaches", summary="List breached SLAs")
async def check_sla_breaches(
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    return _get_engine().check_sla_breaches(org_id)


@router.post("/sla/{sla_id}/resolve", summary="Resolve an SLA entry")
async def resolve_sla(
    sla_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    ok = _get_engine().resolve_sla(org_id, sla_id)
    if not ok:
        raise HTTPException(status_code=404, detail="SLA entry not found")
    return {"sla_id": sla_id, "resolved": True}


@router.post("/cohorts", summary="Create a vulnerability cohort")
async def create_cohort(
    body: CohortRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    try:
        return _get_engine().create_cohort(org_id, body.model_dump())
    except Exception as exc:
        logger.error("create_cohort failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/cohorts", summary="List vulnerability cohorts")
async def list_cohorts(
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    return _get_engine().list_cohorts(org_id)


@router.get("/stats", summary="Aggregate vulnerability trend statistics")
async def get_trend_stats(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    return _get_engine().get_trend_stats(org_id)
