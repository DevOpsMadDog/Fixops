"""Security Posture History Router — ALDECI.

Endpoints for the SecurityPostureHistoryEngine (SQLite-backed, org_id isolated).

Prefix: /api/v1/posture-history
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/posture-history/snapshots                  record_snapshot
  GET   /api/v1/posture-history/snapshots                  get_snapshots
  POST  /api/v1/posture-history/trends/compute             compute_trend
  GET   /api/v1/posture-history/trends                     get_trends
  PUT   /api/v1/posture-history/baselines                  set_baseline
  GET   /api/v1/posture-history/baselines/{domain}         get_baseline
  GET   /api/v1/posture-history/delta                      get_posture_delta
  GET   /api/v1/posture-history/summary                    get_domain_summary
"""
from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/posture-history",
    tags=["Security Posture History"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        try:
            from core.security_posture_history_engine import (
                SecurityPostureHistoryEngine,
            )
            _engine = SecurityPostureHistoryEngine()
        except Exception as exc:
            _logger.error("Failed to init SecurityPostureHistoryEngine: %s", exc)
            raise HTTPException(status_code=503, detail="Engine unavailable")
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class SnapshotCreate(BaseModel):
    domain: str
    score: float
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    source: str = ""


class TrendCompute(BaseModel):
    domain: str
    period: str = "monthly"


class BaselineSet(BaseModel):
    domain: str
    baseline_score: float
    target_score: float
    set_by: str = ""


# ---------------------------------------------------------------------------
# Snapshots
# ---------------------------------------------------------------------------

@router.get("/", dependencies=[Depends(api_key_auth)])
def list_posture_history(org_id: str = Query("default")):
    """Get security posture history domain summary for the org."""
    return _get_engine().get_domain_summary(org_id=org_id)


@router.post("/snapshots", dependencies=[Depends(api_key_auth)], status_code=201)
def record_snapshot(body: SnapshotCreate, org_id: str = Query(default="default")):
    """Record a posture snapshot for a domain."""
    try:
        return _get_engine().record_snapshot(
            org_id=org_id,
            domain=body.domain,
            score=body.score,
            findings_count=body.findings_count,
            critical_count=body.critical_count,
            high_count=body.high_count,
            source=body.source,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/snapshots", dependencies=[Depends(api_key_auth)])
def get_snapshots(
     org_id: str = Query(default="default"),
    domain: Optional[str] = Query(None),
    days: int = Query(30),
):
    """Get posture snapshots filtered by date range and optional domain."""
    return _get_engine().get_snapshots(org_id=org_id, domain=domain, days=days)


# ---------------------------------------------------------------------------
# Trends
# ---------------------------------------------------------------------------

@router.post("/trends/compute", dependencies=[Depends(api_key_auth)], status_code=201)
def compute_trend(body: TrendCompute, org_id: str = Query(default="default")):
    """Compute and store a posture trend for a domain/period."""
    try:
        return _get_engine().compute_trend(
            org_id=org_id,
            domain=body.domain,
            period=body.period,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/trends", dependencies=[Depends(api_key_auth)])
def get_trends(
     org_id: str = Query(default="default"),
    domain: Optional[str] = Query(None),
):
    """Get computed posture trends, optionally filtered by domain."""
    return _get_engine().get_trends(org_id=org_id, domain=domain)


# ---------------------------------------------------------------------------
# Baselines
# ---------------------------------------------------------------------------

@router.put("/baselines", dependencies=[Depends(api_key_auth)])
def set_baseline(body: BaselineSet, org_id: str = Query(default="default")):
    """Create or update a posture baseline for a domain."""
    try:
        return _get_engine().set_baseline(
            org_id=org_id,
            domain=body.domain,
            baseline_score=body.baseline_score,
            target_score=body.target_score,
            set_by=body.set_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/baselines/{domain}", dependencies=[Depends(api_key_auth)])
def get_baseline(domain: str, org_id: str = Query(default="default")):
    """Get the baseline for a specific domain."""
    result = _get_engine().get_baseline(org_id=org_id, domain=domain)
    if result is None:
        raise HTTPException(status_code=404, detail="Baseline not found")
    return result


# ---------------------------------------------------------------------------
# Delta & Summary
# ---------------------------------------------------------------------------

@router.get("/delta", dependencies=[Depends(api_key_auth)])
def get_posture_delta(
     org_id: str = Query(default="default"),
    domain: str = Query(...),
    days: int = Query(30),
):
    """Get score delta (oldest to newest) for a domain over N days."""
    return _get_engine().get_posture_delta(org_id=org_id, domain=domain, days=days)


@router.get("/summary", dependencies=[Depends(api_key_auth)])
def get_domain_summary(org_id: str = Query(default="default")):
    """Get per-domain latest score, trend, and baseline gap."""
    return _get_engine().get_domain_summary(org_id=org_id)
