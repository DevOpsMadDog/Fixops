"""Security KPI metrics router — track and trend security performance KPIs.

Prefix: /api/v1/kpi

Endpoints:
  POST   /record          — record a single KPI measurement
  POST   /record-batch    — record multiple KPIs at once
  GET    /current         — latest value for every KPI
  GET    /trend/{kpi_name} — historical trend (query: days)
  GET    /benchmarks      — compare KPIs against industry benchmarks
  POST   /snapshot        — take a point-in-time snapshot
  GET    /snapshots       — list historical snapshots
  GET    /scorecard       — calculate security scorecard
  GET    /targets         — get KPI targets
  POST   /targets         — set a KPI target
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.security_kpi_tracker import KPI_NAMES, SecurityKPITracker
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/kpi", tags=["security-kpi"])

# Shared tracker instance (file-backed SQLite)
_tracker: Optional[SecurityKPITracker] = None


def _get_tracker() -> SecurityKPITracker:
    global _tracker
    if _tracker is None:
        _tracker = SecurityKPITracker()
    return _tracker


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class RecordKPIRequest(BaseModel):
    kpi_name: str = Field(..., description=f"One of: {KPI_NAMES}")
    value: float = Field(..., description="Numeric KPI value")
    org_id: str = Field("default", description="Organisation ID")
    period: Optional[str] = Field(None, description="'daily'|'weekly'|'monthly'")
    metadata: Optional[Dict[str, Any]] = None


class BatchKPIItem(BaseModel):
    kpi_name: str
    value: float
    period: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class RecordBatchRequest(BaseModel):
    kpis: List[BatchKPIItem]
    org_id: str = Field("default", description="Organisation ID")


class SetTargetRequest(BaseModel):
    kpi_name: str
    target_value: float
    target_date: str = Field(..., description="ISO date string, e.g. '2026-12-31'")
    org_id: str = Field("default")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/record", summary="Record a single KPI measurement")
def record_kpi(req: RecordKPIRequest) -> dict:
    tracker = _get_tracker()
    try:
        return tracker.record_kpi(
            kpi_name=req.kpi_name,
            value=req.value,
            org_id=req.org_id,
            period=req.period,
            metadata=req.metadata,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/record-batch", summary="Record multiple KPI measurements")
def record_batch(req: RecordBatchRequest) -> List[dict]:
    tracker = _get_tracker()
    results: List[dict] = []
    errors: List[str] = []

    for item in req.kpis:
        try:
            record = tracker.record_kpi(
                kpi_name=item.kpi_name,
                value=item.value,
                org_id=req.org_id,
                period=item.period,
                metadata=item.metadata,
            )
            results.append(record)
        except ValueError as exc:
            errors.append(str(exc))

    if errors and not results:
        raise HTTPException(status_code=422, detail="; ".join(errors))

    return results


@router.get("/current", summary="Get latest value for all KPIs")
def get_current(org_id: str = Query("default")) -> dict:
    return _get_tracker().get_current_kpis(org_id=org_id)


@router.get("/trend/{kpi_name}", summary="Get historical trend for a KPI")
def get_trend(
    kpi_name: str,
    days: int = Query(30, ge=1, le=365),
    org_id: str = Query("default"),
) -> List[dict]:
    if kpi_name not in KPI_NAMES:
        raise HTTPException(status_code=404, detail=f"Unknown KPI '{kpi_name}'")
    return _get_tracker().get_kpi_trend(kpi_name=kpi_name, days=days, org_id=org_id)


@router.get("/benchmarks", summary="Compare KPIs against industry benchmarks")
def get_benchmarks(org_id: str = Query("default")) -> dict:
    return _get_tracker().get_benchmark_comparison(org_id=org_id)


@router.post("/snapshot", summary="Take a point-in-time KPI snapshot")
def take_snapshot(org_id: str = Query("default")) -> dict:
    return _get_tracker().record_snapshot(org_id=org_id)


@router.get("/snapshots", summary="List historical KPI snapshots")
def list_snapshots(
    org_id: str = Query("default"),
    limit: int = Query(30, ge=1, le=200),
) -> List[dict]:
    return _get_tracker().get_snapshots(org_id=org_id, limit=limit)


@router.get("/scorecard", summary="Generate security scorecard")
def get_scorecard(org_id: str = Query("default")) -> dict:
    return _get_tracker().calculate_score_card(org_id=org_id)


@router.get("/targets", summary="Get KPI targets")
def get_targets(org_id: str = Query("default")) -> List[dict]:
    return _get_tracker().get_targets(org_id=org_id)


@router.post("/targets", summary="Set a KPI target")
def set_target(req: SetTargetRequest) -> dict:
    tracker = _get_tracker()
    try:
        return tracker.set_target(
            kpi_name=req.kpi_name,
            target_value=req.target_value,
            target_date=req.target_date,
            org_id=req.org_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
