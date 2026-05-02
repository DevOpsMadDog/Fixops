"""KPI Tracking Router — ALDECI.

Endpoints for the KPI Tracking engine.

Prefix: /api/v1/kpi-tracking
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/kpi-tracking/kpis                         create_kpi
  GET   /api/v1/kpi-tracking/kpis                         list_kpis
  GET   /api/v1/kpi-tracking/kpis/{kpi_id}                get_kpi
  POST  /api/v1/kpi-tracking/kpis/{kpi_id}/measurements   record_measurement
  GET   /api/v1/kpi-tracking/kpis/{kpi_id}/measurements   list_measurements
  GET   /api/v1/kpi-tracking/kpis/{kpi_id}/performance    get_kpi_performance
  GET   /api/v1/kpi-tracking/stats                        get_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/kpi-tracking",
    tags=["KPI Tracking"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.kpi_tracking_engine import KPITrackingEngine
        _engine = KPITrackingEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class KPICreate(BaseModel):
    name: str
    kpi_category: str = "operational"
    direction: str = "higher_better"
    target_value: float
    unit: str = ""
    frequency: str = "monthly"
    description: str = ""


class MeasurementCreate(BaseModel):
    value: float
    notes: str = ""


# ---------------------------------------------------------------------------
# KPIs
# ---------------------------------------------------------------------------

@router.post("/kpis", dependencies=[Depends(api_key_auth)], status_code=201)
def create_kpi(body: KPICreate, org_id: str = Query(default="default")):
    """Create a new KPI definition."""
    try:
        return _get_engine().create_kpi(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/kpis", dependencies=[Depends(api_key_auth)])
def list_kpis(
     org_id: str = Query(default="default"),
    kpi_category: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List KPIs with optional category and status filters."""
    return _get_engine().list_kpis(org_id, kpi_category=kpi_category, status=status)


@router.get("/kpis/{kpi_id}", dependencies=[Depends(api_key_auth)])
def get_kpi(kpi_id: str, org_id: str = Query(default="default")):
    """Get a single KPI by ID."""
    kpi = _get_engine().get_kpi(org_id, kpi_id)
    if not kpi:
        raise HTTPException(status_code=404, detail="KPI not found")
    return kpi


# ---------------------------------------------------------------------------
# Measurements
# ---------------------------------------------------------------------------

@router.post(
    "/kpis/{kpi_id}/measurements",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def record_measurement(kpi_id: str, body: MeasurementCreate, org_id: str = Query(default="default")):
    """Record a measurement for a KPI."""
    try:
        result = _get_engine().record_measurement(
            org_id, kpi_id, body.value, notes=body.notes
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not result:
        raise HTTPException(status_code=404, detail="KPI not found")
    return result


@router.get("/kpis/{kpi_id}/measurements", dependencies=[Depends(api_key_auth)])
def list_measurements(
    kpi_id: str,
     org_id: str = Query(default="default"),
    limit: int = Query(30, ge=1, le=500),
):
    """List measurements for a KPI."""
    return _get_engine().list_measurements(org_id, kpi_id, limit=limit)


@router.get("/kpis/{kpi_id}/performance", dependencies=[Depends(api_key_auth)])
def get_kpi_performance(kpi_id: str, org_id: str = Query(default="default")):
    """Get performance summary for a KPI."""
    result = _get_engine().get_kpi_performance(org_id, kpi_id)
    if not result:
        raise HTTPException(status_code=404, detail="KPI not found")
    return result


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_kpi_stats(org_id: str = Query(default="default")):
    """Return aggregated KPI statistics."""
    return _get_engine().get_kpi_stats(org_id)
