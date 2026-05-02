"""
Security KPI API endpoints — ALDECI CISO Dashboard.

8 endpoints covering KPI recording, querying, trend analysis,
threshold management, health status, and executive summaries.

Protected via api_key_auth dependency.
"""

from __future__ import annotations

from typing import Any, Dict, List

from apps.api.auth_deps import api_key_auth
from core.kpi_engine import (
    KPI,
    ExecutiveKPISummary,
    KPICategory,
    KPIEngine,
    KPIHealthStatus,
    KPITarget,
)
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/api/v1/kpis",
    tags=["kpis"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None  # lazy-initialised on first request


def _get_engine():
    global _engine
    if _engine is None:
        _engine = KPIEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class KPIRecordRequest(BaseModel):
    """Request body for recording a KPI value."""

    name: str = Field(..., min_length=1, description="KPI name (e.g. mttd_minutes)")
    value: float = Field(..., description="Numeric KPI value")
    category: KPICategory = Field(..., description="KPI category")
    org_id: str = Field("default", description="Organisation identifier")
    period: str = Field("", description="Reporting period label (e.g. 2026-04)")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class KPITargetRequest(BaseModel):
    """Request body for configuring KPI thresholds."""

    name: str = Field(..., min_length=1, description="KPI name")
    target: float = Field(..., description="Ideal target value")
    yellow: float = Field(..., description="Yellow alert threshold")
    red: float = Field(..., description="Red alert threshold")
    higher_is_better: bool = Field(
        True,
        description="True for coverage/rate KPIs; False for MTTD/MTTR",
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/record", response_model=KPI, status_code=201)
async def record_kpi(body: KPIRecordRequest) -> KPI:
    """
    Record a single KPI data point.

    Stores the value with timestamp, org, and category.
    Unit is resolved automatically from built-in definitions.
    """
    return _get_engine().record_kpi(
        name=body.name,
        value=body.value,
        category=body.category,
        org_id=body.org_id,
        period=body.period,
        metadata=body.metadata,
    )


@router.get("/current", response_model=List[KPI])
async def get_current_kpis(
    org_id: str = Query("default", description="Organisation identifier"),
) -> List[KPI]:
    """
    Return the most-recent value for every KPI recorded for this org.

    Includes target and trend (up/down/stable) derived from historical data.
    """
    return _get_engine().get_current_kpis(org_id=org_id)


@router.get("/trend/{name}", response_model=List[Dict[str, Any]])
async def get_kpi_trend(
    name: str,
    org_id: str = Query("default", description="Organisation identifier"),
    days: int = Query(30, ge=1, le=365, description="Number of days of history to return"),
) -> List[Dict[str, Any]]:
    """
    Return historical values for a named KPI.

    Useful for trend charts on the CISO dashboard.
    Returns list of {timestamp, value} dicts ordered chronologically.
    """
    trend = _get_engine().get_kpi_trend(name=name, org_id=org_id, days=days)
    if not trend:
        raise HTTPException(
            status_code=404,
            detail=f"No KPI data found for '{name}' in org '{org_id}' over the last {days} days.",
        )
    return trend


@router.put("/targets", response_model=KPITarget)
async def set_target(body: KPITargetRequest) -> KPITarget:
    """
    Configure thresholds for a KPI.

    Overwrites any existing target configuration for the named KPI.
    Thresholds determine green/yellow/red health classification.
    """
    return _get_engine().set_target(
        name=body.name,
        target=body.target,
        yellow=body.yellow,
        red=body.red,
        higher_is_better=body.higher_is_better,
    )


@router.get("/health", response_model=List[KPIHealthStatus])
async def get_kpi_health(
    org_id: str = Query("default", description="Organisation identifier"),
) -> List[KPIHealthStatus]:
    """
    Return RAG (green/yellow/red) health status for all KPIs.

    Uses configured thresholds to classify each KPI.
    KPIs without recorded data or targets show as 'unknown'.
    """
    return _get_engine().get_kpi_health(org_id=org_id)


@router.get("/executive", response_model=ExecutiveKPISummary)
async def get_executive_kpis(
    org_id: str = Query("default", description="Organisation identifier"),
) -> ExecutiveKPISummary:
    """
    Return top 10 KPIs for the CISO executive dashboard.

    Prioritises: critical findings, MTTD, MTTR, SLA compliance,
    compliance score, scan coverage, patch rate, false positive rate,
    connector uptime, and vulnerability density.

    Includes overall portfolio health (green/yellow/red) and per-KPI breakdown.
    """
    return _get_engine().get_executive_kpis(org_id=org_id)


@router.post("/calculate", response_model=List[KPI])
async def auto_calculate_kpis(
    org_id: str = Query("default", description="Organisation identifier"),
) -> List[KPI]:
    """
    Trigger auto-calculation of all KPIs from platform data.

    Queries analytics engine, findings database, and connector status
    to populate KPI values automatically.  Returns newly recorded KPIs.
    """
    return _get_engine().auto_calculate_kpis(org_id=org_id)


@router.get("/definitions", response_model=List[Dict[str, Any]])
async def list_kpi_definitions() -> List[Dict[str, Any]]:
    """
    Return all built-in KPI definitions.

    Each entry includes name, display_name, unit, category,
    higher_is_better flag, and default target value.
    Use this to discover available KPI names before recording data.
    """
    return _get_engine().list_kpi_definitions()
