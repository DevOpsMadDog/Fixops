"""Executive Reporting API Router — ALDECI.

Endpoints (all under /api/v1/exec-reporting):

  Reports:
    POST   /reports              — create executive report
    GET    /reports              — list reports (filter: report_type, status)
    GET    /reports/{id}         — get report + metrics
    POST   /reports/{id}/metrics — add metric to report
    POST   /reports/{id}/publish — publish report

  KPIs:
    GET    /kpis                 — list all KPIs
    POST   /kpis                 — upsert KPI
    GET    /kpis/{name}          — get single KPI

  Board presentations:
    POST   /board-presentations  — create board presentation
    GET    /board-presentations  — list all presentations

  Summary:
    GET    /summary              — aggregated exec summary

Auth: api_key_auth from apps.api.auth_deps
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/exec-reporting", tags=["exec-reporting"])

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.executive_reporting_engine import ExecutiveReportingEngine
        _engine = ExecutiveReportingEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ReportIn(BaseModel):
    report_type: str = "monthly"
    title: str = ""
    period_start: str = ""
    period_end: str = ""
    sections: List[str] = Field(default_factory=list)
    created_by: str = ""


class MetricIn(BaseModel):
    metric_name: str
    metric_value: float = 0.0
    metric_unit: str = ""
    trend: str = "stable"
    comparison_value: float = 0.0
    comparison_period: str = ""
    narrative: str = ""


class KPIIn(BaseModel):
    kpi_name: str
    kpi_value: float
    target_value: float
    kpi_unit: str = ""
    trend: str = "stable"


class BoardPresentationIn(BaseModel):
    title: str = ""
    presentation_date: str = ""
    audience: str = "board"
    risk_summary: str = ""
    key_metrics: Dict[str, Any] = Field(default_factory=dict)
    action_items: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

@router.post("/reports", status_code=201)
def create_report(
    payload: ReportIn,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Create an executive report."""
    try:
        return _get_engine().create_report(org_id, payload.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("create_report failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/reports")
def list_reports(
    org_id: str = Query("default"),
    report_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """List executive reports."""
    try:
        return _get_engine().list_reports(org_id, report_type=report_type, status=status)
    except Exception as exc:
        logger.exception("list_reports failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/reports/{report_id}")
def get_report(
    report_id: str,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Get a report with its metrics."""
    try:
        result = _get_engine().get_report(org_id, report_id)
        if result is None:
            raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("get_report failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/reports/{report_id}/metrics", status_code=201)
def add_metric(
    report_id: str,
    payload: MetricIn,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Add a metric to a report."""
    try:
        return _get_engine().add_metric(org_id, report_id, payload.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("add_metric failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/reports/{report_id}/publish")
def publish_report(
    report_id: str,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Publish a report."""
    try:
        ok = _get_engine().publish_report(org_id, report_id)
        if not ok:
            raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
        return {"report_id": report_id, "status": "published"}
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("publish_report failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# KPIs
# ---------------------------------------------------------------------------

@router.post("/kpis", status_code=201)
def set_kpi(
    payload: KPIIn,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Upsert a KPI."""
    try:
        return _get_engine().set_kpi(
            org_id,
            payload.kpi_name,
            payload.kpi_value,
            payload.target_value,
            payload.kpi_unit,
            payload.trend,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("set_kpi failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/kpis")
def list_kpis(
    org_id: str = Query("default"),
) -> List[Dict[str, Any]]:
    """List all KPIs for org."""
    try:
        return _get_engine().list_kpis(org_id)
    except Exception as exc:
        logger.exception("list_kpis failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/kpis/{kpi_name}")
def get_kpi(
    kpi_name: str,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Get a single KPI by name."""
    try:
        result = _get_engine().get_kpi(org_id, kpi_name)
        if result is None:
            raise HTTPException(status_code=404, detail=f"KPI '{kpi_name}' not found")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("get_kpi failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Board presentations
# ---------------------------------------------------------------------------

@router.post("/board-presentations", status_code=201)
def create_board_presentation(
    payload: BoardPresentationIn,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Create a board presentation."""
    try:
        return _get_engine().create_board_presentation(org_id, payload.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("create_board_presentation failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/board-presentations")
def list_board_presentations(
    org_id: str = Query("default"),
) -> List[Dict[str, Any]]:
    """List all board presentations."""
    try:
        return _get_engine().list_board_presentations(org_id)
    except Exception as exc:
        logger.exception("list_board_presentations failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

@router.get("/summary")
def get_exec_summary(
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Return aggregated executive summary."""
    try:
        return _get_engine().get_exec_summary(org_id)
    except Exception as exc:
        logger.exception("get_exec_summary failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/context/{entity_id}")
def get_trustgraph_context(
    entity_id: str,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Return TrustGraph cross-domain context for an entity (related assets, findings, incidents)."""
    return _get_engine().get_trustgraph_context(org_id, entity_id)
