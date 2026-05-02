"""Regulatory Reporting API endpoints — ALDECI.

Manages regulatory compliance tracking and report lifecycle.

Endpoints:
  POST /api/v1/regulatory-reporting/regulations               — register regulation
  GET  /api/v1/regulatory-reporting/regulations               — list regulations
  PUT  /api/v1/regulatory-reporting/regulations/{reg_id}/compliance-score — update score
  POST /api/v1/regulatory-reporting/reports                   — create report
  PUT  /api/v1/regulatory-reporting/reports/{report_id}/submit — submit report
  GET  /api/v1/regulatory-reporting/reports                   — list reports
  GET  /api/v1/regulatory-reporting/stats                     — regulatory stats

Protected via api_key_auth dependency.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from core.regulatory_reporting_engine import (
    ComplianceScoreUpdate,
    RegulationCreate,
    RegulatoryReportingEngine,
    ReportCreate,
    ReportSubmit,
)
from fastapi import APIRouter, Depends, HTTPException, Query

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/regulatory-reporting",
    tags=["regulatory-reporting"],
    dependencies=[Depends(api_key_auth)],
)

# Lazy singleton
_engine: Optional[RegulatoryReportingEngine] = None


def _get_engine() -> RegulatoryReportingEngine:
    global _engine
    if _engine is None:
        _engine = RegulatoryReportingEngine()
    return _engine


# ---------------------------------------------------------------------------
# Regulation endpoints
# ---------------------------------------------------------------------------


@router.post("/regulations", status_code=201)
async def register_regulation(
    body: RegulationCreate,
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """Register a new regulation for the org."""
    try:
        return _get_engine().register_regulation(org_id, body)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/regulations")
async def list_regulations(
    org_id: str = Query("default", description="Organisation identifier"),
    regulation_type: Optional[str] = Query(None, description="Filter by regulation type"),
) -> List[Dict[str, Any]]:
    """List regulations for the org, optionally filtered by type."""
    return _get_engine().list_regulations(org_id, regulation_type=regulation_type)


@router.put("/regulations/{reg_id}/compliance-score")
async def update_compliance_score(
    reg_id: str,
    body: ComplianceScoreUpdate,
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """Update compliance score for a regulation (clamped 0-100)."""
    try:
        return _get_engine().update_compliance_score(
            org_id, reg_id, body.score, body.notes
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Report endpoints
# ---------------------------------------------------------------------------


@router.post("/reports", status_code=201)
async def create_report(
    body: ReportCreate,
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """Create a new compliance report in draft status."""
    try:
        return _get_engine().create_report(org_id, body)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.put("/reports/{report_id}/submit")
async def submit_report(
    report_id: str,
    body: ReportSubmit,
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """Submit a draft report."""
    try:
        return _get_engine().submit_report(org_id, report_id, body.submitted_by)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/reports")
async def list_reports(
    org_id: str = Query("default", description="Organisation identifier"),
    regulation_id: Optional[str] = Query(None, description="Filter by regulation ID"),
    status: Optional[str] = Query(None, description="Filter by status"),
) -> List[Dict[str, Any]]:
    """List reports for the org, optionally filtered."""
    return _get_engine().list_reports(org_id, regulation_id=regulation_id, status=status)


# ---------------------------------------------------------------------------
# Stats endpoint
# ---------------------------------------------------------------------------


@router.get("/stats")
async def get_regulatory_stats(
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """Return regulatory compliance statistics for the org."""
    return _get_engine().get_regulatory_stats(org_id)


__all__ = ["router"]
