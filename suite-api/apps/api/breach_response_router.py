"""Data Breach Response API — ALDECI.

Endpoints for managing breach cases, regulatory notifications,
and compliance reports (GDPR 72h, HIPAA 60-day, CCPA, etc.).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

try:
    from core.breach_response_engine import BreachResponseEngine

    _engine: Optional[BreachResponseEngine] = None

    def _get_engine() -> BreachResponseEngine:
        global _engine
        if _engine is None:
            _engine = BreachResponseEngine()
        return _engine

    _HAS_BREACH = True
except ImportError as _exc:
    _logger.warning("breach_response_router: engine unavailable: %s", _exc)
    _HAS_BREACH = False

router = APIRouter(prefix="/api/v1/breach-response", tags=["breach-response"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class CreateCaseRequest(BaseModel):
    title: str
    breach_type: str
    data_types_affected: List[str] = []
    estimated_records_affected: int = 0
    notifiable: bool = False
    discovered_at: Optional[str] = None
    breach_date: Optional[str] = None
    regulatory_deadline: Optional[str] = None
    status: str = "suspected"
    org_id: str = "default"


class UpdateCaseRequest(BaseModel):
    title: Optional[str] = None
    breach_type: Optional[str] = None
    status: Optional[str] = None
    data_types_affected: Optional[List[str]] = None
    estimated_records_affected: Optional[int] = None
    notifiable: Optional[bool] = None
    breach_date: Optional[str] = None
    regulatory_deadline: Optional[str] = None


class LogNotificationRequest(BaseModel):
    notified_party: str
    notification_type: str
    sent_at: str
    content_summary: str = ""
    org_id: str = "default"


class AddReportRequest(BaseModel):
    regulator: str
    report_date: str
    status: str = "draft"
    org_id: str = "default"


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _require_breach() -> None:
    if not _HAS_BREACH:
        raise HTTPException(status_code=503, detail="Breach response engine unavailable")


# ---------------------------------------------------------------------------
# Breach Case endpoints
# ---------------------------------------------------------------------------


@router.get("/cases")
def list_cases(
    org_id: str = Query(default="default"),
    status: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """List breach cases for an org, optionally filtered by status."""
    _require_breach()
    engine = _get_engine()
    cases = engine.list_cases(org_id=org_id, status=status)
    return {"cases": cases, "count": len(cases)}


@router.post("/cases")
def create_case(request: CreateCaseRequest) -> Dict[str, Any]:
    """Create a new data breach case."""
    _require_breach()
    engine = _get_engine()
    data = request.model_dump(exclude={"org_id"})
    case = engine.create_case(org_id=request.org_id, data=data)
    return case


@router.get("/cases/{case_id}")
def get_case(
    case_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Get a single breach case by ID."""
    _require_breach()
    engine = _get_engine()
    case = engine.get_case(org_id=org_id, case_id=case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Breach case not found")
    return case


@router.patch("/cases/{case_id}")
def update_case(
    case_id: str,
    request: UpdateCaseRequest,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Update mutable fields of a breach case."""
    _require_breach()
    engine = _get_engine()
    data = {k: v for k, v in request.model_dump().items() if v is not None}
    updated = engine.update_case(org_id=org_id, case_id=case_id, data=data)
    if not updated:
        raise HTTPException(status_code=404, detail="Breach case not found or no changes")
    case = engine.get_case(org_id=org_id, case_id=case_id)
    return case or {}


# ---------------------------------------------------------------------------
# Notification endpoints
# ---------------------------------------------------------------------------


@router.get("/cases/{case_id}/notifications")
def list_notifications(
    case_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """List all notifications sent for a breach case."""
    _require_breach()
    engine = _get_engine()
    notifications = engine.list_notifications(org_id=org_id, case_id=case_id)
    return {"notifications": notifications, "count": len(notifications)}


@router.post("/cases/{case_id}/notifications")
def log_notification(
    case_id: str,
    request: LogNotificationRequest,
) -> Dict[str, Any]:
    """Log a notification (regulatory, customer, media, internal) for a breach case."""
    _require_breach()
    engine = _get_engine()
    record = engine.log_notification(
        org_id=request.org_id,
        case_id=case_id,
        notified_party=request.notified_party,
        notification_type=request.notification_type,
        sent_at=request.sent_at,
        content_summary=request.content_summary,
    )
    return record


# ---------------------------------------------------------------------------
# Regulatory Report endpoints
# ---------------------------------------------------------------------------


@router.get("/cases/{case_id}/reports")
def list_reports(
    case_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """List regulatory reports for a breach case."""
    _require_breach()
    engine = _get_engine()
    reports = engine.list_reports(org_id=org_id, case_id=case_id)
    return {"reports": reports, "count": len(reports)}


@router.post("/cases/{case_id}/reports")
def add_regulatory_report(
    case_id: str,
    request: AddReportRequest,
) -> Dict[str, Any]:
    """Create a regulatory report entry for a breach case."""
    _require_breach()
    engine = _get_engine()
    record = engine.add_regulatory_report(
        org_id=request.org_id,
        case_id=case_id,
        regulator=request.regulator,
        report_date=request.report_date,
        status=request.status,
    )
    return record


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@router.get("/stats")
def get_stats(
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Aggregate breach statistics for an org."""
    _require_breach()
    engine = _get_engine()
    return engine.get_breach_stats(org_id=org_id)
