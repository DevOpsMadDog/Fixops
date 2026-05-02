"""
SLA Engine Router — Security Finding SLA Tracking and Breach Prevention.

Endpoints:
  POST /api/v1/sla-engine/track              — start tracking a finding
  GET  /api/v1/sla-engine/status/{finding_id} — get SLA status
  GET  /api/v1/sla-engine/at-risk            — list at-risk findings
  GET  /api/v1/sla-engine/dashboard          — SLA dashboard stats
  GET  /api/v1/sla-engine/compliance-rate    — compliance rate
  POST /api/v1/sla-engine/resolve/{finding_id} — mark finding resolved
  POST /api/v1/sla-engine/policy             — create SLA policy
  POST /api/v1/sla-engine/alerts             — trigger breach alert scan

Compliance: SOC2 CC7.2, ISO27001 A.12.6.1, PCI-DSS Req 6.3
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from core.sla_engine import SLAEngine, SLAPolicy, SLAStatus, SLATracking
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/sla-engine", tags=["SLA Engine"])

# Module-level singleton
_engine = None  # lazy-initialised on first request


def _get_engine() -> SLAEngine:
    global _engine
    if _engine is None:
        _engine = SLAEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class TrackFindingRequest(BaseModel):
    finding_id: str
    severity: str
    policy_id: Optional[str] = None
    discovered_at: Optional[datetime] = None


class CreatePolicyRequest(BaseModel):
    name: str
    deadlines: Dict[str, int] = Field(
        default_factory=lambda: {"critical": 24, "high": 72, "medium": 168, "low": 720},
        description="Deadline in hours per severity level",
    )


class AlertsResponse(BaseModel):
    alert_ids: List[str]
    count: int


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/track",
    response_model=SLATracking,
    status_code=status.HTTP_201_CREATED,
    summary="Start tracking a finding against SLA",
)
async def track_finding(
    payload: TrackFindingRequest,
    org_id: str = Depends(get_org_id),
    engine: SLAEngine = Depends(_get_engine),
) -> SLATracking:
    """Begin SLA tracking for a security finding. Idempotent — returns existing record if already tracked."""
    try:
        return engine.track_finding(
            finding_id=payload.finding_id,
            severity=payload.severity,
            policy_id=payload.policy_id,
            org_id=org_id,
            discovered_at=payload.discovered_at,
        )
    except Exception as exc:
        logger.exception("sla_track_error", exc_info=exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc


@router.get(
    "/status/{finding_id}",
    response_model=SLAStatus,
    summary="Get SLA status for a finding",
)
async def get_status(
    finding_id: str,
    engine: SLAEngine = Depends(_get_engine),
) -> SLAStatus:
    """Return ON_TRACK, AT_RISK, BREACHED, or RESOLVED for a tracked finding."""
    try:
        return engine.check_status(finding_id)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.get(
    "/at-risk",
    response_model=List[SLAStatus],
    summary="List findings at risk of SLA breach",
)
async def get_at_risk(
    org_id: str = Depends(get_org_id),
    engine: SLAEngine = Depends(_get_engine),
) -> List[SLAStatus]:
    """Return all findings currently AT_RISK or BREACHED for the org."""
    return engine.get_at_risk_findings(org_id=org_id)


@router.get(
    "/dashboard",
    response_model=Dict[str, Any],
    summary="SLA dashboard stats",
)
async def get_dashboard(
    org_id: str = Depends(get_org_id),
    engine: SLAEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Aggregate SLA metrics: counts by status, compliance rate."""
    return engine.get_dashboard(org_id=org_id)


@router.get(
    "/compliance-rate",
    summary="SLA compliance rate for past N days",
)
async def get_compliance_rate(
    days: int = Query(default=30, ge=1, le=365),
    org_id: str = Depends(get_org_id),
    engine: SLAEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Calculate SLA compliance rate: % of resolved findings fixed within deadline."""
    rate = engine.calculate_compliance_rate(org_id=org_id, days=days)
    return {"org_id": org_id, "days": days, "compliance_rate": rate}


@router.post(
    "/resolve/{finding_id}",
    response_model=SLAStatus,
    summary="Mark a finding as resolved",
)
async def resolve_finding(
    finding_id: str,
    engine: SLAEngine = Depends(_get_engine),
) -> SLAStatus:
    """Record that a finding has been resolved. SLA is marked met or breached based on timing."""
    try:
        return engine.record_resolution(finding_id)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.post(
    "/policy",
    response_model=SLAPolicy,
    status_code=status.HTTP_201_CREATED,
    summary="Create or update a named SLA policy",
)
async def create_policy(
    payload: CreatePolicyRequest,
    org_id: str = Depends(get_org_id),
    engine: SLAEngine = Depends(_get_engine),
) -> SLAPolicy:
    """Create a named SLA policy with per-severity deadlines (in hours)."""
    try:
        return engine.create_sla_policy(
            name=payload.name,
            deadlines=payload.deadlines,
            org_id=org_id,
        )
    except Exception as exc:
        logger.exception("sla_policy_create_error", exc_info=exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc


@router.post(
    "/alerts",
    response_model=AlertsResponse,
    summary="Trigger breach alert scan",
)
async def send_breach_alerts(
    engine: SLAEngine = Depends(_get_engine),
) -> AlertsResponse:
    """Scan all tracked findings and send alerts for those >90% through their deadline."""
    alert_ids = engine.send_breach_alerts()
    return AlertsResponse(alert_ids=alert_ids, count=len(alert_ids))
