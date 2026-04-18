"""Alert Triage Router — ALDECI.

Centralized alert ingestion and triage workflow across SIEM, EDR, NDR,
Cloud, WAF, IDS, and Firewall sources.

Prefix: /api/v1/alert-triage
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/alert-triage/alerts                  ingest_alert
  GET    /api/v1/alert-triage/alerts                  list_alerts
  GET    /api/v1/alert-triage/alerts/{id}             get_alert
  PATCH  /api/v1/alert-triage/alerts/{id}/triage      triage_alert
  POST   /api/v1/alert-triage/bulk-triage             bulk_triage
  GET    /api/v1/alert-triage/queue                   get_triage_queue
  GET    /api/v1/alert-triage/stats                   get_triage_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from apps.api.auth_deps import require_role

_logger = logging.getLogger(__name__)

_ANALYST_ROLES = ("admin", "super_admin", "org_admin", "security_engineer", "analyst")

router = APIRouter(
    prefix="/api/v1/alert-triage",
    tags=["Alert Triage"],
    dependencies=[require_role(*_ANALYST_ROLES)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.alert_triage_engine import AlertTriageEngine
        _engine = AlertTriageEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class IngestAlertRequest(BaseModel):
    title: str = Field(..., description="Short alert title")
    source_system: str = Field(
        default="siem",
        description="siem | edr | ndr | cloud | waf | ids | firewall | custom",
    )
    severity: str = Field(
        default="medium",
        description="critical | high | medium | low | info",
    )
    raw_alert_json: Optional[Dict[str, Any]] = Field(
        default=None, description="Raw alert payload from source system"
    )


class TriageAlertRequest(BaseModel):
    triage_status: str = Field(
        ...,
        description=(
            "new | triaging | escalated | investigating | "
            "resolved | false_positive | duplicate"
        ),
    )
    assigned_to: Optional[str] = Field(default=None, description="Assignee username")
    triage_notes: Optional[str] = Field(default=None, description="Analyst notes")
    escalation_reason: Optional[str] = Field(
        default=None, description="Required when escalating"
    )


class BulkTriageRequest(BaseModel):
    alert_ids: List[str] = Field(..., description="List of alert IDs to action")
    action: str = Field(
        ..., description="resolve | false_positive | escalate"
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/alerts", dependencies=[Depends(api_key_auth)])
def ingest_alert(
    req: IngestAlertRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Ingest a new alert. Priority is auto-assigned from severity."""
    try:
        return _get_engine().ingest_alert(
            org_id,
            {
                "title": req.title,
                "source_system": req.source_system,
                "severity": req.severity,
                "raw_alert_json": req.raw_alert_json or {},
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/alerts", dependencies=[Depends(api_key_auth)])
def list_alerts(
    org_id: str = Query(..., description="Organization ID"),
    source_system: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    priority: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List alerts with optional filters."""
    return _get_engine().list_alerts(
        org_id,
        source_system=source_system,
        severity=severity,
        status=status,
        priority=priority,
    )


@router.get("/alerts/{alert_id}", dependencies=[Depends(api_key_auth)])
def get_alert(
    alert_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Retrieve a single alert by ID."""
    alert = _get_engine().get_alert(org_id, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")
    return alert


@router.patch("/alerts/{alert_id}/triage", dependencies=[Depends(api_key_auth)])
def triage_alert(
    alert_id: str,
    req: TriageAlertRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Update triage status and metadata for an alert."""
    try:
        return _get_engine().triage_alert(
            org_id,
            alert_id,
            {
                "triage_status": req.triage_status,
                "assigned_to": req.assigned_to or "",
                "triage_notes": req.triage_notes or "",
                "escalation_reason": req.escalation_reason or "",
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/bulk-triage", dependencies=[Depends(api_key_auth)])
def bulk_triage(
    req: BulkTriageRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Apply the same triage action to multiple alerts at once."""
    try:
        return _get_engine().bulk_triage(org_id, req.alert_ids, req.action)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/queue", dependencies=[Depends(api_key_auth)])
def get_triage_queue(
    org_id: str = Query(..., description="Organization ID"),
    limit: int = Query(default=50, ge=1, le=500),
) -> List[Dict[str, Any]]:
    """Return the prioritized triage queue (new + triaging, p1 first)."""
    return _get_engine().get_triage_queue(org_id, limit=limit)


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_triage_stats(
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Return aggregate triage statistics."""
    return _get_engine().get_triage_stats(org_id)


@router.get("/alerts/{alert_id}/context", dependencies=[Depends(api_key_auth)])
def get_alert_context(
    alert_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Return TrustGraph cross-domain context for an alert (related assets, findings, incidents)."""
    return _get_engine().get_alert_context(org_id, alert_id)
