"""Incident Communications Router — ALDECI.

Manages all communications during security incidents: notifications,
status updates, resolutions, post-mortems, stakeholder briefs, press
releases, acknowledgment tracking, and reusable templates.

Prefix: /api/v1/incident-comms
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/incident-comms/comms                         create_comm
  GET    /api/v1/incident-comms/comms                         list_comms
  GET    /api/v1/incident-comms/comms/{id}                    get_comm
  POST   /api/v1/incident-comms/comms/{id}/send               send_comm
  POST   /api/v1/incident-comms/comms/{id}/acknowledge        record_acknowledgment
  GET    /api/v1/incident-comms/comms/{id}/acknowledgments    list_acknowledgments
  POST   /api/v1/incident-comms/templates                     create_template
  GET    /api/v1/incident-comms/templates                     list_templates
  GET    /api/v1/incident-comms/stats                         get_comms_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/incident-comms",
    tags=["Incident Communications"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.incident_comms_engine import IncidentCommsEngine
        _engine = IncidentCommsEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CreateCommRequest(BaseModel):
    incident_id: Optional[str] = Field(default=None, description="Associated incident ID")
    comm_type: str = Field(
        default="status_update",
        description=(
            "initial_notification | status_update | resolution | "
            "post_mortem | stakeholder_brief | press_release"
        ),
    )
    channel: str = Field(
        default="email",
        description="email | slack | teams | sms | pagerduty | status_page | internal",
    )
    subject: str = Field(..., description="Communication subject (required)")
    body: str = Field(..., description="Communication body content (required)")
    audience: str = Field(
        default="internal",
        description="internal | external | executive | technical | customer | all",
    )
    severity: str = Field(
        default="medium",
        description="critical | high | medium | low",
    )
    comm_status: str = Field(
        default="draft",
        description="draft | sent | delivered | failed",
    )
    scheduled_at: Optional[str] = Field(default=None, description="Scheduled send time (ISO 8601)")
    author: Optional[str] = Field(default=None, description="Author name or ID")


class SendCommRequest(BaseModel):
    delivered: Optional[int] = Field(default=None, ge=0, description="Number of successful deliveries")
    failed: Optional[int] = Field(default=None, ge=0, description="Number of failed deliveries")


class AcknowledgeCommRequest(BaseModel):
    acknowledger_id: str = Field(..., description="ID of the person acknowledging (required)")
    notes: Optional[str] = Field(default=None, description="Optional acknowledgment notes")


class CreateTemplateRequest(BaseModel):
    template_name: str = Field(..., description="Unique template name (required)")
    comm_type: str = Field(
        default="status_update",
        description=(
            "initial_notification | status_update | resolution | "
            "post_mortem | stakeholder_brief | press_release"
        ),
    )
    channel: str = Field(
        default="email",
        description="email | slack | teams | sms | pagerduty | status_page | internal",
    )
    subject_template: Optional[str] = Field(default=None, description="Subject line template")
    body_template: Optional[str] = Field(default=None, description="Body template with placeholders")
    audience: Optional[str] = Field(default="internal", description="Target audience")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/", dependencies=[Depends(api_key_auth)])
def get_service_summary(
    org_id: str = Query(default="default"),
) -> dict:
    """Return incident-communications service summary (stats + available channels).

    5-state envelope: items/total/org_id/filters_applied/hint.
    """
    stats = _get_engine().get_comms_stats(org_id)
    channels = ["email", "slack", "teams", "sms", "pagerduty", "status_page", "internal"]
    comm_types = [
        "initial_notification", "status_update", "resolution",
        "post_mortem", "stakeholder_brief", "press_release",
    ]
    items = [
        {"key": "stats", "value": stats},
        {"key": "channels", "value": channels},
        {"key": "comm_types", "value": comm_types},
    ]
    envelope: dict = {
        "items": items,
        "total": len(items),
        "org_id": org_id,
        "filters_applied": {},
        "service": "incident-comms",
    }
    if stats.get("total_comms", 0) == 0:
        envelope["hint"] = (
            "No incident communications yet. Create one via "
            "POST /api/v1/incident-comms/comms."
        )
    return envelope


@router.post("/comms", dependencies=[Depends(api_key_auth)])
def create_comm(
    req: CreateCommRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Create a new incident communication."""
    try:
        return _get_engine().create_comm(
            org_id,
            {
                "incident_id": req.incident_id or "",
                "comm_type": req.comm_type,
                "channel": req.channel,
                "subject": req.subject,
                "body": req.body,
                "audience": req.audience,
                "severity": req.severity,
                "comm_status": req.comm_status,
                "scheduled_at": req.scheduled_at,
                "author": req.author or "",
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/comms", dependencies=[Depends(api_key_auth)])
def list_comms(
    org_id: str = Query(..., description="Organization ID"),
    incident_id: Optional[str] = Query(default=None),
    comm_type: Optional[str] = Query(default=None),
    comm_status: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List incident communications with optional filters."""
    return _get_engine().list_comms(
        org_id,
        incident_id=incident_id,
        comm_type=comm_type,
        comm_status=comm_status,
    )


@router.get("/comms/{comm_id}", dependencies=[Depends(api_key_auth)])
def get_comm(
    comm_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Retrieve a single communication by ID."""
    comm = _get_engine().get_comm(org_id, comm_id)
    if comm is None:
        raise HTTPException(status_code=404, detail=f"Communication '{comm_id}' not found")
    return comm


@router.post("/comms/{comm_id}/send", dependencies=[Depends(api_key_auth)])
def send_comm(
    comm_id: str,
    req: SendCommRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Mark a communication as sent and update delivery counts."""
    try:
        return _get_engine().send_comm(
            org_id,
            comm_id,
            delivered=req.delivered,
            failed=req.failed,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/comms/{comm_id}/acknowledge", dependencies=[Depends(api_key_auth)])
def record_acknowledgment(
    comm_id: str,
    req: AcknowledgeCommRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Record an acknowledgment for a communication."""
    try:
        return _get_engine().record_acknowledgment(
            org_id,
            comm_id,
            {
                "acknowledger_id": req.acknowledger_id,
                "notes": req.notes or "",
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/comms/{comm_id}/acknowledgments", dependencies=[Depends(api_key_auth)])
def list_acknowledgments(
    comm_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> List[Dict[str, Any]]:
    """List all acknowledgments for a specific communication."""
    return _get_engine().list_acknowledgments(org_id, comm_id)


@router.post("/templates", dependencies=[Depends(api_key_auth)])
def create_template(
    req: CreateTemplateRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Create a reusable communication template."""
    try:
        return _get_engine().create_template(
            org_id,
            {
                "template_name": req.template_name,
                "comm_type": req.comm_type,
                "channel": req.channel,
                "subject_template": req.subject_template or "",
                "body_template": req.body_template or "",
                "audience": req.audience or "internal",
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/templates", dependencies=[Depends(api_key_auth)])
def list_templates(
    org_id: str = Query(..., description="Organization ID"),
    comm_type: Optional[str] = Query(default=None),
    channel: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List communication templates with optional filters."""
    return _get_engine().list_templates(
        org_id,
        comm_type=comm_type,
        channel=channel,
    )


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_comms_stats(
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Return aggregate incident communications statistics."""
    return _get_engine().get_comms_stats(org_id)
