"""
IR Playbook Router — Incident Response Playbook Engine endpoints.

8 endpoints:
  GET    /api/v1/ir/playbooks                   list_playbooks
  POST   /api/v1/ir/incidents                   create_incident
  GET    /api/v1/ir/incidents/{id}              get_incident
  POST   /api/v1/ir/incidents/{id}/advance      advance_phase
  GET    /api/v1/ir/incidents/{id}/timeline     get_timeline
  GET    /api/v1/ir/incidents/{id}/evidence     get_evidence_chain
  GET    /api/v1/ir/metrics                     get_metrics
  GET    /api/v1/ir/notifications               get_notifications
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "ir_playbook_router: auth_deps not available, relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.ir_playbook_engine import (
    IncidentSeverity,
    IncidentType,
    IRIncident,
    IRMetrics,
    IRPlaybook,
    IRPlaybookEngine,
    RegulatoryNotification,
    TimelineEvent,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/ir",
    tags=["Incident Response"],
    dependencies=_AUTH_DEP,
)

# Shared engine instance (SQLite-backed, shared across requests)
_engine: Optional[IRPlaybookEngine] = None


def _get_engine() -> IRPlaybookEngine:
    global _engine
    if _engine is None:
        _engine = IRPlaybookEngine()
    return _engine


# ============================================================================
# REQUEST / RESPONSE MODELS
# ============================================================================


class CreateIncidentRequest(BaseModel):
    """Request body for creating a new incident."""

    title: str = Field(..., min_length=5, max_length=500, description="Short descriptive title")
    incident_type: IncidentType = Field(..., description="Type of security incident")
    severity: IncidentSeverity = Field(..., description="Incident severity level")
    org_id: str = Field("default", description="Organization identifier")
    assigned_to: Optional[str] = Field(None, description="Responder username or team")
    affected_systems: List[str] = Field(default_factory=list, description="Affected system hostnames/IPs")
    affected_users: List[str] = Field(default_factory=list, description="Affected user accounts")
    tags: List[str] = Field(default_factory=list, description="Free-form classification tags")
    context: Dict[str, Any] = Field(default_factory=dict, description="Additional incident context")
    detected_at: Optional[datetime] = Field(None, description="Override detection timestamp (ISO-8601)")


class AdvancePhaseRequest(BaseModel):
    """Request body for advancing an incident to the next phase."""

    approved_by: Optional[str] = Field(None, description="Approver username (required for gated phases)")
    notes: str = Field("", description="Phase completion notes")


class AddEvidenceRequest(BaseModel):
    """Request body for adding evidence to an incident."""

    collector_id: str = Field(..., description="ID of the collector (user, tool, or system)")
    evidence_type: str = Field(..., description="Evidence type: log, screenshot, pcap, image, etc.")
    description: str = Field(..., description="Human-readable description of this evidence")
    raw_content: str = Field(..., description="Raw evidence content (text, base64 for binary)")


class PlaybookSummary(BaseModel):
    """Lightweight playbook summary for list responses."""

    id: str
    name: str
    incident_type: str
    description: str
    severity_threshold: str
    phase_count: int
    step_count: int
    applicable_regulations: List[str]


class IncidentResponse(BaseModel):
    """Full incident response model."""

    id: str
    playbook_id: str
    title: str
    incident_type: str
    severity: str
    status: str
    current_phase: str
    org_id: str
    assigned_to: Optional[str]
    affected_systems: List[str]
    affected_users: List[str]
    tags: List[str]
    phase_history: List[Dict[str, Any]]
    context: Dict[str, Any]
    created_at: datetime
    detected_at: Optional[datetime]
    contained_at: Optional[datetime]
    resolved_at: Optional[datetime]
    updated_at: datetime
    current_phase_steps: List[Dict[str, Any]]


class EvidenceResponse(BaseModel):
    """Evidence chain item response."""

    id: str
    incident_id: str
    collector_id: str
    evidence_type: str
    description: str
    sha256_hash: str
    collected_at: datetime
    previous_hash: str
    chain_sequence: int
    chain_valid: bool = True


class NotificationResponse(BaseModel):
    """Regulatory notification response."""

    id: str
    incident_id: str
    framework: str
    deadline_hours: Optional[int]
    detection_time: datetime
    deadline_at: Optional[datetime]
    notified_at: Optional[datetime]
    is_overdue: bool
    status: str
    template: str
    hours_remaining: Optional[float]


# ============================================================================
# HELPERS
# ============================================================================


def _playbook_to_summary(pb: IRPlaybook) -> PlaybookSummary:
    step_count = sum(len(steps) for steps in pb.phases.values())
    return PlaybookSummary(
        id=pb.id,
        name=pb.name,
        incident_type=pb.incident_type.value,
        description=pb.description,
        severity_threshold=pb.severity_threshold.value,
        phase_count=len(pb.phases),
        step_count=step_count,
        applicable_regulations=[r.value for r in pb.applicable_regulations],
    )


def _incident_to_response(incident: IRIncident, engine: IRPlaybookEngine) -> IncidentResponse:
    """Build full incident response with current phase steps."""
    playbook = engine.get_playbook(incident.playbook_id)
    current_steps: List[Dict[str, Any]] = []
    if playbook and incident.current_phase.value in playbook.phases:
        steps = playbook.phases[incident.current_phase.value]
        current_steps = [
            {
                "id": s.id,
                "name": s.name,
                "description": s.description,
                "action_type": s.action_type.value,
                "action_mode": s.action_mode.value,
                "requires_approval": s.requires_approval,
                "evidence_required": s.evidence_required,
                "order": s.order,
            }
            for s in steps
        ]
    return IncidentResponse(
        id=incident.id,
        playbook_id=incident.playbook_id,
        title=incident.title,
        incident_type=incident.incident_type.value,
        severity=incident.severity.value,
        status=incident.status.value,
        current_phase=incident.current_phase.value,
        org_id=incident.org_id,
        assigned_to=incident.assigned_to,
        affected_systems=incident.affected_systems,
        affected_users=incident.affected_users,
        tags=incident.tags,
        phase_history=[p.model_dump(mode="json") for p in incident.phase_history],
        context=incident.context,
        created_at=incident.created_at,
        detected_at=incident.detected_at,
        contained_at=incident.contained_at,
        resolved_at=incident.resolved_at,
        updated_at=incident.updated_at,
        current_phase_steps=current_steps,
    )


def _notification_to_response(n: RegulatoryNotification) -> NotificationResponse:
    from datetime import timezone
    now = datetime.now(timezone.utc)
    hours_remaining: Optional[float] = None
    if n.deadline_at and n.status not in ("sent",):
        delta = (n.deadline_at - now).total_seconds() / 3600
        hours_remaining = round(delta, 2)
    return NotificationResponse(
        id=n.id,
        incident_id=n.incident_id,
        framework=n.framework.value,
        deadline_hours=n.deadline_hours,
        detection_time=n.detection_time,
        deadline_at=n.deadline_at,
        notified_at=n.notified_at,
        is_overdue=n.is_overdue,
        status=n.status,
        template=n.template,
        hours_remaining=hours_remaining,
    )


# ============================================================================
# ENDPOINTS
# ============================================================================


@router.get(
    "/playbooks",
    response_model=List[PlaybookSummary],
    summary="List IR Playbooks",
    description="Return all 15 built-in NIST 800-61 incident response playbooks.",
)
def list_playbooks() -> List[PlaybookSummary]:
    engine = _get_engine()
    playbooks = engine.list_playbooks()
    return [_playbook_to_summary(pb) for pb in playbooks]


@router.post(
    "/incidents",
    response_model=IncidentResponse,
    status_code=201,
    summary="Create Incident",
    description=(
        "Create a new incident. Auto-selects the matching NIST 800-61 playbook. "
        "Automatically creates regulatory notification deadlines for applicable frameworks."
    ),
)
def create_incident(req: CreateIncidentRequest) -> IncidentResponse:
    engine = _get_engine()
    try:
        incident = engine.create_incident(
            title=req.title,
            incident_type=req.incident_type,
            severity=req.severity,
            org_id=req.org_id,
            assigned_to=req.assigned_to,
            affected_systems=req.affected_systems,
            affected_users=req.affected_users,
            tags=req.tags,
            context=req.context,
            detected_at=req.detected_at,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _incident_to_response(incident, engine)


@router.get(
    "/incidents/{incident_id}",
    response_model=IncidentResponse,
    summary="Get Incident",
    description="Retrieve an incident by ID including current NIST phase and pending steps.",
)
def get_incident(
    incident_id: str,
    org_id: str = Query("default", description="Organization ID"),
) -> IncidentResponse:
    engine = _get_engine()
    incident = engine.get_incident(incident_id, org_id=org_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    return _incident_to_response(incident, engine)


@router.post(
    "/incidents/{incident_id}/advance",
    response_model=IncidentResponse,
    summary="Advance Incident Phase",
    description=(
        "Advance incident to the next NIST 800-61 phase: "
        "Detection & Analysis → Containment → Eradication → Recovery → Lessons Learned → Closed."
    ),
)
def advance_phase(
    incident_id: str,
    req: AdvancePhaseRequest,
    org_id: str = Query("default", description="Organization ID"),
) -> IncidentResponse:
    engine = _get_engine()
    try:
        incident = engine.advance_phase(
            incident_id=incident_id,
            org_id=org_id,
            approved_by=req.approved_by,
            notes=req.notes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _incident_to_response(incident, engine)


@router.get(
    "/incidents/{incident_id}/timeline",
    response_model=List[TimelineEvent],
    summary="Get Incident Timeline",
    description="Return chronological timeline of all events, actions, and communications for the incident.",
)
def get_timeline(
    incident_id: str,
    org_id: str = Query("default", description="Organization ID"),
) -> List[TimelineEvent]:
    engine = _get_engine()
    try:
        return engine.get_timeline(incident_id, org_id=org_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get(
    "/incidents/{incident_id}/evidence",
    response_model=List[EvidenceResponse],
    summary="Get Evidence Chain",
    description=(
        "Return the cryptographically-linked evidence chain for an incident. "
        "Each item includes SHA-256 hash, collector ID, and chain integrity status."
    ),
)
def get_evidence_chain(
    incident_id: str,
    org_id: str = Query("default", description="Organization ID"),
) -> List[EvidenceResponse]:
    engine = _get_engine()
    try:
        chain = engine.get_evidence_chain(incident_id, org_id=org_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    # Verify chain integrity
    chain_valid = engine.verify_evidence_chain(incident_id, org_id=org_id)

    result: List[EvidenceResponse] = []
    for item in chain:
        result.append(
            EvidenceResponse(
                id=item.id,
                incident_id=item.incident_id,
                collector_id=item.collector_id,
                evidence_type=item.evidence_type,
                description=item.description,
                sha256_hash=item.sha256_hash,
                collected_at=item.collected_at,
                previous_hash=item.previous_hash,
                chain_sequence=item.chain_sequence,
                chain_valid=chain_valid,
            )
        )
    return result


@router.post(
    "/incidents/{incident_id}/evidence",
    response_model=EvidenceResponse,
    status_code=201,
    summary="Add Evidence",
    description="Add a piece of evidence to the incident with cryptographic chain-of-custody.",
)
def add_evidence(
    incident_id: str,
    req: AddEvidenceRequest,
    org_id: str = Query("default", description="Organization ID"),
) -> EvidenceResponse:
    engine = _get_engine()
    try:
        item = engine.add_evidence(
            incident_id=incident_id,
            collector_id=req.collector_id,
            evidence_type=req.evidence_type,
            description=req.description,
            raw_content=req.raw_content,
            org_id=org_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return EvidenceResponse(
        id=item.id,
        incident_id=item.incident_id,
        collector_id=item.collector_id,
        evidence_type=item.evidence_type,
        description=item.description,
        sha256_hash=item.sha256_hash,
        collected_at=item.collected_at,
        previous_hash=item.previous_hash,
        chain_sequence=item.chain_sequence,
        chain_valid=True,
    )


@router.get(
    "/metrics",
    response_model=IRMetrics,
    summary="IR Metrics Dashboard",
    description=(
        "Return incident response metrics: MTTD, MTTC, MTTR, "
        "incident counts by type/severity, and playbook effectiveness scores."
    ),
)
def get_metrics(
    org_id: str = Query("default", description="Organization ID"),
) -> IRMetrics:
    engine = _get_engine()
    return engine.get_metrics(org_id=org_id)


@router.get(
    "/notifications",
    response_model=List[NotificationResponse],
    summary="Regulatory Notification Deadlines",
    description=(
        "Return all regulatory notification deadlines and status: "
        "GDPR (72h), HIPAA (60d), PCI-DSS (immediate), CCPA (30d), SOC2, NIST. "
        "Includes hours remaining and generated notification templates."
    ),
)
def get_notifications(
    org_id: str = Query("default", description="Organization ID"),
    incident_id: Optional[str] = Query(None, description="Filter by incident ID"),
) -> List[NotificationResponse]:
    engine = _get_engine()
    notifications = engine.get_notifications(org_id=org_id, incident_id=incident_id)
    return [_notification_to_response(n) for n in notifications]


@router.post(
    "/notifications/{notification_id}/mark-sent",
    response_model=NotificationResponse,
    summary="Mark Notification Sent",
    description="Record that a regulatory notification has been filed with the relevant authority.",
)
def mark_notification_sent(
    notification_id: str,
    org_id: str = Query("default", description="Organization ID"),
) -> NotificationResponse:
    engine = _get_engine()
    notification = engine.mark_notification_sent(notification_id, org_id=org_id)
    if notification is None:
        raise HTTPException(status_code=404, detail=f"Notification '{notification_id}' not found")
    return _notification_to_response(notification)
