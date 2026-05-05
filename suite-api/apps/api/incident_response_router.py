"""Incident Response Playbook API endpoints.

Provides runbook management, timeline tracking, and post-incident review:
- Create/list/get incidents with auto-populated playbook steps
- State machine status transitions
- Step assignment and completion
- Timeline event logging
- Finding/evidence linking
- Post-mortem creation and retrieval
- Playbook templates and statistics
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

try:
    from core.incident_response import (
        IncidentResponseManager,
        IncidentSeverity,
        IncidentStatus,
        IncidentType,
    )

    _manager: Optional[IncidentResponseManager] = None

    def _get_manager() -> IncidentResponseManager:
        global _manager
        if _manager is None:
            _manager = IncidentResponseManager()
        return _manager

    _HAS_IR = True
except ImportError as _exc:
    _logger.warning("incident_response_router: incident_response unavailable: %s", _exc)
    _HAS_IR = False

router = APIRouter(prefix="/api/v1/incidents", tags=["incident-response"])


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class CreateIncidentRequest(BaseModel):
    title: str
    type: str
    severity: str
    reported_by: str
    org_id: str = "default"


class UpdateStatusRequest(BaseModel):
    new_status: str


class AssignStepRequest(BaseModel):
    assignee: str


class CompleteStepRequest(BaseModel):
    notes: Optional[str] = None


class AddTimelineEventRequest(BaseModel):
    event_description: str
    author: str


class LinkFindingRequest(BaseModel):
    finding_id: str


class LinkEvidenceRequest(BaseModel):
    evidence_id: str


class CreatePostMortemRequest(BaseModel):
    summary: str
    root_cause: str
    impact: str = ""
    timeline_summary: str = ""
    lessons_learned: List[str] = []
    action_items: List[Dict[str, Any]] = []
    authored_by: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_ir():
    if not _HAS_IR:
        raise HTTPException(status_code=503, detail="Incident response module unavailable")


def _parse_incident_type(value: str) -> IncidentType:
    try:
        return IncidentType(value)
    except ValueError:
        valid = [t.value for t in IncidentType]
        raise HTTPException(status_code=422, detail=f"Invalid incident type '{value}'. Valid: {valid}")


def _parse_incident_severity(value: str) -> IncidentSeverity:
    try:
        return IncidentSeverity(value)
    except ValueError:
        valid = [s.value for s in IncidentSeverity]
        raise HTTPException(status_code=422, detail=f"Invalid severity '{value}'. Valid: {valid}")


def _parse_incident_status(value: str) -> IncidentStatus:
    try:
        return IncidentStatus(value)
    except ValueError:
        valid = [s.value for s in IncidentStatus]
        raise HTTPException(status_code=422, detail=f"Invalid status '{value}'. Valid: {valid}")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("")
def create_incident(request: CreateIncidentRequest) -> Dict[str, Any]:
    """Create a new incident with auto-populated playbook steps."""
    _require_ir()
    manager = _get_manager()
    inc_type = _parse_incident_type(request.type)
    severity = _parse_incident_severity(request.severity)
    incident = manager.create_incident(
        title=request.title,
        type=inc_type,
        severity=severity,
        reported_by=request.reported_by,
        org_id=request.org_id,
    )
    result = incident.model_dump(mode="json")
    # TrustGraph async indexing (fire-and-forget, non-blocking)
    try:
        import asyncio

        from core.trustgraph_event_bus import EVENT_INCIDENT_CREATED, get_event_bus
        bus = get_event_bus()
        if bus and bus.enabled:
            asyncio.ensure_future(bus.emit(EVENT_INCIDENT_CREATED, {
                "incident_id": str(result.get("id", "")),
                "type": "incident",
                "severity": result.get("severity", "medium"),
                "source": "incident_response_router",
                "data": result,
            }))
    except Exception:
        pass  # event bus is best-effort
    return result


@router.get("/stats")
def get_stats(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return incident statistics by type, severity, status, and resolution time."""
    _require_ir()
    manager = _get_manager()
    return manager.get_incident_stats(org_id=org_id)


@router.get("/templates/{incident_type}")
def get_playbook_template(incident_type: str) -> Dict[str, Any]:
    """Return the built-in playbook template for the given incident type."""
    _require_ir()
    manager = _get_manager()
    inc_type = _parse_incident_type(incident_type)
    steps = manager.get_playbook_template(inc_type)
    return {
        "incident_type": incident_type,
        "steps": [s.model_dump(mode="json") for s in steps],
        "step_count": len(steps),
    }


@router.get("")
def list_incidents(
    org_id: str = Query(default="default"),
    status: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """List incidents with optional status and severity filters."""
    _require_ir()
    manager = _get_manager()
    status_filter = _parse_incident_status(status) if status else None
    severity_filter = _parse_incident_severity(severity) if severity else None
    incidents = manager.list_incidents(
        org_id=org_id,
        status_filter=status_filter,
        severity_filter=severity_filter,
    )
    return {
        "incidents": [i.model_dump(mode="json") for i in incidents],
        "count": len(incidents),
    }


@router.get("/{incident_id}")
def get_incident(incident_id: str) -> Dict[str, Any]:
    """Get a single incident by ID."""
    _require_ir()
    manager = _get_manager()
    incident = manager.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident.model_dump(mode="json")


@router.put("/{incident_id}/status")
def update_status(incident_id: str, request: UpdateStatusRequest) -> Dict[str, Any]:
    """Update incident status via state machine transitions."""
    _require_ir()
    manager = _get_manager()
    new_status = _parse_incident_status(request.new_status)
    try:
        incident = manager.update_status(incident_id, new_status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return incident.model_dump(mode="json")


@router.post("/{incident_id}/steps/{step_order}/assign")
def assign_step(
    incident_id: str, step_order: int, request: AssignStepRequest
) -> Dict[str, Any]:
    """Assign a responder to a playbook step."""
    _require_ir()
    manager = _get_manager()
    try:
        incident = manager.assign_step(incident_id, step_order, request.assignee)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return incident.model_dump(mode="json")


@router.post("/{incident_id}/steps/{step_order}/complete")
def complete_step(
    incident_id: str, step_order: int, request: CompleteStepRequest
) -> Dict[str, Any]:
    """Mark a playbook step as completed."""
    _require_ir()
    manager = _get_manager()
    try:
        incident = manager.complete_step(incident_id, step_order, request.notes)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return incident.model_dump(mode="json")


@router.post("/{incident_id}/timeline")
def add_timeline_event(
    incident_id: str, request: AddTimelineEventRequest
) -> Dict[str, Any]:
    """Append an event to the incident timeline."""
    _require_ir()
    manager = _get_manager()
    try:
        incident = manager.add_timeline_event(
            incident_id, request.event_description, request.author
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return incident.model_dump(mode="json")


@router.post("/{incident_id}/post-mortem")
def create_post_mortem(
    incident_id: str, request: CreatePostMortemRequest
) -> Dict[str, Any]:
    """Create a post-mortem for a closed incident."""
    _require_ir()
    manager = _get_manager()
    try:
        pm = manager.create_post_mortem(
            incident_id=incident_id,
            summary=request.summary,
            root_cause=request.root_cause,
            impact=request.impact,
            timeline_summary=request.timeline_summary,
            lessons=request.lessons_learned,
            action_items=request.action_items,
            author=request.authored_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return pm.model_dump(mode="json")


@router.get("/{incident_id}/post-mortem")
def get_post_mortem(incident_id: str) -> Dict[str, Any]:
    """Retrieve the post-mortem for an incident."""
    _require_ir()
    manager = _get_manager()
    pm = manager.get_post_mortem(incident_id)
    if pm is None:
        raise HTTPException(status_code=404, detail="Post-mortem not found")
    return pm.model_dump(mode="json")


@router.get("/", summary="Incidents index", tags=["incident-response"])
async def incidents_index(
    org_id: str = Query("default"),
    status: Optional[str] = Query(None, description="Filter by status (open, investigating, contained, closed, post_mortem)"),
    severity: Optional[str] = Query(None, description="Filter by severity (critical, high, medium, low)"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """Return incident list and summary stats for the org."""
    if not _HAS_IR:
        return {"router": "incidents", "org_id": org_id, "stats": {}, "items": [], "total": 0, "limit": limit, "offset": offset}
    try:
        manager = _get_manager()
        status_filter = None
        severity_filter = None
        if status:
            try:
                status_filter = IncidentStatus(status)
            except ValueError:
                pass
        if severity:
            try:
                severity_filter = IncidentSeverity(severity)
            except ValueError:
                pass
        incidents = manager.list_incidents(org_id=org_id, status_filter=status_filter, severity_filter=severity_filter)
        stats = manager.get_incident_stats(org_id=org_id) if hasattr(manager, "get_incident_stats") else {}
        page = incidents[offset: offset + limit]
        items = [i.model_dump(mode="json") for i in page]
    except Exception as exc:
        _logger.exception("incidents_index: list failed")
        return {"router": "incidents", "org_id": org_id, "stats": {}, "items": [], "total": 0, "limit": limit, "offset": offset, "error": str(exc)}
    return {"router": "incidents", "org_id": org_id, "stats": stats, "items": items, "total": len(incidents), "limit": limit, "offset": offset}
