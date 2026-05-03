"""ALDECI PagerDuty incident-management router — REAL API only, NO MOCKS.

Mounted at ``/api/v1/pagerduty`` under the ``read:scans`` scope.

Endpoints
---------
GET    /                       — capability summary
GET    /incidents              — list incidents (statuses[], service_ids[], limit, offset)
POST   /incidents              — create incident (PagerDuty payload + From: header)
POST   /incidents/{id}/notes   — add a note to an incident
PUT    /incidents/{id}         — acknowledge / resolve / mutate
GET    /services               — list services
GET    /oncalls                — list on-call assignments
POST   /change_events/enqueue  — enqueue a change event via Events API v2
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field

from core.pagerduty_incident_engine import (
    PagerDutyUnavailableError,
    get_pagerduty_incident_engine,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/pagerduty",
    tags=["pagerduty"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------- Pydantic


class _ServiceRef(BaseModel):
    id: str
    type: str = "service_reference"


class _IncidentBody(BaseModel):
    type: str = "incident_body"
    details: str = ""


class _AssigneeRef(BaseModel):
    assignee: Dict[str, Any]


class _IncidentCreatePayload(BaseModel):
    type: str = "incident"
    title: str
    service: _ServiceRef
    urgency: str = Field("high", pattern="^(high|low)$")
    body: Optional[_IncidentBody] = None
    assignments: Optional[List[Dict[str, Any]]] = None
    escalation_policy: Optional[Dict[str, Any]] = None


class CreateIncidentRequest(BaseModel):
    incident: _IncidentCreatePayload


class _IncidentMutationPayload(BaseModel):
    type: str = "incident_reference"
    status: Optional[str] = Field(None, pattern="^(acknowledged|resolved)$")
    title: Optional[str] = None
    urgency: Optional[str] = Field(None, pattern="^(high|low)$")
    resolution: Optional[str] = None


class UpdateIncidentRequest(BaseModel):
    incident: _IncidentMutationPayload


class _NotePayload(BaseModel):
    content: str


class AddNoteRequest(BaseModel):
    note: _NotePayload


class _ChangeEventPayload(BaseModel):
    summary: str
    source: Optional[str] = None
    timestamp: Optional[str] = None
    custom_details: Optional[Dict[str, Any]] = None


class EnqueueChangeEventRequest(BaseModel):
    routing_key: str
    payload: _ChangeEventPayload


# ----------------------------------------------------------------- helpers


def _to_503(exc: PagerDutyUnavailableError) -> HTTPException:
    return HTTPException(status_code=503, detail=str(exc))


# ----------------------------------------------------------------- endpoints


@router.get("/", summary="PagerDuty capability summary")
def capability_summary() -> Dict[str, Any]:
    eng = get_pagerduty_incident_engine()
    return eng.capability_summary()


@router.get("/incidents", summary="List PagerDuty incidents")
def list_incidents(
    statuses: Optional[List[str]] = Query(
        None, alias="statuses[]", description="triggered|acknowledged|resolved"
    ),
    service_ids: Optional[List[str]] = Query(
        None, alias="service_ids[]", description="PagerDuty service IDs"
    ),
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    eng = get_pagerduty_incident_engine()
    try:
        return eng.list_incidents(
            statuses=statuses,
            service_ids=service_ids,
            limit=limit,
            offset=offset,
        )
    except PagerDutyUnavailableError as exc:
        raise _to_503(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/incidents", summary="Create PagerDuty incident", status_code=201)
def create_incident(
    body: CreateIncidentRequest,
    from_header: Optional[str] = Header(None, alias="From"),
) -> Dict[str, Any]:
    eng = get_pagerduty_incident_engine()
    if from_header:
        # Allow per-request override; the engine still uses env when missing.
        eng._from_email = from_header.strip()  # noqa: SLF001
    try:
        return eng.create_incident(body.dict(exclude_none=True))
    except PagerDutyUnavailableError as exc:
        raise _to_503(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/incidents/{incident_id}/notes", summary="Add note to incident", status_code=201)
def add_incident_note(
    incident_id: str,
    body: AddNoteRequest,
) -> Dict[str, Any]:
    eng = get_pagerduty_incident_engine()
    try:
        return eng.add_incident_note(incident_id, body.note.content)
    except PagerDutyUnavailableError as exc:
        raise _to_503(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.put("/incidents/{incident_id}", summary="Update PagerDuty incident")
def update_incident(
    incident_id: str,
    body: UpdateIncidentRequest,
) -> Dict[str, Any]:
    eng = get_pagerduty_incident_engine()
    try:
        return eng.update_incident(incident_id, body.dict(exclude_none=True))
    except PagerDutyUnavailableError as exc:
        raise _to_503(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/services", summary="List PagerDuty services")
def list_services(limit: int = Query(25, ge=1, le=100)) -> Dict[str, Any]:
    eng = get_pagerduty_incident_engine()
    try:
        return eng.list_services(limit=limit)
    except PagerDutyUnavailableError as exc:
        raise _to_503(exc)


@router.get("/oncalls", summary="List PagerDuty on-call assignments")
def list_oncalls(
    escalation_policy_ids: Optional[List[str]] = Query(
        None, alias="escalation_policy_ids[]"
    ),
    time_zone: str = Query("UTC"),
) -> Dict[str, Any]:
    eng = get_pagerduty_incident_engine()
    try:
        return eng.list_oncalls(
            escalation_policy_ids=escalation_policy_ids,
            time_zone=time_zone,
        )
    except PagerDutyUnavailableError as exc:
        raise _to_503(exc)


@router.post("/change_events/enqueue", summary="Enqueue PagerDuty change event")
def enqueue_change_event(body: EnqueueChangeEventRequest = Body(...)) -> Dict[str, Any]:
    eng = get_pagerduty_incident_engine()
    try:
        return eng.enqueue_change_event(
            routing_key=body.routing_key,
            payload=body.payload.dict(exclude_none=True),
        )
    except PagerDutyUnavailableError as exc:
        raise _to_503(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


# Optional: list escalation policies (capability summary advertises it)
@router.get("/escalation_policies", summary="List PagerDuty escalation policies")
def list_escalation_policies(limit: int = Query(25, ge=1, le=100)) -> Dict[str, Any]:
    eng = get_pagerduty_incident_engine()
    try:
        return eng.list_escalation_policies(limit=limit)
    except PagerDutyUnavailableError as exc:
        raise _to_503(exc)


__all__ = ["router"]
