"""Vulnerability Workflow Router — ALDECI.

Endpoints for the Vulnerability Workflow engine.

Prefix: /api/v1/vuln-workflow
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/vuln-workflow/tickets                        create_ticket
  GET    /api/v1/vuln-workflow/tickets                        list_tickets
  GET    /api/v1/vuln-workflow/tickets/{ticket_id}            get_ticket
  PATCH  /api/v1/vuln-workflow/tickets/{ticket_id}            update_ticket
  POST   /api/v1/vuln-workflow/tickets/{ticket_id}/comments   add_comment
  POST   /api/v1/vuln-workflow/tickets/{ticket_id}/assign     assign_ticket
  POST   /api/v1/vuln-workflow/tickets/{ticket_id}/accept-risk accept_risk
  POST   /api/v1/vuln-workflow/tickets/bulk-assign            bulk_assign
  POST   /api/v1/vuln-workflow/tickets/bulk-close             bulk_close
  GET    /api/v1/vuln-workflow/sla                            get_sla_config
  POST   /api/v1/vuln-workflow/sla                            set_sla_config
  GET    /api/v1/vuln-workflow/stats                          get_workflow_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/vuln-workflow",
    tags=["vuln-workflow"],
)

_engines: Dict[str, Any] = {}


def _get_engine(org_id: str):
    if org_id not in _engines:
        from core.vuln_workflow_engine import VulnWorkflowEngine
        _engines[org_id] = VulnWorkflowEngine(org_id)
    return _engines[org_id]


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class TicketCreate(BaseModel):
    title: str
    cve_id: str = ""
    severity: str = "medium"
    cvss_score: float = 0.0
    affected_assets: List[str] = Field(default_factory=list)
    assignee_id: str = ""
    assignee_team: str = ""
    priority: str = "p3"
    due_date: Optional[str] = None
    resolution_notes: str = ""
    source_engine: str = "manual"
    tags: List[str] = Field(default_factory=list)


class TicketUpdate(BaseModel):
    title: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    assignee_id: Optional[str] = None
    assignee_team: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    due_date: Optional[str] = None
    resolution_notes: Optional[str] = None
    updated_by: str = "system"


class CommentAdd(BaseModel):
    author_id: str
    body: str
    comment_type: str = "comment"


class AssignTicket(BaseModel):
    assignee_id: str
    team: str
    assigned_by: str


class AcceptRisk(BaseModel):
    accepted_by: str
    reason: str
    expiry_date: Optional[str] = None


class BulkAssign(BaseModel):
    ticket_ids: List[str]
    assignee_id: str
    team: str
    applied_by: str


class BulkClose(BaseModel):
    ticket_ids: List[str]
    applied_by: str
    reason: str


class SLAConfigSet(BaseModel):
    severity: str
    sla_days: int
    escalation_days: int = 7
    owner_team: str = ""


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/tickets", dependencies=[Depends(api_key_auth)])
def create_ticket(
    payload: TicketCreate,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Create a new vulnerability ticket with auto SLA due-date."""
    engine = _get_engine(org_id)
    try:
        return engine.create_ticket(org_id, payload.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/tickets", dependencies=[Depends(api_key_auth)])
def list_tickets(
    org_id: str = Query(..., description="Organization ID"),
    status: Optional[str] = Query(None),
    assignee: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    team: Optional[str] = Query(None),
    overdue_only: bool = Query(False),
    limit: int = Query(50, ge=1, le=500),
) -> List[Dict[str, Any]]:
    """List tickets with optional filters and overdue flag."""
    engine = _get_engine(org_id)
    return engine.list_tickets(
        org_id,
        status=status,
        assignee=assignee,
        severity=severity,
        team=team,
        overdue_only=overdue_only,
        limit=limit,
    )


@router.get("/tickets/{ticket_id}", dependencies=[Depends(api_key_auth)])
def get_ticket(
    ticket_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Get a ticket with its comments."""
    engine = _get_engine(org_id)
    result = engine.get_ticket(org_id, ticket_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Ticket {ticket_id} not found.")
    return result


@router.patch("/tickets/{ticket_id}", dependencies=[Depends(api_key_auth)])
def update_ticket(
    ticket_id: str,
    payload: TicketUpdate,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Update ticket fields. Logs a status_change comment on transitions."""
    engine = _get_engine(org_id)
    data = {k: v for k, v in payload.model_dump().items() if v is not None}
    result = engine.update_ticket(org_id, ticket_id, data)
    if not result:
        raise HTTPException(status_code=404, detail=f"Ticket {ticket_id} not found.")
    return result


@router.post("/tickets/{ticket_id}/comments", dependencies=[Depends(api_key_auth)])
def add_comment(
    ticket_id: str,
    payload: CommentAdd,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Add a comment to a ticket."""
    engine = _get_engine(org_id)
    try:
        return engine.add_comment(
            org_id, ticket_id,
            payload.author_id,
            payload.body,
            payload.comment_type,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/tickets/{ticket_id}/assign", dependencies=[Depends(api_key_auth)])
def assign_ticket(
    ticket_id: str,
    payload: AssignTicket,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Reassign a ticket and log an assignment comment."""
    engine = _get_engine(org_id)
    result = engine.assign_ticket(
        org_id, ticket_id,
        payload.assignee_id,
        payload.team,
        payload.assigned_by,
    )
    if not result:
        raise HTTPException(status_code=404, detail=f"Ticket {ticket_id} not found.")
    return result


@router.post("/tickets/{ticket_id}/accept-risk", dependencies=[Depends(api_key_auth)])
def accept_risk(
    ticket_id: str,
    payload: AcceptRisk,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Mark a ticket as accepted_risk with audit trail."""
    engine = _get_engine(org_id)
    result = engine.accept_risk(
        org_id, ticket_id,
        payload.accepted_by,
        payload.reason,
        payload.expiry_date,
    )
    if not result:
        raise HTTPException(status_code=404, detail=f"Ticket {ticket_id} not found.")
    return result


@router.post("/tickets/bulk-assign", dependencies=[Depends(api_key_auth)])
def bulk_assign(
    payload: BulkAssign,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Bulk reassign a list of tickets."""
    engine = _get_engine(org_id)
    try:
        return engine.bulk_assign(
            org_id,
            payload.ticket_ids,
            payload.assignee_id,
            payload.team,
            payload.applied_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/tickets/bulk-close", dependencies=[Depends(api_key_auth)])
def bulk_close(
    payload: BulkClose,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Bulk resolve a list of tickets."""
    engine = _get_engine(org_id)
    try:
        return engine.bulk_close(
            org_id,
            payload.ticket_ids,
            payload.applied_by,
            payload.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/sla", dependencies=[Depends(api_key_auth)])
def get_sla_config(
    org_id: str = Query(..., description="Organization ID"),
) -> List[Dict[str, Any]]:
    """Return all SLA configs for org."""
    engine = _get_engine(org_id)
    return engine.get_sla_config(org_id)


@router.post("/sla", dependencies=[Depends(api_key_auth)])
def set_sla_config(
    payload: SLAConfigSet,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Upsert SLA config for a severity level."""
    engine = _get_engine(org_id)
    try:
        return engine.set_sla_config(
            org_id,
            payload.severity,
            payload.sla_days,
            payload.escalation_days,
            payload.owner_team,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_workflow_stats(
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Return aggregated workflow stats for org."""
    engine = _get_engine(org_id)
    return engine.get_workflow_stats(org_id)
