"""Email Filtering Router — REST endpoints for email filtering management.

Endpoints under /api/v1/email-filtering:
  POST   /rules                  — Create a filter rule
  GET    /rules                  — List filter rules (filter: rule_type, action)
  GET    /rules/{rule_id}        — Get a single filter rule
  POST   /events                 — Log an email event
  GET    /events                 — List email events (filter: filter_result, limit)
  GET    /stats                  — Email filtering statistics
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/email-filtering",
    tags=["Email Filtering"],
    dependencies=[Depends(api_key_auth)],
)

_engine_instance = None


def _get_engine():
    global _engine_instance
    if _engine_instance is None:
        try:
            from core.email_filtering_engine import EmailFilteringEngine
            _engine_instance = EmailFilteringEngine()
        except Exception as exc:
            _logger.error("EmailFilteringEngine unavailable: %s", exc)
            raise HTTPException(status_code=503, detail=f"Email filtering engine unavailable: {exc}")
    return _engine_instance


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CreateFilterRuleRequest(BaseModel):
    name: str
    rule_type: str
    action: str = "quarantine"
    priority: int = 50
    pattern: str = ""
    description: str = ""
    status: str = "active"


class LogEmailEventRequest(BaseModel):
    sender: str
    recipient: str
    subject: str = ""
    filter_result: str
    rule_id: str = ""
    threat_score: int = 0
    processed_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Rules endpoints
# ---------------------------------------------------------------------------

@router.post("/rules", response_model=Dict[str, Any])
def create_filter_rule(body: CreateFilterRuleRequest, org_id: str = Query("default")):
    eng = _get_engine()
    try:
        rule = eng.create_filter_rule(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return rule


@router.get("/rules", response_model=Dict[str, Any])
def list_filter_rules(
    org_id: str = Query("default"),
    rule_type: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
):
    eng = _get_engine()
    try:
        rules = eng.list_filter_rules(org_id, rule_type=rule_type, action=action)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"total": len(rules), "rules": rules}


@router.get("/rules/{rule_id}", response_model=Dict[str, Any])
def get_filter_rule(rule_id: str, org_id: str = Query("default")):
    eng = _get_engine()
    rule = eng.get_filter_rule(org_id, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id!r} not found")
    return rule


# ---------------------------------------------------------------------------
# Events endpoints
# ---------------------------------------------------------------------------

@router.post("/events", response_model=Dict[str, Any])
def log_email_event(body: LogEmailEventRequest, org_id: str = Query("default")):
    eng = _get_engine()
    data = body.model_dump()
    if data.get("processed_at") is None:
        data.pop("processed_at", None)
    try:
        event = eng.log_email_event(org_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return event


@router.get("/events", response_model=Dict[str, Any])
def list_email_events(
    org_id: str = Query("default"),
    filter_result: Optional[str] = Query(None),
    limit: int = Query(50),
):
    eng = _get_engine()
    events = eng.list_email_events(org_id, filter_result=filter_result, limit=limit)
    return {"total": len(events), "events": events}


# ---------------------------------------------------------------------------
# Stats endpoint
# ---------------------------------------------------------------------------

@router.get("/stats", response_model=Dict[str, Any])
def get_email_stats(org_id: str = Query("default")):
    eng = _get_engine()
    return eng.get_email_stats(org_id)
