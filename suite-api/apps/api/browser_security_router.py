"""Browser Security Router — REST endpoints for browser security management.

Endpoints under /api/v1/browser-security:
  POST   /policies                      — Create a browser security policy
  GET    /policies                      — List policies (filter: browser_type, status)
  GET    /policies/{policy_id}          — Get a single policy
  POST   /events                        — Record a browser security event
  GET    /events                        — List events (filter: event_type, severity, blocked)
  POST   /extensions                    — Register a browser extension
  GET    /extensions                    — List extensions (filter: risk_level, status)
  PUT    /extensions/{ext_id}/status    — Update extension status
  GET    /stats                         — Browser security statistics
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/browser-security",
    tags=["Browser Security"],
    dependencies=[Depends(api_key_auth)],
)

_engine_instance = None


def _get_engine():
    global _engine_instance
    if _engine_instance is None:
        try:
            from core.browser_security_engine import BrowserSecurityEngine
            _engine_instance = BrowserSecurityEngine()
        except Exception as exc:
            _logger.error("BrowserSecurityEngine unavailable: %s", exc)
            raise HTTPException(
                status_code=503, detail=f"Browser security engine unavailable: {exc}"
            )
    return _engine_instance


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CreatePolicyRequest(BaseModel):
    policy_name: str
    browser_type: str = "all"
    enforcement_level: str = "recommended"
    settings: Dict[str, Any] = {}
    status: str = "active"


class RecordEventRequest(BaseModel):
    event_type: str
    severity: str = "medium"
    policy_id: str = ""
    user_id: str = ""
    device_id: str = ""
    url: str = ""
    details: str = ""
    blocked: bool = False
    event_at: Optional[str] = None


class RegisterExtensionRequest(BaseModel):
    extension_id: str
    name: str
    version: str = ""
    browser_type: str = "all"
    risk_level: str = "medium"
    permissions: List[str] = []
    status: str = "under_review"
    publisher: str = ""


class UpdateExtensionStatusRequest(BaseModel):
    status: str


# ---------------------------------------------------------------------------
# Policy endpoints
# ---------------------------------------------------------------------------

@router.post("/policies", response_model=Dict[str, Any])
def create_policy(body: CreatePolicyRequest, org_id: str = Query("default")):
    eng = _get_engine()
    try:
        policy = eng.create_policy(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return policy


@router.get("/policies", response_model=Dict[str, Any])
def list_policies(
    org_id: str = Query("default"),
    browser_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    eng = _get_engine()
    policies = eng.list_policies(org_id, browser_type=browser_type, status=status)
    return {"total": len(policies), "policies": policies}


@router.get("/policies/{policy_id}", response_model=Dict[str, Any])
def get_policy(policy_id: str, org_id: str = Query("default")):
    eng = _get_engine()
    policy = eng.get_policy(org_id, policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail=f"Policy {policy_id!r} not found")
    return policy


# ---------------------------------------------------------------------------
# Event endpoints
# ---------------------------------------------------------------------------

@router.post("/events", response_model=Dict[str, Any])
def record_event(body: RecordEventRequest, org_id: str = Query("default")):
    eng = _get_engine()
    data = body.model_dump()
    if data.get("event_at") is None:
        data.pop("event_at", None)
    try:
        event = eng.record_event(org_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return event


@router.get("/events", response_model=Dict[str, Any])
def list_events(
    org_id: str = Query("default"),
    event_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    blocked: Optional[bool] = Query(None),
):
    eng = _get_engine()
    events = eng.list_events(org_id, event_type=event_type, severity=severity, blocked=blocked)
    return {"total": len(events), "events": events}


# ---------------------------------------------------------------------------
# Extension endpoints
# ---------------------------------------------------------------------------

@router.post("/extensions", response_model=Dict[str, Any])
def register_extension(body: RegisterExtensionRequest, org_id: str = Query("default")):
    eng = _get_engine()
    try:
        ext = eng.register_extension(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return ext


@router.get("/extensions", response_model=Dict[str, Any])
def list_extensions(
    org_id: str = Query("default"),
    risk_level: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    eng = _get_engine()
    extensions = eng.list_extensions(org_id, risk_level=risk_level, status=status)
    return {"total": len(extensions), "extensions": extensions}


@router.put("/extensions/{ext_id}/status", response_model=Dict[str, Any])
def update_extension_status(
    ext_id: str,
    body: UpdateExtensionStatusRequest,
    org_id: str = Query("default"),
):
    eng = _get_engine()
    try:
        result = eng.update_extension_status(org_id, ext_id, body.status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if result is None:
        raise HTTPException(status_code=404, detail=f"Extension {ext_id!r} not found")
    return result


# ---------------------------------------------------------------------------
# Stats endpoint
# ---------------------------------------------------------------------------

@router.get("/stats", response_model=Dict[str, Any])
def get_browser_stats(org_id: str = Query("default")):
    eng = _get_engine()
    return eng.get_browser_stats(org_id)
