"""Endpoint Security / EDR Router — ALDECI.

10 endpoints under /api/v1/endpoint-security:
  GET    /endpoints                          list endpoints (org scoped, optional status filter)
  POST   /endpoints                          register a new endpoint
  PATCH  /endpoints/{endpoint_id}/status     update endpoint status
  GET    /alerts                             list alerts (status + severity filters)
  POST   /alerts                             create an EDR alert
  POST   /alerts/{alert_id}/resolve          resolve an alert
  GET    /stats                              EDR summary statistics
  GET    /policies                           list EDR policies
  POST   /policies                           create an EDR policy
  GET    /endpoints/{endpoint_id}/timeline   alert timeline for an endpoint
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "endpoint_security_router: auth_deps not available, "
        "relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.endpoint_security_engine import EndpointSecurityEngine

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/endpoint-security",
    tags=["endpoint-security"],
    dependencies=_AUTH_DEP,
)

_engine: Optional[EndpointSecurityEngine] = None


def _get_engine() -> EndpointSecurityEngine:
    global _engine
    if _engine is None:
        _engine = EndpointSecurityEngine()
    return _engine


# ============================================================================
# REQUEST / RESPONSE MODELS
# ============================================================================


class RegisterEndpointRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    hostname: str = Field(..., description="Endpoint hostname")
    ip: str = Field("", description="IP address")
    os: str = Field("", description="Operating system")
    agent_version: str = Field("", description="EDR agent version")
    status: str = Field("active", description="active or inactive")
    risk_score: int = Field(0, ge=0, le=100, description="Risk score 0–100")
    last_seen: str = Field("", description="ISO-8601 timestamp of last check-in")
    policy_id: str = Field("", description="Assigned policy ID")


class UpdateStatusRequest(BaseModel):
    status: str = Field(..., description="New status: active or inactive")


class CreateAlertRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    endpoint_id: str = Field(..., description="Target endpoint ID")
    severity: str = Field("medium", description="critical/high/medium/low")
    alert_type: str = Field(
        "policy_violation",
        description="malware/ransomware/lateral_movement/privilege_escalation/data_exfil/policy_violation",
    )
    description: str = Field("", description="Alert description")
    status: str = Field("open", description="open/investigating/resolved")


class ResolveAlertRequest(BaseModel):
    resolution_note: str = Field(..., description="Resolution note / root cause")


class CreatePolicyRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    name: str = Field(..., description="Policy name")
    description: str = Field("", description="Policy description")
    rules: Dict[str, Any] = Field(default_factory=dict, description="Policy rules (JSON)")
    enabled: bool = Field(True, description="Whether the policy is active")


# ============================================================================
# ENDPOINTS
# ============================================================================


@router.get("/endpoints", response_model=List[Dict[str, Any]], summary="List endpoints")
def list_endpoints(
    org_id: str = Query("default"),
    status: Optional[str] = Query(None, description="Filter by status: active or inactive"),
    eng: EndpointSecurityEngine = Depends(_get_engine),
):
    return eng.list_endpoints(org_id, status=status)


@router.post("/endpoints", response_model=Dict[str, Any], summary="Register endpoint")
def register_endpoint(
    body: RegisterEndpointRequest,
    eng: EndpointSecurityEngine = Depends(_get_engine),
):
    data = body.model_dump(exclude={"org_id"})
    return eng.register_endpoint(body.org_id, data)


@router.patch(
    "/endpoints/{endpoint_id}/status",
    response_model=Dict[str, Any],
    summary="Update endpoint status",
)
def update_endpoint_status(
    endpoint_id: str,
    body: UpdateStatusRequest,
    org_id: str = Query("default"),
    eng: EndpointSecurityEngine = Depends(_get_engine),
):
    updated = eng.update_endpoint_status(org_id, endpoint_id, body.status)
    if not updated:
        raise HTTPException(
            status_code=404,
            detail=f"Endpoint '{endpoint_id}' not found or invalid status '{body.status}'",
        )
    return {"endpoint_id": endpoint_id, "status": body.status, "updated": True}


@router.get("/alerts", response_model=List[Dict[str, Any]], summary="List EDR alerts")
def list_alerts(
    org_id: str = Query("default"),
    status: Optional[str] = Query(None, description="open/investigating/resolved"),
    severity: Optional[str] = Query(None, description="critical/high/medium/low"),
    eng: EndpointSecurityEngine = Depends(_get_engine),
):
    return eng.list_alerts(org_id, status=status, severity=severity)


@router.post("/alerts", response_model=Dict[str, Any], summary="Create EDR alert")
def create_alert(
    body: CreateAlertRequest,
    eng: EndpointSecurityEngine = Depends(_get_engine),
):
    data = body.model_dump(exclude={"org_id"})
    return eng.create_alert(body.org_id, data)


@router.post(
    "/alerts/{alert_id}/resolve",
    response_model=Dict[str, Any],
    summary="Resolve an alert",
)
def resolve_alert(
    alert_id: str,
    body: ResolveAlertRequest,
    org_id: str = Query("default"),
    eng: EndpointSecurityEngine = Depends(_get_engine),
):
    resolved = eng.resolve_alert(org_id, alert_id, body.resolution_note)
    if not resolved:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")
    return {"alert_id": alert_id, "status": "resolved", "resolution_note": body.resolution_note}


@router.get("/stats", response_model=Dict[str, Any], summary="EDR statistics")
def get_edr_stats(
    org_id: str = Query("default"),
    eng: EndpointSecurityEngine = Depends(_get_engine),
):
    return eng.get_edr_stats(org_id)


@router.get("/policies", response_model=List[Dict[str, Any]], summary="List EDR policies")
def list_policies(
    org_id: str = Query("default"),
    eng: EndpointSecurityEngine = Depends(_get_engine),
):
    return eng.list_policies(org_id)


@router.post("/policies", response_model=Dict[str, Any], summary="Create EDR policy")
def create_policy(
    body: CreatePolicyRequest,
    eng: EndpointSecurityEngine = Depends(_get_engine),
):
    data = body.model_dump(exclude={"org_id"})
    return eng.create_policy(body.org_id, data)


@router.get(
    "/endpoints/{endpoint_id}/timeline",
    response_model=List[Dict[str, Any]],
    summary="Alert timeline for an endpoint",
)
def get_endpoint_timeline(
    endpoint_id: str,
    org_id: str = Query("default"),
    eng: EndpointSecurityEngine = Depends(_get_engine),
):
    return eng.get_endpoint_timeline(org_id, endpoint_id)
