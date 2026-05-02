"""API Abuse Detection Router — REST endpoints for API abuse detection.

Endpoints under /api/v1/api-abuse:
  POST   /endpoints                         — Register an API endpoint
  GET    /endpoints                         — List endpoints (filter: service_name, status)
  GET    /endpoints/{endpoint_id}           — Get a single endpoint
  POST   /incidents                         — Record an abuse incident
  GET    /incidents                         — List incidents (filter: endpoint_id, abuse_type, status)
  PUT    /incidents/{incident_id}/status    — Update incident status
  POST   /rules                             — Create a detection rule
  GET    /rules                             — List rules (filter: rule_type, enabled)
  GET    /stats                             — API abuse detection statistics
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/api-abuse",
    tags=["API Abuse Detection"],
    dependencies=[Depends(api_key_auth)],
)

_engine_instance = None


def _get_engine():
    global _engine_instance
    if _engine_instance is None:
        try:
            from core.api_abuse_detection_engine import APIAbuseDetectionEngine
            _engine_instance = APIAbuseDetectionEngine()
        except Exception as exc:
            _logger.error("APIAbuseDetectionEngine unavailable: %s", exc)
            raise HTTPException(status_code=503, detail=f"API abuse detection engine unavailable: {exc}")
    return _engine_instance


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RegisterEndpointRequest(BaseModel):
    path: str
    method: str
    service_name: str = ""
    rate_limit: int = 1000
    abuse_score: float = 0.0
    status: str = "monitored"


class RecordIncidentRequest(BaseModel):
    endpoint_id: str
    abuse_type: str
    severity: str
    source_ip: Optional[str] = None
    request_count: int = 0
    time_window_seconds: int = 60
    blocked: bool = False
    status: str = "open"
    detected_at: Optional[str] = None


class UpdateIncidentStatusRequest(BaseModel):
    status: str


class CreateRuleRequest(BaseModel):
    rule_name: str
    rule_type: str
    threshold: float = 0.0
    action: str
    enabled: bool = True


# ---------------------------------------------------------------------------
# Endpoint endpoints
# ---------------------------------------------------------------------------

@router.post("/endpoints", response_model=Dict[str, Any])
def register_endpoint(body: RegisterEndpointRequest, org_id: str = Query("default")):
    eng = _get_engine()
    try:
        endpoint = eng.register_endpoint(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return endpoint


@router.get("/endpoints", response_model=Dict[str, Any])
def list_endpoints(
    org_id: str = Query("default"),
    service_name: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    eng = _get_engine()
    endpoints = eng.list_endpoints(org_id, service_name=service_name, status=status)
    return {"total": len(endpoints), "endpoints": endpoints}


@router.get("/endpoints/{endpoint_id}", response_model=Dict[str, Any])
def get_endpoint(endpoint_id: str, org_id: str = Query("default")):
    eng = _get_engine()
    endpoint = eng.get_endpoint(org_id, endpoint_id)
    if endpoint is None:
        raise HTTPException(status_code=404, detail=f"Endpoint {endpoint_id!r} not found")
    return endpoint


# ---------------------------------------------------------------------------
# Incident endpoints
# ---------------------------------------------------------------------------

@router.post("/incidents", response_model=Dict[str, Any])
def record_incident(body: RecordIncidentRequest, org_id: str = Query("default")):
    eng = _get_engine()
    data = body.model_dump()
    if data.get("detected_at") is None:
        data.pop("detected_at", None)
    try:
        incident = eng.record_incident(org_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return incident


@router.get("/incidents", response_model=Dict[str, Any])
def list_incidents(
    org_id: str = Query("default"),
    endpoint_id: Optional[str] = Query(None),
    abuse_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    eng = _get_engine()
    incidents = eng.list_incidents(
        org_id, endpoint_id=endpoint_id, abuse_type=abuse_type, status=status
    )
    return {"total": len(incidents), "incidents": incidents}


@router.put("/incidents/{incident_id}/status", response_model=Dict[str, Any])
def update_incident_status(
    incident_id: str,
    body: UpdateIncidentStatusRequest,
    org_id: str = Query("default"),
):
    eng = _get_engine()
    try:
        result = eng.update_incident_status(org_id, incident_id, body.status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return result


# ---------------------------------------------------------------------------
# Rule endpoints
# ---------------------------------------------------------------------------

@router.post("/rules", response_model=Dict[str, Any])
def create_rule(body: CreateRuleRequest, org_id: str = Query("default")):
    eng = _get_engine()
    try:
        rule = eng.create_rule(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return rule


@router.get("/rules", response_model=Dict[str, Any])
def list_rules(
    org_id: str = Query("default"),
    rule_type: Optional[str] = Query(None),
    enabled: Optional[bool] = Query(None),
):
    eng = _get_engine()
    rules = eng.list_rules(org_id, rule_type=rule_type, enabled=enabled)
    return {"total": len(rules), "rules": rules}


# ---------------------------------------------------------------------------
# Stats endpoint
# ---------------------------------------------------------------------------

@router.get("/stats", response_model=Dict[str, Any])
def get_abuse_stats(org_id: str = Query("default")):
    eng = _get_engine()
    return eng.get_abuse_stats(org_id)
