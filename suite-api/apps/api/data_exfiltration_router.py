"""Data Exfiltration Router — REST endpoints for DLP / data exfiltration management.

Endpoints under /api/v1/data-exfiltration:
  POST   /incidents                     — Record an exfiltration incident
  GET    /incidents                     — List incidents (filter: severity, status, incident_type)
  GET    /incidents/{incident_id}       — Get a single incident
  PUT    /incidents/{incident_id}/status — Update incident status
  POST   /policies                      — Create a DLP policy
  GET    /policies                      — List policies (filter: enabled)
  POST   /indicators                    — Add an exfiltration indicator
  GET    /indicators                    — List indicators (filter: incident_id)
  GET    /stats                         — Data exfiltration statistics
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/data-exfiltration",
    tags=["Data Exfiltration"],
    dependencies=[Depends(api_key_auth)],
)

_engine_instance = None


def _get_engine():
    global _engine_instance
    if _engine_instance is None:
        try:
            from core.data_exfiltration_engine import DataExfiltrationEngine
            _engine_instance = DataExfiltrationEngine()
        except Exception as exc:
            _logger.error("DataExfiltrationEngine unavailable: %s", exc)
            raise HTTPException(
                status_code=503, detail=f"Data exfiltration engine unavailable: {exc}"
            )
    return _engine_instance


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RecordIncidentRequest(BaseModel):
    incident_type: str
    severity: str = "medium"
    user_id: str = ""
    data_classification: str = "internal"
    estimated_volume_mb: float = 0.0
    destination: str = ""
    detection_method: str = "dlp"
    status: str = "detected"
    blocked: bool = False
    detected_at: Optional[str] = None


class UpdateIncidentStatusRequest(BaseModel):
    status: str


class CreatePolicyRequest(BaseModel):
    policy_name: str
    action: str = "alert"
    data_classification: str = "internal"
    channel: str = "all"
    enabled: bool = True


class AddIndicatorRequest(BaseModel):
    incident_id: str = ""
    indicator_type: str
    value: str = ""
    confidence_score: float = 50.0


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
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    incident_type: Optional[str] = Query(None),
):
    eng = _get_engine()
    incidents = eng.list_incidents(
        org_id, severity=severity, status=status, incident_type=incident_type
    )
    return {"total": len(incidents), "incidents": incidents}


@router.get("/incidents/{incident_id}", response_model=Dict[str, Any])
def get_incident(incident_id: str, org_id: str = Query("default")):
    eng = _get_engine()
    incident = eng.get_incident(org_id, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id!r} not found")
    return incident


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
    if result is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id!r} not found")
    return result


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
    enabled: Optional[bool] = Query(None),
):
    eng = _get_engine()
    policies = eng.list_policies(org_id, enabled=enabled)
    return {"total": len(policies), "policies": policies}


# ---------------------------------------------------------------------------
# Indicator endpoints
# ---------------------------------------------------------------------------

@router.post("/indicators", response_model=Dict[str, Any])
def add_indicator(body: AddIndicatorRequest, org_id: str = Query("default")):
    eng = _get_engine()
    try:
        indicator = eng.add_indicator(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return indicator


@router.get("/indicators", response_model=Dict[str, Any])
def list_indicators(
    org_id: str = Query("default"),
    incident_id: Optional[str] = Query(None),
):
    eng = _get_engine()
    indicators = eng.list_indicators(org_id, incident_id=incident_id)
    return {"total": len(indicators), "indicators": indicators}


# ---------------------------------------------------------------------------
# Stats endpoint
# ---------------------------------------------------------------------------

@router.get("/stats", response_model=Dict[str, Any])
def get_exfil_stats(org_id: str = Query("default")):
    eng = _get_engine()
    return eng.get_exfil_stats(org_id)
