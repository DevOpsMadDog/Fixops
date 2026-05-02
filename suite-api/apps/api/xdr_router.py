"""XDR Correlation Engine API router — ALDECI.

Endpoints at /api/v1/xdr/* for signal ingestion, incident management,
signal-to-incident linking, correlation rules, and stats.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from core.xdr_engine import XDREngine
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/xdr", tags=["xdr"])
_engine = None  # lazy-initialised on first request


def _get_engine():
    global _engine
    if _engine is None:
        _engine = XDREngine()
    return _engine


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class IngestSignalRequest(BaseModel):
    source_type: str = Field(default="endpoint", description="endpoint/network/cloud/identity/email/application/threat_intel")
    source_system: str = Field(default="")
    signal_type: str = Field(default="anomaly", description="malware/lateral_movement/credential_theft/exfiltration/c2/anomaly/policy_violation")
    severity: str = Field(default="medium", description="critical/high/medium/low/info")
    entity_id: str = Field(default="", description="IP, hostname, username, file hash, etc.")
    entity_type: str = Field(default="host", description="host/ip/user/file/process/domain")
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    ingested_at: Optional[str] = None


class CreateIncidentRequest(BaseModel):
    title: str = Field(..., min_length=1)
    description: str = Field(default="")
    attack_stage: str = Field(default="initial_access")
    severity: str = Field(default="medium")
    assigned_to: str = Field(default="")
    affected_entities: List[str] = Field(default_factory=list)


class UpdateIncidentStatusRequest(BaseModel):
    status: str = Field(..., description="new/investigating/contained/resolved")
    assigned_to: Optional[str] = None


class LinkSignalRequest(BaseModel):
    signal_id: str = Field(..., min_length=1)


class CreateRuleRequest(BaseModel):
    name: str = Field(..., min_length=1)
    description: str = Field(default="")
    conditions: Dict[str, Any] = Field(default_factory=dict)
    incident_severity: str = Field(default="medium")
    mitre_tactic: str = Field(default="")
    enabled: int = Field(default=1)


# ---------------------------------------------------------------------------
# Signals
# ---------------------------------------------------------------------------


@router.post("/signals", summary="Ingest a security signal")
def ingest_signal(
    body: IngestSignalRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Ingest a cross-domain security signal and trigger auto-correlation."""
    return _get_engine().ingest_signal(org_id, body.model_dump())


@router.get("/signals", summary="List security signals")
def list_signals(
    source_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """List ingested signals with optional source_type and severity filters."""
    return _get_engine().list_signals(org_id, source_type=source_type, severity=severity, limit=limit)


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------


@router.post("/incidents", summary="Create an XDR incident")
def create_incident(
    body: CreateIncidentRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Manually create a new XDR incident."""
    return _get_engine().create_incident(org_id, body.model_dump())


@router.get("/incidents", summary="List XDR incidents")
def list_incidents(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    attack_stage: Optional[str] = Query(None),
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """List incidents with optional status, severity, and attack_stage filters."""
    return _get_engine().list_incidents(
        org_id, status=status, severity=severity, attack_stage=attack_stage
    )


@router.get("/incidents/{incident_id}", summary="Get incident with linked signals")
def get_incident(
    incident_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Return a full incident record including all linked signals."""
    incident = _get_engine().get_incident(org_id, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id!r} not found")
    return incident


@router.patch("/incidents/{incident_id}/status", summary="Update incident status")
def update_incident_status(
    incident_id: str,
    body: UpdateIncidentStatusRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Update the status (and optionally assignee) of an XDR incident."""
    try:
        updated = _get_engine().update_incident_status(
            org_id, incident_id, body.status, assigned_to=body.assigned_to
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if not updated:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id!r} not found")
    return {"incident_id": incident_id, "status": body.status}


@router.post("/incidents/{incident_id}/signals", summary="Link a signal to an incident")
def link_signal_to_incident(
    incident_id: str,
    body: LinkSignalRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Link an existing signal to an incident (increments signal_count)."""
    linked = _get_engine().link_signal_to_incident(org_id, incident_id, body.signal_id)
    if not linked:
        raise HTTPException(
            status_code=404,
            detail=f"Incident {incident_id!r} or signal {body.signal_id!r} not found",
        )
    return {"incident_id": incident_id, "signal_id": body.signal_id, "linked": True}


# ---------------------------------------------------------------------------
# Correlation rules
# ---------------------------------------------------------------------------


@router.post("/rules", summary="Create a correlation rule")
def create_rule(
    body: CreateRuleRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Create a new correlation rule for automated incident detection."""
    return _get_engine().create_rule(org_id, body.model_dump())


@router.get("/rules", summary="List correlation rules")
def list_rules(
    enabled_only: bool = Query(True, description="Return only enabled rules"),
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """List correlation rules for the org."""
    return _get_engine().list_rules(org_id, enabled_only=enabled_only)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@router.get("/stats", summary="XDR statistics")
def get_xdr_stats(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Return aggregate XDR statistics for the org."""
    return _get_engine().get_xdr_stats(org_id)
