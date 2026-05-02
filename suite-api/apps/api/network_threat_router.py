"""Network Threat Router — ALDECI.

Endpoints for the Network Threat engine.

Prefix: /api/v1/network-threats
Auth:   _verify_api_key

Routes:
  POST /api/v1/network-threats/threats                       record_threat
  POST /api/v1/network-threats/threats/{id}/resolve          resolve_threat
  GET  /api/v1/network-threats/threats/active                get_active_threats
  POST /api/v1/network-threats/rules                         create_rule
  POST /api/v1/network-threats/rules/{id}/trigger            trigger_rule
  GET  /api/v1/network-threats/rules                         list_rules
  PUT  /api/v1/network-threats/baselines                     update_baseline
  GET  /api/v1/network-threats/baselines/anomalous           get_anomalous_baselines
  GET  /api/v1/network-threats/stats                         get_threat_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/network-threats",
    tags=["Network Threats"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.network_threat_engine import NetworkThreatEngine
        _engine = NetworkThreatEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class ThreatCreate(BaseModel):
    threat_name: str
    threat_type: str
    source_ip: str
    dest_ip: str
    dest_port: int = 0
    protocol: str = "tcp"
    severity: str = "medium"
    confidence: float = 0.5


class RuleCreate(BaseModel):
    rule_name: str
    rule_type: str
    pattern: str
    action: str = "alert"


class BaselineUpdate(BaseModel):
    metric_name: str
    baseline_value: float
    current_value: float


# ---------------------------------------------------------------------------
# Threats
# ---------------------------------------------------------------------------


@router.get("/", dependencies=[Depends(api_key_auth)])
def list_network_threats(org_id: str = Query("default")):
    """Get network threat statistics for the org."""
    return _get_engine().get_threat_stats(org_id=org_id)


@router.post("/threats", dependencies=[Depends(api_key_auth)], status_code=201)
def record_threat(body: ThreatCreate, org_id: str = Query(default="default")):
    """Record or update a network threat."""
    try:
        return _get_engine().record_threat(
            org_id,
            body.threat_name,
            body.threat_type,
            body.source_ip,
            body.dest_ip,
            body.dest_port,
            body.protocol,
            body.severity,
            body.confidence,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/threats/{threat_id}/resolve", dependencies=[Depends(api_key_auth)])
def resolve_threat(threat_id: str, org_id: str = Query(default="default")):
    """Resolve an active threat."""
    try:
        return _get_engine().resolve_threat(threat_id, org_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/threats/active", dependencies=[Depends(api_key_auth)])
def get_active_threats(
     org_id: str = Query(default="default"),
    threat_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
):
    """Return active network threats with optional filters."""
    return _get_engine().get_active_threats(org_id, threat_type=threat_type, severity=severity)


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


@router.post("/rules", dependencies=[Depends(api_key_auth)], status_code=201)
def create_rule(body: RuleCreate, org_id: str = Query(default="default")):
    """Create a new threat detection rule."""
    try:
        return _get_engine().create_rule(
            org_id,
            body.rule_name,
            body.rule_type,
            body.pattern,
            body.action,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/rules/{rule_id}/trigger", dependencies=[Depends(api_key_auth)])
def trigger_rule(rule_id: str, org_id: str = Query(default="default")):
    """Increment match_count for a rule."""
    try:
        return _get_engine().trigger_rule(rule_id, org_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/rules", dependencies=[Depends(api_key_auth)])
def list_rules(
     org_id: str = Query(default="default"),
    enabled: Optional[bool] = Query(None),
):
    """List threat detection rules."""
    return _get_engine().list_rules(org_id, enabled=enabled)


# ---------------------------------------------------------------------------
# Baselines
# ---------------------------------------------------------------------------


@router.put("/baselines", dependencies=[Depends(api_key_auth)])
def update_baseline(body: BaselineUpdate, org_id: str = Query(default="default")):
    """Upsert a network baseline metric."""
    return _get_engine().update_baseline(
        org_id,
        body.metric_name,
        body.baseline_value,
        body.current_value,
    )


@router.get("/baselines/anomalous", dependencies=[Depends(api_key_auth)])
def get_anomalous_baselines(org_id: str = Query(default="default")):
    """Return baselines flagged as anomalous."""
    return _get_engine().get_anomalous_baselines(org_id)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_threat_stats(org_id: str = Query(default="default")):
    """Return aggregated network threat statistics."""
    return _get_engine().get_threat_stats(org_id)
