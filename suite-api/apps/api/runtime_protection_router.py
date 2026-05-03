"""
Runtime Protection API — host EDR endpoints.

Provides 10 REST endpoints for the HostRuntimeEngine:
  POST   /api/v1/runtime/events            — ingest a host event
  POST   /api/v1/runtime/events/evaluate   — ingest + evaluate policies
  POST   /api/v1/runtime/policies          — create a custom policy
  GET    /api/v1/runtime/policies          — list policies (org)
  GET    /api/v1/runtime/alerts            — list active (unack) alerts
  POST   /api/v1/runtime/alerts/{id}/ack   — acknowledge an alert
  GET    /api/v1/runtime/threats           — threat timeline
  GET    /api/v1/runtime/stats             — aggregate stats
  GET    /api/v1/runtime/anomalies         — anomaly detection
  GET    /api/v1/runtime/hosts/{host}/process-tree — process tree

Compliance: SOC2 CC6.8, NIST CSF DE.CM-1
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from core.runtime_protection import (
    EventType,
    HostRuntimeEngine,
    PolicyAction,
    RuntimeEvent,
    RuntimePolicy,
    ThreatLevel,
)
from fastapi import APIRouter, Depends, HTTPException, Query

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/runtime", tags=["runtime-protection"])

# Module-level engine instance (in-memory by default; override db_path in prod)
_engine = None  # lazy-initialised on first request


def _get_engine():
    global _engine
    if _engine is None:
        _engine = HostRuntimeEngine()
    return _engine


# ---------------------------------------------------------------------------
# Dependency
# ---------------------------------------------------------------------------


def _get_org_id(org_id: Optional[str] = Query(None)) -> str:
    return org_id or "default"


# ---------------------------------------------------------------------------
# Request / response models (inline — no separate models file needed)
# ---------------------------------------------------------------------------


from pydantic import BaseModel, Field


class EventIngestRequest(BaseModel):
    """Request body for ingesting a runtime event."""

    event_type: EventType
    source_host: str = Field(..., min_length=1)
    process_name: str = Field(..., min_length=1)
    user: str = Field(..., min_length=1)
    details: Dict[str, Any] = Field(default_factory=dict)
    threat_level: ThreatLevel = ThreatLevel.NONE


class PolicyCreateRequest(BaseModel):
    """Request body for creating a custom runtime policy."""

    name: str = Field(..., min_length=1)
    event_type: EventType
    conditions: Dict[str, Any] = Field(default_factory=dict)
    action: PolicyAction = PolicyAction.ALERT
    enabled: bool = True


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", response_model=Dict[str, Any])
async def get_root() -> Dict[str, Any]:
    """
    Runtime protection service index.

    Returns service metadata, available endpoint paths, and capability summary
    for both the Host EDR layer and the RASP HTTP inspection layer.

    Compliance: SOC2 CC6.8, NIST CSF DE.CM-1
    """
    return {
        "service": "eks-runtime-protection",
        "status": "operational",
        "layers": ["host-edr", "rasp"],
        "endpoints": [
            "GET  /api/v1/runtime/",
            "POST /api/v1/runtime/events",
            "POST /api/v1/runtime/events/evaluate",
            "POST /api/v1/runtime/policies",
            "GET  /api/v1/runtime/policies",
            "GET  /api/v1/runtime/alerts",
            "POST /api/v1/runtime/alerts/{id}/ack",
            "GET  /api/v1/runtime/threats",
            "GET  /api/v1/runtime/stats",
            "GET  /api/v1/runtime/anomalies",
            "GET  /api/v1/runtime/hosts/{host}/process-tree",
        ],
        "capabilities": [
            "process-exec-monitoring",
            "file-access-monitoring",
            "network-connect-monitoring",
            "privilege-escalation-detection",
            "container-escape-detection",
            "policy-evaluation",
            "anomaly-detection",
            "process-tree-reconstruction",
        ],
        "compliance": ["SOC2-CC6.8", "NIST-CSF-DE.CM-1", "CIS-Controls-8"],
    }


@router.post("/events", response_model=Dict[str, Any], status_code=201)
async def ingest_event(
    body: EventIngestRequest,
    org_id: str = Depends(_get_org_id),
) -> Dict[str, Any]:
    """
    Ingest a single runtime host event.

    Persists the event without running policy evaluation.
    Use /events/evaluate to also trigger alert generation.
    """
    event = RuntimeEvent(
        event_type=body.event_type,
        source_host=body.source_host,
        process_name=body.process_name,
        user=body.user,
        details=body.details,
        threat_level=body.threat_level,
        org_id=org_id,
    )
    stored = _get_engine().ingest_event(event)
    return {"event_id": stored.id, "org_id": org_id, "status": "ingested"}


@router.post("/events/evaluate", response_model=Dict[str, Any], status_code=201)
async def ingest_and_evaluate(
    body: EventIngestRequest,
    org_id: str = Depends(_get_org_id),
) -> Dict[str, Any]:
    """
    Ingest a runtime event and immediately evaluate all policies against it.

    Returns the event ID and any alerts generated.
    """
    event = RuntimeEvent(
        event_type=body.event_type,
        source_host=body.source_host,
        process_name=body.process_name,
        user=body.user,
        details=body.details,
        threat_level=body.threat_level,
        org_id=org_id,
    )
    _get_engine().ingest_event(event)
    alerts = _get_engine().evaluate_policies(event, org_id)
    return {
        "event_id": event.id,
        "org_id": org_id,
        "alerts_generated": len(alerts),
        "alerts": [
            {
                "id": a.id,
                "policy_id": a.policy_id,
                "threat_level": a.threat_level.value,
                "message": a.message,
            }
            for a in alerts
        ],
    }


@router.post("/policies", response_model=Dict[str, Any], status_code=201)
async def create_policy(
    body: PolicyCreateRequest,
    org_id: str = Depends(_get_org_id),
) -> Dict[str, Any]:
    """Create a custom runtime detection policy."""
    policy = RuntimePolicy(
        name=body.name,
        event_type=body.event_type,
        conditions=body.conditions,
        action=body.action,
        enabled=body.enabled,
        org_id=org_id,
    )
    created = _get_engine().create_policy(policy)
    return {
        "policy_id": created.id,
        "name": created.name,
        "event_type": created.event_type.value,
        "action": created.action.value,
        "enabled": created.enabled,
        "org_id": org_id,
    }


@router.get("/policies", response_model=Dict[str, Any])
async def list_policies(
    org_id: str = Depends(_get_org_id),
) -> Dict[str, Any]:
    """List all runtime policies for an org (includes built-in defaults)."""
    policies = _get_engine().list_policies(org_id)
    return {
        "org_id": org_id,
        "total": len(policies),
        "policies": [
            {
                "id": p.id,
                "name": p.name,
                "event_type": p.event_type.value,
                "action": p.action.value,
                "enabled": p.enabled,
                "org_id": p.org_id,
            }
            for p in policies
        ],
    }


@router.get("/alerts", response_model=Dict[str, Any])
async def get_active_alerts(
    org_id: str = Depends(_get_org_id),
) -> Dict[str, Any]:
    """Get all unacknowledged runtime alerts for an org."""
    alerts = _get_engine().get_active_alerts(org_id)
    return {
        "org_id": org_id,
        "total": len(alerts),
        "alerts": [
            {
                "id": a.id,
                "event_id": a.event_id,
                "policy_id": a.policy_id,
                "threat_level": a.threat_level.value,
                "message": a.message,
                "acknowledged": a.acknowledged,
                "created_at": a.created_at.isoformat(),
            }
            for a in alerts
        ],
    }


@router.post("/alerts/{alert_id}/ack", response_model=Dict[str, Any])
async def acknowledge_alert(
    alert_id: str,
    org_id: str = Depends(_get_org_id),
) -> Dict[str, Any]:
    """Acknowledge a runtime alert by ID."""
    updated = _get_engine().acknowledge_alert(alert_id)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")
    return {"alert_id": alert_id, "acknowledged": True, "org_id": org_id}


@router.get("/threats", response_model=Dict[str, Any])
async def get_threat_timeline(
    hours: int = Query(24, ge=1, le=168),
    org_id: str = Depends(_get_org_id),
) -> Dict[str, Any]:
    """
    Get recent threat events (non-none threat level) within a time window.

    Default window: 24 hours. Maximum: 168 hours (7 days).
    """
    events = _get_engine().get_threat_timeline(org_id, hours=hours)
    return {
        "org_id": org_id,
        "hours": hours,
        "total": len(events),
        "events": [
            {
                "id": e.id,
                "event_type": e.event_type.value,
                "source_host": e.source_host,
                "process_name": e.process_name,
                "user": e.user,
                "threat_level": e.threat_level.value,
                "detected_at": e.detected_at.isoformat(),
            }
            for e in events
        ],
    }


@router.get("/stats", response_model=Dict[str, Any])
async def get_runtime_stats(
    org_id: str = Depends(_get_org_id),
) -> Dict[str, Any]:
    """Get aggregate runtime protection statistics for an org."""
    return _get_engine().get_runtime_stats(org_id)


@router.get("/anomalies", response_model=Dict[str, Any])
async def detect_anomalies(
    org_id: str = Depends(_get_org_id),
) -> Dict[str, Any]:
    """Detect unusual patterns in the last hour of runtime event data."""
    anomalies = _get_engine().detect_anomalies(org_id)
    return {
        "org_id": org_id,
        "total": len(anomalies),
        "anomalies": anomalies,
    }


@router.get("/hosts/{host}/process-tree", response_model=Dict[str, Any])
async def get_process_tree(
    host: str,
    org_id: str = Depends(_get_org_id),
) -> Dict[str, Any]:
    """
    Get the process execution tree for a specific host.

    Returns process_exec events with parent-child relationships
    reconstructed via pid/ppid fields in event details.
    """
    tree = _get_engine().get_process_tree(host, org_id)
    return {
        "org_id": org_id,
        "host": host,
        "total_processes": len(tree),
        "process_tree": tree,
    }
