"""Cloud Security Analytics API router — ALDECI.

Endpoints at /api/v1/cloud-analytics/* for cloud security events, anomalies, rules, and stats.
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
        "cloud_security_analytics_router: auth_deps not available, relying on app-level auth"
    )
    _AUTH_DEP = []

from core.cloud_security_analytics_engine import CloudSecurityAnalyticsEngine

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/cloud-analytics",
    tags=["Cloud Security Analytics"],
    dependencies=_AUTH_DEP,
)

_engine: Optional[CloudSecurityAnalyticsEngine] = None


def _get_engine() -> CloudSecurityAnalyticsEngine:
    global _engine
    if _engine is None:
        _engine = CloudSecurityAnalyticsEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class RecordEventRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    event_source: str = Field("cloudtrail", description="Cloud event source")
    event_type: str = Field("api_call", description="Event type")
    severity: str = Field("low", description="Severity: critical/high/medium/low")
    account_id: str = Field("", description="Cloud account ID")
    region: str = Field("", description="Cloud region")
    resource_type: str = Field("", description="Resource type")
    resource_id: str = Field("", description="Resource ID")
    actor: str = Field("", description="Actor (user/role/service)")
    risk_score: float = Field(0.0, ge=0.0, le=100.0, description="Risk score 0-100")
    details: str = Field("", description="Event details / raw payload")
    event_at: Optional[str] = Field(None, description="ISO-8601 event timestamp")


class RecordAnomalyRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    anomaly_type: str = Field("unusual_api", description="Anomaly type")
    severity: str = Field("medium", description="Severity: critical/high/medium/low")
    account_id: str = Field("", description="Cloud account ID")
    confidence_score: float = Field(0.0, ge=0.0, le=100.0, description="Confidence 0-100")
    affected_resources: List[str] = Field(default_factory=list, description="Affected resource IDs")
    status: str = Field("open", description="Anomaly status")
    detected_at: Optional[str] = Field(None, description="ISO-8601 detection timestamp")


class UpdateAnomalyStatusRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    status: str = Field(..., description="open/investigating/confirmed/false_positive")


class CreateRuleRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    rule_name: str = Field(..., min_length=1, description="Rule name")
    rule_type: str = Field("detection", description="detection/compliance/baseline/anomaly")
    condition: str = Field("", description="Rule condition expression")
    severity: str = Field("medium", description="Severity: critical/high/medium/low")
    event_sources: List[str] = Field(default_factory=list, description="Applicable event sources")
    enabled: bool = Field(True, description="Whether the rule is active")


class TriggerRuleRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------


@router.post("/events", summary="Record a cloud security event")
def record_event(body: RecordEventRequest) -> Dict[str, Any]:
    """Ingest a cloud security event from any supported source."""
    engine = _get_engine()
    try:
        return engine.record_event(body.org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to record event")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/events", summary="List cloud security events")
def list_events(
    org_id: str = Query("default", description="Organisation ID"),
    event_source: Optional[str] = Query(None, description="Filter by event source"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
) -> List[Dict[str, Any]]:
    """List cloud security events with optional filters."""
    engine = _get_engine()
    try:
        return engine.list_events(
            org_id, event_source=event_source, severity=severity, event_type=event_type
        )
    except Exception as exc:
        logger.exception("Failed to list events")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Anomalies
# ---------------------------------------------------------------------------


@router.post("/anomalies", summary="Record a cloud security anomaly")
def record_anomaly(body: RecordAnomalyRequest) -> Dict[str, Any]:
    """Record a detected cloud security anomaly."""
    engine = _get_engine()
    try:
        return engine.record_anomaly(body.org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to record anomaly")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/anomalies", summary="List cloud security anomalies")
def list_anomalies(
    org_id: str = Query("default", description="Organisation ID"),
    anomaly_type: Optional[str] = Query(None, description="Filter by anomaly type"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status: Optional[str] = Query(None, description="Filter by status"),
) -> List[Dict[str, Any]]:
    """List anomalies with optional filters."""
    engine = _get_engine()
    try:
        return engine.list_anomalies(
            org_id, anomaly_type=anomaly_type, severity=severity, status=status
        )
    except Exception as exc:
        logger.exception("Failed to list anomalies")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.put("/anomalies/{anomaly_id}/status", summary="Update anomaly status")
def update_anomaly_status(anomaly_id: str, body: UpdateAnomalyStatusRequest) -> Dict[str, Any]:
    """Update the status of a cloud security anomaly."""
    engine = _get_engine()
    try:
        return engine.update_anomaly_status(body.org_id, anomaly_id, body.status)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to update anomaly status %s", anomaly_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


@router.post("/rules", summary="Create a detection rule")
def create_rule(body: CreateRuleRequest) -> Dict[str, Any]:
    """Create a cloud security detection/compliance/baseline/anomaly rule."""
    engine = _get_engine()
    try:
        return engine.create_rule(body.org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to create rule")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/rules", summary="List detection rules")
def list_rules(
    org_id: str = Query("default", description="Organisation ID"),
    rule_type: Optional[str] = Query(None, description="Filter by rule type"),
    enabled: Optional[bool] = Query(None, description="Filter by enabled state"),
) -> List[Dict[str, Any]]:
    """List detection rules with optional filters."""
    engine = _get_engine()
    try:
        return engine.list_rules(org_id, rule_type=rule_type, enabled=enabled)
    except Exception as exc:
        logger.exception("Failed to list rules")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.put("/rules/{rule_id}/trigger", summary="Trigger a detection rule")
def trigger_rule(rule_id: str, body: TriggerRuleRequest) -> Dict[str, Any]:
    """Increment match_count for a rule (simulate a rule match)."""
    engine = _get_engine()
    try:
        return engine.trigger_rule(body.org_id, rule_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to trigger rule %s", rule_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# CloudTrail Replay
# ---------------------------------------------------------------------------


class CloudTrailReplayRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    events: List[Dict[str, Any]] = Field(..., min_length=1, description="List of CloudTrail event dicts to replay")
    dry_run: bool = Field(False, description="Validate without persisting if True")


@router.post("/cloud-trail-replay", summary="Replay CloudTrail events into analytics store")
def replay_cloudtrail(body: CloudTrailReplayRequest) -> Dict[str, Any]:
    """Batch-ingest CloudTrail (or compatible) audit events.

    Normalises camelCase CloudTrail keys to ALDECI schema, validates each
    event, and records them via the analytics engine.  Set ``dry_run=true``
    to validate the batch without persisting anything.
    """
    engine = _get_engine()
    try:
        return engine.replay_cloudtrail(body.org_id, body.events, dry_run=body.dry_run)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to replay cloudtrail events")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@router.get("/stats", summary="Get cloud analytics statistics")
def get_analytics_stats(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Return aggregate cloud security analytics statistics."""
    engine = _get_engine()
    try:
        return engine.get_analytics_stats(org_id)
    except Exception as exc:
        logger.exception("Failed to get analytics stats")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
