"""Alerting & Notification Router — ALDECI.

Policy-driven alert management: create policies, trigger/acknowledge/resolve
alerts, view history and statistics.

Prefix: /api/v1/alerting
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/alerting/policies                          create_alert_policy
  GET    /api/v1/alerting/policies                          list_alert_policies
  POST   /api/v1/alerting/trigger                           trigger_alert
  GET    /api/v1/alerting/alerts                            list_alerts
  PATCH  /api/v1/alerting/alerts/{alert_id}/acknowledge     acknowledge_alert
  PATCH  /api/v1/alerting/alerts/{alert_id}/resolve         resolve_alert
  GET    /api/v1/alerting/history                           get_alert_history
  GET    /api/v1/alerting/stats                             get_alerting_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/alerting",
    tags=["Alerting & Notification"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.alerting_notification_engine import AlertingNotificationEngine
        _engine = AlertingNotificationEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CreateAlertPolicyRequest(BaseModel):
    name: str = Field(..., description="Human-readable policy name")
    severity: str = Field(default="medium", description="critical | high | medium | low")
    condition_type: str = Field(
        default="threshold",
        description="threshold | anomaly | pattern | schedule",
    )
    channels: List[str] = Field(
        default_factory=lambda: ["email"],
        description="Delivery channels: email, slack, pagerduty, webhook",
    )
    enabled: bool = Field(default=True, description="Whether the policy is active")


class TriggerAlertRequest(BaseModel):
    title: str = Field(..., description="Short alert title")
    message: str = Field(..., description="Detailed alert message")
    policy_id: Optional[str] = Field(default=None, description="Originating policy ID")
    source_engine: Optional[str] = Field(default=None, description="Engine that raised the alert")
    source_id: Optional[str] = Field(default=None, description="Source record ID")
    severity: str = Field(default="medium", description="critical | high | medium | low")
    context: Optional[Dict[str, Any]] = Field(
        default=None, description="Additional key-value context"
    )


class AcknowledgeAlertRequest(BaseModel):
    acknowledged_by: str = Field(..., description="User or system acknowledging the alert")


class ResolveAlertRequest(BaseModel):
    resolved_by: str = Field(..., description="User or system resolving the alert")
    resolution: str = Field(..., description="Description of the resolution taken")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/policies", dependencies=[Depends(api_key_auth)], status_code=201)
def create_alert_policy(
    body: CreateAlertPolicyRequest,
    org_id: str = Query(default="default"),
):
    """Create a new alert policy with channel routing and severity settings."""
    try:
        return _get_engine().create_alert_policy(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error creating alert policy")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/policies", dependencies=[Depends(api_key_auth)])
def list_alert_policies(
    org_id: str = Query(default="default"),
    enabled: Optional[bool] = Query(default=None),
):
    """List alert policies, optionally filtered by enabled state."""
    return _get_engine().list_alert_policies(org_id, enabled=enabled)


@router.post("/trigger", dependencies=[Depends(api_key_auth)], status_code=201)
def trigger_alert(
    body: TriggerAlertRequest,
    org_id: str = Query(default="default"),
):
    """Trigger a new alert."""
    try:
        data = body.model_dump()
        if data.get("context") is None:
            data["context"] = {}
        return _get_engine().trigger_alert(org_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error triggering alert")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/alerts", dependencies=[Depends(api_key_auth)])
def list_alerts(
    org_id: str = Query(default="default"),
    severity: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    acknowledged: bool = Query(default=False),
    limit: int = Query(default=50, ge=1, le=500),
):
    """List alerts with optional severity/status filters."""
    return _get_engine().list_alerts(
        org_id,
        severity=severity,
        status=status,
        acknowledged=acknowledged,
        limit=limit,
    )


@router.patch("/alerts/{alert_id}/acknowledge", dependencies=[Depends(api_key_auth)])
def acknowledge_alert(
    alert_id: str,
    body: AcknowledgeAlertRequest,
    org_id: str = Query(default="default"),
):
    """Acknowledge an open alert."""
    try:
        return _get_engine().acknowledge_alert(org_id, alert_id, body.acknowledged_by)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error acknowledging alert")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.patch("/alerts/{alert_id}/resolve", dependencies=[Depends(api_key_auth)])
def resolve_alert(
    alert_id: str,
    body: ResolveAlertRequest,
    org_id: str = Query(default="default"),
):
    """Resolve an open or acknowledged alert."""
    try:
        return _get_engine().resolve_alert(
            org_id, alert_id, body.resolved_by, body.resolution
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error resolving alert")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/history", dependencies=[Depends(api_key_auth)])
def get_alert_history(
    org_id: str = Query(default="default"),
    policy_id: Optional[str] = Query(default=None),
    hours: int = Query(default=24, ge=1, le=8760),
):
    """Return alerts triggered within the last N hours."""
    return _get_engine().get_alert_history(org_id, policy_id=policy_id, hours=hours)


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_alerting_stats(org_id: str = Query(default="default")):
    """Return aggregated alerting statistics: policy count, 24h alerts, MTTR, severity breakdown."""
    return _get_engine().get_alerting_stats(org_id)
