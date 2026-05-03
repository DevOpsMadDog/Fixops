"""Slack Notifier Router — ALDECI.

Webhook-based Slack notification endpoints.

Routes:
  POST  /api/v1/integrations/slack/test       Send a test notification
  POST  /api/v1/integrations/slack/configure  Set the webhook URL
  GET   /api/v1/integrations/slack/status     Check if webhook is configured

Auth: api_key_auth (consistent with all other ALDECI routers)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/integrations/slack",
    tags=["Slack Notifications"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Lazy notifier access
# ---------------------------------------------------------------------------


def _get_notifier():
    from core.slack_notifier import get_notifier
    return get_notifier()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class SlackTestRequest(BaseModel):
    message: str = Field(
        default="Test notification from ALDECI",
        description="Custom message body for the test notification",
    )


class SlackConfigureRequest(BaseModel):
    webhook_url: str = Field(
        ...,
        description="Slack Incoming Webhook URL (https://hooks.slack.com/services/...)",
    )


class SlackAlertRequest(BaseModel):
    """For ad-hoc alert notifications via the API."""

    title: str = Field(..., description="Alert title")
    message: str = Field(default="", description="Alert details")
    severity: str = Field(
        default="critical",
        description="critical | high | medium | low",
    )
    alert_id: Optional[str] = Field(default=None, description="Alert ID")
    source_engine: Optional[str] = Field(default=None, description="Source engine name")
    org_id: Optional[str] = Field(default=None, description="Organisation ID")


class SlackIncidentRequest(BaseModel):
    """For incident notification via the API."""

    title: str = Field(..., description="Incident title")
    severity: str = Field(default="high", description="critical | high | medium | low")
    status: str = Field(default="open", description="Incident status")
    assignee: str = Field(default="Unassigned", description="Incident assignee")
    incident_id: Optional[str] = Field(default=None, description="Incident ID")
    description: Optional[str] = Field(default=None, description="Incident description")


class SlackComplianceFailureRequest(BaseModel):
    """For compliance failure notification via the API."""

    framework: str = Field(..., description="Compliance framework (e.g. SOC2, PCI-DSS)")
    control: str = Field(..., description="Failed control ID or name")
    severity: str = Field(default="high", description="critical | high | medium | low")
    failure_id: Optional[str] = Field(default=None, description="Failure record ID")
    description: Optional[str] = Field(default=None, description="Failure description")
    remediation: Optional[str] = Field(default=None, description="Recommended remediation")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", summary="Slack notification channel summary")
def get_slack_root_summary() -> Dict[str, Any]:
    """Return a 5-state summary envelope for the Slack notification channel.

    States:
      configured   — webhook URL is set and channel is ready
      unconfigured — no webhook URL present; channel cannot deliver
      error        — notifier raised an unexpected exception
    """
    try:
        notifier = _get_notifier()
        is_configured = notifier.is_configured
    except Exception as exc:
        _logger.error("slack.notifier.summary error: %s", exc)
        return {
            "status": "error",
            "channel": "slack",
            "error": str(exc),
        }

    status = "configured" if is_configured else "unconfigured"
    envelope: Dict[str, Any] = {
        "status": status,
        "channel": "slack",
        "summary": {
            "webhook_url_set": is_configured,
        },
    }
    if not is_configured:
        envelope["hint"] = (
            "Set SLACK_WEBHOOK_URL env var or POST /api/v1/integrations/slack/configure "
            "to enable Slack notifications."
        )
    return envelope


@router.get("/status", summary="Check Slack webhook configuration status")
def get_slack_status() -> Dict[str, Any]:
    """Return whether the Slack webhook URL is configured."""
    notifier = _get_notifier()
    return {
        "configured": notifier.is_configured,
        "webhook_url_set": notifier.is_configured,
        "hint": (
            None
            if notifier.is_configured
            else "Set SLACK_WEBHOOK_URL env var or POST /configure"
        ),
    }


@router.post("/configure", summary="Set the Slack webhook URL")
def configure_slack_webhook(req: SlackConfigureRequest) -> Dict[str, Any]:
    """Configure the Slack Incoming Webhook URL at runtime.

    The URL must begin with ``https://hooks.slack.com/``.
    This updates the in-process singleton — restart the server to clear it.
    """
    notifier = _get_notifier()
    try:
        notifier.configure(req.webhook_url)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    _logger.info("slack.notifier.configured via API")
    return {"configured": True, "message": "Slack webhook URL updated successfully"}


@router.post("/test", summary="Send a test Slack notification")
def send_test_notification(req: SlackTestRequest) -> Dict[str, Any]:
    """Send a test Block Kit message to the configured webhook.

    Returns 400 if the webhook is not configured, 502 if delivery fails.
    """
    notifier = _get_notifier()
    if not notifier.is_configured:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Slack webhook not configured. POST /configure first or set SLACK_WEBHOOK_URL.",
        )
    sent = notifier.send_test(req.message)
    if not sent:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to deliver notification to Slack. Check the webhook URL.",
        )
    return {"sent": True, "message": "Test notification delivered to Slack"}


@router.post("/notify/alert", summary="Send a critical alert notification to Slack")
def notify_alert(req: SlackAlertRequest) -> Dict[str, Any]:
    """Send a security alert notification to Slack via webhook."""
    notifier = _get_notifier()
    if not notifier.is_configured:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Slack webhook not configured.",
        )
    sent = notifier.send_critical_alert(req.model_dump(exclude_none=True))
    if not sent:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to deliver alert notification to Slack.",
        )
    return {"sent": True, "severity": req.severity, "title": req.title}


@router.post("/notify/incident", summary="Send an incident notification to Slack")
def notify_incident(req: SlackIncidentRequest) -> Dict[str, Any]:
    """Send an incident notification to Slack via webhook."""
    notifier = _get_notifier()
    if not notifier.is_configured:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Slack webhook not configured.",
        )
    sent = notifier.send_incident_notification(req.model_dump(exclude_none=True))
    if not sent:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to deliver incident notification to Slack.",
        )
    return {"sent": True, "title": req.title, "status": req.status}


@router.post("/notify/compliance", summary="Send a compliance failure notification to Slack")
def notify_compliance_failure(req: SlackComplianceFailureRequest) -> Dict[str, Any]:
    """Send a compliance failure notification to Slack via webhook."""
    notifier = _get_notifier()
    if not notifier.is_configured:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Slack webhook not configured.",
        )
    sent = notifier.send_compliance_failure(req.model_dump(exclude_none=True))
    if not sent:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to deliver compliance failure notification to Slack.",
        )
    return {"sent": True, "framework": req.framework, "control": req.control}
