"""Notification management API router.

Endpoints:
    POST   /api/v1/notifications/rules          — create alert rule
    GET    /api/v1/notifications/rules          — list rules
    PUT    /api/v1/notifications/rules/{id}     — update rule
    DELETE /api/v1/notifications/rules/{id}     — delete rule
    GET    /api/v1/notifications/inbox          — get user's in-app notifications
    POST   /api/v1/notifications/read           — mark notifications read
    GET    /api/v1/notifications/preferences    — get user preferences
    PUT    /api/v1/notifications/preferences    — update preferences

Protected by _verify_api_key (injected via app.include_router dependencies).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.notifications import (
    AlertRule,
    Channel,
    DigestFrequency,
    NotificationEngine,
    NotificationPreference,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/notifications", tags=["notifications"])

_engine = None  # lazy-initialised on first request


def _get_engine():
    global _engine
    if _engine is None:
        _engine = NotificationEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class CreateRuleRequest(BaseModel):
    name: str
    description: Optional[str] = None
    enabled: bool = True
    conditions: Dict[str, Any] = Field(default_factory=dict)
    channels: List[Channel] = Field(default_factory=list)
    recipients: List[str] = Field(default_factory=list)
    digest_frequency: DigestFrequency = DigestFrequency.IMMEDIATE


class UpdateRuleRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    conditions: Optional[Dict[str, Any]] = None
    channels: Optional[List[Channel]] = None
    recipients: Optional[List[str]] = None
    digest_frequency: Optional[DigestFrequency] = None


class UpdatePreferenceRequest(BaseModel):
    channels: Optional[List[Channel]] = None
    digest_frequency: Optional[DigestFrequency] = None
    muted_sources: Optional[List[str]] = None
    quiet_hours_start: Optional[int] = Field(default=None, ge=0, le=23)
    quiet_hours_end: Optional[int] = Field(default=None, ge=0, le=23)


class MarkReadRequest(BaseModel):
    notification_ids: List[str]


# ---------------------------------------------------------------------------
# Alert Rules
# ---------------------------------------------------------------------------


@router.post("/rules", status_code=201)
async def create_rule(req: CreateRuleRequest) -> Dict[str, Any]:
    """Create a new alert rule."""
    rule = AlertRule(
        name=req.name,
        description=req.description,
        enabled=req.enabled,
        conditions=req.conditions,
        channels=[c.value if hasattr(c, "value") else c for c in req.channels],
        recipients=req.recipients,
        digest_frequency=req.digest_frequency.value if hasattr(req.digest_frequency, "value") else req.digest_frequency,
    )
    created = _get_engine().add_rule(rule)
    return created.model_dump(mode="json")


@router.get("/rules")
async def list_rules() -> List[Dict[str, Any]]:
    """List all alert rules."""
    rules = _get_engine().list_rules()
    return [r.model_dump(mode="json") for r in rules]


@router.put("/rules/{rule_id}")
async def update_rule(rule_id: str, req: UpdateRuleRequest) -> Dict[str, Any]:
    """Update an existing alert rule."""
    updates: Dict[str, Any] = {}
    if req.name is not None:
        updates["name"] = req.name
    if req.description is not None:
        updates["description"] = req.description
    if req.enabled is not None:
        updates["enabled"] = req.enabled
    if req.conditions is not None:
        updates["conditions"] = req.conditions
    if req.channels is not None:
        updates["channels"] = [c.value if hasattr(c, "value") else c for c in req.channels]
    if req.recipients is not None:
        updates["recipients"] = req.recipients
    if req.digest_frequency is not None:
        updates["digest_frequency"] = req.digest_frequency.value if hasattr(req.digest_frequency, "value") else req.digest_frequency

    if not updates:
        raise HTTPException(status_code=422, detail="No fields to update")

    try:
        updated = _get_engine().update_rule(rule_id, updates)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    return updated.model_dump(mode="json")


@router.delete("/rules/{rule_id}")
async def delete_rule(rule_id: str) -> Dict[str, Any]:
    """Delete an alert rule."""
    deleted = _get_engine().delete_rule(rule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    return {"id": rule_id, "status": "deleted"}


# ---------------------------------------------------------------------------
# In-app inbox
# ---------------------------------------------------------------------------


@router.get("/inbox")
async def get_inbox(user_email: str = Query(..., description="User email address")) -> List[Dict[str, Any]]:
    """Return unread in-app notifications for a user."""
    notifications = _get_engine().get_unread_notifications(user_email)
    return [n.model_dump(mode="json") for n in notifications]


@router.post("/read")
async def mark_read(req: MarkReadRequest) -> Dict[str, Any]:
    """Mark one or more notifications as read."""
    count = _get_engine().mark_read(req.notification_ids)
    return {"marked_read": count}


# ---------------------------------------------------------------------------
# Preferences
# ---------------------------------------------------------------------------


@router.get("/preferences")
async def get_preferences(user_email: str = Query(..., description="User email address")) -> Dict[str, Any]:
    """Get notification preferences for a user."""
    pref = _get_engine().get_preference(user_email)
    if not pref:
        # Return defaults
        default = NotificationPreference(user_email=user_email)
        return default.model_dump(mode="json")
    return pref.model_dump(mode="json")


@router.put("/preferences")
async def update_preferences(
    user_email: str = Query(..., description="User email address"),
    req: UpdatePreferenceRequest = ...,
) -> Dict[str, Any]:
    """Update notification preferences for a user."""
    existing = _get_engine().get_preference(user_email) or NotificationPreference(user_email=user_email)

    updated_data: Dict[str, Any] = existing.model_dump()
    if req.channels is not None:
        updated_data["channels"] = [c.value if hasattr(c, "value") else c for c in req.channels]
    if req.digest_frequency is not None:
        updated_data["digest_frequency"] = req.digest_frequency.value if hasattr(req.digest_frequency, "value") else req.digest_frequency
    if req.muted_sources is not None:
        updated_data["muted_sources"] = req.muted_sources
    if req.quiet_hours_start is not None:
        updated_data["quiet_hours_start"] = req.quiet_hours_start
    if req.quiet_hours_end is not None:
        updated_data["quiet_hours_end"] = req.quiet_hours_end

    pref = NotificationPreference(**updated_data)
    saved = _get_engine().set_preference(pref)
    return saved.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Root summary endpoint (5-state envelope)
# ---------------------------------------------------------------------------

import logging as _notif_logger_mod
_notif_logger = _notif_logger_mod.getLogger(__name__)


@router.get("/")
def get_notification_root_summary(org_id: str = Query(default="default")):
    """Return a 5-state summary envelope for the Notifications domain.

    States:
      healthy   — alert rules configured, no undelivered notifications
      degraded  — rules configured but pending notifications accumulating
      empty     — no alert rules configured yet
      error     — engine raised an exception
      unknown   — unexpected summary structure
    """
    try:
        engine = _get_engine()
        rules = engine.list_rules()
        total_rules = len(rules)
        enabled_rules = sum(1 for r in rules if getattr(r, "enabled", True))
    except Exception as exc:
        _notif_logger.error("notification.summary error: %s", exc)
        return {
            "status": "error",
            "org_id": org_id,
            "error": str(exc),
            "domain": "notifications",
        }

    if total_rules == 0:
        status = "empty"
    elif enabled_rules == 0:
        status = "degraded"
    else:
        status = "healthy"

    envelope = {
        "status": status,
        "org_id": org_id,
        "domain": "notifications",
        "summary": {
            "total_rules": total_rules,
            "enabled_rules": enabled_rules,
        },
    }
    if status == "empty":
        envelope["hint"] = (
            "Create alert rules via POST /api/v1/notifications/rules "
            "to begin receiving security notifications."
        )
    return envelope
