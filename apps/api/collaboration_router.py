"""Team Collaboration API endpoints - Comments, watchers, activity feeds."""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from core.services.collaboration import ActivityType, CollaborationService, EntityType

router = APIRouter(prefix="/api/v1/collaboration", tags=["collaboration"])

# Initialize service with default path
_DATA_DIR = Path("data/collaboration")
_collab_service: Optional[CollaborationService] = None


def get_collab_service() -> CollaborationService:
    """Get or create collaboration service instance."""
    global _collab_service
    if _collab_service is None:
        _collab_service = CollaborationService(_DATA_DIR / "collaboration.db")
    return _collab_service


class AddCommentRequest(BaseModel):
    """Request to add a comment."""

    entity_type: str
    entity_id: str
    org_id: str
    author: str
    content: str
    author_email: Optional[str] = None
    is_internal: bool = True
    parent_comment_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class AddWatcherRequest(BaseModel):
    """Request to add a watcher."""

    entity_type: str
    entity_id: str
    user_id: str
    user_email: Optional[str] = None
    added_by: Optional[str] = None


class RemoveWatcherRequest(BaseModel):
    """Request to remove a watcher."""

    entity_type: str
    entity_id: str
    user_id: str


class RecordActivityRequest(BaseModel):
    """Request to record an activity."""

    entity_type: str
    entity_id: str
    org_id: str
    activity_type: str
    actor: str
    summary: str
    actor_email: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


@router.post("/comments")
def add_comment(request: AddCommentRequest) -> Dict[str, Any]:
    """Add a comment to an entity."""
    try:
        EntityType(request.entity_type)
    except ValueError:
        valid_types = [t.value for t in EntityType]
        raise HTTPException(
            status_code=400,
            detail=f"Invalid entity_type. Must be one of: {valid_types}",
        )

    service = get_collab_service()
    return service.add_comment(
        entity_type=request.entity_type,
        entity_id=request.entity_id,
        org_id=request.org_id,
        author=request.author,
        content=request.content,
        author_email=request.author_email,
        is_internal=request.is_internal,
        parent_comment_id=request.parent_comment_id,
        metadata=request.metadata,
    )


@router.get("/comments")
def get_comments(
    entity_type: str,
    entity_id: str,
    include_internal: bool = True,
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """Get comments for an entity."""
    service = get_collab_service()
    comments = service.get_comments(
        entity_type=entity_type,
        entity_id=entity_id,
        include_internal=include_internal,
        limit=limit,
        offset=offset,
    )
    return {
        "comments": comments,
        "count": len(comments),
        "entity_type": entity_type,
        "entity_id": entity_id,
    }


@router.put("/comments/{comment_id}/promote")
def promote_to_evidence(comment_id: str, promoted_by: str) -> Dict[str, Any]:
    """Promote a comment to evidence for compliance."""
    service = get_collab_service()
    success = service.promote_to_evidence(comment_id, promoted_by)
    if not success:
        raise HTTPException(status_code=404, detail="Comment not found")
    return {"status": "promoted", "comment_id": comment_id}


@router.post("/watchers")
def add_watcher(request: AddWatcherRequest) -> Dict[str, Any]:
    """Add a watcher to an entity."""
    service = get_collab_service()
    return service.add_watcher(
        entity_type=request.entity_type,
        entity_id=request.entity_id,
        user_id=request.user_id,
        user_email=request.user_email,
        added_by=request.added_by,
    )


@router.delete("/watchers")
def remove_watcher(
    entity_type: str,
    entity_id: str,
    user_id: str,
) -> Dict[str, Any]:
    """Remove a watcher from an entity."""
    service = get_collab_service()
    success = service.remove_watcher(
        entity_type=entity_type,
        entity_id=entity_id,
        user_id=user_id,
    )
    if not success:
        return {"status": "not_found", "user_id": user_id}
    return {"status": "removed", "user_id": user_id}


@router.get("/watchers")
def get_watchers(entity_type: str, entity_id: str) -> Dict[str, Any]:
    """Get watchers for an entity."""
    service = get_collab_service()
    watchers = service.get_watchers(entity_type, entity_id)
    return {
        "watchers": watchers,
        "count": len(watchers),
        "entity_type": entity_type,
        "entity_id": entity_id,
    }


@router.get("/watchers/user/{user_id}")
def get_watched_entities(
    user_id: str, entity_type: Optional[str] = None
) -> Dict[str, Any]:
    """Get entities watched by a user."""
    service = get_collab_service()
    entities = service.get_watched_entities(user_id, entity_type)
    return {
        "user_id": user_id,
        "watched_entities": entities,
        "count": len(entities),
    }


@router.post("/activities")
def record_activity(request: RecordActivityRequest) -> Dict[str, Any]:
    """Record an activity in the feed."""
    try:
        EntityType(request.entity_type)
    except ValueError:
        valid_entity_types = [t.value for t in EntityType]
        raise HTTPException(
            status_code=400,
            detail=f"Invalid entity_type. Must be one of: {valid_entity_types}",
        )

    try:
        ActivityType(request.activity_type)
    except ValueError:
        valid_types = [t.value for t in ActivityType]
        raise HTTPException(
            status_code=400,
            detail=f"Invalid activity_type. Must be one of: {valid_types}",
        )

    service = get_collab_service()
    activity_id = service.record_activity(
        entity_type=request.entity_type,
        entity_id=request.entity_id,
        org_id=request.org_id,
        activity_type=request.activity_type,
        actor=request.actor,
        summary=request.summary,
        actor_email=request.actor_email,
        details=request.details,
    )
    return {"activity_id": activity_id, "status": "recorded"}


@router.get("/activities")
def get_activity_feed(
    org_id: str,
    entity_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    activity_types: Optional[str] = None,
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """Get activity feed with optional filters."""
    service = get_collab_service()

    types_list = None
    if activity_types:
        types_list = [t.strip() for t in activity_types.split(",")]

    activities = service.get_activity_feed(
        org_id=org_id,
        entity_type=entity_type,
        entity_id=entity_id,
        activity_types=types_list,
        limit=limit,
        offset=offset,
    )
    return {
        "activities": activities,
        "count": len(activities),
        "org_id": org_id,
    }


@router.get("/mentions/{user_id}")
def get_user_mentions(
    user_id: str, unacknowledged_only: bool = False
) -> Dict[str, Any]:
    """Get mentions for a user."""
    service = get_collab_service()
    mentions = service.get_user_mentions(user_id, unacknowledged_only)
    return {
        "user_id": user_id,
        "mentions": mentions,
        "count": len(mentions),
    }


@router.put("/mentions/{mention_id}/acknowledge")
def acknowledge_mention(mention_id: int) -> Dict[str, Any]:
    """Acknowledge a mention."""
    service = get_collab_service()
    success = service.acknowledge_mention(mention_id)
    if not success:
        raise HTTPException(status_code=404, detail="Mention not found")
    return {"status": "acknowledged", "mention_id": mention_id}


@router.get("/entity-types")
def list_entity_types() -> Dict[str, Any]:
    """List all valid entity types."""
    return {"entity_types": [t.value for t in EntityType]}


@router.get("/activity-types")
def list_activity_types() -> Dict[str, Any]:
    """List all valid activity types."""
    return {"activity_types": [t.value for t in ActivityType]}


class QueueNotificationRequest(BaseModel):
    """Request to queue a notification."""

    entity_type: str
    entity_id: str
    notification_type: str
    title: str
    message: str
    recipients: List[str]
    priority: str = "normal"
    metadata: Optional[Dict[str, Any]] = None


class NotifyWatchersRequest(BaseModel):
    """Request to notify all watchers of an entity."""

    entity_type: str
    entity_id: str
    notification_type: str
    title: str
    message: str
    priority: str = "normal"
    metadata: Optional[Dict[str, Any]] = None
    exclude_users: Optional[List[str]] = None


class UpdateNotificationPreferencesRequest(BaseModel):
    """Request to update notification preferences."""

    email_enabled: Optional[bool] = None
    slack_enabled: Optional[bool] = None
    in_app_enabled: Optional[bool] = None
    digest_frequency: Optional[str] = None
    quiet_hours_start: Optional[str] = None
    quiet_hours_end: Optional[str] = None
    notification_types: Optional[List[str]] = None


@router.post("/notifications/queue")
def queue_notification(request: QueueNotificationRequest) -> Dict[str, Any]:
    """Queue a notification for delivery.

    Notification types:
    - new_critical_finding: New critical/high severity finding
    - status_change: Finding/task status changed
    - comment_mention: User was mentioned in a comment
    - sla_breach: SLA deadline approaching or breached
    - assignment: Task/finding assigned to user

    Priority levels: low, normal, high, urgent
    """
    valid_priorities = ["low", "normal", "high", "urgent"]
    if request.priority not in valid_priorities:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid priority. Must be one of: {valid_priorities}",
        )

    service = get_collab_service()
    notification_id = service.queue_notification(
        entity_type=request.entity_type,
        entity_id=request.entity_id,
        notification_type=request.notification_type,
        title=request.title,
        message=request.message,
        recipients=request.recipients,
        priority=request.priority,
        metadata=request.metadata,
    )
    return {
        "notification_id": notification_id,
        "status": "queued",
        "recipients_count": len(request.recipients),
    }


@router.post("/notifications/notify-watchers")
def notify_watchers(request: NotifyWatchersRequest) -> Dict[str, Any]:
    """Notify all watchers of an entity.

    This is a convenience endpoint that:
    1. Gets all watchers for the entity
    2. Queues notifications for each watcher
    3. Returns summary of notifications queued
    """
    valid_priorities = ["low", "normal", "high", "urgent"]
    if request.priority not in valid_priorities:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid priority. Must be one of: {valid_priorities}",
        )

    service = get_collab_service()
    return service.notify_watchers(
        entity_type=request.entity_type,
        entity_id=request.entity_id,
        notification_type=request.notification_type,
        title=request.title,
        message=request.message,
        priority=request.priority,
        metadata=request.metadata,
        exclude_users=request.exclude_users,
    )


@router.get("/notifications/pending")
def get_pending_notifications(
    limit: int = Query(default=100, le=500)
) -> Dict[str, Any]:
    """Get pending notifications for delivery."""
    service = get_collab_service()
    notifications = service.get_pending_notifications(limit)
    return {
        "notifications": notifications,
        "count": len(notifications),
    }


@router.put("/notifications/{notification_id}/sent")
def mark_notification_sent(
    notification_id: str, error: Optional[str] = None
) -> Dict[str, Any]:
    """Mark a notification as sent or failed."""
    service = get_collab_service()
    success = service.mark_notification_sent(notification_id, error)
    if not success:
        raise HTTPException(status_code=404, detail="Notification not found")
    status = "failed" if error else "sent"
    return {"notification_id": notification_id, "status": status}


@router.get("/notifications/preferences/{user_id}")
def get_notification_preferences(user_id: str) -> Dict[str, Any]:
    """Get notification preferences for a user."""
    service = get_collab_service()
    return service.get_user_notification_preferences(user_id)


@router.put("/notifications/preferences/{user_id}")
def update_notification_preferences(
    user_id: str, request: UpdateNotificationPreferencesRequest
) -> Dict[str, Any]:
    """Update notification preferences for a user.

    Digest frequency options: immediate, hourly, daily, weekly
    """
    valid_frequencies = ["immediate", "hourly", "daily", "weekly"]
    if request.digest_frequency and request.digest_frequency not in valid_frequencies:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid digest_frequency. Must be one of: {valid_frequencies}",
        )

    service = get_collab_service()
    return service.update_notification_preferences(
        user_id=user_id,
        email_enabled=request.email_enabled,
        slack_enabled=request.slack_enabled,
        in_app_enabled=request.in_app_enabled,
        digest_frequency=request.digest_frequency,
        quiet_hours_start=request.quiet_hours_start,
        quiet_hours_end=request.quiet_hours_end,
        notification_types=request.notification_types,
    )


class DeliverNotificationRequest(BaseModel):
    """Request to deliver a specific notification.

    Note: SMTP password should be configured via FIXOPS_SMTP_PASSWORD environment
    variable for security. Do not pass credentials in request bodies.
    """

    slack_webhook: Optional[str] = None
    email_smtp_host: Optional[str] = None
    email_smtp_port: Optional[int] = 587
    email_smtp_user: Optional[str] = None
    email_from: Optional[str] = None


class ProcessNotificationsRequest(BaseModel):
    """Request to process pending notifications.

    Note: SMTP password should be configured via FIXOPS_SMTP_PASSWORD environment
    variable for security. Do not pass credentials in request bodies.
    """

    slack_webhook: Optional[str] = None
    email_smtp_host: Optional[str] = None
    email_smtp_port: Optional[int] = 587
    email_smtp_user: Optional[str] = None
    email_from: Optional[str] = None
    limit: int = 100


@router.post("/notifications/{notification_id}/deliver")
def deliver_notification(
    notification_id: str, request: DeliverNotificationRequest
) -> Dict[str, Any]:
    """Deliver a specific notification via configured channels.

    Supports Slack webhook and/or email (SMTP) delivery.
    Respects user notification preferences.
    """
    service = get_collab_service()

    email_config = None
    if request.email_smtp_host and request.email_smtp_user:
        smtp_password = os.environ.get("FIXOPS_SMTP_PASSWORD")
        email_config = {
            "smtp_host": request.email_smtp_host,
            "smtp_port": request.email_smtp_port,
            "smtp_user": request.email_smtp_user,
            "smtp_password": smtp_password,
            "from_email": request.email_from,
        }

    return service.deliver_notification(
        notification_id=notification_id,
        slack_webhook=request.slack_webhook,
        email_config=email_config,
    )


@router.post("/notifications/process")
def process_pending_notifications(
    request: ProcessNotificationsRequest,
) -> Dict[str, Any]:
    """Process all pending notifications in the queue.

    This is the main worker endpoint that should be called periodically
    (e.g., by a cron job or scheduler) to deliver queued notifications.

    Supports Slack webhook and/or email (SMTP) delivery.
    Respects user notification preferences.
    """
    service = get_collab_service()

    email_config = None
    if request.email_smtp_host and request.email_smtp_user:
        smtp_password = os.environ.get("FIXOPS_SMTP_PASSWORD")
        email_config = {
            "smtp_host": request.email_smtp_host,
            "smtp_port": request.email_smtp_port,
            "smtp_user": request.email_smtp_user,
            "smtp_password": smtp_password,
            "from_email": request.email_from,
        }

    return service.process_pending_notifications(
        slack_webhook=request.slack_webhook,
        email_config=email_config,
        limit=request.limit,
    )
