"""Team Collaboration API endpoints - Comments, watchers, activity feeds."""

from pathlib import Path
from typing import Any, Dict, Optional

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
