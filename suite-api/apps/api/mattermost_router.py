"""ALDECI Mattermost API Router.

Direct pass-through to the Mattermost REST API v4 — covers the endpoints
needed for posting, retrieving, editing, and deleting messages, listing
teams/channels for a user, paging through channel history, and uploading
file attachments.

Endpoints (mounted at ``/api/v1/mattermost``)
---------------------------------------------
GET    /                                       — capability summary
POST   /api/v4/posts                           — create a post
GET    /api/v4/posts/{post_id}                 — fetch a post
PUT    /api/v4/posts/{post_id}                 — update a post
DELETE /api/v4/posts/{post_id}                 — delete a post (soft)
GET    /api/v4/users/{user_id}/teams           — list a user's teams
GET    /api/v4/teams/{team_id}/channels        — list channels in a team
GET    /api/v4/channels/{channel_id}/posts     — list posts in a channel
POST   /api/v4/files                           — upload one or more files

When ``MATTERMOST_URL`` / ``MATTERMOST_TOKEN`` are unset the capability
summary reports ``status="unavailable"`` and the lookup endpoints respond
with HTTP 503.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, File, Form, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/mattermost",
    tags=["mattermost"],
)


# ---------------------------------------------------------------------------
# Lazy engine accessor (test seam)
# ---------------------------------------------------------------------------


def _get_engine():
    from core.mattermost_engine import get_mattermost_engine
    return get_mattermost_engine()


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class CapabilitySummary(BaseModel):
    service: str
    endpoints: List[str]
    mattermost_url_present: bool
    mattermost_token_present: bool
    status: str = Field(..., description="ok | empty | unavailable")


class PostCreateRequest(BaseModel):
    """Mirrors Mattermost's POST /api/v4/posts body shape."""

    channel_id: str = Field(..., description="Target channel UUID")
    message: str = Field(..., description="Message body (markdown)")
    props: Optional[Dict[str, Any]] = Field(None, description="Arbitrary post props")
    file_ids: Optional[List[str]] = Field(None, description="Attached file UUIDs")
    root_id: Optional[str] = Field(None, description="Reply parent post id")
    type: Optional[str] = Field(None, description="Post type (default '')")


class PostUpdateRequest(BaseModel):
    """Body for PUT /api/v4/posts/{post_id}."""

    message: str
    file_ids: List[str] = Field(default_factory=list)
    has_reactions: bool = False
    props: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _raise_unavailable() -> None:
    raise HTTPException(
        status_code=503,
        detail={
            "error": "mattermost_unavailable",
            "message": "MATTERMOST_URL and MATTERMOST_TOKEN environment variables are not configured",
        },
    )


def _map_mattermost_error(exc: Exception) -> HTTPException:
    """Translate a MattermostHTTPError (or unavailable) into an HTTPException."""
    from core.mattermost_engine import MattermostHTTPError, MattermostUnavailable

    if isinstance(exc, MattermostUnavailable):
        return HTTPException(
            status_code=503,
            detail={"error": "mattermost_unavailable", "message": str(exc)},
        )
    if isinstance(exc, MattermostHTTPError):
        passthrough = {400, 401, 403, 404, 409, 422, 429}
        status_code = exc.status_code if exc.status_code in passthrough else 502
        return HTTPException(
            status_code=status_code,
            detail={
                "error": "mattermost_upstream_error",
                "upstream_status": exc.status_code,
                "message": str(exc),
                "payload": exc.payload,
            },
        )
    return HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=CapabilitySummary,
    summary="Mattermost capability summary",
)
def capability_summary() -> CapabilitySummary:
    """Return service identity, exposed endpoints, and configuration status."""
    engine = _get_engine()
    return CapabilitySummary(**engine.capability_summary())


@router.post(
    "/api/v4/posts",
    summary="Create a post",
)
def create_post(req: PostCreateRequest) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.create_post(
            channel_id=req.channel_id,
            message=req.message,
            props=req.props,
            file_ids=req.file_ids,
            root_id=req.root_id,
            type=req.type,
        )
    except Exception as exc:
        raise _map_mattermost_error(exc) from exc


@router.get(
    "/api/v4/posts/{post_id}",
    summary="Fetch a post by id",
)
def get_post(
    post_id: str,
    include_deleted: bool = Query(False, description="Include soft-deleted posts"),
) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.get_post(post_id, include_deleted=include_deleted)
    except Exception as exc:
        raise _map_mattermost_error(exc) from exc


@router.put(
    "/api/v4/posts/{post_id}",
    summary="Update a post",
)
def update_post(post_id: str, req: PostUpdateRequest) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.update_post(
            post_id,
            message=req.message,
            file_ids=req.file_ids,
            has_reactions=req.has_reactions,
            props=req.props,
        )
    except Exception as exc:
        raise _map_mattermost_error(exc) from exc


@router.delete(
    "/api/v4/posts/{post_id}",
    summary="Delete a post (soft)",
)
def delete_post(post_id: str) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.delete_post(post_id)
    except Exception as exc:
        raise _map_mattermost_error(exc) from exc


@router.get(
    "/api/v4/users/{user_id}/teams",
    summary="List teams a user belongs to",
)
def get_user_teams(user_id: str) -> List[Dict[str, Any]]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.get_user_teams(user_id)
    except Exception as exc:
        raise _map_mattermost_error(exc) from exc


@router.get(
    "/api/v4/teams/{team_id}/channels",
    summary="List channels in a team",
)
def get_team_channels(
    team_id: str,
    per_page: Optional[int] = Query(None, ge=1, le=200),
    page: Optional[int] = Query(None, ge=0),
) -> List[Dict[str, Any]]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.get_team_channels(team_id, per_page=per_page, page=page)
    except Exception as exc:
        raise _map_mattermost_error(exc) from exc


@router.get(
    "/api/v4/channels/{channel_id}/posts",
    summary="List posts in a channel (paginated)",
)
def get_channel_posts(
    channel_id: str,
    since: Optional[int] = Query(None, ge=0, description="Unix ms — only posts after"),
    before: Optional[str] = Query(None, description="Page back from this post id"),
    after: Optional[str] = Query(None, description="Page forward from this post id"),
    page: Optional[int] = Query(None, ge=0),
    per_page: Optional[int] = Query(None, ge=1, le=200),
) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.get_channel_posts(
            channel_id,
            since=since,
            before=before,
            after=after,
            page=page,
            per_page=per_page,
        )
    except Exception as exc:
        raise _map_mattermost_error(exc) from exc


@router.post(
    "/api/v4/files",
    summary="Upload one or more files to a channel",
)
async def upload_files(
    channel_id: str = Form(..., description="Target channel UUID"),
    files: List[UploadFile] = File(..., description="One or more files"),
) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    payload: List = []
    for f in files:
        content = await f.read()
        payload.append((f.filename or "file", content, f.content_type or "application/octet-stream"))
    try:
        return engine.upload_files(channel_id, payload)
    except Exception as exc:
        raise _map_mattermost_error(exc) from exc
