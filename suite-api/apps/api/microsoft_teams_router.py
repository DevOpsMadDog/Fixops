"""ALDECI Microsoft Teams router — REAL API only, NO MOCKS.

Mounted at ``/api/v1/microsoft-teams`` under the ``read:scans`` scope.

Endpoints
---------
GET    /                                                   — capability summary
POST   /webhook                                            — proxy MessageCard / Adaptive Card to TEAMS_WEBHOOK_URL
GET    /v1.0/me/joinedTeams                                — list joined Teams (Graph)
GET    /v1.0/teams/{team_id}/channels                      — list channels
POST   /v1.0/teams/{team_id}/channels/{channel_id}/messages — post a chat message
GET    /v1.0/teams/{team_id}/channels/{channel_id}/messages — list channel messages

Auth: api_key_auth + read:scans scope (mounted by platform_app).
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from core.microsoft_teams_engine import (
    MicrosoftTeamsUnavailableError,
    get_microsoft_teams_engine,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/microsoft-teams",
    tags=["microsoft-teams"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------- Pydantic


class _Fact(BaseModel):
    name: str
    value: str


class _Section(BaseModel):
    activityTitle: Optional[str] = None
    activitySubtitle: Optional[str] = None
    activityImage: Optional[str] = None
    facts: Optional[List[_Fact]] = None
    markdown: Optional[bool] = None


class _ActionTarget(BaseModel):
    os: str = "default"
    uri: str


class _PotentialAction(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    type: str = Field(default="OpenUri", alias="@type")
    name: str
    targets: Optional[List[_ActionTarget]] = None


class WebhookMessageCard(BaseModel):
    """Legacy MessageCard payload (most common Teams Incoming Webhook format)."""

    model_config = ConfigDict(extra="allow")

    text: Optional[str] = None
    summary: Optional[str] = None
    themeColor: Optional[str] = None
    sections: Optional[List[_Section]] = None
    potentialAction: Optional[List[_PotentialAction]] = None


class _AdaptiveAttachment(BaseModel):
    contentType: str
    content: Dict[str, Any]


class WebhookAdaptiveCard(BaseModel):
    """Power Automate / Adaptive Card payload variant."""

    model_config = ConfigDict(extra="allow")

    type: str = "message"
    attachments: List[_AdaptiveAttachment]


class _MessageBody(BaseModel):
    contentType: str = Field("html", pattern="^(html|text)$")
    content: str


class PostChannelMessageRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    body: _MessageBody
    mentions: Optional[List[Dict[str, Any]]] = None


# ----------------------------------------------------------------- helpers


def _to_503(exc: MicrosoftTeamsUnavailableError) -> HTTPException:
    return HTTPException(status_code=503, detail=str(exc))


# ----------------------------------------------------------------- endpoints


@router.get("/", summary="Microsoft Teams capability summary")
def capability_summary() -> Dict[str, Any]:
    eng = get_microsoft_teams_engine()
    return eng.capability_summary()


@router.post("/webhook", summary="Proxy a MessageCard or Adaptive Card to the Teams webhook")
def post_webhook(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    eng = get_microsoft_teams_engine()
    if not isinstance(payload, dict) or not payload:
        raise HTTPException(status_code=422, detail="payload must be a non-empty JSON object")
    # Best-effort schema validation (accept either MessageCard or Adaptive Card).
    try:
        if "attachments" in payload and payload.get("type") == "message":
            WebhookAdaptiveCard.model_validate(payload)
        else:
            WebhookMessageCard.model_validate(payload)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"invalid Teams webhook payload: {exc}")

    try:
        return eng.post_webhook(payload)
    except MicrosoftTeamsUnavailableError as exc:
        raise _to_503(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/v1.0/me/joinedTeams", summary="List Teams the authenticated user has joined")
def list_joined_teams() -> Dict[str, Any]:
    eng = get_microsoft_teams_engine()
    try:
        return eng.list_joined_teams()
    except MicrosoftTeamsUnavailableError as exc:
        raise _to_503(exc)


@router.get(
    "/v1.0/teams/{team_id}/channels",
    summary="List channels in a Team",
)
def list_channels(team_id: str) -> Dict[str, Any]:
    eng = get_microsoft_teams_engine()
    try:
        return eng.list_channels(team_id)
    except MicrosoftTeamsUnavailableError as exc:
        raise _to_503(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get(
    "/v1.0/teams/{team_id}/channels/{channel_id}/messages",
    summary="List recent messages in a channel",
)
def list_channel_messages(
    team_id: str,
    channel_id: str,
    top: Optional[int] = Query(None, alias="$top", ge=1, le=100),
) -> Dict[str, Any]:
    eng = get_microsoft_teams_engine()
    try:
        return eng.list_channel_messages(team_id, channel_id, top=top)
    except MicrosoftTeamsUnavailableError as exc:
        raise _to_503(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post(
    "/v1.0/teams/{team_id}/channels/{channel_id}/messages",
    summary="Post a chat message to a Teams channel",
    status_code=201,
)
def post_channel_message(
    team_id: str,
    channel_id: str,
    body: PostChannelMessageRequest,
) -> Dict[str, Any]:
    eng = get_microsoft_teams_engine()
    try:
        return eng.post_channel_message(
            team_id,
            channel_id,
            body.model_dump(exclude_none=True),
        )
    except MicrosoftTeamsUnavailableError as exc:
        raise _to_503(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


__all__ = ["router"]
