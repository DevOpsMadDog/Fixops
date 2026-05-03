"""ALDECI Discord integration router — REAL API only, NO MOCKS.

Mounted at ``/api/v1/discord`` under the ``read:scans`` scope.

Endpoints
---------
GET    /                                                — capability summary
POST   /webhooks/{wh_id}/{wh_token}                     — proxy webhook send
                                                          (?wait=true returns msg)
GET    /api/v10/channels/{channel_id}/messages          — list channel messages
POST   /api/v10/channels/{channel_id}/messages          — create channel message
GET    /api/v10/guilds/{guild_id}/channels              — list guild channels
GET    /api/v10/users/@me/guilds                        — list current user's
                                                          guilds (bot self)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query, Response
from pydantic import BaseModel, Field

from core.discord_integration_engine import (
    DiscordUnavailableError,
    get_discord_integration_engine,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/discord",
    tags=["discord"],
    dependencies=[Depends(api_key_auth)],
)


# --------------------------------------------------------------- Pydantic


class _EmbedFooter(BaseModel):
    text: str
    icon_url: Optional[str] = None


class _EmbedImage(BaseModel):
    url: str
    height: Optional[int] = None
    width: Optional[int] = None


class _EmbedThumbnail(BaseModel):
    url: Optional[str] = None
    height: Optional[int] = None
    width: Optional[int] = None


class _EmbedVideo(BaseModel):
    url: Optional[str] = None
    height: Optional[int] = None
    width: Optional[int] = None


class _EmbedProvider(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None


class _EmbedAuthor(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    icon_url: Optional[str] = None


class _EmbedField(BaseModel):
    name: str
    value: str
    inline: bool = False


class _Embed(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    url: Optional[str] = None
    timestamp: Optional[str] = None
    color: Optional[int] = None
    footer: Optional[_EmbedFooter] = None
    image: Optional[_EmbedImage] = None
    thumbnail: Optional[_EmbedThumbnail] = None
    video: Optional[_EmbedVideo] = None
    provider: Optional[_EmbedProvider] = None
    author: Optional[_EmbedAuthor] = None
    fields: Optional[List[_EmbedField]] = None


class _AllowedMentions(BaseModel):
    parse: Optional[List[str]] = None
    roles: Optional[List[str]] = None
    users: Optional[List[str]] = None
    replied_user: Optional[bool] = None


class _MessageReference(BaseModel):
    message_id: Optional[str] = None
    channel_id: Optional[str] = None
    guild_id: Optional[str] = None


class WebhookExecuteBody(BaseModel):
    content: Optional[str] = None
    username: Optional[str] = None
    avatar_url: Optional[str] = None
    tts: Optional[bool] = None
    embeds: Optional[List[_Embed]] = None
    allowed_mentions: Optional[_AllowedMentions] = None
    message_reference: Optional[_MessageReference] = None
    components: Optional[List[Dict[str, Any]]] = None


class CreateMessageBody(BaseModel):
    content: Optional[str] = None
    tts: Optional[bool] = None
    embeds: Optional[List[_Embed]] = None
    message_reference: Optional[_MessageReference] = None
    components: Optional[List[Dict[str, Any]]] = None
    sticker_ids: Optional[List[str]] = None


# --------------------------------------------------------------- helpers


def _to_503(exc: DiscordUnavailableError) -> HTTPException:
    return HTTPException(status_code=503, detail=str(exc))


# --------------------------------------------------------------- endpoints


@router.get("/", summary="Discord capability summary")
def capability_summary() -> Dict[str, Any]:
    eng = get_discord_integration_engine()
    return eng.capability_summary()


@router.post(
    "/webhooks/{wh_id}/{wh_token}",
    summary="Proxy Discord webhook execute",
)
def execute_webhook(
    wh_id: str = Path(..., min_length=1),
    wh_token: str = Path(..., min_length=1),
    wait: bool = Query(False, description="Return full message object when true"),
    body: WebhookExecuteBody = Body(...),
):
    eng = get_discord_integration_engine()
    try:
        result = eng.post_webhook(
            wh_id=wh_id,
            wh_token=wh_token,
            body=body.dict(exclude_none=True),
            wait=wait,
        )
    except DiscordUnavailableError as exc:
        raise _to_503(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if wait:
        return result
    return Response(status_code=204)


@router.get(
    "/api/v10/channels/{channel_id}/messages",
    summary="List channel messages (bot)",
)
def list_channel_messages(
    channel_id: str = Path(..., min_length=1),
    limit: int = Query(50, ge=1, le=100),
    before: Optional[str] = Query(None),
    after: Optional[str] = Query(None),
    around: Optional[str] = Query(None),
) -> Dict[str, Any]:
    eng = get_discord_integration_engine()
    try:
        return eng.list_channel_messages(
            channel_id=channel_id,
            limit=limit,
            before=before,
            after=after,
            around=around,
        )
    except DiscordUnavailableError as exc:
        raise _to_503(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post(
    "/api/v10/channels/{channel_id}/messages",
    summary="Create channel message (bot)",
    status_code=201,
)
def create_channel_message(
    channel_id: str = Path(..., min_length=1),
    body: CreateMessageBody = Body(...),
) -> Dict[str, Any]:
    eng = get_discord_integration_engine()
    try:
        return eng.create_channel_message(
            channel_id=channel_id,
            body=body.dict(exclude_none=True),
        )
    except DiscordUnavailableError as exc:
        raise _to_503(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get(
    "/api/v10/guilds/{guild_id}/channels",
    summary="List guild channels (bot)",
)
def list_guild_channels(
    guild_id: str = Path(..., min_length=1),
) -> Dict[str, Any]:
    eng = get_discord_integration_engine()
    try:
        return eng.list_guild_channels(guild_id=guild_id)
    except DiscordUnavailableError as exc:
        raise _to_503(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get(
    "/api/v10/users/@me/guilds",
    summary="List current bot's guilds",
)
def list_user_guilds(
    limit: int = Query(200, ge=1, le=200),
    before: Optional[str] = Query(None),
    after: Optional[str] = Query(None),
) -> Dict[str, Any]:
    eng = get_discord_integration_engine()
    try:
        return eng.list_user_guilds(limit=limit, before=before, after=after)
    except DiscordUnavailableError as exc:
        raise _to_503(exc)


__all__ = ["router"]
