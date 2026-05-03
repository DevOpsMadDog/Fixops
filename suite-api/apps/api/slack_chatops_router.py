"""ALDECI Slack ChatOps router - REAL httpx only, NO MOCKS.

Mounted at ``/api/v1/slack-chatops`` under the ``read:scans`` scope.

Endpoints
---------
GET  /                                  - capability summary
POST /api/chat.postMessage              - post a message to a channel/DM/thread
POST /api/chat.update                   - update an existing message
POST /api/chat.delete                   - delete a message
GET  /api/users.list                    - list workspace members (cursor paginated)
GET  /api/conversations.list            - list channels/groups/IMs (cursor paginated)
POST /api/files.upload                  - upload a file (multipart) to one or more channels
POST /api/reactions.add                 - add an emoji reaction to a message

When SLACK_BOT_TOKEN is not set the capability summary still responds 200
with ``status="unavailable"`` and every operation returns HTTP 503.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, File, Form, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field

from core.slack_chatops_engine import (
    SlackChatOpsUnavailableError,
    get_slack_chatops_engine,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/slack-chatops",
    tags=["slack-chatops"],
    dependencies=[Depends(api_key_auth)],
)


# --------------------------------------------------------------- Pydantic


class ChatPostMessageRequest(BaseModel):
    channel: str
    text: Optional[str] = None
    blocks: Optional[List[Dict[str, Any]]] = None
    attachments: Optional[List[Dict[str, Any]]] = None
    thread_ts: Optional[str] = None
    reply_broadcast: Optional[bool] = None
    mrkdwn: Optional[bool] = None
    parse: Optional[str] = None
    link_names: Optional[bool] = None
    unfurl_links: Optional[bool] = None
    unfurl_media: Optional[bool] = None
    icon_url: Optional[str] = None
    icon_emoji: Optional[str] = None
    username: Optional[str] = None


class ChatUpdateRequest(BaseModel):
    channel: str
    ts: str
    text: Optional[str] = None
    blocks: Optional[List[Dict[str, Any]]] = None
    attachments: Optional[List[Dict[str, Any]]] = None
    parse: Optional[str] = None


class ChatDeleteRequest(BaseModel):
    channel: str
    ts: str
    as_user: Optional[bool] = None


class ReactionsAddRequest(BaseModel):
    channel: str
    name: str = Field(description="emoji name without colons, e.g. 'thumbsup'")
    timestamp: str


# ------------------------------------------------------------------ helpers


def _to_503(exc: SlackChatOpsUnavailableError) -> HTTPException:
    return HTTPException(status_code=503, detail=str(exc))


# ----------------------------------------------------------------- endpoints


@router.get("/", summary="Slack ChatOps capability summary")
def capability_summary() -> Dict[str, Any]:
    eng = get_slack_chatops_engine()
    return eng.capability_summary()


@router.post("/api/chat.postMessage", summary="Post a Slack message")
def chat_post_message(body: ChatPostMessageRequest = Body(...)) -> Dict[str, Any]:
    eng = get_slack_chatops_engine()
    payload = body.dict(exclude_none=True)
    try:
        return eng.chat_post_message(payload)
    except SlackChatOpsUnavailableError as exc:
        raise _to_503(exc)


@router.post("/api/chat.update", summary="Update an existing Slack message")
def chat_update(body: ChatUpdateRequest = Body(...)) -> Dict[str, Any]:
    eng = get_slack_chatops_engine()
    payload = body.dict(exclude_none=True)
    try:
        return eng.chat_update(payload)
    except SlackChatOpsUnavailableError as exc:
        raise _to_503(exc)


@router.post("/api/chat.delete", summary="Delete a Slack message")
def chat_delete(body: ChatDeleteRequest = Body(...)) -> Dict[str, Any]:
    eng = get_slack_chatops_engine()
    payload = body.dict(exclude_none=True)
    try:
        return eng.chat_delete(payload)
    except SlackChatOpsUnavailableError as exc:
        raise _to_503(exc)


@router.get("/api/users.list", summary="List Slack workspace members")
def users_list(
    limit: Optional[int] = Query(None, ge=1, le=1000),
    cursor: Optional[str] = Query(None),
) -> Dict[str, Any]:
    eng = get_slack_chatops_engine()
    try:
        return eng.users_list(limit=limit, cursor=cursor)
    except SlackChatOpsUnavailableError as exc:
        raise _to_503(exc)


@router.get("/api/conversations.list", summary="List Slack channels/groups/IMs")
def conversations_list(
    types: Optional[str] = Query(
        "public_channel,private_channel,mpim,im",
        description="comma-separated list of channel types",
    ),
    limit: Optional[int] = Query(None, ge=1, le=1000),
    cursor: Optional[str] = Query(None),
    exclude_archived: Optional[bool] = Query(True),
) -> Dict[str, Any]:
    eng = get_slack_chatops_engine()
    try:
        return eng.conversations_list(
            types=types,
            limit=limit,
            cursor=cursor,
            exclude_archived=exclude_archived,
        )
    except SlackChatOpsUnavailableError as exc:
        raise _to_503(exc)


@router.post("/api/files.upload", summary="Upload a file to Slack channels")
async def files_upload(
    channels: str = Form(...),
    content: Optional[str] = Form(None),
    filename: Optional[str] = Form(None),
    filetype: Optional[str] = Form(None),
    initial_comment: Optional[str] = Form(None),
    thread_ts: Optional[str] = Form(None),
    title: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
) -> Dict[str, Any]:
    eng = get_slack_chatops_engine()
    file_bytes: Optional[bytes] = None
    if file is not None:
        file_bytes = await file.read()
        if not filename:
            filename = file.filename or "upload.bin"
        if not filetype and file.content_type:
            filetype = file.content_type
    if file_bytes is None and content is None:
        raise HTTPException(
            status_code=400,
            detail="either 'file' (multipart) or 'content' (form text) is required",
        )
    try:
        return eng.files_upload(
            channels=channels,
            content=content,
            file_bytes=file_bytes,
            filename=filename,
            filetype=filetype,
            initial_comment=initial_comment,
            thread_ts=thread_ts,
            title=title,
        )
    except SlackChatOpsUnavailableError as exc:
        raise _to_503(exc)


@router.post("/api/reactions.add", summary="Add an emoji reaction to a Slack message")
def reactions_add(body: ReactionsAddRequest = Body(...)) -> Dict[str, Any]:
    eng = get_slack_chatops_engine()
    payload = body.dict(exclude_none=True)
    try:
        return eng.reactions_add(payload)
    except SlackChatOpsUnavailableError as exc:
        raise _to_503(exc)


__all__ = ["router"]
