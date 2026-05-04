"""ALDECI Google Chat router — REAL API only, NO MOCKS.

Mounted at ``/api/v1/google-chat`` under the ``read:scans`` scope.

Endpoints
---------
GET    /                                    — capability summary
POST   /webhook                             — proxy text/card to GCHAT_WEBHOOK_URL
GET    /v1/spaces                           — list spaces
POST   /v1/spaces/{space}/messages          — post message via service-account JWT
GET    /v1/spaces/{space}/members           — list members

Auth: api_key_auth + read:scans scope (mounted by platform_app).
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from core.google_chat_engine import (
    GoogleChatUnavailableError,
    get_google_chat_engine,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/google-chat",
    tags=["google-chat"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------- Pydantic


class _CardHeader(BaseModel):
    model_config = ConfigDict(extra="allow")

    title: Optional[str] = None
    subtitle: Optional[str] = None
    imageUrl: Optional[str] = None


class _TextParagraph(BaseModel):
    model_config = ConfigDict(extra="allow")

    text: str


class _Widget(BaseModel):
    model_config = ConfigDict(extra="allow")

    textParagraph: Optional[_TextParagraph] = None


class _Section(BaseModel):
    model_config = ConfigDict(extra="allow")

    widgets: Optional[List[_Widget]] = None


class _Card(BaseModel):
    model_config = ConfigDict(extra="allow")

    header: Optional[_CardHeader] = None
    sections: Optional[List[_Section]] = None


class _CardV2Wrapper(BaseModel):
    model_config = ConfigDict(extra="allow")

    cardId: Optional[str] = None
    card: Optional[_Card] = None


class _Thread(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: Optional[str] = None
    threadKey: Optional[str] = None


class WebhookPayload(BaseModel):
    """Google Chat incoming-webhook payload — must include text or cards."""

    model_config = ConfigDict(extra="allow")

    text: Optional[str] = None
    cards: Optional[List[_Card]] = None
    cardsV2: Optional[List[_CardV2Wrapper]] = None
    thread: Optional[_Thread] = None
    fallbackText: Optional[str] = None


class PostMessageRequest(BaseModel):
    """Google Chat REST POST /spaces/{space}/messages payload."""

    model_config = ConfigDict(extra="allow")

    text: Optional[str] = None
    cards: Optional[List[_Card]] = None
    cardsV2: Optional[List[_CardV2Wrapper]] = None
    thread: Optional[_Thread] = None
    fallbackText: Optional[str] = None


# ----------------------------------------------------------------- helpers


def _to_503(exc: GoogleChatUnavailableError) -> HTTPException:
    return HTTPException(status_code=503, detail=str(exc))


def _validate_message_has_content(model: Any) -> None:
    if not (model.text or model.cards or model.cardsV2):
        raise HTTPException(
            status_code=422,
            detail="message must include at least one of: text, cards, cardsV2",
        )


# ----------------------------------------------------------------- endpoints


@router.get("/", summary="Google Chat capability summary")
def capability_summary() -> Dict[str, Any]:
    eng = get_google_chat_engine()
    return eng.capability_summary()


@router.post("/webhook", summary="Proxy text/card payload to the Google Chat webhook")
def post_webhook(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    eng = get_google_chat_engine()
    if not isinstance(payload, dict) or not payload:
        raise HTTPException(status_code=422, detail="payload must be a non-empty JSON object")
    # Best-effort schema validation (text- or card-payload).
    try:
        model = WebhookPayload.model_validate(payload)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"invalid Google Chat webhook payload: {exc}")
    if not (model.text or model.cards or model.cardsV2):
        raise HTTPException(
            status_code=422,
            detail="webhook payload must include at least one of: text, cards, cardsV2",
        )

    try:
        return eng.post_webhook(payload)
    except GoogleChatUnavailableError as exc:
        raise _to_503(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/v1/spaces", summary="List spaces accessible to the bot")
def list_spaces(
    pageSize: Optional[int] = Query(None, ge=1, le=1000),
    pageToken: Optional[str] = Query(None),
) -> Dict[str, Any]:
    eng = get_google_chat_engine()
    try:
        return eng.list_spaces(page_size=pageSize, page_token=pageToken)
    except GoogleChatUnavailableError as exc:
        raise _to_503(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get(
    "/v1/spaces/{space}/members",
    summary="List members of a space",
)
def list_members(
    space: str,
    pageSize: Optional[int] = Query(None, ge=1, le=1000),
    pageToken: Optional[str] = Query(None),
) -> Dict[str, Any]:
    eng = get_google_chat_engine()
    try:
        return eng.list_members(space, page_size=pageSize, page_token=pageToken)
    except GoogleChatUnavailableError as exc:
        raise _to_503(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post(
    "/v1/spaces/{space}/messages",
    summary="Post a message to a Google Chat space",
)
def post_message(
    space: str,
    body: PostMessageRequest,
) -> Dict[str, Any]:
    eng = get_google_chat_engine()
    _validate_message_has_content(body)
    payload = body.model_dump(exclude_none=True)
    try:
        return eng.post_message(space, payload)
    except GoogleChatUnavailableError as exc:
        raise _to_503(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


__all__ = ["router"]
