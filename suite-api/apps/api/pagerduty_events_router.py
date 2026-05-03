"""ALDECI PagerDuty Events API v2 router — REAL API only, NO MOCKS.

Mounted at ``/api/v1/pagerduty-events`` under the ``read:scans`` scope.

This router is **distinct** from the existing ``/api/v1/pagerduty`` REST
incident-management router (``pagerduty_router.py``). The Events API v2 uses a
``routing_key`` (per-integration) instead of a REST API token.

Endpoints
---------
GET    /                          — capability summary
POST   /v2/enqueue                — trigger / acknowledge / resolve alert event
POST   /v2/change/enqueue         — submit a change event (deploy, config flip)
GET    /v2/dedup_key/lookup       — look up the latest state for a dedup_key
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from core.pagerduty_events_v2_engine import (
    PagerDutyEventsV2UnavailableError,
    get_pagerduty_events_v2_engine,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/pagerduty-events",
    tags=["pagerduty-events"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------- Pydantic


class _Link(BaseModel):
    href: str
    text: Optional[str] = None


class _Image(BaseModel):
    src: str
    href: Optional[str] = None
    alt: Optional[str] = None


class _AlertPayload(BaseModel):
    summary: str
    source: str
    severity: str = Field(..., pattern="^(critical|error|warning|info)$")
    timestamp: Optional[str] = None
    component: Optional[str] = None
    group: Optional[str] = None
    class_: Optional[str] = Field(None, alias="class")
    custom_details: Optional[Dict[str, Any]] = None

    class Config:
        populate_by_name = True


class _AcknowledgeOrResolvePayload(BaseModel):
    summary: Optional[str] = None
    source: Optional[str] = None
    severity: Optional[str] = Field(None, pattern="^(critical|error|warning|info)$")
    timestamp: Optional[str] = None
    component: Optional[str] = None
    group: Optional[str] = None
    class_: Optional[str] = Field(None, alias="class")
    custom_details: Optional[Dict[str, Any]] = None

    class Config:
        populate_by_name = True


class EnqueueEventRequest(BaseModel):
    routing_key: Optional[str] = None
    event_action: str = Field(..., pattern="^(trigger|acknowledge|resolve)$")
    payload: Dict[str, Any]
    dedup_key: Optional[str] = None
    client: Optional[str] = None
    client_url: Optional[str] = None
    links: Optional[List[_Link]] = None
    images: Optional[List[_Image]] = None


class _ChangePayload(BaseModel):
    summary: str
    source: str
    timestamp: str
    custom_details: Optional[Dict[str, Any]] = None


class EnqueueChangeEventRequest(BaseModel):
    routing_key: Optional[str] = None
    payload: _ChangePayload
    links: Optional[List[_Link]] = None


# ----------------------------------------------------------------- helpers


def _to_503(exc: PagerDutyEventsV2UnavailableError) -> HTTPException:
    return HTTPException(status_code=503, detail=str(exc))


# ----------------------------------------------------------------- endpoints


@router.get("/", summary="PagerDuty Events API v2 capability summary")
def capability_summary() -> Dict[str, Any]:
    eng = get_pagerduty_events_v2_engine()
    return eng.capability_summary()


@router.post("/v2/enqueue", summary="Enqueue a PagerDuty alert event (trigger|ack|resolve)")
def enqueue_event(body: EnqueueEventRequest = Body(...)) -> Dict[str, Any]:
    eng = get_pagerduty_events_v2_engine()
    try:
        # Pydantic v2: serialise links/images to plain dicts before forwarding
        payload = dict(body.payload)
        links = (
            [link.model_dump(exclude_none=True) for link in body.links]
            if body.links
            else None
        )
        images = (
            [img.model_dump(exclude_none=True) for img in body.images]
            if body.images
            else None
        )
        return eng.enqueue_event(
            routing_key=body.routing_key,
            event_action=body.event_action,
            payload=payload,
            dedup_key=body.dedup_key,
            client=body.client,
            client_url=body.client_url,
            links=links,
            images=images,
        )
    except PagerDutyEventsV2UnavailableError as exc:
        raise _to_503(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/v2/change/enqueue", summary="Enqueue a PagerDuty change event")
def enqueue_change_event(body: EnqueueChangeEventRequest = Body(...)) -> Dict[str, Any]:
    eng = get_pagerduty_events_v2_engine()
    try:
        payload = body.payload.model_dump(exclude_none=True)
        links = (
            [link.model_dump(exclude_none=True) for link in body.links]
            if body.links
            else None
        )
        return eng.enqueue_change_event(
            routing_key=body.routing_key,
            payload=payload,
            links=links,
        )
    except PagerDutyEventsV2UnavailableError as exc:
        raise _to_503(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/v2/dedup_key/lookup", summary="Look up a dedup_key's latest state")
def dedup_key_lookup(
    routing_key: Optional[str] = Query(
        None, description="Optional override for the env-default routing key"
    ),
    dedup_key: str = Query(..., description="The dedup_key to look up"),
) -> Dict[str, Any]:
    eng = get_pagerduty_events_v2_engine()
    try:
        return eng.dedup_key_lookup(routing_key=routing_key, dedup_key=dedup_key)
    except PagerDutyEventsV2UnavailableError as exc:
        raise _to_503(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


__all__ = ["router"]
