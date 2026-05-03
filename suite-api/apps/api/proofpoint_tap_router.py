"""ALDECI Proofpoint TAP router — REAL httpx only, NO MOCKS.

Mounted at ``/api/v1/proofpoint-tap`` under the ``read:scans`` scope.

Endpoints
---------
GET   /                              — capability summary
GET   /v2/siem/all                   — combined SIEM feed (messages + clicks)
GET   /v2/siem/clicks/blocked        — blocked URL clicks only
GET   /v2/siem/messages/delivered    — delivered messages only
GET   /v2/forensics                  — threat/campaign forensics
GET   /v2/url/decode                 — decode Proofpoint-encoded URLs (query)
POST  /v2/url/decode                 — decode Proofpoint-encoded URLs (body)
GET   /v2/people/vap                 — Very Attacked People
GET   /v2/people/top-clickers        — top URL clickers

When ``PROOFPOINT_TAP_PRINCIPAL`` / ``PROOFPOINT_TAP_SECRET`` are not set,
every lookup endpoint returns HTTP 503. The capability summary still
responds 200 with ``status="unavailable"``.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Query

from core.proofpoint_tap_engine import (
    ProofpointTAPUnavailableError,
    get_proofpoint_tap_engine,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/proofpoint-tap",
    tags=["proofpoint-tap"],
    dependencies=[Depends(api_key_auth)],
)


# ------------------------------------------------------------------ helpers


def _to_503(exc: ProofpointTAPUnavailableError) -> HTTPException:
    return HTTPException(status_code=503, detail=str(exc))


# ----------------------------------------------------------------- endpoints


@router.get("/", summary="Proofpoint TAP capability summary")
def capability_summary() -> Dict[str, Any]:
    eng = get_proofpoint_tap_engine()
    return eng.capability_summary()


# ------------------------------------------------------------------- SIEM


@router.get("/v2/siem/all", summary="Combined SIEM feed (messages + clicks)")
def siem_all(
    format: str = Query("json", pattern="^(json|syslog)$"),
    sinceSeconds: Optional[int] = Query(None, ge=1, le=3600),
    interval: Optional[str] = Query(None, description="ISO-8601 interval window"),
) -> Dict[str, Any]:
    eng = get_proofpoint_tap_engine()
    try:
        return eng.siem_all(
            format=format, sinceSeconds=sinceSeconds, interval=interval
        )
    except ProofpointTAPUnavailableError as exc:
        raise _to_503(exc)


@router.get("/v2/siem/clicks/blocked", summary="Blocked URL clicks only")
def siem_clicks_blocked(
    format: str = Query("json", pattern="^(json|syslog)$"),
    sinceSeconds: Optional[int] = Query(None, ge=1, le=3600),
) -> Dict[str, Any]:
    eng = get_proofpoint_tap_engine()
    try:
        return eng.siem_clicks_blocked(format=format, sinceSeconds=sinceSeconds)
    except ProofpointTAPUnavailableError as exc:
        raise _to_503(exc)


@router.get("/v2/siem/messages/delivered", summary="Delivered messages only")
def siem_messages_delivered(
    format: str = Query("json", pattern="^(json|syslog)$"),
    sinceSeconds: Optional[int] = Query(None, ge=1, le=3600),
) -> Dict[str, Any]:
    eng = get_proofpoint_tap_engine()
    try:
        return eng.siem_messages_delivered(
            format=format, sinceSeconds=sinceSeconds
        )
    except ProofpointTAPUnavailableError as exc:
        raise _to_503(exc)


# ------------------------------------------------------------- forensics


@router.get("/v2/forensics", summary="Threat or campaign forensics report")
def forensics(
    threatId: Optional[str] = Query(None, min_length=1),
    campaignId: Optional[str] = Query(None, min_length=1),
    aggregate: Optional[bool] = Query(None),
) -> Dict[str, Any]:
    eng = get_proofpoint_tap_engine()
    try:
        return eng.forensics(
            threatId=threatId, campaignId=campaignId, aggregate=aggregate
        )
    except ProofpointTAPUnavailableError as exc:
        raise _to_503(exc)


# ------------------------------------------------------------ URL decode


@router.get("/v2/url/decode", summary="Decode Proofpoint-encoded URLs (query)")
def url_decode_get(
    urls: str = Query(
        ..., min_length=1, description="Comma-separated base64 pp-URL strings"
    ),
) -> Dict[str, Any]:
    eng = get_proofpoint_tap_engine()
    try:
        return eng.url_decode_get(urls=urls)
    except ProofpointTAPUnavailableError as exc:
        raise _to_503(exc)


@router.post("/v2/url/decode", summary="Decode Proofpoint-encoded URLs (body)")
def url_decode_post(
    body: Dict[str, List[str]] = Body(
        ..., examples=[{"urls": ["https://urldefense.proofpoint.com/v2/url?u=..."]}]
    ),
) -> Dict[str, Any]:
    eng = get_proofpoint_tap_engine()
    urls = body.get("urls") or []
    if not isinstance(urls, list) or not urls:
        raise HTTPException(
            status_code=400, detail="body.urls must be a non-empty list of strings"
        )
    try:
        return eng.url_decode_post(urls=urls)
    except ProofpointTAPUnavailableError as exc:
        raise _to_503(exc)


# ------------------------------------------------------------------ people


@router.get("/v2/people/vap", summary="Very Attacked People (VAP)")
def people_vap(
    window: str = Query("14d", pattern="^(1d|14d|2w|30d|90d|3m)$"),
    size: Optional[int] = Query(None, ge=1, le=10000),
    page: Optional[int] = Query(None, ge=1),
) -> Dict[str, Any]:
    eng = get_proofpoint_tap_engine()
    try:
        return eng.people_vap(window=window, size=size, page=page)
    except ProofpointTAPUnavailableError as exc:
        raise _to_503(exc)


@router.get("/v2/people/top-clickers", summary="Top URL clickers")
def people_top_clickers(
    window: str = Query("14d", pattern="^(1d|14d|2w|30d|90d|3m)$"),
    size: Optional[int] = Query(None, ge=1, le=10000),
    page: Optional[int] = Query(None, ge=1),
) -> Dict[str, Any]:
    eng = get_proofpoint_tap_engine()
    try:
        return eng.people_top_clickers(window=window, size=size, page=page)
    except ProofpointTAPUnavailableError as exc:
        raise _to_503(exc)


__all__ = ["router"]
