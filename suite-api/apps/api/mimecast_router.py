"""Mimecast Email Security Router — ALDECI.

Wraps ``core.mimecast_email_engine`` under prefix ``/api/v1/mimecast``:

  * GET  /                                          capability summary
  * POST /api/ttp/url/decode-url                    decode rewritten URLs
  * POST /api/gateway/get-hold-message-list         list held messages
  * POST /api/gateway/release-hold-message          release held messages
  * POST /api/ttp/threat-intel/get-feed             pull threat-intel feed (binary→b64)
  * POST /api/audit/get-siem-logs                   pull SIEM audit logs
  * POST /api/managedsender/get-managed-senders     list managed senders
  * POST /api/policy/anti-spoofing/get-policy       list anti-spoofing policies

NO MOCKS rule
-------------
* When any of MIMECAST_BASE_URL / MIMECAST_APP_ID / MIMECAST_APP_KEY /
  MIMECAST_ACCESS_KEY / MIMECAST_SECRET_KEY is unset:
    - Capability summary surfaces ``status="unavailable"``.
    - All POST endpoints → HTTP 503.
* No fabricated payloads.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/mimecast",
    tags=["Mimecast"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Engine accessor (lazy import so tests can patch the singleton)
# ---------------------------------------------------------------------------


def _engine():
    from core.mimecast_email_engine import get_mimecast_email_engine

    return get_mimecast_email_engine()


def _serve(callable_):
    """Run a Mimecast call, translating engine errors to HTTP responses."""
    from core.mimecast_email_engine import MimecastUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except MimecastUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    mimecast_app_id_present: bool
    mimecast_app_key_present: bool
    mimecast_access_key_present: bool
    mimecast_secret_key_present: bool
    status: str  # ok | empty | unavailable


_CAPABILITY_ENDPOINTS = [
    "/api/ttp/url/decode-url",
    "/api/gateway/get-hold-message-list",
    "/api/ttp/threat-intel/get-feed",
    "/api/audit/get-siem-logs",
    "/api/managedsender/get-managed-senders",
]


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=CapabilityResponse,
    summary="Mimecast Email Security capability summary",
)
async def capability_summary() -> CapabilityResponse:
    eng = _engine()
    app_id_ok = eng.app_id_present()
    app_key_ok = eng.app_key_present()
    access_key_ok = eng.access_key_present()
    secret_key_ok = eng.secret_key_present()
    if not (app_id_ok and app_key_ok and access_key_ok and secret_key_ok):
        status = "unavailable"
    else:
        # We never cache; "empty" is reserved for future cache wiring.
        status = "ok"
    return CapabilityResponse(
        service="Mimecast Email Security",
        endpoints=_CAPABILITY_ENDPOINTS,
        mimecast_app_id_present=app_id_ok,
        mimecast_app_key_present=app_key_ok,
        mimecast_access_key_present=access_key_ok,
        mimecast_secret_key_present=secret_key_ok,
        status=status,
    )


# ---------------------------------------------------------------------------
# TTP URL decode
# ---------------------------------------------------------------------------


@router.post("/api/ttp/url/decode-url")
async def decode_url(body: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """Decode rewritten Mimecast TTP URLs.

    body: {data:[{url}]}
    response: {meta, data:[{url, decodedUrl, success, errors:[]}]}
    """
    eng = _engine()
    return _serve(lambda: eng.decode_url(body))


# ---------------------------------------------------------------------------
# Gateway — held messages
# ---------------------------------------------------------------------------


@router.post("/api/gateway/get-hold-message-list")
async def get_hold_message_list(body: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """List held messages with pagination + search/filter.

    body.data[0] supports: start, end, admin?, searchBy?{fieldName,value},
                            filterBy?[{fieldName:reason, value, eq:[]}]
    response: {meta, data:[{id, fromHdr, fromEnv, to, sentDateTime, status,
                            route, reason, info, size, attachments, subject,
                            hasError, dateReceived}]}
    """
    eng = _engine()
    return _serve(lambda: eng.get_hold_message_list(body))


@router.post("/api/gateway/release-hold-message")
async def release_hold_message(body: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """Release one or more held messages.

    body: {meta, data:[{id}]}
    """
    eng = _engine()
    return _serve(lambda: eng.release_hold_message(body))


# ---------------------------------------------------------------------------
# TTP threat-intel feed (returns binary envelope: content_type + b64 payload)
# ---------------------------------------------------------------------------


@router.post("/api/ttp/threat-intel/get-feed")
async def get_threat_intel_feed(body: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """Pull threat-intel feed file.

    body.data[0]: {feedType:malware|phishing|impersonation|threats|spam,
                   fileFormat:csv|stix|misp, compress?, start?, end?,
                   fileType:full|incremental}
    response: {content_type, content_length, content_b64} — base64-encoded
              feed bytes, suitable for handing back to a downloader or
              persisting to object storage.
    """
    eng = _engine()
    return _serve(lambda: eng.get_threat_intel_feed(body))


# ---------------------------------------------------------------------------
# Audit / SIEM logs
# ---------------------------------------------------------------------------


@router.post("/api/audit/get-siem-logs")
async def get_siem_logs(body: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """Pull paginated SIEM audit logs.

    body.data[0]: {type:gateway|process|delivery|am|av|spam|policy|exec,
                   compress, fileFormat:json|key_value, token?:cursor}
    """
    eng = _engine()
    return _serve(lambda: eng.get_siem_logs(body))


# ---------------------------------------------------------------------------
# Managed senders
# ---------------------------------------------------------------------------


@router.post("/api/managedsender/get-managed-senders")
async def get_managed_senders(body: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """List managed senders (Permitted/Blocked).

    body.data[0]: {filter:Permitted|Blocked, type:Email|Domain, source?,
                   page?, sortField?}
    response: {meta, data:[{sender, type, source, comment, scope, lastUpdated}]}
    """
    eng = _engine()
    return _serve(lambda: eng.get_managed_senders(body))


# ---------------------------------------------------------------------------
# Anti-spoofing policy
# ---------------------------------------------------------------------------


@router.post("/api/policy/anti-spoofing/get-policy")
async def get_anti_spoofing_policy(body: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """List anti-spoofing policies."""
    eng = _engine()
    return _serve(lambda: eng.get_anti_spoofing_policy(body))


__all__ = ["router"]
