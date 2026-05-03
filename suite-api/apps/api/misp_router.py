"""MISP Threat-Sharing Integration Router — ALDECI.

Wraps ``core.misp_integration_engine.MISPIntegrationEngine`` with REST endpoints
for events, attributes, feeds, and tags from a tenant-supplied MISP instance.

Prefix: /api/v1/misp
Auth:   api_key_auth dependency (mount layer adds scope checks — read:scans)

Routes:
  GET  /api/v1/misp/                              capability summary
  GET  /api/v1/misp/events                        paginated event list
  GET  /api/v1/misp/events/{event_id}             single event view
  POST /api/v1/misp/attributes/restSearch         flexible attribute search
  GET  /api/v1/misp/feeds                         enabled feeds catalog
  GET  /api/v1/misp/tags                          tag lookup

NO MOCKS rule:
  * MISP_URL + MISP_AUTH_KEY env unset → capability summary surfaces
    ``status="unavailable"`` and live endpoints return HTTP 503.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/misp",
    tags=["MISP Threat Intel"],
    dependencies=[Depends(api_key_auth)],
)


def _engine():
    # Indirection so tests can patch the module-level engine via
    # reset_misp_integration_engine() then re-create with stub client.
    from core.misp_integration_engine import get_misp_integration_engine

    return get_misp_integration_engine()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    misp_url_present: bool
    misp_auth_key_present: bool
    status: str  # ok | empty | unavailable


class AttributeRestSearchBody(BaseModel):
    value: Optional[str] = None
    type: Optional[str] = None
    category: Optional[str] = None
    tags: Optional[List[str]] = None
    last: Optional[str] = "24h"
    returnFormat: Optional[str] = "json"

    class Config:
        extra = "allow"  # MISP supports many more search fields.


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _serve(callable_):
    """Translate engine errors to HTTP responses.

    MISPUnavailableError -> 503 (URL/key missing, network, upstream error)
    ValueError           -> 422 (input validation)
    """
    from core.misp_integration_engine import MISPUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except MISPUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", response_model=CapabilityResponse)
async def capability_summary() -> CapabilityResponse:
    """Service capability summary — safe to call without configuration."""
    eng = _engine()
    url_present = eng.url_present()
    key_present = eng.auth_key_present()
    if not (url_present and key_present):
        status = "unavailable"
    else:
        status = "ok"
    return CapabilityResponse(
        service="MISP",
        endpoints=[
            "/events",
            "/events/{id}",
            "/attributes/restSearch",
            "/feeds",
            "/tags",
        ],
        misp_url_present=url_present,
        misp_auth_key_present=key_present,
        status=status,
    )


@router.get("/events")
async def list_events(
    limit: int = Query(50, ge=1, le=1000, description="Max events per page"),
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
) -> Dict[str, Any]:
    """Paginated MISP event index."""
    eng = _engine()
    return _serve(lambda: eng.list_events(limit=limit, page=page))


@router.get("/events/{event_id}")
async def get_event(
    event_id: str = Path(..., description="MISP event id"),
) -> Dict[str, Any]:
    """Single event view including attributes + objects + related events."""
    eng = _engine()
    return _serve(lambda: eng.get_event(event_id))


@router.post("/attributes/restSearch")
async def attributes_rest_search(
    body: AttributeRestSearchBody = Body(default_factory=AttributeRestSearchBody),
) -> Dict[str, Any]:
    """Flexible attribute search via MISP /attributes/restSearch."""
    eng = _engine()
    payload = body.model_dump(exclude_none=True)
    return _serve(lambda: eng.attributes_rest_search(payload))


@router.get("/feeds")
async def list_feeds() -> Dict[str, Any]:
    """List enabled MISP feeds."""
    eng = _engine()
    feeds = _serve(lambda: eng.list_feeds())
    return {"feeds": feeds, "total": len(feeds)}


@router.get("/tags")
async def list_tags(
    searchall: Optional[str] = Query(
        default=None, description="Substring filter applied by MISP"
    ),
) -> Dict[str, Any]:
    """Tag lookup; ``searchall`` performs a substring match on tag names."""
    eng = _engine()
    return _serve(lambda: eng.list_tags(searchall=searchall))


__all__ = ["router"]
