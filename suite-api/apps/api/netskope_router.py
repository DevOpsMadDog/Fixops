"""Netskope CASB API Live REST Router — ALDECI (NEW — 2026-05-04).

Wraps ``core.netskope_casb_engine.NetskopeCASBEngine`` with REST endpoints
for events / DLP incidents / SCIM users / URL policy lists / UCI series /
per-user UCI detail against the live Netskope tenant.

Prefix: /api/v1/netskope
Auth:   api_key_auth dependency (mount layer adds read:scans scope)

Routes:
  GET  /api/v1/netskope/                                       capability summary
  GET  /api/v1/netskope/api/v2/events/data/page                alerts / events
  GET  /api/v1/netskope/api/v2/events/data/incidents           DLP incidents
  GET  /api/v1/netskope/api/v2/scim/Users                      SCIM v2 user directory
  GET  /api/v1/netskope/api/v2/policy/url/list                 URL policy lists
  GET  /api/v1/netskope/api/v2/services/operational/uci        UCI time series
  POST /api/v1/netskope/api/v2/incidents/uba/getuci            per-user UCI detail

NO MOCKS rule: when NETSKOPE_TENANT_URL / NETSKOPE_API_TOKEN are missing
the capability summary reports ``status="unavailable"`` and every live
endpoint returns HTTP 503. We do not fabricate Netskope data ever.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/netskope",
    tags=["Netskope CASB"],
    dependencies=[Depends(api_key_auth)],
)


def _engine():
    # Indirection so tests can patch via reset_netskope_casb_engine().
    from core.netskope_casb_engine import get_netskope_casb_engine
    return get_netskope_casb_engine()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    netskope_tenant_url_present: bool
    netskope_api_token_present: bool
    status: str  # ok | empty | unavailable


class NetskopeEnvelope(BaseModel):
    """Netskope passthrough envelope — extra fields preserved."""
    model_config = {"extra": "allow"}

    result: Any = None
    ok: Optional[Any] = None
    status: Optional[Any] = None


class SCIMListResponse(BaseModel):
    """SCIM v2 ListResponse envelope — extra fields preserved."""
    model_config = {"extra": "allow"}

    schemas: List[str] = Field(default_factory=list)
    totalResults: Optional[int] = None
    startIndex: Optional[int] = None
    itemsPerPage: Optional[int] = None
    Resources: List[Any] = Field(default_factory=list)


class UBAGetUCIRequest(BaseModel):
    start_time: int
    end_time: int
    ip: str
    user_id: Optional[str] = None
    user_name: Optional[str] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _serve(callable_):
    """Run a Netskope call, translating engine errors to HTTP responses.

    NetskopeUnavailableError -> 503 (creds missing, network, upstream error)
    ValueError               -> 422 (input validation)
    """
    from core.netskope_casb_engine import NetskopeUnavailableError
    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except NetskopeUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", response_model=CapabilityResponse)
async def capability_summary() -> CapabilityResponse:
    """Service summary — safe to call without Netskope credentials."""
    eng = _engine()
    tenant = eng.tenant_url_present()
    tok = eng.api_token_present()
    status = "ok" if (tenant and tok) else "unavailable"
    return CapabilityResponse(
        service="Netskope CASB",
        endpoints=[
            "/api/v2/events/data/page",
            "/api/v2/events/data/incidents",
            "/api/v2/scim/Users",
            "/api/v2/policy/url/list",
            "/api/v2/services/operational/uci",
        ],
        netskope_tenant_url_present=tenant,
        netskope_api_token_present=tok,
        status=status,
    )


@router.get(
    "/api/v2/events/data/page",
    response_model=NetskopeEnvelope,
)
async def list_events_page(
    type: Optional[str] = Query(
        None,
        description=(
            "alert|application|page|infrastructure|network|incident"
        ),
    ),
    query: Optional[str] = Query(None, description="Netskope query DSL filter"),
    starttime: Optional[int] = Query(None, description="Epoch start time"),
    endtime: Optional[int] = Query(None, description="Epoch end time"),
    limit: Optional[int] = Query(None, ge=1, le=10000),
    token: Optional[str] = Query(None, description="Pagination cursor"),
) -> NetskopeEnvelope:
    eng = _engine()
    data = _serve(
        lambda: eng.list_events_page(
            type=type,
            query=query,
            starttime=starttime,
            endtime=endtime,
            limit=limit,
            token=token,
        )
    )
    return NetskopeEnvelope(**data)


@router.get(
    "/api/v2/events/data/incidents",
    response_model=NetskopeEnvelope,
)
async def list_dlp_incidents(
    starttime: Optional[int] = Query(None, description="Epoch start time"),
    endtime: Optional[int] = Query(None, description="Epoch end time"),
    query: Optional[str] = Query(None, description="Netskope query DSL filter"),
    limit: Optional[int] = Query(None, ge=1, le=10000),
    token: Optional[str] = Query(None, description="Pagination cursor"),
) -> NetskopeEnvelope:
    eng = _engine()
    data = _serve(
        lambda: eng.list_dlp_incidents(
            starttime=starttime,
            endtime=endtime,
            query=query,
            limit=limit,
            token=token,
        )
    )
    return NetskopeEnvelope(**data)


@router.get(
    "/api/v2/scim/Users",
    response_model=SCIMListResponse,
)
async def list_scim_users(
    startIndex: Optional[int] = Query(None, ge=1),
    count: Optional[int] = Query(None, ge=0, le=1000),
    filter: Optional[str] = Query(
        None, description="SCIM v2 filter expression"
    ),
) -> SCIMListResponse:
    eng = _engine()
    data = _serve(
        lambda: eng.list_scim_users(
            startIndex=startIndex,
            count=count,
            filter=filter,
        )
    )
    return SCIMListResponse(**data)


@router.get(
    "/api/v2/policy/url/list",
    response_model=NetskopeEnvelope,
)
async def list_url_policy(
    cursor: Optional[str] = Query(None, description="Pagination cursor"),
    limit: Optional[int] = Query(None, ge=1, le=1000),
) -> NetskopeEnvelope:
    eng = _engine()
    data = _serve(lambda: eng.list_url_policy(cursor=cursor, limit=limit))
    return NetskopeEnvelope(**data)


@router.get(
    "/api/v2/services/operational/uci",
    response_model=NetskopeEnvelope,
)
async def get_uci_series(
    starttime: Optional[int] = Query(None, description="Epoch start time"),
    endtime: Optional[int] = Query(None, description="Epoch end time"),
) -> NetskopeEnvelope:
    eng = _engine()
    data = _serve(
        lambda: eng.get_uci_series(starttime=starttime, endtime=endtime)
    )
    return NetskopeEnvelope(**data)


@router.post(
    "/api/v2/incidents/uba/getuci",
    response_model=NetskopeEnvelope,
)
async def get_uba_uci(body: UBAGetUCIRequest) -> NetskopeEnvelope:
    eng = _engine()
    data = _serve(
        lambda: eng.get_uba_uci(
            start_time=body.start_time,
            end_time=body.end_time,
            ip=body.ip,
            user_id=body.user_id,
            user_name=body.user_name,
        )
    )
    return NetskopeEnvelope(**data)


__all__ = ["router"]
