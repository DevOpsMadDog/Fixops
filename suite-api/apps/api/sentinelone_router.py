"""SentinelOne Singularity EDR Live REST Router — ALDECI.

Wraps ``core.sentinelone_edr_engine.SentinelOneEDREngine`` with REST
endpoints for agents, threats, sites, groups, and mitigation actions
against the live SentinelOne API. Distinct from
``sentinelone_connector_router.py`` (which ingests offline JSON dumps via
``connectors/sentinelone_connector.py``) — this router is the *live
ApiToken* surface.

Prefix: /api/v1/sentinelone
Auth:   api_key_auth dependency (mount layer adds read:scans scope)

Routes:
  GET  /api/v1/sentinelone/                                      capability summary
  GET  /api/v1/sentinelone/web/api/v2.1/agents                   list agents
  GET  /api/v1/sentinelone/web/api/v2.1/threats                  list threats
  GET  /api/v1/sentinelone/web/api/v2.1/sites                    list sites
  GET  /api/v1/sentinelone/web/api/v2.1/groups                   list groups
  POST /api/v1/sentinelone/web/api/v2.1/threats/mitigate/{action} mitigate threats

NO MOCKS rule: when SENTINELONE_URL/SENTINELONE_API_TOKEN are missing
the capability summary reports ``status="unavailable"`` and every live
endpoint returns HTTP 503. We do not fabricate agents, threats, sites,
or groups ever.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/sentinelone",
    tags=["SentinelOne EDR"],
    dependencies=[Depends(api_key_auth)],
)


def _engine():
    # Indirection so tests can patch via reset_sentinelone_edr_engine().
    from core.sentinelone_edr_engine import get_sentinelone_edr_engine
    return get_sentinelone_edr_engine()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    sentinelone_url_present: bool
    sentinelone_api_token_present: bool
    status: str  # ok | empty | unavailable


class AgentsResponse(BaseModel):
    data: List[Dict[str, Any]] = Field(default_factory=list)
    pagination: Dict[str, Any] = Field(default_factory=dict)


class ThreatsResponse(BaseModel):
    data: List[Dict[str, Any]] = Field(default_factory=list)
    pagination: Dict[str, Any] = Field(default_factory=dict)


class SitesResponse(BaseModel):
    data: Dict[str, Any] = Field(default_factory=dict)


class GroupsResponse(BaseModel):
    data: List[Dict[str, Any]] = Field(default_factory=list)
    pagination: Dict[str, Any] = Field(default_factory=dict)


class MitigateFilter(BaseModel):
    ids: Optional[List[str]] = Field(default=None, description="Threat IDs to mitigate")
    cursor: Optional[str] = None
    query: Optional[str] = None


class MitigateRequest(BaseModel):
    filter: Dict[str, Any] = Field(..., description="Threat filter selector")
    data: Optional[Dict[str, Any]] = Field(
        default=None, description="Optional action-specific data payload"
    )


class MitigateResponse(BaseModel):
    data: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _serve(callable_):
    """Run a SentinelOne call, translating engine errors to HTTP responses.

    SentinelOneUnavailableError -> 503 (auth missing, network, upstream error)
    ValueError                  -> 422 (input validation)
    """
    from core.sentinelone_edr_engine import SentinelOneUnavailableError
    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except SentinelOneUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", response_model=CapabilityResponse)
async def capability_summary() -> CapabilityResponse:
    """Service summary — safe to call without SentinelOne credentials."""
    eng = _engine()
    url_p = eng.url_present()
    tok_p = eng.api_token_present()
    if url_p and tok_p:
        status = "ok"
    elif url_p or tok_p:
        status = "empty"
    else:
        status = "unavailable"
    return CapabilityResponse(
        service="SentinelOne EDR",
        endpoints=[
            "/web/api/v2.1/agents",
            "/web/api/v2.1/threats",
            "/web/api/v2.1/sites",
            "/web/api/v2.1/groups",
            "/web/api/v2.1/threats/mitigate",
        ],
        sentinelone_url_present=url_p,
        sentinelone_api_token_present=tok_p,
        status=status,
    )


@router.get("/web/api/v2.1/agents", response_model=AgentsResponse)
async def list_agents(
    limit: int = Query(100, ge=1, le=1000),
    siteIds: Optional[str] = Query(None, max_length=1024),
    groupIds: Optional[str] = Query(None, max_length=1024),
    isActive: Optional[bool] = Query(None),
    isUpToDate: Optional[bool] = Query(None),
    infected: Optional[bool] = Query(None),
    isPendingUninstall: Optional[bool] = Query(None),
    osTypes: Optional[str] = Query(None, max_length=256),
    query: Optional[str] = Query(None, max_length=1024),
    cursor: Optional[str] = Query(None, max_length=2048),
) -> AgentsResponse:
    eng = _engine()
    data = _serve(
        lambda: eng.list_agents(
            limit=limit,
            site_ids=siteIds,
            group_ids=groupIds,
            is_active=isActive,
            is_up_to_date=isUpToDate,
            infected=infected,
            is_pending_uninstall=isPendingUninstall,
            os_types=osTypes,
            query=query,
            cursor=cursor,
        )
    )
    return AgentsResponse(**data)


@router.get("/web/api/v2.1/threats", response_model=ThreatsResponse)
async def list_threats(
    limit: int = Query(100, ge=1, le=1000),
    statuses: Optional[str] = Query(None, max_length=256),
    resolved: Optional[bool] = Query(None),
    siteIds: Optional[str] = Query(None, max_length=1024),
    engines: Optional[str] = Query(None, max_length=256),
    classifications: Optional[str] = Query(None, max_length=256),
    createdAtGte: Optional[str] = Query(None, max_length=64),
    query: Optional[str] = Query(None, max_length=1024),
    cursor: Optional[str] = Query(None, max_length=2048),
) -> ThreatsResponse:
    eng = _engine()
    data = _serve(
        lambda: eng.list_threats(
            limit=limit,
            statuses=statuses,
            resolved=resolved,
            site_ids=siteIds,
            engines=engines,
            classifications=classifications,
            created_at_gte=createdAtGte,
            query=query,
            cursor=cursor,
        )
    )
    return ThreatsResponse(**data)


@router.get("/web/api/v2.1/sites", response_model=SitesResponse)
async def list_sites(
    limit: int = Query(100, ge=1, le=1000),
    siteType: Optional[str] = Query(None, max_length=64),
    state: Optional[str] = Query(None, max_length=64),
) -> SitesResponse:
    eng = _engine()
    data = _serve(lambda: eng.list_sites(limit=limit, site_type=siteType, state=state))
    return SitesResponse(**data)


@router.get("/web/api/v2.1/groups", response_model=GroupsResponse)
async def list_groups(
    limit: int = Query(100, ge=1, le=1000),
    siteIds: Optional[str] = Query(None, max_length=1024),
    type: Optional[str] = Query(None, max_length=64),
) -> GroupsResponse:
    eng = _engine()
    data = _serve(lambda: eng.list_groups(limit=limit, site_ids=siteIds, type=type))
    return GroupsResponse(**data)


@router.post(
    "/web/api/v2.1/threats/mitigate/{action}",
    response_model=MitigateResponse,
)
async def mitigate_threats(
    action: str = Path(..., description="kill|quarantine|un-quarantine|remediate|rollback-remediation|network-quarantine|disconnect-from-network|reconnect-to-network"),
    req: MitigateRequest = Body(...),
) -> MitigateResponse:
    eng = _engine()
    data = _serve(
        lambda: eng.mitigate_threats(
            action=action,
            filter_body=req.filter,
            data_body=req.data,
        )
    )
    return MitigateResponse(**data)


__all__ = ["router"]
