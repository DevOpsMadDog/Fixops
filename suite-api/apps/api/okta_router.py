"""Okta IAM Live REST Router — ALDECI (NEW — 2026-05-04).

Wraps ``core.okta_iam_engine.OktaIAMEngine`` with REST endpoints for
Users / Groups / Apps / System Logs / Sessions against a live Okta
tenant. Distinct from ``okta_live_connector_router.py`` (which exposes a
sync/health surface for the legacy connector framework) — this router is
the *direct read-through* surface keyed off ``OKTA_DOMAIN`` /
``OKTA_API_TOKEN``.

Prefix: /api/v1/okta
Auth:   api_key_auth dependency (mount layer adds read:scans scope)

Routes:
  GET  /api/v1/okta/                              capability summary
  GET  /api/v1/okta/api/v1/users                  list users
  GET  /api/v1/okta/api/v1/groups                 list groups
  GET  /api/v1/okta/api/v1/apps                   list applications
  GET  /api/v1/okta/api/v1/logs                   System Log events
  GET  /api/v1/okta/api/v1/sessions/{id}          fetch session by id
  POST /api/v1/okta/api/v1/sessions/me/lifecycle/refresh   refresh me

NO MOCKS rule: when OKTA_DOMAIN / OKTA_API_TOKEN are missing the
capability summary reports ``status="unavailable"`` and every live
endpoint returns HTTP 503. We do not fabricate users / groups / apps /
log events / sessions ever.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/okta",
    tags=["Okta IAM"],
    dependencies=[Depends(api_key_auth)],
)


def _engine():
    # Indirection so tests can patch via reset_okta_iam_engine().
    from core.okta_iam_engine import get_okta_iam_engine
    return get_okta_iam_engine()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    okta_domain_present: bool
    okta_api_token_present: bool
    status: str  # ok | empty | unavailable


class UsersResponse(BaseModel):
    users: List[Dict[str, Any]] = Field(default_factory=list)
    next_cursor: Optional[str] = None


class GroupsResponse(BaseModel):
    groups: List[Dict[str, Any]] = Field(default_factory=list)
    next_cursor: Optional[str] = None


class AppsResponse(BaseModel):
    apps: List[Dict[str, Any]] = Field(default_factory=list)
    next_cursor: Optional[str] = None


class LogsResponse(BaseModel):
    events: List[Dict[str, Any]] = Field(default_factory=list)
    next_cursor: Optional[str] = None


class SessionResponse(BaseModel):
    # Free-form pass-through of Okta session payload.
    # Common keys: id, login, userId, expiresAt, status,
    # lastPasswordVerification, lastFactorVerification, amr.
    model_config = {"extra": "allow"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _serve(callable_):
    """Run an Okta call, translating engine errors to HTTP responses.

    OktaUnavailableError -> 503 (creds missing, network, upstream error)
    ValueError           -> 422 (input validation)
    """
    from core.okta_iam_engine import OktaUnavailableError
    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except OktaUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", response_model=CapabilityResponse)
async def capability_summary() -> CapabilityResponse:
    """Service summary — safe to call without Okta credentials."""
    eng = _engine()
    dom = eng.domain_present()
    tok = eng.token_present()
    if dom and tok:
        status = "ok"
    elif dom or tok:
        status = "empty"
    else:
        status = "unavailable"
    return CapabilityResponse(
        service="Okta",
        endpoints=[
            "/api/v1/users",
            "/api/v1/groups",
            "/api/v1/apps",
            "/api/v1/logs",
            "/api/v1/sessions",
        ],
        okta_domain_present=dom,
        okta_api_token_present=tok,
        status=status,
    )


@router.get("/api/v1/users", response_model=UsersResponse)
async def list_users(
    q: Optional[str] = Query(None, description="Free-text first/last/email match"),
    filter: Optional[str] = Query(None, alias="filter", description="Okta SCIM filter"),
    search: Optional[str] = Query(None, description="Okta search expression"),
    limit: Optional[int] = Query(None, ge=1, le=200),
    after: Optional[str] = Query(None, max_length=1024, description="Pagination cursor"),
) -> UsersResponse:
    eng = _engine()
    data = _serve(
        lambda: eng.list_users(
            q=q, filter_=filter, search=search, limit=limit, after=after
        )
    )
    return UsersResponse(**data)


@router.get("/api/v1/groups", response_model=GroupsResponse)
async def list_groups(
    q: Optional[str] = Query(None, description="Group name search"),
    filter: Optional[str] = Query(None, alias="filter", description="Okta filter"),
    limit: Optional[int] = Query(None, ge=1, le=200),
    after: Optional[str] = Query(None, max_length=1024),
) -> GroupsResponse:
    eng = _engine()
    data = _serve(
        lambda: eng.list_groups(
            q=q, filter_=filter, limit=limit, after=after
        )
    )
    return GroupsResponse(**data)


@router.get("/api/v1/apps", response_model=AppsResponse)
async def list_apps(
    filter: Optional[str] = Query(None, alias="filter", description="Okta filter"),
    limit: Optional[int] = Query(None, ge=1, le=200),
    after: Optional[str] = Query(None, max_length=1024),
) -> AppsResponse:
    eng = _engine()
    data = _serve(
        lambda: eng.list_apps(filter_=filter, limit=limit, after=after)
    )
    return AppsResponse(**data)


@router.get("/api/v1/logs", response_model=LogsResponse)
async def list_logs(
    since: Optional[str] = Query(None, description="ISO-8601 lower bound"),
    until: Optional[str] = Query(None, description="ISO-8601 upper bound"),
    filter: Optional[str] = Query(None, alias="filter", description="Okta filter"),
    q: Optional[str] = Query(None, description="Free-text search"),
    limit: Optional[int] = Query(None, ge=1, le=1000),
    after: Optional[str] = Query(None, max_length=1024),
) -> LogsResponse:
    eng = _engine()
    data = _serve(
        lambda: eng.list_logs(
            since=since, until=until, filter_=filter, q=q,
            limit=limit, after=after,
        )
    )
    return LogsResponse(**data)


@router.get("/api/v1/sessions/{session_id}", response_model=SessionResponse)
async def get_session(
    session_id: str = Path(..., min_length=1, max_length=256),
) -> SessionResponse:
    eng = _engine()
    data = _serve(lambda: eng.get_session(session_id))
    return SessionResponse(**data)


@router.post("/api/v1/sessions/me/lifecycle/refresh", response_model=SessionResponse)
async def refresh_session_me() -> SessionResponse:
    eng = _engine()
    data = _serve(lambda: eng.refresh_session_me())
    return SessionResponse(**data)


__all__ = ["router"]
