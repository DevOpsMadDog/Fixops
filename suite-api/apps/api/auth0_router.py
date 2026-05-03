"""Auth0 Management API Router — ALDECI.

Wraps ``core.auth0_engine`` and exposes Auth0 Management API v2 endpoints
under prefix ``/api/v1/auth0``.

  * GET /                               — capability summary
  * GET /api/v2/users                    — list users (lucene query support)
  * GET /api/v2/users/{user_id}          — single user
  * GET /api/v2/users/{user_id}/roles    — roles assigned to user
  * GET /api/v2/users/{user_id}/permissions — permissions assigned to user
  * GET /api/v2/clients                  — applications / clients
  * GET /api/v2/connections              — identity providers
  * GET /api/v2/logs                     — tenant log events
  * GET /api/v2/roles                    — roles
  * GET /api/v2/roles/{role_id}/permissions — permissions in role

NO MOCKS rule
-------------
* When AUTH0_DOMAIN / AUTH0_CLIENT_ID / AUTH0_CLIENT_SECRET is unset:
    - Capability summary surfaces ``status="unavailable"``.
    - All live endpoints → HTTP 503.
* No fabricated payloads.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/auth0",
    tags=["Auth0"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Engine accessor (lazy import so tests can patch the singleton)
# ---------------------------------------------------------------------------


def _engine():
    from core.auth0_engine import get_auth0_engine

    return get_auth0_engine()


def _serve(callable_):
    """Run an Auth0 call, translating engine errors to HTTP responses.

    Auth0UnavailableError -> 503 (creds missing, network, upstream error)
    ValueError            -> 422 (input validation)
    """
    from core.auth0_engine import Auth0UnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Auth0UnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    auth0_domain_present: bool
    auth0_client_id_present: bool
    auth0_client_secret_present: bool
    status: str  # ok | empty | unavailable


# ---------------------------------------------------------------------------
# Capability
# ---------------------------------------------------------------------------


_ENDPOINTS = [
    "/api/v2/users",
    "/api/v2/clients",
    "/api/v2/connections",
    "/api/v2/logs",
    "/api/v2/roles",
]


@router.get("/", response_model=CapabilityResponse)
def capability() -> CapabilityResponse:
    """Capability summary — surfaces credential presence + status."""
    eng = _engine()
    domain = eng.domain_present()
    cid = eng.client_id_present()
    csec = eng.client_secret_present()

    if not (domain and cid and csec):
        status = "unavailable"
    elif eng.has_token():
        status = "ok"
    else:
        status = "empty"

    return CapabilityResponse(
        service="Auth0 Management API",
        endpoints=_ENDPOINTS,
        auth0_domain_present=domain,
        auth0_client_id_present=cid,
        auth0_client_secret_present=csec,
        status=status,
    )


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


@router.get("/api/v2/users")
def list_users(
    per_page: int = Query(50, ge=1, le=100),
    page: int = Query(0, ge=0),
    include_totals: bool = Query(False),
    search_engine: str = Query("v3"),
    q: Optional[str] = Query(None, description="Lucene query"),
    sort: Optional[str] = Query(None, description="field:1 or field:-1"),
    fields: Optional[str] = Query(None, description="Comma-separated field list"),
    include_fields: bool = Query(True),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().list_users(
            per_page=per_page,
            page=page,
            include_totals=include_totals,
            search_engine=search_engine,
            q=q,
            sort=sort,
            fields=fields,
            include_fields=include_fields,
        )
    )


@router.get("/api/v2/users/{user_id}")
def get_user(user_id: str = Path(..., min_length=1)) -> Dict[str, Any]:
    body = _serve(lambda: _engine().get_user(user_id))
    if body is None:
        raise HTTPException(status_code=404, detail=f"user {user_id} not found")
    return body


@router.get("/api/v2/users/{user_id}/roles")
def get_user_roles(user_id: str = Path(..., min_length=1)) -> Dict[str, Any]:
    roles = _serve(lambda: _engine().get_user_roles(user_id))
    return {"user_id": user_id, "roles": roles}


@router.get("/api/v2/users/{user_id}/permissions")
def get_user_permissions(user_id: str = Path(..., min_length=1)) -> Dict[str, Any]:
    perms = _serve(lambda: _engine().get_user_permissions(user_id))
    return {"user_id": user_id, "permissions": perms}


# ---------------------------------------------------------------------------
# Clients
# ---------------------------------------------------------------------------


@router.get("/api/v2/clients")
def list_clients(
    fields: Optional[str] = Query(None),
    include_fields: bool = Query(True),
    page: int = Query(0, ge=0),
    per_page: int = Query(50, ge=1, le=100),
    include_totals: bool = Query(False),
    is_global: Optional[bool] = Query(None),
    is_first_party: Optional[bool] = Query(None),
    app_type: Optional[str] = Query(
        None,
        pattern=r"^(native|spa|regular_web|non_interactive)$",
    ),
    client_id: Optional[str] = Query(None),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().list_clients(
            fields=fields,
            include_fields=include_fields,
            page=page,
            per_page=per_page,
            include_totals=include_totals,
            is_global=is_global,
            is_first_party=is_first_party,
            app_type=app_type,
            client_id=client_id,
        )
    )


# ---------------------------------------------------------------------------
# Connections
# ---------------------------------------------------------------------------


@router.get("/api/v2/connections")
def list_connections(
    strategy: Optional[str] = Query(None),
    name: Optional[str] = Query(None),
    fields: Optional[str] = Query(None),
    include_fields: bool = Query(True),
    page: int = Query(0, ge=0),
    per_page: int = Query(50, ge=1, le=100),
) -> Dict[str, Any]:
    conns = _serve(
        lambda: _engine().list_connections(
            strategy=strategy,
            name=name,
            fields=fields,
            include_fields=include_fields,
            page=page,
            per_page=per_page,
        )
    )
    return {"connections": conns, "length": len(conns)}


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------


@router.get("/api/v2/logs")
def list_logs(
    per_page: int = Query(50, ge=1, le=100),
    page: int = Query(0, ge=0),
    q: Optional[str] = Query(None, description="Lucene query"),
    from_log_id: Optional[str] = Query(None, alias="from"),
    take: Optional[int] = Query(None, ge=1, le=100),
    include_totals: bool = Query(False),
    fields: Optional[str] = Query(None),
    include_fields: bool = Query(True),
    sort: Optional[str] = Query(None),
) -> Dict[str, Any]:
    logs = _serve(
        lambda: _engine().list_logs(
            per_page=per_page,
            page=page,
            q=q,
            from_log_id=from_log_id,
            take=take,
            include_totals=include_totals,
            fields=fields,
            include_fields=include_fields,
            sort=sort,
        )
    )
    return {"logs": logs, "length": len(logs)}


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------


@router.get("/api/v2/roles")
def list_roles(
    per_page: int = Query(50, ge=1, le=100),
    page: int = Query(0, ge=0),
    name_filter: Optional[str] = Query(None),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().list_roles(
            per_page=per_page,
            page=page,
            name_filter=name_filter,
        )
    )


@router.get("/api/v2/roles/{role_id}/permissions")
def get_role_permissions(role_id: str = Path(..., min_length=1)) -> Dict[str, Any]:
    perms = _serve(lambda: _engine().get_role_permissions(role_id))
    return {"role_id": role_id, "permissions": perms}


__all__ = ["router"]
