"""CyberArk PAM (PVWA REST) Router — ALDECI.

Wraps ``core.cyberark_pam_engine.CyberArkPAMEngine`` with REST endpoints
mirroring the CyberArk Password Vault Web Access (PVWA) HTTP API.

Prefix: /api/v1/cyberark-pam
Auth:   api_key_auth dependency (mount layer adds scope checks — read:scans)

NOTE: ALDECI also ships ``cyberark_live_connector_router`` (a higher-level
abstraction). This router is the *raw PVWA wire-protocol* surface and uses
its own prefix to avoid collision.

Routes:
  GET  /api/v1/cyberark-pam/                                                   capability summary
  POST /api/v1/cyberark-pam/PasswordVault/API/auth/Cyberark/Logon              session token
  POST /api/v1/cyberark-pam/PasswordVault/API/auth/Logoff                      invalidate token
  GET  /api/v1/cyberark-pam/PasswordVault/API/Accounts                         account list
  GET  /api/v1/cyberark-pam/PasswordVault/API/Accounts/{id}                    single account
  POST /api/v1/cyberark-pam/PasswordVault/API/Accounts/{id}/Password/Retrieve  password retrieval
  GET  /api/v1/cyberark-pam/PasswordVault/API/Safes                            safe list
  GET  /api/v1/cyberark-pam/PasswordVault/API/Safes/{safe_url_id}/Members      safe members
  GET  /api/v1/cyberark-pam/PasswordVault/API/PSM/Sessions                     PSM sessions list
  GET  /api/v1/cyberark-pam/PasswordVault/API/PSM/Recordings                   PSM recordings list

NO MOCKS rule: when ``CYBERARK_URL``, ``CYBERARK_USERNAME`` or
``CYBERARK_PASSWORD`` is unset the capability summary returns
``status="unavailable"`` and every live call returns HTTP 503. We never
fabricate accounts, safes, sessions or recordings.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query, Response
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/cyberark-pam",
    tags=["CyberArk PAM"],
    dependencies=[Depends(api_key_auth)],
)


def _engine():
    from core.cyberark_pam_engine import get_cyberark_pam_engine

    return get_cyberark_pam_engine()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    cyberark_url_present: bool
    cyberark_username_present: bool
    cyberark_password_present: bool
    status: str  # ok | empty | unavailable


class LogonRequest(BaseModel):
    username: str = Field(..., description="Vault user")
    password: str = Field(..., description="Vault password / API key")
    concurrentSession: Optional[bool] = Field(
        default=None,
        description="Allow multiple concurrent sessions for the same user",
    )


class PasswordRetrieveRequest(BaseModel):
    reason: str = Field(..., description="Audited justification for password disclosure")
    ticketingSystemName: Optional[str] = None
    ticketId: Optional[str] = None
    version: Optional[int] = Field(
        default=None, description="Specific password version to retrieve"
    )
    actionType: Optional[str] = Field(
        default=None,
        description="show | copy | connect (audited action verb)",
    )
    isUse: Optional[bool] = None
    machine: Optional[str] = None
    useDoubleAuth: Optional[bool] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _serve(callable_):
    """Translate engine errors to HTTP responses.

    CyberArkPAMUnavailableError -> 503
    ValueError                  -> 422
    """
    from core.cyberark_pam_engine import CyberArkPAMUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except CyberArkPAMUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", response_model=CapabilityResponse)
async def capability_summary() -> CapabilityResponse:
    """Service capability summary — safe to call without CyberArk env."""
    eng = _engine()
    url = eng.cyberark_url_present()
    user = eng.cyberark_username_present()
    pw = eng.cyberark_password_present()
    if not (url and user and pw):
        status = "unavailable"
    else:
        status = "empty"  # no cache; live calls populate
    return CapabilityResponse(
        service="CyberArk PAM (PVWA)",
        endpoints=[
            "/PasswordVault/API/auth/Cyberark/Logon",
            "/PasswordVault/API/Accounts",
            "/PasswordVault/API/Safes",
            "/PasswordVault/API/PSM/Sessions",
            "/PasswordVault/API/Accounts/{id}/Password/Retrieve",
        ],
        cyberark_url_present=url,
        cyberark_username_present=user,
        cyberark_password_present=pw,
        status=status,
    )


@router.post("/PasswordVault/API/auth/Cyberark/Logon")
async def logon(body: LogonRequest = Body(...)) -> Response:
    """``POST /PasswordVault/API/auth/Cyberark/Logon`` — returns raw quoted token string."""
    eng = _engine()
    token = _serve(
        lambda: eng.logon(
            username=body.username,
            password=body.password,
            concurrent_session=body.concurrentSession,
        )
    )
    # Preserve raw quoted string contract (CyberArk emits a JSON string literal).
    return Response(content=token, media_type="application/json")


@router.post("/PasswordVault/API/auth/Logoff", status_code=204)
async def logoff() -> Response:
    """``POST /PasswordVault/API/auth/Logoff`` — invalidates token."""
    eng = _engine()
    _serve(eng.logoff)
    return Response(status_code=204)


@router.get("/PasswordVault/API/Accounts")
async def list_accounts(
    search: Optional[str] = Query(None),
    filter: Optional[str] = Query(None),  # noqa: A002
    limit: Optional[int] = Query(None, ge=0, le=10000),
    offset: Optional[int] = Query(None, ge=0),
    sort: Optional[str] = Query(None),
    savedfilter: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """``GET /PasswordVault/API/Accounts`` — paginated account list."""
    eng = _engine()
    return _serve(
        lambda: eng.list_accounts(
            search=search,
            filter=filter,
            limit=limit,
            offset=offset,
            sort=sort,
            savedfilter=savedfilter,
        )
    )


@router.get("/PasswordVault/API/Accounts/{account_id}")
async def get_account(
    account_id: str = Path(..., description="Vault account id"),
) -> Dict[str, Any]:
    """``GET /PasswordVault/API/Accounts/{id}``"""
    eng = _engine()
    return _serve(lambda: eng.get_account(account_id=account_id))


@router.post("/PasswordVault/API/Accounts/{account_id}/Password/Retrieve")
async def retrieve_password(
    account_id: str = Path(..., description="Vault account id"),
    body: PasswordRetrieveRequest = Body(...),
) -> Response:
    """``POST /PasswordVault/API/Accounts/{id}/Password/Retrieve``.

    Returns the raw quoted JSON string CyberArk emits — callers receive the
    password verbatim per CyberArk's API contract.
    """
    if body.actionType and body.actionType not in {"show", "copy", "connect"}:
        raise HTTPException(
            status_code=422,
            detail="actionType must be one of show|copy|connect.",
        )
    eng = _engine()
    pw = _serve(
        lambda: eng.retrieve_password(
            account_id=account_id,
            reason=body.reason,
            ticketing_system_name=body.ticketingSystemName,
            ticket_id=body.ticketId,
            version=body.version,
            action_type=body.actionType,
            is_use=body.isUse,
            machine=body.machine,
            use_double_auth=body.useDoubleAuth,
        )
    )
    return Response(content=pw, media_type="application/json")


@router.get("/PasswordVault/API/Safes")
async def list_safes(
    limit: Optional[int] = Query(None, ge=0, le=10000),
    offset: Optional[int] = Query(None, ge=0),
    sort: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    extendedDetails: Optional[bool] = Query(None),
) -> Dict[str, Any]:
    """``GET /PasswordVault/API/Safes``"""
    eng = _engine()
    return _serve(
        lambda: eng.list_safes(
            limit=limit,
            offset=offset,
            sort=sort,
            search=search,
            extended_details=extendedDetails,
        )
    )


@router.get("/PasswordVault/API/Safes/{safe_url_id}/Members")
async def list_safe_members(
    safe_url_id: str = Path(..., description="Safe URL id"),
    search: Optional[str] = Query(None),
    sort: Optional[str] = Query(None),
    offset: Optional[int] = Query(None, ge=0),
    limit: Optional[int] = Query(None, ge=0, le=10000),
    filter: Optional[str] = Query(None),  # noqa: A002
    memberType: Optional[str] = Query(
        None, description="User | Group | Role"
    ),
) -> Dict[str, Any]:
    """``GET /PasswordVault/API/Safes/{safe_url_id}/Members``"""
    eng = _engine()
    return _serve(
        lambda: eng.list_safe_members(
            safe_url_id=safe_url_id,
            search=search,
            sort=sort,
            offset=offset,
            limit=limit,
            filter=filter,
            member_type=memberType,
        )
    )


@router.get("/PasswordVault/API/PSM/Sessions")
async def list_psm_sessions(
    limit: Optional[int] = Query(None, ge=0, le=10000),
    offset: Optional[int] = Query(None, ge=0),
    search: Optional[str] = Query(None),
    sort: Optional[str] = Query(None),
    filter: Optional[str] = Query(None),  # noqa: A002
) -> Dict[str, Any]:
    """``GET /PasswordVault/API/PSM/Sessions``"""
    eng = _engine()
    return _serve(
        lambda: eng.list_psm_sessions(
            limit=limit,
            offset=offset,
            search=search,
            sort=sort,
            filter=filter,
        )
    )


@router.get("/PasswordVault/API/PSM/Recordings")
async def list_psm_recordings(
    fromDate: Optional[str] = Query(None, description="ISO 8601 lower bound"),
    toDate: Optional[str] = Query(None, description="ISO 8601 upper bound"),
    limit: Optional[int] = Query(None, ge=0, le=10000),
    offset: Optional[int] = Query(None, ge=0),
    search: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """``GET /PasswordVault/API/PSM/Recordings``"""
    eng = _engine()
    return _serve(
        lambda: eng.list_psm_recordings(
            from_date=fromDate,
            to_date=toDate,
            limit=limit,
            offset=offset,
            search=search,
        )
    )
