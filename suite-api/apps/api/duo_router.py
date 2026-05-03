"""Duo Security MFA Router - ALDECI.

Prefix: /api/v1/duo
Auth:   X-API-Key + scope read:scans (mounted in platform_app.py)

Routes:
  GET  /                         capability summary
  POST /auth/v2/preauth          enrollment + factor probe
  POST /auth/v2/auth             issue auth challenge
  GET  /auth/v2/auth_status      poll async tx
  GET  /auth/v2/check            signature/time check
  GET  /admin/v1/users           list/filter users
  GET  /admin/v1/integrations    list integrations

NO MOCKS rule
-------------
* When DUO_IKEY / DUO_SKEY / DUO_HOST are missing:
    - capability summary -> status="unavailable"
    - any live endpoint  -> HTTP 503
* No fabricated payloads.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/duo",
    tags=["Duo Security MFA"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Engine accessor
# ---------------------------------------------------------------------------


def _engine():
    from core.duo_mfa_engine import get_duo_mfa_engine

    return get_duo_mfa_engine()


def _serve(callable_):
    """Translate engine errors into HTTP responses.

    DuoUnavailableError -> 503 (creds missing / network / upstream error)
    ValueError          -> 422 (input validation)
    """
    from core.duo_mfa_engine import DuoUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except DuoUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    duo_ikey_present: bool
    duo_skey_present: bool
    duo_host_present: bool
    status: str  # ok | empty | unavailable


class DuoDevice(BaseModel):
    capabilities: List[str] = []
    device: str = ""
    type: str = ""
    name: str = ""
    number: str = ""
    sms_nextcode: str = ""


class PreauthRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=128)
    ipaddr: Optional[str] = None
    hostname: Optional[str] = None
    trusted_device_token: Optional[str] = None


class PreauthResponse(BaseModel):
    result: str  # auth | allow | deny | enroll
    status_msg: str = ""
    devices: List[DuoDevice] = []


class AuthRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=128)
    factor: str = Field("auto", description="auto|push|passcode|phone|sms")
    device: str = Field("auto")
    passcode: Optional[str] = None
    async_: Optional[bool] = Field(default=None, alias="async")
    ipaddr: Optional[str] = None
    hostname: Optional[str] = None

    model_config = {"populate_by_name": True}


class AuthResponse(BaseModel):
    txid: str = ""
    result: str  # allow | deny | waiting
    status: str = ""
    status_msg: str = ""


class AuthStatusResponse(BaseModel):
    result: str
    status: str = ""
    status_msg: str = ""


class CheckResponse(BaseModel):
    time: int


class DuoUser(BaseModel):
    user_id: str = ""
    username: str = ""
    alias1: str = ""
    alias2: str = ""
    alias3: str = ""
    alias4: str = ""
    realname: str = ""
    email: str = ""
    status: str = ""
    last_login: Optional[int] = None
    phones: List[Any] = []
    tokens: List[Any] = []
    u2ftokens: List[Any] = []
    groups: List[Any] = []


class UsersResponse(BaseModel):
    users: List[DuoUser] = []


class DuoIntegration(BaseModel):
    integration_key: str = ""
    name: str = ""
    type: str = ""
    enroll_policy: str = ""
    greeting: str = ""
    networks_for_api_access: List[str] = []


class IntegrationsResponse(BaseModel):
    integrations: List[DuoIntegration] = []


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", response_model=CapabilityResponse, summary="Duo MFA capability summary")
async def capability_summary() -> CapabilityResponse:
    """Capability summary - safe to call without creds."""
    eng = _engine()
    ikey = eng.ikey_present()
    skey = eng.skey_present()
    host = eng.host_present()
    if not (ikey and skey and host):
        status = "unavailable"
    else:
        status = "ok"
    return CapabilityResponse(
        service="Duo Security",
        endpoints=[
            "/auth/v2/auth",
            "/auth/v2/check",
            "/admin/v1/users",
            "/admin/v1/integrations",
            "/admin/v1/logs/authentication",
        ],
        duo_ikey_present=ikey,
        duo_skey_present=skey,
        duo_host_present=host,
        status=status,
    )


@router.post("/auth/v2/preauth", response_model=PreauthResponse)
async def preauth_endpoint(body: PreauthRequest = Body(...)) -> PreauthResponse:
    """Duo Auth API v2 /preauth - enrollment + factor probe."""
    eng = _engine()
    data = _serve(
        lambda: eng.preauth(
            username=body.username,
            ipaddr=body.ipaddr,
            hostname=body.hostname,
            trusted_device_token=body.trusted_device_token,
        )
    )
    return PreauthResponse(**data)


@router.post("/auth/v2/auth", response_model=AuthResponse)
async def auth_endpoint(body: AuthRequest = Body(...)) -> AuthResponse:
    """Duo Auth API v2 /auth - issue auth challenge."""
    eng = _engine()
    data = _serve(
        lambda: eng.auth(
            username=body.username,
            factor=body.factor,
            device=body.device,
            passcode=body.passcode,
            async_=body.async_,
            ipaddr=body.ipaddr,
            hostname=body.hostname,
        )
    )
    return AuthResponse(**data)


@router.get("/auth/v2/auth_status", response_model=AuthStatusResponse)
async def auth_status_endpoint(
    txid: str = Query(..., description="Async auth transaction id"),
) -> AuthStatusResponse:
    """Duo Auth API v2 /auth_status - poll async tx."""
    eng = _engine()
    data = _serve(lambda: eng.auth_status(txid))
    return AuthStatusResponse(**data)


@router.get("/auth/v2/check", response_model=CheckResponse)
async def check_endpoint() -> CheckResponse:
    """Duo Auth API v2 /check - signature/time check."""
    eng = _engine()
    data = _serve(lambda: eng.check())
    return CheckResponse(**data)


@router.get("/admin/v1/users", response_model=UsersResponse)
async def admin_users_endpoint(
    username: Optional[str] = Query(None, description="Exact username filter"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> UsersResponse:
    """Duo Admin API v1 /users - list users."""
    eng = _engine()
    data = _serve(lambda: eng.admin_users(username=username, limit=limit, offset=offset))
    return UsersResponse(**data)


@router.get("/admin/v1/integrations", response_model=IntegrationsResponse)
async def admin_integrations_endpoint(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> IntegrationsResponse:
    """Duo Admin API v1 /integrations - list integrations."""
    eng = _engine()
    data = _serve(lambda: eng.admin_integrations(limit=limit, offset=offset))
    return IntegrationsResponse(**data)


__all__ = ["router"]
