"""SailPoint IdentityNow IGA Live REST Router — ALDECI (NEW — 2026-05-04).

Wraps ``core.sailpoint_iga_engine.SailPointIGAEngine`` with REST endpoints
for Identities / Access Profiles / Roles / Certification Campaigns /
Access Requests against a live IdentityNow tenant.

Prefix: /api/v1/sailpoint-iga
Auth:   api_key_auth dependency (mount layer adds read:scans scope)

Routes:
  GET  /api/v1/sailpoint-iga/                                       capability summary
  GET  /api/v1/sailpoint-iga/v3/identities                          list identities
  GET  /api/v1/sailpoint-iga/v3/identities/{identity_id}            single identity
  GET  /api/v1/sailpoint-iga/v3/identities/{identity_id}/account-summary  identity accounts
  GET  /api/v1/sailpoint-iga/v3/access-profiles                     list access profiles
  GET  /api/v1/sailpoint-iga/v3/roles                               list roles
  GET  /api/v1/sailpoint-iga/v3/certification-campaigns             list campaigns
  GET  /api/v1/sailpoint-iga/v3/access-requests                     list access requests

NO MOCKS rule: when SAILPOINT_TENANT_URL / SAILPOINT_CLIENT_ID /
SAILPOINT_CLIENT_SECRET are missing the capability summary reports
``status="unavailable"`` and every live endpoint returns HTTP 503. We do
not fabricate identities / access profiles / roles / campaigns / access
requests ever.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/sailpoint-iga",
    tags=["SailPoint IdentityNow IGA"],
    dependencies=[Depends(api_key_auth)],
)


def _engine():
    # Indirection so tests can patch via reset_sailpoint_iga_engine().
    from core.sailpoint_iga_engine import get_sailpoint_iga_engine
    return get_sailpoint_iga_engine()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    sailpoint_tenant_url_present: bool
    sailpoint_client_id_present: bool
    sailpoint_client_secret_present: bool
    status: str  # ok | empty | unavailable


class IdentityResponse(BaseModel):
    # Free-form pass-through of IdentityNow identity payload.
    model_config = {"extra": "allow"}


class AccountSummaryResponse(BaseModel):
    accounts: List[Dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _serve(callable_):
    """Run a SailPoint call, translating engine errors to HTTP responses.

    SailPointUnavailableError -> 503 (creds missing, network, upstream)
    ValueError                -> 422 (input validation)
    """
    from core.sailpoint_iga_engine import SailPointUnavailableError
    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except SailPointUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


@router.get("/", response_model=CapabilityResponse)
async def capability_summary() -> CapabilityResponse:
    """Service summary — safe to call without SailPoint credentials."""
    eng = _engine()
    url_present = eng.tenant_url_present()
    cid_present = eng.client_id_present()
    sec_present = eng.client_secret_present()
    if url_present and cid_present and sec_present:
        status = "ok"
    elif url_present or cid_present or sec_present:
        status = "empty"
    else:
        status = "unavailable"
    return CapabilityResponse(
        service="SailPoint IdentityNow",
        endpoints=[
            "/v3/identities",
            "/v3/access-profiles",
            "/v3/roles",
            "/v3/certification-campaigns",
            "/v3/access-requests",
        ],
        sailpoint_tenant_url_present=url_present,
        sailpoint_client_id_present=cid_present,
        sailpoint_client_secret_present=sec_present,
        status=status,
    )


# ---------------------------------------------------------------------------
# Identities
# ---------------------------------------------------------------------------


@router.get("/v3/identities", response_model=List[Dict[str, Any]])
async def list_identities(
    limit: Optional[int] = Query(None, ge=1, le=250),
    offset: Optional[int] = Query(None, ge=0),
    filters: Optional[str] = Query(None, description="CEL filter expression"),
    sorters: Optional[str] = Query(None, description="Sort field (e.g. name)"),
) -> List[Dict[str, Any]]:
    eng = _engine()
    return _serve(
        lambda: eng.list_identities(
            limit=limit, offset=offset, filters=filters, sorters=sorters
        )
    )


@router.get("/v3/identities/{identity_id}", response_model=IdentityResponse)
async def get_identity(
    identity_id: str = Path(..., min_length=1, max_length=256),
) -> IdentityResponse:
    eng = _engine()
    data = _serve(lambda: eng.get_identity(identity_id))
    return IdentityResponse(**data)


@router.get(
    "/v3/identities/{identity_id}/account-summary",
    response_model=AccountSummaryResponse,
)
async def get_identity_account_summary(
    identity_id: str = Path(..., min_length=1, max_length=256),
) -> AccountSummaryResponse:
    eng = _engine()
    data = _serve(lambda: eng.get_identity_account_summary(identity_id))
    return AccountSummaryResponse(**data)


# ---------------------------------------------------------------------------
# Access profiles
# ---------------------------------------------------------------------------


@router.get("/v3/access-profiles", response_model=List[Dict[str, Any]])
async def list_access_profiles(
    limit: Optional[int] = Query(None, ge=1, le=250),
    offset: Optional[int] = Query(None, ge=0),
    filters: Optional[str] = Query(None, description="CEL filter expression"),
    sorters: Optional[str] = Query(None),
    for_subadmin: Optional[str] = Query(
        None,
        alias="for-subadmin",
        description="Identity ID of subadmin context",
    ),
    include_deleted: Optional[bool] = Query(
        None,
        alias="include-deleted",
        description="Include soft-deleted access profiles",
    ),
) -> List[Dict[str, Any]]:
    eng = _engine()
    return _serve(
        lambda: eng.list_access_profiles(
            limit=limit,
            offset=offset,
            filters=filters,
            sorters=sorters,
            for_subadmin=for_subadmin,
            include_deleted=include_deleted,
        )
    )


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------


@router.get("/v3/roles", response_model=List[Dict[str, Any]])
async def list_roles(
    limit: Optional[int] = Query(None, ge=1, le=250),
    offset: Optional[int] = Query(None, ge=0),
    filters: Optional[str] = Query(None, description="CEL filter expression"),
    sorters: Optional[str] = Query(None),
    for_subadmin: Optional[str] = Query(
        None,
        alias="for-subadmin",
        description="Identity ID of subadmin context",
    ),
) -> List[Dict[str, Any]]:
    eng = _engine()
    return _serve(
        lambda: eng.list_roles(
            limit=limit,
            offset=offset,
            filters=filters,
            sorters=sorters,
            for_subadmin=for_subadmin,
        )
    )


# ---------------------------------------------------------------------------
# Certification campaigns
# ---------------------------------------------------------------------------


@router.get("/v3/certification-campaigns", response_model=List[Dict[str, Any]])
async def list_certification_campaigns(
    limit: Optional[int] = Query(None, ge=1, le=250),
    offset: Optional[int] = Query(None, ge=0),
    filters: Optional[str] = Query(
        None,
        description='CEL filter, e.g. status eq "ACTIVE"',
    ),
) -> List[Dict[str, Any]]:
    eng = _engine()
    return _serve(
        lambda: eng.list_certification_campaigns(
            limit=limit, offset=offset, filters=filters
        )
    )


# ---------------------------------------------------------------------------
# Access requests
# ---------------------------------------------------------------------------


@router.get("/v3/access-requests", response_model=List[Dict[str, Any]])
async def list_access_requests(
    requested_for: Optional[str] = Query(
        None, alias="requested-for", description="Identity ID requested for"
    ),
    requested_by: Optional[str] = Query(
        None, alias="requested-by", description="Identity ID who requested"
    ),
    regarding_identity: Optional[str] = Query(
        None,
        alias="regarding-identity",
        description="Identity ID involved in the request",
    ),
    assigned_to: Optional[str] = Query(
        None,
        alias="assigned-to",
        description="Identity ID currently assigned the request",
    ),
    limit: Optional[int] = Query(None, ge=1, le=250),
    offset: Optional[int] = Query(None, ge=0),
) -> List[Dict[str, Any]]:
    eng = _engine()
    return _serve(
        lambda: eng.list_access_requests(
            requested_for=requested_for,
            requested_by=requested_by,
            regarding_identity=regarding_identity,
            assigned_to=assigned_to,
            limit=limit,
            offset=offset,
        )
    )


__all__ = ["router"]
