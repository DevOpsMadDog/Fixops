"""Akamai EdgeGrid Router — ALDECI.

Wraps PAPI v1 + AppSec v1 surfaces under prefix ``/api/v1/akamai``:

  - GET  /                                                          — capability summary
  - GET  /papi/v1/groups                                            — PAPI groups
  - GET  /papi/v1/properties?contractId&groupId                     — PAPI properties
  - GET  /papi/v1/properties/{property_id}/versions                 — version history
  - GET  /papi/v1/properties/{property_id}/versions/{version}/rules — rule tree
  - GET  /appsec/v1/configs                                         — AppSec configs
  - GET  /appsec/v1/configs/{config_id}/versions                    — AppSec versions
  - POST /appsec/v1/configs/{config_id}/versions/{ver}/security-events
                                                                    — security events query

NO MOCKS rule
-------------
* When any of AKAMAI_HOST / AKAMAI_CLIENT_TOKEN / AKAMAI_CLIENT_SECRET /
  AKAMAI_ACCESS_TOKEN is unset:
    - Capability summary surfaces ``status="unavailable"``.
    - All live endpoints return HTTP 503.
* No fabricated payloads.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/akamai",
    tags=["Akamai"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Engine accessor (lazy import so tests can patch the singleton)
# ---------------------------------------------------------------------------


def _engine():
    from core.akamai_engine import get_akamai_engine

    return get_akamai_engine()


def _serve(callable_):
    """Run an Akamai call, translating engine errors to HTTP responses.

    AkamaiUnavailableError -> 503 (creds missing, network, upstream error)
    ValueError             -> 422 (input validation)
    """
    from core.akamai_engine import AkamaiUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except AkamaiUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------


class SecurityEventsFilter(BaseModel):
    from_: Optional[str] = Field(default=None, alias="from")
    to: Optional[str] = None
    asnList: Optional[List[str]] = None
    attackGroupList: Optional[List[str]] = None
    clientReputationList: Optional[List[str]] = None
    countryCodeList: Optional[List[str]] = None
    eventTypeList: Optional[List[str]] = None
    ipList: Optional[List[str]] = None
    networkList: Optional[List[str]] = None
    policyList: Optional[List[str]] = None
    protocolList: Optional[List[str]] = None
    ruleList: Optional[List[str]] = None
    ruleSeverityList: Optional[List[str]] = None

    model_config = ConfigDict(populate_by_name=True)


class SecurityEventsQuery(BaseModel):
    filter: SecurityEventsFilter = Field(default_factory=SecurityEventsFilter)
    limit: int = Field(default=100, ge=1, le=10000)
    offset: int = Field(default=0, ge=0)


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


@router.get("/", summary="Akamai EdgeGrid capability summary")
def capability_summary() -> Dict[str, Any]:
    eng = _engine()
    host_ok = eng.host_present()
    ct_ok = eng.client_token_present()
    cs_ok = eng.client_secret_present()
    at_ok = eng.access_token_present()
    creds = host_ok and ct_ok and cs_ok and at_ok
    return {
        "service": "Akamai (EdgeGrid)",
        "endpoints": [
            "/papi/v1/groups",
            "/papi/v1/properties",
            "/appsec/v1/configs",
            "/appsec/v1/configs/{id}/versions/{ver}/security-events",
        ],
        "akamai_host_present": host_ok,
        "akamai_client_token_present": ct_ok,
        "akamai_client_secret_present": cs_ok,
        "akamai_access_token_present": at_ok,
        "status": "ok" if creds else "unavailable",
    }


# ---------------------------------------------------------------------------
# PAPI v1 endpoints
# ---------------------------------------------------------------------------


@router.get("/papi/v1/groups", summary="List PAPI groups")
def papi_groups() -> Dict[str, Any]:
    return _serve(lambda: _engine().papi_groups())


@router.get("/papi/v1/properties", summary="List PAPI properties")
def papi_properties(
    contractId: str = Query(..., description="Akamai contract ID"),
    groupId: str = Query(..., description="Akamai group ID"),
) -> Dict[str, Any]:
    return _serve(lambda: _engine().papi_properties(contractId, groupId))


@router.get(
    "/papi/v1/properties/{property_id}/versions",
    summary="List PAPI property versions",
)
def papi_property_versions(
    property_id: str = Path(..., description="Akamai property ID"),
    contractId: str = Query(...),
    groupId: str = Query(...),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().papi_property_versions(property_id, contractId, groupId)
    )


@router.get(
    "/papi/v1/properties/{property_id}/versions/{version}/rules",
    summary="Fetch PAPI property rule tree",
)
def papi_property_rules(
    property_id: str = Path(...),
    version: int = Path(..., ge=1),
    contractId: str = Query(...),
    groupId: str = Query(...),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().papi_property_rules(
            property_id, version, contractId, groupId
        )
    )


# ---------------------------------------------------------------------------
# AppSec v1 endpoints
# ---------------------------------------------------------------------------


@router.get("/appsec/v1/configs", summary="List AppSec configurations")
def appsec_configs() -> Dict[str, Any]:
    return _serve(lambda: _engine().appsec_configs())


@router.get(
    "/appsec/v1/configs/{config_id}/versions",
    summary="List AppSec configuration versions",
)
def appsec_config_versions(
    config_id: int = Path(..., ge=1),
) -> Dict[str, Any]:
    return _serve(lambda: _engine().appsec_config_versions(config_id))


@router.post(
    "/appsec/v1/configs/{config_id}/versions/{version}/security-events",
    summary="Query AppSec security events",
)
def appsec_security_events(
    config_id: int = Path(..., ge=1),
    version: int = Path(..., ge=1),
    body: SecurityEventsQuery = Body(default_factory=SecurityEventsQuery),
) -> Dict[str, Any]:
    payload = body.model_dump(by_alias=True, exclude_none=True)
    return _serve(
        lambda: _engine().appsec_security_events(config_id, version, payload)
    )


__all__ = ["router"]
