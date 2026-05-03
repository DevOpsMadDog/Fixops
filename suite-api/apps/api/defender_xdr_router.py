"""ALDECI Microsoft Defender XDR router — REAL httpx only, NO MOCKS.

Mounted at ``/api/v1/defender-xdr`` under the ``read:scans`` scope.

This router fronts three Microsoft security surfaces:

  * Microsoft Graph Security API (alerts_v2, incidents)
  * Microsoft Defender for Endpoint (machines, security recommendations)
  * Microsoft 365 Defender (advanced hunting KQL)

Endpoints
---------
GET  /                                                  — capability summary
GET  /v1.0/security/alerts_v2                           — Graph alerts_v2
GET  /v1.0/security/incidents                           — Graph incidents
GET  /api/machines                                      — Defender for Endpoint machines
POST /api/advancedhunting/run                           — M365 Defender advanced hunting
GET  /api/securityrecommendations                       — Defender for Endpoint TVM recs

When AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET are unset
every lookup returns HTTP 503 and the capability summary still responds
200 with ``status="unavailable"``.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from core.defender_xdr_engine import (
    DefenderXDRUnavailableError,
    get_defender_xdr_engine,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/defender-xdr",
    tags=["defender-xdr"],
    dependencies=[Depends(api_key_auth)],
)


# --------------------------------------------------------------- Pydantic


class AdvancedHuntingRequest(BaseModel):
    """Body for ``POST /api/advancedhunting/run`` — KQL query."""

    Query: str = Field(..., description="KQL query string")

    model_config = {"populate_by_name": True}


# ------------------------------------------------------------------ helpers


def _to_503(exc: DefenderXDRUnavailableError) -> HTTPException:
    return HTTPException(status_code=503, detail=str(exc))


# ----------------------------------------------------------------- endpoints


@router.get("/", summary="Microsoft Defender XDR capability summary")
def capability_summary() -> Dict[str, Any]:
    eng = get_defender_xdr_engine()
    return eng.capability_summary()


@router.get(
    "/v1.0/security/alerts_v2",
    summary="List Microsoft Graph Security alerts (alerts_v2)",
)
def list_alerts(
    filter_: Optional[str] = Query(None, alias="$filter"),
    top: Optional[int] = Query(None, alias="$top", ge=1, le=2000),
    orderby: Optional[str] = Query(None, alias="$orderby"),
    select: Optional[str] = Query(None, alias="$select"),
    count: Optional[bool] = Query(None, alias="$count"),
) -> Dict[str, Any]:
    eng = get_defender_xdr_engine()
    try:
        return eng.list_alerts(
            odata_filter=filter_,
            top=top,
            orderby=orderby,
            select=select,
            count=count,
        )
    except DefenderXDRUnavailableError as exc:
        raise _to_503(exc)


@router.get(
    "/v1.0/security/incidents",
    summary="List Microsoft Graph Security incidents",
)
def list_incidents(
    filter_: Optional[str] = Query(None, alias="$filter"),
    top: Optional[int] = Query(None, alias="$top", ge=1, le=2000),
    orderby: Optional[str] = Query(None, alias="$orderby"),
    expand: Optional[str] = Query(None, alias="$expand"),
) -> Dict[str, Any]:
    eng = get_defender_xdr_engine()
    try:
        return eng.list_incidents(
            odata_filter=filter_,
            top=top,
            orderby=orderby,
            expand=expand,
        )
    except DefenderXDRUnavailableError as exc:
        raise _to_503(exc)


@router.get(
    "/api/machines",
    summary="List Defender for Endpoint machines",
)
def list_machines(
    filter_: Optional[str] = Query(None, alias="$filter"),
    top: Optional[int] = Query(None, alias="$top", ge=1, le=10000),
    orderby: Optional[str] = Query(None, alias="$orderby"),
    skip: Optional[int] = Query(None, alias="$skip", ge=0),
) -> Dict[str, Any]:
    eng = get_defender_xdr_engine()
    try:
        return eng.list_machines(
            odata_filter=filter_,
            top=top,
            orderby=orderby,
            skip=skip,
        )
    except DefenderXDRUnavailableError as exc:
        raise _to_503(exc)


@router.post(
    "/api/advancedhunting/run",
    summary="Run an advanced hunting KQL query against M365 Defender",
)
def run_advanced_hunting(body: AdvancedHuntingRequest = Body(...)) -> Dict[str, Any]:
    eng = get_defender_xdr_engine()
    try:
        return eng.run_advanced_hunting(body.Query)
    except DefenderXDRUnavailableError as exc:
        raise _to_503(exc)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get(
    "/api/securityrecommendations",
    summary="List Defender for Endpoint TVM security recommendations",
)
def list_security_recommendations(
    filter_: Optional[str] = Query(None, alias="$filter"),
    top: Optional[int] = Query(None, alias="$top", ge=1, le=10000),
    orderby: Optional[str] = Query(None, alias="$orderby"),
) -> Dict[str, Any]:
    eng = get_defender_xdr_engine()
    try:
        return eng.list_security_recommendations(
            odata_filter=filter_,
            top=top,
            orderby=orderby,
        )
    except DefenderXDRUnavailableError as exc:
        raise _to_503(exc)


__all__ = ["router"]
