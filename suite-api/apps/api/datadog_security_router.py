"""ALDECI Datadog Cloud SIEM router — REAL httpx only, NO MOCKS.

Mounted at ``/api/v1/datadog-security`` under the ``read:scans`` scope.

A separate, partial ``datadog`` mention exists in legacy SIEM-output and
universal-ingest routers; this router is the **dedicated** Cloud SIEM
read-path and uses a fresh prefix to avoid collision with those.

Endpoints
---------
GET  /                                                          — capability summary
POST /api/v2/security_monitoring/signals/search                 — search signals
GET  /api/v2/security_monitoring/rules                          — list rules
GET  /api/v2/security_monitoring/rules/{rule_id}                — single rule
POST /api/v2/security/cases                                     — create case
GET  /api/v2/security/cases/{case_id}                           — get case
GET  /api/v2/security_monitoring/configuration/suppressions     — list suppressions
GET  /api/v2/security_monitoring/notification_rules             — list notification rules

When DD_API_KEY/DD_APP_KEY are not set, every lookup endpoint returns
HTTP 503 and the capability summary still responds 200 with
``status="unavailable"``.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from core.datadog_security_engine import (
    DatadogSecurityUnavailableError,
    get_datadog_security_engine,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/datadog-security",
    tags=["datadog-security"],
    dependencies=[Depends(api_key_auth)],
)


# --------------------------------------------------------------- Pydantic


class _SignalsFilter(BaseModel):
    query: Optional[str] = None
    from_: Optional[str] = Field(default=None, alias="from")
    to: Optional[str] = None

    model_config = {"populate_by_name": True}


class _SignalsPage(BaseModel):
    cursor: Optional[str] = None
    limit: Optional[int] = None


class SignalsSearchRequest(BaseModel):
    filter: Optional[_SignalsFilter] = None
    sort: Optional[str] = "-timestamp"
    page: Optional[_SignalsPage] = None


class _CaseAttributes(BaseModel):
    title: str
    description: Optional[str] = None
    priority: Optional[str] = None
    type: Optional[str] = None
    status: Optional[str] = None


class _CaseData(BaseModel):
    type: str = "case"
    attributes: _CaseAttributes


class CaseCreateRequest(BaseModel):
    data: _CaseData


# ------------------------------------------------------------------ helpers


def _to_503(exc: DatadogSecurityUnavailableError) -> HTTPException:
    return HTTPException(status_code=503, detail=str(exc))


# ----------------------------------------------------------------- endpoints


@router.get("/", summary="Datadog Cloud SIEM capability summary")
def capability_summary() -> Dict[str, Any]:
    eng = get_datadog_security_engine()
    return eng.capability_summary()


@router.post(
    "/api/v2/security_monitoring/signals/search",
    summary="Search Datadog Cloud SIEM signals",
)
def search_signals(body: SignalsSearchRequest = Body(...)) -> Dict[str, Any]:
    eng = get_datadog_security_engine()
    payload = body.dict(by_alias=True, exclude_none=True)
    try:
        return eng.search_signals(payload)
    except DatadogSecurityUnavailableError as exc:
        raise _to_503(exc)


@router.get(
    "/api/v2/security_monitoring/rules",
    summary="List Datadog Cloud SIEM detection rules",
)
def list_rules(
    page_size: Optional[int] = Query(
        None, alias="page[size]", ge=1, le=1000
    ),
    page_number: Optional[int] = Query(
        None, alias="page[number]", ge=0
    ),
    filter_name: Optional[str] = Query(None, alias="filter[name]"),
    filter_severity: Optional[str] = Query(
        None, alias="filter[severity]"
    ),
) -> Dict[str, Any]:
    eng = get_datadog_security_engine()
    try:
        return eng.list_rules(
            page_size=page_size,
            page_number=page_number,
            filter_name=filter_name,
            filter_severity=filter_severity,
        )
    except DatadogSecurityUnavailableError as exc:
        raise _to_503(exc)


@router.get(
    "/api/v2/security_monitoring/rules/{rule_id}",
    summary="Get a single Datadog Cloud SIEM detection rule",
)
def get_rule(rule_id: str) -> Dict[str, Any]:
    eng = get_datadog_security_engine()
    try:
        return eng.get_rule(rule_id)
    except DatadogSecurityUnavailableError as exc:
        raise _to_503(exc)


@router.post(
    "/api/v2/security/cases",
    summary="Create a Datadog Security case",
)
def create_case(body: CaseCreateRequest = Body(...)) -> Dict[str, Any]:
    eng = get_datadog_security_engine()
    payload = body.dict(by_alias=True, exclude_none=True)
    try:
        return eng.create_case(payload)
    except DatadogSecurityUnavailableError as exc:
        raise _to_503(exc)


@router.get(
    "/api/v2/security/cases/{case_id}",
    summary="Get a Datadog Security case",
)
def get_case(case_id: str) -> Dict[str, Any]:
    eng = get_datadog_security_engine()
    try:
        return eng.get_case(case_id)
    except DatadogSecurityUnavailableError as exc:
        raise _to_503(exc)


@router.get(
    "/api/v2/security_monitoring/configuration/suppressions",
    summary="List Datadog Cloud SIEM suppressions",
)
def list_suppressions() -> Dict[str, Any]:
    eng = get_datadog_security_engine()
    try:
        return eng.list_suppressions()
    except DatadogSecurityUnavailableError as exc:
        raise _to_503(exc)


@router.get(
    "/api/v2/security_monitoring/notification_rules",
    summary="List Datadog Cloud SIEM notification rules",
)
def list_notification_rules() -> Dict[str, Any]:
    eng = get_datadog_security_engine()
    try:
        return eng.list_notification_rules()
    except DatadogSecurityUnavailableError as exc:
        raise _to_503(exc)


__all__ = ["router"]
