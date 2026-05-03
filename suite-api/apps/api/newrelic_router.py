"""ALDECI New Relic APM router — REAL httpx only, NO MOCKS.

Mounted at ``/api/v1/newrelic`` under the ``read:scans`` scope.

Endpoints
---------
GET  /                                        — capability summary
GET  /v2/applications.json                    — list applications
GET  /v2/applications/{app_id}.json           — single application
GET  /v2/alerts_incidents.json                — list alert incidents
GET  /v2/alerts_violations.json               — list alert violations
POST /graphql                                 — NerdGraph proxy

When ``NEWRELIC_API_KEY`` is not set, every lookup endpoint returns
HTTP 503 and the capability summary still responds 200 with
``status="unavailable"``.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from core.newrelic_apm_engine import (
    NewRelicAPMUnavailableError,
    get_newrelic_apm_engine,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/newrelic",
    tags=["newrelic"],
    dependencies=[Depends(api_key_auth)],
)


# --------------------------------------------------------------- Pydantic


class GraphQLRequest(BaseModel):
    query: str = Field(..., min_length=1)
    variables: Optional[Dict[str, Any]] = None


# ------------------------------------------------------------------ helpers


def _to_503(exc: NewRelicAPMUnavailableError) -> HTTPException:
    return HTTPException(status_code=503, detail=str(exc))


# ----------------------------------------------------------------- endpoints


@router.get("/", summary="New Relic APM capability summary")
def capability_summary() -> Dict[str, Any]:
    eng = get_newrelic_apm_engine()
    return eng.capability_summary()


@router.get(
    "/v2/applications.json",
    summary="List New Relic APM applications",
)
def list_applications(
    filter_name: Optional[str] = Query(None, alias="filter[name]"),
    filter_language: Optional[str] = Query(None, alias="filter[language]"),
    page: Optional[int] = Query(None, ge=1),
) -> Dict[str, Any]:
    eng = get_newrelic_apm_engine()
    try:
        return eng.list_applications(
            filter_name=filter_name,
            filter_language=filter_language,
            page=page,
        )
    except NewRelicAPMUnavailableError as exc:
        raise _to_503(exc)


@router.get(
    "/v2/applications/{app_id}.json",
    summary="Get a single New Relic APM application",
)
def get_application(app_id: str) -> Dict[str, Any]:
    eng = get_newrelic_apm_engine()
    try:
        return eng.get_application(app_id)
    except NewRelicAPMUnavailableError as exc:
        raise _to_503(exc)


@router.get(
    "/v2/alerts_incidents.json",
    summary="List New Relic alert incidents",
)
def list_incidents(
    only_open: bool = Query(True),
    exclude_violations: bool = Query(False),
) -> Dict[str, Any]:
    eng = get_newrelic_apm_engine()
    try:
        return eng.list_incidents(
            only_open=only_open,
            exclude_violations=exclude_violations,
        )
    except NewRelicAPMUnavailableError as exc:
        raise _to_503(exc)


@router.get(
    "/v2/alerts_violations.json",
    summary="List New Relic alert violations",
)
def list_violations(
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
    only_open: bool = Query(True),
) -> Dict[str, Any]:
    eng = get_newrelic_apm_engine()
    try:
        return eng.list_violations(
            start_date=start_date,
            end_date=end_date,
            only_open=only_open,
        )
    except NewRelicAPMUnavailableError as exc:
        raise _to_503(exc)


@router.post(
    "/graphql",
    summary="Execute a New Relic NerdGraph query",
)
def nerdgraph(body: GraphQLRequest = Body(...)) -> Dict[str, Any]:
    eng = get_newrelic_apm_engine()
    try:
        return eng.graphql(body.query, variables=body.variables)
    except NewRelicAPMUnavailableError as exc:
        raise _to_503(exc)


__all__ = ["router"]
