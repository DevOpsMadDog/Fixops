"""Elastic Security Detection Engine Router — ALDECI.

Wraps ``core.elastic_security_engine.ElasticSecurityEngine`` with REST
endpoints for managing detection rules, alert signals, cases, and
exception lists.

Prefix: /api/v1/elastic-security
Auth:   api_key_auth dependency (mount layer adds scope checks — read:scans)

Routes:
  GET  /api/v1/elastic-security/                                      capability summary
  GET  /api/v1/elastic-security/api/detection_engine/rules            list detection rules
  POST /api/v1/elastic-security/api/detection_engine/signals/search   query alert signals
  GET  /api/v1/elastic-security/api/cases                             list cases
  GET  /api/v1/elastic-security/api/exception_lists                   list exception lists

NO MOCKS rule: when ELASTIC_URL or ELASTIC_API_KEY is missing the
capability summary returns ``status="unavailable"`` and every lookup
endpoint returns HTTP 503. We never fabricate rules, signals, cases,
or exception lists.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/elastic-security",
    tags=["Elastic Security"],
    dependencies=[Depends(api_key_auth)],
)


def _engine():
    # Indirection so tests can patch the engine via reset_elastic_security_engine().
    from core.elastic_security_engine import get_elastic_security_engine

    return get_elastic_security_engine()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    elastic_url_present: bool
    elastic_api_key_present: bool
    status: str  # ok | empty | unavailable


class RuleBrief(BaseModel):
    id: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    risk_score: Optional[Any] = None
    type: Optional[str] = None
    language: Optional[str] = None
    query: Optional[str] = None
    enabled: bool = False
    tags: List[str] = Field(default_factory=list)


class RuleListResponse(BaseModel):
    data: List[RuleBrief] = Field(default_factory=list)
    total: int = 0
    perPage: int = 25
    page: int = 1


class SignalSource(BaseModel):
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    signal_status: Optional[str] = None
    kibana_alert_severity: Optional[Any] = None
    host: Optional[Any] = None
    user: Optional[Any] = None
    source_ip: Optional[Any] = None


class SignalHit(BaseModel):
    model_config = {"populate_by_name": True}

    id: Optional[str] = Field(default=None, alias="_id", serialization_alias="_id")
    source: SignalSource = Field(
        default_factory=SignalSource,
        alias="_source",
        serialization_alias="_source",
    )


class SignalHits(BaseModel):
    total: int = 0
    hits: List[SignalHit] = Field(default_factory=list)


class SignalsResponse(BaseModel):
    took: int = 0
    hits: SignalHits = Field(default_factory=SignalHits)


class CaseBrief(BaseModel):
    id: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    severity: Optional[str] = None
    owner: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    totalAlerts: int = 0
    totalComments: int = 0


class CaseListResponse(BaseModel):
    cases: List[CaseBrief] = Field(default_factory=list)
    total: int = 0
    perPage: int = 20
    page: int = 1


class ExceptionListBrief(BaseModel):
    id: Optional[str] = None
    list_id: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    type: Optional[str] = None
    namespace_type: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    version: Optional[Any] = None


class ExceptionListResponse(BaseModel):
    data: List[ExceptionListBrief] = Field(default_factory=list)
    total: int = 0
    perPage: int = 20
    page: int = 1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _serve(callable_):
    """Run an Elastic Security call, translating engine errors to HTTP responses.

    ElasticSecurityUnavailableError -> 503 (auth missing, network, upstream)
    ValueError                      -> 422 (input validation)
    """
    from core.elastic_security_engine import ElasticSecurityUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ElasticSecurityUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", response_model=CapabilityResponse)
async def capability_summary() -> CapabilityResponse:
    """Return the service summary — safe to call without Elastic creds."""
    eng = _engine()
    url_present = eng.url_present()
    key_present = eng.api_key_present()
    if not url_present or not key_present:
        status = "unavailable"
    else:
        status = "ok"
    return CapabilityResponse(
        service="Elastic Security",
        endpoints=[
            "/api/detection_engine/rules",
            "/api/detection_engine/signals/search",
            "/api/cases",
            "/api/exception_lists",
        ],
        elastic_url_present=url_present,
        elastic_api_key_present=key_present,
        status=status,
    )


@router.get(
    "/api/detection_engine/rules",
    response_model=RuleListResponse,
)
async def list_rules(
    per_page: int = Query(25, ge=1, le=1000, description="Rules per page"),
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
) -> RuleListResponse:
    eng = _engine()
    data = _serve(lambda: eng.list_rules(per_page=per_page, page=page))
    return RuleListResponse(**data)


@router.post(
    "/api/detection_engine/signals/search",
    response_model=SignalsResponse,
)
async def search_signals(
    body: Dict[str, Any] = Body(
        ...,
        description=(
            "Elasticsearch query DSL — must include `query`. Optional: "
            "`sort`, `size`, `from`."
        ),
    ),
) -> SignalsResponse:
    eng = _engine()
    data = _serve(lambda: eng.search_signals(body))
    return SignalsResponse(**data)


@router.get(
    "/api/cases",
    response_model=CaseListResponse,
)
async def list_cases(
    perPage: int = Query(20, ge=1, le=1000, description="Cases per page"),
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    status: Optional[str] = Query(
        None,
        description="Filter by status — one of open|closed|in-progress",
    ),
) -> CaseListResponse:
    eng = _engine()
    data = _serve(
        lambda: eng.list_cases(per_page=perPage, page=page, status=status)
    )
    return CaseListResponse(**data)


@router.get(
    "/api/exception_lists",
    response_model=ExceptionListResponse,
)
async def list_exception_lists(
    per_page: int = Query(20, ge=1, le=1000),
    page: int = Query(1, ge=1),
) -> ExceptionListResponse:
    eng = _engine()
    data = _serve(
        lambda: eng.list_exception_lists(per_page=per_page, page=page)
    )
    return ExceptionListResponse(**data)


__all__ = ["router"]
