"""Vanta Compliance Router — ALDECI.

REST surface under prefix ``/api/v1/vanta`` wrapping ``core.vanta_compliance_engine``.

Endpoints
---------
* GET  /                                    — capability summary
* GET  /v1/controls                         — list controls (filters: status, framework)
* GET  /v1/controls/{control_id}            — single control
* GET  /v1/controls/{control_id}/tests      — control tests
* GET  /v1/integrations                     — integrations
* GET  /v1/audits                           — audits
* GET  /v1/people                           — people
* GET  /v1/findings                         — findings

Auth
----
api_key_auth dependency (mount layer adds scope checks — read:scans).

NO MOCKS rule
-------------
* When VANTA_API_KEY is unset:
    - Capability summary surfaces ``status="unavailable"``.
    - All live endpoints return HTTP 503.
* No fabricated payloads.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Path, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/vanta",
    tags=["Vanta"],
)


# ---------------------------------------------------------------------------
# Engine accessor (lazy import so tests can patch the singleton)
# ---------------------------------------------------------------------------


def _get_engine():
    from core.vanta_compliance_engine import get_vanta_compliance_engine

    return get_vanta_compliance_engine()


def _serve(callable_):
    """Run a Vanta call, translating engine errors to HTTP responses."""
    from core.vanta_compliance_engine import VantaHTTPError, VantaUnavailable

    try:
        return callable_()
    except VantaUnavailable as exc:
        raise HTTPException(
            status_code=503,
            detail={"error": "vanta_unavailable", "message": str(exc)},
        ) from exc
    except VantaHTTPError as exc:
        # Surface upstream 4xx verbatim; collapse 5xx to 502
        upstream = exc.status_code
        if 400 <= upstream < 500:
            status = upstream
        else:
            status = 502
        raise HTTPException(
            status_code=status,
            detail={
                "error": "vanta_upstream_error",
                "upstream_status": upstream,
                "payload": exc.payload,
                "message": str(exc),
            },
        ) from exc


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    vanta_api_key_present: bool
    status: str  # ok | empty | unavailable


# Generic envelope — Vanta returns {"results": {"data": [...], "pageInfo": {...}}}
class PageInfo(BaseModel):
    endCursor: Optional[str] = None
    hasNextPage: bool = False


class ResultsEnvelope(BaseModel):
    data: List[Dict[str, Any]] = Field(default_factory=list)
    pageInfo: PageInfo = Field(default_factory=PageInfo)


class PaginatedResponse(BaseModel):
    results: ResultsEnvelope = Field(default_factory=ResultsEnvelope)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=CapabilityResponse,
    summary="Vanta capability summary",
)
async def capability_summary() -> CapabilityResponse:
    """Return the service summary — safe to call without a token."""
    eng = _get_engine()
    summary = eng.capability_summary()
    return CapabilityResponse(**summary)


@router.get(
    "/v1/controls",
    response_model=PaginatedResponse,
    summary="List Vanta controls",
)
async def list_controls(
    status: Optional[str] = Query(
        default=None,
        pattern="^(passing|failing|not_applicable)$",
    ),
    framework: Optional[str] = Query(
        default=None,
        pattern="^(SOC2|ISO27001|HIPAA|GDPR|PCI)$",
    ),
    pageSize: Optional[int] = Query(default=None, ge=1, le=500),
    pageCursor: Optional[str] = Query(default=None),
) -> PaginatedResponse:
    eng = _get_engine()
    data = _serve(
        lambda: eng.list_controls(
            status=status,
            framework=framework,
            page_size=pageSize,
            page_cursor=pageCursor,
        )
    )
    return PaginatedResponse(**data)


@router.get(
    "/v1/controls/{control_id}",
    summary="Get a single Vanta control",
)
async def get_control(
    control_id: str = Path(..., description="Vanta control identifier"),
) -> Dict[str, Any]:
    eng = _get_engine()
    return _serve(lambda: eng.get_control(control_id))


@router.get(
    "/v1/controls/{control_id}/tests",
    response_model=PaginatedResponse,
    summary="List tests attached to a Vanta control",
)
async def list_control_tests(
    control_id: str = Path(..., description="Vanta control identifier"),
    status: Optional[str] = Query(
        default=None,
        pattern="^(passing|failing|not_run)$",
    ),
    pageSize: Optional[int] = Query(default=None, ge=1, le=500),
    pageCursor: Optional[str] = Query(default=None),
) -> PaginatedResponse:
    eng = _get_engine()
    data = _serve(
        lambda: eng.list_control_tests(
            control_id,
            status=status,
            page_size=pageSize,
            page_cursor=pageCursor,
        )
    )
    return PaginatedResponse(**data)


@router.get(
    "/v1/integrations",
    response_model=PaginatedResponse,
    summary="List Vanta integrations",
)
async def list_integrations(
    pageSize: Optional[int] = Query(default=None, ge=1, le=500),
    pageCursor: Optional[str] = Query(default=None),
) -> PaginatedResponse:
    eng = _get_engine()
    data = _serve(
        lambda: eng.list_integrations(
            page_size=pageSize,
            page_cursor=pageCursor,
        )
    )
    return PaginatedResponse(**data)


@router.get(
    "/v1/audits",
    response_model=PaginatedResponse,
    summary="List Vanta audits",
)
async def list_audits(
    status: Optional[str] = Query(
        default=None,
        pattern="^(open|closed|in_progress)$",
    ),
    framework: Optional[str] = Query(default=None),
    pageSize: Optional[int] = Query(default=None, ge=1, le=500),
    pageCursor: Optional[str] = Query(default=None),
) -> PaginatedResponse:
    eng = _get_engine()
    data = _serve(
        lambda: eng.list_audits(
            status=status,
            framework=framework,
            page_size=pageSize,
            page_cursor=pageCursor,
        )
    )
    return PaginatedResponse(**data)


@router.get(
    "/v1/people",
    response_model=PaginatedResponse,
    summary="List people on the Vanta tenant",
)
async def list_people(
    role: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    pageSize: Optional[int] = Query(default=None, ge=1, le=500),
    pageCursor: Optional[str] = Query(default=None),
) -> PaginatedResponse:
    eng = _get_engine()
    data = _serve(
        lambda: eng.list_people(
            role=role,
            status=status,
            page_size=pageSize,
            page_cursor=pageCursor,
        )
    )
    return PaginatedResponse(**data)


@router.get(
    "/v1/findings",
    response_model=PaginatedResponse,
    summary="List Vanta findings",
)
async def list_findings(
    severity: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    pageSize: Optional[int] = Query(default=None, ge=1, le=500),
    pageCursor: Optional[str] = Query(default=None),
) -> PaginatedResponse:
    eng = _get_engine()
    data = _serve(
        lambda: eng.list_findings(
            severity=severity,
            status=status,
            page_size=pageSize,
            page_cursor=pageCursor,
        )
    )
    return PaginatedResponse(**data)


__all__ = ["router"]
