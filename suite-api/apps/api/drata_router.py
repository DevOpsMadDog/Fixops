"""Drata Compliance Router — ALDECI.

REST surface under prefix ``/api/v1/drata`` wrapping ``core.drata_compliance_engine``.

Endpoints
---------
* GET  /                                    — capability summary
* GET  /api/controls                        — list controls (filters: status, framework)
* GET  /api/controls/{control_id}           — single control
* GET  /api/controls/{control_id}/tests     — control tests
* GET  /api/integrations                    — integrations
* GET  /api/audits                          — audits
* GET  /api/people                          — people
* GET  /api/findings                        — findings
* GET  /api/policies                        — policies (filter: published)

Auth
----
api_key_auth dependency (mount layer adds scope checks — read:scans).

NO MOCKS rule
-------------
* When DRATA_API_KEY is unset:
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
    prefix="/api/v1/drata",
    tags=["Drata"],
)


# ---------------------------------------------------------------------------
# Engine accessor (lazy import so tests can patch the singleton)
# ---------------------------------------------------------------------------


def _get_engine():
    from core.drata_compliance_engine import get_drata_compliance_engine

    return get_drata_compliance_engine()


def _serve(callable_):
    """Run a Drata call, translating engine errors to HTTP responses."""
    from core.drata_compliance_engine import DrataHTTPError, DrataUnavailable

    try:
        return callable_()
    except DrataUnavailable as exc:
        raise HTTPException(
            status_code=503,
            detail={"error": "drata_unavailable", "message": str(exc)},
        ) from exc
    except DrataHTTPError as exc:
        # Surface upstream 4xx verbatim; collapse 5xx to 502
        upstream = exc.status_code
        if 400 <= upstream < 500:
            status = upstream
        else:
            status = 502
        raise HTTPException(
            status_code=status,
            detail={
                "error": "drata_upstream_error",
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
    drata_api_key_present: bool
    status: str  # ok | empty | unavailable


# Drata returns {"results": [...], "pagination": {"cursor": ..., "has_next": ...}}
class Pagination(BaseModel):
    cursor: Optional[str] = None
    has_next: bool = False


class PaginatedResponse(BaseModel):
    results: List[Dict[str, Any]] = Field(default_factory=list)
    pagination: Pagination = Field(default_factory=Pagination)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=CapabilityResponse,
    summary="Drata capability summary",
)
async def capability_summary() -> CapabilityResponse:
    """Return the service summary — safe to call without a token."""
    eng = _get_engine()
    summary = eng.capability_summary()
    return CapabilityResponse(**summary)


@router.get(
    "/api/controls",
    response_model=PaginatedResponse,
    summary="List Drata controls",
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
    "/api/controls/{control_id}",
    summary="Get a single Drata control",
)
async def get_control(
    control_id: str = Path(..., description="Drata control identifier"),
) -> Dict[str, Any]:
    eng = _get_engine()
    return _serve(lambda: eng.get_control(control_id))


@router.get(
    "/api/controls/{control_id}/tests",
    response_model=PaginatedResponse,
    summary="List tests attached to a Drata control",
)
async def list_control_tests(
    control_id: str = Path(..., description="Drata control identifier"),
    pageSize: Optional[int] = Query(default=None, ge=1, le=500),
    pageCursor: Optional[str] = Query(default=None),
) -> PaginatedResponse:
    eng = _get_engine()
    data = _serve(
        lambda: eng.list_control_tests(
            control_id,
            page_size=pageSize,
            page_cursor=pageCursor,
        )
    )
    return PaginatedResponse(**data)


@router.get(
    "/api/integrations",
    response_model=PaginatedResponse,
    summary="List Drata integrations",
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
    "/api/audits",
    response_model=PaginatedResponse,
    summary="List Drata audits",
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
    "/api/people",
    response_model=PaginatedResponse,
    summary="List people on the Drata tenant",
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
    "/api/findings",
    response_model=PaginatedResponse,
    summary="List Drata findings",
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


@router.get(
    "/api/policies",
    response_model=PaginatedResponse,
    summary="List Drata policies",
)
async def list_policies(
    published: Optional[bool] = Query(default=None, description="If true, return only published policies"),
    pageSize: Optional[int] = Query(default=None, ge=1, le=500),
    pageCursor: Optional[str] = Query(default=None),
) -> PaginatedResponse:
    eng = _get_engine()
    data = _serve(
        lambda: eng.list_policies(
            published=published,
            page_size=pageSize,
            page_cursor=pageCursor,
        )
    )
    return PaginatedResponse(**data)


__all__ = ["router"]
