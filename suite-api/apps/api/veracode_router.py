"""Veracode SAST Router — ALDECI.

REST surface under prefix ``/api/v1/veracode`` wrapping ``core.veracode_engine``.

Endpoints
---------
* GET /                                                      — capability summary
* GET /appsec/v1/applications                                — list applications
* GET /appsec/v1/applications/{app_guid}                     — single application
* GET /appsec/v2/applications/{app_guid}/findings            — list findings
* GET /appsec/v1/findings/{finding_id}/annotations           — annotations
* GET /appsec/v1/policies                                    — list policies

Auth
----
api_key_auth dependency (mount layer adds scope checks — read:scans).

NO MOCKS rule
-------------
* When VERACODE_API_ID / VERACODE_API_KEY is unset:
    - Capability summary surfaces ``status="unavailable"``.
    - All live endpoints return HTTP 503.
* No fabricated payloads.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/veracode",
    tags=["Veracode"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Engine accessor (lazy import so tests can patch the singleton)
# ---------------------------------------------------------------------------


def _engine():
    from core.veracode_engine import get_veracode_engine

    return get_veracode_engine()


def _serve(callable_):
    """Run a Veracode call, translating engine errors to HTTP responses."""
    from core.veracode_engine import VeracodeUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except VeracodeUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    veracode_api_id_present: bool
    veracode_api_key_present: bool
    status: str  # ok | empty | unavailable


class GenericResponse(BaseModel):
    """Loose wrapper — Veracode AppSec payloads are deeply nested HAL+JSON
    structures with many optional fields. We forward the upstream JSON
    verbatim and let the UI consume the documented shape."""

    model_config = ConfigDict(extra="allow")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=CapabilityResponse,
    summary="Veracode capability summary",
)
async def capability_summary() -> CapabilityResponse:
    """Return the service summary — safe to call without credentials."""
    eng = _engine()
    id_present = eng.api_id_present()
    key_present = eng.api_key_present()
    if not (id_present and key_present):
        status = "unavailable"
    else:
        status = "ok"
    return CapabilityResponse(
        service="Veracode",
        endpoints=[
            "/appsec/v1/applications",
            "/appsec/v1/applications/{guid}",
            "/appsec/v2/applications/{guid}/findings",
            "/appsec/v1/findings/{id}/annotations",
            "/appsec/v1/policies",
        ],
        veracode_api_id_present=id_present,
        veracode_api_key_present=key_present,
        status=status,
    )


@router.get(
    "/appsec/v1/applications",
    summary="List Veracode applications",
)
async def list_applications(
    size: Optional[int] = Query(default=None, ge=1, le=500),
    page: Optional[int] = Query(default=None, ge=0),
    name: Optional[str] = Query(default=None, description="Substring search"),
) -> Dict[str, Any]:
    eng = _engine()
    return _serve(
        lambda: eng.list_applications(size=size, page=page, name=name)
    )


@router.get(
    "/appsec/v1/applications/{app_guid}",
    summary="Get a single Veracode application by GUID",
)
async def get_application(
    app_guid: str = Path(..., description="Application GUID"),
) -> Dict[str, Any]:
    eng = _engine()
    return _serve(lambda: eng.get_application(app_guid))


@router.get(
    "/appsec/v2/applications/{app_guid}/findings",
    summary="List findings for a Veracode application",
)
async def list_findings(
    app_guid: str = Path(..., description="Application GUID"),
    size: Optional[int] = Query(default=None, ge=1, le=500),
    page: Optional[int] = Query(default=None, ge=0),
    context: Optional[str] = Query(
        default=None, description="Sandbox GUID for sandbox-scoped findings"
    ),
    include_annot: Optional[bool] = Query(default=None),
    include_exp_date: Optional[bool] = Query(default=None),
    violates_policy: Optional[bool] = Query(default=None),
    scan_type: Optional[str] = Query(
        default=None,
        pattern="^(STATIC|DYNAMIC|MANUAL|SCA)$",
    ),
    severity: Optional[int] = Query(default=None, ge=1, le=5),
    severity_gte: Optional[int] = Query(default=None, ge=1, le=5),
    cwe: Optional[int] = Query(default=None, ge=1),
) -> Dict[str, Any]:
    eng = _engine()
    return _serve(
        lambda: eng.list_findings(
            app_guid=app_guid,
            size=size,
            page=page,
            context=context,
            include_annot=include_annot,
            include_exp_date=include_exp_date,
            violates_policy=violates_policy,
            scan_type=scan_type,
            severity=severity,
            severity_gte=severity_gte,
            cwe=cwe,
        )
    )


@router.get(
    "/appsec/v1/findings/{finding_id}/annotations",
    summary="List annotations for a finding",
)
async def list_finding_annotations(
    finding_id: str = Path(..., description="Veracode finding issue ID"),
    app_guid: str = Query(..., description="Application GUID owning the finding"),
) -> Dict[str, Any]:
    eng = _engine()
    return _serve(
        lambda: eng.list_finding_annotations(finding_id, app_guid=app_guid)
    )


@router.get(
    "/appsec/v1/policies",
    summary="List Veracode policies",
)
async def list_policies(
    name: Optional[str] = Query(default=None, description="Substring search"),
    size: Optional[int] = Query(default=None, ge=1, le=500),
    page: Optional[int] = Query(default=None, ge=0),
) -> Dict[str, Any]:
    eng = _engine()
    return _serve(
        lambda: eng.list_policies(name=name, size=size, page=page)
    )


__all__ = ["router"]
