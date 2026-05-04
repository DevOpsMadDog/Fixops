"""Contrast Security RASP/IAST Router — ALDECI.

Wraps Contrast NG REST surfaces under prefix ``/api/v1/contrast``:

  - GET /                                                     — capability summary
  - GET /api/ng/{org_id}/applications                         — application inventory
  - GET /api/ng/{org_id}/applications/{app_id}                — single application
  - GET /api/ng/{org_id}/traces/{app_id}/filter               — vulnerability traces
  - GET /api/ng/{org_id}/traces/{trace_uuid}                  — single trace
  - GET /api/ng/{org_id}/protect/policies                     — RASP protect policies
  - GET /api/ng/{org_id}/servers                              — server inventory
  - GET /api/ng/{org_id}/libraries                            — SCA libraries

NO MOCKS rule
-------------
* When any of CONTRAST_BASE_URL / CONTRAST_API_KEY / CONTRAST_AUTH_HEADER /
  CONTRAST_SERVICE_KEY is unset:
    - Capability summary surfaces ``status="unavailable"``.
    - All live endpoints return HTTP 503.
* No fabricated payloads.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Path, Query

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/contrast",
    tags=["Contrast"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Engine accessor (lazy import so tests can patch the singleton)
# ---------------------------------------------------------------------------


def _engine():
    from core.contrast_engine import get_contrast_engine

    return get_contrast_engine()


def _serve(callable_):
    """Run a Contrast call, translating engine errors to HTTP responses.

    ContrastUnavailableError -> 503 (creds missing, network, upstream error)
    ValueError               -> 422 (input validation)
    """
    from core.contrast_engine import ContrastUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ContrastUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


@router.get("/", summary="Contrast Security RASP/IAST capability summary")
def capability_summary() -> Dict[str, Any]:
    eng = _engine()
    base_ok = eng.base_url_present()
    key_ok = eng.api_key_present()
    auth_ok = eng.auth_header_present()
    svc_ok = eng.service_key_present()
    creds = base_ok and key_ok and auth_ok and svc_ok
    return {
        "service": "Contrast Security",
        "endpoints": [
            "/api/ng/{org}/applications",
            "/api/ng/{org}/traces",
            "/api/ng/{org}/protect/policies",
            "/api/ng/{org}/servers",
            "/api/ng/{org}/libraries",
        ],
        "contrast_base_url_present": base_ok,
        "contrast_api_key_present": key_ok,
        "contrast_auth_header_present": auth_ok,
        "contrast_service_key_present": svc_ok,
        "status": "ok" if creds else "unavailable",
    }


# ---------------------------------------------------------------------------
# Applications
# ---------------------------------------------------------------------------


@router.get(
    "/api/ng/{org_id}/applications",
    summary="List Contrast applications for an organization",
)
def list_applications(
    org_id: str = Path(..., description="Contrast organization UUID"),
    limit: Optional[int] = Query(default=None, ge=1, le=10000),
    offset: Optional[int] = Query(default=None, ge=0),
    filterText: Optional[str] = Query(default=None),
    filterServers: Optional[str] = Query(default=None),
    filterTags: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().applications(
            org_id,
            limit=limit,
            offset=offset,
            filter_text=filterText,
            filter_servers=filterServers,
            filter_tags=filterTags,
        )
    )


@router.get(
    "/api/ng/{org_id}/applications/{app_id}",
    summary="Get a single Contrast application",
)
def get_application(
    org_id: str = Path(...),
    app_id: str = Path(..., description="Contrast application UUID"),
) -> Dict[str, Any]:
    return _serve(lambda: _engine().application(org_id, app_id))


# ---------------------------------------------------------------------------
# Traces (Assess vulnerabilities)
# ---------------------------------------------------------------------------


@router.get(
    "/api/ng/{org_id}/traces/{app_id}/filter",
    summary="List Contrast Assess traces for an application",
)
def list_traces(
    org_id: str = Path(...),
    app_id: str = Path(...),
    severities: Optional[str] = Query(
        default=None,
        description="Comma-separated severities: CRITICAL,HIGH,MEDIUM,LOW,NOTE",
    ),
    statuses: Optional[str] = Query(
        default=None,
        description="Comma-separated statuses: REPORTED,SUSPICIOUS,CONFIRMED,NOTPROBLEM,REMEDIATED,REOPENED,FIXED,UNTRACKED",
    ),
    limit: Optional[int] = Query(default=None, ge=1, le=10000),
    offset: Optional[int] = Query(default=None, ge=0),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().traces_filter(
            org_id,
            app_id,
            severities=severities,
            statuses=statuses,
            limit=limit,
            offset=offset,
        )
    )


@router.get(
    "/api/ng/{org_id}/traces/{trace_uuid}",
    summary="Get a single Contrast trace",
)
def get_trace(
    org_id: str = Path(...),
    trace_uuid: str = Path(..., description="Contrast trace UUID"),
) -> Dict[str, Any]:
    return _serve(lambda: _engine().trace(org_id, trace_uuid))


# ---------------------------------------------------------------------------
# Protect policies (RASP)
# ---------------------------------------------------------------------------


@router.get(
    "/api/ng/{org_id}/protect/policies",
    summary="List Contrast Protect (RASP) policies",
)
def list_protect_policies(
    org_id: str = Path(...),
) -> Dict[str, Any]:
    return _serve(lambda: _engine().protect_policies(org_id))


# ---------------------------------------------------------------------------
# Servers
# ---------------------------------------------------------------------------


@router.get(
    "/api/ng/{org_id}/servers",
    summary="List Contrast-monitored servers",
)
def list_servers(
    org_id: str = Path(...),
    expand: Optional[str] = Query(default=None, description="e.g. skip_links"),
    q: Optional[str] = Query(default=None),
    applicationIds: Optional[str] = Query(default=None),
    environment: Optional[str] = Query(
        default=None,
        description="DEVELOPMENT|QA|PRODUCTION",
    ),
    offset: Optional[int] = Query(default=None, ge=0),
    limit: Optional[int] = Query(default=None, ge=1, le=10000),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().servers(
            org_id,
            expand=expand,
            q=q,
            application_ids=applicationIds,
            environment=environment,
            offset=offset,
            limit=limit,
        )
    )


# ---------------------------------------------------------------------------
# Libraries (SCA)
# ---------------------------------------------------------------------------


@router.get(
    "/api/ng/{org_id}/libraries",
    summary="List third-party libraries with vuln overlay",
)
def list_libraries(
    org_id: str = Path(...),
    expand: Optional[str] = Query(default=None, description="e.g. manifest,vulns"),
    q: Optional[str] = Query(default=None),
    offset: Optional[int] = Query(default=None, ge=0),
    limit: Optional[int] = Query(default=None, ge=1, le=10000),
    filterScore: Optional[str] = Query(
        default=None, description="A|B|C|D|F"
    ),
    filterLanguage: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().libraries(
            org_id,
            expand=expand,
            q=q,
            offset=offset,
            limit=limit,
            filter_score=filterScore,
            filter_language=filterLanguage,
        )
    )


__all__ = ["router"]
