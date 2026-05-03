"""SonarQube Router — ALDECI.

Wraps ``core.sonarqube_engine.SonarQubeEngine`` with REST endpoints mirroring
the SonarQube Web API surface used by ASPM/CTEM workflows.

Prefix: /api/v1/sonarqube
Auth:   api_key_auth dependency (mount layer adds scope checks — read:scans)

Routes:
  GET  /api/v1/sonarqube/                                 capability summary
  GET  /api/v1/sonarqube/api/projects/search              project listing
  GET  /api/v1/sonarqube/api/issues/search                issue search
  GET  /api/v1/sonarqube/api/qualitygates/project_status  quality gate status
  GET  /api/v1/sonarqube/api/measures/component           metric measures
  GET  /api/v1/sonarqube/api/components/show              component metadata
  GET  /api/v1/sonarqube/api/hotspots/search              security hotspots

NO MOCKS rule: when ``SONARQUBE_URL`` or ``SONAR_TOKEN`` is unset the
capability summary returns ``status="unavailable"`` and every live SonarQube
call returns HTTP 503. We never fabricate findings, never use a SQLite cache.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/sonarqube",
    tags=["SonarQube"],
    dependencies=[Depends(api_key_auth)],
)


def _engine():
    from core.sonarqube_engine import get_sonarqube_engine

    return get_sonarqube_engine()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    sonarqube_url_present: bool
    sonar_token_present: bool
    status: str  # ok | empty | unavailable


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _serve(callable_):
    """Translate engine errors to HTTP responses.

    SonarQubeUnavailableError -> 503  (creds missing, network, upstream error)
    ValueError                -> 422  (input validation)
    """
    from core.sonarqube_engine import SonarQubeUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except SonarQubeUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", response_model=CapabilityResponse)
async def capability_summary() -> CapabilityResponse:
    """Service capability summary — safe to call without SonarQube credentials."""
    eng = _engine()
    url_ok = eng.sonarqube_url_present()
    tok_ok = eng.sonar_token_present()
    if not (url_ok and tok_ok):
        status = "unavailable"
    else:
        status = "empty"  # no in-process cache; live calls populate
    return CapabilityResponse(
        service="SonarQube",
        endpoints=[
            "/api/projects/search",
            "/api/issues/search",
            "/api/qualitygates/project_status",
            "/api/measures/component",
            "/api/components/show",
            "/api/hotspots/search",
        ],
        sonarqube_url_present=url_ok,
        sonar_token_present=tok_ok,
        status=status,
    )


@router.get("/api/projects/search")
async def projects_search(
    qualifiers: str = Query("TRK", description="Component qualifiers (TRK for projects)"),
    q: Optional[str] = Query(None, description="Search query"),
    projects: Optional[str] = Query(None, description="CSV of project keys"),
    p: Optional[int] = Query(None, ge=1, description="Page index (1-based)"),
    ps: Optional[int] = Query(None, ge=1, le=500, description="Page size"),
) -> Dict[str, Any]:
    """List/search SonarQube projects."""
    eng = _engine()
    return _serve(
        lambda: eng.projects_search(
            qualifiers=qualifiers,
            q=q,
            projects=projects,
            p=p,
            ps=ps,
        )
    )


@router.get("/api/issues/search")
async def issues_search(
    componentKeys: Optional[str] = Query(None, description="CSV of component keys"),
    severities: Optional[str] = Query(
        None, description="CSV of INFO,MINOR,MAJOR,CRITICAL,BLOCKER"
    ),
    types: Optional[str] = Query(
        None, description="CSV of CODE_SMELL,BUG,VULNERABILITY,SECURITY_HOTSPOT"
    ),
    statuses: Optional[str] = Query(
        None, description="CSV of OPEN,CONFIRMED,REOPENED,RESOLVED,CLOSED"
    ),
    p: Optional[int] = Query(None, ge=1),
    ps: Optional[int] = Query(None, ge=1, le=500),
    assignees: Optional[str] = Query(None, description="CSV of assignee logins"),
    tags: Optional[str] = Query(None, description="CSV of tags"),
    createdAfter: Optional[str] = Query(None, description="ISO date filter"),
    createdBefore: Optional[str] = Query(None, description="ISO date filter"),
) -> Dict[str, Any]:
    """Search issues across one or more SonarQube components."""
    eng = _engine()
    return _serve(
        lambda: eng.issues_search(
            componentKeys=componentKeys,
            severities=severities,
            types=types,
            statuses=statuses,
            p=p,
            ps=ps,
            assignees=assignees,
            tags=tags,
            createdAfter=createdAfter,
            createdBefore=createdBefore,
        )
    )


@router.get("/api/qualitygates/project_status")
async def qualitygates_project_status(
    projectKey: str = Query(..., description="SonarQube project key"),
    pullRequest: Optional[str] = Query(None),
    branch: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """Fetch the quality gate status for a project (optionally per PR/branch)."""
    eng = _engine()
    return _serve(
        lambda: eng.qualitygates_project_status(
            projectKey=projectKey,
            pullRequest=pullRequest,
            branch=branch,
        )
    )


@router.get("/api/measures/component")
async def measures_component(
    component: str = Query(..., description="Component key (project, dir, file)"),
    metricKeys: str = Query(..., description="CSV of metric keys"),
    branch: Optional[str] = Query(None),
    pullRequest: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """Fetch one or more metric measures for a component."""
    eng = _engine()
    return _serve(
        lambda: eng.measures_component(
            component=component,
            metricKeys=metricKeys,
            branch=branch,
            pullRequest=pullRequest,
        )
    )


@router.get("/api/components/show")
async def components_show(
    key: str = Query(..., description="Component key"),
    branch: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """Show component metadata + ancestors."""
    eng = _engine()
    return _serve(
        lambda: eng.components_show(
            key=key,
            branch=branch,
        )
    )


@router.get("/api/hotspots/search")
async def hotspots_search(
    projectKey: Optional[str] = Query(None),
    hotspots: Optional[str] = Query(None, description="CSV of hotspot keys"),
    status: Optional[str] = Query(None, description="TO_REVIEW | REVIEWED"),
    resolution: Optional[str] = Query(None, description="FIXED | SAFE | ACKNOWLEDGED"),
    pullRequest: Optional[str] = Query(None),
    branch: Optional[str] = Query(None),
    p: Optional[int] = Query(None, ge=1),
    ps: Optional[int] = Query(None, ge=1, le=500),
) -> Dict[str, Any]:
    """Search SonarQube security hotspots."""
    eng = _engine()
    return _serve(
        lambda: eng.hotspots_search(
            projectKey=projectKey,
            hotspots=hotspots,
            status=status,
            resolution=resolution,
            pullRequest=pullRequest,
            branch=branch,
            p=p,
            ps=ps,
        )
    )
