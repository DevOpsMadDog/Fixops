"""Snyk Vulnerability Scanner Router — ALDECI.

REST surface under prefix ``/api/v1/snyk`` wrapping ``core.snyk_vuln_engine``.

Endpoints
---------
* GET  /                                               — capability summary
* GET  /v1/orgs                                        — list organisations
* GET  /v1/orgs/{org_id}/projects                      — list projects (filters/names)
* POST /v1/test/{ecosystem}/{file_path}                — test a manifest
* GET  /v1/orgs/{org_id}/projects/{project_id}/issues  — list project issues
* GET  /v1/reporting                                   — basic reporting summary

Auth
----
api_key_auth dependency (mount layer adds scope checks — read:scans).

NO MOCKS rule
-------------
* When SNYK_TOKEN is unset:
    - Capability summary surfaces ``status="unavailable"``.
    - All live endpoints return HTTP 503.
* No fabricated payloads.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/snyk",
    tags=["Snyk"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Engine accessor (lazy import so tests can patch the singleton)
# ---------------------------------------------------------------------------


def _engine():
    from core.snyk_vuln_engine import get_snyk_vuln_engine

    return get_snyk_vuln_engine()


def _serve(callable_):
    """Run a Snyk call, translating engine errors to HTTP responses."""
    from core.snyk_vuln_engine import SnykUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except SnykUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    snyk_token_present: bool
    status: str  # ok | empty | unavailable


class OrgGroup(BaseModel):
    id: str = ""
    name: str = ""


class OrgEntry(BaseModel):
    id: str = ""
    name: str = ""
    slug: str = ""
    group: OrgGroup = Field(default_factory=OrgGroup)


class OrgsResponse(BaseModel):
    orgs: List[OrgEntry]


class IssueCountsBySeverity(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class ProjectEntry(BaseModel):
    id: str = ""
    name: str = ""
    type: str = ""
    origin: str = ""
    branch: str = ""
    isMonitored: bool = False
    totalDependencies: int = 0
    issueCountsBySeverity: IssueCountsBySeverity = Field(
        default_factory=IssueCountsBySeverity
    )


class ProjectsResponse(BaseModel):
    projects: List[ProjectEntry]


class TestRequest(BaseModel):
    encoding: str = Field("plain", description="plain or base64")
    files: Dict[str, Any] = Field(default_factory=dict)
    displayTargetFile: str = ""


class VulnerabilityEntry(BaseModel):
    id: str = ""
    title: str = ""
    severity: str = ""
    package: str = ""
    version: str = ""
    fixedIn: List[str] = Field(default_factory=list)


class LicenseEntry(BaseModel):
    id: str = ""
    title: str = ""
    severity: str = ""
    package: str = ""
    version: str = ""


class IssuesBucket(BaseModel):
    vulnerabilities: List[VulnerabilityEntry] = Field(default_factory=list)
    licenses: List[LicenseEntry] = Field(default_factory=list)


class TestResponse(BaseModel):
    ok: bool = False
    dependencyCount: int = 0
    issues: IssuesBucket = Field(default_factory=IssuesBucket)


class IssuesFilter(BaseModel):
    severities: List[str] = Field(default_factory=list)


class IssuesQuery(BaseModel):
    filters: IssuesFilter = Field(default_factory=IssuesFilter)


class IssuesResponse(BaseModel):
    issues: IssuesBucket = Field(default_factory=IssuesBucket)


class ReportingResponse(BaseModel):
    service: str
    snyk_token_present: bool
    status: str
    notes: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=CapabilityResponse,
    summary="Snyk capability summary",
)
async def capability_summary() -> CapabilityResponse:
    """Return the service summary — safe to call without a token."""
    eng = _engine()
    token_present = eng.api_key_present()
    if not token_present:
        status = "unavailable"
    else:
        # No persistent cache; we surface "ok" once the token is present.
        status = "ok"
    return CapabilityResponse(
        service="Snyk",
        endpoints=[
            "/v1/orgs",
            "/v1/orgs/{org}/projects",
            "/v1/test",
            "/v1/orgs/{org}/projects/{project}/issues",
            "/v1/reporting",
        ],
        snyk_token_present=token_present,
        status=status,
    )


@router.get(
    "/v1/orgs",
    response_model=OrgsResponse,
    summary="List Snyk organisations",
)
async def list_orgs() -> OrgsResponse:
    eng = _engine()
    data = _serve(lambda: eng.list_orgs())
    return OrgsResponse(**data)


@router.get(
    "/v1/orgs/{org_id}/projects",
    response_model=ProjectsResponse,
    summary="List Snyk projects for an organisation",
)
async def list_projects(
    org_id: str = Path(..., description="Snyk organisation UUID"),
    filters: Optional[List[str]] = Query(
        default=None,
        alias="filters[]",
        description="Repeated filter params (tags|status)",
    ),
    names: Optional[str] = Query(
        default=None,
        description="Comma-separated project names to match",
    ),
) -> ProjectsResponse:
    eng = _engine()
    data = _serve(
        lambda: eng.list_projects(org_id=org_id, filters=filters, names=names)
    )
    return ProjectsResponse(**data)


@router.post(
    "/v1/test/{ecosystem}/{file_path:path}",
    response_model=TestResponse,
    summary="Test a manifest for vulnerabilities",
)
async def test_manifest(
    ecosystem: str = Path(
        ...,
        description="Package ecosystem",
        pattern="^(npm|maven|pip|gomodules|composer|gradle|rubygems)$",
    ),
    file_path: str = Path(..., description="Manifest file path"),
    body: TestRequest = Body(default_factory=TestRequest),
) -> TestResponse:
    eng = _engine()
    data = _serve(
        lambda: eng.test_manifest(
            ecosystem=ecosystem,
            file_path=file_path,
            encoding=body.encoding,
            files=body.files,
            display_target_file=body.displayTargetFile,
        )
    )
    return TestResponse(**data)


@router.get(
    "/v1/orgs/{org_id}/projects/{project_id}/issues",
    response_model=IssuesResponse,
    summary="List issues for a Snyk project",
)
async def project_issues(
    org_id: str = Path(..., description="Snyk organisation UUID"),
    project_id: str = Path(..., description="Snyk project UUID"),
    body: IssuesQuery = Body(default_factory=IssuesQuery),
) -> IssuesResponse:
    eng = _engine()
    data = _serve(
        lambda: eng.project_issues(
            org_id=org_id,
            project_id=project_id,
            severities=body.filters.severities or None,
        )
    )
    return IssuesResponse(**data)


@router.get(
    "/v1/reporting",
    response_model=ReportingResponse,
    summary="Snyk reporting capability stub",
)
async def reporting_summary() -> ReportingResponse:
    """Reporting endpoint — returns a status summary.

    Snyk's full reporting API requires a Business/Enterprise plan and is
    org-scoped; we expose a capability check here so consumers can wire UI
    placeholders without erroring out when a token is absent.
    """
    eng = _engine()
    present = eng.api_key_present()
    if not present:
        status = "unavailable"
        notes = "SNYK_TOKEN is not configured"
    else:
        status = "ok"
        notes = (
            "Reporting capability available; query org-scoped reports via the "
            "Snyk REST surface (/orgs/{org}/projects + /issues)."
        )
    return ReportingResponse(
        service="Snyk",
        snyk_token_present=present,
        status=status,
        notes=notes,
    )


__all__ = ["router"]
