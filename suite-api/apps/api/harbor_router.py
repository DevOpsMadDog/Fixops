"""ALDECI Harbor Container Registry API Router.

Direct pass-through to the Harbor v2.0 REST API — image vulnerability scanning,
project / repository / artifact catalog, scanner registry.

Endpoints (mounted at ``/api/v1/harbor``)
-----------------------------------------
GET    /                                                                          — capability summary
GET    /api/v2.0/health                                                           — overall + component health
GET    /api/v2.0/projects                                                         — list projects
GET    /api/v2.0/projects/{project_name}/repositories                             — list repositories
GET    /api/v2.0/projects/{project_name}/repositories/{repository_name}/artifacts — list artifacts (+optional scan_overview)
GET    /api/v2.0/projects/{project_name}/repositories/{repository_name}/artifacts/{digest}/additions/vulnerabilities
                                                                                  — vuln-only payload
POST   /api/v2.0/projects/{project_name}/repositories/{repository_name}/artifacts/{digest}/scan
                                                                                  — trigger scan (202)
DELETE /api/v2.0/projects/{project_name}/repositories/{repository_name}/artifacts/{digest}
                                                                                  — delete artifact
GET    /api/v2.0/scanners                                                         — list scanners
POST   /api/v2.0/projects/{project_name}/scanner                                  — set project scanner

When ``HARBOR_URL`` / ``HARBOR_USERNAME`` / ``HARBOR_PASSWORD`` are unset the
capability summary reports ``status="unavailable"`` and lookup endpoints
respond with HTTP 503.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Response
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/harbor",
    tags=["harbor"],
)


# ---------------------------------------------------------------------------
# Lazy engine accessor (test seam)
# ---------------------------------------------------------------------------


def _get_engine():
    from core.harbor_registry_engine import get_harbor_registry_engine
    return get_harbor_registry_engine()


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class CapabilitySummary(BaseModel):
    service: str
    endpoints: List[str]
    harbor_url_present: bool
    harbor_username_present: bool
    harbor_password_present: bool
    status: str = Field(..., description="ok | empty | unavailable")


class HealthComponent(BaseModel):
    name: Optional[str] = None
    status: Optional[str] = None
    error: Optional[str] = None


class HealthSummary(BaseModel):
    status: Optional[str] = Field(None, description="healthy | unhealthy")
    components: List[HealthComponent] = []


class ProjectMetadata(BaseModel):
    public: Optional[str] = None
    enable_content_trust: Optional[str] = None
    prevent_vul: Optional[str] = None
    severity: Optional[str] = None
    auto_scan: Optional[str] = None


class CVEAllowlistItem(BaseModel):
    cve_id: Optional[str] = None


class CVEAllowlist(BaseModel):
    id: Optional[int] = None
    project_id: Optional[int] = None
    expires_at: Optional[int] = None
    items: List[CVEAllowlistItem] = []
    creation_time: Optional[str] = None
    update_time: Optional[str] = None


class Project(BaseModel):
    project_id: Optional[int] = None
    name: Optional[str] = None
    owner_name: Optional[str] = None
    owner_id: Optional[int] = None
    creation_time: Optional[str] = None
    update_time: Optional[str] = None
    deleted: Optional[bool] = None
    current_user_role_id: Optional[int] = None
    current_user_role_ids: List[int] = []
    repo_count: Optional[int] = None
    chart_count: Optional[int] = None
    metadata: Optional[ProjectMetadata] = None
    cve_allowlist: Optional[CVEAllowlist] = None


class Repository(BaseModel):
    id: Optional[int] = None
    project_id: Optional[int] = None
    name: Optional[str] = None
    description: Optional[str] = None
    artifact_count: Optional[int] = None
    pull_count: Optional[int] = None
    creation_time: Optional[str] = None
    update_time: Optional[str] = None


class Tag(BaseModel):
    id: Optional[int] = None
    repository_id: Optional[int] = None
    artifact_id: Optional[int] = None
    name: Optional[str] = None
    push_time: Optional[str] = None
    pull_time: Optional[str] = None
    immutable: Optional[bool] = None
    signed: Optional[bool] = None


class Vulnerability(BaseModel):
    id: Optional[str] = None
    package: Optional[str] = None
    version: Optional[str] = None
    fix_version: Optional[str] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    links: List[str] = []


class VulnerabilitySummaryCounts(BaseModel):
    Critical: Optional[int] = None
    High: Optional[int] = None
    Medium: Optional[int] = None
    Low: Optional[int] = None
    Negligible: Optional[int] = None
    None_: Optional[int] = Field(None, alias="None")
    Unknown: Optional[int] = None

    class Config:
        populate_by_name = True


class VulnerabilitySummary(BaseModel):
    total: Optional[int] = None
    fixable: Optional[int] = None
    summary: Optional[VulnerabilitySummaryCounts] = None


class ScanReport(BaseModel):
    vulnerabilities: List[Vulnerability] = []
    severity: Optional[str] = None
    scan_status: Optional[str] = None
    vulnerability_summary: Optional[VulnerabilitySummary] = None


class ScannerRef(BaseModel):
    name: Optional[str] = None
    vendor: Optional[str] = None
    version: Optional[str] = None


class ScanOverview(BaseModel):
    report: Optional[ScanReport] = None
    scanner: Optional[ScannerRef] = None
    status: Optional[str] = Field(
        None, description="Pending | Running | Stopped | Error | Success"
    )


class ArtifactExtraAttrConfig(BaseModel):
    pass


class ArtifactExtraAttrs(BaseModel):
    architecture: Optional[str] = None
    os: Optional[str] = None
    created: Optional[str] = None
    config: Optional[Dict[str, Any]] = None


class Artifact(BaseModel):
    id: Optional[int] = None
    type: Optional[str] = None
    media_type: Optional[str] = None
    manifest_media_type: Optional[str] = None
    project_id: Optional[int] = None
    repository_id: Optional[int] = None
    digest: Optional[str] = None
    size: Optional[int] = None
    push_time: Optional[str] = None
    pull_time: Optional[str] = None
    extra_attrs: Optional[ArtifactExtraAttrs] = None
    annotations: Optional[Dict[str, Any]] = None
    references: List[Dict[str, Any]] = []
    tags: List[Tag] = []
    addition_links: Optional[Dict[str, Any]] = None
    scan_overview: Optional[Dict[str, ScanOverview]] = None


class VulnerabilityReport(BaseModel):
    report: Optional[ScanReport] = None
    scanner: Optional[ScannerRef] = None
    severity: Optional[str] = None
    scan_status: Optional[str] = None
    vulnerability_summary: Optional[VulnerabilitySummary] = None


class ScannerCapabilities(BaseModel):
    consumes_mime_types: List[str] = []
    produces_mime_types: List[str] = []


class Scanner(BaseModel):
    uuid: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    url: Optional[str] = None
    auth: Optional[str] = None
    access_credential: Optional[str] = None
    skip_certVerify: Optional[bool] = None
    use_internal_addr: Optional[bool] = None
    disabled: Optional[bool] = None
    is_default: Optional[bool] = None
    health: Optional[str] = None
    vendor: Optional[str] = None
    version: Optional[str] = None
    adapter: Optional[str] = None
    capabilities: Optional[ScannerCapabilities] = None
    properties: Optional[Dict[str, Any]] = None


class SetScannerRequest(BaseModel):
    scanner_id: str = Field(..., description="UUID of the scanner to bind to the project")


class ScanAccepted(BaseModel):
    accepted: bool
    status_code: int


class ArtifactDeleted(BaseModel):
    deleted: bool


class ProjectScannerUpdated(BaseModel):
    updated: bool
    scanner_id: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _raise_unavailable() -> None:
    raise HTTPException(
        status_code=503,
        detail={
            "error": "harbor_registry_unavailable",
            "message": "HARBOR_URL, HARBOR_USERNAME and HARBOR_PASSWORD environment "
            "variables are not configured",
        },
    )


def _map_harbor_error(exc: Exception) -> HTTPException:
    """Translate a HarborRegistryHTTPError (or unavailable) into an HTTPException."""
    from core.harbor_registry_engine import (
        HarborRegistryHTTPError,
        HarborRegistryUnavailable,
    )

    if isinstance(exc, HarborRegistryUnavailable):
        return HTTPException(
            status_code=503,
            detail={"error": "harbor_registry_unavailable", "message": str(exc)},
        )
    if isinstance(exc, HarborRegistryHTTPError):
        passthrough = {400, 401, 403, 404, 409, 422, 429}
        status = exc.status_code if exc.status_code in passthrough else 502
        return HTTPException(
            status_code=status,
            detail={
                "error": "harbor_upstream_error",
                "upstream_status": exc.status_code,
                "message": str(exc),
                "payload": exc.payload,
            },
        )
    return HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=CapabilitySummary,
    summary="Harbor capability summary",
)
def capability_summary() -> CapabilitySummary:
    """Return service identity, exposed endpoints, and configuration status."""
    engine = _get_engine()
    return CapabilitySummary(**engine.capability_summary())


@router.get(
    "/api/v2.0/health",
    response_model=HealthSummary,
    summary="Harbor overall + per-component health",
)
def harbor_health() -> HealthSummary:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.health()
    except Exception as exc:
        raise _map_harbor_error(exc) from exc
    return HealthSummary(
        status=body.get("status"),
        components=[
            HealthComponent(**c) for c in body.get("components", []) if isinstance(c, dict)
        ],
    )


@router.get(
    "/api/v2.0/projects",
    response_model=List[Project],
    summary="List Harbor projects",
)
def list_projects(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    name: Optional[str] = Query(None, description="Filter by project name (substring match)"),
    owner: Optional[str] = Query(None, description="Filter by owner username"),
    public: Optional[bool] = Query(None, description="Filter by public flag"),
) -> List[Project]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.list_projects(
            page=page,
            page_size=page_size,
            name=name,
            owner=owner,
            public=public,
        )
    except Exception as exc:
        raise _map_harbor_error(exc) from exc
    return [Project(**p) for p in body if isinstance(p, dict)]


@router.get(
    "/api/v2.0/projects/{project_name}/repositories",
    response_model=List[Repository],
    summary="List repositories under a project",
)
def list_repositories(
    project_name: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    q: Optional[str] = Query(None, description="Generic Harbor query string"),
    sort: Optional[str] = Query(None, description="Sort field, e.g. 'name' or '-update_time'"),
) -> List[Repository]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.list_repositories(
            project_name,
            page=page,
            page_size=page_size,
            q=q,
            sort=sort,
        )
    except Exception as exc:
        raise _map_harbor_error(exc) from exc
    return [Repository(**r) for r in body if isinstance(r, dict)]


@router.get(
    "/api/v2.0/projects/{project_name}/repositories/{repository_name}/artifacts",
    response_model=List[Artifact],
    summary="List artifacts of a repository (with optional scan overview)",
)
def list_artifacts(
    project_name: str,
    repository_name: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    q: Optional[str] = Query(None),
    sort: Optional[str] = Query(None),
    with_tag: Optional[bool] = Query(None),
    with_scan_overview: Optional[bool] = Query(None),
    with_signature: Optional[bool] = Query(None),
) -> List[Artifact]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.list_artifacts(
            project_name,
            repository_name,
            page=page,
            page_size=page_size,
            q=q,
            sort=sort,
            with_tag=with_tag,
            with_scan_overview=with_scan_overview,
            with_signature=with_signature,
        )
    except Exception as exc:
        raise _map_harbor_error(exc) from exc
    return [Artifact(**a) for a in body if isinstance(a, dict)]


@router.get(
    "/api/v2.0/projects/{project_name}/repositories/{repository_name}/artifacts/{digest}/additions/vulnerabilities",
    response_model=VulnerabilityReport,
    summary="Vulnerability-only report for an artifact",
)
def get_artifact_vulnerabilities(
    project_name: str,
    repository_name: str,
    digest: str,
) -> VulnerabilityReport:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.get_artifact_vulnerabilities(
            project_name, repository_name, digest
        )
    except Exception as exc:
        raise _map_harbor_error(exc) from exc
    # Harbor returns either {report, scanner, severity, scan_status, vulnerability_summary}
    # OR a mime-keyed dict like {"application/vnd.security.vulnerability.report; ...": {...}}
    # If the latter, peel the first value.
    if body and not any(
        k in body for k in ("report", "scanner", "severity", "scan_status", "vulnerability_summary")
    ):
        # mime-keyed payload
        first = next((v for v in body.values() if isinstance(v, dict)), {})
        body = first
    return VulnerabilityReport(**body)


@router.post(
    "/api/v2.0/projects/{project_name}/repositories/{repository_name}/artifacts/{digest}/scan",
    response_model=ScanAccepted,
    status_code=202,
    summary="Trigger a vulnerability scan for an artifact",
)
def scan_artifact(
    project_name: str,
    repository_name: str,
    digest: str,
    response: Response,
) -> ScanAccepted:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.trigger_scan(project_name, repository_name, digest)
    except Exception as exc:
        raise _map_harbor_error(exc) from exc
    response.status_code = 202
    return ScanAccepted(
        accepted=bool(body.get("accepted", True)),
        status_code=int(body.get("status_code", 202)),
    )


@router.delete(
    "/api/v2.0/projects/{project_name}/repositories/{repository_name}/artifacts/{digest}",
    response_model=ArtifactDeleted,
    summary="Delete an artifact",
)
def delete_artifact(
    project_name: str,
    repository_name: str,
    digest: str,
) -> ArtifactDeleted:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.delete_artifact(project_name, repository_name, digest)
    except Exception as exc:
        raise _map_harbor_error(exc) from exc
    return ArtifactDeleted(deleted=bool(body.get("deleted", True)))


@router.get(
    "/api/v2.0/scanners",
    response_model=List[Scanner],
    summary="List configured scanner adapters",
)
def list_scanners(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    q: Optional[str] = Query(None),
    sort: Optional[str] = Query(None),
) -> List[Scanner]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.list_scanners(page=page, page_size=page_size, q=q, sort=sort)
    except Exception as exc:
        raise _map_harbor_error(exc) from exc
    return [Scanner(**s) for s in body if isinstance(s, dict)]


@router.post(
    "/api/v2.0/projects/{project_name}/scanner",
    response_model=ProjectScannerUpdated,
    summary="Bind a scanner adapter to a project",
)
def set_project_scanner(
    project_name: str,
    payload: SetScannerRequest,
) -> ProjectScannerUpdated:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.set_project_scanner(project_name, payload.scanner_id)
    except Exception as exc:
        raise _map_harbor_error(exc) from exc
    return ProjectScannerUpdated(
        updated=bool(body.get("updated", True)),
        scanner_id=str(body.get("scanner_id", payload.scanner_id)),
    )
