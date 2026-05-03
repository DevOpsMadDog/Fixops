"""ALDECI Google Artifact Registry (GAR) API Router.

Direct pass-through to the Google Artifact Registry v1 REST API — locations,
repositories, packages, versions, docker images, files, and IAM policy.

Endpoints (mounted at ``/api/v1/gar``)
--------------------------------------
GET /                                                                                          — capability summary
GET /v1/projects/{project}/locations                                                           — list locations
GET /v1/projects/{project}/locations/{location}/repositories                                   — list repositories
GET /v1/projects/{project}/locations/{location}/repositories/{repository:path}/packages        — list packages
GET /v1/projects/{project}/locations/{location}/repositories/{repository:path}/packages/{package:path}/versions
                                                                                               — list versions
GET /v1/projects/{project}/locations/{location}/repositories/{repository:path}/dockerImages    — list docker images
GET /v1/projects/{project}/locations/{location}/repositories/{repository:path}:getIamPolicy    — IAM policy
GET /v1/projects/{project}/locations/{location}/repositories/{repository:path}/files           — list files

When ``GOOGLE_APPLICATION_CREDENTIALS`` is unset the capability summary reports
``status="unavailable"`` and lookup endpoints respond with HTTP 503.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Path as FPath, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/gar",
    tags=["gar"],
)


# ---------------------------------------------------------------------------
# Lazy engine accessor (test seam)
# ---------------------------------------------------------------------------


def _get_engine():
    from core.gar_engine import get_gar_engine
    return get_gar_engine()


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class CapabilitySummary(BaseModel):
    service: str
    endpoints: List[str]
    google_app_creds_present: bool
    status: str = Field(..., description="ok | empty | unavailable")


class Location(BaseModel):
    name: Optional[str] = None
    locationId: Optional[str] = None
    displayName: Optional[str] = None
    labels: Dict[str, str] = {}
    metadata: Dict[str, Any] = {}


class LocationsResponse(BaseModel):
    locations: List[Location] = []
    nextPageToken: Optional[str] = None


class MavenConfig(BaseModel):
    allowSnapshotOverwrites: Optional[bool] = None
    versionPolicy: Optional[str] = Field(
        None, description="RELEASE | SNAPSHOT | VERSION_POLICY_UNSPECIFIED"
    )


class DockerConfig(BaseModel):
    immutableTags: Optional[bool] = None


class VirtualRepositoryConfig(BaseModel):
    upstreamPolicies: List[Dict[str, Any]] = []


class RemoteRepositoryConfig(BaseModel):
    description: Optional[str] = None
    mavenRepository: Optional[Dict[str, Any]] = None
    npmRepository: Optional[Dict[str, Any]] = None
    aptRepository: Optional[Dict[str, Any]] = None
    yumRepository: Optional[Dict[str, Any]] = None
    pythonRepository: Optional[Dict[str, Any]] = None
    dockerRepository: Optional[Dict[str, Any]] = None
    upstreamCredentials: Optional[Dict[str, Any]] = None


class Repository(BaseModel):
    name: Optional[str] = None
    format: Optional[str] = Field(
        None, description="DOCKER | MAVEN | NPM | APT | YUM | PYTHON | GENERIC | KFP | GO"
    )
    mode: Optional[str] = Field(
        None,
        description="STANDARD_REPOSITORY | VIRTUAL_REPOSITORY | REMOTE_REPOSITORY",
    )
    description: Optional[str] = None
    labels: Dict[str, str] = {}
    createTime: Optional[str] = None
    updateTime: Optional[str] = None
    kmsKeyName: Optional[str] = None
    mavenConfig: Optional[MavenConfig] = None
    dockerConfig: Optional[DockerConfig] = None
    virtualRepositoryConfig: Optional[VirtualRepositoryConfig] = None
    remoteRepositoryConfig: Optional[RemoteRepositoryConfig] = None
    sizeBytes: Optional[str] = None
    satisfiesPzs: Optional[bool] = None
    satisfiesPzi: Optional[bool] = None
    cleanupPolicies: Dict[str, Any] = {}
    cleanupPolicyDryRun: Optional[bool] = None


class RepositoriesResponse(BaseModel):
    repositories: List[Repository] = []
    nextPageToken: Optional[str] = None


class Package(BaseModel):
    name: Optional[str] = None
    displayName: Optional[str] = None
    createTime: Optional[str] = None
    updateTime: Optional[str] = None
    annotations: Dict[str, str] = {}


class PackagesResponse(BaseModel):
    packages: List[Package] = []
    nextPageToken: Optional[str] = None


class RelatedTag(BaseModel):
    name: Optional[str] = None
    version: Optional[str] = None


class Version(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    createTime: Optional[str] = None
    updateTime: Optional[str] = None
    relatedTags: List[RelatedTag] = []
    metadata: Dict[str, Any] = {}
    annotations: Dict[str, str] = {}


class VersionsResponse(BaseModel):
    versions: List[Version] = []
    nextPageToken: Optional[str] = None


class DockerImage(BaseModel):
    name: Optional[str] = None
    uri: Optional[str] = None
    tags: List[str] = []
    imageSizeBytes: Optional[str] = None
    uploadTime: Optional[str] = None
    mediaType: Optional[str] = None
    buildTime: Optional[str] = None
    updateTime: Optional[str] = None


class DockerImagesResponse(BaseModel):
    dockerImages: List[DockerImage] = []
    nextPageToken: Optional[str] = None


class IamCondition(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    expression: Optional[str] = None


class IamBinding(BaseModel):
    role: Optional[str] = None
    members: List[str] = []
    condition: Optional[IamCondition] = None


class IamPolicy(BaseModel):
    version: Optional[int] = None
    etag: Optional[str] = None
    bindings: List[IamBinding] = []
    auditConfigs: List[Dict[str, Any]] = []


class FileHash(BaseModel):
    type: Optional[str] = Field(None, description="SHA256 | MD5")
    value: Optional[str] = None


class GARFile(BaseModel):
    name: Optional[str] = None
    sizeBytes: Optional[str] = None
    hashes: List[FileHash] = []
    createTime: Optional[str] = None
    updateTime: Optional[str] = None
    owner: Optional[str] = None
    fetchTime: Optional[str] = None
    annotations: Dict[str, str] = {}


class FilesResponse(BaseModel):
    files: List[GARFile] = []
    nextPageToken: Optional[str] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _raise_unavailable() -> None:
    raise HTTPException(
        status_code=503,
        detail={
            "error": "gar_unavailable",
            "message": "GOOGLE_APPLICATION_CREDENTIALS environment variable is "
            "not configured (or points to an invalid keyfile)",
        },
    )


def _map_gar_error(exc: Exception) -> HTTPException:
    """Translate a GARHTTPError (or unavailable) into an HTTPException."""
    from core.gar_engine import GARHTTPError, GARUnavailable

    if isinstance(exc, GARUnavailable):
        return HTTPException(
            status_code=503,
            detail={"error": "gar_unavailable", "message": str(exc)},
        )
    if isinstance(exc, GARHTTPError):
        passthrough = {400, 401, 403, 404, 409, 422, 429}
        status = exc.status_code if exc.status_code in passthrough else 502
        return HTTPException(
            status_code=status,
            detail={
                "error": "gar_upstream_error",
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
    summary="Google Artifact Registry capability summary",
)
def capability_summary() -> CapabilitySummary:
    """Return service identity, exposed endpoints, and configuration status."""
    engine = _get_engine()
    return CapabilitySummary(**engine.capability_summary())


@router.get(
    "/v1/projects/{project}/locations",
    response_model=LocationsResponse,
    summary="List GAR locations available to a project",
)
def list_locations(project: str) -> LocationsResponse:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.list_locations(project)
    except Exception as exc:
        raise _map_gar_error(exc) from exc
    locations = [
        Location(**loc) for loc in body.get("locations", []) if isinstance(loc, dict)
    ]
    return LocationsResponse(
        locations=locations, nextPageToken=body.get("nextPageToken")
    )


@router.get(
    "/v1/projects/{project}/locations/{location}/repositories",
    response_model=RepositoriesResponse,
    summary="List repositories in a project + location",
)
def list_repositories(
    project: str,
    location: str,
    pageSize: Optional[int] = Query(None, ge=1, le=1000),
    pageToken: Optional[str] = Query(None),
) -> RepositoriesResponse:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.list_repositories(
            project, location, page_size=pageSize, page_token=pageToken
        )
    except Exception as exc:
        raise _map_gar_error(exc) from exc
    repos = [
        Repository(**r) for r in body.get("repositories", []) if isinstance(r, dict)
    ]
    return RepositoriesResponse(
        repositories=repos, nextPageToken=body.get("nextPageToken")
    )


@router.get(
    "/v1/projects/{project}/locations/{location}/repositories/{repository:path}/packages",
    response_model=PackagesResponse,
    summary="List packages in a repository",
)
def list_packages(
    project: str,
    location: str,
    repository: str = FPath(..., description="Repository ID (may contain '/')"),
    pageSize: Optional[int] = Query(None, ge=1, le=1000),
    pageToken: Optional[str] = Query(None),
    filter: Optional[str] = Query(None, description="CEL filter"),
    orderBy: Optional[str] = Query(None),
) -> PackagesResponse:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.list_packages(
            project,
            location,
            repository,
            page_size=pageSize,
            page_token=pageToken,
            filter_=filter,
            order_by=orderBy,
        )
    except Exception as exc:
        raise _map_gar_error(exc) from exc
    packages = [
        Package(**p) for p in body.get("packages", []) if isinstance(p, dict)
    ]
    return PackagesResponse(
        packages=packages, nextPageToken=body.get("nextPageToken")
    )


@router.get(
    "/v1/projects/{project}/locations/{location}/repositories/{repository}/packages/{package:path}/versions",
    response_model=VersionsResponse,
    summary="List versions of a package",
)
def list_versions(
    project: str,
    location: str,
    repository: str,
    package: str = FPath(..., description="Package ID (may contain '/')"),
    pageSize: Optional[int] = Query(None, ge=1, le=1000),
    pageToken: Optional[str] = Query(None),
    view: Optional[str] = Query(None, description="BASIC | FULL"),
    orderBy: Optional[str] = Query(None),
) -> VersionsResponse:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.list_versions(
            project,
            location,
            repository,
            package,
            page_size=pageSize,
            page_token=pageToken,
            view=view,
            order_by=orderBy,
        )
    except Exception as exc:
        raise _map_gar_error(exc) from exc
    versions = [
        Version(**v) for v in body.get("versions", []) if isinstance(v, dict)
    ]
    return VersionsResponse(
        versions=versions, nextPageToken=body.get("nextPageToken")
    )


@router.get(
    "/v1/projects/{project}/locations/{location}/repositories/{repository:path}/dockerImages",
    response_model=DockerImagesResponse,
    summary="List Docker images in a repository",
)
def list_docker_images(
    project: str,
    location: str,
    repository: str = FPath(..., description="Repository ID (may contain '/')"),
    pageSize: Optional[int] = Query(None, ge=1, le=1000),
    pageToken: Optional[str] = Query(None),
    orderBy: Optional[str] = Query(None),
    filter: Optional[str] = Query(None, description="CEL filter"),
) -> DockerImagesResponse:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.list_docker_images(
            project,
            location,
            repository,
            page_size=pageSize,
            page_token=pageToken,
            order_by=orderBy,
            filter_=filter,
        )
    except Exception as exc:
        raise _map_gar_error(exc) from exc
    images = [
        DockerImage(**i) for i in body.get("dockerImages", []) if isinstance(i, dict)
    ]
    return DockerImagesResponse(
        dockerImages=images, nextPageToken=body.get("nextPageToken")
    )


@router.get(
    "/v1/projects/{project}/locations/{location}/repositories/{repository:path}:getIamPolicy",
    response_model=IamPolicy,
    summary="Get IAM policy for a repository",
)
def get_iam_policy(
    project: str,
    location: str,
    repository: str = FPath(..., description="Repository ID (may contain '/')"),
    requestedPolicyVersion: Optional[int] = Query(
        None, alias="options.requestedPolicyVersion", ge=1, le=3
    ),
) -> IamPolicy:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.get_iam_policy(
            project,
            location,
            repository,
            requested_policy_version=requestedPolicyVersion,
        )
    except Exception as exc:
        raise _map_gar_error(exc) from exc
    return IamPolicy(
        version=body.get("version"),
        etag=body.get("etag"),
        bindings=[
            IamBinding(**b) for b in body.get("bindings", []) if isinstance(b, dict)
        ],
        auditConfigs=body.get("auditConfigs", []),
    )


@router.get(
    "/v1/projects/{project}/locations/{location}/repositories/{repository:path}/files",
    response_model=FilesResponse,
    summary="List files (artifacts) in a repository",
)
def list_files(
    project: str,
    location: str,
    repository: str = FPath(..., description="Repository ID (may contain '/')"),
    pageSize: Optional[int] = Query(None, ge=1, le=1000),
    pageToken: Optional[str] = Query(None),
    filter: Optional[str] = Query(None, description="CEL filter"),
    orderBy: Optional[str] = Query(None),
) -> FilesResponse:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.list_files(
            project,
            location,
            repository,
            page_size=pageSize,
            page_token=pageToken,
            filter_=filter,
            order_by=orderBy,
        )
    except Exception as exc:
        raise _map_gar_error(exc) from exc
    files = [GARFile(**f) for f in body.get("files", []) if isinstance(f, dict)]
    return FilesResponse(files=files, nextPageToken=body.get("nextPageToken"))
