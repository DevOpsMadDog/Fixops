"""ALDECI GitLab CI/CD API Router.

Direct pass-through to the GitLab v4 REST API for CI/CD operations
(projects, pipelines, jobs). Distinct from the legacy GitLab repo
*connector* — this is the CI/CD pass-through facade, mounted under
``/api/v1/gitlab-pipeline`` to avoid prefix collision.

Endpoints (mounted at ``/api/v1/gitlab-pipeline``)
--------------------------------------------------
GET    /                                                          — capability summary
GET    /api/v4/projects                                           — list projects (membership/per_page/page/search/order_by/sort)
GET    /api/v4/projects/{id}/pipelines                            — list pipelines (status/ref/per_page/page/order_by/sort)
GET    /api/v4/projects/{id}/pipelines/{pipeline_id}              — single pipeline
POST   /api/v4/projects/{id}/pipeline                             — trigger pipeline (body: ref + variables[])
POST   /api/v4/projects/{id}/pipelines/{pipeline_id}/cancel       — cancel pipeline
POST   /api/v4/projects/{id}/pipelines/{pipeline_id}/retry        — retry pipeline
DELETE /api/v4/projects/{id}/pipelines/{pipeline_id}              — delete pipeline (204)
GET    /api/v4/projects/{id}/jobs                                 — list jobs (scope filter)
GET    /api/v4/projects/{id}/pipelines/{pipeline_id}/jobs         — list pipeline jobs
GET    /api/v4/projects/{id}/jobs/{job_id}                        — single job
POST   /api/v4/projects/{id}/jobs/{job_id}/retry                  — retry job
POST   /api/v4/projects/{id}/jobs/{job_id}/cancel                 — cancel job

When ``GITLAB_TOKEN`` is unset the capability summary reports
``status="unavailable"`` and lookup endpoints respond with HTTP 503.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Body, HTTPException, Query, Response
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/gitlab-pipeline",
    tags=["gitlab-pipeline"],
)


# ---------------------------------------------------------------------------
# Lazy engine accessor (test seam)
# ---------------------------------------------------------------------------


def _get_engine():
    from core.gitlab_pipeline_engine import get_gitlab_pipeline_engine
    return get_gitlab_pipeline_engine()


# ---------------------------------------------------------------------------
# Pydantic models (kept permissive — GitLab payloads vary by version/edition)
# ---------------------------------------------------------------------------


class CapabilitySummary(BaseModel):
    service: str
    endpoints: List[str]
    gitlab_url_present: bool
    gitlab_token_present: bool
    status: str = Field(..., description="ok | empty | unavailable")


class NamespaceRef(BaseModel):
    id: Optional[int] = None
    name: Optional[str] = None
    path: Optional[str] = None
    kind: Optional[str] = None
    full_path: Optional[str] = None


class ProjectSummary(BaseModel):
    id: Optional[int] = None
    description: Optional[str] = None
    default_branch: Optional[str] = None
    visibility: Optional[Literal["public", "internal", "private"]] = None
    ssh_url_to_repo: Optional[str] = None
    http_url_to_repo: Optional[str] = None
    web_url: Optional[str] = None
    name: Optional[str] = None
    name_with_namespace: Optional[str] = None
    path: Optional[str] = None
    path_with_namespace: Optional[str] = None
    created_at: Optional[str] = None
    last_activity_at: Optional[str] = None
    namespace: Optional[NamespaceRef] = None
    archived: Optional[bool] = None
    forks_count: Optional[int] = None
    star_count: Optional[int] = None
    open_issues_count: Optional[int] = None
    default_protected_branch: Optional[str] = None

    model_config = {"extra": "allow"}


class PipelineSummary(BaseModel):
    id: Optional[int] = None
    project_id: Optional[int] = None
    sha: Optional[str] = None
    ref: Optional[str] = None
    status: Optional[str] = None
    source: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    web_url: Optional[str] = None

    model_config = {"extra": "allow"}


class PipelineUser(BaseModel):
    id: Optional[int] = None
    name: Optional[str] = None
    username: Optional[str] = None
    state: Optional[str] = None
    avatar_url: Optional[str] = None
    web_url: Optional[str] = None


class DetailedStatus(BaseModel):
    icon: Optional[str] = None
    text: Optional[str] = None
    label: Optional[str] = None
    group: Optional[str] = None
    tooltip: Optional[str] = None
    has_details: Optional[bool] = None
    details_path: Optional[str] = None
    illustration: Optional[Any] = None
    favicon: Optional[str] = None

    model_config = {"extra": "allow"}


class PipelineDetail(PipelineSummary):
    before_sha: Optional[str] = None
    tag: Optional[bool] = None
    yaml_errors: Optional[str] = None
    user: Optional[PipelineUser] = None
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    committed_at: Optional[str] = None
    duration: Optional[float] = None
    queued_duration: Optional[float] = None
    coverage: Optional[Any] = None
    detailed_status: Optional[DetailedStatus] = None


class PipelineVariable(BaseModel):
    key: str
    value: str
    variable_type: Optional[Literal["env_var", "file"]] = "env_var"


class CreatePipelineRequest(BaseModel):
    ref: str = Field(..., description="Branch/tag the pipeline runs against")
    variables: Optional[List[PipelineVariable]] = None


class JobSummary(BaseModel):
    id: Optional[int] = None
    status: Optional[str] = None
    stage: Optional[str] = None
    name: Optional[str] = None
    ref: Optional[str] = None
    tag: Optional[bool] = None
    coverage: Optional[Any] = None
    allow_failure: Optional[bool] = None
    created_at: Optional[str] = None
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    duration: Optional[float] = None
    queued_duration: Optional[float] = None
    user: Optional[Dict[str, Any]] = None
    commit: Optional[Dict[str, Any]] = None
    pipeline: Optional[Dict[str, Any]] = None
    web_url: Optional[str] = None
    project: Optional[Dict[str, Any]] = None
    artifacts: Optional[List[Dict[str, Any]]] = None
    runner: Optional[Dict[str, Any]] = None
    artifacts_expire_at: Optional[str] = None
    archived: Optional[bool] = None

    model_config = {"extra": "allow"}


# Pipeline status / source / job-scope literals — used as Query type-hints
PIPELINE_STATUS = Literal[
    "created",
    "waiting_for_resource",
    "preparing",
    "pending",
    "running",
    "success",
    "failed",
    "canceled",
    "skipped",
    "manual",
    "scheduled",
]


JOB_SCOPE = Literal[
    "created",
    "pending",
    "running",
    "failed",
    "success",
    "canceled",
    "skipped",
    "manual",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _raise_unavailable() -> None:
    raise HTTPException(
        status_code=503,
        detail={
            "error": "gitlab_pipeline_unavailable",
            "message": "GITLAB_TOKEN environment variable is not configured",
        },
    )


def _map_gitlab_error(exc: Exception) -> HTTPException:
    """Translate a GitLabPipeline error into an HTTPException."""
    from core.gitlab_pipeline_engine import (
        GitLabPipelineHTTPError,
        GitLabPipelineUnavailable,
    )

    if isinstance(exc, GitLabPipelineUnavailable):
        return HTTPException(
            status_code=503,
            detail={"error": "gitlab_pipeline_unavailable", "message": str(exc)},
        )
    if isinstance(exc, GitLabPipelineHTTPError):
        passthrough = {400, 401, 403, 404, 409, 422, 429}
        status = exc.status_code if exc.status_code in passthrough else 502
        return HTTPException(
            status_code=status,
            detail={
                "error": "gitlab_upstream_error",
                "upstream_status": exc.status_code,
                "message": str(exc),
                "payload": exc.payload,
            },
        )
    return HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=CapabilitySummary,
    summary="GitLab CI/CD capability summary",
)
def capability_summary() -> CapabilitySummary:
    engine = _get_engine()
    return CapabilitySummary(**engine.capability_summary())


# ---------------------------------------------------------------------------
# Projects
# ---------------------------------------------------------------------------


@router.get(
    "/api/v4/projects",
    response_model=List[ProjectSummary],
    summary="List projects (filtered by membership / search / sort)",
)
def list_projects(
    membership: bool = Query(True, description="Only projects the token user is a member of"),
    per_page: int = Query(20, ge=1, le=100),
    page: int = Query(1, ge=1),
    search: Optional[str] = Query(None),
    order_by: Optional[str] = Query(None, description="id|name|path|created_at|updated_at|last_activity_at"),
    sort: Optional[Literal["asc", "desc"]] = Query(None),
) -> List[ProjectSummary]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.list_projects(
            membership=membership,
            per_page=per_page,
            page=page,
            search=search,
            order_by=order_by,
            sort=sort,
        )
    except Exception as exc:
        raise _map_gitlab_error(exc) from exc
    return [ProjectSummary(**p) for p in body if isinstance(p, dict)]


# ---------------------------------------------------------------------------
# Pipelines
# ---------------------------------------------------------------------------


@router.get(
    "/api/v4/projects/{project_id}/pipelines",
    response_model=List[PipelineSummary],
    summary="List pipelines for a project",
)
def list_pipelines(
    project_id: str,
    per_page: int = Query(20, ge=1, le=100),
    page: int = Query(1, ge=1),
    status: Optional[PIPELINE_STATUS] = Query(None),
    ref: Optional[str] = Query(None),
    order_by: Optional[str] = Query(None, description="id|status|ref|updated_at|user_id"),
    sort: Optional[Literal["asc", "desc"]] = Query(None),
) -> List[PipelineSummary]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.list_pipelines(
            project_id,
            per_page=per_page,
            page=page,
            status=status,
            ref=ref,
            order_by=order_by,
            sort=sort,
        )
    except Exception as exc:
        raise _map_gitlab_error(exc) from exc
    return [PipelineSummary(**p) for p in body if isinstance(p, dict)]


@router.get(
    "/api/v4/projects/{project_id}/pipelines/{pipeline_id}",
    response_model=PipelineDetail,
    summary="Get a single pipeline",
)
def get_pipeline(project_id: str, pipeline_id: int) -> PipelineDetail:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.get_pipeline(project_id, pipeline_id)
    except Exception as exc:
        raise _map_gitlab_error(exc) from exc
    return PipelineDetail(**body)


@router.post(
    "/api/v4/projects/{project_id}/pipeline",
    response_model=PipelineDetail,
    status_code=201,
    summary="Create (trigger) a pipeline on a ref",
)
def create_pipeline(
    project_id: str,
    payload: CreatePipelineRequest = Body(...),
) -> PipelineDetail:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.create_pipeline(
            project_id,
            ref=payload.ref,
            variables=(
                [v.model_dump(exclude_none=True) for v in payload.variables]
                if payload.variables
                else None
            ),
        )
    except Exception as exc:
        raise _map_gitlab_error(exc) from exc
    return PipelineDetail(**body)


@router.post(
    "/api/v4/projects/{project_id}/pipelines/{pipeline_id}/cancel",
    response_model=PipelineDetail,
    summary="Cancel a pipeline",
)
def cancel_pipeline(project_id: str, pipeline_id: int) -> PipelineDetail:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.cancel_pipeline(project_id, pipeline_id)
    except Exception as exc:
        raise _map_gitlab_error(exc) from exc
    return PipelineDetail(**body)


@router.post(
    "/api/v4/projects/{project_id}/pipelines/{pipeline_id}/retry",
    response_model=PipelineDetail,
    summary="Retry a pipeline",
)
def retry_pipeline(project_id: str, pipeline_id: int) -> PipelineDetail:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.retry_pipeline(project_id, pipeline_id)
    except Exception as exc:
        raise _map_gitlab_error(exc) from exc
    return PipelineDetail(**body)


@router.delete(
    "/api/v4/projects/{project_id}/pipelines/{pipeline_id}",
    status_code=204,
    summary="Delete a pipeline",
)
def delete_pipeline(project_id: str, pipeline_id: int) -> Response:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        engine.delete_pipeline(project_id, pipeline_id)
    except Exception as exc:
        raise _map_gitlab_error(exc) from exc
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------


@router.get(
    "/api/v4/projects/{project_id}/jobs",
    response_model=List[JobSummary],
    summary="List jobs across a project",
)
def list_jobs(
    project_id: str,
    per_page: int = Query(20, ge=1, le=100),
    page: int = Query(1, ge=1),
    scope: Optional[JOB_SCOPE] = Query(None),
) -> List[JobSummary]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.list_jobs(project_id, per_page=per_page, page=page, scope=scope)
    except Exception as exc:
        raise _map_gitlab_error(exc) from exc
    return [JobSummary(**j) for j in body if isinstance(j, dict)]


@router.get(
    "/api/v4/projects/{project_id}/pipelines/{pipeline_id}/jobs",
    response_model=List[JobSummary],
    summary="List jobs belonging to one pipeline",
)
def list_pipeline_jobs(
    project_id: str,
    pipeline_id: int,
    include_retried: bool = Query(False),
    per_page: int = Query(20, ge=1, le=100),
) -> List[JobSummary]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.list_pipeline_jobs(
            project_id,
            pipeline_id,
            include_retried=include_retried,
            per_page=per_page,
        )
    except Exception as exc:
        raise _map_gitlab_error(exc) from exc
    return [JobSummary(**j) for j in body if isinstance(j, dict)]


@router.get(
    "/api/v4/projects/{project_id}/jobs/{job_id}",
    response_model=JobSummary,
    summary="Get a single job",
)
def get_job(project_id: str, job_id: int) -> JobSummary:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.get_job(project_id, job_id)
    except Exception as exc:
        raise _map_gitlab_error(exc) from exc
    return JobSummary(**body)


@router.post(
    "/api/v4/projects/{project_id}/jobs/{job_id}/retry",
    response_model=JobSummary,
    summary="Retry a job",
)
def retry_job(project_id: str, job_id: int) -> JobSummary:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.retry_job(project_id, job_id)
    except Exception as exc:
        raise _map_gitlab_error(exc) from exc
    return JobSummary(**body)


@router.post(
    "/api/v4/projects/{project_id}/jobs/{job_id}/cancel",
    response_model=JobSummary,
    summary="Cancel a job",
)
def cancel_job(project_id: str, job_id: int) -> JobSummary:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.cancel_job(project_id, job_id)
    except Exception as exc:
        raise _map_gitlab_error(exc) from exc
    return JobSummary(**body)
