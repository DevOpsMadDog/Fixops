"""ALDECI Bitbucket Cloud API Router.

Direct pass-through to the Bitbucket Cloud REST API v2.0 for workspace,
repository, pipeline, pull request, and branch operations.

Endpoints (mounted at ``/api/v1/bitbucket``)
--------------------------------------------
GET  /                                                                      — capability summary
GET  /2.0/workspaces                                                        — list workspaces
GET  /2.0/workspaces/{workspace}/repositories                               — list repositories
GET  /2.0/repositories/{ws}/{repo}/pipelines                                — list pipelines
POST /2.0/repositories/{ws}/{repo}/pipelines                                — trigger pipeline (201)
POST /2.0/repositories/{ws}/{repo}/pipelines/{pipeline_uuid}/stopPipeline   — stop pipeline (204)
GET  /2.0/repositories/{ws}/{repo}/pipelines/{pipeline_uuid}/steps          — list pipeline steps
GET  /2.0/repositories/{ws}/{repo}/pullrequests                             — list pull requests
GET  /2.0/repositories/{ws}/{repo}/branches                                 — list branches
GET  /2.0/repositories/{ws}/{repo}/commit/{sha}/statuses                    — list commit build statuses

When ``BITBUCKET_USER`` / ``BITBUCKET_APP_PASSWORD`` are unset the capability
summary reports ``status="unavailable"`` and lookup endpoints respond with
HTTP 503.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Body, HTTPException, Query, Response
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/bitbucket",
    tags=["bitbucket"],
)


# ---------------------------------------------------------------------------
# Lazy engine accessor (test seam)
# ---------------------------------------------------------------------------


def _get_engine():
    from core.bitbucket_engine import get_bitbucket_engine
    return get_bitbucket_engine()


# ---------------------------------------------------------------------------
# Pydantic models (kept permissive — Bitbucket payloads vary)
# ---------------------------------------------------------------------------


class CapabilitySummary(BaseModel):
    service: str
    endpoints: List[str]
    bitbucket_user_present: bool
    bitbucket_app_password_present: bool
    status: str = Field(..., description="ok | empty | unavailable")


class PaginatedResponse(BaseModel):
    pagelen: Optional[int] = None
    page: Optional[int] = None
    size: Optional[int] = None
    values: Optional[List[Dict[str, Any]]] = None
    next: Optional[str] = None
    previous: Optional[str] = None

    model_config = {"extra": "allow"}


class PipelineCreateTarget(BaseModel):
    type: str = Field(..., description="pipeline_ref_target | pipeline_commit_target")
    ref_type: Optional[Literal["branch", "tag"]] = None
    ref_name: Optional[str] = None
    selector: Optional[Dict[str, Any]] = None
    commit: Optional[Dict[str, Any]] = None

    model_config = {"extra": "allow"}


class PipelineVariable(BaseModel):
    key: str
    value: str
    secured: Optional[bool] = False


class CreatePipelineRequest(BaseModel):
    target: PipelineCreateTarget
    variables: Optional[List[PipelineVariable]] = None


# Pipeline state literals
PIPELINE_STATE = Literal[
    "PENDING",
    "BUILDING",
    "IN_PROGRESS",
    "COMPLETED",
    "HALTED",
    "STOPPED",
]

PR_STATE = Literal["OPEN", "MERGED", "DECLINED", "SUPERSEDED"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _raise_unavailable() -> None:
    raise HTTPException(
        status_code=503,
        detail={
            "error": "bitbucket_unavailable",
            "message": "BITBUCKET_USER and BITBUCKET_APP_PASSWORD env vars are not configured",
        },
    )


def _map_bitbucket_error(exc: Exception) -> HTTPException:
    """Translate a Bitbucket error into an HTTPException."""
    from core.bitbucket_engine import (
        BitbucketHTTPError,
        BitbucketUnavailable,
    )

    if isinstance(exc, BitbucketUnavailable):
        return HTTPException(
            status_code=503,
            detail={"error": "bitbucket_unavailable", "message": str(exc)},
        )
    if isinstance(exc, BitbucketHTTPError):
        passthrough = {400, 401, 403, 404, 409, 422, 429}
        status = exc.status_code if exc.status_code in passthrough else 502
        return HTTPException(
            status_code=status,
            detail={
                "error": "bitbucket_upstream_error",
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
    summary="Bitbucket Cloud capability summary",
)
def capability_summary() -> CapabilitySummary:
    engine = _get_engine()
    return CapabilitySummary(**engine.capability_summary())


# ---------------------------------------------------------------------------
# Workspaces
# ---------------------------------------------------------------------------


@router.get(
    "/2.0/workspaces",
    response_model=PaginatedResponse,
    summary="List workspaces visible to the authenticated user",
)
def list_workspaces(
    pagelen: Optional[int] = Query(None, ge=1, le=100),
    page: Optional[int] = Query(None, ge=1),
) -> PaginatedResponse:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.list_workspaces(pagelen=pagelen, page=page)
    except Exception as exc:
        raise _map_bitbucket_error(exc) from exc
    return PaginatedResponse(**body)


# ---------------------------------------------------------------------------
# Repositories
# ---------------------------------------------------------------------------


@router.get(
    "/2.0/workspaces/{workspace}/repositories",
    response_model=PaginatedResponse,
    summary="List repositories within a workspace",
)
def list_repositories(
    workspace: str,
    role: Optional[Literal["admin", "contributor", "member", "owner"]] = Query(None),
    q: Optional[str] = Query(None, description="BBQL filter expression"),
    sort: Optional[str] = Query(None),
    pagelen: Optional[int] = Query(None, ge=1, le=100),
    page: Optional[int] = Query(None, ge=1),
) -> PaginatedResponse:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.list_repositories(
            workspace,
            role=role,
            q=q,
            sort=sort,
            pagelen=pagelen,
            page=page,
        )
    except Exception as exc:
        raise _map_bitbucket_error(exc) from exc
    return PaginatedResponse(**body)


# ---------------------------------------------------------------------------
# Pipelines
# ---------------------------------------------------------------------------


@router.get(
    "/2.0/repositories/{workspace}/{repo_slug}/pipelines",
    response_model=PaginatedResponse,
    summary="List pipelines for a repository",
)
def list_pipelines(
    workspace: str,
    repo_slug: str,
    sort: Optional[str] = Query(None),
    pagelen: Optional[int] = Query(None, ge=1, le=100),
    page: Optional[int] = Query(None, ge=1),
    q: Optional[str] = Query(None, description="BBQL filter expression"),
) -> PaginatedResponse:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.list_pipelines(
            workspace, repo_slug,
            sort=sort, pagelen=pagelen, page=page, q=q,
        )
    except Exception as exc:
        raise _map_bitbucket_error(exc) from exc
    return PaginatedResponse(**body)


@router.post(
    "/2.0/repositories/{workspace}/{repo_slug}/pipelines",
    status_code=201,
    summary="Trigger a pipeline run",
)
def trigger_pipeline(
    workspace: str,
    repo_slug: str,
    payload: CreatePipelineRequest = Body(...),
) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.trigger_pipeline(
            workspace, repo_slug,
            target=payload.target.model_dump(exclude_none=True),
            variables=(
                [v.model_dump(exclude_none=True) for v in payload.variables]
                if payload.variables
                else None
            ),
        )
    except Exception as exc:
        raise _map_bitbucket_error(exc) from exc
    return body


@router.post(
    "/2.0/repositories/{workspace}/{repo_slug}/pipelines/{pipeline_uuid}/stopPipeline",
    status_code=204,
    summary="Stop an in-progress pipeline",
)
def stop_pipeline(
    workspace: str,
    repo_slug: str,
    pipeline_uuid: str,
) -> Response:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        engine.stop_pipeline(workspace, repo_slug, pipeline_uuid)
    except Exception as exc:
        raise _map_bitbucket_error(exc) from exc
    return Response(status_code=204)


@router.get(
    "/2.0/repositories/{workspace}/{repo_slug}/pipelines/{pipeline_uuid}/steps",
    response_model=PaginatedResponse,
    summary="List steps for a pipeline run",
)
def list_pipeline_steps(
    workspace: str,
    repo_slug: str,
    pipeline_uuid: str,
) -> PaginatedResponse:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.list_pipeline_steps(workspace, repo_slug, pipeline_uuid)
    except Exception as exc:
        raise _map_bitbucket_error(exc) from exc
    return PaginatedResponse(**body)


# ---------------------------------------------------------------------------
# Pull requests
# ---------------------------------------------------------------------------


@router.get(
    "/2.0/repositories/{workspace}/{repo_slug}/pullrequests",
    response_model=PaginatedResponse,
    summary="List pull requests for a repository",
)
def list_pull_requests(
    workspace: str,
    repo_slug: str,
    state: Optional[PR_STATE] = Query(None),
    pagelen: Optional[int] = Query(None, ge=1, le=100),
    page: Optional[int] = Query(None, ge=1),
) -> PaginatedResponse:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.list_pull_requests(
            workspace, repo_slug,
            state=state, pagelen=pagelen, page=page,
        )
    except Exception as exc:
        raise _map_bitbucket_error(exc) from exc
    return PaginatedResponse(**body)


# ---------------------------------------------------------------------------
# Branches
# ---------------------------------------------------------------------------


@router.get(
    "/2.0/repositories/{workspace}/{repo_slug}/branches",
    response_model=PaginatedResponse,
    summary="List branches for a repository",
)
def list_branches(
    workspace: str,
    repo_slug: str,
    pagelen: Optional[int] = Query(None, ge=1, le=100),
) -> PaginatedResponse:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.list_branches(workspace, repo_slug, pagelen=pagelen)
    except Exception as exc:
        raise _map_bitbucket_error(exc) from exc
    return PaginatedResponse(**body)


# ---------------------------------------------------------------------------
# Commit build statuses
# ---------------------------------------------------------------------------


@router.get(
    "/2.0/repositories/{workspace}/{repo_slug}/commit/{commit_sha}/statuses",
    response_model=PaginatedResponse,
    summary="List build statuses attached to a commit",
)
def list_commit_statuses(
    workspace: str,
    repo_slug: str,
    commit_sha: str,
) -> PaginatedResponse:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.list_commit_statuses(workspace, repo_slug, commit_sha)
    except Exception as exc:
        raise _map_bitbucket_error(exc) from exc
    return PaginatedResponse(**body)
