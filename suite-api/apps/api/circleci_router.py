"""ALDECI CircleCI v2 API Router.

Direct pass-through to the CircleCI v2 REST API.

Endpoints (mounted at ``/api/v1/circleci``)
-------------------------------------------
GET    /                                                   — capability summary
GET    /api/v2/project/{project_slug:path}/pipeline        — list pipelines
POST   /api/v2/project/{project_slug:path}/pipeline        — trigger pipeline
GET    /api/v2/pipeline/{pipeline_id}                      — pipeline detail
GET    /api/v2/pipeline/{pipeline_id}/workflow             — list workflows
GET    /api/v2/workflow/{workflow_id}                      — workflow detail
POST   /api/v2/workflow/{workflow_id}/cancel               — cancel workflow
POST   /api/v2/workflow/{workflow_id}/rerun                — rerun workflow
GET    /api/v2/workflow/{workflow_id}/job                  — list workflow jobs
GET    /api/v2/project/{project_slug:path}/insights/workflows/{workflow_name} — workflow insights

When ``CIRCLECI_TOKEN`` is unset the capability summary reports
``status="unavailable"`` and lookup endpoints respond with HTTP 503.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/circleci",
    tags=["circleci"],
)


# ---------------------------------------------------------------------------
# Lazy engine accessor (test seam)
# ---------------------------------------------------------------------------


def _get_engine():
    from core.circleci_engine import get_circleci_engine
    return get_circleci_engine()


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class CapabilitySummary(BaseModel):
    service: str
    endpoints: List[str]
    token_present: bool
    status: str = Field(..., description="ok | empty | unavailable")


class TriggerActor(BaseModel):
    model_config = ConfigDict(extra="allow")
    login: Optional[str] = None
    avatar_url: Optional[str] = None


class PipelineTrigger(BaseModel):
    model_config = ConfigDict(extra="allow")
    type: Optional[str] = Field(
        None, description="webhook | api | schedule"
    )
    received_at: Optional[str] = None
    actor: Optional[TriggerActor] = None


class CommitInfo(BaseModel):
    model_config = ConfigDict(extra="allow")
    subject: Optional[str] = None
    body: Optional[str] = None


class PipelineVCS(BaseModel):
    model_config = ConfigDict(extra="allow")
    provider_name: Optional[str] = None
    target_repository_url: Optional[str] = None
    branch: Optional[str] = None
    review_id: Optional[str] = None
    review_url: Optional[str] = None
    revision: Optional[str] = None
    tag: Optional[str] = None
    commit: Optional[CommitInfo] = None
    origin_repository_url: Optional[str] = None


class Pipeline(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: Optional[str] = None
    errors: List[Dict[str, Any]] = []
    project_slug: Optional[str] = None
    updated_at: Optional[str] = None
    number: Optional[int] = None
    state: Optional[str] = Field(
        None,
        description="created | errored | setup-pending | setup | pending",
    )
    created_at: Optional[str] = None
    trigger: Optional[PipelineTrigger] = None
    vcs: Optional[PipelineVCS] = None


class PipelineList(BaseModel):
    items: List[Pipeline] = []
    next_page_token: Optional[str] = None


class PipelineCreated(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: Optional[str] = None
    state: Optional[str] = None
    number: Optional[int] = None
    created_at: Optional[str] = None


class TriggerPipelineRequest(BaseModel):
    branch: Optional[str] = None
    tag: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None


class Workflow(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: Optional[str] = None
    name: Optional[str] = None
    project_slug: Optional[str] = None
    status: Optional[str] = Field(
        None,
        description=(
            "success | running | not_run | failed | error | failing | "
            "on_hold | canceled | unauthorized"
        ),
    )
    started_by: Optional[str] = None
    pipeline_id: Optional[str] = None
    pipeline_number: Optional[int] = None
    tag: Optional[str] = None
    created_at: Optional[str] = None
    stopped_at: Optional[str] = None


class WorkflowList(BaseModel):
    items: List[Workflow] = []
    next_page_token: Optional[str] = None


class CancelWorkflowResponse(BaseModel):
    model_config = ConfigDict(extra="allow")
    message: Optional[str] = None


class RerunWorkflowRequest(BaseModel):
    jobs: Optional[List[str]] = None
    from_failed: Optional[bool] = None
    sparse_tree: Optional[bool] = None
    enable_ssh: Optional[bool] = None


class RerunWorkflowResponse(BaseModel):
    model_config = ConfigDict(extra="allow")
    workflow_id: Optional[str] = None
    message: Optional[str] = None


class WorkflowJob(BaseModel):
    model_config = ConfigDict(extra="allow")
    canceled_by: Optional[str] = None
    dependencies: List[str] = []
    job_number: Optional[int] = None
    id: Optional[str] = None
    started_at: Optional[str] = None
    name: Optional[str] = None
    project_slug: Optional[str] = None
    status: Optional[str] = Field(
        None, description="queued | running | success | failed | canceled"
    )
    type: Optional[str] = Field(None, description="build | approval")
    stopped_at: Optional[str] = None
    approval_request_id: Optional[str] = None
    approved_by: Optional[str] = None


class WorkflowJobList(BaseModel):
    items: List[WorkflowJob] = []
    next_page_token: Optional[str] = None


class DurationMetrics(BaseModel):
    model_config = ConfigDict(extra="allow")


class WorkflowMetrics(BaseModel):
    model_config = ConfigDict(extra="allow")
    success_rate: Optional[float] = None
    total_runs: Optional[int] = None
    successful_runs: Optional[int] = None
    mttr: Optional[float] = None
    total_credits_used: Optional[int] = None
    failed_runs: Optional[int] = None
    median_credits_used: Optional[int] = None
    throughput: Optional[float] = None
    total_recoveries: Optional[int] = None
    duration_metrics: Optional[Dict[str, Any]] = None


class WorkflowTrends(BaseModel):
    model_config = ConfigDict(extra="allow")
    total_runs: Optional[float] = None
    success_rate: Optional[float] = None
    total_credits_used: Optional[float] = None
    failed_runs: Optional[float] = None
    mttr: Optional[float] = None
    throughput: Optional[float] = None
    total_recoveries: Optional[float] = None


class WorkflowInsightsItem(BaseModel):
    model_config = ConfigDict(extra="allow")
    name: Optional[str] = None
    window_start: Optional[str] = None
    window_end: Optional[str] = None
    metrics: Optional[WorkflowMetrics] = None
    trends: Optional[WorkflowTrends] = None


class WorkflowInsights(BaseModel):
    items: List[WorkflowInsightsItem] = []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _raise_unavailable() -> None:
    raise HTTPException(
        status_code=503,
        detail={
            "error": "circleci_unavailable",
            "message": "CIRCLECI_TOKEN environment variable is not configured",
        },
    )


def _map_circleci_error(exc: Exception) -> HTTPException:
    """Translate a CircleCIHTTPError (or unavailable) into an HTTPException."""
    from core.circleci_engine import CircleCIHTTPError, CircleCIUnavailable

    if isinstance(exc, CircleCIUnavailable):
        return HTTPException(
            status_code=503,
            detail={"error": "circleci_unavailable", "message": str(exc)},
        )
    if isinstance(exc, CircleCIHTTPError):
        passthrough = {400, 401, 403, 404, 409, 422, 429}
        status = exc.status_code if exc.status_code in passthrough else 502
        return HTTPException(
            status_code=status,
            detail={
                "error": "circleci_upstream_error",
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
    summary="CircleCI capability summary",
)
def capability_summary() -> CapabilitySummary:
    """Return service identity, exposed endpoints, and configuration status."""
    engine = _get_engine()
    return CapabilitySummary(**engine.capability_summary())


@router.get(
    "/api/v2/project/{project_slug:path}/pipeline",
    response_model=PipelineList,
    summary="List pipelines for a project",
)
def list_pipelines(
    project_slug: str,
    branch: Optional[str] = Query(None, description="Filter by branch"),
    page_token: Optional[str] = Query(
        None, alias="page-token", description="Pagination token"
    ),
) -> PipelineList:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.list_pipelines(
            project_slug, branch=branch, page_token=page_token
        )
    except Exception as exc:
        raise _map_circleci_error(exc) from exc
    return PipelineList(
        items=[Pipeline(**p) for p in body.get("items", []) if isinstance(p, dict)],
        next_page_token=body.get("next_page_token"),
    )


@router.post(
    "/api/v2/project/{project_slug:path}/pipeline",
    response_model=PipelineCreated,
    status_code=201,
    summary="Trigger a new pipeline",
)
def trigger_pipeline(
    project_slug: str,
    payload: TriggerPipelineRequest = Body(default_factory=TriggerPipelineRequest),
) -> PipelineCreated:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.trigger_pipeline(
            project_slug,
            branch=payload.branch,
            tag=payload.tag,
            parameters=payload.parameters,
        )
    except Exception as exc:
        raise _map_circleci_error(exc) from exc
    return PipelineCreated(**body)


@router.get(
    "/api/v2/pipeline/{pipeline_id}",
    response_model=Pipeline,
    summary="Get a single pipeline by ID",
)
def get_pipeline(pipeline_id: str) -> Pipeline:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.get_pipeline(pipeline_id)
    except Exception as exc:
        raise _map_circleci_error(exc) from exc
    return Pipeline(**body)


@router.get(
    "/api/v2/pipeline/{pipeline_id}/workflow",
    response_model=WorkflowList,
    summary="List workflows for a pipeline",
)
def list_pipeline_workflows(pipeline_id: str) -> WorkflowList:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.list_workflows(pipeline_id)
    except Exception as exc:
        raise _map_circleci_error(exc) from exc
    return WorkflowList(
        items=[Workflow(**w) for w in body.get("items", []) if isinstance(w, dict)],
        next_page_token=body.get("next_page_token"),
    )


@router.get(
    "/api/v2/workflow/{workflow_id}",
    response_model=Workflow,
    summary="Get a single workflow by ID",
)
def get_workflow(workflow_id: str) -> Workflow:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.get_workflow(workflow_id)
    except Exception as exc:
        raise _map_circleci_error(exc) from exc
    return Workflow(**body)


@router.post(
    "/api/v2/workflow/{workflow_id}/cancel",
    response_model=CancelWorkflowResponse,
    summary="Cancel a running workflow",
)
def cancel_workflow(workflow_id: str) -> CancelWorkflowResponse:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.cancel_workflow(workflow_id)
    except Exception as exc:
        raise _map_circleci_error(exc) from exc
    return CancelWorkflowResponse(**body)


@router.post(
    "/api/v2/workflow/{workflow_id}/rerun",
    response_model=RerunWorkflowResponse,
    summary="Rerun a workflow",
)
def rerun_workflow(
    workflow_id: str,
    payload: RerunWorkflowRequest = Body(default_factory=RerunWorkflowRequest),
) -> RerunWorkflowResponse:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.rerun_workflow(
            workflow_id,
            jobs=payload.jobs,
            from_failed=payload.from_failed,
            sparse_tree=payload.sparse_tree,
            enable_ssh=payload.enable_ssh,
        )
    except Exception as exc:
        raise _map_circleci_error(exc) from exc
    return RerunWorkflowResponse(**body)


@router.get(
    "/api/v2/workflow/{workflow_id}/job",
    response_model=WorkflowJobList,
    summary="List jobs for a workflow",
)
def list_workflow_jobs(workflow_id: str) -> WorkflowJobList:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.list_workflow_jobs(workflow_id)
    except Exception as exc:
        raise _map_circleci_error(exc) from exc
    return WorkflowJobList(
        items=[WorkflowJob(**j) for j in body.get("items", []) if isinstance(j, dict)],
        next_page_token=body.get("next_page_token"),
    )


@router.get(
    "/api/v2/project/{project_slug:path}/insights/workflows/{workflow_name}",
    response_model=WorkflowInsights,
    summary="Workflow insights / metrics",
)
def workflow_insights(
    project_slug: str,
    workflow_name: str,
    branch: Optional[str] = Query(None, description="Branch filter"),
    start_date: Optional[str] = Query(
        None, alias="start-date", description="ISO 8601 start date"
    ),
    end_date: Optional[str] = Query(
        None, alias="end-date", description="ISO 8601 end date"
    ),
) -> WorkflowInsights:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.insights_workflows(
            project_slug,
            workflow_name,
            branch=branch,
            start_date=start_date,
            end_date=end_date,
        )
    except Exception as exc:
        raise _map_circleci_error(exc) from exc
    return WorkflowInsights(
        items=[
            WorkflowInsightsItem(**i)
            for i in body.get("items", [])
            if isinstance(i, dict)
        ]
    )
