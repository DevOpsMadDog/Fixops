"""ALDECI Jenkins CI API Router.

Direct pass-through to the Jenkins REST API — the JSON facade exposed at
``/api/json`` on every Jenkins object.

Endpoints (mounted at ``/api/v1/jenkins``)
------------------------------------------
GET    /                                   — capability summary
GET    /api/json                           — Jenkins root summary
GET    /job/{name}/api/json                — single job summary
GET    /job/{name}/{build_num}/api/json    — single build summary
GET    /queue/api/json                     — pending queue
GET    /computer/api/json                  — nodes / executors
POST   /job/{name}/build                   — trigger a build (201)

When ``JENKINS_URL`` / ``JENKINS_USER`` / ``JENKINS_TOKEN`` are unset the
capability summary reports ``status="unavailable"`` and lookup endpoints
respond with HTTP 503.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/jenkins",
    tags=["jenkins"],
)


# ---------------------------------------------------------------------------
# Lazy engine accessor (test seam)
# ---------------------------------------------------------------------------


def _get_engine():
    from core.jenkins_ci_engine import get_jenkins_ci_engine
    return get_jenkins_ci_engine()


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class CapabilitySummary(BaseModel):
    service: str
    endpoints: List[str]
    jenkins_url_present: bool
    jenkins_user_present: bool
    jenkins_token_present: bool
    status: str = Field(..., description="ok | empty | unavailable")


class JobRef(BaseModel):
    name: str
    url: str
    color: Optional[str] = None


class ViewRef(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None


class JenkinsRoot(BaseModel):
    jobs: List[JobRef] = []
    views: List[ViewRef] = []
    numExecutors: Optional[int] = None
    useSecurity: Optional[bool] = None
    mode: Optional[str] = None
    nodeName: Optional[str] = None
    nodeDescription: Optional[str] = None
    quietingDown: Optional[bool] = None
    slaveAgentPort: Optional[int] = None


class BuildRef(BaseModel):
    number: Optional[int] = None
    url: Optional[str] = None


class HealthReportItem(BaseModel):
    description: Optional[str] = None
    score: Optional[int] = None


class JobSummary(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    displayName: Optional[str] = None
    description: Optional[str] = None
    buildable: Optional[bool] = None
    color: Optional[str] = None
    lastBuild: Optional[BuildRef] = None
    lastSuccessfulBuild: Optional[BuildRef] = None
    lastFailedBuild: Optional[BuildRef] = None
    healthReport: List[HealthReportItem] = []


class BuildSummary(BaseModel):
    number: Optional[int] = None
    result: Optional[str] = Field(
        None, description="SUCCESS | FAILURE | ABORTED | UNSTABLE | null when building"
    )
    building: Optional[bool] = None
    duration: Optional[int] = None
    timestamp: Optional[int] = None
    url: Optional[str] = None
    actions: List[Dict[str, Any]] = []
    changeSet: Dict[str, Any] = Field(default_factory=lambda: {"items": []})


class QueueItem(BaseModel):
    id: Optional[int] = None
    task: Optional[Dict[str, Any]] = None
    inQueueSince: Optional[int] = None
    blocked: Optional[bool] = None
    why: Optional[str] = None
    params: Optional[str] = None


class QueueSummary(BaseModel):
    items: List[QueueItem] = []


class ComputerNode(BaseModel):
    displayName: Optional[str] = None
    idle: Optional[bool] = None
    jnlpAgent: Optional[bool] = None
    launchSupported: Optional[bool] = None
    manualLaunchAllowed: Optional[bool] = None
    monitorData: Optional[Dict[str, Any]] = None
    numExecutors: Optional[int] = None
    offline: Optional[bool] = None
    temporarilyOffline: Optional[bool] = None


class ComputerSummary(BaseModel):
    computer: List[ComputerNode] = []
    totalExecutors: Optional[int] = None
    busyExecutors: Optional[int] = None


class BuildTriggered(BaseModel):
    queued: bool
    location: Optional[str] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _raise_unavailable() -> None:
    raise HTTPException(
        status_code=503,
        detail={
            "error": "jenkins_ci_unavailable",
            "message": "JENKINS_URL, JENKINS_USER and JENKINS_TOKEN environment variables are not configured",
        },
    )


def _map_jenkins_error(exc: Exception) -> HTTPException:
    """Translate a JenkinsCIHTTPError (or unavailable) into an HTTPException."""
    from core.jenkins_ci_engine import JenkinsCIHTTPError, JenkinsCIUnavailable

    if isinstance(exc, JenkinsCIUnavailable):
        return HTTPException(
            status_code=503,
            detail={"error": "jenkins_ci_unavailable", "message": str(exc)},
        )
    if isinstance(exc, JenkinsCIHTTPError):
        passthrough = {400, 401, 403, 404, 409, 422, 429}
        status = exc.status_code if exc.status_code in passthrough else 502
        return HTTPException(
            status_code=status,
            detail={
                "error": "jenkins_upstream_error",
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
    summary="Jenkins CI capability summary",
)
def capability_summary() -> CapabilitySummary:
    """Return service identity, exposed endpoints, and configuration status."""
    engine = _get_engine()
    return CapabilitySummary(**engine.capability_summary())


@router.get(
    "/api/json",
    response_model=JenkinsRoot,
    summary="Jenkins root summary (jobs, views, executors)",
)
def jenkins_root() -> JenkinsRoot:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.root()
    except Exception as exc:
        raise _map_jenkins_error(exc) from exc
    scalars = {k: body.get(k) for k in JenkinsRoot.model_fields if k in body and k not in ("jobs", "views")}
    return JenkinsRoot(
        **scalars,
        jobs=[JobRef(**j) for j in body.get("jobs", []) if isinstance(j, dict)],
        views=[ViewRef(**v) for v in body.get("views", []) if isinstance(v, dict)],
    )


@router.get(
    "/job/{name}/api/json",
    response_model=JobSummary,
    summary="Single Jenkins job summary",
)
def get_job(name: str) -> JobSummary:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.get_job(name)
    except Exception as exc:
        raise _map_jenkins_error(exc) from exc
    return JobSummary(**body)


@router.get(
    "/job/{name}/{build_num}/api/json",
    response_model=BuildSummary,
    summary="Single Jenkins build summary",
)
def get_build(name: str, build_num: int) -> BuildSummary:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.get_build(name, build_num)
    except Exception as exc:
        raise _map_jenkins_error(exc) from exc
    return BuildSummary(**body)


@router.get(
    "/queue/api/json",
    response_model=QueueSummary,
    summary="Pending build queue",
)
def get_queue() -> QueueSummary:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.get_queue()
    except Exception as exc:
        raise _map_jenkins_error(exc) from exc
    return QueueSummary(**body)


@router.get(
    "/computer/api/json",
    response_model=ComputerSummary,
    summary="Node / executor summary",
)
def get_computer() -> ComputerSummary:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.get_computer()
    except Exception as exc:
        raise _map_jenkins_error(exc) from exc
    return ComputerSummary(**body)


@router.post(
    "/job/{name}/build",
    response_model=BuildTriggered,
    status_code=201,
    summary="Trigger a Jenkins build",
)
def trigger_build(
    name: str,
    token: Optional[str] = Query(None, description="Optional Jenkins remote build token"),
) -> BuildTriggered:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.trigger_build(name, token=token)
    except Exception as exc:
        raise _map_jenkins_error(exc) from exc
    return BuildTriggered(
        queued=bool(body.get("queued", True)),
        location=body.get("location"),
    )
