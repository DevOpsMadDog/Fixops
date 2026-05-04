"""LangSmith LLM Observability Router — ALDECI.

Wraps `core.langsmith_engine` under prefix ``/api/v1/langsmith``.

  - GET  /                                          capability summary
  - GET  /api/v1/runs                               list runs (filterable)
  - GET  /api/v1/runs/{run_id}                      single run detail
  - GET  /api/v1/datasets                           list datasets
  - GET  /api/v1/datasets/{dataset_id}              single dataset detail
  - POST /api/v1/datasets/{dataset_id}/examples     bulk create examples
  - GET  /api/v1/datasets/{dataset_id}/examples     list dataset examples
  - POST /api/v1/feedback                           attach feedback to a run
  - GET  /api/v1/sessions                           list sessions / projects

NO MOCKS rule
-------------
* When LANGSMITH_API_KEY is unset:
    - Capability summary surfaces ``status="unavailable"``.
    - All other endpoints return HTTP 503.
* No fabricated payloads — everything we return came from the LangSmith API.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/langsmith",
    tags=["LangSmith"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Engine accessor (lazy import so tests can patch the singleton)
# ---------------------------------------------------------------------------


def _engine():
    from core.langsmith_engine import get_langsmith_engine

    return get_langsmith_engine()


def _serve(callable_):
    """Run a LangSmith call, translating engine errors to HTTP responses.

    LangSmithUnavailableError -> 503 (key missing, network, upstream error)
    ValueError                -> 422 (input validation)
    """
    from core.langsmith_engine import LangSmithUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except LangSmithUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    langsmith_api_key_present: bool
    langsmith_endpoint: str
    status: str  # ok | empty | unavailable


class RunRow(BaseModel):
    id: str = ""
    name: str = ""
    run_type: str = ""
    start_time: str = ""
    end_time: str = ""
    extra: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[Any] = None
    serialized: Dict[str, Any] = Field(default_factory=dict)
    events: List[Dict[str, Any]] = Field(default_factory=list)
    inputs: Dict[str, Any] = Field(default_factory=dict)
    outputs: Dict[str, Any] = Field(default_factory=dict)
    reference_example_id: Optional[str] = None
    parent_run_id: Optional[str] = None
    child_run_ids: List[str] = Field(default_factory=list)
    session_id: str = ""
    total_tokens: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_cost: float = 0.0
    prompt_cost: float = 0.0
    completion_cost: float = 0.0
    child_runs: List[Dict[str, Any]] = Field(default_factory=list)
    feedback_stats: Dict[str, Any] = Field(default_factory=dict)
    app_path: str = ""
    status: str = ""
    completed_at: str = ""
    latency: float = 0.0
    manifest_id: Optional[str] = None
    manifest_s3_id: Optional[str] = None
    attachments: List[Any] = Field(default_factory=list)
    execution_order: int = 0
    in_dataset: bool = False
    parent_run_ids: List[str] = Field(default_factory=list)
    trace_id: str = ""
    dotted_order: str = ""


class RunsListResponse(BaseModel):
    runs: List[RunRow] = Field(default_factory=list)
    cursor: str = ""


class DatasetRow(BaseModel):
    id: str = ""
    name: str = ""
    description: str = ""
    created_at: str = ""
    modified_at: str = ""
    data_type: str = ""
    example_count: int = 0
    session_count: int = 0
    last_session_start_time: str = ""
    inputs_schema_definition: Optional[Any] = None
    outputs_schema_definition: Optional[Any] = None
    externally_managed: bool = False
    transformations: List[Any] = Field(default_factory=list)
    tenant_id: str = ""


class ExampleRow(BaseModel):
    id: str = ""
    dataset_id: str = ""
    inputs: Dict[str, Any] = Field(default_factory=dict)
    outputs: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    source_run_id: Optional[str] = None
    created_at: str = ""
    modified_at: str = ""


class CreateExampleItem(BaseModel):
    inputs: Dict[str, Any]
    outputs: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None
    source_run_id: Optional[str] = None
    dataset_id: Optional[str] = None  # may be passed in body, will be overridden


class CreateExamplesResponse(BaseModel):
    created_at: str = ""
    modified_at: str = ""
    dataset_id: str
    ids: List[str] = Field(default_factory=list)


class FeedbackSource(BaseModel):
    type: str = "api"  # api | app | model
    metadata: Optional[Dict[str, Any]] = None


class FeedbackRequest(BaseModel):
    run_id: str = Field(..., description="UUID of the run this feedback belongs to")
    key: str = Field(..., description="Feedback key (e.g. 'helpfulness', 'correctness')")
    score: Optional[float] = None
    value: Optional[Any] = None
    comment: Optional[str] = None
    correction: Optional[Any] = None
    feedback_source: Optional[FeedbackSource] = None
    source_run_id: Optional[str] = None
    target_run_id: Optional[str] = None


class FeedbackResponse(BaseModel):
    id: str = ""
    created_at: str = ""
    modified_at: str = ""
    run_id: str = ""
    key: str = ""
    score: Optional[float] = None
    value: Optional[Any] = None
    comment: Optional[str] = None
    correction: Optional[Any] = None
    feedback_source: Optional[Dict[str, Any]] = None
    session_id: str = ""
    comparative_experiment_id: Optional[str] = None
    feedback_group_id: Optional[str] = None
    comparative_experiment_run_id: Optional[str] = None
    extra: Dict[str, Any] = Field(default_factory=dict)
    trace_id: str = ""


class SessionRow(BaseModel):
    id: str = ""
    name: str = ""
    description: str = ""
    start_time: str = ""
    end_time: str = ""
    extra: Dict[str, Any] = Field(default_factory=dict)
    tenant_id: str = ""
    reference_dataset_id: Optional[str] = None
    run_count: int = 0
    latency_p50: float = 0.0
    latency_p99: float = 0.0
    total_tokens: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_cost: float = 0.0
    prompt_cost: float = 0.0
    completion_cost: float = 0.0
    error_rate: float = 0.0
    feedback_stats: Dict[str, Any] = Field(default_factory=dict)


class SessionsListResponse(BaseModel):
    sessions: List[SessionRow] = Field(default_factory=list)
    cursor: str = ""


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/", response_model=CapabilityResponse, summary="LangSmith capability summary"
)
async def capability_summary() -> CapabilityResponse:
    """Return the service summary — safe to call without an API key."""
    eng = _engine()
    api_key_present = eng.api_key_present()
    endpoint_url = eng.endpoint()
    if not api_key_present:
        status = "unavailable"
    else:
        # We don't keep a local cache to inspect, so:
        #   - key present → "ok" (live API path is reachable)
        #   - key missing → "unavailable"
        status = "ok"
    return CapabilityResponse(
        service="LangSmith",
        endpoints=[
            "/api/v1/runs",
            "/api/v1/datasets",
            "/api/v1/datasets/{id}/examples",
            "/api/v1/feedback",
            "/api/v1/sessions",
        ],
        langsmith_api_key_present=api_key_present,
        langsmith_endpoint=endpoint_url,
        status=status,
    )


@router.get("/api/v1/runs", response_model=RunsListResponse)
async def list_runs_endpoint(
    session_id: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    run_type: Optional[str] = Query(
        None, description="llm|chain|tool|retriever|embedding|prompt|parser"
    ),
    error: Optional[bool] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    cursor: Optional[str] = Query(None),
) -> RunsListResponse:
    eng = _engine()
    data = _serve(
        lambda: eng.list_runs(
            session_id=session_id,
            start_time=start_time,
            end_time=end_time,
            run_type=run_type,
            error=error,
            limit=limit,
            cursor=cursor,
        )
    )
    return RunsListResponse(**data)


@router.get("/api/v1/runs/{run_id}", response_model=RunRow)
async def get_run_endpoint(
    run_id: str = Path(..., description="UUID of the run to retrieve"),
) -> RunRow:
    eng = _engine()
    data = _serve(lambda: eng.get_run(run_id))
    return RunRow(**data)


@router.get("/api/v1/datasets", response_model=List[DatasetRow])
async def list_datasets_endpoint(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    data_type: Optional[str] = Query(None, description="kv|llm|chat"),
    dataset_name: Optional[str] = Query(None),
) -> List[DatasetRow]:
    eng = _engine()
    rows = _serve(
        lambda: eng.list_datasets(
            limit=limit,
            offset=offset,
            data_type=data_type,
            dataset_name=dataset_name,
        )
    )
    return [DatasetRow(**r) for r in rows]


@router.get("/api/v1/datasets/{dataset_id}", response_model=DatasetRow)
async def get_dataset_endpoint(
    dataset_id: str = Path(..., description="UUID of the dataset to retrieve"),
) -> DatasetRow:
    eng = _engine()
    data = _serve(lambda: eng.get_dataset(dataset_id))
    return DatasetRow(**data)


@router.post(
    "/api/v1/datasets/{dataset_id}/examples",
    response_model=CreateExamplesResponse,
)
async def create_examples_endpoint(
    dataset_id: str = Path(..., description="UUID of the dataset"),
    body: List[CreateExampleItem] = Body(...),
) -> CreateExamplesResponse:
    eng = _engine()
    examples_payload = [item.model_dump(exclude_none=False) for item in body]
    data = _serve(lambda: eng.create_examples(dataset_id, examples_payload))
    return CreateExamplesResponse(**data)


@router.get(
    "/api/v1/datasets/{dataset_id}/examples",
    response_model=List[ExampleRow],
)
async def list_examples_endpoint(
    dataset_id: str = Path(..., description="UUID of the dataset"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> List[ExampleRow]:
    eng = _engine()
    rows = _serve(
        lambda: eng.list_examples(dataset_id, limit=limit, offset=offset)
    )
    return [ExampleRow(**r) for r in rows]


@router.post("/api/v1/feedback", response_model=FeedbackResponse)
async def create_feedback_endpoint(
    body: FeedbackRequest = Body(...),
) -> FeedbackResponse:
    eng = _engine()
    fb_source = body.feedback_source.model_dump() if body.feedback_source else None
    data = _serve(
        lambda: eng.create_feedback(
            run_id=body.run_id,
            key=body.key,
            score=body.score,
            value=body.value,
            comment=body.comment,
            correction=body.correction,
            feedback_source=fb_source,
            source_run_id=body.source_run_id,
            target_run_id=body.target_run_id,
        )
    )
    return FeedbackResponse(**data)


@router.get("/api/v1/sessions", response_model=SessionsListResponse)
async def list_sessions_endpoint(
    reference_dataset: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    cursor: Optional[str] = Query(None),
) -> SessionsListResponse:
    eng = _engine()
    data = _serve(
        lambda: eng.list_sessions(
            reference_dataset=reference_dataset,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
            cursor=cursor,
        )
    )
    return SessionsListResponse(**data)


__all__ = ["router"]
