"""Braintrust LLM-Eval Router — ALDECI.

Wraps Braintrust REST API (https://api.braintrust.dev) under prefix
``/api/v1/braintrust``.

Surface
-------
* GET  /                                — capability summary
* GET  /v1/experiment                   — list experiments
* GET  /v1/experiment/{exp_id}          — fetch single experiment
* POST /v1/experiment                   — create experiment
* POST /v1/experiment/{exp_id}/insert   — append events
* GET  /v1/dataset                      — list datasets
* GET  /v1/dataset/{ds_id}              — fetch single dataset
* POST /v1/dataset/{ds_id}/insert       — append dataset rows
* GET  /v1/project                      — list projects
* GET  /v1/score                        — list scoring functions

NO MOCKS rule
-------------
* When BRAINTRUST_API_KEY is unset:
    - Capability summary surfaces ``status="unavailable"``.
    - All live endpoints → HTTP 503.
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
    prefix="/api/v1/braintrust",
    tags=["Braintrust"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Engine accessor (lazy import so tests can patch the singleton)
# ---------------------------------------------------------------------------


def _engine():
    from core.braintrust_engine import get_braintrust_engine

    return get_braintrust_engine()


def _serve(callable_):
    """Run a Braintrust call, translating engine errors to HTTP responses.

    BraintrustUnavailableError -> 503 (key missing, network, upstream error)
    ValueError                 -> 422 (input validation)
    """
    from core.braintrust_engine import BraintrustUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except BraintrustUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilitySummary(BaseModel):
    service: str
    endpoints: List[str]
    braintrust_api_key_present: bool
    status: str  # ok | empty | unavailable


class ListingResponse(BaseModel):
    objects: List[Dict[str, Any]]
    cursor: Optional[str] = None


class RowIdsResponse(BaseModel):
    row_ids: List[str]


class RepoInfo(BaseModel):
    commit: Optional[str] = None
    branch: Optional[str] = None
    tag: Optional[str] = None
    dirty: Optional[bool] = None
    author_name: Optional[str] = None
    author_email: Optional[str] = None
    commit_message: Optional[str] = None
    commit_time: Optional[str] = None
    git_diff: Optional[str] = None


class ExperimentCreateRequest(BaseModel):
    project_id: str = Field(..., description="Parent project UUID")
    name: str = Field(..., description="Experiment name")
    description: Optional[str] = None
    public: Optional[bool] = None
    base_exp_id: Optional[str] = None
    dataset_id: Optional[str] = None
    dataset_version: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    repo_info: Optional[RepoInfo] = None
    tags: Optional[List[str]] = None


class ExperimentEvent(BaseModel):
    id: Optional[str] = None
    dataset_record_id: Optional[str] = None
    input: Any
    output: Any
    expected: Optional[Any] = None
    scores: Optional[Dict[str, float]] = None
    metadata: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None
    metrics: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    span_attributes: Optional[Dict[str, Any]] = None
    root_span_id: Optional[str] = None
    span_id: Optional[str] = None
    parent_span_id: Optional[str] = None
    span_parents: Optional[List[str]] = None
    is_merge: Optional[bool] = Field(default=None, alias="_is_merge")
    object_delete: Optional[bool] = Field(default=None, alias="_object_delete")

    class Config:
        populate_by_name = True


class ExperimentInsertRequest(BaseModel):
    events: List[Dict[str, Any]] = Field(
        ..., description="Raw event dicts forwarded as-is to Braintrust"
    )


class DatasetEvent(BaseModel):
    id: Optional[str] = None
    input: Any
    expected: Optional[Any] = None
    metadata: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None
    is_merge: Optional[bool] = Field(default=None, alias="_is_merge")
    parent_id: Optional[str] = Field(default=None, alias="_parent_id")
    object_delete: Optional[bool] = Field(default=None, alias="_object_delete")

    class Config:
        populate_by_name = True


class DatasetInsertRequest(BaseModel):
    events: List[Dict[str, Any]] = Field(
        ..., description="Raw dataset event dicts forwarded as-is to Braintrust"
    )


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


@router.get("/", response_model=CapabilitySummary, summary="Braintrust capability summary")
async def capability_summary() -> CapabilitySummary:
    """Return the service summary — safe to call without an API key."""
    eng = _engine()
    api_key_present = eng.api_key_present()
    status = "ok" if api_key_present else "unavailable"
    # status="empty" is reserved for future use once we cache project counts;
    # without a local cache we cannot distinguish ok vs empty without an API call.
    return CapabilitySummary(
        service="Braintrust",
        endpoints=[
            "/v1/experiment",
            "/v1/dataset",
            "/v1/project",
            "/v1/score",
            "/v1/prompt",
            "/v1/function",
        ],
        braintrust_api_key_present=api_key_present,
        status=status,
    )


# ---------------------------------------------------------------------------
# Experiments
# ---------------------------------------------------------------------------


@router.get("/v1/experiment", response_model=ListingResponse)
async def list_experiments(
    project_id: Optional[str] = Query(default=None, description="Filter by project UUID"),
    project_name: Optional[str] = Query(default=None, description="Filter by project name"),
    starting_after: Optional[str] = Query(default=None, description="Cursor — start after this id"),
    ending_before: Optional[str] = Query(default=None, description="Cursor — end before this id"),
    limit: Optional[int] = Query(default=None, ge=1, le=1000, description="Max rows"),
) -> ListingResponse:
    eng = _engine()
    data = _serve(
        lambda: eng.list_experiments(
            project_id=project_id,
            project_name=project_name,
            starting_after=starting_after,
            ending_before=ending_before,
            limit=limit,
        )
    )
    return ListingResponse(**data)


@router.get("/v1/experiment/{exp_id}")
async def get_experiment(
    exp_id: str = Path(..., description="Experiment UUID"),
) -> Dict[str, Any]:
    eng = _engine()
    return _serve(lambda: eng.get_experiment(exp_id))


@router.post("/v1/experiment")
async def create_experiment(
    body: ExperimentCreateRequest = Body(...),
) -> Dict[str, Any]:
    eng = _engine()
    payload = body.model_dump(exclude_none=True)
    return _serve(lambda: eng.create_experiment(payload))


@router.post("/v1/experiment/{exp_id}/insert", response_model=RowIdsResponse)
async def insert_experiment_events(
    exp_id: str = Path(..., description="Experiment UUID"),
    body: ExperimentInsertRequest = Body(...),
) -> RowIdsResponse:
    eng = _engine()
    data = _serve(lambda: eng.insert_experiment_events(exp_id, body.events))
    return RowIdsResponse(**data)


# ---------------------------------------------------------------------------
# Datasets
# ---------------------------------------------------------------------------


@router.get("/v1/dataset", response_model=ListingResponse)
async def list_datasets(
    project_id: Optional[str] = Query(default=None),
    project_name: Optional[str] = Query(default=None),
    starting_after: Optional[str] = Query(default=None),
    ending_before: Optional[str] = Query(default=None),
    limit: Optional[int] = Query(default=None, ge=1, le=1000),
) -> ListingResponse:
    eng = _engine()
    data = _serve(
        lambda: eng.list_datasets(
            project_id=project_id,
            project_name=project_name,
            starting_after=starting_after,
            ending_before=ending_before,
            limit=limit,
        )
    )
    return ListingResponse(**data)


@router.get("/v1/dataset/{ds_id}")
async def get_dataset(
    ds_id: str = Path(..., description="Dataset UUID"),
) -> Dict[str, Any]:
    eng = _engine()
    return _serve(lambda: eng.get_dataset(ds_id))


@router.post("/v1/dataset/{ds_id}/insert", response_model=RowIdsResponse)
async def insert_dataset_events(
    ds_id: str = Path(..., description="Dataset UUID"),
    body: DatasetInsertRequest = Body(...),
) -> RowIdsResponse:
    eng = _engine()
    data = _serve(lambda: eng.insert_dataset_events(ds_id, body.events))
    return RowIdsResponse(**data)


# ---------------------------------------------------------------------------
# Projects
# ---------------------------------------------------------------------------


@router.get("/v1/project", response_model=ListingResponse)
async def list_projects(
    org_name: Optional[str] = Query(default=None, description="Filter by org name"),
    starting_after: Optional[str] = Query(default=None),
    ending_before: Optional[str] = Query(default=None),
    limit: Optional[int] = Query(default=None, ge=1, le=1000),
) -> ListingResponse:
    eng = _engine()
    data = _serve(
        lambda: eng.list_projects(
            org_name=org_name,
            starting_after=starting_after,
            ending_before=ending_before,
            limit=limit,
        )
    )
    return ListingResponse(**data)


# ---------------------------------------------------------------------------
# Scores
# ---------------------------------------------------------------------------


@router.get("/v1/score", response_model=ListingResponse)
async def list_scores() -> ListingResponse:
    eng = _engine()
    data = _serve(lambda: eng.list_scores())
    return ListingResponse(**data)


__all__ = ["router"]
