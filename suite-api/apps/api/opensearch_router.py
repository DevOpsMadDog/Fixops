"""OpenSearch Anomaly Detection Router — ALDECI.

Wraps ``core.opensearch_detection_engine.OpenSearchDetectionEngine`` with
REST endpoints for managing detectors and querying anomaly results.

Prefix: /api/v1/opensearch
Auth:   api_key_auth dependency (mount layer adds scope checks — read:scans)

Routes:
  GET  /api/v1/opensearch/                              capability summary
  GET  /api/v1/opensearch/detectors                     list detectors
  POST /api/v1/opensearch/detectors                     create detector
  GET  /api/v1/opensearch/detectors/{id}                single detector
  POST /api/v1/opensearch/detectors/{id}/_start         start detection job
  POST /api/v1/opensearch/detectors/{id}/_stop          stop detection job
  GET  /api/v1/opensearch/detectors/{id}/results        anomaly results

NO MOCKS rule: when OPENSEARCH_URL is missing the capability summary
returns ``status="unavailable"`` and every detector endpoint returns
HTTP 503. We never fabricate detectors, jobs, or anomaly results.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/opensearch",
    tags=["OpenSearch Anomaly Detection"],
    dependencies=[Depends(api_key_auth)],
)


def _engine():
    # Indirection so tests can patch the engine via reset_opensearch_detection_engine().
    from core.opensearch_detection_engine import get_opensearch_detection_engine

    return get_opensearch_detection_engine()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    opensearch_url_present: bool
    status: str  # ok | empty | unavailable


class FeatureAttribute(BaseModel):
    feature_name: Optional[str] = None
    feature_enabled: bool = True
    aggregation_query: Dict[str, Any] = Field(default_factory=dict)


class DetectorBrief(BaseModel):
    detector_id: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    time_field: Optional[str] = None
    indices: List[str] = Field(default_factory=list)
    feature_attributes: List[FeatureAttribute] = Field(default_factory=list)
    detection_interval: Dict[str, Any] = Field(default_factory=dict)
    window_delay: Dict[str, Any] = Field(default_factory=dict)


class DetectorDetail(DetectorBrief):
    last_update_time: Optional[Any] = None


class DetectorListResponse(BaseModel):
    detectors: List[DetectorBrief] = Field(default_factory=list)
    totalDetectors: int = 0


class DetectorCreateResponse(BaseModel):
    detector_id: Optional[str] = None
    version: Optional[Any] = None
    result: Dict[str, Any] = Field(default_factory=dict)


class DetectorActionResponse(BaseModel):
    detector_id: str
    started: Optional[bool] = None
    stopped: Optional[bool] = None
    result: Dict[str, Any] = Field(default_factory=dict)


class AnomalyResult(BaseModel):
    result_id: Optional[str] = None
    detector_id: Optional[str] = None
    data_start_time: Optional[Any] = None
    data_end_time: Optional[Any] = None
    anomaly_grade: Optional[float] = None
    confidence: Optional[float] = None
    feature_data: List[Dict[str, Any]] = Field(default_factory=list)


class ResultsResponse(BaseModel):
    detector_id: str
    results: List[AnomalyResult] = Field(default_factory=list)
    totalResults: int = 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _serve(callable_):
    """Run an OpenSearch call, translating engine errors to HTTP responses.

    OpenSearchUnavailableError -> 503 (auth missing, network, upstream error)
    ValueError                 -> 422 (input validation)
    """
    from core.opensearch_detection_engine import OpenSearchUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except OpenSearchUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", response_model=CapabilityResponse)
async def capability_summary() -> CapabilityResponse:
    """Return the service summary — safe to call without an OpenSearch URL."""
    eng = _engine()
    url_present = eng.url_present()
    if not url_present:
        status = "unavailable"
    else:
        # We can't cheaply probe upstream without burning a request, so treat
        # "URL present" as ok. The detector list endpoint will surface
        # transport errors with a 503.
        status = "ok"
    return CapabilityResponse(
        service="OpenSearch Anomaly Detection",
        endpoints=[
            "/detectors",
            "/detectors/{id}",
            "/detectors/{id}/_start",
            "/detectors/{id}/_stop",
            "/detectors/{id}/results",
        ],
        opensearch_url_present=url_present,
        status=status,
    )


@router.get("/detectors", response_model=DetectorListResponse)
async def list_detectors(
    size: int = Query(100, ge=1, le=1000, description="Max detectors to return"),
) -> DetectorListResponse:
    eng = _engine()
    data = _serve(lambda: eng.list_detectors(size=size))
    return DetectorListResponse(**data)


@router.post(
    "/detectors",
    response_model=DetectorCreateResponse,
    status_code=201,
)
async def create_detector(
    body: Dict[str, Any] = Body(
        ...,
        description=(
            "OpenSearch AD detector body — name, description, time_field, "
            "indices, feature_attributes, detection_interval, window_delay."
        ),
    ),
) -> DetectorCreateResponse:
    eng = _engine()
    data = _serve(lambda: eng.create_detector(body))
    return DetectorCreateResponse(**data)


@router.get("/detectors/{detector_id}", response_model=DetectorDetail)
async def get_detector(
    detector_id: str = Path(..., min_length=1, description="Detector ID"),
) -> DetectorDetail:
    eng = _engine()
    data = _serve(lambda: eng.get_detector(detector_id))
    return DetectorDetail(**data)


@router.post(
    "/detectors/{detector_id}/_start",
    response_model=DetectorActionResponse,
)
async def start_detector(
    detector_id: str = Path(..., min_length=1, description="Detector ID"),
) -> DetectorActionResponse:
    eng = _engine()
    data = _serve(lambda: eng.start_detector(detector_id))
    return DetectorActionResponse(**data)


@router.post(
    "/detectors/{detector_id}/_stop",
    response_model=DetectorActionResponse,
)
async def stop_detector(
    detector_id: str = Path(..., min_length=1, description="Detector ID"),
) -> DetectorActionResponse:
    eng = _engine()
    data = _serve(lambda: eng.stop_detector(detector_id))
    return DetectorActionResponse(**data)


@router.get(
    "/detectors/{detector_id}/results",
    response_model=ResultsResponse,
)
async def get_results(
    detector_id: str = Path(..., min_length=1, description="Detector ID"),
    startTime: Optional[int] = Query(
        None, description="Lower bound for data_start_time (epoch millis)"
    ),
    endTime: Optional[int] = Query(
        None, description="Upper bound for data_start_time (epoch millis)"
    ),
    size: int = Query(100, ge=1, le=1000),
) -> ResultsResponse:
    eng = _engine()
    data = _serve(
        lambda: eng.get_results(
            detector_id,
            start_time=startTime,
            end_time=endTime,
            size=size,
        )
    )
    return ResultsResponse(**data)


__all__ = ["router"]
