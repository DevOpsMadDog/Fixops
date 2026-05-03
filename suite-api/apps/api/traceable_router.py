"""Traceable AI Router — ALDECI.

Wraps Traceable AI Platform under prefix ``/api/v1/traceable``:

  - GET  /                                  capability summary
  - GET  /api/v1/services                   service inventory
  - GET  /api/v1/apis                       API inventory
  - GET  /api/v1/apis/{api_id}              API detail
  - GET  /api/v1/anomalies                  runtime anomalies
  - GET  /api/v1/threats                    active threats
  - GET  /api/v1/users-and-attribution      attributed users
  - POST /api/v1/policies/test              policy evaluation

NO MOCKS rule
-------------
* When TRACEABLE_BASE_URL or TRACEABLE_API_TOKEN is unset:
    - Capability summary surfaces ``status="unavailable"``.
    - All live endpoints return HTTP 503.
* No fabricated payloads.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/traceable",
    tags=["Traceable AI"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Engine accessor (lazy import so tests can patch the singleton)
# ---------------------------------------------------------------------------


def _engine():
    from core.traceable_engine import get_traceable_engine

    return get_traceable_engine()


def _serve(callable_):
    """Run a Traceable call, translating engine errors to HTTP responses.

    TraceableUnavailableError -> 503
    ValueError                -> 422
    """
    from core.traceable_engine import TraceableUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except TraceableUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class SampleRequest(BaseModel):
    method: str = Field(default="GET")
    path: str = Field(default="/")
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[Any] = None
    queryParams: Dict[str, Any] = Field(default_factory=dict)


class PolicyTestRequest(BaseModel):
    policyId: str
    sampleRequest: SampleRequest


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


@router.get("/", summary="Traceable AI capability summary")
def capability_summary() -> Dict[str, Any]:
    eng = _engine()
    base_ok = eng.base_url_present()
    tok_ok = eng.api_token_present()
    creds = base_ok and tok_ok
    return {
        "service": "Traceable AI",
        "endpoints": [
            "/api/v1/services",
            "/api/v1/apis",
            "/api/v1/anomalies",
            "/api/v1/threats",
            "/api/v1/users-and-attribution",
        ],
        "traceable_base_url_present": base_ok,
        "traceable_api_token_present": tok_ok,
        "status": "ok" if creds else "unavailable",
    }


# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------


@router.get("/api/v1/services", summary="List discovered services")
def list_services(
    startTime: Optional[str] = Query(default=None),
    endTime: Optional[str] = Query(default=None),
    pageSize: Optional[int] = Query(default=None, ge=1, le=1000),
    pageToken: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().list_services(
            start_time=startTime,
            end_time=endTime,
            page_size=pageSize,
            page_token=pageToken,
        )
    )


# ---------------------------------------------------------------------------
# APIs
# ---------------------------------------------------------------------------


@router.get("/api/v1/apis", summary="List discovered APIs")
def list_apis(
    serviceId: Optional[str] = Query(default=None),
    pageSize: Optional[int] = Query(default=None, ge=1, le=1000),
    pageToken: Optional[str] = Query(default=None),
    searchString: Optional[str] = Query(default=None),
    sensitiveDataOnly: Optional[bool] = Query(default=None),
    riskScoreGte: Optional[int] = Query(default=None, ge=0, le=100),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().list_apis(
            service_id=serviceId,
            page_size=pageSize,
            page_token=pageToken,
            search_string=searchString,
            sensitive_data_only=sensitiveDataOnly,
            risk_score_gte=riskScoreGte,
        )
    )


@router.get("/api/v1/apis/{api_id}", summary="API detail")
def get_api(
    api_id: str = Path(..., min_length=1),
) -> Dict[str, Any]:
    return _serve(lambda: _engine().get_api(api_id))


# ---------------------------------------------------------------------------
# Anomalies
# ---------------------------------------------------------------------------


@router.get("/api/v1/anomalies", summary="List runtime anomalies")
def list_anomalies(
    startTime: Optional[str] = Query(default=None),
    endTime: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None, pattern="^(critical|high|medium|low)$"),
    pageSize: Optional[int] = Query(default=None, ge=1, le=1000),
    pageToken: Optional[str] = Query(default=None),
    serviceId: Optional[str] = Query(default=None),
    apiId: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().list_anomalies(
            start_time=startTime,
            end_time=endTime,
            severity=severity,
            page_size=pageSize,
            page_token=pageToken,
            service_id=serviceId,
            api_id=apiId,
        )
    )


# ---------------------------------------------------------------------------
# Threats
# ---------------------------------------------------------------------------


@router.get("/api/v1/threats", summary="List active threats")
def list_threats(
    type: Optional[str] = Query(default=None),
    pageSize: Optional[int] = Query(default=None, ge=1, le=1000),
    pageToken: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None, pattern="^(critical|high|medium|low)$"),
    startTime: Optional[str] = Query(default=None),
    endTime: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().list_threats(
            threat_type=type,
            page_size=pageSize,
            page_token=pageToken,
            severity=severity,
            start_time=startTime,
            end_time=endTime,
        )
    )


# ---------------------------------------------------------------------------
# Users + Attribution
# ---------------------------------------------------------------------------


@router.get(
    "/api/v1/users-and-attribution", summary="List attributed users"
)
def list_users(
    startTime: Optional[str] = Query(default=None),
    endTime: Optional[str] = Query(default=None),
    pageSize: Optional[int] = Query(default=None, ge=1, le=1000),
    pageToken: Optional[str] = Query(default=None),
    searchUserId: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().list_users(
            start_time=startTime,
            end_time=endTime,
            page_size=pageSize,
            page_token=pageToken,
            search_user_id=searchUserId,
        )
    )


# ---------------------------------------------------------------------------
# Policy test
# ---------------------------------------------------------------------------


@router.post("/api/v1/policies/test", summary="Evaluate a policy against a sample request")
def test_policy(
    body: PolicyTestRequest = Body(...),
) -> Dict[str, Any]:
    payload = body.model_dump(exclude_none=False)
    return _serve(lambda: _engine().test_policy(payload))


__all__ = ["router"]
