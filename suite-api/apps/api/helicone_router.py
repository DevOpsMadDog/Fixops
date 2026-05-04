"""Helicone LLM Observability Router — ALDECI.

Wraps the Helicone REST surface under prefix ``/api/v1/helicone``:

  - GET  /                                  — capability summary
  - POST /v1/request/query                  — list/filter request logs
  - GET  /v1/property?propertyName=...      — custom property values
  - GET  /v1/user/metrics?userId=...        — per-user aggregates
  - POST /v1/cost-by-time                   — cost timeseries
  - GET  /v1/dataset                        — dataset list
  - POST /v1/feedback                       — attach feedback to request

NO MOCKS rule
-------------
* When ``HELICONE_API_KEY`` is unset:
    - Capability summary surfaces ``status="unavailable"``.
    - All live endpoints return HTTP 503.
* No fabricated payloads.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Query

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/helicone",
    tags=["Helicone"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Engine accessor (lazy import so tests can patch the singleton)
# ---------------------------------------------------------------------------


def _engine():
    from core.helicone_engine import get_helicone_engine

    return get_helicone_engine()


def _serve(callable_):
    """Run a Helicone call, translating engine errors to HTTP responses.

    HeliconeUnavailableError -> 503 (creds missing, network, upstream error)
    ValueError               -> 422 (input validation)
    """
    from core.helicone_engine import HeliconeUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except HeliconeUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


@router.get("/", summary="Helicone capability summary")
def capability_summary() -> Dict[str, Any]:
    eng = _engine()
    key_present = eng.api_key_present()
    return {
        "service": "Helicone",
        "endpoints": [
            "/v1/request/query",
            "/v1/property",
            "/v1/user/metrics",
            "/v1/cost-by-time",
            "/v1/dataset",
            "/v1/feedback",
        ],
        "helicone_api_key_present": key_present,
        "helicone_base_url": eng.base_url(),
        "status": "ok" if key_present else "unavailable",
    }


# ---------------------------------------------------------------------------
# Live endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/v1/request/query",
    summary="Query Helicone request logs (filters, sort, pagination)",
)
def request_query(body: Dict[str, Any] = Body(default_factory=dict)) -> Dict[str, Any]:
    return _serve(lambda: _engine().request_query(body))


@router.get(
    "/v1/property",
    summary="List custom property values + counts",
)
def property_values(
    propertyName: str = Query(..., description="Helicone custom property name"),
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=10000),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().property_values(propertyName, offset=offset, limit=limit)
    )


@router.get(
    "/v1/user/metrics",
    summary="Per-user aggregates (totalRequests, totalTokens, totalCost, ...)",
)
def user_metrics(
    userId: str = Query(..., description="Helicone user_id"),
    startTime: str = Query(None, description="ISO-8601 lower bound (optional)"),
    endTime: str = Query(None, description="ISO-8601 upper bound (optional)"),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().user_metrics(
            userId, start_time=startTime, end_time=endTime
        )
    )


@router.post(
    "/v1/cost-by-time",
    summary="Cost timeseries by hour/day/week/month",
)
def cost_by_time(body: Dict[str, Any] = Body(default_factory=dict)) -> Dict[str, Any]:
    return _serve(lambda: _engine().cost_by_time(body))


@router.get(
    "/v1/dataset",
    summary="List Helicone datasets",
)
def dataset_list() -> Dict[str, Any]:
    return _serve(lambda: _engine().dataset_list())


@router.post(
    "/v1/feedback",
    summary="Attach feedback (rating + scores) to a logged request",
)
def feedback(body: Dict[str, Any] = Body(default_factory=dict)) -> Dict[str, Any]:
    return _serve(lambda: _engine().feedback(body))


__all__ = ["router"]
