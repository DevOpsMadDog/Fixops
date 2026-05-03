"""Akto API Security Router — ALDECI.

Wraps Akto's REST surfaces under prefix ``/api/v1/akto``:

  - GET  /                          — capability summary
  - GET  /api/discovered-apis       — inventory of discovered APIs
  - GET  /api/sensitive-data        — sensitive-data findings
  - GET  /api/test-results          — security test results
  - GET  /api/runtime-issues        — runtime-detected issues
  - POST /api/start-test            — kick off a test run
  - GET  /api/test-runs             — historical test-run summaries
  - GET  /api/collections           — API collection list

NO MOCKS rule
-------------
* When AKTO_BASE_URL or AKTO_API_TOKEN is unset:
    - Capability summary surfaces ``status="unavailable"``.
    - All live endpoints return HTTP 503.
* No fabricated payloads.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/akto",
    tags=["Akto"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Engine accessor (lazy import so tests can patch the singleton)
# ---------------------------------------------------------------------------


def _engine():
    from core.akto_engine import get_akto_engine

    return get_akto_engine()


def _serve(callable_):
    """Run an Akto call, translating engine errors to HTTP responses.

    AktoUnavailableError -> 503 (creds missing, network, upstream error)
    ValueError           -> 422 (input validation)
    """
    from core.akto_engine import AktoUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except AktoUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------


class StartTestRequest(BaseModel):
    collectionId: int = Field(..., ge=0, description="Akto API collection ID")
    testIds: List[str] = Field(
        ..., min_length=1, description="Test sub-types to run"
    )
    testRunTime: int = Field(
        ..., ge=0, description="Schedule timestamp (epoch seconds)"
    )
    testRunHourlySchedule: Optional[int] = Field(default=None, ge=0)
    sendSlackAlert: Optional[bool] = Field(default=None)
    recurringDailyOption: Optional[bool] = Field(default=None)


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


@router.get("/", summary="Akto capability summary")
def capability_summary() -> Dict[str, Any]:
    eng = _engine()
    base_ok = eng.base_url_present()
    tok_ok = eng.api_token_present()
    return {
        "service": "Akto",
        "endpoints": [
            "/api/discovered-apis",
            "/api/sensitive-data",
            "/api/test-results",
            "/api/runtime-issues",
            "/api/start-test",
        ],
        "akto_base_url_present": base_ok,
        "akto_api_token_present": tok_ok,
        "status": "ok" if (base_ok and tok_ok) else "unavailable",
    }


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


@router.get("/api/discovered-apis", summary="List Akto-discovered APIs")
def discovered_apis(
    collectionId: Optional[int] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=1000),
    skip: int = Query(default=0, ge=0),
    sortField: Optional[str] = Query(default=None),
    sortOrder: Optional[str] = Query(default=None, pattern="^(asc|desc|ASC|DESC)$"),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().discovered_apis(
            collection_id=collectionId,
            limit=limit,
            skip=skip,
            sort_field=sortField,
            sort_order=sortOrder,
        )
    )


@router.get("/api/sensitive-data", summary="List sensitive-data findings")
def sensitive_data(
    collectionId: Optional[int] = Query(default=None),
    dataType: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=1000),
    skip: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().sensitive_data(
            collection_id=collectionId,
            data_type=dataType,
            limit=limit,
            skip=skip,
        )
    )


# ---------------------------------------------------------------------------
# Test results / runtime issues
# ---------------------------------------------------------------------------


@router.get("/api/test-results", summary="List Akto test results")
def test_results(
    testRunId: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=1000),
    skip: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().test_results(
            test_run_id=testRunId, limit=limit, skip=skip
        )
    )


@router.get("/api/runtime-issues", summary="List Akto runtime issues")
def runtime_issues(
    startTimestamp: Optional[int] = Query(default=None, ge=0),
    endTimestamp: Optional[int] = Query(default=None, ge=0),
    severity: Optional[str] = Query(
        default=None, pattern="^(HIGH|MEDIUM|LOW|high|medium|low)$"
    ),
    limit: int = Query(default=50, ge=1, le=1000),
    skip: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().runtime_issues(
            start_timestamp=startTimestamp,
            end_timestamp=endTimestamp,
            severity=severity,
            limit=limit,
            skip=skip,
        )
    )


# ---------------------------------------------------------------------------
# Test launch / runs
# ---------------------------------------------------------------------------


@router.post("/api/start-test", summary="Start an Akto test run")
def start_test(body: StartTestRequest = Body(...)) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().start_test(
            collection_id=body.collectionId,
            test_ids=body.testIds,
            test_run_time=body.testRunTime,
            test_run_hourly_schedule=body.testRunHourlySchedule,
            send_slack_alert=body.sendSlackAlert,
            recurring_daily_option=body.recurringDailyOption,
        )
    )


@router.get("/api/test-runs", summary="List historical test runs")
def test_runs(
    limit: int = Query(default=50, ge=1, le=1000),
    skip: int = Query(default=0, ge=0),
    state: Optional[str] = Query(
        default=None,
        pattern="^(RUNNING|COMPLETED|FAILED|SCHEDULED|CANCELED)$",
    ),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().test_runs(limit=limit, skip=skip, state=state)
    )


@router.get("/api/collections", summary="List Akto API collections")
def collections() -> Dict[str, Any]:
    return _serve(lambda: _engine().collections())


__all__ = ["router"]
