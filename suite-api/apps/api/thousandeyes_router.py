"""ThousandEyes Network Intelligence Router — ALDECI.

Surfaces the ThousandEyes v6 REST API under prefix ``/api/v1/thousandeyes``:

  - GET  /                             capability summary
  - GET  /v6/tests.json                list tests
  - GET  /v6/tests/{test_id}.json      single test detail
  - GET  /v6/agents.json               list agents
  - GET  /v6/alerts.json               list alerts in window
  - GET  /v6/web/page-load.json        page-load test results
  - GET  /v6/net/metrics.json          network-layer metrics
  - GET  /v6/dns/server-metrics.json   DNS server metrics
  - GET  /v6/bgp/metrics.json          BGP metrics

NO MOCKS rule
-------------
* When THOUSANDEYES_API_TOKEN is unset:
    - Capability summary surfaces ``status="unavailable"``.
    - All live endpoints return HTTP 503.
* No fabricated payloads.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/thousandeyes",
    tags=["ThousandEyes"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Engine accessor (lazy import so tests can patch the singleton)
# ---------------------------------------------------------------------------


def _engine():
    from core.thousandeyes_engine import get_thousandeyes_engine

    return get_thousandeyes_engine()


def _serve(callable_):
    """Run a ThousandEyes call, translating engine errors to HTTP responses.

    ThousandEyesUnavailableError -> 503 (token missing, network, upstream error)
    ValueError                   -> 422 (input validation)
    """
    from core.thousandeyes_engine import ThousandEyesUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ThousandEyesUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    thousandeyes_api_token_present: bool
    status: str  # ok | empty | unavailable


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", response_model=CapabilityResponse, summary="ThousandEyes capability summary")
async def capability_summary() -> CapabilityResponse:
    """Return the service summary — safe to call without a token."""
    eng = _engine()
    token_present = eng.api_token_present()
    if not token_present:
        status = "unavailable"
    else:
        status = "ok"
    return CapabilityResponse(
        service="ThousandEyes",
        endpoints=[
            "/v6/tests",
            "/v6/agents",
            "/v6/alerts",
            "/v6/web/page-load",
            "/v6/net/metrics",
            "/v6/dns/server-metrics",
        ],
        thousandeyes_api_token_present=token_present,
        status=status,
    )


@router.get("/v6/tests.json", summary="ThousandEyes — list tests")
async def list_tests_endpoint(
    aid: Optional[str] = Query(None, description="Account group ID"),
    format: str = Query("json", description="Response format (json only)"),
) -> Dict[str, Any]:
    eng = _engine()
    return _serve(lambda: eng.list_tests(aid=aid))


@router.get("/v6/tests/{test_id}.json", summary="ThousandEyes — single test detail")
async def test_detail_endpoint(
    test_id: str = Path(..., description="ThousandEyes testId"),
    aid: Optional[str] = Query(None, description="Account group ID"),
) -> Dict[str, Any]:
    eng = _engine()
    return _serve(lambda: eng.test_detail(test_id, aid=aid))


@router.get("/v6/agents.json", summary="ThousandEyes — list agents")
async def list_agents_endpoint(
    aid: Optional[str] = Query(None, description="Account group ID"),
    agentTypes: Optional[str] = Query(
        None,
        description="Comma-separated subset of: enterprise, cloud, enterprise-cluster",
    ),
) -> Dict[str, Any]:
    eng = _engine()
    return _serve(lambda: eng.list_agents(aid=aid, agent_types=agentTypes))


@router.get("/v6/alerts.json", summary="ThousandEyes — list alerts")
async def list_alerts_endpoint(
    aid: Optional[str] = Query(None, description="Account group ID"),
    from_: Optional[str] = Query(
        None, alias="from", description="Window start (ISO 8601)"
    ),
    to: Optional[str] = Query(None, description="Window end (ISO 8601)"),
    format: str = Query("json", description="Response format (json only)"),
) -> Dict[str, Any]:
    eng = _engine()
    return _serve(
        lambda: eng.list_alerts(aid=aid, from_iso=from_, to_iso=to)
    )


@router.get("/v6/web/page-load.json", summary="ThousandEyes — web page-load metrics")
async def web_page_load_endpoint(
    aid: Optional[str] = Query(None, description="Account group ID"),
    testId: str = Query(..., description="ThousandEyes testId"),
    from_: Optional[str] = Query(
        None, alias="from", description="Window start (ISO 8601)"
    ),
    to: Optional[str] = Query(None, description="Window end (ISO 8601)"),
    window: Optional[str] = Query(
        None, description="Look-back window (e.g. 10m, 1h, 24h)"
    ),
    format: str = Query("json", description="Response format (json only)"),
) -> Dict[str, Any]:
    eng = _engine()
    return _serve(
        lambda: eng.web_page_load(
            testId, aid=aid, from_iso=from_, to_iso=to, window=window
        )
    )


@router.get("/v6/net/metrics.json", summary="ThousandEyes — network-layer metrics")
async def net_metrics_endpoint(
    aid: Optional[str] = Query(None, description="Account group ID"),
    testId: str = Query(..., description="ThousandEyes testId"),
    from_: Optional[str] = Query(
        None, alias="from", description="Window start (ISO 8601)"
    ),
    to: Optional[str] = Query(None, description="Window end (ISO 8601)"),
    format: str = Query("json", description="Response format (json only)"),
) -> Dict[str, Any]:
    eng = _engine()
    return _serve(
        lambda: eng.net_metrics(testId, aid=aid, from_iso=from_, to_iso=to)
    )


@router.get(
    "/v6/dns/server-metrics.json", summary="ThousandEyes — DNS server metrics"
)
async def dns_server_metrics_endpoint(
    aid: Optional[str] = Query(None, description="Account group ID"),
    testId: str = Query(..., description="ThousandEyes testId"),
    from_: Optional[str] = Query(
        None, alias="from", description="Window start (ISO 8601)"
    ),
    to: Optional[str] = Query(None, description="Window end (ISO 8601)"),
    format: str = Query("json", description="Response format (json only)"),
) -> Dict[str, Any]:
    eng = _engine()
    return _serve(
        lambda: eng.dns_server_metrics(
            testId, aid=aid, from_iso=from_, to_iso=to
        )
    )


@router.get("/v6/bgp/metrics.json", summary="ThousandEyes — BGP metrics")
async def bgp_metrics_endpoint(
    aid: Optional[str] = Query(None, description="Account group ID"),
    testId: str = Query(..., description="ThousandEyes testId"),
    from_: Optional[str] = Query(
        None, alias="from", description="Window start (ISO 8601)"
    ),
    to: Optional[str] = Query(None, description="Window end (ISO 8601)"),
    format: str = Query("json", description="Response format (json only)"),
) -> Dict[str, Any]:
    eng = _engine()
    return _serve(
        lambda: eng.bgp_metrics(testId, aid=aid, from_iso=from_, to_iso=to)
    )


__all__ = ["router"]
