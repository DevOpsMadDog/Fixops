"""
ALDECI Grafana Loki Integration Router.

Proxies Loki's HTTP API under /api/v1/loki/* with auth + scope guards.

Endpoints:
  GET  /api/v1/loki/                       — capability summary
  GET  /api/v1/loki/labels                 — list label names
  GET  /api/v1/loki/label/{name}/values    — list values for a label
  POST /api/v1/loki/push                   — push log streams (returns 204)
  POST /api/v1/loki/query                  — instant LogQL query
  POST /api/v1/loki/query_range            — range LogQL query
  GET  /api/v1/loki/series                 — series matching selector(s)

NO MOCKS — when LOKI_URL is unset, capability returns status=unavailable
and proxied endpoints return 503.

Vision Pillars: V8 (Observability)
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/loki",
    tags=["loki"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Lazy engine accessor (test override via monkeypatch)
# ---------------------------------------------------------------------------


def _get_engine():
    from core.loki_integration_engine import get_loki_integration_engine

    return get_loki_integration_engine()


def _engine_errors():
    from core.loki_integration_engine import LokiUnavailableError, LokiUpstreamError

    return LokiUnavailableError, LokiUpstreamError


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    loki_url_present: bool
    status: str  # ok | empty | unavailable


class LabelsResponse(BaseModel):
    status: str
    data: List[str]


class PushRequest(BaseModel):
    streams: List[Dict[str, Any]] = Field(
        ...,
        description='[{stream:{label:value...}, values:[[ts_ns, log_line], ...]}, ...]',
    )


class QueryRequest(BaseModel):
    query: str = Field(..., description="LogQL query expression")
    time: Optional[str] = Field(default=None, description="RFC3339 or ns timestamp")
    limit: Optional[int] = Field(default=None, ge=1, le=5000)
    direction: Optional[str] = Field(default=None, description="backward|forward")


class QueryRangeRequest(BaseModel):
    query: str
    start: str
    end: str
    step: Optional[str] = None
    limit: Optional[int] = Field(default=None, ge=1, le=5000)
    direction: Optional[str] = Field(default=None, description="backward|forward")


class QueryResponse(BaseModel):
    status: str
    data: Dict[str, Any]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _raise_for_engine_error(exc: Exception) -> None:
    LokiUnavailableError, LokiUpstreamError = _engine_errors()
    if isinstance(exc, LokiUnavailableError):
        raise HTTPException(status_code=503, detail="Loki upstream unavailable: LOKI_URL not configured")
    if isinstance(exc, LokiUpstreamError):
        # Preserve upstream code where reasonable; otherwise surface 502.
        upstream = getattr(exc, "status_code", 502)
        if upstream == 401:
            raise HTTPException(status_code=502, detail=f"Loki upstream rejected auth: {exc.body[:200]}")
        if upstream == 404:
            raise HTTPException(status_code=404, detail=f"Loki upstream 404: {exc.body[:200]}")
        if upstream >= 500:
            raise HTTPException(status_code=502, detail=f"Loki upstream {upstream}: {exc.body[:200]}")
        raise HTTPException(status_code=502, detail=f"Loki upstream {upstream}: {exc.body[:200]}")
    raise HTTPException(status_code=500, detail=f"Loki integration error: {exc!s}")


def _validate_direction(d: Optional[str]) -> Optional[str]:
    if d is None:
        return None
    if d not in ("backward", "forward"):
        raise HTTPException(status_code=400, detail="direction must be 'backward' or 'forward'")
    return d


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", response_model=CapabilityResponse)
def capability_summary() -> CapabilityResponse:
    eng = _get_engine()
    url_present = eng.is_available()
    return CapabilityResponse(
        service="Grafana Loki",
        endpoints=list(eng.SUPPORTED_ENDPOINTS),
        loki_url_present=url_present,
        status="ok" if url_present else "unavailable",
    )


@router.get("/labels", response_model=LabelsResponse)
def list_labels() -> LabelsResponse:
    eng = _get_engine()
    try:
        result = eng.get_labels()
    except Exception as exc:
        _raise_for_engine_error(exc)
    return LabelsResponse(
        status=str(result.get("status", "success")),
        data=list(result.get("data", []) or []),
    )


@router.get("/label/{name}/values", response_model=LabelsResponse)
def list_label_values(name: str) -> LabelsResponse:
    if not name or not name.replace("_", "").isalnum():
        raise HTTPException(status_code=400, detail="label name must be alphanumeric (underscores ok)")
    eng = _get_engine()
    try:
        result = eng.get_label_values(name)
    except Exception as exc:
        _raise_for_engine_error(exc)
    return LabelsResponse(
        status=str(result.get("status", "success")),
        data=list(result.get("data", []) or []),
    )


@router.post("/push", status_code=204)
def push_streams(payload: PushRequest) -> Response:
    if not payload.streams:
        raise HTTPException(status_code=400, detail="streams must be a non-empty list")
    eng = _get_engine()
    try:
        eng.push({"streams": payload.streams})
    except Exception as exc:
        _raise_for_engine_error(exc)
    return Response(status_code=204)


@router.post("/query", response_model=QueryResponse)
def query(payload: QueryRequest) -> QueryResponse:
    if not payload.query.strip():
        raise HTTPException(status_code=400, detail="query must be a non-empty LogQL expression")
    direction = _validate_direction(payload.direction)
    eng = _get_engine()
    try:
        result = eng.query(
            logql=payload.query,
            time=payload.time,
            limit=payload.limit,
            direction=direction,
        )
    except Exception as exc:
        _raise_for_engine_error(exc)
    data = result.get("data") or {}
    if not isinstance(data, dict):
        data = {"result": data}
    return QueryResponse(status=str(result.get("status", "success")), data=data)


@router.post("/query_range", response_model=QueryResponse)
def query_range(payload: QueryRangeRequest) -> QueryResponse:
    if not payload.query.strip():
        raise HTTPException(status_code=400, detail="query must be a non-empty LogQL expression")
    if not payload.start or not payload.end:
        raise HTTPException(status_code=400, detail="start and end timestamps are required")
    direction = _validate_direction(payload.direction)
    eng = _get_engine()
    try:
        result = eng.query_range(
            logql=payload.query,
            start=payload.start,
            end=payload.end,
            step=payload.step,
            limit=payload.limit,
            direction=direction,
        )
    except Exception as exc:
        _raise_for_engine_error(exc)
    data = result.get("data") or {}
    if not isinstance(data, dict):
        data = {"result": data}
    return QueryResponse(status=str(result.get("status", "success")), data=data)


@router.get("/series", response_model=QueryResponse)
def list_series(
    match: List[str] = Query(default=[], alias="match[]", description="One or more LogQL series selectors"),
    start: Optional[str] = Query(default=None, description="RFC3339 or ns timestamp"),
    end: Optional[str] = Query(default=None, description="RFC3339 or ns timestamp"),
) -> QueryResponse:
    if not match:
        raise HTTPException(status_code=400, detail="at least one match[] selector is required")
    eng = _get_engine()
    try:
        result = eng.series(match=list(match), start=start, end=end)
    except Exception as exc:
        _raise_for_engine_error(exc)
    data = result.get("data") or []
    return QueryResponse(
        status=str(result.get("status", "success")),
        data={"result": data} if isinstance(data, list) else data,
    )


__all__ = ["router"]
