"""Regression tests for HTTP observability instrumentation."""

from __future__ import annotations

import asyncio
import sys
import types
from typing import Generator

import pytest
from fastapi import HTTPException
from starlette.responses import Response

# Patch pydantic_settings before importing application modules. Tests use a
# lightweight stand-in so importing `get_settings` does not require optional
# dependencies.
if "pydantic_settings" not in sys.modules:  # pragma: no cover - import guard
    from pydantic import FieldInfo

    pydantic_settings = types.ModuleType("pydantic_settings")

    class _BaseSettings:
        def __init__(self, **overrides):
            for name, value in self.__class__.__dict__.items():
                if name.startswith("_") or callable(value) or isinstance(value, property):
                    continue
                default = value.default if isinstance(value, FieldInfo) else value
                setattr(self, name, overrides.get(name, default))

    pydantic_settings.BaseSettings = _BaseSettings
    pydantic_settings.SettingsConfigDict = dict
    sys.modules["pydantic_settings"] = pydantic_settings

from src.core.middleware import PerformanceMiddleware
from src.services.metrics import FixOpsMetrics


@pytest.fixture(autouse=True)
def reset_metrics() -> Generator[None, None, None]:
    """Ensure every test runs with a clean metrics slate."""

    FixOpsMetrics.reset_runtime_stats()
    yield
    FixOpsMetrics.reset_runtime_stats()


def _build_request(path: str, method: str) -> types.SimpleNamespace:
    return types.SimpleNamespace(
        url=types.SimpleNamespace(path=path),
        method=method,
        state=types.SimpleNamespace(),
    )


def test_successful_hot_path_updates_latency_and_ratio() -> None:
    """Successful decision requests should publish hot path latency without errors."""

    middleware = PerformanceMiddleware(lambda scope, receive, send: None)  # type: ignore[arg-type]
    request = _build_request("/api/v1/decisions/make-decision", "POST")

    async def call_next(_: object) -> Response:
        return Response(content="ok", media_type="application/json", status_code=200)

    response = asyncio.run(middleware.dispatch(request, call_next))

    assert response.status_code == 200
    assert FixOpsMetrics.get_error_ratio("decision") == 0

    latency = FixOpsMetrics.get_hot_path_latency_us("/api/v1/decisions/make-decision")
    assert latency is not None and latency > 0
    assert FixOpsMetrics.get_inflight("decision") == 0


def test_policy_errors_drive_error_ratio() -> None:
    """Failing policy evaluations must be tracked as errors for observability dashboards."""

    middleware = PerformanceMiddleware(lambda scope, receive, send: None)  # type: ignore[arg-type]
    request = _build_request("/api/v1/policy/evaluate", "POST")

    async def call_next(_: object) -> Response:
        raise HTTPException(status_code=503, detail="policy gate offline")

    with pytest.raises(HTTPException):
        asyncio.run(middleware.dispatch(request, call_next))

    assert FixOpsMetrics.get_error_ratio("policy") == 1

    latency = FixOpsMetrics.get_hot_path_latency_us("/api/v1/policy/evaluate")
    assert latency is not None and latency > 0
    assert FixOpsMetrics.get_inflight("policy") == 0


def test_evidence_requests_are_classified_correctly() -> None:
    """Evidence retrieval should register under the evidence family for ratios."""

    middleware = PerformanceMiddleware(lambda scope, receive, send: None)  # type: ignore[arg-type]
    request = _build_request("/api/v1/decisions/evidence/abc123", "GET")

    async def call_next(_: object) -> Response:
        return Response(content="{}", media_type="application/json", status_code=200)

    response = asyncio.run(middleware.dispatch(request, call_next))

    assert response.status_code == 200
    assert FixOpsMetrics.get_error_ratio("evidence") == 0

    latency = FixOpsMetrics.get_hot_path_latency_us("/api/v1/decisions/evidence")
    assert latency is not None and latency > 0
    assert FixOpsMetrics.get_inflight("evidence") == 0
