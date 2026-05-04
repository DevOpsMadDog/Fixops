"""Tests for /api/v1/metrics Prometheus exposition endpoint."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    from apps.api.health import router as health_router

    app = FastAPI()
    app.include_router(health_router)
    return TestClient(app)


def test_metrics_returns_200(client):
    resp = client.get("/api/v1/metrics")
    assert resp.status_code == 200


def test_metrics_content_type_text_plain(client):
    resp = client.get("/api/v1/metrics")
    assert "text/plain" in resp.headers["content-type"]


def test_metrics_contains_engines_gauge(client):
    resp = client.get("/api/v1/metrics")
    assert "fixops_engines_total" in resp.text


def test_metrics_contains_latency_gauge(client):
    resp = client.get("/api/v1/metrics")
    assert "fixops_metrics_endpoint_latency_ms" in resp.text
