"""Tests for /api/v1/metrics Prometheus exposition endpoint."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


# Use the shared minimal health-router client from conftest to avoid the
# full create_app() startup cost (which exceeds the 10s timeout).
@pytest.fixture(scope="module")
def client(health_router_client: TestClient) -> TestClient:
    return health_router_client


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
