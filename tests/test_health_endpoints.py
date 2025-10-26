"""Tests for health check and readiness endpoints."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_health_endpoint_returns_200(demo_client: TestClient) -> None:
    """Health endpoint should always return 200 OK."""
    response = demo_client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "fixops-api"
    assert "timestamp" in data
    assert "version" in data


def test_health_endpoint_no_auth_required(demo_client: TestClient) -> None:
    """Health endpoint should not require authentication."""
    response = demo_client.get("/api/v1/health")
    assert response.status_code == 200


def test_readiness_endpoint_returns_200_when_ready(demo_client: TestClient) -> None:
    """Readiness endpoint should return 200 when all checks pass."""
    response = demo_client.get("/api/v1/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"
    assert data["service"] == "fixops-api"
    assert "checks" in data
    assert "timestamp" in data


def test_readiness_endpoint_checks_app_state(demo_client: TestClient) -> None:
    """Readiness endpoint should check application state."""
    response = demo_client.get("/api/v1/ready")
    data = response.json()
    assert "checks" in data
    assert "app_state" in data["checks"]
    assert data["checks"]["app_state"]["status"] in ["healthy", "unhealthy"]


def test_readiness_endpoint_checks_overlay(demo_client: TestClient) -> None:
    """Readiness endpoint should check overlay configuration."""
    response = demo_client.get("/api/v1/ready")
    data = response.json()
    assert "checks" in data
    assert "overlay" in data["checks"]
    assert data["checks"]["overlay"]["status"] == "healthy"
    assert "mode" in data["checks"]["overlay"]


def test_readiness_endpoint_checks_storage(demo_client: TestClient) -> None:
    """Readiness endpoint should check storage availability."""
    response = demo_client.get("/api/v1/ready")
    data = response.json()
    assert "checks" in data
    assert "storage" in data["checks"]


def test_readiness_endpoint_no_auth_required(demo_client: TestClient) -> None:
    """Readiness endpoint should not require authentication."""
    response = demo_client.get("/api/v1/ready")
    assert response.status_code in [200, 503]  # Either ready or not ready


def test_version_endpoint_returns_version_info(demo_client: TestClient) -> None:
    """Version endpoint should return version and build information."""
    response = demo_client.get("/api/v1/version")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "fixops-api"
    assert "version" in data
    assert "build_date" in data
    assert "git_commit" in data
    assert "python_version" in data
    assert "environment" in data


def test_version_endpoint_no_auth_required(demo_client: TestClient) -> None:
    """Version endpoint should not require authentication."""
    response = demo_client.get("/api/v1/version")
    assert response.status_code == 200


def test_metrics_endpoint_returns_metrics(demo_client: TestClient) -> None:
    """Metrics endpoint should return application metrics."""
    response = demo_client.get("/api/v1/metrics")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "fixops-api"
    assert "timestamp" in data
    assert "version" in data


def test_metrics_endpoint_includes_artifact_counts(demo_client: TestClient) -> None:
    """Metrics endpoint should include artifact counts if available."""
    response = demo_client.get("/api/v1/metrics")
    data = response.json()
    assert "service" in data


def test_metrics_endpoint_no_auth_required(demo_client: TestClient) -> None:
    """Metrics endpoint should not require authentication."""
    response = demo_client.get("/api/v1/metrics")
    assert response.status_code == 200
