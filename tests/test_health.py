"""
Lockdown test — Health endpoint shape stability.

Verifies that the three health-related routes defined in
suite-api/apps/api/health.py maintain their contract:

  GET /api/v1/health             → 200, has "status" key
  GET /api/v1/health/comprehensive → 200, has top-level "status" +
                                     exactly the 5 subsystem keys
  GET /api/v1/metrics            → 200, Content-Type text/plain (Prometheus)

These tests are shape-only — they do NOT assert subsystem values are "ok"
because the test environment may lack live feeds.db, crypto keys, etc.
Any schema regression (missing key, wrong HTTP status) will fail the gate.

Run:
    python -m pytest tests/test_health.py -x --tb=short --timeout=10 -q -o "addopts="
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Ensure suite-api is importable
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

# Disable metrics scrape token auth and rate limiting for tests
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from fastapi.testclient import TestClient  # noqa: E402

from apps.api.app import create_app  # noqa: E402

# ---------------------------------------------------------------------------
# Shared client fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client() -> TestClient:
    app = create_app()
    return TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# Test 1 — Liveness probe
# ---------------------------------------------------------------------------

def test_health_liveness_returns_200_with_status_key(client: TestClient) -> None:
    """GET /api/v1/health must return 200 and a top-level 'status' key."""
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    body = resp.json()
    assert "status" in body, f"'status' key missing from /health response: {body}"


# ---------------------------------------------------------------------------
# Test 2 — Comprehensive health — top-level fields
# ---------------------------------------------------------------------------

def test_health_comprehensive_returns_200(client: TestClient) -> None:
    """GET /api/v1/health/comprehensive must return 200 (always — never 503)."""
    resp = client.get("/api/v1/health/comprehensive")
    assert resp.status_code == 200, (
        f"Expected 200 from /health/comprehensive, got {resp.status_code}: {resp.text}"
    )


def test_health_comprehensive_has_status_field(client: TestClient) -> None:
    """Top-level 'status' must be present and one of 'ok' or 'degraded'."""
    resp = client.get("/api/v1/health/comprehensive")
    body = resp.json()
    assert "status" in body, f"'status' key missing: {body}"
    assert body["status"] in ("ok", "degraded"), (
        f"Unexpected status value '{body['status']}' — expected 'ok' or 'degraded'"
    )


def test_health_comprehensive_has_checks_dict(client: TestClient) -> None:
    """Top-level 'checks' must be a dict."""
    resp = client.get("/api/v1/health/comprehensive")
    body = resp.json()
    assert "checks" in body, f"'checks' key missing: {body}"
    assert isinstance(body["checks"], dict), (
        f"'checks' must be a dict, got {type(body['checks'])}"
    )


_EXPECTED_SUBSYSTEMS = {"trustgraph", "feeds_db", "crypto", "risk_scorer", "brain_pipeline"}


def test_health_comprehensive_has_all_five_subsystems(client: TestClient) -> None:
    """All 5 subsystem keys must be present in the 'checks' dict."""
    resp = client.get("/api/v1/health/comprehensive")
    body = resp.json()
    checks = body.get("checks", {})
    missing = _EXPECTED_SUBSYSTEMS - set(checks.keys())
    assert not missing, (
        f"Missing subsystem keys in /health/comprehensive checks: {missing}\n"
        f"Got keys: {sorted(checks.keys())}"
    )


def test_health_comprehensive_each_subsystem_has_status(client: TestClient) -> None:
    """Every subsystem entry must carry a 'status' field."""
    resp = client.get("/api/v1/health/comprehensive")
    body = resp.json()
    checks = body.get("checks", {})
    for subsystem in _EXPECTED_SUBSYSTEMS:
        entry = checks.get(subsystem, {})
        assert "status" in entry, (
            f"Subsystem '{subsystem}' has no 'status' field: {entry}"
        )


def test_health_comprehensive_has_elapsed_ms(client: TestClient) -> None:
    """Top-level 'elapsed_ms' must be present and numeric."""
    resp = client.get("/api/v1/health/comprehensive")
    body = resp.json()
    assert "elapsed_ms" in body, f"'elapsed_ms' key missing: {body}"
    assert isinstance(body["elapsed_ms"], (int, float)), (
        f"'elapsed_ms' must be numeric, got {type(body['elapsed_ms'])}"
    )


def test_health_comprehensive_has_resources_with_metrics(client: TestClient) -> None:
    """Top-level 'resources' dict must have disk_percent, memory_percent, sqlite_wal_size_mb."""
    resp = client.get("/api/v1/health/comprehensive")
    body = resp.json()
    assert "resources" in body, f"'resources' key missing: {body}"
    resources = body.get("resources", {})
    assert isinstance(resources, dict), (
        f"'resources' must be a dict, got {type(resources)}"
    )
    # Verify required metric keys
    required_metrics = {"disk_percent", "memory_percent", "sqlite_wal_size_mb"}
    missing = required_metrics - set(resources.keys())
    assert not missing, (
        f"Missing resource metrics in /health/comprehensive: {missing}\n"
        f"Got keys: {sorted(resources.keys())}"
    )
    # Verify numeric types (None is acceptable for unreachable metrics)
    for metric_key in required_metrics:
        value = resources.get(metric_key)
        assert value is None or isinstance(value, (int, float)), (
            f"Resource metric '{metric_key}' must be numeric or None, got {type(value)}: {value}"
        )


# ---------------------------------------------------------------------------
# Test 3 — Prometheus metrics
# ---------------------------------------------------------------------------

def test_metrics_returns_200(client: TestClient) -> None:
    """GET /api/v1/metrics must return 200 with FIXOPS_DISABLE_RATE_LIMIT=1."""
    resp = client.get("/api/v1/metrics")
    assert resp.status_code == 200, (
        f"Expected 200 from /metrics, got {resp.status_code}: {resp.text[:300]}"
    )


def test_metrics_content_type_is_text_plain(client: TestClient) -> None:
    """Content-Type must start with 'text/plain' (Prometheus exposition format)."""
    resp = client.get("/api/v1/metrics")
    ct = resp.headers.get("content-type", "")
    assert ct.startswith("text/plain"), (
        f"Expected content-type text/plain, got '{ct}'"
    )


def test_metrics_contains_prometheus_gauge_lines(client: TestClient) -> None:
    """Response body must include at least one '# TYPE ... gauge' line."""
    resp = client.get("/api/v1/metrics")
    assert "# TYPE" in resp.text, (
        f"No Prometheus TYPE comment found in /metrics body:\n{resp.text[:500]}"
    )
    assert "gauge" in resp.text, (
        f"No 'gauge' TYPE found in /metrics body:\n{resp.text[:500]}"
    )


def test_metrics_contains_engines_total(client: TestClient) -> None:
    """fixops_engines_total metric must be present."""
    resp = client.get("/api/v1/metrics")
    assert "fixops_engines_total" in resp.text, (
        f"'fixops_engines_total' missing from /metrics:\n{resp.text[:500]}"
    )


def test_metrics_contains_routers_total(client: TestClient) -> None:
    """fixops_routers_total metric must be present."""
    resp = client.get("/api/v1/metrics")
    assert "fixops_routers_total" in resp.text, (
        f"'fixops_routers_total' missing from /metrics:\n{resp.text[:500]}"
    )
