"""Tests for the Prometheus metrics endpoint — metrics_router.py.

Covers:
  1. Prometheus text format structure and required metric families
  2. Label syntax correctness
  3. JSON summary endpoint returns expected keys

Total: 3 tests.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# App fixture — import lazily so sitecustomize path injection works
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    from apps.api.app import create_app
    app = create_app()
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


_HEADERS = {"X-API-Key": "test-key"}
_PARAMS = {"org_id": "test-org"}


# ---------------------------------------------------------------------------
# 1. Prometheus exposition format — structure and required families
# ---------------------------------------------------------------------------

def test_prometheus_endpoint_structure(client):
    """GET /api/v1/metrics/prometheus returns text/plain with required metric families."""
    resp = client.get("/api/v1/metrics/prometheus", headers=_HEADERS, params=_PARAMS)
    assert resp.status_code == 200, resp.text

    ct = resp.headers.get("content-type", "")
    assert "text/plain" in ct, f"Expected text/plain content-type, got: {ct}"

    body = resp.text

    # Required HELP lines
    required_metrics = [
        "aldeci_alerts_total",
        "aldeci_posture_score",
        "aldeci_engine_count",
        "aldeci_uptime_seconds",
        "aldeci_scrape_timestamp_seconds",
    ]
    for metric in required_metrics:
        assert f"# HELP {metric}" in body, f"Missing HELP for {metric}"
        assert f"# TYPE {metric}" in body, f"Missing TYPE for {metric}"


# ---------------------------------------------------------------------------
# 2. Prometheus label syntax — severity labels present, values are numbers
# ---------------------------------------------------------------------------

def test_prometheus_alert_labels_and_values(client):
    """Severity labels appear with numeric values in correct Prometheus format."""
    resp = client.get("/api/v1/metrics/prometheus", headers=_HEADERS, params=_PARAMS)
    assert resp.status_code == 200

    body = resp.text
    lines = body.splitlines()

    # Find all aldeci_alerts_total metric lines (not HELP/TYPE)
    alert_lines = [
        ln for ln in lines
        if ln.startswith("aldeci_alerts_total{") and not ln.startswith("#")
    ]

    severities_found = set()
    for line in alert_lines:
        # Format: aldeci_alerts_total{severity="<sev>"} <number>
        assert 'severity="' in line, f"Expected severity label in: {line}"
        parts = line.rsplit(" ", 1)
        assert len(parts) == 2, f"Unexpected line format: {line}"
        value_str = parts[1]
        float(value_str)  # must be a valid number — raises ValueError if not

        # Extract severity value
        sev_start = line.index('severity="') + len('severity="')
        sev_end = line.index('"', sev_start)
        severities_found.add(line[sev_start:sev_end])

    expected_severities = {"critical", "high", "medium", "low", "info"}
    assert expected_severities == severities_found, (
        f"Expected severities {expected_severities}, got {severities_found}"
    )


# ---------------------------------------------------------------------------
# 3. JSON summary endpoint — required top-level keys present
# ---------------------------------------------------------------------------

def test_metrics_summary_json_keys(client):
    """GET /api/v1/metrics/summary returns JSON with all required top-level keys."""
    resp = client.get("/api/v1/metrics/summary", headers=_HEADERS, params=_PARAMS)
    assert resp.status_code == 200

    data = resp.json()
    for key in ("org_id", "alerts", "posture", "engine_count", "uptime_seconds", "scraped_at"):
        assert key in data, f"Missing key '{key}' in summary response"

    assert data["engine_count"] > 0, "engine_count should be positive"
    assert data["uptime_seconds"] >= 0, "uptime_seconds must be non-negative"

    alerts = data["alerts"]
    for sev in ("critical", "high", "medium", "low", "info", "total"):
        assert sev in alerts, f"Missing severity '{sev}' in alerts dict"

    posture = data["posture"]
    assert "overall_score" in posture
    assert "grade" in posture
