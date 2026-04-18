"""Tests for Prometheus metrics router — metrics_router.py.

Tests the metric collection helpers and Prometheus text format builder
directly, without spinning up the full FastAPI application (avoids OTEL
retry timeouts). A thin FastAPI test client is used for the endpoint test.

Total: 3 tests.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Helpers — import the router module functions directly
# ---------------------------------------------------------------------------

from apps.api.metrics_router import (
    _build_prometheus_text,
    _collect_alert_metrics,
    _collect_posture_metrics,
    _prom_line,
)


# ---------------------------------------------------------------------------
# 1. Prometheus exposition format — structure and required metric families
# ---------------------------------------------------------------------------

def test_prometheus_text_structure():
    """_build_prometheus_text returns text with all required HELP/TYPE blocks."""
    body = _build_prometheus_text("test-org")

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

    # Must end with a newline per Prometheus exposition spec
    assert body.endswith("\n")


# ---------------------------------------------------------------------------
# 2. Alert severity labels — correct format and all severities present
# ---------------------------------------------------------------------------

def test_prometheus_alert_severity_labels():
    """Each severity label produces a valid Prometheus metric line with a numeric value."""
    body = _build_prometheus_text("test-org")
    lines = body.splitlines()

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
        float(parts[1])  # must be a valid number

        sev_start = line.index('severity="') + len('severity="')
        sev_end = line.index('"', sev_start)
        severities_found.add(line[sev_start:sev_end])

    assert severities_found == {"critical", "high", "medium", "low", "info"}


# ---------------------------------------------------------------------------
# 3. Endpoint returns 200 text/plain via a minimal test app
# ---------------------------------------------------------------------------

def test_prometheus_endpoint_returns_text_plain():
    """GET /api/v1/metrics/prometheus returns 200 with text/plain content-type."""
    from apps.api.metrics_router import router

    # Build a minimal app with auth dependency overridden to a no-op
    app = FastAPI()

    async def _noop_auth():
        return None

    from apps.api.auth_deps import api_key_auth
    app.dependency_overrides[api_key_auth] = _noop_auth
    app.include_router(router)

    with TestClient(app, raise_server_exceptions=True) as client:
        resp = client.get("/api/v1/metrics/prometheus", params={"org_id": "test-org"})

    assert resp.status_code == 200, resp.text
    ct = resp.headers.get("content-type", "")
    assert "text/plain" in ct, f"Unexpected content-type: {ct}"
    # Spot-check a required metric is present
    assert "aldeci_engine_count" in resp.text
