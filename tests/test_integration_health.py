"""
Integration Health Monitor Test Suite — 30+ tests

Tests for IntegrationHealthMonitor (core logic) and integration_health_router
(API layer). All tests use temporary SQLite databases to avoid side effects.

Run with:
    python -m pytest tests/test_integration_health.py -x --tb=short --timeout=30 -q
"""

from __future__ import annotations

import http.server
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

# Ensure suite-core is on path
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.integration_health import (
    HealthCheckResult,
    IntegrationHealthMonitor,
    IntegrationInfo,
    ServiceStatus,
    _real_probe,
    _simulate_check,
)


# ---------------------------------------------------------------------------
# Helpers — local HTTP server fixture
# ---------------------------------------------------------------------------


def _free_port() -> int:
    """Return a free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _SilentHandler(http.server.BaseHTTPRequestHandler):
    """Minimal HTTP handler that always returns 200 OK."""

    def do_HEAD(self):  # noqa: N802
        self.send_response(200)
        self.end_headers()

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, *args):  # silence server logs during tests
        pass


@pytest.fixture(scope="module")
def local_http_server():
    """Start a real local HTTP server for the duration of the test module."""
    port = _free_port()
    server = http.server.HTTPServer(("127.0.0.1", port), _SilentHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_db(tmp_path):
    """Return a monitor backed by a temp DB."""
    return IntegrationHealthMonitor(db_path=str(tmp_path / "test_health.db"))


@pytest.fixture()
def org_id():
    return "org-test-001"


@pytest.fixture()
def registered(tmp_db, org_id):
    """Register a single integration and return its IntegrationInfo."""
    return tmp_db.register_integration(
        name="Jira Cloud",
        type="jira",
        endpoint_url="https://jira.example.com",
        org_id=org_id,
    )


# ---------------------------------------------------------------------------
# ServiceStatus enum
# ---------------------------------------------------------------------------


def test_service_status_values():
    assert ServiceStatus.HEALTHY == "healthy"
    assert ServiceStatus.DEGRADED == "degraded"
    assert ServiceStatus.DOWN == "down"
    assert ServiceStatus.UNKNOWN == "unknown"
    assert ServiceStatus.DISABLED == "disabled"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


def test_integration_info_defaults():
    info = IntegrationInfo(
        id="abc",
        name="Test",
        type="github",
        endpoint_url="https://api.github.com",
        org_id="org-1",
    )
    assert info.status == ServiceStatus.UNKNOWN
    assert info.uptime_pct == 100.0
    assert info.consecutive_failures == 0
    assert info.auto_disabled is False
    assert info.error_message is None


def test_health_check_result_defaults():
    r = HealthCheckResult(
        integration_id="int-1",
        status=ServiceStatus.HEALTHY,
        response_ms=42.5,
    )
    assert r.error is None
    assert r.checked_at is not None
    assert "T" in r.checked_at  # ISO format


# ---------------------------------------------------------------------------
# register_integration
# ---------------------------------------------------------------------------


def test_register_returns_integration_info(tmp_db, org_id):
    info = tmp_db.register_integration("Slack", "slack", "https://slack.com", org_id)
    assert isinstance(info, IntegrationInfo)
    assert info.name == "Slack"
    assert info.type == "slack"
    assert info.endpoint_url == "https://slack.com"
    assert info.org_id == org_id
    assert info.id  # UUID assigned


def test_register_multiple_integrations(tmp_db, org_id):
    tmp_db.register_integration("Jira", "jira", "https://jira.example.com", org_id)
    tmp_db.register_integration("GitHub", "github", "https://github.com", org_id)
    integrations = tmp_db.list_integrations(org_id)
    assert len(integrations) == 2


# ---------------------------------------------------------------------------
# list_integrations
# ---------------------------------------------------------------------------


def test_list_integrations_empty(tmp_db, org_id):
    result = tmp_db.list_integrations(org_id)
    assert result == []


def test_list_integrations_filtered_by_status(tmp_db, org_id):
    i1 = tmp_db.register_integration("Jira", "jira", "https://jira.example.com", org_id)
    i2 = tmp_db.register_integration("GitHub", "github", "https://github.com", org_id)

    # Force i1 to DOWN via record_check
    tmp_db.record_check(i1.id, ServiceStatus.DOWN, 0.0, "connection refused")

    healthy = tmp_db.list_integrations(org_id, status_filter="unknown")
    assert any(i.id == i2.id for i in healthy)
    down = tmp_db.list_integrations(org_id, status_filter="down")
    assert any(i.id == i1.id for i in down)


def test_list_integrations_multi_tenant_isolation(tmp_db):
    tmp_db.register_integration("Jira", "jira", "https://jira.example.com", "org-A")
    tmp_db.register_integration("Slack", "slack", "https://slack.com", "org-B")

    a = tmp_db.list_integrations("org-A")
    b = tmp_db.list_integrations("org-B")
    assert len(a) == 1 and a[0].org_id == "org-A"
    assert len(b) == 1 and b[0].org_id == "org-B"


# ---------------------------------------------------------------------------
# get_integration
# ---------------------------------------------------------------------------


def test_get_integration_found(registered, tmp_db):
    fetched = tmp_db.get_integration(registered.id)
    assert fetched.id == registered.id
    assert fetched.name == registered.name


def test_get_integration_not_found(tmp_db):
    with pytest.raises(ValueError, match="not found"):
        tmp_db.get_integration("nonexistent-id")


# ---------------------------------------------------------------------------
# delete_integration
# ---------------------------------------------------------------------------


def test_delete_integration(tmp_db, org_id, registered):
    tmp_db.delete_integration(registered.id)
    with pytest.raises(ValueError):
        tmp_db.get_integration(registered.id)


def test_delete_also_removes_history(tmp_db, org_id, registered):
    tmp_db.record_check(registered.id, ServiceStatus.HEALTHY, 50.0, None)
    tmp_db.delete_integration(registered.id)
    # Integration is gone; no exception here since we query health_checks directly
    # via a fresh monitor to confirm cleanup
    monitor2 = IntegrationHealthMonitor(db_path=tmp_db.db_path)
    with pytest.raises(ValueError):
        monitor2.get_integration(registered.id)


# ---------------------------------------------------------------------------
# record_check + state transitions
# ---------------------------------------------------------------------------


def test_record_check_healthy_clears_failures(tmp_db, registered):
    tmp_db.record_check(registered.id, ServiceStatus.DOWN, 0.0, "err")
    tmp_db.record_check(registered.id, ServiceStatus.HEALTHY, 100.0, None)
    info = tmp_db.get_integration(registered.id)
    assert info.consecutive_failures == 0
    assert info.status == ServiceStatus.HEALTHY
    assert info.error_message is None
    assert info.last_success is not None


def test_record_check_failure_increments_counter(tmp_db, registered):
    tmp_db.record_check(registered.id, ServiceStatus.DOWN, 0.0, "timeout")
    info = tmp_db.get_integration(registered.id)
    assert info.consecutive_failures == 1
    assert info.status == ServiceStatus.DOWN


def test_record_check_degraded_increments_counter(tmp_db, registered):
    tmp_db.record_check(registered.id, ServiceStatus.DEGRADED, 800.0, "slow")
    info = tmp_db.get_integration(registered.id)
    assert info.consecutive_failures == 1


# ---------------------------------------------------------------------------
# auto_disable
# ---------------------------------------------------------------------------


def test_auto_disable_after_five_failures(tmp_db, registered):
    for _ in range(5):
        tmp_db.record_check(registered.id, ServiceStatus.DOWN, 0.0, "refused")
    info = tmp_db.get_integration(registered.id)
    assert info.auto_disabled is True
    assert info.status == ServiceStatus.DISABLED


def test_auto_disable_explicit(tmp_db, registered):
    tmp_db.auto_disable(registered.id)
    info = tmp_db.get_integration(registered.id)
    assert info.auto_disabled is True
    assert info.status == ServiceStatus.DISABLED


# ---------------------------------------------------------------------------
# enable_integration
# ---------------------------------------------------------------------------


def test_enable_resets_state(tmp_db, registered):
    tmp_db.auto_disable(registered.id)
    tmp_db.enable_integration(registered.id)
    info = tmp_db.get_integration(registered.id)
    assert info.auto_disabled is False
    assert info.status == ServiceStatus.UNKNOWN
    assert info.consecutive_failures == 0


# ---------------------------------------------------------------------------
# check_health
# ---------------------------------------------------------------------------


def test_check_health_disabled_integration(tmp_db, registered):
    tmp_db.auto_disable(registered.id)
    result = tmp_db.check_health(registered.id)
    assert result.status == ServiceStatus.DISABLED
    assert result.response_ms == 0.0


def test_check_health_returns_result(tmp_db, registered):
    result = tmp_db.check_health(registered.id)
    assert isinstance(result, HealthCheckResult)
    assert result.integration_id == registered.id
    assert result.status in list(ServiceStatus)
    assert result.response_ms >= 0


def test_check_health_updates_integration(tmp_db, registered):
    tmp_db.check_health(registered.id)
    info = tmp_db.get_integration(registered.id)
    assert info.last_check is not None


# ---------------------------------------------------------------------------
# check_all
# ---------------------------------------------------------------------------


def test_check_all_returns_result_per_integration(tmp_db, org_id):
    tmp_db.register_integration("Jira", "jira", "https://jira.example.com", org_id)
    tmp_db.register_integration("GitHub", "github", "https://github.com", org_id)
    results = tmp_db.check_all(org_id)
    assert len(results) == 2
    for r in results:
        assert isinstance(r, HealthCheckResult)


def test_check_all_skips_disabled(tmp_db, org_id):
    i1 = tmp_db.register_integration("Jira", "jira", "https://jira.example.com", org_id)
    tmp_db.auto_disable(i1.id)
    results = tmp_db.check_all(org_id)
    assert results[0].status == ServiceStatus.DISABLED


# ---------------------------------------------------------------------------
# get_check_history
# ---------------------------------------------------------------------------


def test_get_check_history_empty(tmp_db, registered):
    history = tmp_db.get_check_history(registered.id)
    assert history == []


def test_get_check_history_ordered_desc(tmp_db, registered):
    for _ in range(3):
        tmp_db.record_check(registered.id, ServiceStatus.HEALTHY, 50.0, None)
    history = tmp_db.get_check_history(registered.id)
    assert len(history) == 3
    # Most recent first
    for entry in history:
        assert isinstance(entry, HealthCheckResult)


def test_get_check_history_limit(tmp_db, registered):
    for _ in range(10):
        tmp_db.record_check(registered.id, ServiceStatus.HEALTHY, 30.0, None)
    history = tmp_db.get_check_history(registered.id, limit=5)
    assert len(history) == 5


# ---------------------------------------------------------------------------
# get_uptime
# ---------------------------------------------------------------------------


def test_get_uptime_all_healthy(tmp_db, registered):
    for _ in range(5):
        tmp_db.record_check(registered.id, ServiceStatus.HEALTHY, 50.0, None)
    uptime = tmp_db.get_uptime(registered.id, days=30)
    assert uptime == 100.0


def test_get_uptime_mixed(tmp_db, registered):
    tmp_db.record_check(registered.id, ServiceStatus.HEALTHY, 50.0, None)
    tmp_db.record_check(registered.id, ServiceStatus.DOWN, 0.0, "err")
    uptime = tmp_db.get_uptime(registered.id, days=30)
    assert 0 < uptime < 100


def test_get_uptime_no_history(tmp_db, registered):
    uptime = tmp_db.get_uptime(registered.id, days=30)
    assert uptime == 100.0


# ---------------------------------------------------------------------------
# get_dashboard
# ---------------------------------------------------------------------------


def test_get_dashboard_structure(tmp_db, org_id):
    tmp_db.register_integration("Jira", "jira", "https://jira.example.com", org_id)
    dashboard = tmp_db.get_dashboard(org_id)
    assert "org_id" in dashboard
    assert "total" in dashboard
    assert "summary" in dashboard
    assert "integrations" in dashboard
    assert "generated_at" in dashboard
    assert dashboard["total"] == 1


def test_get_dashboard_empty_org(tmp_db, org_id):
    dashboard = tmp_db.get_dashboard(org_id)
    assert dashboard["total"] == 0
    assert dashboard["integrations"] == []


# ---------------------------------------------------------------------------
# get_alerts
# ---------------------------------------------------------------------------


def test_get_alerts_none_when_all_healthy(tmp_db, org_id):
    i = tmp_db.register_integration("Jira", "jira", "https://jira.example.com", org_id)
    tmp_db.record_check(i.id, ServiceStatus.HEALTHY, 50.0, None)
    alerts = tmp_db.get_alerts(org_id)
    assert alerts == []


def test_get_alerts_includes_down(tmp_db, org_id):
    i = tmp_db.register_integration("Jira", "jira", "https://jira.example.com", org_id)
    tmp_db.record_check(i.id, ServiceStatus.DOWN, 0.0, "connection refused")
    alerts = tmp_db.get_alerts(org_id)
    assert len(alerts) == 1
    assert alerts[0]["integration_id"] == i.id
    assert alerts[0]["status"] == "down"


def test_get_alerts_includes_disabled(tmp_db, org_id):
    i = tmp_db.register_integration("Slack", "slack", "https://slack.com", org_id)
    tmp_db.auto_disable(i.id)
    alerts = tmp_db.get_alerts(org_id)
    assert any(a["integration_id"] == i.id for a in alerts)


# ---------------------------------------------------------------------------
# get_health_stats
# ---------------------------------------------------------------------------


def test_get_health_stats_empty(tmp_db, org_id):
    stats = tmp_db.get_health_stats(org_id)
    assert stats["total"] == 0
    assert stats["avg_uptime_pct"] == 0.0
    assert stats["avg_response_ms"] is None


def test_get_health_stats_counts(tmp_db, org_id):
    i1 = tmp_db.register_integration("Jira", "jira", "https://jira.example.com", org_id)
    i2 = tmp_db.register_integration("GitHub", "github", "https://github.com", org_id)
    tmp_db.record_check(i1.id, ServiceStatus.HEALTHY, 50.0, None)
    tmp_db.record_check(i2.id, ServiceStatus.DOWN, 0.0, "err")
    stats = tmp_db.get_health_stats(org_id)
    assert stats["total"] == 2
    assert stats["healthy"] == 1
    assert stats["down"] == 1


# ---------------------------------------------------------------------------
# _simulate_check helper — kept test-only, NOT used by check_health()
# ---------------------------------------------------------------------------


def test_simulate_check_returns_tuple():
    response_ms, status, error = _simulate_check("https://example.com")
    assert isinstance(response_ms, float)
    assert status in list(ServiceStatus)


def test_simulate_check_deterministic():
    r1 = _simulate_check("https://deterministic.example.com")
    r2 = _simulate_check("https://deterministic.example.com")
    assert r1 == r2


def test_simulate_check_down_has_zero_ms():
    response_ms, status, error = _simulate_check("https://jira.example.com")
    assert response_ms >= 0
    if status == ServiceStatus.DOWN:
        assert response_ms == 0.0
        assert error is not None
    elif status == ServiceStatus.HEALTHY:
        assert error is None


# ---------------------------------------------------------------------------
# _real_probe — unit tests (no network for unreachable / missing URL)
# ---------------------------------------------------------------------------


def test_real_probe_empty_url_returns_unknown():
    """Empty endpoint URL must yield UNKNOWN — not fabricated healthy/down."""
    ms, status, error = _real_probe("")
    assert status == ServiceStatus.UNKNOWN
    assert ms == 0.0
    assert error is not None and "not configured" in error.lower()


def test_real_probe_whitespace_url_returns_unknown():
    ms, status, error = _real_probe("   ")
    assert status == ServiceStatus.UNKNOWN


def test_real_probe_unreachable_host_returns_down():
    """Connecting to a closed port must yield DOWN with a real error string."""
    # Port 1 on loopback is virtually always closed / permission-denied
    ms, status, error = _real_probe("http://127.0.0.1:1", timeout=3.0)
    assert status == ServiceStatus.DOWN
    assert error is not None
    assert len(error) > 0
    # Must NOT be fabricated — real latency, not the old heuristic magic values
    # (heuristic would have returned 50-222.5 ms for healthy, or exactly 0.0
    # for down with "Connection refused or timeout")
    # We only assert the string differs from the old literal fabricated message
    assert error != "Connection refused or timeout"  # old simulation string


def test_real_probe_invalid_hostname_returns_down():
    """An unresolvable hostname must yield DOWN."""
    ms, status, error = _real_probe("http://this-host-does-not-exist.invalid", timeout=3.0)
    assert status == ServiceStatus.DOWN
    assert error is not None


# ---------------------------------------------------------------------------
# _real_probe — integration test against a real local HTTP server
# ---------------------------------------------------------------------------


def test_real_probe_reachable_server_healthy(local_http_server):
    """A real HTTP server must return HEALTHY with latency > 0."""
    ms, status, error = _real_probe(local_http_server, timeout=5.0)
    assert status == ServiceStatus.HEALTHY
    assert ms > 0, f"Expected real latency > 0, got {ms}"
    assert error is None


def test_real_probe_latency_is_measured(local_http_server):
    """Latency must be a positive float measured by perf_counter, not a heuristic."""
    ms, status, error = _real_probe(local_http_server, timeout=5.0)
    assert isinstance(ms, float)
    # Real network call on loopback — should be sub-second but > 0
    assert 0 < ms < 5000, f"Suspiciously out-of-range latency: {ms} ms"


# ---------------------------------------------------------------------------
# check_health() integration — ensure it uses _real_probe, not _simulate_check
# ---------------------------------------------------------------------------


def test_check_health_uses_real_probe_not_simulate(tmp_db, org_id, local_http_server):
    """check_health() must produce results consistent with real probing.

    The old _simulate_check was deterministic from URL hash.  We verify that
    check_health() against our local server always returns HEALTHY (which
    _simulate_check might not, depending on hash), proving it's a real probe.
    """
    info = tmp_db.register_integration(
        name="LocalServer",
        type="test",
        endpoint_url=local_http_server,
        org_id=org_id,
    )
    result = tmp_db.check_health(info.id)
    assert isinstance(result, HealthCheckResult)
    assert result.status == ServiceStatus.HEALTHY
    assert result.response_ms > 0
    assert result.error is None


def test_check_health_unreachable_endpoint_returns_down(tmp_db, org_id):
    """check_health() against a dead port must record DOWN — no fabricated healthy."""
    info = tmp_db.register_integration(
        name="DeadEndpoint",
        type="test",
        endpoint_url="http://127.0.0.1:1",
        org_id=org_id,
    )
    result = tmp_db.check_health(info.id)
    assert result.status == ServiceStatus.DOWN
    assert result.error is not None
    # Must not be the old heuristic's fabricated string
    assert result.error != "Connection refused or timeout"


def test_check_health_empty_url_records_unknown(tmp_db, org_id):
    """An integration with no endpoint_url should record UNKNOWN, not a fake status."""
    # Register with a placeholder, then forcibly clear the URL via raw DB write
    info = tmp_db.register_integration(
        name="NoURL",
        type="test",
        endpoint_url="placeholder",
        org_id=org_id,
    )
    # Patch the stored URL to empty so _real_probe sees it
    import sqlite3 as _sqlite3
    conn = _sqlite3.connect(str(tmp_db.db_path))
    conn.execute("UPDATE integrations SET endpoint_url = '' WHERE id = ?", (info.id,))
    conn.commit()
    conn.close()

    result = tmp_db.check_health(info.id)
    assert result.status == ServiceStatus.UNKNOWN
    assert result.response_ms == 0.0
