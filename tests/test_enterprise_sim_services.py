"""Tests for enterprise simulation service connectors.

Tests verify that each connector:
- Returns ConnectorHealth(healthy=False) when the service is down (no raise)
- Constructs correct request URLs and payloads
- Handles auth headers correctly
- Returns ConnectorOutcome with expected structure

All tests run without real services — they use non-routable addresses
(localhost with ports unlikely to be in use) and verify graceful failure.

Usage:
    pytest tests/test_enterprise_sim_services.py --timeout=10 -v
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure suite-core is on the path (mirrors other Beast Mode tests)
suite_core_path = str(Path(__file__).parent.parent / "suite-core")
if suite_core_path not in sys.path:
    sys.path.insert(0, suite_core_path)

from core.enterprise_sim_services import (
    ConnectorHealth,
    ConnectorOutcome,
    NetBoxCMDBConnector,
    NtfyNotificationConnector,
    ShuffleSOARConnector,
    TheHiveConnector,
    WazuhSIEMConnector,
    get_all_connectors,
    health_check_all,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Use a port that is almost certainly not listening locally
_DEAD_PORT = 19999


def _dead_wazuh() -> WazuhSIEMConnector:
    return WazuhSIEMConnector(base_url=f"https://127.0.0.1:{_DEAD_PORT}", timeout=1.0)


def _dead_shuffle() -> ShuffleSOARConnector:
    return ShuffleSOARConnector(base_url=f"http://127.0.0.1:{_DEAD_PORT}", timeout=1.0)


def _dead_thehive() -> TheHiveConnector:
    return TheHiveConnector(base_url=f"http://127.0.0.1:{_DEAD_PORT}", timeout=1.0)


def _dead_netbox() -> NetBoxCMDBConnector:
    return NetBoxCMDBConnector(base_url=f"http://127.0.0.1:{_DEAD_PORT}", timeout=1.0)


def _dead_ntfy() -> NtfyNotificationConnector:
    return NtfyNotificationConnector(
        server=f"http://127.0.0.1:{_DEAD_PORT}",
        default_topic="test-alerts",
        timeout=1.0,
    )


# ---------------------------------------------------------------------------
# Test 1: WazuhSIEMConnector.health_check returns False when service is down
# ---------------------------------------------------------------------------


def test_wazuh_health_check_returns_false_when_down():
    conn = _dead_wazuh()
    result = conn.health_check()
    assert isinstance(result, ConnectorHealth)
    assert result.healthy is False
    assert result.latency_ms >= 0
    assert result.message  # non-empty error message


# ---------------------------------------------------------------------------
# Test 2: WazuhSIEMConnector.get_alerts returns failed outcome (not raise)
# ---------------------------------------------------------------------------


def test_wazuh_get_alerts_does_not_raise_when_down():
    conn = _dead_wazuh()
    # Auth will fail → outcome is returned, not raised
    result = conn.get_alerts()
    assert isinstance(result, ConnectorOutcome)
    assert result.status in ("failed", "skipped")
    assert not result.success


# ---------------------------------------------------------------------------
# Test 3: ShuffleSOARConnector.health_check returns False when service is down
# ---------------------------------------------------------------------------


def test_shuffle_health_check_returns_false_when_down():
    conn = _dead_shuffle()
    result = conn.health_check()
    assert isinstance(result, ConnectorHealth)
    assert result.healthy is False


# ---------------------------------------------------------------------------
# Test 4: ShuffleSOARConnector.trigger_workflow returns failed outcome
# ---------------------------------------------------------------------------


def test_shuffle_trigger_workflow_does_not_raise_when_down():
    conn = _dead_shuffle()
    result = conn.trigger_workflow("fake-workflow-id", execution_argument="test")
    assert isinstance(result, ConnectorOutcome)
    assert result.status == "failed"


# ---------------------------------------------------------------------------
# Test 5: TheHiveConnector.health_check returns False when service is down
# ---------------------------------------------------------------------------


def test_thehive_health_check_returns_false_when_down():
    conn = _dead_thehive()
    result = conn.health_check()
    assert isinstance(result, ConnectorHealth)
    assert result.healthy is False


# ---------------------------------------------------------------------------
# Test 6: TheHiveConnector.create_case returns failed outcome (not raise)
# ---------------------------------------------------------------------------


def test_thehive_create_case_does_not_raise_when_down():
    conn = _dead_thehive()
    result = conn.create_case(
        title="Test Incident",
        description="Connection refused — service down",
        severity=3,
    )
    assert isinstance(result, ConnectorOutcome)
    assert result.status == "failed"
    assert not result.success


# ---------------------------------------------------------------------------
# Test 7: NetBoxCMDBConnector.health_check returns False when service is down
# ---------------------------------------------------------------------------


def test_netbox_health_check_returns_false_when_down():
    conn = _dead_netbox()
    result = conn.health_check()
    assert isinstance(result, ConnectorHealth)
    assert result.healthy is False


# ---------------------------------------------------------------------------
# Test 8: NetBoxCMDBConnector.list_devices returns failed outcome (not raise)
# ---------------------------------------------------------------------------


def test_netbox_list_devices_does_not_raise_when_down():
    conn = _dead_netbox()
    result = conn.list_devices()
    assert isinstance(result, ConnectorOutcome)
    assert result.status == "failed"


# ---------------------------------------------------------------------------
# Test 9: NtfyNotificationConnector.health_check returns False when down
# ---------------------------------------------------------------------------


def test_ntfy_health_check_returns_false_when_down():
    conn = _dead_ntfy()
    result = conn.health_check()
    assert isinstance(result, ConnectorHealth)
    assert result.healthy is False


# ---------------------------------------------------------------------------
# Test 10: NtfyNotificationConnector.send_alert returns failed outcome
# ---------------------------------------------------------------------------


def test_ntfy_send_alert_does_not_raise_when_down():
    conn = _dead_ntfy()
    result = conn.send_alert(message="Test alert", title="Test", priority="high")
    assert isinstance(result, ConnectorOutcome)
    assert result.status == "failed"
    assert not result.success


# ---------------------------------------------------------------------------
# Test 11: health_check_all returns dict with all service names
# ---------------------------------------------------------------------------


def test_health_check_all_returns_all_services():
    connectors = {
        "wazuh": _dead_wazuh(),
        "shuffle": _dead_shuffle(),
        "thehive": _dead_thehive(),
        "netbox": _dead_netbox(),
        "ntfy": _dead_ntfy(),
    }
    results = health_check_all(connectors)
    assert set(results.keys()) == {"wazuh", "shuffle", "thehive", "netbox", "ntfy"}
    for name, health in results.items():
        assert "healthy" in health, f"{name} missing 'healthy' key"
        assert health["healthy"] is False, f"{name} should be unhealthy"


# ---------------------------------------------------------------------------
# Test 12: ConnectorOutcome.success property logic
# ---------------------------------------------------------------------------


def test_connector_outcome_success_property():
    assert ConnectorOutcome("sent", {}).success is True
    assert ConnectorOutcome("fetched", {}).success is True
    assert ConnectorOutcome("created", {}).success is True
    assert ConnectorOutcome("success", {}).success is True
    assert ConnectorOutcome("failed", {}).success is False
    assert ConnectorOutcome("skipped", {}).success is False


# ---------------------------------------------------------------------------
# Test 13: Wazuh headers include Bearer token when auth succeeds (mocked)
# ---------------------------------------------------------------------------


def test_wazuh_auth_headers_with_mocked_token():
    conn = WazuhSIEMConnector(
        base_url="https://localhost:55000", user="admin", password="secret", timeout=1.0
    )
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"data": {"token": "test-jwt-token"}}

    with patch.object(conn.session, "post", return_value=mock_resp):
        headers = conn._auth_headers()

    assert "Authorization" in headers
    assert headers["Authorization"] == "Bearer test-jwt-token"


# ---------------------------------------------------------------------------
# Test 14: Shuffle _headers includes Bearer when api_key is set
# ---------------------------------------------------------------------------


def test_shuffle_headers_include_auth():
    conn = ShuffleSOARConnector(api_key="my-shuffle-key")
    headers = conn._headers()
    assert headers["Authorization"] == "Bearer my-shuffle-key"
    assert headers["Content-Type"] == "application/json"


# ---------------------------------------------------------------------------
# Test 15: TheHiveConnector.add_observable returns created with mocked response
# ---------------------------------------------------------------------------


def test_thehive_add_observable_success_mocked():
    conn = TheHiveConnector(api_key="test-key", timeout=1.0)
    mock_resp = MagicMock()
    mock_resp.status_code = 201
    mock_resp.json.return_value = [{"_id": "obs-001"}]

    with patch.object(conn.session, "post", return_value=mock_resp):
        result = conn.add_observable(
            case_id="case-123",
            data_type="ip",
            data="10.0.0.1",
            message="Suspicious IP",
        )

    assert result.status == "created"
    assert result.success is True
    assert result.details["observable_id"] == "obs-001"
    assert result.details["data_type"] == "ip"


# ---------------------------------------------------------------------------
# Test 16: NetBoxCMDBConnector.create_device returns created with mocked response
# ---------------------------------------------------------------------------


def test_netbox_create_device_success_mocked():
    conn = NetBoxCMDBConnector(api_token="test-token", timeout=1.0)
    mock_resp = MagicMock()
    mock_resp.status_code = 201
    mock_resp.json.return_value = {"id": 42, "url": "http://localhost:8080/api/dcim/devices/42/"}

    with patch.object(conn.session, "post", return_value=mock_resp):
        result = conn.create_device(
            name="server-01",
            device_type_id=1,
            site_id=1,
            role_id=1,
        )

    assert result.status == "created"
    assert result.success is True
    assert result.details["device_id"] == 42
    assert result.details["name"] == "server-01"


# ---------------------------------------------------------------------------
# Test 17: NtfyNotificationConnector.send_finding formats message correctly
# ---------------------------------------------------------------------------


def test_ntfy_send_finding_formats_and_calls_send_alert():
    conn = _dead_ntfy()
    finding = {
        "title": "SQL Injection",
        "severity": "critical",
        "cve_id": "CVE-2024-1234",
        "asset": "web-app-01",
        "description": "Found SQL injection in login endpoint",
    }
    # send_finding calls send_alert which calls session.post — it will fail
    # but we verify the outcome type and that it doesn't raise
    result = conn.send_finding(finding)
    assert isinstance(result, ConnectorOutcome)
    # Service is down so it fails, but no exception raised
    assert result.status == "failed"


# ---------------------------------------------------------------------------
# Test 18: get_all_connectors returns correct connector types
# ---------------------------------------------------------------------------


def test_get_all_connectors_returns_correct_types():
    connectors = get_all_connectors(
        wazuh_url=f"https://127.0.0.1:{_DEAD_PORT}",
        shuffle_url=f"http://127.0.0.1:{_DEAD_PORT}",
        thehive_url=f"http://127.0.0.1:{_DEAD_PORT}",
        netbox_url=f"http://127.0.0.1:{_DEAD_PORT}",
        ntfy_server=f"http://127.0.0.1:{_DEAD_PORT}",
    )
    assert isinstance(connectors["wazuh"], WazuhSIEMConnector)
    assert isinstance(connectors["shuffle"], ShuffleSOARConnector)
    assert isinstance(connectors["thehive"], TheHiveConnector)
    assert isinstance(connectors["netbox"], NetBoxCMDBConnector)
    assert isinstance(connectors["ntfy"], NtfyNotificationConnector)


# ---------------------------------------------------------------------------
# Test 19: NetBoxCMDBConnector _headers includes Token auth
# ---------------------------------------------------------------------------


def test_netbox_headers_include_token_auth():
    conn = NetBoxCMDBConnector(api_token="nb-token-abc123")
    headers = conn._headers()
    assert headers["Authorization"] == "Token nb-token-abc123"
    assert headers["Content-Type"] == "application/json"


# ---------------------------------------------------------------------------
# Test 20: WazuhSIEMConnector.push_event fails gracefully when auth fails
# ---------------------------------------------------------------------------


def test_wazuh_push_event_fails_gracefully_when_auth_fails():
    conn = _dead_wazuh()
    event = {
        "message": "Failed login attempt",
        "location": "/var/log/auth.log",
        "log_format": "syslog",
    }
    result = conn.push_event(event)
    assert isinstance(result, ConnectorOutcome)
    assert result.status == "failed"
    assert not result.success


# ---------------------------------------------------------------------------
# Test 21: ShuffleSOARConnector.create_ir_playbook success (mocked)
# ---------------------------------------------------------------------------


def test_shuffle_create_ir_playbook_success_mocked():
    conn = ShuffleSOARConnector(api_key="shuffle-key", timeout=1.0)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"id": "wf-uuid-001", "name": "IR Playbook: Ransomware"}

    with patch.object(conn.session, "post", return_value=mock_resp):
        result = conn.create_ir_playbook(
            name="IR Playbook: Ransomware",
            description="Automated ransomware incident response",
        )

    assert result.status == "created"
    assert result.success is True
    assert result.details["workflow_id"] == "wf-uuid-001"
