"""Tests for DefenderXDRLiveConnector.

4 tests:
1. Missing creds → graceful no-op (needs_credentials)
2. Mock Graph API response parses and persists correctly
3. Live API call (skipped if creds absent)
4. Pagination: @odata.nextLink followed correctly
"""
from __future__ import annotations

import os
import json
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

import sys
sys.path.insert(0, "/Users/devops.ai/fixops/Fixops")
sys.path.insert(0, "/Users/devops.ai/fixops/Fixops/suite-core")


def _mock_findings():
    fe = MagicMock()
    fe.record_finding.return_value = {"id": "test-finding-id-xdr"}
    return fe


# ---------------------------------------------------------------------------
# Test 1: missing creds → graceful no-op
# ---------------------------------------------------------------------------
def test_defender_missing_creds_graceful_noop():
    env_patch = {
        "DEFENDER_TENANT_ID": "",
        "DEFENDER_CLIENT_ID": "",
        "DEFENDER_CLIENT_SECRET": "",
    }
    with patch.dict(os.environ, env_patch, clear=False):
        from connectors.defender_xdr_live_connector import DefenderXDRLiveConnector
        connector = DefenderXDRLiveConnector(findings_engine=_mock_findings())
        result = connector.fetch_alerts(org_id="test-org")

    assert result["status"] == "needs_credentials"
    assert result["mode"] == "no-op"
    assert result["alert_count"] == 0
    assert result["findings_recorded"] == 0
    assert "hint" in result
    assert isinstance(result["alerts"], list)


# ---------------------------------------------------------------------------
# Test 2: mock Graph API response parses and persists correctly
# ---------------------------------------------------------------------------
def test_defender_mock_api_parses_correctly():
    from connectors.defender_xdr_live_connector import DefenderXDRLiveConnector
    from connectors.defender_xdr_connector import _DEFENDER_FALLBACK_ALERTS

    fe = _mock_findings()
    connector = DefenderXDRLiveConnector(findings_engine=fe)

    # Use first 3 fallback alerts as mock API response
    sample_alerts = _DEFENDER_FALLBACK_ALERTS[:3]

    with patch.dict(os.environ, {
        "DEFENDER_TENANT_ID": "fake-tenant-id",
        "DEFENDER_CLIENT_ID": "fake-client-id",
        "DEFENDER_CLIENT_SECRET": "fake-secret",
    }), \
    patch("connectors.defender_xdr_live_connector._get_graph_token",
          return_value="bearer-tok"), \
    patch("connectors.defender_xdr_live_connector._fetch_all_alerts",
          return_value=sample_alerts):

        result = connector.fetch_alerts(org_id="test-org-xdr", force_refresh=True)

    assert result["status"] == "ok"
    assert result["mode"] == "live"
    assert result["alert_count"] == 3
    assert result["findings_recorded"] == 3
    assert len(result["alerts"]) == 3

    # Verify normalized alert shape
    alert = result["alerts"][0]
    assert "title" in alert
    assert "severity" in alert
    assert alert["severity"] in {"informational", "low", "medium", "high", "critical"}
    assert "finding_type" in alert

    # Verify record_finding called with correct args
    assert fe.record_finding.call_count == 3
    kwargs = fe.record_finding.call_args_list[0][1]
    assert kwargs["org_id"] == "test-org-xdr"
    assert kwargs["source_tool"] == "defender_xdr"
    assert kwargs["correlation_key"].startswith("defender_xdr|")


# ---------------------------------------------------------------------------
# Test 3: live API call (skipped if creds absent)
# ---------------------------------------------------------------------------
@pytest.mark.skipif(
    not all(os.environ.get(v) for v in (
        "DEFENDER_TENANT_ID", "DEFENDER_CLIENT_ID", "DEFENDER_CLIENT_SECRET"
    )),
    reason="DEFENDER_TENANT_ID / DEFENDER_CLIENT_ID / DEFENDER_CLIENT_SECRET not set",
)
def test_defender_live_api_call():
    from connectors.defender_xdr_live_connector import DefenderXDRLiveConnector
    connector = DefenderXDRLiveConnector(findings_engine=_mock_findings(), max_alerts=10)
    result = connector.fetch_alerts(org_id="live-test-org", force_refresh=True)
    assert result["status"] in {"ok", "api_error", "partial"}
    assert isinstance(result["alert_count"], int)
    assert isinstance(result["alerts"], list)


# ---------------------------------------------------------------------------
# Test 4: pagination — @odata.nextLink followed correctly
# ---------------------------------------------------------------------------
def test_defender_pagination_follows_next_link():
    """_fetch_all_alerts follows @odata.nextLink until exhausted."""
    from connectors.defender_xdr_live_connector import _fetch_all_alerts
    from connectors.defender_xdr_connector import _DEFENDER_FALLBACK_ALERTS

    page1_alerts = _DEFENDER_FALLBACK_ALERTS[:3]
    page2_alerts = _DEFENDER_FALLBACK_ALERTS[3:6]
    page3_alerts = _DEFENDER_FALLBACK_ALERTS[6:8]

    responses = [
        {"value": page1_alerts, "@odata.nextLink": "https://graph.microsoft.com/page2"},
        {"value": page2_alerts, "@odata.nextLink": "https://graph.microsoft.com/page3"},
        {"value": page3_alerts},  # no nextLink = last page
    ]
    call_count = 0

    class MockResp:
        def __init__(self, data):
            self._data = data
        def raise_for_status(self):
            pass
        def json(self):
            return self._data

    def mock_get(url, params=None, headers=None, timeout=None):
        nonlocal call_count
        resp = MockResp(responses[call_count])
        call_count += 1
        return resp

    with patch("httpx.get", side_effect=mock_get):
        alerts = _fetch_all_alerts(token="tok", max_alerts=100, filter_str=None)

    expected_count = len(page1_alerts) + len(page2_alerts) + len(page3_alerts)
    assert len(alerts) == expected_count
    assert call_count == 3
