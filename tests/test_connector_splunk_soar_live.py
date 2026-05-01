"""Tests for Splunk SOAR / Phantom Live Connector.

4 tests:
1. Missing creds → graceful no-op (needs_credentials)
2. Mock API response parses correctly
3. Live API call (skipped if creds absent)
4. Pagination: multiple pages of containers collected
"""
from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest
import sys

sys.path.insert(0, "/Users/devops.ai/fixops/Fixops")
sys.path.insert(0, "/Users/devops.ai/fixops/Fixops/suite-core")


def _mock_findings():
    fe = MagicMock()
    fe.record_finding.return_value = {"id": "test-finding-soar-001"}
    return fe


def test_splunk_soar_missing_creds_graceful_noop():
    """When SPLUNK_SOAR_TOKEN absent → needs_credentials, no crash."""
    env_patch = {"SPLUNK_SOAR_TOKEN": "", "SPLUNK_SOAR_BASE_URL": ""}
    with patch.dict(os.environ, env_patch, clear=False):
        from connectors.splunk_soar_connector import SplunkSOARConnector
        connector = SplunkSOARConnector(findings_engine=_mock_findings())
        result = connector.sync(org_id="test-org")

    assert result["status"] == "needs_credentials"
    assert result["mode"] == "no-op"
    assert result["containers_synced"] == 0
    assert isinstance(result["findings"], list)
    assert "hint" in result


def test_splunk_soar_mock_api_parses_correctly():
    """A mocked SOAR containers response normalizes to ALDECI shape."""
    from connectors.splunk_soar_connector import SplunkSOARConnector

    fe = _mock_findings()
    connector = SplunkSOARConnector(findings_engine=fe)

    sample_containers = [
        {
            "id": 42,
            "name": "Phishing Alert — Finance Team",
            "description": "Suspicious email targeting finance team.",
            "severity": "high",
            "status": "open",
            "label": "phishing",
            "owner_name": "soc_analyst",
            "asset_name": "email-gateway",
            "artifact_count": 5,
            "create_time": "2024-01-15T10:00:00Z",
        }
    ]

    with patch.dict(os.environ, {
        "SPLUNK_SOAR_TOKEN": "fake-token",
        "SPLUNK_SOAR_BASE_URL": "https://soar.test.com",
    }), \
    patch("connectors.splunk_soar_connector._paginate", return_value=sample_containers):
        result = connector.sync(org_id="test-org", force_refresh=True)

    assert result["status"] == "ok"
    assert result["containers_synced"] == 1
    assert result["findings_recorded"] == 1
    assert len(result["findings"]) == 1

    finding = result["findings"][0]
    assert finding["asset_type"] == "soar_incident"
    assert finding["source_tool"] == "splunk_soar"
    assert finding["finding_type"] == "incident"
    assert finding["severity"] == "high"
    assert finding["correlation_key"] == "soar_container|42"
    assert finding["artifact_count"] == 5


@pytest.mark.skipif(
    not (os.environ.get("SPLUNK_SOAR_TOKEN") and os.environ.get("SPLUNK_SOAR_BASE_URL")),
    reason="SPLUNK_SOAR_TOKEN / SPLUNK_SOAR_BASE_URL not set",
)
def test_splunk_soar_live_api_call():
    """Live integration test — requires real Splunk SOAR credentials."""
    from connectors.splunk_soar_connector import SplunkSOARConnector
    connector = SplunkSOARConnector(findings_engine=_mock_findings(), max_containers=5)
    result = connector.sync(org_id="live-test-org", force_refresh=True)

    assert result["status"] in ("ok", "api_error", "needs_credentials")
    assert isinstance(result["findings"], list)


def test_splunk_soar_pagination_collects_all_pages():
    """_paginate collects containers across multiple pages."""
    from connectors.splunk_soar_connector import _paginate

    page1 = {"data": [{"id": 1, "name": "C1"}], "count": 2}
    page2 = {"data": [{"id": 2, "name": "C2"}], "count": 2}
    page3 = {"data": [], "count": 2}  # terminal empty page

    responses = [page1, page2, page3]
    call_count = 0

    class MockResp:
        def __init__(self, data):
            self._data = data
            self.status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return self._data

    def mock_get(url, **kwargs):
        nonlocal call_count
        resp = MockResp(responses[min(call_count, len(responses) - 1)])
        call_count += 1
        return resp

    with patch("httpx.get", side_effect=mock_get):
        items = _paginate(
            base_url="https://soar.test.com",
            endpoint="/rest/container",
        )

    assert len(items) == 2
    assert items[0]["id"] == 1
    assert items[1]["id"] == 2
