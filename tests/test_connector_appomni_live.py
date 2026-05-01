"""Tests for AppOmni Live Connector (SSPM).

4 tests:
1. Missing creds → graceful no-op (needs_credentials)
2. Mock API response parses correctly
3. Live API call (skipped if creds absent)
4. _normalize_finding produces correct ALDECI finding shape
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
    fe.record_finding.return_value = {"id": "test-finding-appomni-001"}
    return fe


def test_appomni_missing_creds_graceful_noop():
    """When APPOMNI_API_KEY absent → needs_credentials, no crash."""
    env_patch = {"APPOMNI_API_KEY": ""}
    with patch.dict(os.environ, env_patch, clear=False):
        from connectors.appomni_connector import AppOmniConnector
        connector = AppOmniConnector(findings_engine=_mock_findings())
        result = connector.sync(org_id="test-org")

    assert result["status"] == "needs_credentials"
    assert result["mode"] == "no-op"
    assert result["findings_count"] == 0
    assert isinstance(result["findings"], list)
    assert "hint" in result


def test_appomni_mock_api_parses_correctly():
    """A mocked AppOmni findings response normalizes to ALDECI shape."""
    from connectors.appomni_connector import AppOmniConnector

    fe = _mock_findings()
    connector = AppOmniConnector(findings_engine=fe)

    sample_findings = [
        {
            "id": "ao-001",
            "title": "MFA not enforced for admin users",
            "description": "Admin accounts lack MFA enforcement.",
            "severity": "high",
            "app_name": "Salesforce",
            "app_id": "sf-app-001",
            "category": "authentication",
            "status": "open",
            "created_at": "2024-01-01T00:00:00Z",
        }
    ]

    with patch.dict(os.environ, {"APPOMNI_API_KEY": "fake-key"}), \
    patch("connectors.appomni_connector._paginate_findings", return_value=sample_findings), \
    patch("connectors.appomni_connector._paginate_apps", return_value=[]):
        result = connector.sync(org_id="test-org", force_refresh=True)

    assert result["status"] == "ok"
    assert result["findings_count"] == 1
    assert result["findings_recorded"] == 1
    assert len(result["findings"]) == 1

    finding = result["findings"][0]
    assert finding["asset_type"] == "saas_application"
    assert finding["source_tool"] == "appomni"
    assert finding["finding_type"] == "sspm"
    assert finding["severity"] == "high"
    assert finding["correlation_key"] == "appomni_finding|ao-001"


@pytest.mark.skipif(
    not os.environ.get("APPOMNI_API_KEY"),
    reason="APPOMNI_API_KEY not set",
)
def test_appomni_live_api_call():
    """Live integration test — requires real AppOmni credentials."""
    from connectors.appomni_connector import AppOmniConnector
    connector = AppOmniConnector(findings_engine=_mock_findings(), max_findings=10)
    result = connector.sync(org_id="live-test-org", force_refresh=True)

    assert result["status"] in ("ok", "api_error", "needs_credentials")
    assert isinstance(result["findings"], list)


def test_appomni_normalize_finding_shape():
    """_normalize_finding maps severity correctly."""
    from connectors.appomni_connector import _normalize_finding

    raw = {
        "id": "ao-999",
        "title": "Overprivileged OAuth app",
        "description": "Third-party app has excessive scopes.",
        "severity": "critical",
        "app_name": "Google Workspace",
        "app_id": "gws-001",
        "category": "authorization",
        "status": "open",
    }
    finding = _normalize_finding(raw)

    assert finding["severity"] == "critical"
    assert finding["source_tool"] == "appomni"
    assert finding["finding_type"] == "sspm"
    assert finding["asset_type"] == "saas_application"
    assert finding["correlation_key"] == "appomni_finding|ao-999"
    assert "Google Workspace" in finding["description"]
