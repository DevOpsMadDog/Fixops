"""Tests for Adaptive Shield Live Connector (SSPM).

4 tests:
1. Missing creds → graceful no-op (needs_credentials)
2. Mock API response parses correctly
3. Live API call (skipped if creds absent)
4. _normalize_check severity bump on failed checks
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
    fe.record_finding.return_value = {"id": "test-finding-as-001"}
    return fe


def test_adaptive_shield_missing_creds_graceful_noop():
    """When ADAPTIVESHIELD_API_KEY absent → needs_credentials, no crash."""
    env_patch = {"ADAPTIVESHIELD_API_KEY": ""}
    with patch.dict(os.environ, env_patch, clear=False):
        from connectors.adaptive_shield_connector import AdaptiveShieldConnector
        connector = AdaptiveShieldConnector(findings_engine=_mock_findings())
        result = connector.sync(org_id="test-org")

    assert result["status"] == "needs_credentials"
    assert result["mode"] == "no-op"
    assert result["checks_count"] == 0
    assert isinstance(result["findings"], list)
    assert "hint" in result


def test_adaptive_shield_mock_api_parses_correctly():
    """A mocked Adaptive Shield checks response normalizes to ALDECI shape."""
    from connectors.adaptive_shield_connector import AdaptiveShieldConnector

    fe = _mock_findings()
    connector = AdaptiveShieldConnector(findings_engine=fe)

    # Only failed checks should surface as findings
    sample_checks = [
        {
            "id": "as-001",
            "title": "SSO not enforced",
            "description": "Single sign-on is not enforced for all users.",
            "severity": "high",
            "appName": "Microsoft 365",
            "appId": "m365-001",
            "category": "authentication",
            "status": "fail",
        },
        {
            "id": "as-002",
            "title": "Password policy compliant",
            "description": "Password policy meets requirements.",
            "severity": "low",
            "appName": "Slack",
            "appId": "slack-001",
            "category": "authentication",
            "status": "pass",  # Should be filtered out
        },
    ]

    with patch.dict(os.environ, {"ADAPTIVESHIELD_API_KEY": "fake-key"}), \
    patch("connectors.adaptive_shield_connector._paginate", side_effect=[
        sample_checks,  # /v1/checks
        [],             # /v1/apps
    ]):
        result = connector.sync(org_id="test-org", force_refresh=True)

    assert result["status"] == "ok"
    assert result["checks_count"] == 2  # total fetched
    # Only 1 finding (pass filtered out)
    assert len(result["findings"]) == 1
    assert result["findings_recorded"] == 1

    finding = result["findings"][0]
    assert finding["source_tool"] == "adaptive_shield"
    assert finding["finding_type"] == "sspm"
    assert finding["severity"] == "high"
    assert finding["correlation_key"] == "adaptive_shield_check|as-001"


@pytest.mark.skipif(
    not os.environ.get("ADAPTIVESHIELD_API_KEY"),
    reason="ADAPTIVESHIELD_API_KEY not set",
)
def test_adaptive_shield_live_api_call():
    """Live integration test — requires real Adaptive Shield credentials."""
    from connectors.adaptive_shield_connector import AdaptiveShieldConnector
    connector = AdaptiveShieldConnector(findings_engine=_mock_findings(), max_checks=10)
    result = connector.sync(org_id="live-test-org", force_refresh=True)

    assert result["status"] in ("ok", "api_error", "needs_credentials")
    assert isinstance(result["findings"], list)


def test_adaptive_shield_severity_bump_on_fail():
    """_normalize_check bumps low severity to medium when status=fail."""
    from connectors.adaptive_shield_connector import _normalize_check

    check = {
        "id": "as-bump-001",
        "title": "Audit logging disabled",
        "severity": "low",
        "status": "fail",
        "appName": "GitHub",
        "appId": "gh-001",
        "category": "logging",
    }
    finding = _normalize_check(check)

    # "fail" + "low" → should be bumped to "medium"
    assert finding["severity"] == "medium"
    assert finding["source_tool"] == "adaptive_shield"
    assert finding["correlation_key"] == "adaptive_shield_check|as-bump-001"
