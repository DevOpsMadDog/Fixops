"""Tests for CrowdStrikeLiveConnector.

4 tests:
1. Missing creds → graceful no-op (needs_credentials)
2. Mock API response parses correctly
3. Live API call (skipped if creds absent)
4. Pagination: multiple pages of detection IDs collected
"""
from __future__ import annotations

import os
import time
import threading
from typing import Any, Dict
from unittest.mock import MagicMock, patch, call

import pytest

# Ensure suite-core is on path via sitecustomize
import sys
sys.path.insert(0, "/Users/devops.ai/fixops/Fixops")
sys.path.insert(0, "/Users/devops.ai/fixops/Fixops/suite-core")


# ---------------------------------------------------------------------------
# Helper: build a minimal mock SecurityFindingsEngine
# ---------------------------------------------------------------------------
def _mock_findings():
    fe = MagicMock()
    fe.record_finding.return_value = {"id": "test-finding-id-001"}
    return fe


# ---------------------------------------------------------------------------
# Test 1: missing credentials → graceful no-op
# ---------------------------------------------------------------------------
def test_crowdstrike_missing_creds_graceful_noop():
    """When CROWDSTRIKE_CLIENT_ID / SECRET absent → status=needs_credentials, no crash."""
    env_patch = {k: "" for k in ("CROWDSTRIKE_CLIENT_ID", "CROWDSTRIKE_CLIENT_SECRET")}
    with patch.dict(os.environ, env_patch, clear=False):
        from connectors.crowdstrike_live_connector import CrowdStrikeLiveConnector
        connector = CrowdStrikeLiveConnector(findings_engine=_mock_findings())
        result = connector.fetch_detections(org_id="test-org")

    assert result["status"] == "needs_credentials"
    assert result["mode"] == "no-op"
    assert result["detection_count"] == 0
    assert result["findings_recorded"] == 0
    assert "hint" in result
    assert isinstance(result["detections"], list)
    assert len(result["detections"]) == 0


# ---------------------------------------------------------------------------
# Test 2: mock API response parses correctly
# ---------------------------------------------------------------------------
def test_crowdstrike_mock_api_parses_correctly():
    """A mocked Falcon API response is parsed and normalized correctly."""
    from connectors.crowdstrike_live_connector import CrowdStrikeLiveConnector
    from connectors.crowdstrike_falcon_connector import FALCON_SAMPLE_DETECTIONS

    fe = _mock_findings()
    connector = CrowdStrikeLiveConnector(findings_engine=fe)

    # Patch _get_token, _fetch_detection_ids, _fetch_detection_summaries
    with patch.dict(os.environ, {
        "CROWDSTRIKE_CLIENT_ID": "fake-id",
        "CROWDSTRIKE_CLIENT_SECRET": "fake-secret",
    }), \
    patch("connectors.crowdstrike_live_connector._get_token", return_value="tok-abc"), \
    patch("connectors.crowdstrike_live_connector._fetch_detection_ids",
          return_value=["det-001", "det-002"]), \
    patch("connectors.crowdstrike_live_connector._fetch_detection_summaries",
          return_value=FALCON_SAMPLE_DETECTIONS[:2]):

        result = connector.fetch_detections(org_id="test-org", force_refresh=True)

    assert result["status"] == "ok"
    assert result["mode"] == "live"
    assert result["detection_count"] == 2
    assert result["findings_recorded"] == 2
    assert len(result["detections"]) == 2

    # Verify shape of first normalized detection
    det = result["detections"][0]
    assert "detection_id" in det
    assert det["severity"] in {"critical", "high", "medium", "low", "informational"}
    assert "title" in det
    assert det["asset_type"] == "host"

    # Verify record_finding was called for each detection
    assert fe.record_finding.call_count == 2
    call_kwargs = fe.record_finding.call_args_list[0][1]
    assert call_kwargs["org_id"] == "test-org"
    assert call_kwargs["source_tool"] == "crowdstrike_falcon"
    assert call_kwargs["correlation_key"].startswith("crowdstrike_falcon|")


# ---------------------------------------------------------------------------
# Test 3: live API call (skipped if creds absent)
# ---------------------------------------------------------------------------
@pytest.mark.skipif(
    not (os.environ.get("CROWDSTRIKE_CLIENT_ID") and os.environ.get("CROWDSTRIKE_CLIENT_SECRET")),
    reason="CROWDSTRIKE_CLIENT_ID / CROWDSTRIKE_CLIENT_SECRET not set",
)
def test_crowdstrike_live_api_call():
    """Live integration test — requires real Falcon API credentials."""
    from connectors.crowdstrike_live_connector import CrowdStrikeLiveConnector
    connector = CrowdStrikeLiveConnector(findings_engine=_mock_findings(), max_detections=10)
    result = connector.fetch_detections(org_id="live-test-org", force_refresh=True)

    assert result["status"] in {"ok", "api_error"}
    assert isinstance(result["detection_count"], int)
    assert isinstance(result["detections"], list)


# ---------------------------------------------------------------------------
# Test 4: pagination — multiple pages of detection IDs collected
# ---------------------------------------------------------------------------
def test_crowdstrike_pagination_collects_all_pages():
    """_fetch_detection_ids stops when total is reached or resources empty."""
    from connectors.crowdstrike_live_connector import _fetch_detection_ids

    # Page 1: 3 IDs, total=6 (more pages exist)
    # Page 2: 3 IDs, offset reaches total → loop stops (no page3 needed)
    page1 = {
        "resources": ["det-001", "det-002", "det-003"],
        "meta": {"pagination": {"total": 6, "offset": 0, "limit": 3}},
    }
    page2 = {
        "resources": ["det-004", "det-005", "det-006"],
        "meta": {"pagination": {"total": 6, "offset": 3, "limit": 3}},
    }

    responses = [page1, page2]
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
        ids = _fetch_detection_ids(
            base_url="https://fake.crowdstrike.com",
            token="tok",
            filter_expr="",
            max_ids=10,
        )

    assert ids == ["det-001", "det-002", "det-003", "det-004", "det-005", "det-006"]
    assert call_count == 2
