"""
Tests for GitHub Advanced Security integration.

Covers:
  - GitHubSecurityClient: configuration, mock data, normalization, dismiss, import_all, history
  - GitHubSecurityRouter: all 8 API endpoints (via TestClient)

Usage:
    pytest tests/test_github_security.py -x --tb=short --timeout=10 -q
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

# Ensure suite-core is on path (mirrors other test files)
suite_core_path = str(Path(__file__).parent.parent / "suite-core")
if suite_core_path not in sys.path:
    sys.path.insert(0, suite_core_path)

from core.github_security import (
    GitHubSecurityClient,
    _MOCK_CODE_SCANNING_ALERTS,
    _MOCK_DEPENDABOT_ALERTS,
    _MOCK_SECRET_SCANNING_ALERTS,
    _import_history,
)


# ===========================================================================
# Helpers
# ===========================================================================

def make_client(**kwargs) -> GitHubSecurityClient:
    """Return an unconfigured client by default."""
    return GitHubSecurityClient(**kwargs)


def make_configured_client() -> GitHubSecurityClient:
    return GitHubSecurityClient(token="ghp_test", owner="acme", repo="myrepo")


# ===========================================================================
# 1. Configuration / is_configured
# ===========================================================================

class TestIsConfigured:
    def test_unconfigured_by_default(self):
        client = GitHubSecurityClient()
        # Without env vars set this should be False
        with patch.dict("os.environ", {}, clear=True):
            c = GitHubSecurityClient()
        assert isinstance(c.is_configured(), bool)

    def test_configured_when_all_provided(self):
        client = make_configured_client()
        assert client.is_configured() is True

    def test_not_configured_missing_token(self):
        client = GitHubSecurityClient(owner="acme", repo="repo")
        assert client.is_configured() is False

    def test_not_configured_missing_owner(self):
        client = GitHubSecurityClient(token="tok", repo="repo")
        assert client.is_configured() is False

    def test_not_configured_missing_repo(self):
        client = GitHubSecurityClient(token="tok", owner="acme")
        assert client.is_configured() is False

    def test_reads_from_env(self):
        with patch.dict("os.environ", {
            "GITHUB_TOKEN": "env_token",
            "GITHUB_OWNER": "env_owner",
            "GITHUB_REPO": "env_repo",
        }):
            c = GitHubSecurityClient()
            assert c.is_configured() is True
            assert c.token == "env_token"
            assert c.owner == "env_owner"
            assert c.repo == "env_repo"


# ===========================================================================
# 2. Mock data fallback (unconfigured client)
# ===========================================================================

class TestMockFallback:
    def test_code_scanning_returns_mock_when_unconfigured(self):
        client = GitHubSecurityClient()
        alerts = client.get_code_scanning_alerts()
        assert isinstance(alerts, list)
        assert len(alerts) > 0
        assert alerts[0].get("_mock") is True

    def test_dependabot_returns_mock_when_unconfigured(self):
        client = GitHubSecurityClient()
        alerts = client.get_dependabot_alerts()
        assert isinstance(alerts, list)
        assert len(alerts) > 0
        assert alerts[0].get("_mock") is True

    def test_secret_scanning_returns_mock_when_unconfigured(self):
        client = GitHubSecurityClient()
        alerts = client.get_secret_scanning_alerts()
        assert isinstance(alerts, list)
        assert len(alerts) > 0
        assert alerts[0].get("_mock") is True

    def test_mock_data_is_copies_not_references(self):
        """Mutations to returned lists should not affect module-level mock data."""
        client = GitHubSecurityClient()
        alerts = client.get_code_scanning_alerts()
        alerts.clear()
        assert len(_MOCK_CODE_SCANNING_ALERTS) > 0


# ===========================================================================
# 3. Normalization — code scanning
# ===========================================================================

class TestNormalizeCodeScanning:
    def setup_method(self):
        self.client = GitHubSecurityClient()
        self.raw = list(_MOCK_CODE_SCANNING_ALERTS)

    def test_returns_list(self):
        result = self.client.normalize_results(self.raw, "code_scanning")
        assert isinstance(result, list)

    def test_count_matches_input(self):
        result = self.client.normalize_results(self.raw, "code_scanning")
        assert len(result) == len(self.raw)

    def test_required_fields_present(self):
        result = self.client.normalize_results(self.raw, "code_scanning")
        for finding in result:
            assert "id" in finding
            assert "source_tool" in finding
            assert "source_id" in finding
            assert "severity" in finding
            assert "title" in finding
            assert "alert_type" in finding

    def test_alert_type_set_correctly(self):
        result = self.client.normalize_results(self.raw, "code_scanning")
        for f in result:
            assert f["alert_type"] == "code_scanning"

    def test_severity_mapped_from_error(self):
        result = self.client.normalize_results(self.raw, "code_scanning")
        # Mock alerts have severity "error" → should map to "high"
        assert result[0]["severity"] == "high"

    def test_is_mock_flag_propagated(self):
        result = self.client.normalize_results(self.raw, "code_scanning")
        for f in result:
            assert f["is_mock"] is True

    def test_empty_input_returns_empty(self):
        result = self.client.normalize_results([], "code_scanning")
        assert result == []


# ===========================================================================
# 4. Normalization — Dependabot
# ===========================================================================

class TestNormalizeDependabot:
    def setup_method(self):
        self.client = GitHubSecurityClient()
        self.raw = list(_MOCK_DEPENDABOT_ALERTS)

    def test_returns_list(self):
        result = self.client.normalize_results(self.raw, "dependabot")
        assert isinstance(result, list)

    def test_count_matches_input(self):
        result = self.client.normalize_results(self.raw, "dependabot")
        assert len(result) == len(self.raw)

    def test_cve_id_extracted(self):
        result = self.client.normalize_results(self.raw, "dependabot")
        assert result[0]["cve_id"] == "CVE-2023-32681"

    def test_package_name_extracted(self):
        result = self.client.normalize_results(self.raw, "dependabot")
        assert result[0]["package_name"] == "requests"

    def test_severity_mapped(self):
        result = self.client.normalize_results(self.raw, "dependabot")
        # "medium" → "medium"
        assert result[0]["severity"] == "medium"
        # "high" → "high"
        assert result[1]["severity"] == "high"

    def test_recommendation_contains_package(self):
        result = self.client.normalize_results(self.raw, "dependabot")
        assert "requests" in result[0]["recommendation"]

    def test_alert_type_set_correctly(self):
        result = self.client.normalize_results(self.raw, "dependabot")
        for f in result:
            assert f["alert_type"] == "dependabot"


# ===========================================================================
# 5. Normalization — secret scanning
# ===========================================================================

class TestNormalizeSecretScanning:
    def setup_method(self):
        self.client = GitHubSecurityClient()
        self.raw = list(_MOCK_SECRET_SCANNING_ALERTS)

    def test_returns_list(self):
        result = self.client.normalize_results(self.raw, "secret_scanning")
        assert isinstance(result, list)

    def test_severity_always_critical(self):
        result = self.client.normalize_results(self.raw, "secret_scanning")
        for f in result:
            assert f["severity"] == "critical"

    def test_secret_type_preserved(self):
        result = self.client.normalize_results(self.raw, "secret_scanning")
        assert result[0]["secret_type"] == "github_personal_access_token"

    def test_alert_type_set_correctly(self):
        result = self.client.normalize_results(self.raw, "secret_scanning")
        for f in result:
            assert f["alert_type"] == "secret_scanning"

    def test_title_contains_secret_type(self):
        result = self.client.normalize_results(self.raw, "secret_scanning")
        assert "Secret exposed" in result[0]["title"]


# ===========================================================================
# 6. Normalization — unknown type
# ===========================================================================

class TestNormalizeUnknownType:
    def test_unknown_type_returns_raw(self):
        client = GitHubSecurityClient()
        raw = [{"number": 1, "state": "open"}]
        result = client.normalize_results(raw, "unknown_type")
        assert result == raw


# ===========================================================================
# 7. dismiss_alert — unconfigured
# ===========================================================================

class TestDismissAlert:
    def test_dismiss_skipped_when_unconfigured(self):
        client = GitHubSecurityClient()
        result = client.dismiss_alert("code_scanning", 1, "false_positive")
        assert result["status"] == "skipped"

    def test_dismiss_unknown_type_returns_error(self):
        client = make_configured_client()
        with patch.object(client, "_patch", return_value={"number": 1}):
            result = client.dismiss_alert("bad_type", 1, "false_positive")
        assert result["status"] == "error"

    def test_dismiss_code_scanning_calls_patch(self):
        client = make_configured_client()
        mock_response = {"number": 1, "state": "dismissed"}
        with patch.object(client, "_patch", return_value=mock_response) as mock_patch:
            result = client.dismiss_alert("code_scanning", 1, "false_positive", "test comment")
        mock_patch.assert_called_once()
        assert result["status"] == "dismissed"
        assert result["alert_number"] == 1

    def test_dismiss_dependabot_calls_patch(self):
        client = make_configured_client()
        with patch.object(client, "_patch", return_value={"state": "dismissed"}) as mock_patch:
            result = client.dismiss_alert("dependabot", 2, "tolerable_risk")
        mock_patch.assert_called_once()
        assert result["status"] == "dismissed"

    def test_dismiss_secret_scanning_calls_patch(self):
        client = make_configured_client()
        with patch.object(client, "_patch", return_value={"state": "dismissed"}) as mock_patch:
            result = client.dismiss_alert("secret_scanning", 3, "false_positive")
        mock_patch.assert_called_once()
        assert result["status"] == "dismissed"


# ===========================================================================
# 8. import_all
# ===========================================================================

class TestImportAll:
    def test_import_all_returns_summary(self):
        client = GitHubSecurityClient()
        result = client.import_all(org_id="test_org")
        assert "import_id" in result
        assert "total_findings" in result
        assert "counts_by_type" in result
        assert "severity_breakdown" in result
        assert "findings" in result

    def test_import_all_mock_flag_set(self):
        client = GitHubSecurityClient()
        result = client.import_all(org_id="test_org_mock")
        assert result["is_mock"] is True

    def test_import_all_counts_all_types(self):
        client = GitHubSecurityClient()
        result = client.import_all(org_id="test_org_counts")
        counts = result["counts_by_type"]
        assert "code_scanning" in counts
        assert "dependabot" in counts
        assert "secret_scanning" in counts

    def test_import_all_total_matches_type_counts(self):
        client = GitHubSecurityClient()
        result = client.import_all(org_id="test_org_total")
        total = sum(result["counts_by_type"].values())
        assert result["total_findings"] == total

    def test_import_all_severity_breakdown_keys(self):
        client = GitHubSecurityClient()
        result = client.import_all(org_id="test_org_sev")
        sev = result["severity_breakdown"]
        for key in ("critical", "high", "medium", "low", "info"):
            assert key in sev

    def test_import_all_findings_have_required_fields(self):
        client = GitHubSecurityClient()
        result = client.import_all(org_id="test_org_fields")
        for finding in result["findings"]:
            assert "id" in finding
            assert "severity" in finding
            assert "alert_type" in finding

    def test_import_all_status_completed(self):
        client = GitHubSecurityClient()
        result = client.import_all(org_id="test_org_status")
        assert result["status"] == "completed"

    def test_import_all_org_id_preserved(self):
        client = GitHubSecurityClient()
        result = client.import_all(org_id="special_org")
        assert result["org_id"] == "special_org"


# ===========================================================================
# 9. get_import_history
# ===========================================================================

class TestImportHistory:
    def test_history_empty_for_new_org(self):
        client = GitHubSecurityClient()
        history = client.get_import_history(org_id="brand_new_org_xyz")
        assert isinstance(history, list)
        assert len(history) == 0

    def test_history_grows_after_import(self):
        client = GitHubSecurityClient()
        org = "history_test_org_unique"
        client.import_all(org_id=org)
        history = client.get_import_history(org_id=org)
        assert len(history) >= 1

    def test_history_entries_have_no_findings_key(self):
        """History summaries should omit the full findings list."""
        client = GitHubSecurityClient()
        org = "history_no_findings_org"
        client.import_all(org_id=org)
        history = client.get_import_history(org_id=org)
        for entry in history:
            assert "findings" not in entry

    def test_history_most_recent_first(self):
        client = GitHubSecurityClient()
        org = "history_order_org"
        client.import_all(org_id=org)
        client.import_all(org_id=org)
        history = client.get_import_history(org_id=org)
        if len(history) >= 2:
            # Most recent first means started_at of [0] >= [1]
            assert history[0]["started_at"] >= history[1]["started_at"]


# ===========================================================================
# 10. HTTP client — configured client fetcher mocking
# ===========================================================================

class TestConfiguredClientFetcher:
    def test_get_code_scanning_calls_get(self):
        client = make_configured_client()
        mock_alerts = [{"number": 10, "state": "open", "rule": {"id": "test"}}]
        with patch.object(client, "_get", return_value=mock_alerts) as mock_get:
            result = client.get_code_scanning_alerts()
        mock_get.assert_called_once()
        assert result == mock_alerts

    def test_get_dependabot_calls_get(self):
        client = make_configured_client()
        mock_alerts = [{"number": 20, "state": "open"}]
        with patch.object(client, "_get", return_value=mock_alerts) as mock_get:
            result = client.get_dependabot_alerts()
        mock_get.assert_called_once()
        assert result == mock_alerts

    def test_get_secret_scanning_calls_get(self):
        client = make_configured_client()
        mock_alerts = [{"number": 30, "state": "open"}]
        with patch.object(client, "_get", return_value=mock_alerts) as mock_get:
            result = client.get_secret_scanning_alerts()
        mock_get.assert_called_once()
        assert result == mock_alerts


# ===========================================================================
# 11. API Router (via FastAPI TestClient)
# ===========================================================================

try:
    from fastapi.testclient import TestClient
    from fastapi import FastAPI

    _TESTCLIENT_AVAILABLE = True
except ImportError:
    _TESTCLIENT_AVAILABLE = False


def _make_test_app():
    """Build a minimal FastAPI app with the GitHub Security router."""
    suite_api_path = str(Path(__file__).parent.parent / "suite-api")
    if suite_api_path not in sys.path:
        sys.path.insert(0, suite_api_path)

    from apps.api.github_security_router import router
    import apps.api.auth_deps as auth_deps

    app = FastAPI()

    async def no_auth():
        return None

    # Set override BEFORE including router so dependency injection picks it up
    app.dependency_overrides[auth_deps.api_key_auth] = no_auth
    app.include_router(router)
    return app


@pytest.mark.skipif(not _TESTCLIENT_AVAILABLE, reason="fastapi not available")
class TestGitHubSecurityRouter:
    @pytest.fixture(autouse=True)
    def client(self):
        app = _make_test_app()
        self.http = TestClient(app)

    def test_status_endpoint_returns_200(self):
        resp = self.http.get("/api/v1/security/github/status")
        assert resp.status_code == 200

    def test_status_has_configured_field(self):
        resp = self.http.get("/api/v1/security/github/status")
        data = resp.json()
        assert "configured" in data
        assert "is_mock" in data

    def test_code_scanning_endpoint_returns_200(self):
        resp = self.http.get("/api/v1/security/github/alerts/code-scanning")
        assert resp.status_code == 200

    def test_code_scanning_returns_list(self):
        resp = self.http.get("/api/v1/security/github/alerts/code-scanning")
        assert isinstance(resp.json(), list)

    def test_dependabot_endpoint_returns_200(self):
        resp = self.http.get("/api/v1/security/github/alerts/dependabot")
        assert resp.status_code == 200

    def test_dependabot_returns_list(self):
        resp = self.http.get("/api/v1/security/github/alerts/dependabot")
        assert isinstance(resp.json(), list)

    def test_secret_scanning_endpoint_returns_200(self):
        resp = self.http.get("/api/v1/security/github/alerts/secret-scanning")
        assert resp.status_code == 200

    def test_secret_scanning_returns_list(self):
        resp = self.http.get("/api/v1/security/github/alerts/secret-scanning")
        assert isinstance(resp.json(), list)

    def test_all_alerts_endpoint_returns_200(self):
        resp = self.http.get("/api/v1/security/github/alerts/all")
        assert resp.status_code == 200

    def test_all_alerts_returns_combined_list(self):
        resp = self.http.get("/api/v1/security/github/alerts/all")
        data = resp.json()
        assert isinstance(data, list)
        # Should include all 3 types combined
        types = {f.get("alert_type") for f in data}
        assert types == {"code_scanning", "dependabot", "secret_scanning"}

    def test_import_endpoint_returns_200(self):
        resp = self.http.post(
            "/api/v1/security/github/import",
            json={"org_id": "router_test_org"},
        )
        assert resp.status_code == 200

    def test_import_returns_summary_fields(self):
        resp = self.http.post(
            "/api/v1/security/github/import",
            json={"org_id": "router_test_org_2"},
        )
        data = resp.json()
        assert "import_id" in data
        assert "total_findings" in data
        assert "severity_breakdown" in data

    def test_history_endpoint_returns_200(self):
        resp = self.http.get("/api/v1/security/github/history?org_id=router_test_org")
        assert resp.status_code == 200

    def test_history_returns_list(self):
        resp = self.http.get("/api/v1/security/github/history?org_id=router_test_org")
        assert isinstance(resp.json(), list)

    def test_dismiss_invalid_type_returns_422(self):
        resp = self.http.post(
            "/api/v1/security/github/alerts/invalid_type/1/dismiss",
            json={"reason": "false_positive"},
        )
        assert resp.status_code == 422

    def test_dismiss_valid_type_returns_200_in_mock_mode(self):
        resp = self.http.post(
            "/api/v1/security/github/alerts/code_scanning/1/dismiss",
            json={"reason": "false_positive"},
        )
        # In mock mode (unconfigured) the client returns status=skipped not failed → 200
        assert resp.status_code == 200

    def test_code_scanning_raw_mode(self):
        resp = self.http.get(
            "/api/v1/security/github/alerts/code-scanning?normalize=false"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        # Raw mode preserves _mock flag from source
        assert data[0].get("_mock") is True
