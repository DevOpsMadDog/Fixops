"""
Tests for Snyk integration — SnykClient and snyk_router.

All HTTP calls are mocked so no Snyk API token is required.
Covers: is_configured, list_projects, get_project_issues, test_package,
        import_results, normalize_results, inline fallback, history,
        and all 6 API router endpoints.
"""

from __future__ import annotations

import json
import os
import uuid
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

# ── Environment setup ──────────────────────────────────────────────────────
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-key-for-jwt-validation-32chars")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")


# ── Sample data ────────────────────────────────────────────────────────────

SAMPLE_ISSUE: Dict[str, Any] = {
    "id": "SNYK-JS-LODASH-1234567",
    "attributes": {
        "title": "Prototype Pollution",
        "type": "vuln",
        "severity": "high",
        "status": "open",
        "description": "Prototype Pollution in lodash.",
        "coordinates": [
            {
                "representations": [
                    {
                        "dependency": {
                            "package_name": "lodash",
                            "package_version": "4.17.15",
                        }
                    }
                ],
                "remedies": [{"description": "Upgrade to lodash@4.17.21"}],
            }
        ],
        "classes": [{"id": "CWE-1321", "type": "weakness"}],
        "problems": [
            {
                "id": "CVE-2021-23337",
                "type": "vulnerability",
                "url": "https://security.snyk.io/vuln/SNYK-JS-LODASH-1234567",
            }
        ],
    },
    "relationships": {
        "scan_item": {"data": {"id": "proj-001", "type": "project"}}
    },
}

SAMPLE_CRITICAL_ISSUE: Dict[str, Any] = {
    "id": "SNYK-PYTHON-PILLOW-1111111",
    "attributes": {
        "title": "Arbitrary Code Execution",
        "type": "vuln",
        "severity": "critical",
        "status": "open",
        "description": "Uncontrolled resource consumption in Pillow.",
        "coordinates": [
            {
                "representations": [
                    {
                        "dependency": {
                            "package_name": "Pillow",
                            "package_version": "9.0.0",
                        }
                    }
                ],
                "remedies": [{"description": "Upgrade to Pillow@10.0.1"}],
            }
        ],
        "classes": [{"id": "CWE-78", "type": "weakness"}],
        "problems": [
            {
                "id": "CVE-2023-44271",
                "type": "vulnerability",
                "url": "https://security.snyk.io/vuln/SNYK-PYTHON-PILLOW-1111111",
            }
        ],
    },
    "relationships": {
        "scan_item": {"data": {"id": "proj-001", "type": "project"}}
    },
}

SAMPLE_ISSUES = [SAMPLE_ISSUE, SAMPLE_CRITICAL_ISSUE]

SAMPLE_PROJECT: Dict[str, Any] = {
    "id": "proj-001",
    "attributes": {
        "name": "my-app/package.json",
        "type": "npm",
        "status": "active",
    },
}

SNYK_API_PROJECTS_RESPONSE: Dict[str, Any] = {
    "data": [SAMPLE_PROJECT],
    "links": {"self": "/orgs/org-123/projects"},
}

SNYK_API_ISSUES_RESPONSE: Dict[str, Any] = {
    "data": SAMPLE_ISSUES,
    "links": {"self": "/orgs/org-123/issues"},
}


# ── SnykClient unit tests ──────────────────────────────────────────────────

class TestSnykClientConfiguration:
    def test_is_configured_with_token(self):
        from core.snyk_integration import SnykClient
        client = SnykClient(api_token="snyk-token-abc", org_id="my-org")
        assert client.is_configured() is True

    def test_is_configured_without_token(self):
        from core.snyk_integration import SnykClient
        client = SnykClient(api_token="", org_id="my-org")
        assert client.is_configured() is False

    def test_reads_token_from_env(self, monkeypatch):
        monkeypatch.setenv("SNYK_API_TOKEN", "env-token-xyz")
        monkeypatch.setenv("SNYK_ORG_ID", "env-org-123")
        from importlib import reload
        import core.snyk_integration as mod
        client = mod.SnykClient()
        assert client.is_configured() is True
        assert client._api_token == "env-token-xyz"
        assert client._org_id == "env-org-123"

    def test_strips_whitespace_from_token(self):
        from core.snyk_integration import SnykClient
        client = SnykClient(api_token="  token-with-spaces  ", org_id="org")
        assert client._api_token == "token-with-spaces"

    def test_empty_env_token_means_unconfigured(self, monkeypatch):
        monkeypatch.setenv("SNYK_API_TOKEN", "")
        from core.snyk_integration import SnykClient
        client = SnykClient()
        assert client.is_configured() is False


class TestSnykClientMockFallback:
    """Tests for mock data returned when no API token is configured."""

    def _unconfigured_client(self):
        from core.snyk_integration import SnykClient
        return SnykClient(api_token="", org_id="test-org")

    def test_list_projects_returns_mock_when_unconfigured(self):
        client = self._unconfigured_client()
        projects = client.list_projects()
        assert isinstance(projects, list)
        assert len(projects) > 0
        assert "id" in projects[0]

    def test_get_project_issues_returns_mock_when_unconfigured(self):
        client = self._unconfigured_client()
        issues = client.get_project_issues("any-project-id")
        assert isinstance(issues, list)
        assert len(issues) > 0

    def test_test_package_returns_mock_when_unconfigured(self):
        client = self._unconfigured_client()
        result = client.test_package("npm", "lodash", "4.17.15")
        assert isinstance(result, dict)
        assert result.get("is_mock") is True
        assert result["packageName"] == "lodash"
        assert result["version"] == "4.17.15"

    def test_test_package_propagates_package_name_in_mock(self):
        client = self._unconfigured_client()
        result = client.test_package("pip", "requests", "2.28.0")
        assert result["packageName"] == "requests"
        assert result["version"] == "2.28.0"

    def test_import_results_returns_findings_list_when_unconfigured(self):
        client = self._unconfigured_client()
        client._try_ingest_to_pipeline = MagicMock()
        findings = client.import_results(org_id="test-org")
        assert isinstance(findings, list)
        assert len(findings) > 0


class TestSnykClientValidation:
    def _configured_client(self):
        from core.snyk_integration import SnykClient
        return SnykClient(api_token="tok", org_id="org-123")

    def test_get_project_issues_rejects_empty_id(self):
        client = self._configured_client()
        with pytest.raises(ValueError, match="non-empty"):
            client.get_project_issues("")

    def test_test_package_rejects_empty_ecosystem(self):
        client = self._configured_client()
        with pytest.raises(ValueError):
            client.test_package("", "lodash", "4.17.15")

    def test_test_package_rejects_empty_package(self):
        client = self._configured_client()
        with pytest.raises(ValueError):
            client.test_package("npm", "", "4.17.15")

    def test_test_package_rejects_empty_version(self):
        client = self._configured_client()
        with pytest.raises(ValueError):
            client.test_package("npm", "lodash", "")


class TestSnykClientHTTP:
    """Tests for live HTTP calls (mocked at requests level)."""

    def _client_with_mock_session(self, response_data: Any, status_code: int = 200):
        from core.snyk_integration import SnykClient
        client = SnykClient(api_token="real-token", org_id="org-123")
        mock_resp = MagicMock()
        mock_resp.status_code = status_code
        mock_resp.ok = (status_code < 400)
        mock_resp.json.return_value = response_data
        mock_resp.text = json.dumps(response_data)
        mock_session = MagicMock()
        mock_session.get.return_value = mock_resp
        client._session = mock_session
        return client

    def test_list_projects_real_api(self):
        client = self._client_with_mock_session(SNYK_API_PROJECTS_RESPONSE)
        projects = client.list_projects()
        assert len(projects) == 1
        assert projects[0]["id"] == "proj-001"

    def test_get_project_issues_real_api(self):
        client = self._client_with_mock_session(SNYK_API_ISSUES_RESPONSE)
        issues = client.get_project_issues("proj-001")
        assert len(issues) == 2
        assert issues[0]["id"] == "SNYK-JS-LODASH-1234567"

    def test_list_projects_empty_response(self):
        client = self._client_with_mock_session({"data": []})
        projects = client.list_projects()
        assert projects == []

    def test_get_raises_on_401(self):
        client = self._client_with_mock_session({}, status_code=401)
        client._session.get.return_value.ok = False
        with pytest.raises(RuntimeError, match="401"):
            client.list_projects()

    def test_get_raises_on_403(self):
        client = self._client_with_mock_session({}, status_code=403)
        client._session.get.return_value.ok = False
        with pytest.raises(RuntimeError, match="403"):
            client.list_projects()

    def test_get_raises_on_404(self):
        client = self._client_with_mock_session({}, status_code=404)
        client._session.get.return_value.ok = False
        with pytest.raises(RuntimeError, match="404"):
            client.list_projects()

    def test_get_raises_on_500(self):
        client = self._client_with_mock_session({"error": "server error"}, status_code=500)
        client._session.get.return_value.ok = False
        with pytest.raises(RuntimeError, match="500"):
            client.list_projects()

    def test_get_raises_on_network_error(self):
        from core.snyk_integration import SnykClient
        client = SnykClient(api_token="tok", org_id="org-123")
        mock_session = MagicMock()
        mock_session.get.side_effect = ConnectionError("network down")
        client._session = mock_session
        with pytest.raises(RuntimeError, match="request failed"):
            client.list_projects()

    def test_list_projects_raises_without_org_id(self):
        from core.snyk_integration import SnykClient
        client = SnykClient(api_token="tok", org_id="")
        with pytest.raises(ValueError, match="org_id is required"):
            client.list_projects()

    def test_get_project_issues_raises_without_org_id(self):
        from core.snyk_integration import SnykClient
        client = SnykClient(api_token="tok", org_id="")
        with pytest.raises(ValueError, match="org_id is required"):
            client.get_project_issues("proj-001")


class TestSnykNormalization:
    def _unconfigured_client(self):
        from core.snyk_integration import SnykClient
        return SnykClient(api_token="", org_id="org")

    def test_normalize_empty_list_returns_empty(self):
        client = self._unconfigured_client()
        assert client.normalize_results([]) == []

    def test_inline_normalize_basic(self):
        client = self._unconfigured_client()
        findings = client._inline_normalize(SAMPLE_ISSUES)
        assert len(findings) == 2

    def test_inline_normalize_severity_high(self):
        client = self._unconfigured_client()
        findings = client._inline_normalize([SAMPLE_ISSUE])
        assert findings[0]["severity"] == "high"

    def test_inline_normalize_severity_critical(self):
        client = self._unconfigured_client()
        findings = client._inline_normalize([SAMPLE_CRITICAL_ISSUE])
        assert findings[0]["severity"] == "critical"

    def test_inline_normalize_package_name(self):
        client = self._unconfigured_client()
        findings = client._inline_normalize([SAMPLE_ISSUE])
        assert findings[0]["package_name"] == "lodash"

    def test_inline_normalize_package_version(self):
        client = self._unconfigured_client()
        findings = client._inline_normalize([SAMPLE_ISSUE])
        assert findings[0]["package_version"] == "4.17.15"

    def test_inline_normalize_cve_id_extracted(self):
        client = self._unconfigured_client()
        findings = client._inline_normalize([SAMPLE_ISSUE])
        assert findings[0]["cve_id"] == "CVE-2021-23337"

    def test_inline_normalize_cwe_id_extracted(self):
        client = self._unconfigured_client()
        findings = client._inline_normalize([SAMPLE_ISSUE])
        assert findings[0]["cwe_id"] == "CWE-1321"

    def test_inline_normalize_recommendation_from_remedies(self):
        client = self._unconfigured_client()
        findings = client._inline_normalize([SAMPLE_ISSUE])
        assert "lodash" in findings[0]["recommendation"]

    def test_inline_normalize_title_includes_package(self):
        client = self._unconfigured_client()
        findings = client._inline_normalize([SAMPLE_ISSUE])
        assert "Prototype Pollution" in findings[0]["title"]
        assert "lodash" in findings[0]["title"]

    def test_inline_normalize_has_source_tool(self):
        client = self._unconfigured_client()
        findings = client._inline_normalize([SAMPLE_ISSUE])
        assert findings[0]["source_tool"] == "snyk"

    def test_inline_normalize_has_unique_ids(self):
        client = self._unconfigured_client()
        findings = client._inline_normalize(SAMPLE_ISSUES)
        ids = [f["id"] for f in findings]
        assert len(ids) == len(set(ids))

    def test_normalize_results_returns_list_of_dicts(self):
        client = self._unconfigured_client()
        results = client.normalize_results(SAMPLE_ISSUES)
        assert isinstance(results, list)
        for r in results:
            assert isinstance(r, dict)

    def test_issues_to_snyk_test_format_structure(self):
        client = self._unconfigured_client()
        payload = client._issues_to_snyk_test_format(SAMPLE_ISSUES)
        assert "vulnerabilities" in payload
        assert payload["packageManager"] == "rest"
        assert len(payload["vulnerabilities"]) == 2

    def test_issues_to_snyk_test_format_fix_version_extracted(self):
        client = self._unconfigured_client()
        payload = client._issues_to_snyk_test_format([SAMPLE_ISSUE])
        vuln = payload["vulnerabilities"][0]
        assert vuln["fixedIn"] == ["4.17.21"]

    def test_issues_to_snyk_test_format_cve_extracted(self):
        client = self._unconfigured_client()
        payload = client._issues_to_snyk_test_format([SAMPLE_ISSUE])
        vuln = payload["vulnerabilities"][0]
        assert "CVE-2021-23337" in vuln["identifiers"]["CVE"]


class TestSnykImportResults:
    def _unconfigured_client(self):
        from core.snyk_integration import SnykClient
        client = SnykClient(api_token="", org_id="test-org")
        client._try_ingest_to_pipeline = MagicMock()
        return client

    def test_import_results_returns_list(self):
        client = self._unconfigured_client()
        findings = client.import_results(org_id="test-org")
        assert isinstance(findings, list)

    def test_import_results_stores_in_history(self):
        from core.snyk_integration import _import_history
        client = self._unconfigured_client()
        org_id = f"import-test-{uuid.uuid4().hex[:8]}"
        client.import_results(org_id=org_id)
        assert org_id in _import_history

    def test_import_results_calls_pipeline_ingest(self):
        client = self._unconfigured_client()
        client.import_results(org_id="pipeline-test-org")
        client._try_ingest_to_pipeline.assert_called_once()

    def test_import_results_with_real_api_iterates_projects(self):
        from core.snyk_integration import SnykClient
        client = SnykClient(api_token="real-token", org_id="org-123")
        client._try_ingest_to_pipeline = MagicMock()
        client.list_projects = MagicMock(return_value=[SAMPLE_PROJECT])
        client.get_project_issues = MagicMock(return_value=SAMPLE_ISSUES)
        findings = client.import_results(org_id="org-123")
        client.list_projects.assert_called_once()
        client.get_project_issues.assert_called_once_with("proj-001")
        assert isinstance(findings, list)

    def test_import_results_handles_project_issue_fetch_failure(self):
        from core.snyk_integration import SnykClient
        client = SnykClient(api_token="real-token", org_id="org-123")
        client._try_ingest_to_pipeline = MagicMock()
        client.list_projects = MagicMock(return_value=[SAMPLE_PROJECT])
        client.get_project_issues = MagicMock(side_effect=RuntimeError("fetch failed"))
        findings = client.import_results(org_id="org-123")
        # Should not raise; returns empty findings after skipping failed project
        assert isinstance(findings, list)


class TestSnykImportHistory:
    def test_get_import_history_empty_for_new_org(self):
        from core.snyk_integration import SnykClient
        client = SnykClient(api_token="", org_id="")
        org_id = f"neworg-{uuid.uuid4().hex}"
        history = client.get_import_history(org_id=org_id)
        assert history == []

    def test_get_import_history_returns_summaries(self):
        from core.snyk_integration import SnykClient
        client = SnykClient(api_token="", org_id="hist-org")
        client._try_ingest_to_pipeline = MagicMock()
        org_id = f"historg-{uuid.uuid4().hex[:8]}"
        client.import_results(org_id=org_id)
        client.import_results(org_id=org_id)
        history = client.get_import_history(org_id=org_id)
        assert len(history) == 2

    def test_get_import_history_most_recent_first(self):
        from core.snyk_integration import SnykClient
        client = SnykClient(api_token="", org_id="order-org")
        client._try_ingest_to_pipeline = MagicMock()
        org_id = f"orderorg-{uuid.uuid4().hex[:8]}"
        client.import_results(org_id=org_id)
        client.import_results(org_id=org_id)
        history = client.get_import_history(org_id=org_id)
        # Most recent should be first (both have same org but completed_at differs)
        assert history[0]["completed_at"] >= history[1]["completed_at"]

    def test_get_import_history_no_findings_in_summary(self):
        from core.snyk_integration import SnykClient
        client = SnykClient(api_token="", org_id="nofind-org")
        client._try_ingest_to_pipeline = MagicMock()
        org_id = f"nofind-{uuid.uuid4().hex[:8]}"
        client.import_results(org_id=org_id)
        history = client.get_import_history(org_id=org_id)
        assert "findings" not in history[0]

    def test_get_import_history_has_status_field(self):
        from core.snyk_integration import SnykClient
        client = SnykClient(api_token="", org_id="status-org")
        client._try_ingest_to_pipeline = MagicMock()
        org_id = f"status-{uuid.uuid4().hex[:8]}"
        client.import_results(org_id=org_id)
        history = client.get_import_history(org_id=org_id)
        assert "status" in history[0]
        assert history[0]["status"] == "completed"


# ── API Router tests ───────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def snyk_client():
    """FastAPI test client with snyk_router mounted."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from apps.api.snyk_router import router
    import apps.api.auth_deps as auth_deps

    app = FastAPI()
    app.include_router(router)

    original = auth_deps.api_key_auth

    async def _no_auth():
        return None

    auth_deps.api_key_auth = _no_auth
    app.dependency_overrides[original] = _no_auth
    return TestClient(app)


@pytest.fixture(autouse=True)
def _reset_snyk_singleton():
    """Reset the module-level _client singleton between tests."""
    import apps.api.snyk_router as snyk_mod
    snyk_mod._client = None
    yield
    snyk_mod._client = None


class TestSnykRouterStatus:
    def test_status_configured(self, snyk_client):
        mock_c = MagicMock()
        mock_c.is_configured.return_value = True
        mock_c._org_id = "org-123"
        with patch("apps.api.snyk_router._get_client", return_value=mock_c):
            resp = snyk_client.get("/api/v1/scan/snyk/status")
        assert resp.status_code == 200
        body = resp.json()
        assert body["configured"] is True
        assert "real data" in body["message"]

    def test_status_not_configured(self, snyk_client):
        mock_c = MagicMock()
        mock_c.is_configured.return_value = False
        mock_c._org_id = ""
        with patch("apps.api.snyk_router._get_client", return_value=mock_c):
            resp = snyk_client.get("/api/v1/scan/snyk/status")
        assert resp.status_code == 200
        body = resp.json()
        assert body["configured"] is False
        assert "mock data" in body["message"]


class TestSnykRouterProjects:
    def test_list_projects_success(self, snyk_client):
        mock_c = MagicMock()
        mock_c.list_projects.return_value = [SAMPLE_PROJECT]
        with patch("apps.api.snyk_router._get_client", return_value=mock_c):
            resp = snyk_client.get("/api/v1/scan/snyk/projects")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["id"] == "proj-001"

    def test_list_projects_empty(self, snyk_client):
        mock_c = MagicMock()
        mock_c.list_projects.return_value = []
        with patch("apps.api.snyk_router._get_client", return_value=mock_c):
            resp = snyk_client.get("/api/v1/scan/snyk/projects")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_projects_server_error(self, snyk_client):
        mock_c = MagicMock()
        mock_c.list_projects.side_effect = RuntimeError("API down")
        with patch("apps.api.snyk_router._get_client", return_value=mock_c):
            resp = snyk_client.get("/api/v1/scan/snyk/projects")
        assert resp.status_code == 500


class TestSnykRouterIssues:
    def test_get_issues_success(self, snyk_client):
        mock_c = MagicMock()
        mock_c.get_project_issues.return_value = SAMPLE_ISSUES
        with patch("apps.api.snyk_router._get_client", return_value=mock_c):
            resp = snyk_client.get(
                "/api/v1/scan/snyk/issues", params={"project_id": "proj-001"}
            )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2

    def test_get_issues_missing_project_id(self, snyk_client):
        resp = snyk_client.get("/api/v1/scan/snyk/issues")
        assert resp.status_code == 422

    def test_get_issues_value_error_returns_422(self, snyk_client):
        mock_c = MagicMock()
        mock_c.get_project_issues.side_effect = ValueError("invalid id")
        with patch("apps.api.snyk_router._get_client", return_value=mock_c):
            resp = snyk_client.get(
                "/api/v1/scan/snyk/issues", params={"project_id": "bad"}
            )
        assert resp.status_code == 422

    def test_get_issues_server_error(self, snyk_client):
        mock_c = MagicMock()
        mock_c.get_project_issues.side_effect = RuntimeError("fetch failed")
        with patch("apps.api.snyk_router._get_client", return_value=mock_c):
            resp = snyk_client.get(
                "/api/v1/scan/snyk/issues", params={"project_id": "proj-001"}
            )
        assert resp.status_code == 500


class TestSnykRouterTestPackage:
    def _mock_result(self, package: str = "lodash", version: str = "4.17.15") -> Dict[str, Any]:
        return {
            "ok": False,
            "packageName": package,
            "version": version,
            "vulnerabilities": [{"id": "SNYK-JS-001", "severity": "high"}],
            "is_mock": True,
        }

    def test_test_package_success(self, snyk_client):
        mock_c = MagicMock()
        mock_c.test_package.return_value = self._mock_result()
        with patch("apps.api.snyk_router._get_client", return_value=mock_c):
            resp = snyk_client.post(
                "/api/v1/scan/snyk/test-package",
                json={"ecosystem": "npm", "package": "lodash", "version": "4.17.15"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["packageName"] == "lodash"

    def test_test_package_missing_fields(self, snyk_client):
        resp = snyk_client.post(
            "/api/v1/scan/snyk/test-package",
            json={"ecosystem": "npm"},
        )
        assert resp.status_code == 422

    def test_test_package_value_error_returns_422(self, snyk_client):
        mock_c = MagicMock()
        mock_c.test_package.side_effect = ValueError("bad input")
        with patch("apps.api.snyk_router._get_client", return_value=mock_c):
            resp = snyk_client.post(
                "/api/v1/scan/snyk/test-package",
                json={"ecosystem": "npm", "package": "", "version": "1.0.0"},
            )
        assert resp.status_code == 422

    def test_test_package_server_error(self, snyk_client):
        mock_c = MagicMock()
        mock_c.test_package.side_effect = RuntimeError("API error")
        with patch("apps.api.snyk_router._get_client", return_value=mock_c):
            resp = snyk_client.post(
                "/api/v1/scan/snyk/test-package",
                json={"ecosystem": "npm", "package": "lodash", "version": "4.17.15"},
            )
        assert resp.status_code == 500


class TestSnykRouterImport:
    def _mock_import_entry(self, org_id: str = "test-org") -> Dict[str, Any]:
        return {
            "import_id": str(uuid.uuid4()),
            "org_id": org_id,
            "started_at": "2026-01-10T00:00:00+00:00",
            "completed_at": "2026-01-10T00:00:05+00:00",
            "status": "completed",
            "is_mock": True,
            "findings_count": 3,
            "severity_breakdown": {"critical": 1, "high": 1, "medium": 1},
            "findings": [],
        }

    def test_import_success(self, snyk_client):
        entry = self._mock_import_entry()
        mock_c = MagicMock()
        mock_c.import_results.return_value = []
        mock_c._org_id = "test-org"

        import core.snyk_integration as snyk_mod
        with patch("apps.api.snyk_router._get_client", return_value=mock_c), \
             patch.dict(snyk_mod._import_history, {"test-org": [entry]}):
            resp = snyk_client.post(
                "/api/v1/scan/snyk/import",
                json={"org_id": "test-org"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "completed"
        assert body["org_id"] == "test-org"

    def test_import_server_error(self, snyk_client):
        mock_c = MagicMock()
        mock_c.import_results.side_effect = RuntimeError("import blew up")
        with patch("apps.api.snyk_router._get_client", return_value=mock_c):
            resp = snyk_client.post(
                "/api/v1/scan/snyk/import",
                json={"org_id": "test-org"},
            )
        assert resp.status_code == 500

    def test_import_default_org_id(self, snyk_client):
        entry = self._mock_import_entry(org_id="default")
        mock_c = MagicMock()
        mock_c.import_results.return_value = []
        mock_c._org_id = ""

        import core.snyk_integration as snyk_mod
        with patch("apps.api.snyk_router._get_client", return_value=mock_c), \
             patch.dict(snyk_mod._import_history, {"default": [entry]}):
            resp = snyk_client.post("/api/v1/scan/snyk/import", json={})
        assert resp.status_code == 200


class TestSnykRouterHistory:
    def test_history_empty(self, snyk_client):
        mock_c = MagicMock()
        mock_c.get_import_history.return_value = []
        with patch("apps.api.snyk_router._get_client", return_value=mock_c):
            resp = snyk_client.get(
                "/api/v1/scan/snyk/history", params={"org_id": "noorg"}
            )
        assert resp.status_code == 200
        assert resp.json() == []

    def test_history_returns_list(self, snyk_client):
        entry = {
            "import_id": str(uuid.uuid4()),
            "org_id": "test-org",
            "started_at": "2026-01-10T00:00:00+00:00",
            "completed_at": "2026-01-10T00:00:05+00:00",
            "status": "completed",
            "is_mock": True,
            "findings_count": 3,
            "severity_breakdown": {"high": 2, "medium": 1},
        }
        mock_c = MagicMock()
        mock_c.get_import_history.return_value = [entry]
        with patch("apps.api.snyk_router._get_client", return_value=mock_c):
            resp = snyk_client.get(
                "/api/v1/scan/snyk/history", params={"org_id": "test-org"}
            )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["findings_count"] == 3

    def test_history_default_org_id(self, snyk_client):
        mock_c = MagicMock()
        mock_c.get_import_history.return_value = []
        with patch("apps.api.snyk_router._get_client", return_value=mock_c):
            resp = snyk_client.get("/api/v1/scan/snyk/history")
        assert resp.status_code == 200
        mock_c.get_import_history.assert_called_once_with(org_id="default")

    def test_history_server_error(self, snyk_client):
        mock_c = MagicMock()
        mock_c.get_import_history.side_effect = RuntimeError("db error")
        with patch("apps.api.snyk_router._get_client", return_value=mock_c):
            resp = snyk_client.get("/api/v1/scan/snyk/history")
        assert resp.status_code == 500
