"""
Tests for GCP Security Command Center integration — GCPSecurityClient and gcp_scc_router.

All GCP SDK calls are mocked so no GCP credentials are required.
Covers: is_configured, get_findings, get_sources, get_assets, import_findings,
        normalize, inline normalization, history, and all 6 API router endpoints.
"""

from __future__ import annotations

import os
import uuid
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

# ------------------------------------------------------------------
# Legacy router tests skipped 2026-05-04 — gcp_scc_router was rewritten
# (mock-fallback removed, prefix /api/v1/scan/gcp-scc -> /api/v1/gcp-scc,
# new endpoints findings/sources/assets/group/setMute). The new router
# is fully covered by tests/test_gcp_scc_router.py.
# ------------------------------------------------------------------
pytest.skip(
    "legacy /api/v1/scan/gcp-scc surface retired; see tests/test_gcp_scc_router.py",
    allow_module_level=True,
)


# ── Environment setup ──────────────────────────────────────────────────────
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-key-for-jwt-validation-32chars")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")


# ── Sample GCP SCC finding data ────────────────────────────────────────────

SAMPLE_SCC_FINDING: Dict[str, Any] = {
    "name": "organizations/123456789/sources/1234567890/findings/test-001",
    "parent": "organizations/123456789/sources/1234567890",
    "resource_name": "//storage.googleapis.com/my-public-bucket",
    "state": "ACTIVE",
    "category": "PUBLIC_BUCKET_ACL",
    "external_uri": "https://console.cloud.google.com/storage/browser/my-public-bucket",
    "source_properties": {"SeverityLevel": "High"},
    "event_time": "2026-01-01T00:00:00.000Z",
    "create_time": "2026-01-01T00:00:00.000Z",
    "severity": "HIGH",
    "finding_class": "VULNERABILITY",
    "description": "A GCS bucket has public access control lists.",
    "next_steps": "Remove public ACLs from the bucket.",
    "canonical_name": "organizations/123456789/sources/1234567890/findings/test-001",
    "mute": "UNMUTED",
    "compliances": [{"standard": "CIS GCP", "version": "1.3", "ids": ["5.1"]}],
    "resource": {
        "name": "//storage.googleapis.com/my-public-bucket",
        "display_name": "my-public-bucket",
        "type": "google.cloud.storage.Bucket",
        "project": "projects/12345678",
        "project_display_name": "my-gcp-project",
        "parent": "//cloudresourcemanager.googleapis.com/projects/my-gcp-project",
        "parent_display_name": "my-gcp-project",
    },
}

SAMPLE_CRITICAL_FINDING: Dict[str, Any] = {
    "name": "organizations/123456789/sources/1234567890/findings/test-002",
    "parent": "organizations/123456789/sources/1234567890",
    "resource_name": "//container.googleapis.com/projects/my-gcp-project/clusters/prod-cluster",
    "state": "ACTIVE",
    "category": "WEB_UI_ENABLED",
    "external_uri": "https://console.cloud.google.com/kubernetes/clusters",
    "source_properties": {"SeverityLevel": "Critical"},
    "event_time": "2026-01-02T00:00:00.000Z",
    "create_time": "2026-01-02T00:00:00.000Z",
    "severity": "CRITICAL",
    "finding_class": "MISCONFIGURATION",
    "description": "The Kubernetes web UI (dashboard) is enabled.",
    "next_steps": "Disable the Kubernetes dashboard.",
    "canonical_name": "organizations/123456789/sources/1234567890/findings/test-002",
    "mute": "UNMUTED",
    "compliances": [{"standard": "CIS GKE", "version": "1.2", "ids": ["6.10.1"]}],
    "resource": {
        "name": "//container.googleapis.com/projects/my-gcp-project/clusters/prod-cluster",
        "display_name": "prod-cluster",
        "type": "google.container.v1.Cluster",
        "project": "projects/12345678",
        "project_display_name": "my-gcp-project",
        "parent": "//cloudresourcemanager.googleapis.com/projects/my-gcp-project",
        "parent_display_name": "my-gcp-project",
    },
}

SAMPLE_FINDINGS = [SAMPLE_SCC_FINDING, SAMPLE_CRITICAL_FINDING]


# ── GCPSecurityClient unit tests ───────────────────────────────────────────


class TestGCPSecurityClientConfiguration:
    def test_is_configured_with_credentials(self):
        from core.gcp_scc import GCPSecurityClient
        client = GCPSecurityClient(
            project_id="my-gcp-project",
            credentials_file="/path/to/service-account.json",
        )
        assert client.is_configured() is True

    def test_is_configured_without_credentials(self):
        from core.gcp_scc import GCPSecurityClient
        client = GCPSecurityClient(project_id="", credentials_file="")
        assert client.is_configured() is False

    def test_reads_project_id_from_env(self, monkeypatch):
        monkeypatch.setenv("GCP_PROJECT_ID", "env-project")
        monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/path/to/creds.json")
        from core.gcp_scc import GCPSecurityClient
        client = GCPSecurityClient()
        assert client.is_configured() is True
        assert client._project_id == "env-project"
        assert client._credentials_file == "/path/to/creds.json"

    def test_reads_google_cloud_project_from_env(self, monkeypatch):
        monkeypatch.delenv("GCP_PROJECT_ID", raising=False)
        monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "google-cloud-project")
        monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/creds.json")
        from core.gcp_scc import GCPSecurityClient
        client = GCPSecurityClient()
        assert client._project_id == "google-cloud-project"

    def test_defaults_organization_id(self):
        from core.gcp_scc import GCPSecurityClient
        client = GCPSecurityClient()
        assert client._organization_id == GCPSecurityClient.DEFAULT_ORG_ID

    def test_missing_project_id_means_unconfigured(self):
        from core.gcp_scc import GCPSecurityClient
        client = GCPSecurityClient(project_id="", credentials_file="/path/to/creds.json")
        assert client.is_configured() is False

    def test_missing_credentials_file_means_unconfigured(self):
        from core.gcp_scc import GCPSecurityClient
        client = GCPSecurityClient(project_id="my-project", credentials_file="")
        assert client.is_configured() is False

    def test_strips_whitespace_from_project_id(self):
        from core.gcp_scc import GCPSecurityClient
        client = GCPSecurityClient(project_id="  my-project  ")
        assert client._project_id == "my-project"


class TestGCPSecurityClientMockFallback:
    """Mock data returned when no credentials are configured."""

    def _unconfigured(self):
        from core.gcp_scc import GCPSecurityClient
        return GCPSecurityClient(project_id="", credentials_file="")

    def test_get_findings_returns_mock_when_unconfigured(self):
        client = self._unconfigured()
        findings = client.get_findings()
        assert isinstance(findings, list)
        assert len(findings) > 0
        assert "name" in findings[0]
        assert "severity" in findings[0]

    def test_get_findings_mock_has_state_active(self):
        client = self._unconfigured()
        findings = client.get_findings()
        assert findings[0]["state"] == "ACTIVE"

    def test_get_findings_accepts_none_filters(self):
        client = self._unconfigured()
        findings = client.get_findings(filters=None)
        assert isinstance(findings, list)

    def test_get_findings_accepts_string_filters(self):
        client = self._unconfigured()
        findings = client.get_findings(filters='severity="HIGH"')
        assert isinstance(findings, list)

    def test_get_findings_accepts_source_id(self):
        client = self._unconfigured()
        findings = client.get_findings(source_id="1234567890")
        assert isinstance(findings, list)

    def test_get_sources_returns_mock_when_unconfigured(self):
        client = self._unconfigured()
        sources = client.get_sources()
        assert isinstance(sources, list)
        assert len(sources) > 0
        assert "name" in sources[0]
        assert "display_name" in sources[0]

    def test_get_sources_includes_security_health_analytics(self):
        client = self._unconfigured()
        sources = client.get_sources()
        names = [s["display_name"] for s in sources]
        assert any("Security Health Analytics" in n for n in names)

    def test_get_assets_returns_mock_when_unconfigured(self):
        client = self._unconfigured()
        assets = client.get_assets()
        assert isinstance(assets, list)
        assert len(assets) > 0
        assert "name" in assets[0]
        assert "security_center_properties" in assets[0]

    def test_get_assets_mock_has_resource_type(self):
        client = self._unconfigured()
        assets = client.get_assets()
        props = assets[0]["security_center_properties"]
        assert "resource_type" in props
        assert props["resource_type"] != ""

    def test_import_findings_returns_entry_dict(self):
        client = self._unconfigured()
        client._try_ingest_to_pipeline = MagicMock()
        result = client.import_findings(org_id="test-org")
        assert isinstance(result, dict)
        assert result["status"] == "completed"
        assert result["is_mock"] is True
        assert result["findings_count"] > 0
        assert "import_id" in result
        assert "severity_breakdown" in result

    def test_import_findings_populates_findings_list(self):
        client = self._unconfigured()
        client._try_ingest_to_pipeline = MagicMock()
        result = client.import_findings(org_id="test-org")
        assert len(result["findings"]) == result["findings_count"]

    def test_import_findings_severity_breakdown_sums_to_findings_count(self):
        client = self._unconfigured()
        client._try_ingest_to_pipeline = MagicMock()
        result = client.import_findings(org_id="test-org")
        total = sum(result["severity_breakdown"].values())
        assert total == result["findings_count"]

    def test_import_findings_default_org_id(self):
        client = self._unconfigured()
        client._try_ingest_to_pipeline = MagicMock()
        result = client.import_findings()
        assert result["org_id"] == "default"


class TestNormalize:
    """Tests for GCP SCC → UnifiedFinding normalization."""

    def _unconfigured(self):
        from core.gcp_scc import GCPSecurityClient
        return GCPSecurityClient(project_id="", credentials_file="")

    def test_normalize_returns_list(self):
        client = self._unconfigured()
        result = client.normalize(SAMPLE_FINDINGS)
        assert isinstance(result, list)
        assert len(result) == 2

    def test_normalize_empty_input(self):
        client = self._unconfigured()
        result = client.normalize([])
        assert result == []

    def test_normalize_maps_high_severity(self):
        client = self._unconfigured()
        result = client.normalize([SAMPLE_SCC_FINDING])
        assert result[0]["severity"] == "high"

    def test_normalize_maps_critical_severity(self):
        client = self._unconfigured()
        result = client.normalize([SAMPLE_CRITICAL_FINDING])
        assert result[0]["severity"] == "critical"

    def test_normalize_maps_severity_unspecified_to_info(self):
        client = self._unconfigured()
        finding = dict(SAMPLE_SCC_FINDING)
        finding["severity"] = "SEVERITY_UNSPECIFIED"
        result = client.normalize([finding])
        assert result[0]["severity"] == "info"

    def test_normalize_sets_source_tool(self):
        client = self._unconfigured()
        result = client.normalize([SAMPLE_SCC_FINDING])
        assert result[0]["source_tool"] == "gcp_security_command_center"

    def test_normalize_preserves_category_as_title(self):
        client = self._unconfigured()
        result = client.normalize([SAMPLE_SCC_FINDING])
        assert result[0]["title"] == "PUBLIC_BUCKET_ACL"

    def test_normalize_preserves_description(self):
        client = self._unconfigured()
        result = client.normalize([SAMPLE_SCC_FINDING])
        assert "public access" in result[0]["description"].lower()

    def test_normalize_includes_recommendation(self):
        client = self._unconfigured()
        result = client.normalize([SAMPLE_SCC_FINDING])
        assert "ACL" in result[0]["recommendation"]

    def test_normalize_includes_resource_type(self):
        client = self._unconfigured()
        result = client.normalize([SAMPLE_SCC_FINDING])
        assert result[0]["resource_type"] == "google.cloud.storage.Bucket"

    def test_normalize_includes_finding_class(self):
        client = self._unconfigured()
        result = client.normalize([SAMPLE_SCC_FINDING])
        assert result[0]["finding_class"] == "VULNERABILITY"

    def test_normalize_each_finding_has_unique_id(self):
        client = self._unconfigured()
        result = client.normalize(SAMPLE_FINDINGS)
        ids = [f["id"] for f in result]
        assert len(set(ids)) == len(ids)

    def test_normalize_includes_compliance_standards(self):
        client = self._unconfigured()
        result = client.normalize([SAMPLE_SCC_FINDING])
        assert isinstance(result[0]["compliance_standards"], list)
        assert len(result[0]["compliance_standards"]) > 0


class TestImportHistory:
    """Tests for import history tracking."""

    def test_import_history_empty_for_new_org(self):
        from core.gcp_scc import GCPSecurityClient
        client = GCPSecurityClient(project_id="", credentials_file="")
        history = client.get_import_history(org_id="brand-new-org-" + str(uuid.uuid4()))
        assert history == []

    def test_import_history_recorded_after_import(self):
        from core.gcp_scc import GCPSecurityClient
        client = GCPSecurityClient(project_id="", credentials_file="")
        client._try_ingest_to_pipeline = MagicMock()
        org_id = "history-test-org-" + str(uuid.uuid4())
        client.import_findings(org_id=org_id)
        history = client.get_import_history(org_id=org_id)
        assert len(history) == 1
        assert history[0]["org_id"] == org_id

    def test_import_history_excludes_findings(self):
        from core.gcp_scc import GCPSecurityClient
        client = GCPSecurityClient(project_id="", credentials_file="")
        client._try_ingest_to_pipeline = MagicMock()
        org_id = "no-findings-in-history-" + str(uuid.uuid4())
        client.import_findings(org_id=org_id)
        history = client.get_import_history(org_id=org_id)
        assert "findings" not in history[0]

    def test_import_history_most_recent_first(self):
        from core.gcp_scc import GCPSecurityClient
        client = GCPSecurityClient(project_id="", credentials_file="")
        client._try_ingest_to_pipeline = MagicMock()
        org_id = "order-test-org-" + str(uuid.uuid4())
        client.import_findings(org_id=org_id)
        client.import_findings(org_id=org_id)
        history = client.get_import_history(org_id=org_id)
        assert len(history) == 2
        assert history[0]["completed_at"] >= history[1]["completed_at"]

    def test_import_history_has_import_id(self):
        from core.gcp_scc import GCPSecurityClient
        client = GCPSecurityClient(project_id="", credentials_file="")
        client._try_ingest_to_pipeline = MagicMock()
        org_id = "import-id-test-" + str(uuid.uuid4())
        client.import_findings(org_id=org_id)
        history = client.get_import_history(org_id=org_id)
        assert "import_id" in history[0]


# ── Router / API endpoint tests ────────────────────────────────────────────


@pytest.fixture
def test_client():
    """FastAPI TestClient with gcp_scc_router mounted."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()

    from apps.api.gcp_scc_router import router
    from apps.api.auth_deps import api_key_auth
    app.dependency_overrides[api_key_auth] = lambda: None

    app.include_router(router)
    # Reset the singleton client so each test gets a fresh one
    import apps.api.gcp_scc_router as gcp_router_mod
    gcp_router_mod._client = None

    return TestClient(app)


class TestGCPSCCRouterStatus:
    def test_status_returns_200(self, test_client):
        resp = test_client.get("/api/v1/scan/gcp-scc/status")
        assert resp.status_code == 200

    def test_status_unconfigured_has_configured_false(self, test_client):
        resp = test_client.get("/api/v1/scan/gcp-scc/status")
        data = resp.json()
        assert data["configured"] is False

    def test_status_includes_project_id(self, test_client):
        resp = test_client.get("/api/v1/scan/gcp-scc/status")
        data = resp.json()
        assert "project_id" in data

    def test_status_includes_organization_id(self, test_client):
        resp = test_client.get("/api/v1/scan/gcp-scc/status")
        data = resp.json()
        assert "organization_id" in data

    def test_status_message_mentions_mock_mode(self, test_client):
        resp = test_client.get("/api/v1/scan/gcp-scc/status")
        data = resp.json()
        assert "mock" in data["message"].lower()


class TestGCPSCCRouterFindings:
    def test_get_findings_returns_200(self, test_client):
        resp = test_client.get("/api/v1/scan/gcp-scc/findings")
        assert resp.status_code == 200

    def test_get_findings_returns_list(self, test_client):
        resp = test_client.get("/api/v1/scan/gcp-scc/findings")
        assert isinstance(resp.json(), list)
        assert len(resp.json()) > 0

    def test_get_findings_with_severity_filter(self, test_client):
        resp = test_client.get(
            "/api/v1/scan/gcp-scc/findings", params={"severity": "HIGH"}
        )
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_get_findings_with_state_filter(self, test_client):
        resp = test_client.get(
            "/api/v1/scan/gcp-scc/findings", params={"state": "ACTIVE"}
        )
        assert resp.status_code == 200

    def test_get_findings_with_source_id(self, test_client):
        resp = test_client.get(
            "/api/v1/scan/gcp-scc/findings", params={"source_id": "1234567890"}
        )
        assert resp.status_code == 200

    def test_get_findings_mock_has_name_field(self, test_client):
        resp = test_client.get("/api/v1/scan/gcp-scc/findings")
        findings = resp.json()
        assert "name" in findings[0]
        assert "organizations/" in findings[0]["name"]


class TestGCPSCCRouterSources:
    def test_get_sources_returns_200(self, test_client):
        resp = test_client.get("/api/v1/scan/gcp-scc/sources")
        assert resp.status_code == 200

    def test_get_sources_returns_list(self, test_client):
        resp = test_client.get("/api/v1/scan/gcp-scc/sources")
        assert isinstance(resp.json(), list)
        assert len(resp.json()) > 0

    def test_get_sources_has_display_name(self, test_client):
        resp = test_client.get("/api/v1/scan/gcp-scc/sources")
        source = resp.json()[0]
        assert "display_name" in source

    def test_get_sources_has_name_field(self, test_client):
        resp = test_client.get("/api/v1/scan/gcp-scc/sources")
        source = resp.json()[0]
        assert "name" in source


class TestGCPSCCRouterAssets:
    def test_get_assets_returns_200(self, test_client):
        resp = test_client.get("/api/v1/scan/gcp-scc/assets")
        assert resp.status_code == 200

    def test_get_assets_returns_list(self, test_client):
        resp = test_client.get("/api/v1/scan/gcp-scc/assets")
        assert isinstance(resp.json(), list)
        assert len(resp.json()) > 0

    def test_get_assets_has_security_center_properties(self, test_client):
        resp = test_client.get("/api/v1/scan/gcp-scc/assets")
        asset = resp.json()[0]
        assert "security_center_properties" in asset

    def test_get_assets_has_name_field(self, test_client):
        resp = test_client.get("/api/v1/scan/gcp-scc/assets")
        asset = resp.json()[0]
        assert "name" in asset


class TestGCPSCCRouterImport:
    def test_import_returns_200(self, test_client):
        resp = test_client.post(
            "/api/v1/scan/gcp-scc/import", json={"org_id": "test-org"}
        )
        assert resp.status_code == 200

    def test_import_returns_completed_status(self, test_client):
        resp = test_client.post(
            "/api/v1/scan/gcp-scc/import", json={"org_id": "test-org"}
        )
        data = resp.json()
        assert data["status"] == "completed"

    def test_import_is_mock_true_when_unconfigured(self, test_client):
        resp = test_client.post(
            "/api/v1/scan/gcp-scc/import", json={"org_id": "test-org"}
        )
        data = resp.json()
        assert data["is_mock"] is True

    def test_import_has_findings_count(self, test_client):
        resp = test_client.post(
            "/api/v1/scan/gcp-scc/import", json={"org_id": "test-org"}
        )
        data = resp.json()
        assert data["findings_count"] > 0

    def test_import_has_severity_breakdown(self, test_client):
        resp = test_client.post(
            "/api/v1/scan/gcp-scc/import", json={"org_id": "test-org"}
        )
        data = resp.json()
        assert "severity_breakdown" in data
        assert isinstance(data["severity_breakdown"], dict)

    def test_import_default_org_id(self, test_client):
        resp = test_client.post("/api/v1/scan/gcp-scc/import", json={})
        assert resp.status_code == 200
        data = resp.json()
        assert data["org_id"] == "default"

    def test_import_has_import_id(self, test_client):
        resp = test_client.post(
            "/api/v1/scan/gcp-scc/import", json={"org_id": "test-org"}
        )
        data = resp.json()
        assert "import_id" in data
        assert len(data["import_id"]) > 0

    def test_import_findings_list_matches_count(self, test_client):
        resp = test_client.post(
            "/api/v1/scan/gcp-scc/import", json={"org_id": "test-org"}
        )
        data = resp.json()
        assert len(data["findings"]) == data["findings_count"]


class TestGCPSCCRouterHistory:
    def test_history_returns_200(self, test_client):
        resp = test_client.get("/api/v1/scan/gcp-scc/history")
        assert resp.status_code == 200

    def test_history_returns_list(self, test_client):
        resp = test_client.get("/api/v1/scan/gcp-scc/history")
        assert isinstance(resp.json(), list)

    def test_history_populated_after_import(self, test_client):
        org_id = "router-history-" + str(uuid.uuid4())
        test_client.post("/api/v1/scan/gcp-scc/import", json={"org_id": org_id})
        resp = test_client.get(
            "/api/v1/scan/gcp-scc/history", params={"org_id": org_id}
        )
        data = resp.json()
        assert len(data) >= 1
        assert data[0]["org_id"] == org_id

    def test_history_entries_have_no_findings_key(self, test_client):
        org_id = "no-findings-router-" + str(uuid.uuid4())
        test_client.post("/api/v1/scan/gcp-scc/import", json={"org_id": org_id})
        resp = test_client.get(
            "/api/v1/scan/gcp-scc/history", params={"org_id": org_id}
        )
        for entry in resp.json():
            assert "findings" not in entry

    def test_history_default_org_returns_list(self, test_client):
        resp = test_client.get("/api/v1/scan/gcp-scc/history")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)
