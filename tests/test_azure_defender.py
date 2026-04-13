"""
Tests for Azure Defender integration — AzureDefenderClient and azure_defender_router.

All Azure SDK calls are mocked so no Azure credentials are required.
Covers: is_configured, get_alerts, get_secure_score, get_recommendations,
        import_findings, normalize, inline normalization, history,
        and all 6 API router endpoints.
"""

from __future__ import annotations

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


# ── Sample Azure Defender alert data ──────────────────────────────────────

SAMPLE_HIGH_ALERT: Dict[str, Any] = {
    "id": "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Security/locations/centralus/alerts/test-alert-001",
    "name": "test-alert-001",
    "type": "Microsoft.Security/Locations/alerts",
    "properties": {
        "alertDisplayName": "Suspicious process executed",
        "description": "A suspicious process was detected.",
        "severity": "High",
        "status": "Active",
        "compromisedEntity": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/vm-web-01",
        "resourceIdentifiers": [
            {
                "type": "AzureResource",
                "azureResourceId": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/vm-web-01",
            }
        ],
        "alertUri": "https://portal.azure.com/#blade/mock-alert-001",
        "startTimeUtc": "2026-01-05T10:00:00.000Z",
        "endTimeUtc": "2026-01-05T10:30:00.000Z",
        "systemAlertId": "test-alert-001",
        "productName": "Azure Security Center",
        "productComponentName": "VM Protection",
        "vendorName": "Microsoft",
        "alertType": "VM_SuspiciousProcess",
        "remediationSteps": ["Investigate the process tree.", "Isolate the VM if needed."],
        "tactics": ["Execution"],
        "techniques": ["T1059"],
        "intent": "Execution",
        "isIncident": False,
        "timeGeneratedUtc": "2026-01-05T10:01:00.000Z",
    },
}

SAMPLE_CRITICAL_ALERT: Dict[str, Any] = {
    "id": "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Security/locations/centralus/alerts/test-alert-002",
    "name": "test-alert-002",
    "type": "Microsoft.Security/Locations/alerts",
    "properties": {
        "alertDisplayName": "Credential theft tool detected",
        "description": "Mimikatz-like tool detected.",
        "severity": "Critical",
        "status": "Active",
        "compromisedEntity": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/vm-dc-01",
        "resourceIdentifiers": [
            {
                "type": "AzureResource",
                "azureResourceId": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/vm-dc-01",
            }
        ],
        "alertUri": "https://portal.azure.com/#blade/mock-alert-002",
        "startTimeUtc": "2026-01-06T08:00:00.000Z",
        "endTimeUtc": "2026-01-06T08:15:00.000Z",
        "systemAlertId": "test-alert-002",
        "productName": "Azure Security Center",
        "productComponentName": "VM Protection",
        "vendorName": "Microsoft",
        "alertType": "VM_CredentialTheftTool",
        "remediationSteps": ["Isolate the domain controller.", "Reset credentials."],
        "tactics": ["CredentialAccess"],
        "techniques": ["T1003"],
        "intent": "CredentialAccess",
        "isIncident": False,
        "timeGeneratedUtc": "2026-01-06T08:01:00.000Z",
    },
}

SAMPLE_ALERTS = [SAMPLE_HIGH_ALERT, SAMPLE_CRITICAL_ALERT]


# ── AzureDefenderClient unit tests ─────────────────────────────────────────


class TestAzureDefenderClientConfiguration:
    def test_is_configured_with_all_credentials(self):
        from core.azure_defender import AzureDefenderClient
        client = AzureDefenderClient(
            subscription_id="00000000-0000-0000-0000-000000000000",
            tenant_id="tenant-123",
            client_id="client-456",
            client_secret="secret-789",
        )
        assert client.is_configured() is True

    def test_is_configured_without_credentials(self):
        from core.azure_defender import AzureDefenderClient
        client = AzureDefenderClient(
            subscription_id="", tenant_id="", client_id="", client_secret=""
        )
        assert client.is_configured() is False

    def test_reads_credentials_from_env(self, monkeypatch):
        monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-env-123")
        monkeypatch.setenv("AZURE_TENANT_ID", "tenant-env-456")
        monkeypatch.setenv("AZURE_CLIENT_ID", "client-env-789")
        monkeypatch.setenv("AZURE_CLIENT_SECRET", "secret-env-abc")
        from core.azure_defender import AzureDefenderClient
        client = AzureDefenderClient()
        assert client.is_configured() is True
        assert client._subscription_id == "sub-env-123"
        assert client._tenant_id == "tenant-env-456"
        assert client._client_id == "client-env-789"
        assert client._client_secret == "secret-env-abc"

    def test_missing_client_secret_means_unconfigured(self):
        from core.azure_defender import AzureDefenderClient
        client = AzureDefenderClient(
            subscription_id="sub-123", tenant_id="tenant-123",
            client_id="client-123", client_secret=""
        )
        assert client.is_configured() is False

    def test_missing_subscription_id_means_unconfigured(self):
        from core.azure_defender import AzureDefenderClient
        client = AzureDefenderClient(
            subscription_id="", tenant_id="tenant-123",
            client_id="client-123", client_secret="secret-123"
        )
        assert client.is_configured() is False

    def test_strips_whitespace_from_credentials(self):
        from core.azure_defender import AzureDefenderClient
        client = AzureDefenderClient(
            subscription_id="  sub-123  ",
            tenant_id="  tenant-456  ",
            client_id="  client-789  ",
            client_secret="  secret-abc  ",
        )
        assert client._subscription_id == "sub-123"
        assert client._tenant_id == "tenant-456"
        assert client._client_id == "client-789"
        assert client._client_secret == "secret-abc"


class TestAzureDefenderClientMockFallback:
    """Mock data returned when no credentials are configured."""

    def _unconfigured(self):
        from core.azure_defender import AzureDefenderClient
        return AzureDefenderClient(
            subscription_id="", tenant_id="", client_id="", client_secret=""
        )

    def test_get_alerts_returns_mock_when_unconfigured(self):
        client = self._unconfigured()
        alerts = client.get_alerts()
        assert isinstance(alerts, list)
        assert len(alerts) > 0

    def test_get_alerts_mock_has_id_field(self):
        client = self._unconfigured()
        alerts = client.get_alerts()
        assert "id" in alerts[0]

    def test_get_alerts_mock_has_properties(self):
        client = self._unconfigured()
        alerts = client.get_alerts()
        assert "properties" in alerts[0]
        assert "alertDisplayName" in alerts[0]["properties"]

    def test_get_alerts_severity_filter_high(self):
        client = self._unconfigured()
        alerts = client.get_alerts(severity_filter="High")
        for a in alerts:
            assert a["properties"]["severity"] == "High"

    def test_get_alerts_severity_filter_critical(self):
        client = self._unconfigured()
        alerts = client.get_alerts(severity_filter="Critical")
        for a in alerts:
            assert a["properties"]["severity"] == "Critical"

    def test_get_alerts_none_filter_returns_all(self):
        client = self._unconfigured()
        all_alerts = client.get_alerts()
        filtered = client.get_alerts(severity_filter=None)
        assert len(all_alerts) == len(filtered)

    def test_get_secure_score_returns_mock_when_unconfigured(self):
        client = self._unconfigured()
        score = client.get_secure_score()
        assert isinstance(score, dict)
        assert score.get("is_mock") is True

    def test_get_secure_score_has_properties(self):
        client = self._unconfigured()
        score = client.get_secure_score()
        assert "properties" in score
        assert "score" in score["properties"]

    def test_get_secure_score_has_current_value(self):
        client = self._unconfigured()
        score = client.get_secure_score()
        current = score["properties"]["score"]["current"]
        assert isinstance(current, (int, float))
        assert 0 <= current <= 100

    def test_get_recommendations_returns_mock_when_unconfigured(self):
        client = self._unconfigured()
        recs = client.get_recommendations()
        assert isinstance(recs, list)
        assert len(recs) > 0

    def test_get_recommendations_mock_has_properties(self):
        client = self._unconfigured()
        recs = client.get_recommendations()
        assert "properties" in recs[0]
        assert "displayName" in recs[0]["properties"]

    def test_get_recommendations_category_filter(self):
        client = self._unconfigured()
        recs = client.get_recommendations(category="IdentityAndAccess")
        for r in recs:
            assert r["properties"]["category"].lower() == "identityandaccess"

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

    def test_import_findings_severity_breakdown_sums_to_count(self):
        client = self._unconfigured()
        client._try_ingest_to_pipeline = MagicMock()
        result = client.import_findings(org_id="test-org")
        total = sum(result["severity_breakdown"].values())
        assert total == result["findings_count"]


class TestAzureDefenderNormalize:
    """Tests for Azure Defender alert → UnifiedFinding normalization."""

    def _unconfigured(self):
        from core.azure_defender import AzureDefenderClient
        return AzureDefenderClient(
            subscription_id="", tenant_id="", client_id="", client_secret=""
        )

    def test_normalize_returns_list(self):
        client = self._unconfigured()
        result = client.normalize(SAMPLE_ALERTS)
        assert isinstance(result, list)
        assert len(result) == 2

    def test_normalize_empty_input(self):
        client = self._unconfigured()
        result = client.normalize([])
        assert result == []

    def test_normalize_maps_high_severity(self):
        client = self._unconfigured()
        result = client.normalize([SAMPLE_HIGH_ALERT])
        assert result[0]["severity"] == "high"

    def test_normalize_maps_critical_severity(self):
        client = self._unconfigured()
        result = client.normalize([SAMPLE_CRITICAL_ALERT])
        assert result[0]["severity"] == "critical"

    def test_normalize_sets_source_tool(self):
        client = self._unconfigured()
        result = client.normalize([SAMPLE_HIGH_ALERT])
        assert result[0]["source_tool"] == "azure_defender"

    def test_normalize_preserves_title(self):
        client = self._unconfigured()
        result = client.normalize([SAMPLE_HIGH_ALERT])
        assert "Suspicious process" in result[0]["title"]

    def test_normalize_includes_resource_id(self):
        client = self._unconfigured()
        result = client.normalize([SAMPLE_HIGH_ALERT])
        assert "vm-web-01" in result[0]["resource_id"]

    def test_normalize_includes_tactics(self):
        client = self._unconfigured()
        result = client.normalize([SAMPLE_HIGH_ALERT])
        assert result[0]["tactics"] == ["Execution"]

    def test_normalize_includes_techniques(self):
        client = self._unconfigured()
        result = client.normalize([SAMPLE_HIGH_ALERT])
        assert result[0]["techniques"] == ["T1059"]

    def test_normalize_joins_remediation_steps(self):
        client = self._unconfigured()
        result = client.normalize([SAMPLE_HIGH_ALERT])
        assert "Investigate" in result[0]["recommendation"]

    def test_normalize_each_finding_has_unique_id(self):
        client = self._unconfigured()
        result = client.normalize(SAMPLE_ALERTS)
        ids = [f["id"] for f in result]
        assert len(set(ids)) == len(ids)

    def test_normalize_maps_informational_to_info(self):
        client = self._unconfigured()
        info_alert = {
            "id": "test-info",
            "name": "info-alert",
            "properties": {
                "alertDisplayName": "Info alert",
                "description": "Informational alert",
                "severity": "Informational",
                "status": "Active",
                "resourceIdentifiers": [],
                "remediationSteps": [],
                "tactics": [],
                "techniques": [],
            },
        }
        result = client.normalize([info_alert])
        assert result[0]["severity"] == "info"

    def test_normalize_includes_alert_type(self):
        client = self._unconfigured()
        result = client.normalize([SAMPLE_HIGH_ALERT])
        assert result[0]["alert_type"] == "VM_SuspiciousProcess"


class TestAzureDefenderImportHistory:
    """Tests for import history tracking."""

    def test_import_history_empty_for_new_org(self):
        from core.azure_defender import AzureDefenderClient
        client = AzureDefenderClient(
            subscription_id="", tenant_id="", client_id="", client_secret=""
        )
        history = client.get_import_history(org_id="brand-new-org-" + str(uuid.uuid4()))
        assert history == []

    def test_import_history_recorded_after_import(self):
        from core.azure_defender import AzureDefenderClient
        client = AzureDefenderClient(
            subscription_id="", tenant_id="", client_id="", client_secret=""
        )
        client._try_ingest_to_pipeline = MagicMock()
        org_id = "history-test-org-" + str(uuid.uuid4())
        client.import_findings(org_id=org_id)
        history = client.get_import_history(org_id=org_id)
        assert len(history) == 1
        assert history[0]["org_id"] == org_id

    def test_import_history_excludes_findings(self):
        from core.azure_defender import AzureDefenderClient
        client = AzureDefenderClient(
            subscription_id="", tenant_id="", client_id="", client_secret=""
        )
        client._try_ingest_to_pipeline = MagicMock()
        org_id = "no-findings-in-history-" + str(uuid.uuid4())
        client.import_findings(org_id=org_id)
        history = client.get_import_history(org_id=org_id)
        assert "findings" not in history[0]

    def test_import_history_most_recent_first(self):
        from core.azure_defender import AzureDefenderClient
        client = AzureDefenderClient(
            subscription_id="", tenant_id="", client_id="", client_secret=""
        )
        client._try_ingest_to_pipeline = MagicMock()
        org_id = "order-test-org-" + str(uuid.uuid4())
        client.import_findings(org_id=org_id)
        client.import_findings(org_id=org_id)
        history = client.get_import_history(org_id=org_id)
        assert len(history) == 2
        assert history[0]["completed_at"] >= history[1]["completed_at"]


# ── Router / API endpoint tests ────────────────────────────────────────────


@pytest.fixture
def test_client():
    """FastAPI TestClient with azure_defender_router mounted."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()

    from apps.api.azure_defender_router import router
    from apps.api.auth_deps import api_key_auth
    app.dependency_overrides[api_key_auth] = lambda: None

    app.include_router(router)

    # Reset the singleton client so each test gets a fresh unconfigured one
    import apps.api.azure_defender_router as defender_router_mod
    defender_router_mod._client = None

    return TestClient(app)


class TestAzureDefenderRouterStatus:
    def test_status_returns_200(self, test_client):
        resp = test_client.get("/api/v1/scan/azure-defender/status")
        assert resp.status_code == 200

    def test_status_unconfigured_has_configured_false(self, test_client):
        resp = test_client.get("/api/v1/scan/azure-defender/status")
        data = resp.json()
        assert data["configured"] is False

    def test_status_includes_subscription_id(self, test_client):
        resp = test_client.get("/api/v1/scan/azure-defender/status")
        data = resp.json()
        assert "subscription_id" in data

    def test_status_message_mentions_mock_mode(self, test_client):
        resp = test_client.get("/api/v1/scan/azure-defender/status")
        data = resp.json()
        assert "mock" in data["message"].lower()


class TestAzureDefenderRouterAlerts:
    def test_get_alerts_returns_200(self, test_client):
        resp = test_client.get("/api/v1/scan/azure-defender/alerts")
        assert resp.status_code == 200

    def test_get_alerts_returns_list(self, test_client):
        resp = test_client.get("/api/v1/scan/azure-defender/alerts")
        assert isinstance(resp.json(), list)
        assert len(resp.json()) > 0

    def test_get_alerts_with_severity_filter(self, test_client):
        resp = test_client.get(
            "/api/v1/scan/azure-defender/alerts", params={"severity": "High"}
        )
        assert resp.status_code == 200
        alerts = resp.json()
        assert isinstance(alerts, list)
        for a in alerts:
            assert a["properties"]["severity"] == "High"

    def test_get_alerts_mock_has_properties(self, test_client):
        resp = test_client.get("/api/v1/scan/azure-defender/alerts")
        alerts = resp.json()
        assert "properties" in alerts[0]
        assert "alertDisplayName" in alerts[0]["properties"]


class TestAzureDefenderRouterSecureScore:
    def test_get_secure_score_returns_200(self, test_client):
        resp = test_client.get("/api/v1/scan/azure-defender/secure-score")
        assert resp.status_code == 200

    def test_get_secure_score_has_properties(self, test_client):
        resp = test_client.get("/api/v1/scan/azure-defender/secure-score")
        data = resp.json()
        assert "properties" in data

    def test_get_secure_score_is_mock_flag(self, test_client):
        resp = test_client.get("/api/v1/scan/azure-defender/secure-score")
        data = resp.json()
        assert data.get("is_mock") is True


class TestAzureDefenderRouterRecommendations:
    def test_get_recommendations_returns_200(self, test_client):
        resp = test_client.get("/api/v1/scan/azure-defender/recommendations")
        assert resp.status_code == 200

    def test_get_recommendations_returns_list(self, test_client):
        resp = test_client.get("/api/v1/scan/azure-defender/recommendations")
        assert isinstance(resp.json(), list)
        assert len(resp.json()) > 0

    def test_get_recommendations_with_category_filter(self, test_client):
        resp = test_client.get(
            "/api/v1/scan/azure-defender/recommendations",
            params={"category": "IdentityAndAccess"},
        )
        assert resp.status_code == 200
        recs = resp.json()
        assert isinstance(recs, list)

    def test_get_recommendations_mock_has_display_name(self, test_client):
        resp = test_client.get("/api/v1/scan/azure-defender/recommendations")
        recs = resp.json()
        assert "displayName" in recs[0]["properties"]


class TestAzureDefenderRouterImport:
    def test_import_returns_200(self, test_client):
        resp = test_client.post(
            "/api/v1/scan/azure-defender/import", json={"org_id": "test-org"}
        )
        assert resp.status_code == 200

    def test_import_returns_completed_status(self, test_client):
        resp = test_client.post(
            "/api/v1/scan/azure-defender/import", json={"org_id": "test-org"}
        )
        data = resp.json()
        assert data["status"] == "completed"

    def test_import_is_mock_true_when_unconfigured(self, test_client):
        resp = test_client.post(
            "/api/v1/scan/azure-defender/import", json={"org_id": "test-org"}
        )
        data = resp.json()
        assert data["is_mock"] is True

    def test_import_has_findings_count(self, test_client):
        resp = test_client.post(
            "/api/v1/scan/azure-defender/import", json={"org_id": "test-org"}
        )
        data = resp.json()
        assert data["findings_count"] > 0

    def test_import_has_severity_breakdown(self, test_client):
        resp = test_client.post(
            "/api/v1/scan/azure-defender/import", json={"org_id": "test-org"}
        )
        data = resp.json()
        assert "severity_breakdown" in data
        assert isinstance(data["severity_breakdown"], dict)

    def test_import_default_org_id(self, test_client):
        resp = test_client.post(
            "/api/v1/scan/azure-defender/import", json={}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["org_id"] == "default"

    def test_import_findings_list_has_source_tool(self, test_client):
        resp = test_client.post(
            "/api/v1/scan/azure-defender/import", json={"org_id": "tool-check"}
        )
        data = resp.json()
        for f in data["findings"]:
            assert f["source_tool"] == "azure_defender"


class TestAzureDefenderRouterHistory:
    def test_history_returns_200(self, test_client):
        resp = test_client.get("/api/v1/scan/azure-defender/history")
        assert resp.status_code == 200

    def test_history_returns_list(self, test_client):
        resp = test_client.get("/api/v1/scan/azure-defender/history")
        assert isinstance(resp.json(), list)

    def test_history_populated_after_import(self, test_client):
        org_id = "router-history-" + str(uuid.uuid4())
        test_client.post(
            "/api/v1/scan/azure-defender/import", json={"org_id": org_id}
        )
        resp = test_client.get(
            "/api/v1/scan/azure-defender/history", params={"org_id": org_id}
        )
        data = resp.json()
        assert len(data) >= 1
        assert data[0]["org_id"] == org_id

    def test_history_entries_have_no_findings_key(self, test_client):
        org_id = "no-findings-router-" + str(uuid.uuid4())
        test_client.post(
            "/api/v1/scan/azure-defender/import", json={"org_id": org_id}
        )
        resp = test_client.get(
            "/api/v1/scan/azure-defender/history", params={"org_id": org_id}
        )
        for entry in resp.json():
            assert "findings" not in entry
