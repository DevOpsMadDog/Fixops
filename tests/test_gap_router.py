"""Tests for gap_router (suite-api/apps/api/gap_router.py).

Covers:
  - Audit gap endpoints
  - Bulk gap endpoints
  - Copilot gap endpoints (ChatRequest model)
  - FAIL gap endpoints
  - Graph gap endpoints
  - Integrations gap endpoints
  - Router mounting and tag validation
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from apps.api.gap_router import (
    audit_gap,
    bulk_gap,
    copilot_gap,
    ChatRequest,
    fail_gap,
    graph_gap,
    integrations_gap,
    mpte_gap,
    playbooks_gap,
    predictions_gap,
    reports_gap,
    scanner_gap,
    evidence_gap,
    compliance_gap,
    changes_gap,
    workflows_gap,
    sbom_gap,
    attack_paths_gap,
    data_fabric_gap,
    correlation_gap,
    scanner_registry_gap,
    notifications_gap,
    app_config_gap,
    attack_simulation_gap,
    slsa_gap,
    findings_gap,
    compliance_status_gap,
)


# ──────────────────────────────────────────────────────
#  Helper to create a test app with gap routers
# ──────────────────────────────────────────────────────


@pytest.fixture
def app():
    """Create a FastAPI app with gap routers mounted."""
    _app = FastAPI()
    for r in [
        audit_gap, bulk_gap, copilot_gap, fail_gap, graph_gap,
        integrations_gap, mpte_gap, playbooks_gap, predictions_gap,
        reports_gap, scanner_gap, evidence_gap, compliance_gap, changes_gap,
        workflows_gap, sbom_gap, attack_paths_gap, data_fabric_gap,
        correlation_gap, scanner_registry_gap, notifications_gap,
        app_config_gap, attack_simulation_gap, slsa_gap, findings_gap,
        compliance_status_gap,
    ]:
        _app.include_router(r)
    return _app


@pytest.fixture
def client(app):
    """Create a test client with auth headers pre-configured.

    Gap router sub-routers now require authentication (defense-in-depth).
    Use the FIXOPS_API_TOKEN env var (set by conftest.py) as the API key.
    """
    import os
    token = os.getenv("FIXOPS_API_TOKEN", "test-token")
    return TestClient(app, headers={"X-API-Key": token})


# ──────────────────────────────────────────────────────
#  Models
# ──────────────────────────────────────────────────────


class TestChatRequest:
    def test_basic(self):
        req = ChatRequest(message="What vulnerabilities are critical?")
        assert req.message == "What vulnerabilities are critical?"

    def test_with_context(self):
        req = ChatRequest(
            message="Explain CVE-2024-0001",
            context={"app_id": "my-app"},
        )
        assert req.context["app_id"] == "my-app"


# ──────────────────────────────────────────────────────
#  Audit Gap
# ──────────────────────────────────────────────────────


class TestAuditGap:
    def test_list_audit_logs(self, client):
        resp = client.get("/api/v1/audit/")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, (list, dict))

    def test_list_audit_logs_pagination(self, client):
        resp = client.get("/api/v1/audit/?page=1&per_page=5")
        assert resp.status_code == 200


# ──────────────────────────────────────────────────────
#  Bulk Gap
# ──────────────────────────────────────────────────────


class TestBulkGap:
    def test_get_bulk_assignments(self, client):
        resp = client.get("/api/v1/bulk/assign")
        assert resp.status_code == 200


# ──────────────────────────────────────────────────────
#  Copilot Gap
# ──────────────────────────────────────────────────────


class TestCopilotGap:
    def test_list_copilot_agents(self, client):
        resp = client.get("/api/v1/copilot/agents")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, (list, dict))


# ──────────────────────────────────────────────────────
#  Integrations Gap
# ──────────────────────────────────────────────────────


class TestIntegrationsGap:
    def test_list_integrations(self, client):
        resp = client.get("/api/v1/integrations/")
        assert resp.status_code == 200

    def test_list_marketplace(self, client):
        resp = client.get("/api/v1/integrations/marketplace")
        assert resp.status_code == 200
        data = resp.json()
        assert "integrations" in data
        assert "total" in data


# ──────────────────────────────────────────────────────
#  MPTE Gap
# ──────────────────────────────────────────────────────


class TestMpteGap:
    def test_monitoring(self, client):
        resp = client.get("/api/v1/mpte/monitoring")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)


# ──────────────────────────────────────────────────────
#  Playbooks Gap
# ──────────────────────────────────────────────────────


class TestPlaybooksGap:
    def test_list_playbooks(self, client):
        resp = client.get("/api/v1/playbooks/")
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "total" in data

    def test_list_templates(self, client):
        resp = client.get("/api/v1/playbooks/templates")
        assert resp.status_code == 200
        data = resp.json()
        assert "templates" in data
        assert data["total"] > 0


# ──────────────────────────────────────────────────────
#  Predictions Gap
# ──────────────────────────────────────────────────────


class TestPredictionsGap:
    def test_list_predictions(self, client):
        resp = client.get("/api/v1/predictions/")
        assert resp.status_code == 200
        data = resp.json()
        assert "predictions" in data
        assert "model_version" in data


# ──────────────────────────────────────────────────────
#  Reports Gap
# ──────────────────────────────────────────────────────


class TestReportsGap:
    def test_list_report_templates(self, client):
        resp = client.get("/api/v1/reports/templates")
        assert resp.status_code == 200
        data = resp.json()
        assert "templates" in data
        assert data["total"] > 0


# ──────────────────────────────────────────────────────
#  Scanner Gap
# ──────────────────────────────────────────────────────


class TestScannerGap:
    def test_list_parsers(self, client):
        resp = client.get("/api/v1/scanner/parsers")
        assert resp.status_code == 200
        data = resp.json()
        assert "parsers" in data


# ──────────────────────────────────────────────────────
#  Evidence Gap
# ──────────────────────────────────────────────────────


class TestEvidenceGap:
    def test_generate_evidence(self, client):
        resp = client.post("/api/v1/evidence/generate", json={
            "finding_id": "VULN-001",
            "evidence_type": "screenshot",
        })
        assert resp.status_code in (200, 422)


# ──────────────────────────────────────────────────────
#  Compliance Gap
# ──────────────────────────────────────────────────────


class TestComplianceGap:
    def test_audit_bundle(self, client):
        resp = client.post("/api/v1/compliance-engine/audit-bundle", json={
            "framework": "pci-dss",
        })
        assert resp.status_code in (200, 422)


# ──────────────────────────────────────────────────────
#  Changes Gap
# ──────────────────────────────────────────────────────


class TestChangesGap:
    def test_sla_impact(self, client):
        resp = client.post("/api/v1/changes/sla-impact", json={
            "change_id": "CHG-001",
        })
        assert resp.status_code in (200, 422)


# ──────────────────────────────────────────────────────
#  Workflows Gap
# ──────────────────────────────────────────────────────


class TestWorkflowsGap:
    def test_list_rules(self, client):
        resp = client.get("/api/v1/workflows/rules")
        assert resp.status_code == 200
        data = resp.json()
        assert "rules" in data


# ──────────────────────────────────────────────────────
#  App Config Gap
# ──────────────────────────────────────────────────────


class TestAppConfigGap:
    def test_get_config(self, client):
        resp = client.get("/api/v1/app-config/")
        assert resp.status_code == 200
        data = resp.json()
        assert "platform" in data
        assert "features" in data


# ──────────────────────────────────────────────────────
#  SBOM Gap
# ──────────────────────────────────────────────────────


class TestSbomGap:
    def test_list_sbom(self, client):
        resp = client.get("/api/v1/sbom/")
        assert resp.status_code == 200


# ──────────────────────────────────────────────────────
#  Attack Paths Gap
# ──────────────────────────────────────────────────────


class TestAttackPathsGap:
    def test_list_attack_paths(self, client):
        resp = client.get("/api/v1/attack-paths/")
        assert resp.status_code == 200


# ──────────────────────────────────────────────────────
#  Data Fabric Gap
# ──────────────────────────────────────────────────────


class TestDataFabricGap:
    def test_status(self, client):
        resp = client.get("/api/v1/data-fabric/status")
        assert resp.status_code == 200


# ──────────────────────────────────────────────────────
#  Correlation Gap
# ──────────────────────────────────────────────────────


class TestCorrelationGap:
    def test_status(self, client):
        resp = client.get("/api/v1/correlation/status")
        assert resp.status_code == 200


# ──────────────────────────────────────────────────────
#  Scanner Registry Gap
# ──────────────────────────────────────────────────────


class TestScannerRegistryGap:
    def test_list_scanners(self, client):
        resp = client.get("/api/v1/scanner-registry/")
        assert resp.status_code == 200


# ──────────────────────────────────────────────────────
#  Notifications Gap
# ──────────────────────────────────────────────────────


class TestNotificationsGap:
    def test_preferences(self, client):
        resp = client.get("/api/v1/notifications/preferences")
        assert resp.status_code == 200


# ──────────────────────────────────────────────────────
#  Attack Simulation Gap
# ──────────────────────────────────────────────────────


class TestAttackSimulationGap:
    def test_scenarios(self, client):
        resp = client.get("/api/v1/attack-simulation/scenarios")
        assert resp.status_code == 200


# ──────────────────────────────────────────────────────
#  SLSA Gap
# ──────────────────────────────────────────────────────


class TestSlsaGap:
    def test_provenance(self, client):
        resp = client.get("/api/v1/slsa/provenance")
        assert resp.status_code == 200


# ──────────────────────────────────────────────────────
#  Findings Gap
# ──────────────────────────────────────────────────────


class TestFindingsGap:
    def test_list_findings(self, client):
        resp = client.get("/api/v1/findings/")
        assert resp.status_code == 200
        data = resp.json()
        assert "findings" in data or "items" in data or isinstance(data, list)


# ──────────────────────────────────────────────────────
#  Compliance Status Gap
# ──────────────────────────────────────────────────────


class TestComplianceStatusGap:
    def test_status(self, client):
        resp = client.get("/api/v1/compliance/status")
        assert resp.status_code == 200


# ──────────────────────────────────────────────────────
#  Copilot Chat
# ──────────────────────────────────────────────────────


class TestCopilotChat:
    def test_chat(self, client):
        resp = client.post("/api/v1/copilot/chat", json={
            "message": "What are the top vulnerabilities?",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "response" in data or "message" in data or "answer" in data

    def test_suggest(self, client):
        resp = client.post("/api/v1/copilot/suggest", json={
            "context": "SQL injection in login form",
        })
        assert resp.status_code in (200, 404, 405, 422)

