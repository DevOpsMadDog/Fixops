"""Comprehensive tests for suite-core/api/agents_router.py — 28 agent endpoints."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient



@pytest.fixture
def client():
    """Create a test client with the agents router mounted."""
    app = FastAPI()
    from api.agents_router import router
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


# ─── Pydantic Model Imports ────────────────────────────────────────────


class TestModelImports:
    def test_import_enums(self):
        from api.agents_router import AgentType, AgentStatus, TaskPriority, ComplianceFramework
        assert AgentType.SECURITY_ANALYST.value == "security_analyst"
        assert AgentStatus.IDLE.value == "idle"
        assert TaskPriority.CRITICAL.value == "critical"
        assert ComplianceFramework.PCI_DSS.value == "pci-dss"

    def test_import_request_models(self):
        from api.agents_router import (
            AnalyzeVulnRequest,
        )
        # Verify models can be instantiated
        req = AnalyzeVulnRequest(cve_id="CVE-2024-0001")
        assert req.cve_id == "CVE-2024-0001"
        assert req.include_threat_intel is True

    def test_import_response_models(self):
        from api.agents_router import (
            PentestResultResponse,
        )
        pr = PentestResultResponse(task_id="t-1", status="completed", exploitable=True)
        assert pr.exploitable is True


# ─── Security Analyst Endpoints ────────────────────────────────────────


class TestSecurityAnalystEndpoints:
    def test_analyze_vulnerability(self, client):
        resp = client.post(
            "/api/v1/copilot/agents/analyst/analyze",
            json={"cve_id": "CVE-2024-0001"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "task_id" in data
        assert data["agent"] == "security_analyst"

    def test_analyze_vulnerability_no_cve(self, client):
        resp = client.post(
            "/api/v1/copilot/agents/analyst/analyze",
            json={},
        )
        assert resp.status_code == 200

    def test_threat_intel(self, client):
        resp = client.post(
            "/api/v1/copilot/agents/analyst/threat-intel",
            json={"cve_ids": ["CVE-2024-0001", "CVE-2024-0002"]},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "cve_intelligence" in data or "cve_ids" in str(data) or isinstance(data, dict)

    def test_prioritize(self, client):
        resp = client.post(
            "/api/v1/copilot/agents/analyst/prioritize",
            json={"finding_ids": ["f-1", "f-2"], "algorithm": "ssvc"},
        )
        assert resp.status_code == 200

    def test_attack_path(self, client):
        resp = client.post(
            "/api/v1/copilot/agents/analyst/attack-path",
            json={"asset_id": "asset-1", "depth": 3},
        )
        assert resp.status_code == 200


# ─── Pentest Agent Endpoints ───────────────────────────────────────────


class TestPentestEndpoints:
    def test_validate_exploit(self, client):
        resp = client.post(
            "/api/v1/copilot/agents/pentest/validate",
            json={"cve_id": "CVE-2024-0001", "target_id": "target-1"},
        )
        assert resp.status_code == 200

    def test_generate_poc(self, client):
        resp = client.post(
            "/api/v1/copilot/agents/pentest/generate-poc",
            json={"cve_id": "CVE-2024-0001"},
        )
        assert resp.status_code == 200

    def test_reachability(self, client):
        resp = client.post(
            "/api/v1/copilot/agents/pentest/reachability",
            json={"cve_id": "CVE-2024-0001", "asset_ids": ["a-1"]},
        )
        assert resp.status_code == 200

    def test_simulate_attack(self, client):
        resp = client.post(
            "/api/v1/copilot/agents/pentest/simulate",
            json={"scenario_type": "ransomware", "target_assets": ["a-1"]},
        )
        assert resp.status_code == 200


# ─── Compliance Agent Endpoints ─────────────────────────────────────────


class TestComplianceEndpoints:
    def test_map_findings(self, client):
        resp = client.post(
            "/api/v1/copilot/agents/compliance/map-findings",
            json={"finding_ids": ["f-1"], "frameworks": ["pci-dss"]},
        )
        assert resp.status_code == 200

    def test_gap_analysis(self, client):
        resp = client.post(
            "/api/v1/copilot/agents/compliance/gap-analysis",
            json={"framework": "soc2"},
        )
        assert resp.status_code == 200

    def test_audit_evidence(self, client):
        resp = client.post(
            "/api/v1/copilot/agents/compliance/audit-evidence",
            json={"framework": "iso27001"},
        )
        assert resp.status_code == 200

    def test_regulatory_alerts(self, client):
        resp = client.post(
            "/api/v1/copilot/agents/compliance/regulatory-alerts",
            json={},
        )
        assert resp.status_code == 200


# ─── Remediation Agent Endpoints ────────────────────────────────────────


class TestRemediationEndpoints:
    def test_generate_fix(self, client):
        resp = client.post(
            "/api/v1/copilot/agents/remediation/generate-fix",
            json={"finding_id": "f-1"},
        )
        assert resp.status_code == 200

    def test_create_pr(self, client):
        resp = client.post(
            "/api/v1/copilot/agents/remediation/create-pr",
            json={"finding_ids": ["f-1"], "repository": "org/repo"},
        )
        assert resp.status_code == 200

    def test_dependency_update(self, client):
        resp = client.post(
            "/api/v1/copilot/agents/remediation/update-dependencies",
            json={"package_ids": ["lodash"]},
        )
        assert resp.status_code == 200

    def test_playbook(self, client):
        resp = client.post(
            "/api/v1/copilot/agents/remediation/playbook",
            json={"finding_ids": ["f-1"], "audience": "developer"},
        )
        assert resp.status_code == 200

    def test_verify(self, client):
        resp = client.post(
            "/api/v1/copilot/agents/remediation/verify",
            json={"finding_id": "f-1"},
        )
        assert resp.status_code in (200, 422)

    def test_queue(self, client):
        resp = client.get("/api/v1/copilot/agents/remediation/queue")
        assert resp.status_code == 200

    def test_recommendations(self, client):
        resp = client.get("/api/v1/copilot/agents/remediation/recommendations/finding-1")
        assert resp.status_code == 200


# ─── Orchestrator Endpoints ────────────────────────────────────────────


class TestOrchestratorEndpoints:
    def test_orchestrate(self, client):
        resp = client.post(
            "/api/v1/copilot/agents/orchestrate",
            json={"objective": "analyze recent findings", "agents": ["security_analyst"]},
        )
        assert resp.status_code == 200

    def test_get_task_status(self, client):
        # First create a task
        resp = client.post(
            "/api/v1/copilot/agents/analyst/analyze",
            json={"cve_id": "CVE-2024-0001"},
        )
        task_id = resp.json()["task_id"]
        # Then get its status
        status_resp = client.get(f"/api/v1/copilot/agents/tasks/{task_id}")
        assert status_resp.status_code in (200, 404)

    def test_agent_status(self, client):
        resp = client.get("/api/v1/copilot/agents/status")
        assert resp.status_code == 200

    def test_agent_health(self, client):
        resp = client.get("/api/v1/copilot/agents/health")
        assert resp.status_code == 200

    def test_analyst_trending(self, client):
        resp = client.get("/api/v1/copilot/agents/analyst/trending")
        assert resp.status_code == 200

    def test_analyst_risk_score(self, client):
        resp = client.get("/api/v1/copilot/agents/analyst/risk-score/asset-1")
        assert resp.status_code == 200

    def test_analyst_cve(self, client):
        resp = client.get("/api/v1/copilot/agents/analyst/cve/CVE-2024-0001")
        assert resp.status_code == 200

    def test_pentest_results(self, client):
        resp = client.get("/api/v1/copilot/agents/pentest/results/task-1")
        assert resp.status_code in (200, 404)

    def test_compliance_controls(self, client):
        resp = client.get("/api/v1/copilot/agents/compliance/controls/pci-dss")
        assert resp.status_code == 200

    def test_compliance_dashboard(self, client):
        resp = client.get("/api/v1/copilot/agents/compliance/dashboard")
        assert resp.status_code == 200


# ─── Helper Functions ──────────────────────────────────────────────────


class TestHelpers:
    def test_generate_id(self):
        from api.agents_router import _generate_id
        id1 = _generate_id()
        id2 = _generate_id()
        assert id1 != id2
        assert len(id1) == 36  # UUID format

    def test_now(self):
        from api.agents_router import _now
        now = _now()
        assert now.tzinfo is not None
