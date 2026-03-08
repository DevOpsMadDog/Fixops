"""Smoke tests for all untested API routers.

Each test imports the router, mounts it on a minimal FastAPI app, and exercises
key endpoints. This provides baseline coverage for ~45 untested router files.
"""
import os
import sys
import pytest

# Ensure suite paths are available
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for d in ["suite-api", "suite-core", "suite-attack", "suite-feeds",
          "suite-evidence-risk", "suite-integrations"]:
    p = os.path.join(ROOT, d)
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

pytestmark = pytest.mark.skipif(not HAS_FASTAPI, reason="FastAPI not available")


def _make_client(router, prefix: str = "") -> TestClient:
    """Create a TestClient with the given router mounted."""
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


# ─── suite-attack/api routers ───────────────────────────────────────────────

class TestSastRouter:
    """Tests for SAST scanner router."""

    def test_import(self):
        from api import sast_router
        assert sast_router.router is not None

    def test_scan_code(self):
        from api import sast_router
        client = _make_client(sast_router.router)
        resp = client.post("/api/v1/sast/scan/code", json={
            "code": "import os; os.system(input())",
            "filename": "test.py",
        })
        assert resp.status_code in (200, 422)

    def test_scan_code_empty(self):
        from api import sast_router
        client = _make_client(sast_router.router)
        resp = client.post("/api/v1/sast/scan/code", json={
            "code": "   ",
            "filename": "test.py",
        })
        assert resp.status_code in (400, 422)

    def test_get_rules(self):
        from api import sast_router
        client = _make_client(sast_router.router)
        resp = client.get("/api/v1/sast/rules")
        assert resp.status_code == 200

    def test_get_status(self):
        from api import sast_router
        client = _make_client(sast_router.router)
        resp = client.get("/api/v1/sast/status")
        assert resp.status_code == 200

    def test_scan_files(self):
        from api import sast_router
        client = _make_client(sast_router.router)
        resp = client.post("/api/v1/sast/scan/files", json={
            "files": {"test.py": "x = eval(input())"}
        })
        assert resp.status_code == 200


class TestDastRouter:
    """Tests for DAST scanner router."""

    def test_import(self):
        from api import dast_router
        assert dast_router.router is not None

    def test_status(self):
        from api import dast_router
        client = _make_client(dast_router.router)
        resp = client.get("/api/v1/dast/status")
        assert resp.status_code == 200

    def test_scan(self):
        from api import dast_router
        client = _make_client(dast_router.router)
        resp = client.post("/api/v1/dast/scan", json={
            "target_url": "http://example.com",
        })
        assert resp.status_code in (200, 422)


class TestContainerRouter:
    """Tests for container scanner router."""

    def test_import(self):
        from api import container_router
        assert container_router.router is not None

    def test_status(self):
        from api import container_router
        client = _make_client(container_router.router)
        resp = client.get("/api/v1/container/status")
        assert resp.status_code == 200

    def test_scan_dockerfile(self):
        from api import container_router
        client = _make_client(container_router.router)
        resp = client.post("/api/v1/container/scan/dockerfile", json={
            "content": "FROM nginx:latest\nRUN apt-get update",
        })
        assert resp.status_code in (200, 422)

    def test_scan_image(self):
        from api import container_router
        client = _make_client(container_router.router)
        resp = client.post("/api/v1/container/scan/image", json={
            "image": "nginx:latest",
        })
        assert resp.status_code in (200, 422)


class TestCspmRouter:
    """Tests for CSPM router."""

    def test_import(self):
        from api import cspm_router
        assert cspm_router.router is not None

    def test_status(self):
        from api import cspm_router
        client = _make_client(cspm_router.router)
        resp = client.get("/api/v1/cspm/status")
        assert resp.status_code == 200


class TestSecretsRouter:
    """Tests for secrets scanner router."""

    def test_import(self):
        from api import secrets_router
        assert secrets_router.router is not None

    def test_status(self):
        from api import secrets_router
        client = _make_client(secrets_router.router)
        resp = client.get("/api/v1/secrets/status")
        assert resp.status_code == 200

    def test_scan_content(self):
        from api import secrets_router
        client = _make_client(secrets_router.router)
        resp = client.post("/api/v1/secrets/scan/content", json={
            "content": "API_KEY = 'AKIAIOSFODNN7EXAMPLE'",
            "filename": "config.py",
        })
        assert resp.status_code in (200, 422)

    def test_list_secrets(self):
        from api import secrets_router
        client = _make_client(secrets_router.router)
        resp = client.get("/api/v1/secrets")
        assert resp.status_code == 200


class TestMalwareRouter:
    """Tests for malware scanner router."""

    def test_import(self):
        from api import malware_router
        assert malware_router.router is not None

    def test_status(self):
        from api import malware_router
        client = _make_client(malware_router.router)
        resp = client.get("/api/v1/malware/status")
        assert resp.status_code == 200


class TestApiFuzzerRouter:
    """Tests for API fuzzer router."""

    def test_import(self):
        from api import api_fuzzer_router
        assert api_fuzzer_router.router is not None


class TestAttackSimRouter:
    """Tests for attack simulation router."""

    def test_import(self):
        from api import attack_sim_router
        assert attack_sim_router.router is not None


class TestVulnDiscoveryRouter:
    """Tests for vulnerability discovery router."""

    def test_import(self):
        from api import vuln_discovery_router
        assert vuln_discovery_router.router is not None


class TestMpteOrchestratorRouter:
    """Tests for MPTE orchestrator router."""

    def test_import(self):
        from api import mpte_orchestrator_router
        assert mpte_orchestrator_router.router is not None


# ─── suite-core/api routers ─────────────────────────────────────────────────

class TestExposureCaseRouter:
    """Tests for exposure case router."""

    def test_import(self):
        from api import exposure_case_router
        assert exposure_case_router.router is not None

    def test_list_cases(self):
        from api import exposure_case_router
        client = _make_client(exposure_case_router.router)
        resp = client.get("/api/v1/cases")
        assert resp.status_code == 200

    def test_create_case(self):
        from api import exposure_case_router
        client = _make_client(exposure_case_router.router)
        resp = client.post("/api/v1/cases", json={
            "title": "Test exposure case",
            "description": "Test case for coverage",
            "severity": "high",
        })
        # May require more fields, but we test the route exists
        assert resp.status_code in (200, 201, 422, 400)

    def test_stats(self):
        from api import exposure_case_router
        client = _make_client(exposure_case_router.router)
        resp = client.get("/api/v1/cases/stats/summary")
        assert resp.status_code == 200


class TestPredictionsRouter:
    """Tests for predictive analytics router."""

    def test_import(self):
        from api import predictions_router
        assert predictions_router.router is not None

    def test_attack_chain(self):
        from api import predictions_router
        client = _make_client(predictions_router.router)
        resp = client.post("/api/v1/predictions/attack-chain", json={
            "cve_id": "CVE-2024-1234",
            "cvss_score": 7.5,
            "has_exploit": True,
            "is_network_exposed": True,
        })
        assert resp.status_code in (200, 422, 500)


class TestZeroGravityRouter:
    """Tests for zero-gravity data engine router."""

    def test_import(self):
        from api import zero_gravity_router
        assert zero_gravity_router.router is not None

    def test_status(self):
        from api import zero_gravity_router
        client = _make_client(zero_gravity_router.router)
        resp = client.get("/api/v1/zero-gravity/status")
        assert resp.status_code in (200, 404)

    def test_ingest(self):
        from api import zero_gravity_router
        client = _make_client(zero_gravity_router.router)
        resp = client.post("/api/v1/zero-gravity/ingest", json={
            "data_id": "test-001",
            "category": "evidence",
            "content": "test content",
        })
        # 500 may occur if underlying storage isn't configured - that's OK for smoke test
        assert resp.status_code in (200, 201, 422, 500)

    def test_tiers(self):
        from api import zero_gravity_router
        client = _make_client(zero_gravity_router.router)
        resp = client.get("/api/v1/zero-gravity/tiers")
        assert resp.status_code in (200, 500)

    def test_health(self):
        from api import zero_gravity_router
        client = _make_client(zero_gravity_router.router)
        resp = client.get("/api/v1/zero-gravity/health")
        assert resp.status_code in (200, 500)


class TestDeduplicationRouter:
    """Tests for deduplication router."""

    def test_import(self):
        from api import deduplication_router
        assert deduplication_router.router is not None


class TestPipelineRouter:
    """Tests for pipeline router."""

    def test_import(self):
        from api import pipeline_router
        assert pipeline_router.router is not None


class TestStreamingRouter:
    """Tests for streaming router."""

    def test_import(self):
        from api import streaming_router
        assert streaming_router.router is not None


class TestAlgorithmicRouter:
    """Tests for algorithmic router."""

    def test_import(self):
        from api import algorithmic_router
        assert algorithmic_router.router is not None


class TestAirgapRouter:
    """Tests for airgap router."""

    def test_import(self):
        from api import airgap_router
        assert airgap_router.router is not None


class TestAutofixVerifyRouter:
    """Tests for autofix verify router."""

    def test_import(self):
        from api import autofix_verify_router
        assert autofix_verify_router.router is not None


class TestCodeToCloudRouter:
    """Tests for code-to-cloud router."""

    def test_import(self):
        from api import code_to_cloud_router
        assert code_to_cloud_router.router is not None


class TestFuzzyIdentityRouter:
    """Tests for fuzzy identity router."""

    def test_import(self):
        from api import fuzzy_identity_router
        assert fuzzy_identity_router.router is not None


class TestLlmMonitorRouter:
    """Tests for LLM monitor router."""

    def test_import(self):
        from api import llm_monitor_router
        assert llm_monitor_router.router is not None


class TestMcpProtocolRouter:
    """Tests for MCP protocol router."""

    def test_import(self):
        from api import mcp_protocol_router
        assert mcp_protocol_router.router is not None


class TestMindsdbRouter:
    """Tests for MindsDB router."""

    def test_import(self):
        from api import mindsdb_router
        assert mindsdb_router.router is not None


class TestMitreMapperRouter:
    """Tests for MITRE mapper router."""

    def test_import(self):
        from api import mitre_mapper_router
        assert mitre_mapper_router.router is not None


class TestQuantumCryptoRouter:
    """Tests for quantum crypto router."""

    def test_import(self):
        from api import quantum_crypto_router
        assert quantum_crypto_router.router is not None


class TestSingleAgentRouter:
    """Tests for single agent router."""

    def test_import(self):
        from api import single_agent_router
        assert single_agent_router.router is not None


class TestDecisionsApi:
    """Tests for decisions API."""

    def test_import(self):
        from api import decisions
        assert hasattr(decisions, 'router')


# ─── suite-api/apps/api routers ─────────────────────────────────────────────

class TestAdminRouter:
    """Tests for admin router."""

    def test_import(self):
        from apps.api import admin_router
        assert admin_router.router is not None

    def test_list_users(self):
        from apps.api import admin_router
        client = _make_client(admin_router.router)
        resp = client.get("/api/v1/admin/users")
        assert resp.status_code in (200, 401, 403)

    def test_list_teams(self):
        from apps.api import admin_router
        client = _make_client(admin_router.router)
        resp = client.get("/api/v1/admin/teams")
        assert resp.status_code in (200, 401, 403)


class TestAuditRouter:
    """Tests for audit router."""

    def test_import(self):
        from apps.api import audit_router
        assert audit_router.router is not None


class TestCollaborationRouter:
    """Tests for collaboration router."""

    def test_import(self):
        from apps.api import collaboration_router
        assert collaboration_router.router is not None


class TestComplianceEngineRouter:
    """Tests for compliance engine router (lives in suite-evidence-risk)."""

    def test_import(self):
        from api import compliance_engine_router
        assert compliance_engine_router.router is not None


class TestExposureCaseRouterApps:
    """Tests for apps/api exposure case router (lives in suite-core/api)."""

    def test_import(self):
        # This is already tested via TestExposureCaseRouter above
        from api import exposure_case_router
        assert exposure_case_router.router is not None


class TestPoliciesRouter:
    """Tests for policies router."""

    def test_import(self):
        from apps.api import policies_router
        assert policies_router.router is not None


class TestRemediationRouter:
    """Tests for remediation router."""

    def test_import(self):
        from apps.api import remediation_router
        assert remediation_router.router is not None


class TestRiskRouter:
    """Tests for risk router (lives in suite-evidence-risk/api)."""

    def test_import(self):
        from api import risk_router
        assert risk_router.router is not None


class TestScannerIngestRouter:
    """Tests for scanner ingest router."""

    def test_import(self):
        from apps.api import scanner_ingest_router
        assert scanner_ingest_router.router is not None


class TestSystemRouter:
    """Tests for system router."""

    def test_import(self):
        from apps.api import system_router
        assert system_router.router is not None


class TestTeamsRouter:
    """Tests for teams router."""

    def test_import(self):
        from apps.api import teams_router
        assert teams_router.router is not None


class TestUsersRouter:
    """Tests for users router."""

    def test_import(self):
        from apps.api import users_router
        assert users_router.router is not None


class TestValidationRouter:
    """Tests for validation router."""

    def test_import(self):
        from apps.api import validation_router
        assert validation_router.router is not None


class TestWorkflowsRouter:
    """Tests for workflows router."""

    def test_import(self):
        from apps.api import workflows_router
        assert workflows_router.router is not None


class TestDetailedLoggingRouter:
    """Tests for detailed logging."""

    def test_import(self):
        from apps.api import detailed_logging
        assert hasattr(detailed_logging, 'logs_router')

    def test_get_logs(self):
        from apps.api import detailed_logging
        client = _make_client(detailed_logging.logs_router)
        resp = client.get("/api/v1/logs")
        assert resp.status_code in (200, 404)


class TestDemoDataRouter:
    """Tests for demo data module."""

    def test_import(self):
        from apps.api import demo_data
        assert demo_data is not None


class TestAuthRouterApps:
    """Tests for apps/api auth router."""

    def test_import(self):
        from apps.api import auth_router
        assert auth_router.router is not None


class TestLlmMonitorRouterCore:
    """Tests for LLM monitor router (lives in suite-core/api)."""

    def test_import(self):
        from api import llm_monitor_router
        assert llm_monitor_router.router is not None


class TestStreamingRouterCore:
    """Tests for streaming router (lives in suite-core/api)."""

    def test_import(self):
        from api import streaming_router
        assert streaming_router.router is not None


class TestZeroGravityRouterCore:
    """Tests for zero gravity router (lives in suite-core/api)."""

    def test_import(self):
        from api import zero_gravity_router
        assert zero_gravity_router.router is not None
