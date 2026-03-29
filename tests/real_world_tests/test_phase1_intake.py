"""
Phase 1 — Intake & Scope Lock
Owner: Security Architect + GRC

Validates:
- System is healthy and reachable
- Asset inventory is accessible
- Scope registration endpoints work
- Owner mapping is functional
"""
import pytest
from .conftest import PERSONAS


class TestDeploymentHealth:
    """Verify the deployment is live and all subsystems respond."""

    def test_health_endpoint(self, api):
        r = api.get("/health")
        assert r.status_code == 200

    def test_api_v1_health(self, api):
        r = api.get("/api/v1/health")
        assert r.status_code in (200, 404)  # Some deployments mount at /health only

    def test_ready_probe(self, api):
        r = api.get("/api/v1/ready")
        assert r.status_code in (200, 404)

    def test_system_info(self, api):
        r = api.get("/api/v1/system/info")
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, dict)

    def test_system_health(self, api):
        r = api.get("/api/v1/system/health")
        assert r.status_code == 200

    def test_version_endpoint(self, api):
        r = api.get("/api/v1/version")
        assert r.status_code == 200

    def test_metrics_endpoint(self, api):
        r = api.get("/api/v1/metrics")
        assert r.status_code == 200


class TestAssetInventory:
    """Verify asset inventory is accessible for scope registration."""

    def test_list_applications(self, api):
        r = api.get("/api/v1/inventory/applications")
        assert r.status_code == 200

    def test_list_assets(self, api):
        r = api.get("/api/v1/inventory/assets")
        assert r.status_code == 200

    def test_list_services(self, api):
        r = api.get("/api/v1/inventory/services")
        assert r.status_code == 200


class TestScopeRegistration:
    """Validate scope policy and guardrail endpoints."""

    def test_policies_accessible(self, api):
        r = api.get("/api/v1/policies")
        assert r.status_code == 200

    def test_teams_accessible(self, api):
        r = api.get("/api/v1/teams")
        assert r.status_code == 200

    def test_users_accessible(self, api):
        r = api.get("/api/v1/users")
        assert r.status_code == 200

    def test_connectors_types(self, api):
        r = api.get("/api/v1/connectors/types")
        assert r.status_code == 200


class TestKnowledgeGraphReady:
    """Security Architect verifies knowledge graph is online."""

    def test_kg_status(self, api):
        r = api.get("/api/v1/knowledge-graph/status")
        assert r.status_code == 200

    def test_kg_analytics(self, api):
        r = api.get("/api/v1/knowledge-graph/analytics")
        assert r.status_code == 200

    def test_brain_stats(self, api):
        r = api.get("/api/v1/brain/stats")
        assert r.status_code == 200

    def test_code_to_cloud_status(self, api):
        r = api.get("/api/v1/code-to-cloud/status")
        assert r.status_code == 200

