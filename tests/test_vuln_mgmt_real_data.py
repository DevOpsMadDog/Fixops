"""
Tests for vuln-mgmt domain GET / root endpoints (empty-endpoint batch, vuln-mgmt).

Covers 4 endpoints wired to real engines:
  GET /api/v1/vuln-risk        — vuln_risk_router   -> core.vuln_risk_scoring
  GET /api/v1/vuln-lifecycle   — vuln_lifecycle_router -> core.vuln_lifecycle
  GET /api/v1/patch-priority   — patch_prioritizer_router -> core.patch_prioritizer
  GET /api/v1/vuln-exceptions  — vuln_exception_router -> core.vuln_exception_engine
"""
from __future__ import annotations

import os
import pytest
from fastapi.testclient import TestClient

API_TOKEN = os.getenv(
    "FIXOPS_API_TOKEN",
    "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh",
)
HEADERS = {"X-API-Key": API_TOKEN}


@pytest.fixture(scope="module")
def client():
    os.environ.setdefault("FIXOPS_API_TOKEN", API_TOKEN)
    from apps.api.app import create_app
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


# ===========================================================================
# 1. vuln-risk GET /
# ===========================================================================

class TestVulnRiskRoot:
    def test_get_root_returns_200(self, client):
        r = client.get("/api/v1/vuln-risk", headers=HEADERS)
        assert r.status_code == 200

    def test_get_root_has_service_field(self, client):
        body = client.get("/api/v1/vuln-risk", headers=HEADERS).json()
        assert body.get("service") == "vuln-risk-scoring"

    def test_get_root_has_status_ok(self, client):
        body = client.get("/api/v1/vuln-risk", headers=HEADERS).json()
        assert body.get("status") == "ok"

    def test_get_root_has_stats_key(self, client):
        body = client.get("/api/v1/vuln-risk", headers=HEADERS).json()
        assert "stats" in body

    def test_get_root_has_endpoints_list(self, client):
        body = client.get("/api/v1/vuln-risk", headers=HEADERS).json()
        assert isinstance(body.get("endpoints"), list)
        assert len(body["endpoints"]) > 0

    def test_get_root_with_org_id(self, client):
        r = client.get("/api/v1/vuln-risk?org_id=test-org", headers=HEADERS)
        assert r.status_code == 200
        assert r.json().get("org_id") == "test-org"

    def test_get_root_not_501(self, client):
        r = client.get("/api/v1/vuln-risk", headers=HEADERS)
        assert r.status_code != 501


# ===========================================================================
# 2. vuln-lifecycle GET /
# ===========================================================================

class TestVulnLifecycleRoot:
    def test_get_root_returns_200(self, client):
        r = client.get("/api/v1/vuln-lifecycle", headers=HEADERS)
        assert r.status_code == 200

    def test_get_root_has_service_field(self, client):
        body = client.get("/api/v1/vuln-lifecycle", headers=HEADERS).json()
        assert body.get("service") == "vuln-lifecycle"

    def test_get_root_has_status_ok(self, client):
        body = client.get("/api/v1/vuln-lifecycle", headers=HEADERS).json()
        assert body.get("status") == "ok"

    def test_get_root_has_stage_distribution(self, client):
        body = client.get("/api/v1/vuln-lifecycle", headers=HEADERS).json()
        assert "stage_distribution" in body

    def test_get_root_has_flow_key(self, client):
        body = client.get("/api/v1/vuln-lifecycle", headers=HEADERS).json()
        assert "flow" in body

    def test_get_root_has_endpoints_list(self, client):
        body = client.get("/api/v1/vuln-lifecycle", headers=HEADERS).json()
        assert isinstance(body.get("endpoints"), list)
        assert len(body["endpoints"]) > 0

    def test_get_root_not_404(self, client):
        r = client.get("/api/v1/vuln-lifecycle", headers=HEADERS)
        assert r.status_code != 404


# ===========================================================================
# 3. patch-priority GET /
# ===========================================================================

class TestPatchPriorityRoot:
    def test_get_root_returns_200(self, client):
        r = client.get("/api/v1/patch-priority", headers=HEADERS)
        assert r.status_code == 200

    def test_get_root_has_service_field(self, client):
        body = client.get("/api/v1/patch-priority", headers=HEADERS).json()
        assert body.get("service") == "patch-prioritization"

    def test_get_root_has_status_ok(self, client):
        body = client.get("/api/v1/patch-priority", headers=HEADERS).json()
        assert body.get("status") == "ok"

    def test_get_root_has_plan_count(self, client):
        body = client.get("/api/v1/patch-priority", headers=HEADERS).json()
        assert "plan_count" in body
        assert isinstance(body["plan_count"], int)

    def test_get_root_has_stats(self, client):
        body = client.get("/api/v1/patch-priority", headers=HEADERS).json()
        assert "stats" in body

    def test_get_root_has_endpoints_list(self, client):
        body = client.get("/api/v1/patch-priority", headers=HEADERS).json()
        assert isinstance(body.get("endpoints"), list)

    def test_get_root_with_org_id(self, client):
        r = client.get("/api/v1/patch-priority?org_id=acme", headers=HEADERS)
        assert r.status_code == 200
        assert r.json().get("org_id") == "acme"

    def test_get_root_not_501(self, client):
        r = client.get("/api/v1/patch-priority", headers=HEADERS)
        assert r.status_code != 501


# ===========================================================================
# 4. vuln-exceptions GET /
# ===========================================================================

class TestVulnExceptionsRoot:
    def test_get_root_returns_200(self, client):
        r = client.get("/api/v1/vuln-exceptions", headers=HEADERS)
        assert r.status_code == 200

    def test_get_root_has_service_field(self, client):
        body = client.get("/api/v1/vuln-exceptions", headers=HEADERS).json()
        assert body.get("service") == "vuln-exceptions"

    def test_get_root_has_status_ok(self, client):
        body = client.get("/api/v1/vuln-exceptions", headers=HEADERS).json()
        assert body.get("status") == "ok"

    def test_get_root_has_stats(self, client):
        body = client.get("/api/v1/vuln-exceptions", headers=HEADERS).json()
        assert "stats" in body

    def test_get_root_has_endpoints_list(self, client):
        body = client.get("/api/v1/vuln-exceptions", headers=HEADERS).json()
        assert isinstance(body.get("endpoints"), list)
        assert len(body["endpoints"]) > 0

    def test_get_root_with_org_id(self, client):
        r = client.get("/api/v1/vuln-exceptions?org_id=org-xyz", headers=HEADERS)
        assert r.status_code == 200
        assert r.json().get("org_id") == "org-xyz"

    def test_get_root_not_404(self, client):
        r = client.get("/api/v1/vuln-exceptions", headers=HEADERS)
        assert r.status_code != 404
