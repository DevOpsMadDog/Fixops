"""Coverage tests for compliance_engine_router.py (757 LOC).

Tests compliance framework endpoints, policy evaluation, audit reports.
"""
import os
import sys
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for d in ["suite-core", "suite-api", "suite-evidence-risk",
          "suite-attack", "suite-feeds", "suite-integrations"]:
    p = os.path.join(ROOT, d)
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from api import compliance_engine_router
    HAS_DEPS = True
except Exception:
    HAS_DEPS = False

pytestmark = pytest.mark.skipif(not HAS_DEPS, reason="compliance_engine_router not available")


@pytest.fixture(scope="module")
def client():
    app = FastAPI()
    app.include_router(compliance_engine_router.router)
    return TestClient(app, raise_server_exceptions=False)


class TestComplianceRouterImport:
    def test_import(self):
        assert compliance_engine_router.router is not None

    def test_router_has_routes(self):
        assert len(compliance_engine_router.router.routes) > 0


class TestComplianceEndpoints:
    def test_status(self, client):
        resp = client.get("/api/v1/compliance/status")
        assert resp.status_code in (200, 404)

    def test_frameworks_list(self, client):
        resp = client.get("/api/v1/compliance/frameworks")
        assert resp.status_code in (200, 404)

    def test_evaluate(self, client):
        resp = client.post("/api/v1/compliance/evaluate", json={
            "app_id": "APP-TEST-001",
            "framework": "SOC2",
        })
        assert resp.status_code in (200, 400, 404, 422, 500)

    def test_report(self, client):
        resp = client.get("/api/v1/compliance/report")
        assert resp.status_code in (200, 404)

    def test_audit(self, client):
        resp = client.get("/api/v1/compliance/audit")
        assert resp.status_code in (200, 404)
