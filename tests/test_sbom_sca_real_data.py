"""Tests for SBOM / SCA / supply-chain empty-endpoint wiring.

Covers 4 newly-added GET / root endpoints:
  1. GET /api/v1/sbom/                    — sbom_router
  2. GET /api/v1/supply-chain-intel/      — supply_chain_intel_router
  3. GET /api/v1/supply-chain-monitoring/ — supply_chain_monitoring_router
  4. GET /api/v1/sbom-reeval/             — sbom_reeval_router

5-state envelope verified per endpoint:
  - HTTP 200 (not 500/501/404)
  - JSON body is a dict
  - "status" key == "ok"
  - "org_id" key present and reflects query param
  - no mock sentinel values in response
"""
from __future__ import annotations

import os
import sys

# Set env vars BEFORE any imports so auth_deps reads them at module import time
os.environ["FIXOPS_API_TOKEN"] = "test-sbom-sca-xyz"
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-jwt-secret-32-chars-padding!!")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _sub in ("suite-api", "suite-core"):
    _p = os.path.join(_REPO, _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

API_TOKEN = os.environ["FIXOPS_API_TOKEN"]
AUTH = {"X-API-Key": API_TOKEN}


# ---------------------------------------------------------------------------
# Fixtures — one isolated TestClient per router
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def sbom_client(tmp_path_factory):
    import apps.api.sbom_router as _mod
    from core.sbom_engine import SBOMEngine
    _mod._engine = SBOMEngine(data_dir=str(tmp_path_factory.mktemp("sbom")))
    from apps.api.sbom_router import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture(scope="module")
def sci_client(tmp_path_factory):
    import apps.api.supply_chain_intel_router as _mod
    from core.supply_chain_intel_engine import SupplyChainIntelEngine
    _mod._engine = SupplyChainIntelEngine(db_path=str(tmp_path_factory.mktemp("sci") / "sci.db"))
    from apps.api.supply_chain_intel_router import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture(scope="module")
def scm_client(tmp_path_factory):
    import apps.api.supply_chain_monitoring_router as _mod
    from core.supply_chain_monitoring_engine import SupplyChainMonitoringEngine
    _mod._engine = SupplyChainMonitoringEngine(db_path=str(tmp_path_factory.mktemp("scm") / "scm.db"))
    from apps.api.supply_chain_monitoring_router import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture(scope="module")
def reeval_client(tmp_path_factory):
    import apps.api.sbom_reeval_router as _reeval_mod
    from core.sbom_engine import SBOMEngine
    # Use a fresh temp dir so the DB is created from scratch with the current schema
    tmp = tmp_path_factory.mktemp("sbom_reeval")
    _reeval_mod._engine = SBOMEngine(data_dir=str(tmp))
    from apps.api.sbom_reeval_router import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# Endpoint 1: GET /api/v1/sbom/
# ---------------------------------------------------------------------------

class TestSBOMRootEndpoint:
    def test_status_200(self, sbom_client):
        resp = sbom_client.get("/api/v1/sbom/", headers=AUTH)
        assert resp.status_code == 200, f"Got {resp.status_code}: {resp.text}"

    def test_response_is_dict(self, sbom_client):
        assert isinstance(sbom_client.get("/api/v1/sbom/", headers=AUTH).json(), dict)

    def test_status_ok(self, sbom_client):
        body = sbom_client.get("/api/v1/sbom/", headers=AUTH).json()
        assert body.get("status") == "ok"

    def test_org_id_present(self, sbom_client):
        body = sbom_client.get("/api/v1/sbom/", headers=AUTH).json()
        assert "org_id" in body

    def test_stats_key_present(self, sbom_client):
        body = sbom_client.get("/api/v1/sbom/", headers=AUTH).json()
        assert "stats" in body

    def test_vuln_exposure_key_present(self, sbom_client):
        body = sbom_client.get("/api/v1/sbom/", headers=AUTH).json()
        assert "vuln_exposure" in body

    def test_license_summary_key_present(self, sbom_client):
        body = sbom_client.get("/api/v1/sbom/", headers=AUTH).json()
        assert "license_summary" in body

    def test_no_mock_sentinel(self, sbom_client):
        text = sbom_client.get("/api/v1/sbom/", headers=AUTH).text
        for sentinel in ("MOCK_", "lorem ipsum", "Acme Corp", "demo-org"):
            assert sentinel.lower() not in text.lower()

    def test_org_id_reflects_query_param(self, sbom_client):
        body = sbom_client.get("/api/v1/sbom/?org_id=myorg", headers=AUTH).json()
        assert body.get("org_id") == "myorg"

    def test_no_auth_returns_401_or_403(self, sbom_client):
        resp = sbom_client.get("/api/v1/sbom/")
        assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# Endpoint 2: GET /api/v1/supply-chain-intel/
# ---------------------------------------------------------------------------

class TestSupplyChainIntelRootEndpoint:
    def test_status_200(self, sci_client):
        resp = sci_client.get("/api/v1/supply-chain-intel/", headers=AUTH)
        assert resp.status_code == 200, f"Got {resp.status_code}: {resp.text}"

    def test_response_is_dict(self, sci_client):
        assert isinstance(sci_client.get("/api/v1/supply-chain-intel/", headers=AUTH).json(), dict)

    def test_status_ok(self, sci_client):
        body = sci_client.get("/api/v1/supply-chain-intel/", headers=AUTH).json()
        assert body.get("status") == "ok"

    def test_org_id_present(self, sci_client):
        body = sci_client.get("/api/v1/supply-chain-intel/", headers=AUTH).json()
        assert "org_id" in body

    def test_stats_key_present(self, sci_client):
        body = sci_client.get("/api/v1/supply-chain-intel/", headers=AUTH).json()
        assert "stats" in body

    def test_no_mock_sentinel(self, sci_client):
        text = sci_client.get("/api/v1/supply-chain-intel/", headers=AUTH).text
        for sentinel in ("MOCK_", "lorem ipsum", "Acme Corp"):
            assert sentinel.lower() not in text.lower()

    def test_org_id_reflects_query_param(self, sci_client):
        body = sci_client.get("/api/v1/supply-chain-intel/?org_id=intel-org", headers=AUTH).json()
        assert body.get("org_id") == "intel-org"

    def test_no_auth_returns_401_or_403(self, sci_client):
        resp = sci_client.get("/api/v1/supply-chain-intel/")
        assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# Endpoint 3: GET /api/v1/supply-chain-monitoring/
# ---------------------------------------------------------------------------

class TestSupplyChainMonitoringRootEndpoint:
    def test_status_200(self, scm_client):
        resp = scm_client.get("/api/v1/supply-chain-monitoring/", headers=AUTH)
        assert resp.status_code == 200, f"Got {resp.status_code}: {resp.text}"

    def test_response_is_dict(self, scm_client):
        assert isinstance(scm_client.get("/api/v1/supply-chain-monitoring/", headers=AUTH).json(), dict)

    def test_status_ok(self, scm_client):
        body = scm_client.get("/api/v1/supply-chain-monitoring/", headers=AUTH).json()
        assert body.get("status") == "ok"

    def test_org_id_present(self, scm_client):
        body = scm_client.get("/api/v1/supply-chain-monitoring/", headers=AUTH).json()
        assert "org_id" in body

    def test_total_suppliers_key(self, scm_client):
        body = scm_client.get("/api/v1/supply-chain-monitoring/", headers=AUTH).json()
        assert "total_suppliers" in body

    def test_total_events_key(self, scm_client):
        body = scm_client.get("/api/v1/supply-chain-monitoring/", headers=AUTH).json()
        assert "total_events" in body

    def test_open_events_key(self, scm_client):
        body = scm_client.get("/api/v1/supply-chain-monitoring/", headers=AUTH).json()
        assert "open_events" in body

    def test_no_mock_sentinel(self, scm_client):
        text = scm_client.get("/api/v1/supply-chain-monitoring/", headers=AUTH).text
        for sentinel in ("MOCK_", "lorem ipsum", "demo-org"):
            assert sentinel.lower() not in text.lower()

    def test_org_id_reflects_query_param(self, scm_client):
        body = scm_client.get("/api/v1/supply-chain-monitoring/?org_id=monitor-org", headers=AUTH).json()
        assert body.get("org_id") == "monitor-org"

    def test_no_auth_returns_401_or_403(self, scm_client):
        resp = scm_client.get("/api/v1/supply-chain-monitoring/")
        assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# Endpoint 4: GET /api/v1/sbom-reeval/
# ---------------------------------------------------------------------------

class TestSBOMReevalRootEndpoint:
    def test_status_200(self, reeval_client):
        resp = reeval_client.get("/api/v1/sbom-reeval/?org_id=default", headers=AUTH)
        assert resp.status_code == 200, f"Got {resp.status_code}: {resp.text}"

    def test_response_is_dict(self, reeval_client):
        assert isinstance(reeval_client.get("/api/v1/sbom-reeval/?org_id=default", headers=AUTH).json(), dict)

    def test_status_ok(self, reeval_client):
        body = reeval_client.get("/api/v1/sbom-reeval/?org_id=default", headers=AUTH).json()
        assert body.get("status") == "ok"

    def test_org_id_present(self, reeval_client):
        body = reeval_client.get("/api/v1/sbom-reeval/?org_id=default", headers=AUTH).json()
        assert "org_id" in body

    def test_total_schedules_key(self, reeval_client):
        body = reeval_client.get("/api/v1/sbom-reeval/?org_id=default", headers=AUTH).json()
        assert "total_schedules" in body

    def test_enabled_schedules_key(self, reeval_client):
        body = reeval_client.get("/api/v1/sbom-reeval/?org_id=default", headers=AUTH).json()
        assert "enabled_schedules" in body

    def test_total_claims_key(self, reeval_client):
        body = reeval_client.get("/api/v1/sbom-reeval/?org_id=default", headers=AUTH).json()
        assert "total_claims" in body

    def test_no_mock_sentinel(self, reeval_client):
        text = reeval_client.get("/api/v1/sbom-reeval/?org_id=default", headers=AUTH).text
        for sentinel in ("MOCK_", "lorem ipsum", "Acme Corp"):
            assert sentinel.lower() not in text.lower()

    def test_org_id_reflects_query_param(self, reeval_client):
        body = reeval_client.get("/api/v1/sbom-reeval/?org_id=reeval-org", headers=AUTH).json()
        assert body.get("org_id") == "reeval-org"

    def test_no_auth_returns_401_or_403(self, reeval_client):
        resp = reeval_client.get("/api/v1/sbom-reeval/?org_id=default")
        assert resp.status_code in (401, 403)
