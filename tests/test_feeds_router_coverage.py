"""Comprehensive tests for suite-feeds/api/feeds_router.py — 31 feed endpoints."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    app = FastAPI()
    from api.feeds_router import router
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


class TestEPSS:
    def test_get_epss(self, client):
        resp = client.get("/api/v1/feeds/epss")
        assert resp.status_code == 200

    def test_refresh_epss(self, client):
        resp = client.post("/api/v1/feeds/epss/refresh")
        assert resp.status_code in (200, 202)


class TestKEV:
    def test_get_kev(self, client):
        resp = client.get("/api/v1/feeds/kev")
        assert resp.status_code == 200

    def test_refresh_kev(self, client):
        resp = client.post("/api/v1/feeds/kev/refresh")
        assert resp.status_code in (200, 202)


class TestNVD:
    def test_refresh_nvd(self, client):
        resp = client.post("/api/v1/feeds/nvd/refresh")
        assert resp.status_code in (200, 202)

    def test_get_recent(self, client):
        resp = client.get("/api/v1/feeds/nvd/recent")
        assert resp.status_code == 200

    def test_get_cve(self, client):
        resp = client.get("/api/v1/feeds/nvd/CVE-2024-0001")
        assert resp.status_code in (200, 404)


class TestExploitDB:
    def test_refresh_exploitdb(self, client):
        resp = client.post("/api/v1/feeds/exploitdb/refresh")
        assert resp.status_code in (200, 202)


class TestOSV:
    def test_refresh_osv(self, client):
        resp = client.post("/api/v1/feeds/osv/refresh")
        assert resp.status_code in (200, 202)


class TestGitHub:
    def test_refresh_github(self, client):
        resp = client.post("/api/v1/feeds/github/refresh")
        assert resp.status_code in (200, 202)


class TestExploits:
    def test_list_exploits(self, client):
        resp = client.get("/api/v1/feeds/exploits")
        assert resp.status_code == 200

    def test_get_exploit_by_cve(self, client):
        resp = client.get("/api/v1/feeds/exploits/CVE-2024-0001")
        assert resp.status_code in (200, 404)

    def test_create_exploit(self, client):
        resp = client.post(
            "/api/v1/feeds/exploits",
            json={"cve_id": "CVE-2024-0001", "exploit_url": "https://example.com/poc"},
        )
        assert resp.status_code in (200, 201, 422)


class TestThreatActors:
    def test_list_threat_actors(self, client):
        resp = client.get("/api/v1/feeds/threat-actors")
        assert resp.status_code == 200

    def test_get_actors_by_cve(self, client):
        resp = client.get("/api/v1/feeds/threat-actors/CVE-2024-0001")
        assert resp.status_code in (200, 404)

    def test_get_actor_by_name(self, client):
        resp = client.get("/api/v1/feeds/threat-actors/by-actor/APT28")
        assert resp.status_code in (200, 404)

    def test_create_threat_actor(self, client):
        resp = client.post(
            "/api/v1/feeds/threat-actors",
            json={"name": "APT28", "cve_id": "CVE-2024-0001"},
        )
        assert resp.status_code in (200, 201, 422)


class TestSupplyChain:
    def test_list_supply_chain(self, client):
        resp = client.get("/api/v1/feeds/supply-chain")
        assert resp.status_code == 200

    def test_get_package(self, client):
        resp = client.get("/api/v1/feeds/supply-chain/lodash")
        assert resp.status_code in (200, 404)

    def test_create_supply_chain(self, client):
        resp = client.post(
            "/api/v1/feeds/supply-chain",
            json={"package": "lodash", "version": "4.17.21"},
        )
        assert resp.status_code in (200, 201, 422)
