"""
Tests for passive_dns_router — GET / root, resolutions CRUD, fast-flux,
threats, reputation endpoints.  Uses FastAPI TestClient with auth bypassed.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from apps.api.auth_deps import api_key_auth
from apps.api.passive_dns_router import router, _get_engine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    from core.passive_dns_engine import PassiveDNSEngine
    return PassiveDNSEngine(db_path=str(tmp_path / "router_test.db"))


@pytest.fixture
def app(engine):
    a = FastAPI()
    a.include_router(router)
    a.dependency_overrides[api_key_auth] = lambda: None   # bypass auth
    a.dependency_overrides[_get_engine] = lambda: engine  # inject tmp engine
    return a


@pytest.fixture
def client(app):
    return TestClient(app)


ORG = "org-router-test"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_root_returns_service_info(client):
    """GET / must return service name, capabilities list and stats dict."""
    resp = client.get("/api/v1/passive-dns/", params={"org_id": ORG})
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "passive-dns"
    assert "capabilities" in body
    assert "resolution-tracking" in body["capabilities"]
    assert "fast-flux-detection" in body["capabilities"]
    assert isinstance(body["stats"], dict)
    assert "total_resolutions" in body["stats"]


def test_record_and_list_resolution(client):
    """POST /resolutions then GET /resolutions must return the recorded entry."""
    payload = {
        "org_id": ORG,
        "domain": "example.com",
        "resolved_ip": "93.184.216.34",
        "record_type": "A",
        "ttl": 3600,
        "source": "query",
    }
    post_resp = client.post("/api/v1/passive-dns/resolutions", json=payload)
    assert post_resp.status_code == 201
    created = post_resp.json()
    assert created["domain"] == "example.com"
    assert created["resolved_ip"] == "93.184.216.34"

    list_resp = client.get("/api/v1/passive-dns/resolutions", params={"org_id": ORG})
    assert list_resp.status_code == 200
    domains = [r["domain"] for r in list_resp.json()]
    assert "example.com" in domains


def test_record_resolution_invalid_record_type(client):
    """POST /resolutions with bad record_type must return 422."""
    payload = {
        "org_id": ORG,
        "domain": "bad.com",
        "resolved_ip": "1.1.1.1",
        "record_type": "INVALID",
        "source": "query",
    }
    resp = client.post("/api/v1/passive-dns/resolutions", json=payload)
    assert resp.status_code == 422


def test_fast_flux_detection_no_data(client):
    """GET /domains/{domain}/fast-flux with no data must say not fast-flux."""
    resp = client.get(
        "/api/v1/passive-dns/domains/unknown.com/fast-flux",
        params={"org_id": ORG},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["is_fast_flux"] is False
    assert body["distinct_ips"] == 0


def test_add_and_list_threat(client):
    """POST /threats then GET /threats must include the added domain."""
    threat_payload = {
        "org_id": ORG,
        "domain": "malware.example",
        "threat_type": "malware",
        "confidence": 0.95,
        "source": "feed",
        "iocs": ["10.0.0.1"],
    }
    post_resp = client.post("/api/v1/passive-dns/threats", json=threat_payload)
    assert post_resp.status_code == 201
    assert post_resp.json()["domain"] == "malware.example"

    list_resp = client.get("/api/v1/passive-dns/threats", params={"org_id": ORG})
    assert list_resp.status_code == 200
    domains = [t["domain"] for t in list_resp.json()]
    assert "malware.example" in domains


def test_domain_reputation_reflects_threat(client):
    """check_reputation must mark domain malicious after adding a threat."""
    # Seed threat first
    client.post(
        "/api/v1/passive-dns/threats",
        json={
            "org_id": ORG,
            "domain": "phish.example",
            "threat_type": "phishing",
            "confidence": 0.8,
            "source": "manual",
            "iocs": [],
        },
    )

    rep_resp = client.get(
        "/api/v1/passive-dns/domains/phish.example/reputation",
        params={"org_id": ORG},
    )
    assert rep_resp.status_code == 200
    rep = rep_resp.json()
    assert rep.get("is_malicious") is True or rep.get("threat_count", 0) >= 1
