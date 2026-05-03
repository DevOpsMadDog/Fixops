"""
Router-level HTTP tests for OpenCTI threat-intel integration API.

Covers /api/v1/opencti/* via FastAPI TestClient.  The upstream OpenCTI
GraphQL/REST API is replaced with an in-process httpx MockTransport so
no real OpenCTI server is required.

NO MOCKS in product code — these stubs only replace the *external* HTTP
boundary; everything inside the engine + router runs for real.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

for _p in ["suite-core", "suite-api"]:
    _abs = str(Path(__file__).parent.parent / _p)
    if _abs not in sys.path:
        sys.path.insert(0, _abs)

import core.opencti_integration_engine as _engine_mod
from core.opencti_integration_engine import OpenCTIIntegrationEngine
import apps.api.opencti_router as _router_mod
from apps.api.opencti_router import router


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_singleton():
    _engine_mod._engine_singleton = None
    yield
    _engine_mod._engine_singleton = None


def _build_mock_transport():
    """
    Mimics a minimal OpenCTI upstream:
      POST /graphql              → dispatches by query keyword
      POST /api/stix/import      → returns import summary
    """
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        body_text = request.content.decode("utf-8") if request.content else ""
        captured["last"] = {
            "method": request.method,
            "url": str(request.url),
            "headers": dict(request.headers),
            "body": body_text,
        }
        path = request.url.path

        if path == "/graphql" and request.method == "POST":
            try:
                gql = json.loads(body_text)
            except ValueError:
                return httpx.Response(400, json={"errors": [{"message": "bad json"}]})
            query = gql.get("query") or ""
            variables = gql.get("variables") or {}

            if "threatActors" in query:
                return httpx.Response(200, json={"data": {"threatActors": {
                    "edges": [
                        {"node": {
                            "id": "threat-actor--apt29",
                            "name": "APT29",
                            "description": "Cozy Bear",
                            "aliases": ["CozyBear", "TheDukes"],
                            "first_seen": "2008-01-01T00:00:00Z",
                            "last_seen": "2026-04-30T00:00:00Z",
                            "sophistication": "expert",
                            "resource_level": "government",
                            "primary_motivation": "organizational-gain",
                        }},
                    ],
                    "pageInfo": {"globalCount": 1},
                }}})

            if "indicators" in query:
                value = (variables.get("value") or "").strip()
                if not value:
                    return httpx.Response(200, json={"data": {"indicators": {
                        "edges": [], "pageInfo": {"globalCount": 0},
                    }}})
                return httpx.Response(200, json={"data": {"indicators": {
                    "edges": [
                        {"node": {
                            "id": "indicator--abc",
                            "pattern": f"[ipv4-addr:value = '{value}']",
                            "valid_from": "2026-04-01T00:00:00Z",
                            "valid_until": "2026-12-31T00:00:00Z",
                            "objectLabel": {"edges": [
                                {"node": {"value": "malicious-activity"}},
                                {"node": {"value": "c2"}},
                            ]},
                            "killChainPhases": {"edges": [
                                {"node": {"kill_chain_name": "mitre-attack",
                                          "phase_name": "command-and-control"}},
                            ]},
                        }},
                    ],
                    "pageInfo": {"globalCount": 1},
                }}})

            if "intrusionSets" in query:
                return httpx.Response(200, json={"data": {"intrusionSets": {
                    "edges": [
                        {"node": {
                            "id": "intrusion-set--apt28",
                            "name": "APT28",
                            "description": "Fancy Bear",
                            "aliases": ["FancyBear", "Sofacy"],
                            "first_seen": "2004-01-01T00:00:00Z",
                            "last_seen": "2026-04-30T00:00:00Z",
                            "sophistication": "expert",
                            "resource_level": "government",
                            "primary_motivation": "organizational-gain",
                        }},
                    ],
                    "pageInfo": {"globalCount": 1},
                }}})

            if "malwares" in query:
                family = (variables.get("family") or "").strip()
                return httpx.Response(200, json={"data": {"malwares": {
                    "edges": [
                        {"node": {
                            "id": "malware--emotet-1",
                            "name": family or "Emotet",
                            "malware_types": ["banker", "trojan"],
                        }},
                    ],
                    "pageInfo": {"globalCount": 1},
                }}})

            return httpx.Response(200, json={"data": {}})

        if path == "/api/stix/import" and request.method == "POST":
            try:
                bundle = json.loads(body_text)
            except ValueError:
                return httpx.Response(400, json={"error": "bad json"})
            objects = bundle.get("objects") or []
            return httpx.Response(200, json={
                "imported_objects": len(objects),
                "created_relationships": sum(
                    1 for o in objects if isinstance(o, dict) and o.get("type") == "relationship"
                ),
                "work_id": "work--abc-123",
            })

        return httpx.Response(404, json={"error": f"unmocked path: {path}"})

    transport = httpx.MockTransport(handler)
    return transport, captured


@pytest.fixture
def opencti_env(monkeypatch):
    monkeypatch.setenv("OPENCTI_URL", "http://test-opencti:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "test-token-xyz")
    yield


@pytest.fixture
def patched_engine(opencti_env, monkeypatch):
    transport, captured = _build_mock_transport()
    eng = OpenCTIIntegrationEngine()
    monkeypatch.setattr(eng, "_client_or_new", lambda: httpx.Client(transport=transport, timeout=5.0))
    monkeypatch.setattr(_router_mod, "_get_engine", lambda: eng)
    return eng, captured


@pytest.fixture
def client(patched_engine):
    app = FastAPI()
    app.include_router(router)
    try:
        from apps.api.auth_deps import api_key_auth as _auth
        app.dependency_overrides[_auth] = lambda: None
    except ImportError:
        pass
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture
def client_no_opencti(monkeypatch):
    monkeypatch.delenv("OPENCTI_URL", raising=False)
    monkeypatch.delenv("OPENCTI_TOKEN", raising=False)
    eng = OpenCTIIntegrationEngine()
    monkeypatch.setattr(_router_mod, "_get_engine", lambda: eng)

    app = FastAPI()
    app.include_router(router)
    try:
        from apps.api.auth_deps import api_key_auth as _auth
        app.dependency_overrides[_auth] = lambda: None
    except ImportError:
        pass
    return TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# 1. Capability summary
# ---------------------------------------------------------------------------


def test_capability_ok(client):
    resp = client.get("/api/v1/opencti/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "OpenCTI"
    assert body["opencti_url_present"] is True
    assert body["opencti_token_present"] is True
    assert body["status"] == "ok"
    assert "/api/threat-actors" in body["endpoints"]
    assert "/api/indicators" in body["endpoints"]
    assert "/api/stix-import" in body["endpoints"]
    assert "/api/intrusion-sets" in body["endpoints"]
    assert "/api/malware" in body["endpoints"]


def test_capability_unavailable_when_env_unset(client_no_opencti):
    resp = client_no_opencti.get("/api/v1/opencti/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["opencti_url_present"] is False
    assert body["opencti_token_present"] is False
    assert body["status"] == "unavailable"


# ---------------------------------------------------------------------------
# 2. Threat actors
# ---------------------------------------------------------------------------


def test_threat_actors_proxied(client, patched_engine):
    _eng, captured = patched_engine
    resp = client.get("/api/v1/opencti/api/threat-actors", params={"limit": 10, "offset": 0})
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    actor = body["threat_actors"][0]
    assert actor["name"] == "APT29"
    assert "CozyBear" in actor["aliases"]
    assert actor["sophistication"] == "expert"
    # Verify GraphQL boundary used
    assert captured["last"]["method"] == "POST"
    assert captured["last"]["url"].endswith("/graphql")
    assert "authorization" in {k.lower() for k in captured["last"]["headers"]}
    assert any(v.startswith("Bearer ") for k,v in captured["last"]["headers"].items() if k.lower()=="authorization")


# ---------------------------------------------------------------------------
# 3. Indicators
# ---------------------------------------------------------------------------


def test_indicators_lookup(client, patched_engine):
    _eng, captured = patched_engine
    resp = client.get(
        "/api/v1/opencti/api/indicators",
        params={"type": "ipv4-addr", "value": "8.8.8.8"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    ind = body["indicators"][0]
    assert "8.8.8.8" in ind["pattern"]
    assert "malicious-activity" in ind["labels"]
    assert ind["kill_chain_phases"][0]["phase_name"] == "command-and-control"


def test_indicators_bad_type_400(client):
    resp = client.get(
        "/api/v1/opencti/api/indicators",
        params={"type": "bogus-type", "value": "x"},
    )
    assert resp.status_code == 400


def test_indicators_missing_value_422(client):
    resp = client.get("/api/v1/opencti/api/indicators", params={"type": "ipv4-addr"})
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 4. STIX import
# ---------------------------------------------------------------------------


def test_stix_import_bundle(client, patched_engine):
    _eng, captured = patched_engine
    bundle = {
        "type": "bundle",
        "id": "bundle--demo",
        "objects": [
            {"type": "indicator", "id": "indicator--1", "pattern": "[url:value='http://evil.example']"},
            {"type": "malware", "id": "malware--1", "name": "Emotet"},
            {"type": "relationship", "id": "relationship--1",
             "source_ref": "indicator--1", "target_ref": "malware--1"},
        ],
    }
    resp = client.post("/api/v1/opencti/api/stix-import", json={"bundle": bundle})
    assert resp.status_code == 200
    body = resp.json()
    assert body["imported_objects"] == 3
    assert body["created_relationships"] == 1
    assert body["work_id"] == "work--abc-123"
    assert captured["last"]["url"].endswith("/api/stix/import")


def test_stix_import_invalid_bundle_400(client):
    bad = client.post("/api/v1/opencti/api/stix-import", json={"bundle": {"type": "not-bundle", "objects": []}})
    assert bad.status_code == 400
    bad2 = client.post("/api/v1/opencti/api/stix-import", json={"bundle": {"type": "bundle", "objects": "not-a-list"}})
    assert bad2.status_code == 400


# ---------------------------------------------------------------------------
# 5. Intrusion sets
# ---------------------------------------------------------------------------


def test_intrusion_sets_proxied(client):
    resp = client.get("/api/v1/opencti/api/intrusion-sets")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    iset = body["intrusion_sets"][0]
    assert iset["name"] == "APT28"
    assert "FancyBear" in iset["aliases"]


# ---------------------------------------------------------------------------
# 6. Malware
# ---------------------------------------------------------------------------


def test_malware_lookup(client):
    resp = client.get("/api/v1/opencti/api/malware", params={"family": "Emotet"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    mal = body["malware"][0]
    assert mal["name"] == "Emotet"
    assert "trojan" in mal["types"]


def test_malware_no_family(client):
    resp = client.get("/api/v1/opencti/api/malware")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] >= 1


# ---------------------------------------------------------------------------
# 7. Unavailable upstream → 503 across lookup endpoints
# ---------------------------------------------------------------------------


def test_lookup_endpoints_503_when_env_unset(client_no_opencti):
    r = client_no_opencti.get("/api/v1/opencti/api/threat-actors")
    assert r.status_code == 503
    r = client_no_opencti.get(
        "/api/v1/opencti/api/indicators",
        params={"type": "ipv4-addr", "value": "1.1.1.1"},
    )
    assert r.status_code == 503
    r = client_no_opencti.post(
        "/api/v1/opencti/api/stix-import",
        json={"bundle": {"type": "bundle", "objects": []}},
    )
    assert r.status_code == 503
    r = client_no_opencti.get("/api/v1/opencti/api/intrusion-sets")
    assert r.status_code == 503
    r = client_no_opencti.get("/api/v1/opencti/api/malware", params={"family": "Emotet"})
    assert r.status_code == 503
