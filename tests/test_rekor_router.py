"""Router-level tests for the Sigstore Rekor proxy — /api/v1/rekor.

All upstream traffic is intercepted with an httpx MockTransport so the
tests are hermetic — no live Rekor calls.

Covers:
  * GET  /api/v1/rekor/                            capability summary, status=ok
  * GET  /api/v1/rekor/api/v1/log                  proxied tree state
  * GET  /api/v1/rekor/api/v1/log/proof            consistency proof
  * GET  /api/v1/rekor/api/v1/log/entries/{uuid}   entry by uuid
  * GET  /api/v1/rekor/api/v1/log/entries          entry by logIndex
  * POST /api/v1/rekor/api/v1/log/entries          submit entry → 201
  * POST /api/v1/rekor/api/v1/index/retrieve       search by hash → list
  * POST /api/v1/rekor/api/v1/index/retrieve       empty body → 422
  * GET  /api/v1/rekor/                            unreachable → status=unavailable
  * GET  /api/v1/rekor/api/v1/log                  unreachable → 503
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, "suite-api")
sys.path.insert(0, "suite-core")

os.environ.setdefault("ALDECI_API_KEY", "test-key")
os.environ.setdefault("FIXOPS_API_KEY", "test-key")

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Stub upstream Rekor server
# ---------------------------------------------------------------------------


_LOG_STATE = {
    "rootHash": "deadbeef" * 8,
    "signedTreeHead": "BASE64SIGNATURE==",
    "treeID": "1193050959916656506",
    "treeSize": 12345,
    "inactiveShards": [
        {
            "rootHash": "cafebabe" * 8,
            "signedTreeHead": "OLDBASE64==",
            "treeID": "9999",
            "treeSize": 10,
        }
    ],
}

_PROOF_RESPONSE = {
    "rootHash": "deadbeef" * 8,
    "hashes": ["aabb" * 16, "ccdd" * 16],
    "leafIndex": 7,
    "leafHash": "ee" * 32,
}

_ENTRY_RESPONSE = {
    "abcd1234": {
        "body": "ZXlKaGNHbFdaWEp6YVc5dUlqb2lNQzR3TGpFaWZRPT0=",
        "integratedTime": 1714780800,
        "logID": "logid-x",
        "logIndex": 42,
        "verification": {
            "inclusionProof": {
                "checkpoint": "rekor.sigstore.dev - 12345...",
                "hashes": ["aa" * 32],
                "logIndex": 42,
                "rootHash": "deadbeef" * 8,
                "treeSize": 12345,
            },
            "signedEntryTimestamp": "BASE64SET==",
        },
    }
}

_INDEX_RESULT = ["abcd1234", "efgh5678"]


def _stub_handler(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    method = request.method
    if method == "GET" and path == "/api/v1/log":
        return httpx.Response(200, json=_LOG_STATE)
    if method == "GET" and path == "/api/v1/log/proof":
        return httpx.Response(200, json=_PROOF_RESPONSE)
    if method == "GET" and path.startswith("/api/v1/log/entries/"):
        return httpx.Response(200, json=_ENTRY_RESPONSE)
    if method == "GET" and path == "/api/v1/log/entries":
        return httpx.Response(200, json=_ENTRY_RESPONSE)
    if method == "POST" and path == "/api/v1/log/entries":
        return httpx.Response(201, json=_ENTRY_RESPONSE)
    if method == "POST" and path == "/api/v1/index/retrieve":
        return httpx.Response(200, json=_INDEX_RESULT)
    return httpx.Response(404, json={"detail": f"unhandled {method} {path}"})


def _unreachable_handler(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("simulated upstream offline", request=request)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def stub_engine(monkeypatch):
    """Inject a Rekor engine wired to the stub upstream."""
    from core import rekor_engine as _eng_mod

    transport = httpx.MockTransport(_stub_handler)
    stub_client = httpx.Client(
        transport=transport, base_url="https://rekor.example.test"
    )
    engine = _eng_mod.RekorEngine(
        rekor_url="https://rekor.example.test", client=stub_client
    )

    monkeypatch.setattr(_eng_mod, "_singleton", engine, raising=False)
    monkeypatch.setattr(
        _eng_mod, "get_rekor_engine", lambda *a, **kw: engine, raising=True
    )
    yield engine
    engine.close()


@pytest.fixture
def unreachable_engine(monkeypatch):
    """Inject an engine whose upstream always raises ConnectError."""
    from core import rekor_engine as _eng_mod

    transport = httpx.MockTransport(_unreachable_handler)
    stub_client = httpx.Client(
        transport=transport, base_url="https://rekor.offline.test"
    )
    engine = _eng_mod.RekorEngine(
        rekor_url="https://rekor.offline.test", client=stub_client
    )
    monkeypatch.setattr(_eng_mod, "_singleton", engine, raising=False)
    monkeypatch.setattr(
        _eng_mod, "get_rekor_engine", lambda *a, **kw: engine, raising=True
    )
    yield engine
    engine.close()


@pytest.fixture
def client(stub_engine):
    from apps.api.rekor_router import router
    from apps.api.auth_deps import api_key_auth

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[api_key_auth] = lambda: None
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


@pytest.fixture
def offline_client(unreachable_engine):
    from apps.api.rekor_router import router
    from apps.api.auth_deps import api_key_auth

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[api_key_auth] = lambda: None
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


# ---------------------------------------------------------------------------
# Tests — happy path against stub upstream
# ---------------------------------------------------------------------------


def test_health_endpoint_ok(client):
    resp = client.get("/api/v1/rekor/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "Sigstore Rekor"
    assert body["status"] == "ok"
    assert body["rekor_url"] == "https://rekor.example.test"
    assert "/api/v1/log" in body["endpoints"]
    assert "/api/v1/log/entries" in body["endpoints"]
    assert "/api/v1/log/proof" in body["endpoints"]
    assert "/api/v1/index/retrieve" in body["endpoints"]


def test_get_log_returns_tree_state(client):
    resp = client.get("/api/v1/rekor/api/v1/log")
    assert resp.status_code == 200
    body = resp.json()
    assert body["rootHash"] == _LOG_STATE["rootHash"]
    assert body["treeID"] == _LOG_STATE["treeID"]
    assert body["treeSize"] == 12345
    assert body["signedTreeHead"] == _LOG_STATE["signedTreeHead"]
    assert isinstance(body["inactiveShards"], list)
    assert body["inactiveShards"][0]["treeID"] == "9999"


def test_get_proof(client):
    resp = client.get(
        "/api/v1/rekor/api/v1/log/proof",
        params={"lastSize": 12345, "firstSize": 7, "treeID": "1193050959916656506"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["rootHash"] == _PROOF_RESPONSE["rootHash"]
    assert body["leafIndex"] == 7
    assert isinstance(body["hashes"], list)
    assert len(body["hashes"]) == 2


def test_get_entry_by_uuid(client):
    resp = client.get("/api/v1/rekor/api/v1/log/entries/abcd1234")
    assert resp.status_code == 200
    body = resp.json()
    assert "abcd1234" in body
    entry = body["abcd1234"]
    assert entry["logIndex"] == 42
    assert entry["integratedTime"] == 1714780800
    assert "verification" in entry
    assert "inclusionProof" in entry["verification"]
    assert entry["verification"]["inclusionProof"]["treeSize"] == 12345


def test_get_entry_by_index(client):
    resp = client.get(
        "/api/v1/rekor/api/v1/log/entries", params={"logIndex": 42}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "abcd1234" in body


def test_create_entry_returns_201(client):
    payload = {
        "kind": "hashedrekord",
        "apiVersion": "0.0.1",
        "spec": {
            "signature": {
                "content": "MEUCIQ...",
                "publicKey": {"content": "LS0tLS1CRUdJTi..."},
            },
            "data": {"hash": {"algorithm": "sha256", "value": "a" * 64}},
        },
    }
    resp = client.post("/api/v1/rekor/api/v1/log/entries", json=payload)
    assert resp.status_code == 201
    body = resp.json()
    assert "abcd1234" in body


def test_index_retrieve_returns_uuids(client):
    resp = client.post(
        "/api/v1/rekor/api/v1/index/retrieve",
        json={"hash": "sha256:" + ("a" * 64)},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body, list)
    assert body == _INDEX_RESULT


def test_index_retrieve_empty_body_returns_422(client):
    resp = client.post("/api/v1/rekor/api/v1/index/retrieve", json={})
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Tests — upstream unavailable: NO MOCKS, surface failure honestly
# ---------------------------------------------------------------------------


def test_health_when_upstream_unreachable_reports_unavailable(offline_client):
    resp = offline_client.get("/api/v1/rekor/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "unavailable"
    assert body["service"] == "Sigstore Rekor"


def test_get_log_when_upstream_unreachable_returns_503(offline_client):
    resp = offline_client.get("/api/v1/rekor/api/v1/log")
    assert resp.status_code == 503
    detail = resp.json()["detail"]
    assert "rekor.offline.test" in detail or "Rekor" in detail
