"""Router-level tests for SLSA Provenance endpoints — /api/v1/slsa.

Covers:
  GET  /api/v1/slsa/              — health endpoint, 200 + expected keys
  POST /api/v1/slsa/attest        — happy path 201, in-toto envelope returned
  POST /api/v1/slsa/attest        — missing required field → 422
  POST /api/v1/slsa/verify/{id}   — verify a freshly-generated attestation → pass
  GET  /api/v1/slsa/attestations  — list returns the just-generated attestation
  GET  /api/v1/slsa/stats         — stats total > 0 after one attestation
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, "suite-api")
sys.path.insert(0, "suite-core")

# Disable auth for tests
os.environ.setdefault("ALDECI_API_KEY", "test-key")
os.environ.setdefault("FIXOPS_API_KEY", "test-key")

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from apps.api.slsa_provenance_router import router
from apps.api.auth_deps import api_key_auth


# ---------------------------------------------------------------------------
# App fixture — minimal FastAPI app with the SLSA router, auth overridden
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("slsa_router")

    # Override engine DB to a temp file so tests are isolated
    import core.slsa_provenance_engine as _eng_mod
    orig_default = _eng_mod._DEFAULT_DB
    _eng_mod._DEFAULT_DB = str(tmp / "slsa_test.db")

    # Reset cached engine so it picks up the new DB path
    import apps.api.slsa_provenance_router as _router_mod
    _router_mod._engine = None

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[api_key_auth] = lambda: None

    with TestClient(app, raise_server_exceptions=True) as c:
        yield c

    # Restore
    _eng_mod._DEFAULT_DB = orig_default
    _router_mod._engine = None


# Shared payload used across multiple tests
_ATTEST_PAYLOAD = {
    "org_id": "test-org",
    "subject_name": "registry.example.io/app@sha256:abc",
    "subject_sha256": "a" * 64,
    "builder_id": "https://github.com/actions/runner/v2.317.0",
    "build_type": "https://slsa.dev/container-based-build/v0.1?draft",
    "invocation": {"configSource": {"uri": "git+https://github.com/aldeci/demo@main"}},
    "materials": [
        {"uri": "git+https://github.com/aldeci/demo@main", "digest": {"sha1": "deadbeef" * 5}}
    ],
    "metadata": {"buildStartedOn": "2026-05-03T00:00:00Z", "reproducible": False},
    "slsa_level": 3,
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_health_endpoint(client):
    resp = client.get("/api/v1/slsa/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "slsa-provenance"
    assert body["status"] == "ok"
    assert "spec" in body


def test_attest_happy_path_returns_201(client):
    resp = client.post("/api/v1/slsa/attest", json=_ATTEST_PAYLOAD)
    assert resp.status_code == 201
    body = resp.json()
    assert "id" in body
    assert "envelope" in body
    assert "statement" in body
    assert body["slsa_level"] == 3
    # in-toto Statement shape
    stmt = body["statement"]
    assert stmt["_type"] == "https://in-toto.io/Statement/v0.1"
    assert stmt["predicateType"] == "https://slsa.dev/provenance/v0.2"


def test_attest_missing_required_field_returns_422(client):
    bad = dict(_ATTEST_PAYLOAD)
    del bad["subject_sha256"]
    resp = client.post("/api/v1/slsa/attest", json=bad)
    assert resp.status_code == 422


def test_verify_passes_on_fresh_attestation(client):
    # Generate a fresh one
    resp = client.post("/api/v1/slsa/attest", json=_ATTEST_PAYLOAD)
    assert resp.status_code == 201
    att_id = resp.json()["id"]

    resp2 = client.post(f"/api/v1/slsa/verify/{att_id}")
    assert resp2.status_code == 200
    body = resp2.json()
    assert body["attestation_id"] == att_id
    assert body["verdict"] == "pass"
    assert body["checks"]["envelope_parsable"] is True
    assert body["checks"]["has_subject"] is True


def test_list_attestations_returns_generated(client):
    resp = client.get("/api/v1/slsa/attestations", params={"org_id": "test-org"})
    assert resp.status_code == 200
    items = resp.json()
    assert isinstance(items, list)
    assert len(items) >= 1
    assert all(i["org_id"] == "test-org" for i in items)


def test_stats_total_nonzero(client):
    resp = client.get("/api/v1/slsa/stats", params={"org_id": "test-org"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["org_id"] == "test-org"
    assert body["total_attestations"] >= 1
    assert "by_slsa_level" in body
    assert set(body["by_slsa_level"].keys()) == {1, 2, 3, 4} or set(
        map(int, body["by_slsa_level"].keys())
    ) == {1, 2, 3, 4}
