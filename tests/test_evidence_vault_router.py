"""API-level tests for evidence_vault_router.

Covers: GET / root, POST /evidence, GET /evidence/{id},
GET /summary, POST /evidence/{id}/verify.

Uses dependency_overrides to bypass auth and a tmp-path engine.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from apps.api.auth_deps import api_key_auth
from apps.api.evidence_vault_router import router, _get_engine
from core.evidence_vault_engine import EvidenceVaultEngine


@pytest.fixture
def client(tmp_path):
    app = FastAPI()
    app.include_router(router)

    # Inject a fresh tmp engine so tests are isolated
    tmp_engine = EvidenceVaultEngine(db_path=str(tmp_path / "vault_router_test.db"))

    app.dependency_overrides[api_key_auth] = lambda: None
    app.dependency_overrides[_get_engine] = lambda: tmp_engine

    yield TestClient(app)
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# 1. GET / root
# ---------------------------------------------------------------------------


def test_root_returns_ok(client):
    resp = client.get("/api/v1/evidence-vault/")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["prefix"] == "/api/v1/evidence-vault"
    assert "total" in data


def test_root_summary_keys_present(client):
    resp = client.get("/api/v1/evidence-vault/", params={"org_id": "testorg"})
    assert resp.status_code == 200
    data = resp.json()
    for key in ("total", "sealed_count", "by_framework", "expiring_soon", "expired", "active_collections"):
        assert key in data, f"missing key: {key}"


# ---------------------------------------------------------------------------
# 2. POST /evidence
# ---------------------------------------------------------------------------


def test_store_evidence_201(client):
    payload = {
        "org_id": "org1",
        "evidence_name": "Router test evidence",
        "evidence_type": "log_file",
        "framework": "SOC2",
        "control_id": "CC6.1",
        "collected_by": "agent",
        "collection_method": "automated",
        "content": "some log content",
    }
    resp = client.post("/api/v1/evidence-vault/evidence", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["evidence_name"] == "Router test evidence"
    assert data["status"] == "active"
    assert data["sealed"] is False
    assert data["content_hash"] != ""


# ---------------------------------------------------------------------------
# 3. GET /evidence/{id}
# ---------------------------------------------------------------------------


def test_get_evidence_detail_200(client):
    payload = {
        "org_id": "org1",
        "evidence_name": "Detail test",
        "evidence_type": "screenshot",
        "framework": "NIST",
        "control_id": "AC-1",
        "collected_by": "bot",
        "collection_method": "api_pull",
        "content": "detail content",
    }
    created = client.post("/api/v1/evidence-vault/evidence", json=payload).json()
    ev_id = created["id"]

    resp = client.get(f"/api/v1/evidence-vault/evidence/{ev_id}", params={"org_id": "org1"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == ev_id
    assert "access_log" in data


def test_get_evidence_detail_404_unknown(client):
    resp = client.get("/api/v1/evidence-vault/evidence/nonexistent-id", params={"org_id": "org1"})
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 4. POST /evidence/{id}/verify
# ---------------------------------------------------------------------------


def test_verify_integrity_valid(client):
    content = "tamper-evident content"
    payload = {
        "org_id": "org1",
        "evidence_name": "Verify test",
        "evidence_type": "attestation",
        "framework": "ISO27001",
        "control_id": "A.12.1",
        "collected_by": "sys",
        "collection_method": "automated",
        "content": content,
    }
    created = client.post("/api/v1/evidence-vault/evidence", json=payload).json()
    ev_id = created["id"]

    resp = client.post(
        f"/api/v1/evidence-vault/evidence/{ev_id}/verify",
        json={"org_id": "org1", "content": content},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["evidence_id"] == ev_id


def test_verify_integrity_tampered(client):
    content = "original content"
    payload = {
        "org_id": "org1",
        "evidence_name": "Tamper detect",
        "evidence_type": "log_file",
        "framework": "HIPAA",
        "control_id": "164.312",
        "collected_by": "sys",
        "collection_method": "automated",
        "content": content,
    }
    created = client.post("/api/v1/evidence-vault/evidence", json=payload).json()
    ev_id = created["id"]

    resp = client.post(
        f"/api/v1/evidence-vault/evidence/{ev_id}/verify",
        json={"org_id": "org1", "content": "tampered!"},
    )
    assert resp.status_code == 200
    assert resp.json()["valid"] is False
