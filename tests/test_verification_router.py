"""Smoke tests for verification_router."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    from apps.api.verification_router import router
    from apps.api.auth_deps import api_key_auth

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[api_key_auth] = lambda: None
    return TestClient(app)


def test_health(client):
    r = client.get("/api/v1/verification/health")
    assert r.status_code == 200
    assert r.json()["engine"] == "verification"


def test_status(client):
    r = client.get("/api/v1/verification/status")
    assert r.status_code == 200
    body = r.json()
    assert body["ready"] is True
    assert body["signature_count"] > 0
    assert 0 < body["min_confidence"] <= 1


def test_signatures_listing(client):
    r = client.get("/api/v1/verification/signatures")
    assert r.status_code == 200
    sigs = r.json()
    assert isinstance(sigs, list)
    assert len(sigs) > 0
    # Check shape of first signature
    first = sigs[0]
    assert "id" in first
    assert "name" in first
    assert "header_patterns" in first


def test_run_rejects_bad_url(client):
    r = client.post(
        "/api/v1/verification/run",
        json={
            "org_id": "ver-test",
            "target_url": "ftp://nope",
            "signature": {"name": "test"},
        },
    )
    assert r.status_code == 422
