"""Smoke tests for intelligent_security_router."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    from apps.api.intelligent_security_router import router
    from apps.api.auth_deps import api_key_auth

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[api_key_auth] = lambda: None
    return TestClient(app)


def test_health(client):
    r = client.get("/api/v1/intelligent-security/health")
    assert r.status_code == 200
    assert r.json()["engine"] == "intelligent_security"


def test_status(client):
    r = client.get("/api/v1/intelligent-security/status")
    assert r.status_code == 200
    body = r.json()
    # Engine may be degraded if config init fails — both are valid responses
    assert body["engine"] == "intelligent_security"


def test_assessment_invalid_scan_type(client):
    r = client.post(
        "/api/v1/intelligent-security/assessment",
        json={
            "org_id": "ise-test",
            "target": "https://example.com",
            "cve_ids": ["CVE-2024-0001"],
            "scan_type": "telepathic",
        },
    )
    assert r.status_code == 422


def test_assessment_missing_cves_rejected(client):
    r = client.post(
        "/api/v1/intelligent-security/assessment",
        json={
            "org_id": "ise-test",
            "target": "https://example.com",
            "cve_ids": [],
        },
    )
    assert r.status_code == 422
