"""Smoke tests for mitre_attack_coverage_router."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    from core import mitre_attack_coverage_engine as engine_mod

    monkeypatch.setattr(engine_mod, "_DATA_DIR", tmp_path)
    engine_mod._engine_instance = engine_mod.MITREAttackCoverageEngine(
        data_dir=str(tmp_path)
    )

    from apps.api.mitre_attack_coverage_router import router
    from apps.api.auth_deps import api_key_auth

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[api_key_auth] = lambda: None
    return TestClient(app)


def test_health(client):
    r = client.get("/api/v1/mitre-attack-coverage/health")
    assert r.status_code == 200
    assert r.json()["engine"] == "mitre_attack_coverage"


def test_status(client):
    r = client.get("/api/v1/mitre-attack-coverage/status")
    assert r.status_code == 200
    assert r.json()["ready"] is True


def test_seed_then_coverage(client):
    r = client.post("/api/v1/mitre-attack-coverage/seed", json={"org_id": "mitre-test"})
    assert r.status_code == 200, r.text
    assert r.json()["seeded_techniques"] > 0

    r2 = client.get(
        "/api/v1/mitre-attack-coverage/coverage", params={"org_id": "mitre-test"}
    )
    assert r2.status_code == 200, r2.text
    body = r2.json()
    assert body["total_count"] > 0
    assert body["overall_pct"] == 0.0  # nothing detected yet


def test_log_detection_increases_coverage(client):
    client.post("/api/v1/mitre-attack-coverage/seed", json={"org_id": "mitre-detect"})
    r = client.post(
        "/api/v1/mitre-attack-coverage/detections",
        json={
            "org_id": "mitre-detect",
            "technique_id": "T1190",
            "source": "ids",
            "confidence": 0.9,
        },
    )
    assert r.status_code == 200, r.text
    cov = client.get(
        "/api/v1/mitre-attack-coverage/coverage", params={"org_id": "mitre-detect"}
    ).json()
    assert cov["covered_count"] >= 1


def test_heatmap(client):
    client.post("/api/v1/mitre-attack-coverage/seed", json={"org_id": "mitre-heat"})
    r = client.get(
        "/api/v1/mitre-attack-coverage/heatmap", params={"org_id": "mitre-heat"}
    )
    assert r.status_code == 200
    assert r.json()["domain"] == "enterprise-attack"
