"""Smoke tests for context_engine_router."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    from apps.api.context_engine_router import router
    from apps.api.auth_deps import api_key_auth

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[api_key_auth] = lambda: None
    return TestClient(app)


def test_health(client):
    r = client.get("/api/v1/context-engine/health")
    assert r.status_code == 200
    assert r.json()["engine"] == "context_engine"


def test_status(client):
    r = client.get("/api/v1/context-engine/status")
    assert r.status_code == 200
    assert r.json()["ready"] is True


def test_evaluate_basic(client):
    body = {
        "org_id": "ctx-test",
        "settings": {
            "criticality_weights": {"mission_critical": 4, "internal": 1},
            "data_weights": {"pii": 4, "internal": 2, "public": 1},
            "exposure_weights": {"internet": 3, "internal": 1},
            "playbooks": [
                {"name": "Critical", "min_score": 8},
                {"name": "Standard", "min_score": 0},
            ],
        },
        "design_rows": [
            {
                "name": "payments-api",
                "customer_impact": "mission_critical",
                "data_classification": "pii",
                "exposure": "internet",
            },
            {
                "name": "internal-tool",
                "customer_impact": "internal",
                "data_classification": "internal",
                "exposure": "internal",
            },
        ],
        "crosswalk": [
            {
                "design_index": 0,
                "findings": [{"level": "error"}],
                "cves": [{"severity": "critical", "exploited": True}],
            },
        ],
    }
    r = client.post("/api/v1/context-engine/evaluate", json=body)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["org_id"] == "ctx-test"
    assert out["summary"]["components_evaluated"] == 2
    assert len(out["components"]) == 2


def test_evaluate_empty_design_rows_rejected(client):
    r = client.post(
        "/api/v1/context-engine/evaluate",
        json={"org_id": "ctx-test", "settings": {}, "design_rows": []},
    )
    assert r.status_code == 422
