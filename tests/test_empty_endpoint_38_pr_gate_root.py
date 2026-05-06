"""Tests for pr_gate_router GET / root endpoint — Multica #4070."""
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _make_client():
    from apps.api.pr_gate_router import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_pr_gate_root_returns_200():
    client = _make_client()
    resp = client.get("/api/v1/pr-gate/")
    assert resp.status_code == 200, resp.text


def test_pr_gate_root_has_policy_and_evaluations():
    client = _make_client()
    resp = client.get("/api/v1/pr-gate/")
    data = resp.json()
    assert "policy" in data
    assert "evaluations" in data
    assert data["router"] == "pr-gate"
    assert "total" in data["evaluations"]
