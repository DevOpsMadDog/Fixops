"""Tests for container_runtime_router GET / root endpoint — Multica #4085.

Wires the previously hardcoded stub to the real ContainerRuntimeSecurityEngine,
returning live policy_count + engine_available flag.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    from apps.api.container_runtime_router import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_container_runtime_index_returns_200(client):
    resp = client.get("/api/v1/containers/")
    assert resp.status_code == 200, resp.text


def test_container_runtime_index_has_engine_flag(client):
    data = client.get("/api/v1/containers/").json()
    assert "engine_available" in data
    assert isinstance(data["engine_available"], bool)


def test_container_runtime_index_has_live_policy_count(client):
    data = client.get("/api/v1/containers/").json()
    assert "policies_configured" in data
    assert isinstance(data["policies_configured"], int)


def test_container_runtime_index_has_capabilities(client):
    data = client.get("/api/v1/containers/").json()
    assert "capabilities" in data
    assert "image-analysis" in data["capabilities"]
    assert "runtime-policy" in data["capabilities"]


def test_container_runtime_index_status_operational(client):
    data = client.get("/api/v1/containers/").json()
    assert data["status"] == "operational"
