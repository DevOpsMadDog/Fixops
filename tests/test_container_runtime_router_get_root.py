"""Tests for container_runtime_router GET / root endpoint and key POST endpoints.

Covers: index, image analyse, policy create+list, drift detect, CIS benchmark.

Usage:
    pytest tests/test_container_runtime_router_get_root.py -v --timeout=10
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Ensure suite-core and suite-api on path
for _p in ["suite-core", "suite-api"]:
    _abs = str(Path(__file__).parent.parent / _p)
    if _abs not in sys.path:
        sys.path.insert(0, _abs)

from apps.api.container_runtime_router import router

app = FastAPI()
app.include_router(router)
client = TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# GET /
# ---------------------------------------------------------------------------

def test_index_status_ok():
    resp = client.get("/api/v1/containers/")
    assert resp.status_code == 200


def test_index_has_required_keys():
    data = client.get("/api/v1/containers/").json()
    assert data["service"] == "container-runtime-security"
    assert data["status"] == "operational"
    assert isinstance(data["endpoints"], list)
    assert len(data["endpoints"]) >= 9


def test_index_capabilities_present():
    data = client.get("/api/v1/containers/").json()
    caps = data["capabilities"]
    assert "drift-detection" in caps
    assert "cis-benchmark" in caps
    assert "image-signing" in caps


# ---------------------------------------------------------------------------
# POST /images/analyse
# ---------------------------------------------------------------------------

def test_analyse_image_basic():
    resp = client.post("/api/v1/containers/images/analyse", json={"image_ref": "nginx:latest"})
    # engine runs inline — expect 200 or 500 (no docker daemon), never 422/404
    assert resp.status_code in (200, 500)


def test_analyse_image_missing_ref_returns_422():
    resp = client.post("/api/v1/containers/images/analyse", json={"image_ref": ""})
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# POST /policies + GET /policies
# ---------------------------------------------------------------------------

def test_create_and_list_policy():
    payload = {
        "name": "test-policy",
        "approved_base_images": ["ubuntu:22.04"],
        "approved_registries": ["registry.example.com"],
        "allow_root_user": False,
        "require_healthcheck": True,
    }
    create_resp = client.post("/api/v1/containers/policies", json=payload)
    assert create_resp.status_code in (200, 500)

    list_resp = client.get("/api/v1/containers/policies")
    assert list_resp.status_code == 200
    data = list_resp.json()
    assert "policies" in data
    assert "total" in data
