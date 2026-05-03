"""Tests for FIPS Compliance Mode Router (/api/v1/fips)."""
from __future__ import annotations

import importlib
import os

import pytest

# Configure auth BEFORE auth_deps gets imported (same pattern as wave_a tests).
os.environ["FIXOPS_API_TOKEN"] = "fips-test-token"
os.environ.setdefault("FIXOPS_MODE", "dev")

import apps.api.auth_deps as _auth_mod  # noqa: E402
importlib.reload(_auth_mod)

from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture(scope="module")
def client():
    from apps.api.app import create_app
    app = create_app()
    return TestClient(app, headers={"X-API-Key": "fips-test-token"})


def test_get_fips_status_default(client):
    """GET /fips/status returns org_id and fips_mode fields."""
    r = client.get("/api/v1/fips/status?org_id=test-fips-org")
    assert r.status_code == 200, r.text
    data = r.json()
    assert "fips_mode" in data


def test_activate_fips_mode(client):
    """POST /fips/activate sets fips_mode to 1 (idempotent)."""
    r = client.post("/api/v1/fips/activate", json={"org_id": "fips-test-activate"})
    assert r.status_code == 200, r.text
    data = r.json()
    assert int(data.get("fips_mode", 0)) == 1


def test_deactivate_fips_mode(client):
    """POST /fips/deactivate sets fips_mode to 0."""
    client.post("/api/v1/fips/activate", json={"org_id": "fips-test-deactivate"})
    r = client.post("/api/v1/fips/deactivate", json={"org_id": "fips-test-deactivate"})
    assert r.status_code == 200, r.text
    data = r.json()
    assert int(data.get("fips_mode", 1)) == 0


def test_register_pqc_algo_valid(client):
    """POST /fips/pqc/register with valid algo returns inventory row."""
    r = client.post("/api/v1/fips/pqc/register", json={
        "org_id": "fips-pqc-org",
        "service_ref": "auth-service",
        "algo": "ml-dsa-44",
        "category": "signature",
    })
    assert r.status_code == 200, r.text
    data = r.json()
    assert data.get("algo") == "ml-dsa-44"


def test_register_pqc_algo_invalid(client):
    """POST /fips/pqc/register with unknown algo returns 422."""
    r = client.post("/api/v1/fips/pqc/register", json={
        "org_id": "fips-pqc-org",
        "service_ref": "auth-service",
        "algo": "not-a-real-algo-xyz",
        "category": "signature",
    })
    assert r.status_code == 422, r.text


def test_list_pqc_inventory(client):
    """GET /fips/pqc/inventory returns count and inventory list."""
    client.post("/api/v1/fips/pqc/register", json={
        "org_id": "fips-inv-org",
        "service_ref": "svc-a",
        "algo": "ml-kem-768",
        "category": "kem",
    })
    r = client.get("/api/v1/fips/pqc/inventory?org_id=fips-inv-org")
    assert r.status_code == 200, r.text
    data = r.json()
    assert "inventory" in data
    assert data["count"] >= 1


def test_scan_crypto_usage(client):
    """POST /fips/crypto/scan returns scan_id and counts."""
    r = client.post("/api/v1/fips/crypto/scan", json={"org_id": "fips-scan-org"})
    assert r.status_code == 200, r.text
    data = r.json()
    assert "scan_id" in data
    assert "legacy_count" in data


def test_readiness_score(client):
    """GET /fips/readiness returns score 0-100."""
    r = client.get("/api/v1/fips/readiness?org_id=fips-ready-org")
    assert r.status_code == 200, r.text
    data = r.json()
    assert "score" in data
    assert 0 <= data["score"] <= 100


def test_stats(client):
    """GET /fips/stats returns inventory_total and readiness_score."""
    r = client.get("/api/v1/fips/stats?org_id=fips-stats-org")
    assert r.status_code == 200, r.text
    data = r.json()
    assert "inventory_total" in data
    assert "readiness_score" in data
