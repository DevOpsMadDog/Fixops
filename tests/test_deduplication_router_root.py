"""Tests for GET / root endpoint on deduplication_router.

Covers:
  (a) 200 response with expected keys
  (b) org_id param is reflected in response
  (c) returns numeric cluster/event counts
  (d) status_breakdown and severity_breakdown are dicts
  (e) findings_in_system and open_findings are ints
  (f) engine field is 'deduplication'
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from apps.api.deduplication_router import router as dedup_router
import apps.api.deduplication_router as dedup_module


@pytest.fixture()
def isolated_service(tmp_path, monkeypatch):
    """Per-test DeduplicationService pointed at a fresh tmp DB."""
    from core.services.deduplication import DeduplicationService

    db_path = tmp_path / "dedup_root_test.db"
    fresh = DeduplicationService(db_path)
    monkeypatch.setattr(dedup_module, "_dedup_service", fresh)
    # Patch analytics helper to avoid filesystem dependency
    monkeypatch.setattr(
        dedup_module,
        "_get_analytics_findings_count",
        lambda: {"total_findings": 42, "open_findings": 7},
    )
    return fresh


@pytest.fixture()
def client(isolated_service):
    """FastAPI test client with no auth (dedup router has no auth dep)."""
    app = FastAPI()
    app.include_router(dedup_router)
    return TestClient(app)


# ---------------------------------------------------------------------------
# (a) 200 with expected keys
# ---------------------------------------------------------------------------

def test_root_returns_200(client):
    resp = client.get("/api/v1/deduplication/", params={"org_id": "org1"})
    assert resp.status_code == 200, resp.text


def test_root_has_required_keys(client):
    resp = client.get("/api/v1/deduplication/", params={"org_id": "org1"})
    body = resp.json()
    for key in (
        "org_id", "engine", "total_clusters", "total_events",
        "noise_reduction_percent", "status_breakdown", "severity_breakdown",
        "findings_in_system", "open_findings",
    ):
        assert key in body, f"missing key: {key}"


# ---------------------------------------------------------------------------
# (b) org_id reflected
# ---------------------------------------------------------------------------

def test_root_reflects_org_id(client):
    resp = client.get("/api/v1/deduplication/", params={"org_id": "acme-corp"})
    assert resp.json()["org_id"] == "acme-corp"


def test_root_default_org_id(client):
    resp = client.get("/api/v1/deduplication/")
    assert resp.json()["org_id"] == "default"


# ---------------------------------------------------------------------------
# (c) numeric cluster/event counts
# ---------------------------------------------------------------------------

def test_root_cluster_and_event_counts_are_ints(client):
    resp = client.get("/api/v1/deduplication/", params={"org_id": "org1"})
    body = resp.json()
    assert isinstance(body["total_clusters"], int)
    assert isinstance(body["total_events"], int)
    assert body["total_clusters"] >= 0
    assert body["total_events"] >= 0


# ---------------------------------------------------------------------------
# (d) status_breakdown and severity_breakdown are dicts
# ---------------------------------------------------------------------------

def test_root_breakdowns_are_dicts(client):
    resp = client.get("/api/v1/deduplication/", params={"org_id": "org1"})
    body = resp.json()
    assert isinstance(body["status_breakdown"], dict)
    assert isinstance(body["severity_breakdown"], dict)


# ---------------------------------------------------------------------------
# (e) findings counts from analytics helper
# ---------------------------------------------------------------------------

def test_root_findings_counts_from_helper(client):
    resp = client.get("/api/v1/deduplication/", params={"org_id": "org1"})
    body = resp.json()
    assert body["findings_in_system"] == 42
    assert body["open_findings"] == 7


# ---------------------------------------------------------------------------
# (f) engine field
# ---------------------------------------------------------------------------

def test_root_engine_field(client):
    resp = client.get("/api/v1/deduplication/", params={"org_id": "org1"})
    assert resp.json()["engine"] == "deduplication"
