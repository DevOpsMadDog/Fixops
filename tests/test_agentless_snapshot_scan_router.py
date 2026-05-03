"""Tests for agentless_snapshot_scan_router — GAP-020.

Uses a minimal FastAPI app to avoid the 10-second create_app timeout.
Sets FIXOPS_API_TOKEN so api_key_auth accepts the test key.
"""
from __future__ import annotations

import os
import pytest

os.environ.setdefault("FIXOPS_API_TOKEN", "test-key")

from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    from apps.api.agentless_snapshot_scan_router import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


HEADERS = {"X-API-Key": "test-key"}
ORG = "test-org-snap"


def test_root_stats_returns_dict(client):
    r = client.get("/api/v1/agentless-snapshot-scan/", params={"org_id": ORG}, headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body, dict)
    assert "total_snapshots" in body


def test_enqueue_scan_returns_list(client):
    """enqueue_scan discovers snapshots via adapter and returns a list of queued rows."""
    r = client.post(
        "/api/v1/agentless-snapshot-scan/snapshots",
        json={"org_id": ORG, "provider": "aws", "account_id": "123456789"},
        headers=HEADERS,
    )
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_list_snapshots(client):
    r = client.get("/api/v1/agentless-snapshot-scan/snapshots", params={"org_id": ORG}, headers=HEADERS)
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_run_scan_and_list_findings(client):
    # Inject MockAWSAdapter so enqueue returns deterministic snapshots without
    # real cloud credentials.
    from core.agentless_snapshot_scan_engine import MockAWSAdapter
    import apps.api.agentless_snapshot_scan_router as _rmod
    _rmod._engine = None  # reset singleton
    engine = _rmod._get_engine()
    engine.set_adapter(MockAWSAdapter())

    # Enqueue to get snapshot DB IDs
    enq = client.post(
        "/api/v1/agentless-snapshot-scan/snapshots",
        json={"org_id": ORG, "provider": "aws", "account_id": "acc-run-test"},
        headers=HEADERS,
    )
    assert enq.status_code == 200
    rows = enq.json()
    assert isinstance(rows, list)
    assert len(rows) > 0, "MockAWSAdapter should return at least one snapshot"
    db_id = rows[0]["id"]

    # Run the scan
    r = client.post(f"/api/v1/agentless-snapshot-scan/snapshots/{db_id}/run", headers=HEADERS)
    assert r.status_code == 200
    result = r.json()
    assert isinstance(result, dict)
    assert "scan_status" in result or "findings_count" in result or "status" in result

    # Findings should now be queryable
    fr = client.get("/api/v1/agentless-snapshot-scan/findings", params={"org_id": ORG}, headers=HEADERS)
    assert fr.status_code == 200
    assert isinstance(fr.json(), list)


def test_stats_endpoint(client):
    r = client.get("/api/v1/agentless-snapshot-scan/stats", params={"org_id": ORG}, headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert "total_snapshots" in body
    assert "total_findings" in body


def test_enqueue_invalid_provider_returns_422(client):
    r = client.post(
        "/api/v1/agentless-snapshot-scan/snapshots",
        json={"org_id": ORG, "provider": "boguscloud", "account_id": "x"},
        headers=HEADERS,
    )
    assert r.status_code == 422
