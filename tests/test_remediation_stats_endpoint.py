"""HTTP-level tests for GET /api/v1/remediation/stats and /queue.

Wires the remediation router via TestClient (no full create_app cost).
Covers the 5-state envelope: shape, keys, defaults, org isolation, queue.
"""
from __future__ import annotations

import os

os.environ["FIXOPS_MODE"] = "enterprise"
os.environ["FIXOPS_API_TOKEN"] = "test-key"
os.environ["FIXOPS_JWT_SECRET"] = "test-secret-that-is-at-least-32chars!"
os.environ["FIXOPS_DISABLE_TELEMETRY"] = "1"
os.environ["FIXOPS_DISABLE_RATE_LIMIT"] = "1"

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    """Mount only the remediation router to avoid full create_app() cost."""
    from apps.api.remediation_router import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


AUTH = {"X-API-Key": "test-key"}
ORG = "test-remediation-stats"


# ---------------------------------------------------------------------------
# GET /api/v1/remediation/stats
# ---------------------------------------------------------------------------

def test_stats_returns_200(client):
    """Stats endpoint returns HTTP 200 for a fresh org."""
    resp = client.get(
        "/api/v1/remediation/stats",
        params={"org_id": ORG},
        headers=AUTH,
    )
    assert resp.status_code == 200, resp.text


def test_stats_envelope_keys(client):
    """Response contains all required top-level envelope keys."""
    resp = client.get(
        "/api/v1/remediation/stats",
        params={"org_id": ORG},
        headers=AUTH,
    )
    data = resp.json()
    assert data["status"] == "ok"
    assert "total" in data
    assert "by_severity" in data
    assert "by_status" in data
    assert "by_assignee" in data


def test_stats_by_severity_keys(client):
    """by_severity contains the four canonical severity buckets."""
    resp = client.get(
        "/api/v1/remediation/stats",
        params={"org_id": ORG},
        headers=AUTH,
    )
    sev = resp.json()["by_severity"]
    for key in ("critical", "high", "medium", "low"):
        assert key in sev, f"missing severity bucket: {key}"
        assert isinstance(sev[key], int)


def test_stats_by_status_keys(client):
    """by_status contains the four canonical status buckets."""
    resp = client.get(
        "/api/v1/remediation/stats",
        params={"org_id": ORG},
        headers=AUTH,
    )
    st = resp.json()["by_status"]
    for key in ("open", "in_progress", "resolved", "closed"):
        assert key in st, f"missing status bucket: {key}"
        assert isinstance(st[key], int)


def test_stats_total_zero_for_fresh_org(client):
    """A brand-new org should have zero tasks (no seed data)."""
    resp = client.get(
        "/api/v1/remediation/stats",
        params={"org_id": "fresh-org-" + ORG},
        headers=AUTH,
    )
    data = resp.json()
    assert data["total"] == 0


# ---------------------------------------------------------------------------
# GET /api/v1/remediation/queue
# ---------------------------------------------------------------------------

def test_queue_returns_200(client):
    """Queue endpoint returns HTTP 200."""
    resp = client.get(
        "/api/v1/remediation/queue",
        params={"org_id": ORG},
        headers=AUTH,
    )
    assert resp.status_code == 200, resp.text


def test_queue_envelope_keys(client):
    """Queue response contains status, queue list, and total count."""
    resp = client.get(
        "/api/v1/remediation/queue",
        params={"org_id": ORG},
        headers=AUTH,
    )
    data = resp.json()
    assert data["status"] == "ok"
    assert "queue" in data
    assert isinstance(data["queue"], list)
    assert "total" in data
    assert isinstance(data["total"], int)
