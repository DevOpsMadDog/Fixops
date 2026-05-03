"""Tests for CSPM finding-suppression allowlist endpoints.

Covers:
  POST   /api/v1/cspm/allowlist        — create entry
  GET    /api/v1/cspm/allowlist        — list entries (with org_id + rule_id filters)
  DELETE /api/v1/cspm/allowlist/{id}   — delete entry / 404 guard
"""
from __future__ import annotations

import sys
import os

import pytest

# Ensure suite paths are importable without sitecustomize
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in ("suite-api", "suite-core"):
    _abs = os.path.join(_ROOT, _p)
    if _abs not in sys.path:
        sys.path.insert(0, _abs)

from fastapi.testclient import TestClient
from fastapi import FastAPI

from apps.api.cspm_router import router


@pytest.fixture(autouse=True)
def _clear_allowlist():
    """Reset the in-process allowlist store before every test."""
    import core.cspm_engine as _mod
    # The store lives as a module-level list inside the except block shim
    try:
        _mod._ALLOWLIST_STORE.clear()
    except AttributeError:
        pass
    yield
    try:
        _mod._ALLOWLIST_STORE.clear()
    except AttributeError:
        pass


@pytest.fixture()
def client():
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# POST /allowlist — create
# ---------------------------------------------------------------------------

def test_create_allowlist_entry_returns_201(client):
    resp = client.post(
        "/api/v1/cspm/allowlist",
        json={
            "rule_id": "CSPM-AWS-001",
            "reason": "Public bucket approved by security team",
            "created_by": "alice",
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["rule_id"] == "CSPM-AWS-001"
    assert body["reason"] == "Public bucket approved by security team"
    assert body["id"].startswith("allow-")
    assert body["resource_id"] is None        # org-wide suppression
    assert body["expires_at"] is None         # permanent


def test_create_allowlist_with_resource_and_expiry(client):
    resp = client.post(
        "/api/v1/cspm/allowlist",
        json={
            "rule_id": "CSPM-AWS-101",
            "resource_id": "res-abc123",
            "reason": "Temporary exception during migration",
            "expires_at": "2026-12-31T00:00:00Z",
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["resource_id"] == "res-abc123"
    assert body["expires_at"] == "2026-12-31T00:00:00Z"


# ---------------------------------------------------------------------------
# GET /allowlist — list + filters
# ---------------------------------------------------------------------------

def test_list_allowlist_returns_created_entries(client):
    client.post(
        "/api/v1/cspm/allowlist",
        json={"rule_id": "CSPM-AWS-001", "reason": "r1"},
    )
    client.post(
        "/api/v1/cspm/allowlist",
        json={"rule_id": "CSPM-AWS-002", "reason": "r2"},
    )
    resp = client.get("/api/v1/cspm/allowlist", params={"org_id": "default"})
    assert resp.status_code == 200
    entries = resp.json()
    rule_ids = {e["rule_id"] for e in entries}
    assert "CSPM-AWS-001" in rule_ids
    assert "CSPM-AWS-002" in rule_ids


def test_list_allowlist_filter_by_rule_id(client):
    client.post(
        "/api/v1/cspm/allowlist",
        json={"rule_id": "CSPM-AWS-001", "reason": "r1"},
    )
    client.post(
        "/api/v1/cspm/allowlist",
        json={"rule_id": "CSPM-GCP-005", "reason": "r2"},
    )
    resp = client.get(
        "/api/v1/cspm/allowlist",
        params={"org_id": "default", "rule_id": "CSPM-GCP-005"},
    )
    assert resp.status_code == 200
    entries = resp.json()
    assert len(entries) == 1
    assert entries[0]["rule_id"] == "CSPM-GCP-005"


# ---------------------------------------------------------------------------
# DELETE /allowlist/{id}
# ---------------------------------------------------------------------------

def test_delete_allowlist_entry(client):
    create_resp = client.post(
        "/api/v1/cspm/allowlist",
        json={"rule_id": "CSPM-AWS-003", "reason": "to be deleted"},
    )
    entry_id = create_resp.json()["id"]

    del_resp = client.delete(f"/api/v1/cspm/allowlist/{entry_id}")
    assert del_resp.status_code == 200
    assert del_resp.json()["deleted"] is True
    assert del_resp.json()["entry_id"] == entry_id

    # Verify it no longer appears in the list
    list_resp = client.get("/api/v1/cspm/allowlist")
    ids = [e["id"] for e in list_resp.json()]
    assert entry_id not in ids


def test_delete_nonexistent_allowlist_entry_returns_404(client):
    resp = client.delete("/api/v1/cspm/allowlist/allow-doesnotexist")
    assert resp.status_code == 404
