"""Tests for GET /api/v1/secrets-management/audit — org-wide vault audit log.

Covers:
  - Empty audit log returns empty list (200)
  - Access events appear in org-wide log after record_access calls
  - Filter by accessor identity
  - Filter by action type
  - Cross-secret aggregation (events from multiple secrets appear)
  - limit parameter respected
"""
from __future__ import annotations

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))

from fastapi import FastAPI
from fastapi.testclient import TestClient

from apps.api.secrets_management_router import router, _get_engine
from core.secrets_management_engine import SecretsManagementEngine

ORG = "test-vault-audit-org"
OTHER_ORG = "other-org-vault-audit"


@pytest.fixture(scope="module")
def engine(tmp_path_factory):
    db = str(tmp_path_factory.mktemp("vault_audit") / "secrets_mgmt.db")
    return SecretsManagementEngine(db_path=db)


@pytest.fixture(scope="module")
def client(engine):
    import apps.api.secrets_management_router as sm_mod
    original = sm_mod._engine
    sm_mod._engine = engine

    app = FastAPI()
    app.include_router(router)

    with TestClient(app, raise_server_exceptions=True) as c:
        yield c

    sm_mod._engine = original


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _store(engine: SecretsManagementEngine, name: str = "my-key") -> str:
    rec = engine.store_secret(ORG, {"name": name, "secret_type": "api_key"})
    return rec["id"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_audit_empty_returns_list(client):
    """GET /audit on a fresh org returns 200 with an empty list."""
    resp = client.get("/api/v1/secrets-management/audit", params={"org_id": "brand-new-org"})
    assert resp.status_code == 200
    assert resp.json() == []


def test_audit_records_appear_after_access(client, engine):
    """Access events recorded via record_access appear in the org-wide audit log."""
    sid = _store(engine, "audit-secret-1")
    engine.record_access(ORG, sid, accessor="alice", action="read")
    engine.record_access(ORG, sid, accessor="bob", action="rotate")

    resp = client.get("/api/v1/secrets-management/audit", params={"org_id": ORG})
    assert resp.status_code == 200
    entries = resp.json()
    assert len(entries) >= 2
    accessors = {e["accessor"] for e in entries}
    assert "alice" in accessors
    assert "bob" in accessors


def test_audit_filter_by_accessor(client, engine):
    """Filter by accessor returns only that actor's entries."""
    sid = _store(engine, "audit-secret-accessor")
    engine.record_access(ORG, sid, accessor="carol", action="read")
    engine.record_access(ORG, sid, accessor="dave", action="write")

    resp = client.get(
        "/api/v1/secrets-management/audit",
        params={"org_id": ORG, "accessor": "carol"},
    )
    assert resp.status_code == 200
    entries = resp.json()
    assert all(e["accessor"] == "carol" for e in entries)
    accessors = {e["accessor"] for e in entries}
    assert "dave" not in accessors


def test_audit_filter_by_action(client, engine):
    """Filter by action returns only entries matching that action."""
    sid = _store(engine, "audit-secret-action")
    engine.record_access(ORG, sid, accessor="eve", action="delete")
    engine.record_access(ORG, sid, accessor="eve", action="read")

    resp = client.get(
        "/api/v1/secrets-management/audit",
        params={"org_id": ORG, "action": "delete"},
    )
    assert resp.status_code == 200
    entries = resp.json()
    assert all(e["action"] == "delete" for e in entries)


def test_audit_cross_secret_aggregation(client, engine):
    """Org-wide audit log aggregates events from multiple secrets."""
    sid_a = _store(engine, "multi-secret-A")
    sid_b = _store(engine, "multi-secret-B")
    engine.record_access(ORG, sid_a, accessor="svc-a", action="read")
    engine.record_access(ORG, sid_b, accessor="svc-b", action="read")

    resp = client.get("/api/v1/secrets-management/audit", params={"org_id": ORG})
    assert resp.status_code == 200
    secret_ids = {e["secret_id"] for e in resp.json()}
    assert sid_a in secret_ids
    assert sid_b in secret_ids


def test_audit_limit_respected(client, engine):
    """limit query param caps the number of entries returned."""
    sid = _store(engine, "limit-test-secret")
    for i in range(10):
        engine.record_access(ORG, sid, accessor=f"user-{i}", action="read")

    resp = client.get(
        "/api/v1/secrets-management/audit",
        params={"org_id": ORG, "limit": 3},
    )
    assert resp.status_code == 200
    assert len(resp.json()) <= 3


def test_audit_org_isolation(client, engine):
    """Audit log is isolated per org — other org's events do not appear."""
    sid = engine.store_secret(OTHER_ORG, {"name": "other-secret", "secret_type": "token"})["id"]
    engine.record_access(OTHER_ORG, sid, accessor="intruder", action="read")

    resp = client.get("/api/v1/secrets-management/audit", params={"org_id": ORG})
    assert resp.status_code == 200
    accessors = {e["accessor"] for e in resp.json()}
    assert "intruder" not in accessors
