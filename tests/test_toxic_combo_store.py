"""Tests for ToxicComboStore and the findings_wave_b /toxic-combo-rules endpoints."""
import sys
sys.path.insert(0, "/Users/devops.ai/fixops/Fixops/suite-core")
sys.path.insert(0, "/Users/devops.ai/fixops/Fixops/suite-api")

import pytest
import tempfile
import os

from core.toxic_combo_rules import ToxicComboStore, get_store


# ---------------------------------------------------------------------------
# Unit tests — ToxicComboStore
# ---------------------------------------------------------------------------

@pytest.fixture()
def store(tmp_path):
    return ToxicComboStore(db_path=str(tmp_path / "tcs.db"))


def test_put_returns_record(store):
    r = store.put("org-1", {"name": "test-rule", "predicates": [{"attribute": "foo", "operator": "eq"}]})
    assert r["id"]
    assert r["name"] == "test-rule"
    assert r["org_id"] == "org-1"
    assert r["predicates"] == [{"attribute": "foo", "operator": "eq"}]


def test_list_rules_scoped_to_org(store):
    store.put("org-A", {"name": "rule-A", "predicates": [{"attribute": "x", "operator": "gt"}]})
    store.put("org-B", {"name": "rule-B", "predicates": [{"attribute": "y", "operator": "lt"}]})
    assert len(store.list_rules("org-A")) == 1
    assert len(store.list_rules("org-B")) == 1
    assert store.list_rules("org-C") == []


def test_get_rule_returns_correct_record(store):
    r = store.put("org-1", {"name": "rule-get", "predicates": [{"attribute": "a", "operator": "eq"}]})
    fetched = store.get_rule("org-1", r["id"])
    assert fetched is not None
    assert fetched["id"] == r["id"]


def test_get_rule_wrong_org_returns_none(store):
    r = store.put("org-1", {"name": "rule-x", "predicates": [{"attribute": "a", "operator": "eq"}]})
    assert store.get_rule("org-other", r["id"]) is None


def test_delete_rule_returns_true(store):
    r = store.put("org-1", {"name": "to-delete", "predicates": [{"attribute": "a", "operator": "eq"}]})
    assert store.delete_rule("org-1", r["id"]) is True
    assert store.get_rule("org-1", r["id"]) is None


def test_delete_missing_rule_returns_false(store):
    assert store.delete_rule("org-1", "nonexistent-id") is False


def test_put_missing_name_raises(store):
    with pytest.raises(ValueError, match="name is required"):
        store.put("org-1", {"predicates": [{"attribute": "x", "operator": "eq"}]})


def test_put_invalid_predicate_raises(store):
    with pytest.raises(ValueError, match="predicates\[0\]"):
        store.put("org-1", {"name": "bad", "predicates": [{"attribute": "x"}]})  # missing operator


# ---------------------------------------------------------------------------
# Integration tests — FastAPI router (TestClient)
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def patch_store(tmp_path, monkeypatch):
    """Redirect the singleton store to a temp DB for each test."""
    import core.toxic_combo_rules as tcr
    tcr._store = None  # reset singleton
    monkeypatch.setattr(tcr, "_DEFAULT_STORE_DB", str(tmp_path / "router_tcs.db"))


def _make_client():
    from apps.api.findings_wave_b_router import router
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()

    # Bypass auth for tests
    from apps.api.findings_wave_b_router import router as wave_b_router
    import apps.api.findings_wave_b_router as wbmod

    # Override auth deps
    from fastapi import Request
    async def _noop():
        return None
    app.include_router(wave_b_router)

    # Patch auth + org_id
    from apps.api.auth import api_key_auth
    from apps.api.shared_deps import get_org_id
    app.dependency_overrides[api_key_auth] = lambda: None
    app.dependency_overrides[get_org_id] = lambda: "test-org"

    return TestClient(app)


@pytest.mark.integration
def test_create_toxic_combo_rule_201():
    client = _make_client()
    resp = client.post("/api/v1/toxic-combo-rules", json={
        "name": "router-rule",
        "predicates": [{"attribute": "internet_exposed", "operator": "is_true"}],
        "severity": "critical",
        "description": "test rule",
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "router-rule"
    assert data["id"]


@pytest.mark.integration
def test_list_toxic_combo_rules():
    client = _make_client()
    client.post("/api/v1/toxic-combo-rules", json={
        "name": "list-test",
        "predicates": [{"attribute": "x", "operator": "eq"}],
    })
    resp = client.get("/api/v1/toxic-combo-rules")
    assert resp.status_code == 200
    assert resp.json()["count"] >= 1


@pytest.mark.integration
def test_delete_toxic_combo_rule():
    client = _make_client()
    cr = client.post("/api/v1/toxic-combo-rules", json={
        "name": "delete-me",
        "predicates": [{"attribute": "x", "operator": "eq"}],
    })
    rule_id = cr.json()["id"]
    resp = client.delete(f"/api/v1/toxic-combo-rules/{rule_id}")
    assert resp.status_code == 200
    assert resp.json()["deleted"] is True


@pytest.mark.integration
def test_delete_nonexistent_rule_404():
    client = _make_client()
    resp = client.delete("/api/v1/toxic-combo-rules/no-such-id")
    assert resp.status_code == 404
