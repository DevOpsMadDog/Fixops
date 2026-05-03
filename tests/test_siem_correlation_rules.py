"""Tests for SIEM correlation-rules CRUD + run — engine and router.

Covers:
  Engine: create, list, get, delete, run, run-disabled, run-missing
  Router: POST /correlation-rules, GET list, GET single, DELETE, POST run

Total: 12 tests.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI

from core.siem_integration_engine import SIEMIntegrationEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine(tmp_path):
    return SIEMIntegrationEngine(db_path=str(tmp_path / "test_corr_rules.db"))


@pytest.fixture()
def app(tmp_path):
    """Minimal FastAPI app with the SIEM router wired to an isolated engine."""
    from apps.api.siem_integration_router import router, _get_engine
    import apps.api.siem_integration_router as _mod

    # Override singleton with tmp-path engine
    _mod._engine = SIEMIntegrationEngine(db_path=str(tmp_path / "router_corr.db"))
    fa = FastAPI()
    fa.include_router(router)
    return fa


@pytest.fixture()
def client(app):
    return TestClient(app)


# ---------------------------------------------------------------------------
# Engine tests
# ---------------------------------------------------------------------------


def test_create_correlation_rule(engine):
    rule = engine.create_correlation_rule("org1", {
        "name": "Brute Force Detect",
        "description": "Detect repeated auth failures",
        "event_type": "auth",
        "severity": "high",
        "field": "source_ip",
        "threshold": 3,
        "window_hours": 1,
        "action": "brute_force",
    })
    assert rule["rule_id"]
    assert rule["name"] == "Brute Force Detect"
    assert rule["threshold"] == 3
    assert rule["enabled"] is True


def test_list_correlation_rules(engine):
    engine.create_correlation_rule("org1", {"name": "Rule A", "threshold": 5})
    engine.create_correlation_rule("org1", {"name": "Rule B", "threshold": 10, "enabled": False})
    engine.create_correlation_rule("org2", {"name": "Rule C", "threshold": 2})

    all_rules = engine.list_correlation_rules("org1")
    assert len(all_rules) == 2

    enabled = engine.list_correlation_rules("org1", enabled_only=True)
    assert len(enabled) == 1
    assert enabled[0]["name"] == "Rule A"


def test_get_correlation_rule(engine):
    rule = engine.create_correlation_rule("org1", {"name": "Test Rule"})
    fetched = engine.get_correlation_rule("org1", rule["rule_id"])
    assert fetched is not None
    assert fetched["rule_id"] == rule["rule_id"]

    # Wrong org returns None
    assert engine.get_correlation_rule("other_org", rule["rule_id"]) is None


def test_delete_correlation_rule(engine):
    rule = engine.create_correlation_rule("org1", {"name": "To Delete"})
    assert engine.delete_correlation_rule("org1", rule["rule_id"]) is True
    # Already deleted
    assert engine.delete_correlation_rule("org1", rule["rule_id"]) is False
    assert engine.get_correlation_rule("org1", rule["rule_id"]) is None


def test_run_correlation_rule_no_matches(engine):
    rule = engine.create_correlation_rule("org1", {
        "name": "Auth Spike",
        "event_type": "auth",
        "field": "source_ip",
        "threshold": 5,
        "window_hours": 1,
    })
    result = engine.run_correlation_rule("org1", rule["rule_id"])
    assert result["rule_id"] == rule["rule_id"]
    assert result["rule_name"] == "Auth Spike"
    assert result["matched_groups"] == 0
    assert isinstance(result["matches"], list)


def test_run_correlation_rule_with_matches(engine):
    """Insert 6 auth events from same IP, expect 1 matched group."""
    siem = engine.register_siem("org1", {"siem_name": "test", "siem_type": "generic"})
    for _ in range(6):
        engine.ingest_event("org1", {
            "siem_id": siem["siem_id"],
            "event_type": "auth",
            "severity": "high",
            "source_ip": "10.0.0.1",
            "user": "bob",
        })

    rule = engine.create_correlation_rule("org1", {
        "name": "IP Spike",
        "event_type": "auth",
        "field": "source_ip",
        "threshold": 5,
        "window_hours": 24,
    })
    result = engine.run_correlation_rule("org1", rule["rule_id"])
    assert result["matched_groups"] == 1
    assert result["matches"][0]["group_key"] == "10.0.0.1"
    assert result["matches"][0]["event_count"] == 6


def test_run_disabled_rule_raises(engine):
    rule = engine.create_correlation_rule("org1", {"name": "Disabled", "enabled": False})
    with pytest.raises(ValueError, match="disabled"):
        engine.run_correlation_rule("org1", rule["rule_id"])


def test_run_missing_rule_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.run_correlation_rule("org1", "nonexistent-rule-id")


# ---------------------------------------------------------------------------
# Router tests
# ---------------------------------------------------------------------------


def test_router_create_and_list(client):
    resp = client.post("/api/v1/siem/correlation-rules", json={
        "org_id": "org1",
        "name": "Router Rule",
        "threshold": 7,
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "created"
    assert body["rule"]["name"] == "Router Rule"

    list_resp = client.get("/api/v1/siem/correlation-rules?org_id=org1")
    assert list_resp.status_code == 200
    assert list_resp.json()["total"] == 1


def test_router_get_single(client):
    create = client.post("/api/v1/siem/correlation-rules", json={
        "org_id": "org1", "name": "Single Rule"
    })
    rule_id = create.json()["rule"]["rule_id"]

    resp = client.get(f"/api/v1/siem/correlation-rules/{rule_id}?org_id=org1")
    assert resp.status_code == 200
    assert resp.json()["rule_id"] == rule_id

    not_found = client.get("/api/v1/siem/correlation-rules/bad-id?org_id=org1")
    assert not_found.status_code == 404


def test_router_delete(client):
    create = client.post("/api/v1/siem/correlation-rules", json={
        "org_id": "org1", "name": "Del Rule"
    })
    rule_id = create.json()["rule"]["rule_id"]

    del_resp = client.delete(f"/api/v1/siem/correlation-rules/{rule_id}?org_id=org1")
    assert del_resp.status_code == 200
    assert del_resp.json()["status"] == "deleted"

    again = client.delete(f"/api/v1/siem/correlation-rules/{rule_id}?org_id=org1")
    assert again.status_code == 404


def test_router_run(client):
    create = client.post("/api/v1/siem/correlation-rules", json={
        "org_id": "org1",
        "name": "Run Rule",
        "threshold": 2,
        "window_hours": 24,
    })
    rule_id = create.json()["rule"]["rule_id"]

    run_resp = client.post(f"/api/v1/siem/correlation-rules/{rule_id}/run?org_id=org1")
    assert run_resp.status_code == 200
    body = run_resp.json()
    assert body["status"] == "ok"
    assert body["rule_id"] == rule_id
    assert "matched_groups" in body
