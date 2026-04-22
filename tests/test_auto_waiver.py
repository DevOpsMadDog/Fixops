"""Tests for GAP-006 auto-waiver rules (vuln_exception_engine + workflow + risk_acceptance).

Covers:
- rule registration UNIQUE(org_id, rule_key) upsert
- condition match logic (reachable, severity_max, cve_age, kev)
- disabled rules skipped
- deterministic rule order (created_at ASC)
- max_active_count cap
- workflow engine integration
- risk acceptance link_auto_waiver
- org_id isolation
- endpoint smoke tests
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Engine-level fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    from core.vuln_exception_engine import VulnExceptionEngine
    db = tmp_path / "ve.db"
    return VulnExceptionEngine(db_path=str(db))


@pytest.fixture
def workflow_engine(tmp_path):
    from core.security_exception_workflow_engine import SecurityExceptionWorkflowEngine
    db = tmp_path / "workflow.db"
    return SecurityExceptionWorkflowEngine(db_path=str(db))


@pytest.fixture
def ra_engine(tmp_path):
    from core.risk_acceptance_engine import RiskAcceptanceEngine
    db = tmp_path / "ra.db"
    return RiskAcceptanceEngine(db_path=str(db))


# ---------------------------------------------------------------------------
# Rule registration
# ---------------------------------------------------------------------------

def test_register_rule_persists(engine):
    r = engine.register_auto_waiver_rule(
        org_id="org1", rule_key="low-unreachable",
        conditions={"reachable": False, "severity_max": "low"},
        max_active_count=50, approvers=["alice"], expires_days=30,
    )
    assert r["rule_key"] == "low-unreachable"
    assert r["enabled"] is True
    assert r["conditions"]["severity_max"] == "low"


def test_register_rule_unique_upsert(engine):
    engine.register_auto_waiver_rule(
        "org1", "k1", {"kev": False}, max_active_count=10, expires_days=30
    )
    # Same rule_key upserts — no duplicate, updated values
    engine.register_auto_waiver_rule(
        "org1", "k1", {"kev": True}, max_active_count=99, expires_days=60
    )
    rules = engine.list_auto_waiver_rules("org1")
    assert len(rules) == 1
    assert rules[0]["max_active_count"] == 99
    assert rules[0]["expires_days"] == 60
    assert rules[0]["conditions"]["kev"] is True


def test_register_rule_requires_rule_key(engine):
    with pytest.raises(ValueError):
        engine.register_auto_waiver_rule("org1", "", {}, 10, [], 30)


def test_register_rule_rejects_negative_expires(engine):
    with pytest.raises(ValueError):
        engine.register_auto_waiver_rule("org1", "bad", {}, 10, [], -1)


def test_register_rule_rejects_bad_conditions(engine):
    with pytest.raises(ValueError):
        engine.register_auto_waiver_rule("org1", "k", "not-a-dict", 10, [], 30)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# list_auto_waiver_rules
# ---------------------------------------------------------------------------

def test_list_rules_filter_enabled(engine):
    engine.register_auto_waiver_rule("org1", "a", {}, 10, [], 30)
    engine.register_auto_waiver_rule("org1", "b", {}, 10, [], 30)
    engine.delete_auto_waiver_rule("org1", "b")
    enabled = engine.list_auto_waiver_rules("org1", enabled=True)
    assert len(enabled) == 1
    assert enabled[0]["rule_key"] == "a"


def test_list_rules_org_isolation(engine):
    engine.register_auto_waiver_rule("org1", "r1", {}, 10, [], 30)
    engine.register_auto_waiver_rule("org2", "r2", {}, 10, [], 30)
    assert len(engine.list_auto_waiver_rules("org1")) == 1
    assert engine.list_auto_waiver_rules("org1")[0]["rule_key"] == "r1"
    assert len(engine.list_auto_waiver_rules("org2")) == 1


# ---------------------------------------------------------------------------
# Condition matching
# ---------------------------------------------------------------------------

def test_apply_matches_reachable_false(engine):
    engine.register_auto_waiver_rule(
        "org1", "unreach", {"reachable": False}, 10, [], 30
    )
    res = engine.apply_auto_waivers("org1", {
        "cve_id": "CVE-1", "asset_id": "a1", "reachable": False, "severity": "low",
    })
    assert res is not None
    assert res["reason"] == "auto-waiver:unreach"


def test_apply_skips_when_reachable_mismatch(engine):
    engine.register_auto_waiver_rule(
        "org1", "unreach", {"reachable": False}, 10, [], 30
    )
    res = engine.apply_auto_waivers("org1", {
        "cve_id": "CVE-1", "asset_id": "a1", "reachable": True,
    })
    assert res is None


def test_apply_respects_severity_max(engine):
    engine.register_auto_waiver_rule(
        "org1", "low-only", {"severity_max": "medium"}, 10, [], 30
    )
    # critical is above medium — should NOT match
    res = engine.apply_auto_waivers("org1", {
        "cve_id": "CVE-X", "asset_id": "a", "severity": "critical",
    })
    assert res is None
    # low is below medium — should match
    res2 = engine.apply_auto_waivers("org1", {
        "cve_id": "CVE-Y", "asset_id": "a", "severity": "low",
    })
    assert res2 is not None


def test_apply_matches_cve_age(engine):
    engine.register_auto_waiver_rule(
        "org1", "old-cve", {"cve_age_days_min": 90}, 10, [], 30
    )
    res = engine.apply_auto_waivers("org1", {
        "cve_id": "CVE-OLD", "asset_id": "a", "cve_age_days": 100,
    })
    assert res is not None
    res2 = engine.apply_auto_waivers("org1", {
        "cve_id": "CVE-NEW", "asset_id": "a", "cve_age_days": 30,
    })
    assert res2 is None


def test_apply_respects_kev_flag(engine):
    engine.register_auto_waiver_rule(
        "org1", "non-kev", {"kev": False}, 10, [], 30
    )
    # KEV=True finding must NOT match rule requiring kev=False
    res = engine.apply_auto_waivers("org1", {
        "cve_id": "CVE-KEV", "asset_id": "a", "kev": True,
    })
    assert res is None


def test_apply_missing_field_fails_closed(engine):
    # Rule asserts reachable=False but finding lacks the field → no match
    engine.register_auto_waiver_rule(
        "org1", "r", {"reachable": False}, 10, [], 30
    )
    res = engine.apply_auto_waivers("org1", {"cve_id": "CVE-1", "asset_id": "a"})
    assert res is None


def test_apply_compound_conditions(engine):
    engine.register_auto_waiver_rule(
        "org1", "compound",
        {"reachable": False, "severity_max": "medium", "cve_age_days_min": 90, "kev": False},
        10, [], 30,
    )
    # All pass
    res = engine.apply_auto_waivers("org1", {
        "cve_id": "CVE-1", "asset_id": "a",
        "reachable": False, "severity": "low", "cve_age_days": 180, "kev": False,
    })
    assert res is not None


# ---------------------------------------------------------------------------
# Rule ordering + disabled skipped
# ---------------------------------------------------------------------------

def test_disabled_rule_skipped(engine):
    engine.register_auto_waiver_rule("org1", "r1", {"severity_max": "critical"}, 10, [], 30)
    engine.delete_auto_waiver_rule("org1", "r1")  # disabled/deleted
    res = engine.apply_auto_waivers("org1", {
        "cve_id": "C", "asset_id": "a", "severity": "low",
    })
    assert res is None


def test_deterministic_rule_order(engine):
    # Register rule 'a' first; second rule 'b' would also match, but rule_key
    # of returned exception should be 'a' (created_at ASC).
    engine.register_auto_waiver_rule("org1", "a", {"severity_max": "critical"}, 10, [], 30)
    engine.register_auto_waiver_rule("org1", "b", {"severity_max": "critical"}, 10, [], 30)
    res = engine.apply_auto_waivers("org1", {"cve_id": "C", "asset_id": "a", "severity": "low"})
    assert res is not None
    assert "auto-waiver:a" == res["reason"]


# ---------------------------------------------------------------------------
# Max active count cap
# ---------------------------------------------------------------------------

def test_max_active_count_enforced(engine):
    engine.register_auto_waiver_rule("org1", "cap", {"severity_max": "critical"}, max_active_count=2, expires_days=30)
    r1 = engine.apply_auto_waivers("org1", {"cve_id": "C1", "asset_id": "a", "severity": "low"})
    r2 = engine.apply_auto_waivers("org1", {"cve_id": "C2", "asset_id": "a", "severity": "low"})
    r3 = engine.apply_auto_waivers("org1", {"cve_id": "C3", "asset_id": "a", "severity": "low"})
    assert r1 is not None and r2 is not None
    assert r3 is None  # blocked by cap


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def test_auto_waiver_stats(engine):
    engine.register_auto_waiver_rule("org1", "r1", {"severity_max": "critical"}, 10, [], 30)
    engine.apply_auto_waivers("org1", {"cve_id": "C1", "asset_id": "a", "severity": "low"})
    engine.apply_auto_waivers("org1", {"cve_id": "C2", "asset_id": "a", "severity": "low"})
    stats = engine.auto_waiver_stats("org1")
    assert stats["total_rules"] == 1
    assert stats["enabled_rules"] == 1
    assert stats["auto_waived_findings"] == 2
    assert stats["pending_approval"] == 2


def test_stats_empty_org(engine):
    stats = engine.auto_waiver_stats("empty-org")
    assert stats["total_rules"] == 0
    assert stats["auto_waived_findings"] == 0


# ---------------------------------------------------------------------------
# Delete rule
# ---------------------------------------------------------------------------

def test_delete_rule(engine):
    engine.register_auto_waiver_rule("org1", "doomed", {}, 10, [], 30)
    res = engine.delete_auto_waiver_rule("org1", "doomed")
    assert res["deleted"] == 1
    assert engine.list_auto_waiver_rules("org1") == []


# ---------------------------------------------------------------------------
# Exception workflow integration
# ---------------------------------------------------------------------------

def test_workflow_record_auto_waiver(workflow_engine):
    rec = workflow_engine.record_auto_waiver(
        org_id="org1",
        finding_id="f123",
        rule_key="low-unreachable",
        approvers=["alice", "bob"],
        expires_at="2026-12-31T00:00:00+00:00",
    )
    assert rec["status"] == "pending"
    assert rec["requestor"] == "auto-waiver"
    assert "low-unreachable" in rec["policy_name"]


def test_workflow_auto_waiver_visible_in_list(workflow_engine):
    workflow_engine.record_auto_waiver("org1", "f1", "r", [], "2026-12-31T00:00:00+00:00")
    rows = workflow_engine.list_requests("org1", status="pending")
    assert len(rows) == 1
    assert rows[0]["requestor"] == "auto-waiver"


# ---------------------------------------------------------------------------
# Risk acceptance link
# ---------------------------------------------------------------------------

def test_link_auto_waiver(ra_engine):
    acc = ra_engine.submit_acceptance(
        finding_id="f1", requestor="alice", justification="j",
        risk_level="low", expiry_days=30, org_id="org1",
    )
    linked = ra_engine.link_auto_waiver("org1", acc["acceptance_id"], "exc-abc")
    assert linked["auto_waiver_exception_id"] == "exc-abc"
    assert any(
        a["action"] == "auto_waiver_linked" for a in linked["audit_trail"]
    )


def test_link_auto_waiver_unknown_raises(ra_engine):
    with pytest.raises(ValueError):
        ra_engine.link_auto_waiver("org1", "ghost-id", "exc-1")


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------

def test_apply_org_isolation(engine):
    engine.register_auto_waiver_rule("org-A", "r", {"severity_max": "critical"}, 10, [], 30)
    res = engine.apply_auto_waivers("org-B", {
        "cve_id": "C", "asset_id": "a", "severity": "low",
    })
    assert res is None  # no rules for org-B


# ---------------------------------------------------------------------------
# Endpoint smoke tests
# ---------------------------------------------------------------------------

@pytest.fixture
def client(tmp_path):
    # Force router engine to point at a temp DB
    from core.vuln_exception_engine import VulnExceptionEngine
    import apps.api.auto_waiver_router as awr
    awr._engine = VulnExceptionEngine(db_path=str(tmp_path / "api_ve.db"))

    from apps.api.auth_deps import api_key_auth

    from fastapi import FastAPI
    app = FastAPI()
    app.include_router(awr.router)
    # Override the auth dependency for the test client
    app.dependency_overrides[api_key_auth] = lambda: {"sub": "test", "org_id": "test"}
    return TestClient(app)


def test_endpoint_register_rule(client):
    r = client.post(
        "/api/v1/auto-waiver/rule?org_id=o1",
        json={
            "rule_key": "low-unreach",
            "conditions": {"reachable": False, "severity_max": "low"},
            "max_active_count": 5,
            "approvers": ["alice"],
            "expires_days": 30,
        },
    )
    assert r.status_code == 201
    body = r.json()
    assert body["rule_key"] == "low-unreach"


def test_endpoint_list_rules(client):
    client.post("/api/v1/auto-waiver/rule?org_id=o1", json={"rule_key": "x", "conditions": {}, "max_active_count": 1, "approvers": [], "expires_days": 30})
    r = client.get("/api/v1/auto-waiver/rules?org_id=o1")
    assert r.status_code == 200
    assert len(r.json()) == 1


def test_endpoint_apply_finding(client):
    client.post(
        "/api/v1/auto-waiver/rule?org_id=o1",
        json={"rule_key": "low", "conditions": {"severity_max": "critical"}, "max_active_count": 10, "approvers": [], "expires_days": 30},
    )
    r = client.post(
        "/api/v1/auto-waiver/apply?org_id=o1",
        json={"finding": {"cve_id": "C1", "asset_id": "a", "severity": "low"}},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["matched"] is True
    assert body["exception"]["reason"] == "auto-waiver:low"


def test_endpoint_stats(client):
    client.post("/api/v1/auto-waiver/rule?org_id=o1", json={"rule_key": "x", "conditions": {}, "max_active_count": 1, "approvers": [], "expires_days": 30})
    r = client.get("/api/v1/auto-waiver/stats?org_id=o1")
    assert r.status_code == 200
    assert r.json()["total_rules"] == 1


def test_endpoint_delete_rule(client):
    client.post("/api/v1/auto-waiver/rule?org_id=o1", json={"rule_key": "doomed", "conditions": {}, "max_active_count": 1, "approvers": [], "expires_days": 30})
    r = client.delete("/api/v1/auto-waiver/rule/doomed?org_id=o1")
    assert r.status_code == 200
    assert r.json()["deleted"] == 1
