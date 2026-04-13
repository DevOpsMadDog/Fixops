"""
Tests for SOC Automation Engine.

Covers:
- SOCAction enum values
- AutomationRule model creation and defaults
- SOCAutomation: create_rule, get_rule, list_rules, update_rule, delete_rule
- Default rule seeding (10 rules)
- evaluate_finding: matching and non-matching rules
- auto_triage: severity/priority mapping, exploit/asset boosts
- auto_enrich: CVE, IP, asset enrichment
- auto_escalate: severity-based routing, category routing, critical CISO route
- auto_close: FP pattern, info age, low age, no-match
- auto_assign: category expertise, severity tier
- get_automation_stats: counts and time estimates
- Router endpoints (via TestClient)
- Edge cases: unknown org, disabled rules, missing fields

Run with: python -m pytest tests/test_soc_automation.py -v --timeout=15
"""

import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))

from core.soc_automation import (
    AutomationRule,
    AutomationStats,
    EnrichmentResult,
    EscalationResult,
    SOCAction,
    SOCAutomation,
    TriageResult,
    AssignmentResult,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    """SOCAutomation with a fresh temp DB."""
    return SOCAutomation(db_path=str(tmp_path / "soc_test.db"))


@pytest.fixture
def finding_critical():
    return {
        "id": "f-001",
        "severity": "critical",
        "status": "open",
        "category": "network",
        "assigned_to": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


@pytest.fixture
def finding_info_old():
    old = datetime.now(timezone.utc) - timedelta(days=45)
    return {
        "id": "f-002",
        "severity": "info",
        "status": "open",
        "created_at": old.isoformat(),
    }


@pytest.fixture
def finding_fp():
    return {
        "id": "f-003",
        "severity": "medium",
        "status": "open",
        "tags": ["false-positive-candidate"],
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


@pytest.fixture
def finding_with_cve():
    return {
        "id": "f-004",
        "severity": "high",
        "status": "open",
        "cve_id": "CVE-2024-1234",
        "has_cve": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# SOCAction enum
# ---------------------------------------------------------------------------


def test_soc_action_values():
    assert SOCAction.AUTO_TRIAGE == "auto_triage"
    assert SOCAction.AUTO_ENRICH == "auto_enrich"
    assert SOCAction.AUTO_ESCALATE == "auto_escalate"
    assert SOCAction.AUTO_CLOSE == "auto_close"
    assert SOCAction.AUTO_ASSIGN == "auto_assign"
    assert SOCAction.AUTO_INVESTIGATE == "auto_investigate"


def test_soc_action_count():
    assert len(SOCAction) == 6


# ---------------------------------------------------------------------------
# AutomationRule model
# ---------------------------------------------------------------------------


def test_automation_rule_defaults():
    rule = AutomationRule(name="test", action=SOCAction.AUTO_TRIAGE)
    assert rule.enabled is True
    assert rule.execution_count == 0
    assert rule.last_triggered is None
    assert rule.org_id == "default"
    assert isinstance(rule.id, str)
    assert len(rule.id) == 36  # uuid4


def test_automation_rule_custom():
    rule = AutomationRule(
        name="My Rule",
        trigger_condition={"severity": "critical"},
        action=SOCAction.AUTO_ESCALATE,
        config={"team": "leads"},
        org_id="acme",
    )
    assert rule.name == "My Rule"
    assert rule.trigger_condition == {"severity": "critical"}
    assert rule.action == SOCAction.AUTO_ESCALATE
    assert rule.org_id == "acme"


# ---------------------------------------------------------------------------
# Default rule seeding
# ---------------------------------------------------------------------------


def test_default_rules_seeded(engine):
    rules = engine.list_rules(org_id="default")
    assert len(rules) == 10


def test_default_rules_have_required_fields(engine):
    rules = engine.list_rules(org_id="default")
    for rule in rules:
        assert rule.name
        assert rule.action in SOCAction.__members__.values()
        assert isinstance(rule.trigger_condition, dict)


# ---------------------------------------------------------------------------
# Rule CRUD
# ---------------------------------------------------------------------------


def test_create_rule(engine):
    rule = AutomationRule(
        name="Test Rule",
        trigger_condition={"severity": "high"},
        action=SOCAction.AUTO_TRIAGE,
        org_id="default",
    )
    created = engine.create_rule(rule)
    assert created.id == rule.id
    assert created.name == "Test Rule"


def test_get_rule(engine):
    rule = AutomationRule(name="Fetch Me", action=SOCAction.AUTO_ENRICH, org_id="default")
    engine.create_rule(rule)
    fetched = engine.get_rule(rule.id)
    assert fetched is not None
    assert fetched.id == rule.id
    assert fetched.name == "Fetch Me"


def test_get_rule_not_found(engine):
    result = engine.get_rule("nonexistent-id")
    assert result is None


def test_list_rules_empty_org(engine):
    rules = engine.list_rules(org_id="unknown-org")
    assert rules == []


def test_list_rules_org_isolation(engine):
    rule_a = AutomationRule(name="Rule A", action=SOCAction.AUTO_CLOSE, org_id="org-a")
    rule_b = AutomationRule(name="Rule B", action=SOCAction.AUTO_TRIAGE, org_id="org-b")
    engine.create_rule(rule_a)
    engine.create_rule(rule_b)
    assert len(engine.list_rules("org-a")) == 1
    assert len(engine.list_rules("org-b")) == 1


def test_update_rule(engine):
    rule = AutomationRule(name="Original", action=SOCAction.AUTO_ASSIGN, org_id="default")
    engine.create_rule(rule)
    rule.name = "Updated"
    rule.enabled = False
    updated = engine.update_rule(rule)
    assert updated.name == "Updated"
    fetched = engine.get_rule(rule.id)
    assert fetched.name == "Updated"
    assert fetched.enabled is False


def test_delete_rule(engine):
    rule = AutomationRule(name="Delete Me", action=SOCAction.AUTO_CLOSE, org_id="default")
    engine.create_rule(rule)
    assert engine.delete_rule(rule.id) is True
    assert engine.get_rule(rule.id) is None


def test_delete_rule_not_found(engine):
    assert engine.delete_rule("no-such-id") is False


# ---------------------------------------------------------------------------
# evaluate_finding
# ---------------------------------------------------------------------------


def test_evaluate_finding_no_match(engine):
    """A finding that matches no rules fires nothing."""
    results = engine.evaluate_finding(
        finding={"id": "f-x", "severity": "critical", "status": "closed"},
        org_id="empty-org",
    )
    assert results == []


def test_evaluate_finding_disabled_rule_ignored(engine):
    rule = AutomationRule(
        name="Disabled",
        trigger_condition={"severity": "critical"},
        action=SOCAction.AUTO_ESCALATE,
        enabled=False,
        org_id="org-disabled",
    )
    engine.create_rule(rule)
    finding = {"id": "f-d", "severity": "critical", "status": "open"}
    results = engine.evaluate_finding(finding, org_id="org-disabled")
    assert results == []


def test_evaluate_finding_fires_matching_rule(engine):
    rule = AutomationRule(
        name="Critical Escalate",
        trigger_condition={"severity": "critical", "status": "open"},
        action=SOCAction.AUTO_ESCALATE,
        enabled=True,
        org_id="test-org",
    )
    engine.create_rule(rule)
    finding = {"id": "f-e", "severity": "critical", "status": "open"}
    results = engine.evaluate_finding(finding, org_id="test-org")
    assert len(results) == 1
    assert results[0]["action"] == SOCAction.AUTO_ESCALATE.value
    assert results[0]["rule_id"] == rule.id


def test_evaluate_finding_increments_execution_count(engine):
    rule = AutomationRule(
        name="Counter Rule",
        trigger_condition={"severity": "high"},
        action=SOCAction.AUTO_TRIAGE,
        enabled=True,
        org_id="org-count",
    )
    engine.create_rule(rule)
    finding = {"id": "f-cnt", "severity": "high"}
    engine.evaluate_finding(finding, org_id="org-count")
    fetched = engine.get_rule(rule.id)
    assert fetched.execution_count == 1


def test_evaluate_finding_age_condition(engine):
    """age_days_gt condition should match old findings."""
    old_date = (datetime.now(timezone.utc) - timedelta(days=35)).isoformat()
    rule = AutomationRule(
        name="Age Rule",
        trigger_condition={"severity": "info", "age_days_gt": 30},
        action=SOCAction.AUTO_CLOSE,
        enabled=True,
        org_id="age-org",
    )
    engine.create_rule(rule)
    finding = {"id": "f-age", "severity": "info", "created_at": old_date}
    results = engine.evaluate_finding(finding, org_id="age-org")
    assert len(results) == 1


def test_evaluate_finding_age_condition_no_match(engine):
    """age_days_gt should NOT match new findings."""
    new_date = datetime.now(timezone.utc).isoformat()
    rule = AutomationRule(
        name="Age Rule No Match",
        trigger_condition={"severity": "info", "age_days_gt": 30},
        action=SOCAction.AUTO_CLOSE,
        enabled=True,
        org_id="age-org2",
    )
    engine.create_rule(rule)
    finding = {"id": "f-new", "severity": "info", "created_at": new_date}
    results = engine.evaluate_finding(finding, org_id="age-org2")
    assert results == []


# ---------------------------------------------------------------------------
# auto_triage
# ---------------------------------------------------------------------------


def test_auto_triage_critical(engine):
    result = engine.auto_triage({"id": "f", "severity": "critical"})
    assert isinstance(result, TriageResult)
    assert result.severity == "critical"
    assert result.priority == 1


def test_auto_triage_high(engine):
    result = engine.auto_triage({"id": "f", "severity": "high"})
    assert result.priority == 2


def test_auto_triage_medium(engine):
    result = engine.auto_triage({"id": "f", "severity": "medium"})
    assert result.priority == 3


def test_auto_triage_low(engine):
    result = engine.auto_triage({"id": "f", "severity": "low"})
    assert result.priority == 4


def test_auto_triage_info(engine):
    result = engine.auto_triage({"id": "f", "severity": "info"})
    assert result.priority == 5


def test_auto_triage_exploit_boosts_priority(engine):
    result = engine.auto_triage({"id": "f", "severity": "high", "exploit_available": True})
    # high base = 2, exploit = -1 => 1
    assert result.priority == 1
    assert "exploit_available" in result.rationale


def test_auto_triage_critical_asset_boosts(engine):
    result = engine.auto_triage({"id": "f", "severity": "medium", "asset_criticality": "critical"})
    # medium base = 3, asset = -1 => 2
    assert result.priority == 2


def test_auto_triage_cve_in_rationale(engine):
    result = engine.auto_triage({"id": "f", "severity": "high", "cve_id": "CVE-2024-0001"})
    assert "has_cve" in result.rationale


def test_auto_triage_finding_id(engine):
    result = engine.auto_triage({"id": "f-123", "severity": "low"})
    assert result.finding_id == "f-123"


# ---------------------------------------------------------------------------
# auto_enrich
# ---------------------------------------------------------------------------


def test_auto_enrich_with_cve(engine, finding_with_cve):
    result = engine.auto_enrich(finding_with_cve)
    assert isinstance(result, EnrichmentResult)
    assert result.added_context.get("cvss_enriched") is True
    assert any("CVE-2024-1234" in h for h in result.threat_intel_hits)
    assert "CVE-2024-1234" in result.trustgraph_entities


def test_auto_enrich_with_ip(engine):
    finding = {"id": "f-ip", "source_ip": "192.168.1.1"}
    result = engine.auto_enrich(finding)
    assert result.added_context.get("ip_reputation_checked") is True
    assert any("192.168.1.1" in h for h in result.threat_intel_hits)


def test_auto_enrich_with_asset(engine):
    finding = {"id": "f-asset", "asset": "web-server-01"}
    result = engine.auto_enrich(finding)
    assert result.added_context.get("asset_context_enriched") is True
    assert "web-server-01" in result.trustgraph_entities


def test_auto_enrich_enriched_at_present(engine):
    finding = {"id": "f-ts"}
    result = engine.auto_enrich(finding)
    assert "enriched_at" in result.added_context


def test_auto_enrich_sources_listed(engine):
    finding = {"id": "f-src"}
    result = engine.auto_enrich(finding)
    assert "nvd" in result.added_context.get("enrichment_sources", [])


# ---------------------------------------------------------------------------
# auto_escalate
# ---------------------------------------------------------------------------


def test_auto_escalate_critical_to_ciso(engine):
    result = engine.auto_escalate({"id": "f", "severity": "critical", "category": "network"})
    assert isinstance(result, EscalationResult)
    assert result.escalated_to == "ciso-on-call"
    assert result.team == "security-leadership"


def test_auto_escalate_high_to_senior(engine):
    result = engine.auto_escalate({"id": "f", "severity": "high", "category": "general"})
    assert result.team == "senior-analysts"


def test_auto_escalate_cloud_category(engine):
    result = engine.auto_escalate({"id": "f", "severity": "high", "category": "cloud"})
    assert "cloud" in result.escalated_to


def test_auto_escalate_application_category(engine):
    result = engine.auto_escalate({"id": "f", "severity": "medium", "category": "application"})
    assert "appsec" in result.escalated_to


def test_auto_escalate_reason_contains_severity(engine):
    result = engine.auto_escalate({"id": "f", "severity": "low", "category": "network"})
    assert "severity=low" in result.reason


# ---------------------------------------------------------------------------
# auto_close
# ---------------------------------------------------------------------------


def test_auto_close_false_positive_pattern(engine, finding_fp):
    result = engine.auto_close(finding_fp)
    assert result["closed"] is True
    assert "false_positive_pattern" in result["reasons"]


def test_auto_close_info_old(engine, finding_info_old):
    result = engine.auto_close(finding_info_old)
    assert result["closed"] is True
    assert any("info" in r for r in result["reasons"])


def test_auto_close_low_old(engine):
    old = (datetime.now(timezone.utc) - timedelta(days=95)).isoformat()
    finding = {"id": "f-low-old", "severity": "low", "created_at": old}
    result = engine.auto_close(finding)
    assert result["closed"] is True


def test_auto_close_no_criteria(engine, finding_critical):
    result = engine.auto_close(finding_critical)
    assert result["closed"] is False


def test_auto_close_includes_timestamp(engine, finding_fp):
    result = engine.auto_close(finding_fp)
    assert "closed_at" in result


# ---------------------------------------------------------------------------
# auto_assign
# ---------------------------------------------------------------------------


def test_auto_assign_cloud_category(engine):
    finding = {"id": "f", "severity": "medium", "category": "cloud"}
    result = engine.auto_assign(finding)
    assert isinstance(result, AssignmentResult)
    assert "cloud" in result.assigned_to


def test_auto_assign_network_category(engine):
    finding = {"id": "f", "severity": "low", "category": "network"}
    result = engine.auto_assign(finding)
    assert "network" in result.assigned_to


def test_auto_assign_high_severity_tier(engine):
    finding = {"id": "f", "severity": "high", "category": "application"}
    result = engine.auto_assign(finding)
    assert "senior" in result.assigned_to


def test_auto_assign_reason_contains_category(engine):
    finding = {"id": "f", "severity": "medium", "category": "identity"}
    result = engine.auto_assign(finding)
    assert "category=identity" in result.reason


def test_auto_assign_workload_score_range(engine):
    finding = {"id": "f", "severity": "medium", "category": "endpoint"}
    result = engine.auto_assign(finding)
    assert 0.0 <= result.workload_score <= 1.0


# ---------------------------------------------------------------------------
# get_automation_stats
# ---------------------------------------------------------------------------


def test_stats_counts_rules(engine):
    stats = engine.get_automation_stats(org_id="default")
    assert isinstance(stats, AutomationStats)
    assert stats.total_rules == 10
    assert stats.enabled_rules == 10


def test_stats_empty_org(engine):
    stats = engine.get_automation_stats(org_id="no-rules-org")
    assert stats.total_rules == 0
    assert stats.total_executions == 0
    assert stats.estimated_minutes_saved == 0.0


def test_stats_execution_count_after_fire(engine):
    rule = AutomationRule(
        name="Stats Rule",
        trigger_condition={"severity": "critical"},
        action=SOCAction.AUTO_ESCALATE,
        org_id="stats-org",
    )
    engine.create_rule(rule)
    engine.evaluate_finding({"id": "f-s", "severity": "critical"}, org_id="stats-org")
    stats = engine.get_automation_stats(org_id="stats-org")
    assert stats.total_executions == 1
    assert stats.findings_auto_processed == 1
    assert stats.estimated_minutes_saved == 8.0


def test_stats_top_rules_populated(engine):
    rule = AutomationRule(
        name="Top Rule",
        trigger_condition={"severity": "high"},
        action=SOCAction.AUTO_TRIAGE,
        org_id="top-org",
    )
    engine.create_rule(rule)
    for _ in range(3):
        engine.evaluate_finding({"id": str(uuid.uuid4()), "severity": "high"}, org_id="top-org")
    stats = engine.get_automation_stats(org_id="top-org")
    assert len(stats.top_rules) >= 1
    assert stats.top_rules[0]["execution_count"] >= 3


# ---------------------------------------------------------------------------
# Router tests
# ---------------------------------------------------------------------------


@pytest.fixture
def client(tmp_path):
    """TestClient for the SOC automation router with isolated DB."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    import core.soc_automation as soc_mod
    import apps.api.soc_automation_router as router_mod

    # Reset singleton to use temp DB
    router_mod._engine = soc_mod.SOCAutomation(db_path=str(tmp_path / "router_test.db"))

    app = FastAPI()
    app.include_router(router_mod.router)
    return TestClient(app)


def test_router_create_rule(client):
    resp = client.post("/api/v1/soc-automation/rules", json={
        "name": "Router Rule",
        "trigger_condition": {"severity": "high"},
        "action": "auto_triage",
        "org_id": "default",
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "Router Rule"
    assert data["action"] == "auto_triage"


def test_router_list_rules(client):
    resp = client.get("/api/v1/soc-automation/rules?org_id=default")
    assert resp.status_code == 200
    rules = resp.json()
    assert isinstance(rules, list)
    assert len(rules) == 10  # default seeded rules


def test_router_get_rule(client):
    # Create then fetch
    create_resp = client.post("/api/v1/soc-automation/rules", json={
        "name": "Fetch Rule",
        "action": "auto_enrich",
        "org_id": "default",
    })
    rule_id = create_resp.json()["id"]
    resp = client.get(f"/api/v1/soc-automation/rules/{rule_id}")
    assert resp.status_code == 200
    assert resp.json()["id"] == rule_id


def test_router_get_rule_404(client):
    resp = client.get("/api/v1/soc-automation/rules/does-not-exist")
    assert resp.status_code == 404


def test_router_update_rule(client):
    create_resp = client.post("/api/v1/soc-automation/rules", json={
        "name": "Update Me",
        "action": "auto_close",
        "org_id": "default",
    })
    rule_id = create_resp.json()["id"]
    resp = client.put(f"/api/v1/soc-automation/rules/{rule_id}", json={"name": "Updated Name", "enabled": False})
    assert resp.status_code == 200
    assert resp.json()["name"] == "Updated Name"
    assert resp.json()["enabled"] is False


def test_router_delete_rule(client):
    create_resp = client.post("/api/v1/soc-automation/rules", json={
        "name": "Delete Me",
        "action": "auto_assign",
        "org_id": "default",
    })
    rule_id = create_resp.json()["id"]
    del_resp = client.delete(f"/api/v1/soc-automation/rules/{rule_id}")
    assert del_resp.status_code == 204
    get_resp = client.get(f"/api/v1/soc-automation/rules/{rule_id}")
    assert get_resp.status_code == 404


def test_router_evaluate_finding(client):
    resp = client.post("/api/v1/soc-automation/evaluate", json={
        "finding": {"id": "f-router", "severity": "critical", "status": "open"},
        "org_id": "default",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["finding_id"] == "f-router"
    assert "rules_fired" in data
    assert "results" in data


def test_router_stats(client):
    resp = client.get("/api/v1/soc-automation/stats?org_id=default")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_rules"] == 10
    assert "estimated_minutes_saved" in data


def test_router_action_triage(client):
    resp = client.post("/api/v1/soc-automation/actions/auto_triage", json={
        "finding": {"id": "f-act", "severity": "high"},
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["action"] == "auto_triage"
    assert data["result"]["priority"] == 2


def test_router_action_invalid(client):
    resp = client.post("/api/v1/soc-automation/actions/invalid_action", json={
        "finding": {"id": "f"},
    })
    assert resp.status_code == 422


def test_router_create_rule_invalid_action(client):
    resp = client.post("/api/v1/soc-automation/rules", json={
        "name": "Bad Action",
        "action": "not_a_real_action",
        "org_id": "default",
    })
    assert resp.status_code == 422
