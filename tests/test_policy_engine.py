"""
Tests for the ALDECI Policy Engine (suite-core/core/policy_engine.py)
and its REST API router (suite-api/apps/api/policy_engine_router.py).

35+ tests covering:
- PolicyEngine CRUD (create, update, delete, list)
- Rule evaluation: field operators, nested access, AND semantics
- Policy evaluation: scope filtering, priority (DENY > REQUIRE_APPROVAL > WARN > ALLOW)
- Batch evaluation
- Dry-run test_policy
- Evaluation history persistence
- Policy stats
- Import / export round-trip
- Built-in policies (seeded on init)
- REST API endpoints via TestClient
"""

from __future__ import annotations

import json
import os

import pytest

# ── env must be set before any app import ──────────────────────────────────
os.environ["FIXOPS_MODE"] = "dev"
os.environ["FIXOPS_API_TOKEN"] = "test-token"
os.environ["FIXOPS_JWT_SECRET"] = "test-secret-key-that-is-32chars!!"
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

# ── module under test ──────────────────────────────────────────────────────
from core.policy_engine import (
    Policy,
    PolicyDecision,
    PolicyEngine,
    PolicyEvaluation,
    PolicyLanguage,
    PolicyScope,
    _get_nested,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine() -> PolicyEngine:
    """Fresh in-memory engine per test."""
    return PolicyEngine(db_path=":memory:")


@pytest.fixture()
def sample_policy() -> Policy:
    return Policy(
        name="block-critical",
        description="Deny findings with critical severity",
        scope=PolicyScope.FINDINGS,
        language=PolicyLanguage.ALDECI_RULES,
        rules=[{"field": "severity", "operator": "eq", "value": "critical"}],
        decision_on_match=PolicyDecision.DENY,
        enabled=True,
        org_id="acme",
    )


@pytest.fixture()
def api_client():
    """FastAPI TestClient wired to the policy engine router with auth bypassed."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from apps.api.policy_engine_router import router
    from apps.api.auth_deps import api_key_auth

    app = FastAPI()
    # Override auth so tests don't depend on env-loaded token caches
    app.dependency_overrides[api_key_auth] = lambda: None
    app.include_router(router)
    return TestClient(app)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _finding(severity="low", score=0.2, **kwargs):
    return {"severity": severity, "risk_score": score, **kwargs}


# ===========================================================================
# 1. Unit: _get_nested
# ===========================================================================


def test_get_nested_simple():
    assert _get_nested({"a": 1}, "a") == 1


def test_get_nested_dotted():
    data = {"resource": {"tags": {"env": "prod"}}}
    assert _get_nested(data, "resource.tags.env") == "prod"


def test_get_nested_missing():
    assert _get_nested({"a": 1}, "b.c") is None


def test_get_nested_non_dict_midpath():
    assert _get_nested({"a": "string"}, "a.b") is None


# ===========================================================================
# 2. PolicyEngine: CRUD
# ===========================================================================


def test_create_policy(engine, sample_policy):
    created = engine.create_policy(sample_policy)
    assert created.id == sample_policy.id
    assert created.name == "block-critical"
    assert created.version == 1
    assert created.created_at is not None


def test_create_policy_duplicate_raises(engine, sample_policy):
    engine.create_policy(sample_policy)
    with pytest.raises(ValueError, match="already exists"):
        engine.create_policy(sample_policy)


def test_list_policies_empty_org(engine):
    # 'acme' org has no custom policies — but built-ins are org_id='default'
    # list_policies returns policies for org_id IN (org, 'default')
    policies = engine.list_policies(org_id="acme")
    # Built-ins are seeded with org_id='default', so they appear for every org
    assert any(p.name == "no-critical-deploy" for p in policies)


def test_list_policies_scope_filter(engine, sample_policy):
    engine.create_policy(sample_policy)
    findings_policies = engine.list_policies(org_id="acme", scope=PolicyScope.FINDINGS)
    cloud_policies = engine.list_policies(org_id="acme", scope=PolicyScope.CLOUD_RESOURCES)
    assert any(p.name == "block-critical" for p in findings_policies)
    assert not any(p.name == "block-critical" for p in cloud_policies)


def test_update_policy_increments_version(engine, sample_policy):
    engine.create_policy(sample_policy)
    updated = engine.update_policy(sample_policy.id, {"name": "block-critical-v2"})
    assert updated.name == "block-critical-v2"
    assert updated.version == 2


def test_update_policy_not_found(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.update_policy("nonexistent-id", {"name": "x"})


def test_delete_policy(engine, sample_policy):
    engine.create_policy(sample_policy)
    engine.delete_policy(sample_policy.id)
    policies = engine.list_policies(org_id="acme", scope=PolicyScope.FINDINGS)
    assert not any(p.id == sample_policy.id for p in policies)


def test_delete_policy_not_found(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.delete_policy("ghost-id")


# ===========================================================================
# 3. Rule evaluation: _evaluate_rule
# ===========================================================================


def test_rule_eq_match(engine):
    rule = {"field": "severity", "operator": "eq", "value": "critical"}
    assert engine._evaluate_rule(rule, {"severity": "critical"}) is True


def test_rule_eq_no_match(engine):
    rule = {"field": "severity", "operator": "eq", "value": "critical"}
    assert engine._evaluate_rule(rule, {"severity": "low"}) is False


def test_rule_gt(engine):
    rule = {"field": "risk_score", "operator": "gt", "value": 0.5}
    assert engine._evaluate_rule(rule, {"risk_score": 0.9}) is True
    assert engine._evaluate_rule(rule, {"risk_score": 0.3}) is False


def test_rule_lt(engine):
    rule = {"field": "scan_coverage_pct", "operator": "lt", "value": 80}
    assert engine._evaluate_rule(rule, {"scan_coverage_pct": 60}) is True
    assert engine._evaluate_rule(rule, {"scan_coverage_pct": 90}) is False


def test_rule_in_operator(engine):
    rule = {"field": "severity", "operator": "in", "value": ["critical", "high"]}
    assert engine._evaluate_rule(rule, {"severity": "critical"}) is True
    assert engine._evaluate_rule(rule, {"severity": "low"}) is False


def test_rule_contains(engine):
    rule = {"field": "title", "operator": "contains", "value": "SQL"}
    assert engine._evaluate_rule(rule, {"title": "SQL Injection"}) is True
    assert engine._evaluate_rule(rule, {"title": "XSS"}) is False


def test_rule_exists(engine):
    rule = {"field": "cve_id", "operator": "exists", "value": None}
    assert engine._evaluate_rule(rule, {"cve_id": "CVE-2024-1234"}) is True
    assert engine._evaluate_rule(rule, {}) is False


def test_rule_nested_field(engine):
    rule = {"field": "resource.public_access", "operator": "eq", "value": True}
    assert engine._evaluate_rule(rule, {"resource": {"public_access": True}}) is True
    assert engine._evaluate_rule(rule, {"resource": {"public_access": False}}) is False


def test_rule_unknown_operator_returns_false(engine):
    rule = {"field": "x", "operator": "UNKNOWN_OP", "value": 1}
    assert engine._evaluate_rule(rule, {"x": 1}) is False


def test_rule_type_mismatch_returns_false(engine):
    rule = {"field": "score", "operator": "gt", "value": 5}
    assert engine._evaluate_rule(rule, {"score": "not-a-number"}) is False


# ===========================================================================
# 4. Policy evaluation: AND semantics
# ===========================================================================


def test_evaluate_and_all_match(engine, sample_policy):
    """ALDECI_RULES: ALL rules must match (AND semantics)."""
    policy = Policy(
        name="and-test",
        scope=PolicyScope.FINDINGS,
        rules=[
            {"field": "severity", "operator": "eq", "value": "critical"},
            {"field": "risk_score", "operator": "gt", "value": 0.8},
        ],
        decision_on_match=PolicyDecision.DENY,
        org_id="test",
    )
    matched, names = engine._evaluate_policy_rules(
        policy, {"severity": "critical", "risk_score": 0.9}
    )
    assert matched is True
    assert len(names) == 2


def test_evaluate_and_partial_miss(engine):
    policy = Policy(
        name="and-test",
        scope=PolicyScope.FINDINGS,
        rules=[
            {"field": "severity", "operator": "eq", "value": "critical"},
            {"field": "risk_score", "operator": "gt", "value": 0.8},
        ],
        decision_on_match=PolicyDecision.DENY,
        org_id="test",
    )
    matched, _ = engine._evaluate_policy_rules(
        policy, {"severity": "critical", "risk_score": 0.3}  # second rule fails
    )
    assert matched is False


def test_evaluate_empty_rules_no_match(engine):
    policy = Policy(name="empty", scope=PolicyScope.FINDINGS, rules=[], org_id="test")
    matched, _ = engine._evaluate_policy_rules(policy, {"severity": "critical"})
    assert matched is False


# ===========================================================================
# 5. Full evaluation: scope, priority, history
# ===========================================================================


def test_evaluate_default_allow(engine):
    """No matching policies → ALLOW."""
    result = engine.evaluate(
        {"severity": "low"}, scope=PolicyScope.CONTAINERS, org_id="neworg"
    )
    assert result.decision == PolicyDecision.ALLOW


def test_evaluate_deny_wins(engine):
    """DENY policy triggers → decision is DENY."""
    engine.create_policy(
        Policy(
            name="deny-critical",
            scope=PolicyScope.FINDINGS,
            rules=[{"field": "severity", "operator": "eq", "value": "critical"}],
            decision_on_match=PolicyDecision.DENY,
            org_id="testorg",
        )
    )
    result = engine.evaluate(
        {"severity": "critical"}, scope=PolicyScope.FINDINGS, org_id="testorg"
    )
    assert result.decision == PolicyDecision.DENY
    assert result.matched_rules


def test_evaluate_warn_on_non_critical(engine):
    engine.create_policy(
        Policy(
            name="warn-high",
            scope=PolicyScope.FINDINGS,
            rules=[{"field": "severity", "operator": "eq", "value": "high"}],
            decision_on_match=PolicyDecision.WARN,
            org_id="testorg",
        )
    )
    result = engine.evaluate(
        {"severity": "high"}, scope=PolicyScope.FINDINGS, org_id="testorg"
    )
    assert result.decision == PolicyDecision.WARN


def test_evaluate_deny_beats_warn(engine):
    """DENY > WARN in priority."""
    engine.create_policy(
        Policy(
            name="warn-low",
            scope=PolicyScope.FINDINGS,
            rules=[{"field": "risk_score", "operator": "gt", "value": 0.0}],
            decision_on_match=PolicyDecision.WARN,
            org_id="org1",
        )
    )
    engine.create_policy(
        Policy(
            name="deny-critical",
            scope=PolicyScope.FINDINGS,
            rules=[{"field": "severity", "operator": "eq", "value": "critical"}],
            decision_on_match=PolicyDecision.DENY,
            org_id="org1",
        )
    )
    result = engine.evaluate(
        {"severity": "critical", "risk_score": 0.9},
        scope=PolicyScope.FINDINGS,
        org_id="org1",
    )
    assert result.decision == PolicyDecision.DENY


def test_evaluate_scope_isolation(engine):
    """Policies only match their declared scope."""
    engine.create_policy(
        Policy(
            name="deny-deploy",
            scope=PolicyScope.DEPLOYMENTS,
            rules=[{"field": "critical_vuln_count", "operator": "gt", "value": 0}],
            decision_on_match=PolicyDecision.DENY,
            org_id="testorg",
        )
    )
    # Evaluate against FINDINGS scope — should not trigger DEPLOYMENTS policy
    result = engine.evaluate(
        {"critical_vuln_count": 5}, scope=PolicyScope.FINDINGS, org_id="testorg"
    )
    assert result.decision == PolicyDecision.ALLOW


def test_evaluate_batch(engine):
    engine.create_policy(
        Policy(
            name="block-critical-batch",
            scope=PolicyScope.FINDINGS,
            rules=[{"field": "severity", "operator": "eq", "value": "critical"}],
            decision_on_match=PolicyDecision.DENY,
            org_id="batchorg",
        )
    )
    inputs = [
        {"severity": "critical"},
        {"severity": "low"},
        {"severity": "critical"},
    ]
    results = engine.evaluate_batch(inputs, scope=PolicyScope.FINDINGS, org_id="batchorg")
    assert len(results) == 3
    assert results[0].decision == PolicyDecision.DENY
    assert results[1].decision == PolicyDecision.ALLOW
    assert results[2].decision == PolicyDecision.DENY


def test_evaluate_saves_history(engine):
    engine.evaluate({"severity": "low"}, scope=PolicyScope.FINDINGS, org_id="historg")
    history = engine.get_evaluation_history(org_id="historg")
    assert len(history) >= 1


def test_evaluation_history_filtered_by_policy(engine):
    p = engine.create_policy(
        Policy(
            name="hist-policy",
            scope=PolicyScope.FINDINGS,
            rules=[{"field": "severity", "operator": "eq", "value": "critical"}],
            decision_on_match=PolicyDecision.DENY,
            org_id="historg2",
        )
    )
    engine.evaluate({"severity": "critical"}, scope=PolicyScope.FINDINGS, org_id="historg2")
    history = engine.get_evaluation_history(org_id="historg2", policy_id=p.id)
    assert len(history) >= 1
    assert all(e.policy_id == p.id for e in history)


# ===========================================================================
# 6. test_policy (dry-run)
# ===========================================================================


def test_test_policy_match(engine, sample_policy):
    result = engine.test_policy(sample_policy, {"severity": "critical"})
    assert result.decision == PolicyDecision.DENY
    assert result.matched_rules


def test_test_policy_no_match(engine, sample_policy):
    result = engine.test_policy(sample_policy, {"severity": "low"})
    assert result.decision == PolicyDecision.ALLOW
    assert not result.matched_rules


def test_test_policy_not_persisted(engine, sample_policy):
    engine.test_policy(sample_policy, {"severity": "critical"})
    history = engine.get_evaluation_history(org_id="acme")
    # dry-run should not appear in history
    assert len(history) == 0


# ===========================================================================
# 7. JSON Logic language
# ===========================================================================


def test_json_logic_eq_match(engine):
    policy = Policy(
        name="jl-policy",
        scope=PolicyScope.FINDINGS,
        language=PolicyLanguage.JSON_LOGIC,
        rules=[{"==": [{"var": "severity"}, "critical"]}],
        decision_on_match=PolicyDecision.DENY,
        org_id="jlorg",
    )
    matched, names = engine._evaluate_policy_rules(policy, {"severity": "critical"})
    assert matched is True


def test_json_logic_no_match(engine):
    policy = Policy(
        name="jl-policy2",
        scope=PolicyScope.FINDINGS,
        language=PolicyLanguage.JSON_LOGIC,
        rules=[{"==": [{"var": "severity"}, "critical"]}],
        decision_on_match=PolicyDecision.DENY,
        org_id="jlorg",
    )
    matched, _ = engine._evaluate_policy_rules(policy, {"severity": "low"})
    assert matched is False


# ===========================================================================
# 8. Built-in policies
# ===========================================================================


def test_builtin_policies_seeded(engine):
    policies = engine.list_policies(org_id="default")
    names = {p.name for p in policies}
    assert "no-critical-deploy" in names
    assert "require-mfa-cloud" in names
    assert "block-public-s3" in names
    assert "enforce-encryption" in names
    assert "minimum-scan-coverage" in names


def test_builtin_no_critical_deploy(engine):
    result = engine.evaluate(
        {"critical_vuln_count": 3},
        scope=PolicyScope.DEPLOYMENTS,
        org_id="someorg",
    )
    assert result.decision == PolicyDecision.DENY


def test_builtin_block_public_s3(engine):
    result = engine.evaluate(
        {"resource_type": "s3_bucket", "public_access": True},
        scope=PolicyScope.CLOUD_RESOURCES,
        org_id="someorg",
    )
    assert result.decision == PolicyDecision.DENY


def test_builtin_minimum_scan_coverage(engine):
    result = engine.evaluate(
        {"scan_coverage_pct": 50},
        scope=PolicyScope.CODE_CHANGES,
        org_id="someorg",
    )
    assert result.decision == PolicyDecision.REQUIRE_APPROVAL


# ===========================================================================
# 9. Stats
# ===========================================================================


def test_policy_stats(engine):
    engine.evaluate({"severity": "low"}, scope=PolicyScope.FINDINGS, org_id="statsorg")
    stats = engine.get_policy_stats(org_id="statsorg")
    assert "total_policies" in stats
    assert "total_evaluations" in stats
    assert stats["total_evaluations"] >= 1
    assert "decisions" in stats
    assert "policies_by_scope" in stats


# ===========================================================================
# 10. Import / Export
# ===========================================================================


def test_export_import_roundtrip(engine):
    engine.create_policy(
        Policy(
            name="export-test",
            scope=PolicyScope.FINDINGS,
            rules=[{"field": "severity", "operator": "eq", "value": "critical"}],
            decision_on_match=PolicyDecision.DENY,
            org_id="exportorg",
        )
    )
    exported = engine.export_policies(org_id="exportorg")
    assert "export-test" in exported

    # Import into a different engine
    engine2 = PolicyEngine(db_path=":memory:")
    count = engine2.import_policies(exported, org_id="importorg")
    assert count >= 1
    imported_policies = engine2.list_policies(org_id="importorg")
    assert any(p.name == "export-test" for p in imported_policies)


def test_import_invalid_json(engine):
    with pytest.raises((ValueError, Exception)):
        engine.import_policies("not-json", org_id="test")


def test_import_skips_duplicates(engine):
    p = Policy(
        name="dup-test",
        scope=PolicyScope.FINDINGS,
        rules=[],
        org_id="duporg",
    )
    payload = json.dumps([p.model_dump()])
    count1 = engine.import_policies(payload, org_id="duporg")
    count2 = engine.import_policies(payload, org_id="duporg")
    assert count1 == 1
    assert count2 == 0  # duplicate skipped


# ===========================================================================
# 11. REST API via TestClient
# ===========================================================================


def test_api_create_policy(api_client):
    resp = api_client.post(
        "/api/v1/policy-engine/policies",
        json={
            "name": "api-test-policy",
            "scope": "findings",
            "rules": [{"field": "severity", "operator": "eq", "value": "critical"}],
            "decision_on_match": "deny",
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "api-test-policy"
    assert "id" in data


def test_api_list_policies(api_client):
    resp = api_client.get("/api/v1/policy-engine/policies")
    assert resp.status_code == 200
    data = resp.json()
    assert "policies" in data
    assert "total" in data


def test_api_get_policy(api_client):
    # Create then fetch
    create_resp = api_client.post(
        "/api/v1/policy-engine/policies",
        json={"name": "fetch-me", "scope": "findings", "rules": []},
    )
    policy_id = create_resp.json()["id"]
    resp = api_client.get(f"/api/v1/policy-engine/policies/{policy_id}")
    assert resp.status_code == 200
    assert resp.json()["id"] == policy_id


def test_api_get_policy_not_found(api_client):
    resp = api_client.get("/api/v1/policy-engine/policies/does-not-exist")
    assert resp.status_code == 404


def test_api_update_policy(api_client):
    create_resp = api_client.post(
        "/api/v1/policy-engine/policies",
        json={"name": "update-me", "scope": "findings", "rules": []},
    )
    policy_id = create_resp.json()["id"]
    resp = api_client.put(
        f"/api/v1/policy-engine/policies/{policy_id}",
        json={"name": "updated-name"},
    )
    assert resp.status_code == 200
    assert resp.json()["name"] == "updated-name"
    assert resp.json()["version"] == 2


def test_api_delete_policy(api_client):
    create_resp = api_client.post(
        "/api/v1/policy-engine/policies",
        json={"name": "delete-me", "scope": "findings", "rules": []},
    )
    policy_id = create_resp.json()["id"]
    del_resp = api_client.delete(f"/api/v1/policy-engine/policies/{policy_id}")
    assert del_resp.status_code == 204


def test_api_evaluate(api_client):
    resp = api_client.post(
        "/api/v1/policy-engine/evaluate",
        json={"input_data": {"severity": "low"}, "scope": "findings"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "decision" in data
    assert "matched_rules" in data


def test_api_evaluate_batch(api_client):
    resp = api_client.post(
        "/api/v1/policy-engine/evaluate/batch",
        json={
            "inputs": [{"severity": "low"}, {"severity": "high"}],
            "scope": "findings",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["results"]) == 2


def test_api_test_policy(api_client):
    resp = api_client.post(
        "/api/v1/policy-engine/test",
        json={
            "policy": {
                "name": "dry-run",
                "scope": "findings",
                "rules": [{"field": "severity", "operator": "eq", "value": "critical"}],
                "decision_on_match": "deny",
            },
            "test_input": {"severity": "critical"},
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "deny"


def test_api_history(api_client):
    # Trigger an evaluation first
    api_client.post(
        "/api/v1/policy-engine/evaluate",
        json={"input_data": {"severity": "low"}, "scope": "findings"},
    )
    resp = api_client.get("/api/v1/policy-engine/history")
    assert resp.status_code == 200
    assert "history" in resp.json()


def test_api_stats(api_client):
    resp = api_client.get("/api/v1/policy-engine/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_policies" in data


def test_api_export(api_client):
    resp = api_client.get("/api/v1/policy-engine/export")
    assert resp.status_code == 200
    assert "data" in resp.json()


def test_api_import(api_client):
    payload = json.dumps(
        [
            {
                "name": "imported-policy",
                "scope": "findings",
                "rules": [],
                "decision_on_match": "warn",
                "language": "aldeci_rules",
                "enabled": True,
                "org_id": "default",
            }
        ]
    )
    resp = api_client.post(
        "/api/v1/policy-engine/import",
        json={"policies_json": payload},
    )
    assert resp.status_code == 200
    assert resp.json()["imported"] >= 1
