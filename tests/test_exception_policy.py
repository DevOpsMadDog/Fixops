"""
Tests for the Vulnerability Exception Policy Engine — ALDECI.

Coverage:
- Rule CRUD (add, list, update, delete)
- Criteria matching: cve_pattern, scanner, severity, min_age_days, max_cvss, component_pattern
- AND-combined criteria (all must match)
- Actions: suppress, downgrade, defer
- Rule expiration (expires_at)
- Version publish / rollback
- Batch evaluation
- Re-evaluation
- Stats
- API router endpoints
"""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List
from uuid import uuid4

import pytest

# ---------------------------------------------------------------------------
# Environment setup (must happen before any app imports)
# ---------------------------------------------------------------------------
os.environ.setdefault("FIXOPS_MODE", "dev")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-key-that-is-long-enough-32ch")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from core.exception_policy import (
    ExceptionPolicyEngine,
    ExceptionRule,
    MatchCriteria,
    PolicyVersion,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_db(tmp_path: Path) -> Path:
    return tmp_path / "test_exception_policy.db"


@pytest.fixture()
def engine(tmp_db: Path) -> ExceptionPolicyEngine:
    return ExceptionPolicyEngine(db_path=tmp_db)


ORG = "test-org"


def _rule(
    action: str = "suppress",
    cve_pattern: str | None = None,
    scanner: str | None = None,
    severity: str | None = None,
    min_age_days: int | None = None,
    max_cvss: float | None = None,
    component_pattern: str | None = None,
    downgrade_to: str | None = None,
    defer_days: int | None = None,
    expires_at: datetime | None = None,
    enabled: bool = True,
    name: str | None = None,
) -> ExceptionRule:
    return ExceptionRule(
        name=name or f"rule-{uuid4().hex[:6]}",
        description="test rule",
        criteria=MatchCriteria(
            cve_pattern=cve_pattern,
            scanner=scanner,
            severity=severity,
            min_age_days=min_age_days,
            max_cvss=max_cvss,
            component_pattern=component_pattern,
        ),
        action=action,
        downgrade_to=downgrade_to,
        defer_days=defer_days,
        expires_at=expires_at,
        enabled=enabled,
    )


def _finding(
    cve_id: str = "CVE-2024-1234",
    scanner: str = "trivy",
    severity: str = "high",
    age_days: int = 10,
    cvss: float = 7.5,
    component: str = "log4j",
    fid: str | None = None,
) -> Dict[str, Any]:
    first_seen = datetime.now(timezone.utc) - timedelta(days=age_days)
    return {
        "id": fid or str(uuid4()),
        "cve_id": cve_id,
        "source": scanner,
        "severity": severity,
        "first_seen": first_seen.isoformat(),
        "cvss_score": cvss,
        "component": component,
    }


# ---------------------------------------------------------------------------
# 1. Rule CRUD
# ---------------------------------------------------------------------------


def test_add_rule(engine: ExceptionPolicyEngine) -> None:
    rule = _rule(action="suppress", cve_pattern="CVE-2024-.*")
    created = engine.add_rule(rule, org_id=ORG)
    assert created.id == rule.id
    assert created.name == rule.name


def test_list_rules_empty(engine: ExceptionPolicyEngine) -> None:
    assert engine.list_rules(org_id=ORG) == []


def test_list_rules_returns_added(engine: ExceptionPolicyEngine) -> None:
    engine.add_rule(_rule(name="r1"), org_id=ORG)
    engine.add_rule(_rule(name="r2"), org_id=ORG)
    rules = engine.list_rules(org_id=ORG)
    assert len(rules) == 2
    names = {r.name for r in rules}
    assert "r1" in names and "r2" in names


def test_list_rules_enabled_only(engine: ExceptionPolicyEngine) -> None:
    engine.add_rule(_rule(name="on", enabled=True), org_id=ORG)
    engine.add_rule(_rule(name="off", enabled=False), org_id=ORG)
    enabled = engine.list_rules(org_id=ORG, enabled_only=True)
    assert len(enabled) == 1
    assert enabled[0].name == "on"


def test_update_rule_increments_version(engine: ExceptionPolicyEngine) -> None:
    rule = engine.add_rule(_rule(name="original"), org_id=ORG)
    assert rule.version == 1
    updated = engine.update_rule(rule.id, {"name": "renamed"}, org_id=ORG)
    assert updated.version == 2
    assert updated.name == "renamed"


def test_update_rule_not_found(engine: ExceptionPolicyEngine) -> None:
    with pytest.raises(KeyError):
        engine.update_rule("nonexistent-id", {"name": "x"}, org_id=ORG)


def test_delete_rule(engine: ExceptionPolicyEngine) -> None:
    rule = engine.add_rule(_rule(), org_id=ORG)
    engine.delete_rule(rule.id, org_id=ORG)
    assert engine.list_rules(org_id=ORG) == []


def test_delete_rule_not_found(engine: ExceptionPolicyEngine) -> None:
    with pytest.raises(KeyError):
        engine.delete_rule("no-such-id", org_id=ORG)


def test_rules_isolated_by_org(engine: ExceptionPolicyEngine) -> None:
    engine.add_rule(_rule(name="orgA-rule"), org_id="orgA")
    engine.add_rule(_rule(name="orgB-rule"), org_id="orgB")
    assert len(engine.list_rules("orgA")) == 1
    assert len(engine.list_rules("orgB")) == 1
    assert engine.list_rules("orgC") == []


# ---------------------------------------------------------------------------
# 2. Criteria matching — individual fields
# ---------------------------------------------------------------------------


def test_match_cve_pattern_matches(engine: ExceptionPolicyEngine) -> None:
    rule = engine.add_rule(_rule(action="suppress", cve_pattern=r"CVE-2024-\d+"), org_id=ORG)
    result = engine.evaluate_finding(_finding(cve_id="CVE-2024-9999"), org_id=ORG)
    assert result["action"] == "suppress"
    assert result["matched_rule_id"] == rule.id


def test_match_cve_pattern_no_match(engine: ExceptionPolicyEngine) -> None:
    engine.add_rule(_rule(action="suppress", cve_pattern=r"CVE-2023-\d+"), org_id=ORG)
    result = engine.evaluate_finding(_finding(cve_id="CVE-2024-9999"), org_id=ORG)
    assert result["action"] == "none"


def test_match_scanner(engine: ExceptionPolicyEngine) -> None:
    engine.add_rule(_rule(action="suppress", scanner="trivy"), org_id=ORG)
    result = engine.evaluate_finding(_finding(scanner="trivy"), org_id=ORG)
    assert result["action"] == "suppress"


def test_match_scanner_case_insensitive(engine: ExceptionPolicyEngine) -> None:
    engine.add_rule(_rule(action="suppress", scanner="TRIVY"), org_id=ORG)
    result = engine.evaluate_finding(_finding(scanner="trivy"), org_id=ORG)
    assert result["action"] == "suppress"


def test_match_scanner_no_match(engine: ExceptionPolicyEngine) -> None:
    engine.add_rule(_rule(action="suppress", scanner="grype"), org_id=ORG)
    result = engine.evaluate_finding(_finding(scanner="trivy"), org_id=ORG)
    assert result["action"] == "none"


def test_match_severity(engine: ExceptionPolicyEngine) -> None:
    engine.add_rule(_rule(action="suppress", severity="high"), org_id=ORG)
    result = engine.evaluate_finding(_finding(severity="high"), org_id=ORG)
    assert result["action"] == "suppress"


def test_match_severity_no_match(engine: ExceptionPolicyEngine) -> None:
    engine.add_rule(_rule(action="suppress", severity="critical"), org_id=ORG)
    result = engine.evaluate_finding(_finding(severity="high"), org_id=ORG)
    assert result["action"] == "none"


def test_match_min_age_days_passes(engine: ExceptionPolicyEngine) -> None:
    engine.add_rule(_rule(action="suppress", min_age_days=5), org_id=ORG)
    result = engine.evaluate_finding(_finding(age_days=10), org_id=ORG)
    assert result["action"] == "suppress"


def test_match_min_age_days_too_young(engine: ExceptionPolicyEngine) -> None:
    engine.add_rule(_rule(action="suppress", min_age_days=30), org_id=ORG)
    result = engine.evaluate_finding(_finding(age_days=5), org_id=ORG)
    assert result["action"] == "none"


def test_match_max_cvss_passes(engine: ExceptionPolicyEngine) -> None:
    engine.add_rule(_rule(action="suppress", max_cvss=8.0), org_id=ORG)
    result = engine.evaluate_finding(_finding(cvss=7.5), org_id=ORG)
    assert result["action"] == "suppress"


def test_match_max_cvss_too_high(engine: ExceptionPolicyEngine) -> None:
    engine.add_rule(_rule(action="suppress", max_cvss=6.0), org_id=ORG)
    result = engine.evaluate_finding(_finding(cvss=7.5), org_id=ORG)
    assert result["action"] == "none"


def test_match_component_pattern(engine: ExceptionPolicyEngine) -> None:
    engine.add_rule(_rule(action="suppress", component_pattern=r"log4.*"), org_id=ORG)
    result = engine.evaluate_finding(_finding(component="log4j"), org_id=ORG)
    assert result["action"] == "suppress"


def test_match_component_pattern_no_match(engine: ExceptionPolicyEngine) -> None:
    engine.add_rule(_rule(action="suppress", component_pattern=r"spring.*"), org_id=ORG)
    result = engine.evaluate_finding(_finding(component="log4j"), org_id=ORG)
    assert result["action"] == "none"


# ---------------------------------------------------------------------------
# 3. AND-combined criteria
# ---------------------------------------------------------------------------


def test_and_criteria_all_match(engine: ExceptionPolicyEngine) -> None:
    rule = _rule(
        action="suppress",
        cve_pattern=r"CVE-2024-\d+",
        severity="high",
        scanner="trivy",
    )
    engine.add_rule(rule, org_id=ORG)
    result = engine.evaluate_finding(
        _finding(cve_id="CVE-2024-1234", severity="high", scanner="trivy"),
        org_id=ORG,
    )
    assert result["action"] == "suppress"


def test_and_criteria_one_fails(engine: ExceptionPolicyEngine) -> None:
    rule = _rule(
        action="suppress",
        cve_pattern=r"CVE-2024-\d+",
        severity="critical",  # finding is "high" — should not match
        scanner="trivy",
    )
    engine.add_rule(rule, org_id=ORG)
    result = engine.evaluate_finding(
        _finding(cve_id="CVE-2024-1234", severity="high", scanner="trivy"),
        org_id=ORG,
    )
    assert result["action"] == "none"


# ---------------------------------------------------------------------------
# 4. Actions: suppress, downgrade, defer
# ---------------------------------------------------------------------------


def test_action_suppress(engine: ExceptionPolicyEngine) -> None:
    engine.add_rule(_rule(action="suppress", scanner="trivy"), org_id=ORG)
    result = engine.evaluate_finding(_finding(), org_id=ORG)
    assert result["action"] == "suppress"
    assert result["suppressed"] is True


def test_action_downgrade(engine: ExceptionPolicyEngine) -> None:
    engine.add_rule(_rule(action="downgrade", scanner="trivy", downgrade_to="low"), org_id=ORG)
    result = engine.evaluate_finding(_finding(severity="high"), org_id=ORG)
    assert result["action"] == "downgrade"
    assert result["new_severity"] == "low"
    assert result["original_severity"] == "high"
    assert result["suppressed"] is False


def test_action_defer(engine: ExceptionPolicyEngine) -> None:
    engine.add_rule(_rule(action="defer", scanner="trivy", defer_days=14), org_id=ORG)
    result = engine.evaluate_finding(_finding(), org_id=ORG)
    assert result["action"] == "defer"
    assert "defer_until" in result
    assert result["suppressed"] is False


def test_no_match_returns_none_action(engine: ExceptionPolicyEngine) -> None:
    result = engine.evaluate_finding(_finding(), org_id=ORG)
    assert result["action"] == "none"
    assert result["suppressed"] is False
    assert result["matched_rule_id"] is None


# ---------------------------------------------------------------------------
# 5. Rule expiration
# ---------------------------------------------------------------------------


def test_expired_rule_not_applied(engine: ExceptionPolicyEngine) -> None:
    past = datetime.now(timezone.utc) - timedelta(days=1)
    rule = _rule(action="suppress", scanner="trivy", expires_at=past)
    engine.add_rule(rule, org_id=ORG)
    result = engine.evaluate_finding(_finding(), org_id=ORG)
    assert result["action"] == "none"


def test_expire_rules_disables_expired(engine: ExceptionPolicyEngine) -> None:
    past = datetime.now(timezone.utc) - timedelta(days=1)
    future = datetime.now(timezone.utc) + timedelta(days=7)
    engine.add_rule(_rule(name="expired", expires_at=past), org_id=ORG)
    engine.add_rule(_rule(name="active", expires_at=future), org_id=ORG)

    count = engine.expire_rules(org_id=ORG)
    assert count == 1

    rules = engine.list_rules(org_id=ORG)
    disabled = [r for r in rules if not r.enabled]
    assert len(disabled) == 1
    assert disabled[0].name == "expired"


def test_expire_rules_no_expired(engine: ExceptionPolicyEngine) -> None:
    future = datetime.now(timezone.utc) + timedelta(days=7)
    engine.add_rule(_rule(expires_at=future), org_id=ORG)
    count = engine.expire_rules(org_id=ORG)
    assert count == 0


# ---------------------------------------------------------------------------
# 6. Version publish / rollback
# ---------------------------------------------------------------------------


def test_publish_version_increments(engine: ExceptionPolicyEngine) -> None:
    engine.add_rule(_rule(name="r1"), org_id=ORG)
    v1 = engine.publish_version(org_id=ORG, published_by="alice", changelog="initial")
    assert v1.version == 1
    v2 = engine.publish_version(org_id=ORG, published_by="bob", changelog="v2")
    assert v2.version == 2


def test_publish_version_captures_rules(engine: ExceptionPolicyEngine) -> None:
    engine.add_rule(_rule(name="snap-rule"), org_id=ORG)
    pv = engine.publish_version(org_id=ORG)
    assert len(pv.rules) == 1
    assert pv.rules[0].name == "snap-rule"


def test_get_version_history(engine: ExceptionPolicyEngine) -> None:
    engine.publish_version(org_id=ORG, changelog="v1")
    engine.publish_version(org_id=ORG, changelog="v2")
    history = engine.get_version_history(org_id=ORG)
    assert len(history) == 2
    # Newest first
    assert history[0].version == 2
    assert history[1].version == 1


def test_rollback_restores_rules(engine: ExceptionPolicyEngine) -> None:
    rule_a = engine.add_rule(_rule(name="rule-a"), org_id=ORG)
    engine.publish_version(org_id=ORG, changelog="v1 with rule-a")

    # Add another rule and publish v2
    engine.add_rule(_rule(name="rule-b"), org_id=ORG)
    engine.publish_version(org_id=ORG, changelog="v2 with rule-a + rule-b")

    # Rollback to v1 — should have only rule-a
    engine.rollback_to_version(org_id=ORG, version=1)
    rules = engine.list_rules(org_id=ORG)
    assert len(rules) == 1
    assert rules[0].name == "rule-a"


def test_rollback_not_found(engine: ExceptionPolicyEngine) -> None:
    with pytest.raises(KeyError):
        engine.rollback_to_version(org_id=ORG, version=99)


# ---------------------------------------------------------------------------
# 7. Batch evaluation
# ---------------------------------------------------------------------------


def test_evaluate_batch(engine: ExceptionPolicyEngine) -> None:
    engine.add_rule(_rule(action="suppress", scanner="trivy"), org_id=ORG)
    findings = [
        _finding(scanner="trivy"),
        _finding(scanner="grype"),  # won't match
    ]
    results = engine.evaluate_batch(findings, org_id=ORG)
    assert len(results) == 2
    actions = [r["action"] for r in results]
    assert "suppress" in actions
    assert "none" in actions


def test_evaluate_batch_empty_rules(engine: ExceptionPolicyEngine) -> None:
    findings = [_finding(), _finding()]
    results = engine.evaluate_batch(findings, org_id=ORG)
    assert all(r["action"] == "none" for r in results)


# ---------------------------------------------------------------------------
# 8. Re-evaluation
# ---------------------------------------------------------------------------


def test_re_evaluate_all_no_findings(engine: ExceptionPolicyEngine) -> None:
    result = engine.re_evaluate_all(org_id=ORG)
    assert result["total_evaluated"] == 0
    assert result["released"] == 0
    assert result["unchanged"] == 0


def test_re_evaluate_all_releases_finding(engine: ExceptionPolicyEngine) -> None:
    # Suppress a finding
    rule = engine.add_rule(_rule(action="suppress", scanner="trivy"), org_id=ORG)
    fid = str(uuid4())
    finding = _finding(scanner="trivy", fid=fid)
    res = engine.evaluate_finding(finding, org_id=ORG)
    assert res["action"] == "suppress"

    # Delete the rule — finding should now be released
    engine.delete_rule(rule.id, org_id=ORG)
    re_eval = engine.re_evaluate_all(org_id=ORG)
    assert re_eval["total_evaluated"] >= 1
    assert re_eval["released"] >= 1


# ---------------------------------------------------------------------------
# 9. Stats
# ---------------------------------------------------------------------------


def test_stats_empty(engine: ExceptionPolicyEngine) -> None:
    stats = engine.get_suppression_stats(org_id=ORG)
    assert stats["total_rules"] == 0
    assert stats["enabled_rules"] == 0
    assert stats["total_findings_acted"] == 0
    assert stats["by_action"] == {}


def test_stats_after_suppress(engine: ExceptionPolicyEngine) -> None:
    engine.add_rule(_rule(action="suppress", scanner="trivy"), org_id=ORG)
    engine.evaluate_finding(_finding(scanner="trivy"), org_id=ORG)

    stats = engine.get_suppression_stats(org_id=ORG)
    assert stats["total_rules"] == 1
    assert stats["enabled_rules"] == 1
    assert stats["total_findings_acted"] == 1
    assert stats["by_action"].get("suppress", 0) == 1


def test_stats_multiple_actions(engine: ExceptionPolicyEngine) -> None:
    engine.add_rule(_rule(action="suppress", scanner="trivy"), org_id=ORG)
    engine.add_rule(_rule(action="downgrade", scanner="grype", downgrade_to="low"), org_id=ORG)

    engine.evaluate_finding(_finding(scanner="trivy"), org_id=ORG)
    engine.evaluate_finding(_finding(scanner="grype"), org_id=ORG)

    stats = engine.get_suppression_stats(org_id=ORG)
    assert stats["total_rules"] == 2
    assert stats["by_action"].get("suppress", 0) >= 1
    assert stats["by_action"].get("downgrade", 0) >= 1


def test_stats_disabled_rules_counted(engine: ExceptionPolicyEngine) -> None:
    engine.add_rule(_rule(enabled=True), org_id=ORG)
    engine.add_rule(_rule(enabled=False), org_id=ORG)
    stats = engine.get_suppression_stats(org_id=ORG)
    assert stats["total_rules"] == 2
    assert stats["enabled_rules"] == 1
    assert stats["disabled_rules"] == 1


# ---------------------------------------------------------------------------
# 10. API Router
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def api_client():
    """TestClient for the exception policy router."""
    import tempfile

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    # Patch the engine in the router to use a temp DB
    _tmp = tempfile.mktemp(suffix=".db")
    from core.exception_policy import ExceptionPolicyEngine as EPE
    import apps.api.exception_policy_router as epr

    epr._engine = EPE(db_path=Path(_tmp))

    # Override auth dependency so tests don't need real tokens
    from apps.api.auth_deps import api_key_auth

    app = FastAPI()
    app.include_router(epr.router)
    app.dependency_overrides[api_key_auth] = lambda: None

    return TestClient(app)


def test_api_add_rule(api_client) -> None:
    payload = {
        "name": "api-test-rule",
        "description": "from test",
        "criteria": {"scanner": "trivy"},
        "action": "suppress",
    }
    resp = api_client.post("/api/v1/exceptions/rules", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "api-test-rule"
    assert "id" in data


def test_api_list_rules(api_client) -> None:
    resp = api_client.get("/api/v1/exceptions/rules")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_api_update_rule(api_client) -> None:
    # Create a rule first
    payload = {
        "name": "to-update",
        "criteria": {"severity": "low"},
        "action": "suppress",
    }
    created = api_client.post("/api/v1/exceptions/rules", json=payload).json()
    rule_id = created["id"]

    update = {"name": "updated-name"}
    resp = api_client.put(f"/api/v1/exceptions/rules/{rule_id}", json=update)
    assert resp.status_code == 200
    assert resp.json()["name"] == "updated-name"
    assert resp.json()["version"] == 2


def test_api_delete_rule(api_client) -> None:
    payload = {
        "name": "to-delete",
        "criteria": {},
        "action": "suppress",
    }
    created = api_client.post("/api/v1/exceptions/rules", json=payload).json()
    rule_id = created["id"]

    resp = api_client.delete(f"/api/v1/exceptions/rules/{rule_id}")
    assert resp.status_code == 204


def test_api_delete_rule_not_found(api_client) -> None:
    resp = api_client.delete("/api/v1/exceptions/rules/nonexistent-999")
    assert resp.status_code == 404


def test_api_evaluate(api_client) -> None:
    # Add a rule
    api_client.post(
        "/api/v1/exceptions/rules",
        json={"name": "eval-rule", "criteria": {"severity": "info"}, "action": "suppress"},
    )
    payload = {
        "findings": [
            {"id": "f1", "severity": "info", "source": "trivy"},
            {"id": "f2", "severity": "critical", "source": "trivy"},
        ]
    }
    resp = api_client.post("/api/v1/exceptions/evaluate", json=payload)
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) == 2


def test_api_publish_and_versions(api_client) -> None:
    payload = {"published_by": "tester", "changelog": "test publish"}
    resp = api_client.post("/api/v1/exceptions/publish", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["published_by"] == "tester"
    assert data["version"] >= 1

    hist_resp = api_client.get("/api/v1/exceptions/versions")
    assert hist_resp.status_code == 200
    assert len(hist_resp.json()) >= 1


def test_api_rollback(api_client) -> None:
    # Publish a version first
    pub = api_client.post(
        "/api/v1/exceptions/publish",
        json={"published_by": "tester", "changelog": "rollback test"},
    ).json()
    version = pub["version"]

    resp = api_client.post("/api/v1/exceptions/rollback", json={"version": version})
    assert resp.status_code == 200
    assert resp.json()["rolled_back_to"] == version


def test_api_rollback_not_found(api_client) -> None:
    resp = api_client.post("/api/v1/exceptions/rollback", json={"version": 9999})
    assert resp.status_code == 404


def test_api_stats(api_client) -> None:
    resp = api_client.get("/api/v1/exceptions/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_rules" in data
    assert "enabled_rules" in data
    assert "by_action" in data
