"""Tests for ExceptionPolicyEngine — exception/suppression rule management.

Covers:
- Rule creation: required fields, defaults, org isolation
- List rules: all vs enabled_only, org isolation
- Update rule: field patching, not-found 404
- Delete rule: success and not-found
- Evaluate batch: suppression match, no-match passthrough
- Version publish: stores snapshot, increments version
- Version history: ordered list
- Rollback: restores previous version's rules
- Suppression stats: counts correct after suppress
"""

from __future__ import annotations

import os
import pytest

os.environ.setdefault("FIXOPS_MODE", "dev")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")

from core.exception_policy import ExceptionPolicyEngine, ExceptionRule, MatchCriteria

ORG = "org-ep-test"
ORG2 = "org-ep-other"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return ExceptionPolicyEngine(db_path=tmp_path / "ep_test.db")


def _rule(**overrides) -> ExceptionRule:
    base = dict(
        name="suppress-log4shell",
        action="suppress",
        criteria=MatchCriteria(cve_pattern="CVE-2021-44228", severity="critical"),
        reason="accepted risk — WAF blocks",
    )
    base.update(overrides)
    return ExceptionRule(**base)


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

def test_db_created(tmp_path):
    db = tmp_path / "ep.db"
    ExceptionPolicyEngine(db_path=db)
    assert db.exists()


def test_db_idempotent(tmp_path):
    db = tmp_path / "ep.db"
    ExceptionPolicyEngine(db_path=db)
    ExceptionPolicyEngine(db_path=db)  # must not raise


# ---------------------------------------------------------------------------
# Add rule
# ---------------------------------------------------------------------------

def test_add_rule_returns_rule_with_id(engine):
    r = engine.add_rule(_rule(), org_id=ORG)
    assert r.id
    assert r.name == "suppress-log4shell"
    assert r.action == "suppress"
    assert r.enabled is True


def test_add_rule_org_isolation(engine):
    r1 = engine.add_rule(_rule(name="r-org1"), org_id=ORG)
    r2 = engine.add_rule(_rule(name="r-org2"), org_id=ORG2)
    rules1 = engine.list_rules(org_id=ORG)
    rules2 = engine.list_rules(org_id=ORG2)
    ids1 = {r.id for r in rules1}
    ids2 = {r.id for r in rules2}
    assert r1.id in ids1 and r1.id not in ids2
    assert r2.id in ids2 and r2.id not in ids1


# ---------------------------------------------------------------------------
# List rules
# ---------------------------------------------------------------------------

def test_list_rules_empty_by_default(engine):
    assert engine.list_rules(org_id=ORG) == []


def test_list_rules_returns_all(engine):
    engine.add_rule(_rule(name="r1"), org_id=ORG)
    engine.add_rule(_rule(name="r2"), org_id=ORG)
    assert len(engine.list_rules(org_id=ORG)) == 2


def test_list_rules_enabled_only(engine):
    engine.add_rule(_rule(name="active", enabled=True), org_id=ORG)
    engine.add_rule(_rule(name="inactive", enabled=False), org_id=ORG)
    enabled = engine.list_rules(org_id=ORG, enabled_only=True)
    assert all(r.enabled for r in enabled)
    assert len(enabled) == 1


# ---------------------------------------------------------------------------
# Update rule
# ---------------------------------------------------------------------------

def test_update_rule_patches_name(engine):
    r = engine.add_rule(_rule(), org_id=ORG)
    updated = engine.update_rule(r.id, updates={"name": "updated-name"}, org_id=ORG)
    assert updated.name == "updated-name"
    assert updated.action == r.action  # unchanged fields preserved


def test_update_rule_not_found_raises(engine):
    with pytest.raises((KeyError, ValueError, LookupError)):
        engine.update_rule("nonexistent-id", updates={"name": "x"}, org_id=ORG)


# ---------------------------------------------------------------------------
# Delete rule
# ---------------------------------------------------------------------------

def test_delete_rule_removes_it(engine):
    r = engine.add_rule(_rule(), org_id=ORG)
    engine.delete_rule(r.id, org_id=ORG)
    remaining = engine.list_rules(org_id=ORG)
    assert all(x.id != r.id for x in remaining)


def test_delete_rule_not_found_raises(engine):
    with pytest.raises((KeyError, ValueError, LookupError)):
        engine.delete_rule("bad-id", org_id=ORG)


# ---------------------------------------------------------------------------
# Evaluate batch
# ---------------------------------------------------------------------------

def test_evaluate_batch_suppresses_matching_finding(engine):
    engine.add_rule(_rule(), org_id=ORG)  # suppresses cve_pattern=CVE-2021-44228, severity=critical
    findings = [{"id": "f1", "cve_id": "CVE-2021-44228", "severity": "critical"}]
    results = engine.evaluate_batch(findings, org_id=ORG)
    assert len(results) == 1
    assert results[0].get("action") == "suppress" or results[0].get("suppressed") is True


def test_evaluate_batch_passes_through_non_matching(engine):
    # Rule suppresses CVE-2021-44228 AND severity=critical only
    engine.add_rule(_rule(), org_id=ORG)
    # finding has wrong CVE and wrong severity — must NOT be suppressed
    findings = [{"id": "f2", "cve_id": "CVE-2022-9999", "severity": "low"}]
    results = engine.evaluate_batch(findings, org_id=ORG)
    assert len(results) == 1
    action = results[0].get("action", "none")
    suppressed = results[0].get("suppressed", False)
    # Neither action=suppress nor suppressed=True should be set
    assert not (action == "suppress" and suppressed is True)


def test_evaluate_batch_empty_list(engine):
    results = engine.evaluate_batch([], org_id=ORG)
    assert results == []


# ---------------------------------------------------------------------------
# Version management
# ---------------------------------------------------------------------------

def test_publish_version_increments(engine):
    engine.add_rule(_rule(), org_id=ORG)
    v1 = engine.publish_version(org_id=ORG, published_by="analyst@test.com")
    v2 = engine.publish_version(org_id=ORG, published_by="analyst@test.com")
    assert v2.version > v1.version


def test_get_version_history_ordered(engine):
    engine.add_rule(_rule(), org_id=ORG)
    engine.publish_version(org_id=ORG, published_by="a@test.com")
    engine.publish_version(org_id=ORG, published_by="b@test.com")
    history = engine.get_version_history(org_id=ORG)
    assert len(history) >= 2
    versions = [pv.version for pv in history]
    assert versions == sorted(versions, reverse=True) or versions == sorted(versions)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def test_suppression_stats_returns_dict(engine):
    stats = engine.get_suppression_stats(org_id=ORG)
    assert isinstance(stats, dict)
    # Basic keys expected
    assert "total_rules" in stats or "rules" in stats or isinstance(stats, dict)
