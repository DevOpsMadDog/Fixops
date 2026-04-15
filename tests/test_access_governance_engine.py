"""Tests for AccessGovernanceEngine — 35+ tests."""

import os
import sys
from datetime import datetime, timezone, timedelta

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from core.access_governance_engine import AccessGovernanceEngine


@pytest.fixture
def engine(tmp_path):
    return AccessGovernanceEngine(db_path=str(tmp_path / "test.db"))


ORG = "org-ag-001"
USER = "user-alice"
USER2 = "user-bob"


# ---------------------------------------------------------------------------
# grant_entitlement
# ---------------------------------------------------------------------------

class TestGrantEntitlement:
    def test_basic_grant(self, engine):
        ent = engine.grant_entitlement(
            ORG, USER, "app-crm", "application", "read", granted_by="admin"
        )
        assert ent["id"]
        assert ent["user_id"] == USER
        assert ent["resource_id"] == "app-crm"
        assert ent["resource_type"] == "application"
        assert ent["access_level"] == "read"
        assert ent["status"] == "active"
        assert ent["granted_by"] == "admin"

    def test_all_resource_types(self, engine):
        for rt in ["application", "database", "server", "network",
                   "cloud-service", "api", "data-store", "vault"]:
            ent = engine.grant_entitlement(ORG, USER, f"res-{rt}", rt, "read")
            assert ent["resource_type"] == rt

    def test_all_access_levels(self, engine):
        for level in ["read", "write", "admin", "execute", "delete", "full-control"]:
            ent = engine.grant_entitlement(ORG, USER, f"res-{level}", "application", level)
            assert ent["access_level"] == level

    def test_invalid_resource_type_raises(self, engine):
        with pytest.raises(ValueError, match="resource_type"):
            engine.grant_entitlement(ORG, USER, "r1", "invalid_type", "read")

    def test_invalid_access_level_raises(self, engine):
        with pytest.raises(ValueError, match="access_level"):
            engine.grant_entitlement(ORG, USER, "r1", "application", "superpower")

    def test_with_expires_at(self, engine):
        future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        ent = engine.grant_entitlement(
            ORG, USER, "r2", "database", "write", expires_at=future
        )
        assert ent["expires_at"] == future

    def test_org_isolation(self, engine):
        engine.grant_entitlement("org-a", USER, "r", "application", "read")
        engine.grant_entitlement("org-b", USER, "r", "application", "admin")
        ents_a = engine.get_user_entitlements("org-a", USER)
        ents_b = engine.get_user_entitlements("org-b", USER)
        assert ents_a[0]["access_level"] == "read"
        assert ents_b[0]["access_level"] == "admin"


# ---------------------------------------------------------------------------
# revoke_entitlement
# ---------------------------------------------------------------------------

class TestRevokeEntitlement:
    def test_revoke_changes_status(self, engine):
        ent = engine.grant_entitlement(ORG, USER, "r3", "server", "read")
        revoked = engine.revoke_entitlement(ent["id"], ORG)
        assert revoked["status"] == "revoked"

    def test_revoke_not_found_raises(self, engine):
        with pytest.raises(KeyError):
            engine.revoke_entitlement("nonexistent-id", ORG)

    def test_revoke_wrong_org_raises(self, engine):
        ent = engine.grant_entitlement(ORG, USER, "r4", "network", "write")
        with pytest.raises(KeyError):
            engine.revoke_entitlement(ent["id"], "wrong-org")


# ---------------------------------------------------------------------------
# detect_sod_violations
# ---------------------------------------------------------------------------

class TestDetectSodViolations:
    def test_violation_triggers_when_user_has_all_entitlements(self, engine):
        e1 = engine.grant_entitlement(ORG, USER, "finance-app", "application", "write")
        e2 = engine.grant_entitlement(ORG, USER, "payment-db", "database", "admin")
        rules = [
            {
                "rule_name": "finance_sod",
                "entitlement_ids": [e1["id"], e2["id"]],
                "severity": "critical",
            }
        ]
        violations = engine.detect_sod_violations(ORG, USER, rules)
        assert len(violations) == 1
        assert violations[0]["rule_name"] == "finance_sod"
        assert violations[0]["severity"] == "critical"
        assert violations[0]["status"] == "open"

    def test_no_violation_when_partial_entitlements(self, engine):
        e1 = engine.grant_entitlement(ORG, USER2, "res-x", "application", "read")
        rules = [
            {
                "rule_name": "partial_rule",
                "entitlement_ids": [e1["id"], "nonexistent-id"],
                "severity": "high",
            }
        ]
        violations = engine.detect_sod_violations(ORG, USER2, rules)
        assert len(violations) == 0

    def test_no_violation_when_no_entitlements_match(self, engine):
        rules = [
            {
                "rule_name": "ghost_rule",
                "entitlement_ids": ["fake-id-1", "fake-id-2"],
                "severity": "medium",
            }
        ]
        violations = engine.detect_sod_violations(ORG, USER, rules)
        assert len(violations) == 0

    def test_no_duplicate_violation_for_same_rule(self, engine):
        e1 = engine.grant_entitlement(ORG, USER, "dup-res", "api", "admin")
        e2 = engine.grant_entitlement(ORG, USER, "dup-res2", "vault", "full-control")
        rules = [
            {
                "rule_name": "dup_rule",
                "entitlement_ids": [e1["id"], e2["id"]],
                "severity": "high",
            }
        ]
        engine.detect_sod_violations(ORG, USER, rules)
        second = engine.detect_sod_violations(ORG, USER, rules)
        assert len(second) == 0  # Already open

    def test_revoked_entitlement_does_not_trigger(self, engine):
        e1 = engine.grant_entitlement(ORG, USER, "revoked-res", "database", "write")
        e2 = engine.grant_entitlement(ORG, USER, "active-res", "server", "read")
        engine.revoke_entitlement(e1["id"], ORG)
        rules = [
            {
                "rule_name": "revoke_rule",
                "entitlement_ids": [e1["id"], e2["id"]],
                "severity": "critical",
            }
        ]
        violations = engine.detect_sod_violations(ORG, USER, rules)
        assert len(violations) == 0

    def test_empty_rule_list_returns_empty(self, engine):
        violations = engine.detect_sod_violations(ORG, USER, [])
        assert violations == []

    def test_empty_entitlement_ids_skipped(self, engine):
        rules = [{"rule_name": "empty_rule", "entitlement_ids": [], "severity": "medium"}]
        violations = engine.detect_sod_violations(ORG, USER, rules)
        assert len(violations) == 0

    def test_multiple_rules_multiple_violations(self, engine):
        e1 = engine.grant_entitlement(ORG, "multi-user", "a1", "application", "admin")
        e2 = engine.grant_entitlement(ORG, "multi-user", "a2", "database", "full-control")
        e3 = engine.grant_entitlement(ORG, "multi-user", "a3", "vault", "write")
        rules = [
            {"rule_name": "rule_1", "entitlement_ids": [e1["id"], e2["id"]], "severity": "high"},
            {"rule_name": "rule_2", "entitlement_ids": [e2["id"], e3["id"]], "severity": "critical"},
        ]
        violations = engine.detect_sod_violations(ORG, "multi-user", rules)
        assert len(violations) == 2


# ---------------------------------------------------------------------------
# acknowledge_violation
# ---------------------------------------------------------------------------

class TestAcknowledgeViolation:
    def test_acknowledge_sets_status(self, engine):
        e1 = engine.grant_entitlement(ORG, USER, "ack-r1", "application", "admin")
        e2 = engine.grant_entitlement(ORG, USER, "ack-r2", "database", "full-control")
        rules = [{"rule_name": "ack_rule", "entitlement_ids": [e1["id"], e2["id"]], "severity": "high"}]
        viol = engine.detect_sod_violations(ORG, USER, rules)[0]
        acked = engine.acknowledge_violation(viol["id"], ORG, "security-analyst")
        assert acked["status"] == "acknowledged"
        assert acked["acknowledged_by"] == "security-analyst"
        assert acked["acknowledged_at"] is not None

    def test_acknowledge_not_found_raises(self, engine):
        with pytest.raises(KeyError):
            engine.acknowledge_violation("fake-id", ORG, "admin")

    def test_acknowledge_wrong_org_raises(self, engine):
        e1 = engine.grant_entitlement(ORG, USER, "ack-r3", "api", "write")
        e2 = engine.grant_entitlement(ORG, USER, "ack-r4", "vault", "admin")
        rules = [{"rule_name": "wrong_org_rule", "entitlement_ids": [e1["id"], e2["id"]], "severity": "medium"}]
        viol = engine.detect_sod_violations(ORG, USER, rules)[0]
        with pytest.raises(KeyError):
            engine.acknowledge_violation(viol["id"], "wrong-org", "admin")


# ---------------------------------------------------------------------------
# create_role / assign_role_to_user
# ---------------------------------------------------------------------------

class TestRoles:
    def test_create_role_basic(self, engine):
        role = engine.create_role(
            ORG, "security-analyst", "business", ["view_alerts", "triage"], owner="ciso"
        )
        assert role["role_name"] == "security-analyst"
        assert role["role_type"] == "business"
        assert role["user_count"] == 0
        assert role["owner"] == "ciso"

    def test_all_role_types(self, engine):
        for rt in ["business", "technical", "privileged", "service-account", "emergency"]:
            role = engine.create_role(ORG, f"role-{rt}", rt, [])
            assert role["role_type"] == rt

    def test_invalid_role_type_raises(self, engine):
        with pytest.raises(ValueError, match="role_type"):
            engine.create_role(ORG, "bad-role", "invalid_type", [])

    def test_invalid_risk_level_raises(self, engine):
        with pytest.raises(ValueError, match="risk_level"):
            engine.create_role(ORG, "bad-risk", "business", [], risk_level="extreme")

    def test_assign_role_increments_user_count(self, engine):
        role = engine.create_role(ORG, "dev-role", "technical", ["read_code"], owner="cto")
        updated = engine.assign_role_to_user(role["id"], ORG, USER)
        assert updated["user_count"] == 1
        updated2 = engine.assign_role_to_user(role["id"], ORG, USER2)
        assert updated2["user_count"] == 2

    def test_assign_role_grants_entitlements(self, engine):
        role = engine.create_role(ORG, "perm-role", "privileged", ["perm_a", "perm_b"])
        engine.assign_role_to_user(role["id"], ORG, "user-xyz")
        ents = engine.get_user_entitlements(ORG, "user-xyz")
        assert len(ents) == 2  # one per permission

    def test_assign_role_not_found_raises(self, engine):
        with pytest.raises(KeyError):
            engine.assign_role_to_user("nonexistent-role-id", ORG, USER)

    def test_assign_role_wrong_org_raises(self, engine):
        role = engine.create_role(ORG, "org-role", "business", [])
        with pytest.raises(KeyError):
            engine.assign_role_to_user(role["id"], "wrong-org", USER)


# ---------------------------------------------------------------------------
# get_user_entitlements / get_expiring_entitlements
# ---------------------------------------------------------------------------

class TestEntitlementQueries:
    def test_get_user_entitlements_all(self, engine):
        engine.grant_entitlement(ORG, USER, "r-a", "application", "read")
        engine.grant_entitlement(ORG, USER, "r-b", "database", "write")
        ents = engine.get_user_entitlements(ORG, USER)
        assert len(ents) == 2

    def test_get_user_entitlements_filtered_by_status(self, engine):
        ent = engine.grant_entitlement(ORG, USER, "r-c", "server", "read")
        engine.revoke_entitlement(ent["id"], ORG)
        engine.grant_entitlement(ORG, USER, "r-d", "network", "read")
        active = engine.get_user_entitlements(ORG, USER, status="active")
        revoked = engine.get_user_entitlements(ORG, USER, status="revoked")
        assert all(e["status"] == "active" for e in active)
        assert all(e["status"] == "revoked" for e in revoked)

    def test_get_expiring_entitlements(self, engine):
        soon = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
        far = (datetime.now(timezone.utc) + timedelta(days=60)).isoformat()
        engine.grant_entitlement(ORG, USER, "exp-soon", "application", "read", expires_at=soon)
        engine.grant_entitlement(ORG, USER, "exp-far", "application", "read", expires_at=far)
        expiring = engine.get_expiring_entitlements(ORG, days_ahead=30)
        assert len(expiring) == 1
        assert expiring[0]["resource_id"] == "exp-soon"

    def test_get_expiring_excludes_revoked(self, engine):
        soon = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
        ent = engine.grant_entitlement(ORG, USER, "exp-revoked", "vault", "read", expires_at=soon)
        engine.revoke_entitlement(ent["id"], ORG)
        expiring = engine.get_expiring_entitlements(ORG, days_ahead=30)
        ids = [e["resource_id"] for e in expiring]
        assert "exp-revoked" not in ids

    def test_get_expiring_no_expires_at_excluded(self, engine):
        engine.grant_entitlement(ORG, USER, "no-expire", "api", "read")
        expiring = engine.get_expiring_entitlements(ORG, days_ahead=30)
        ids = [e["resource_id"] for e in expiring]
        assert "no-expire" not in ids


# ---------------------------------------------------------------------------
# get_access_summary
# ---------------------------------------------------------------------------

class TestAccessSummary:
    def test_empty_org_summary(self, engine):
        s = engine.get_access_summary("empty-org")
        assert s["total_entitlements"] == 0
        assert s["active_entitlements"] == 0
        assert s["revoked_entitlements"] == 0
        assert s["violations_open"] == 0
        assert s["high_risk_roles"] == 0

    def test_summary_counts(self, engine):
        e1 = engine.grant_entitlement(ORG, USER, "s-r1", "application", "read")
        e2 = engine.grant_entitlement(ORG, USER, "s-r2", "database", "write")
        engine.revoke_entitlement(e1["id"], ORG)

        # Create a SoD violation
        e3 = engine.grant_entitlement(ORG, USER, "s-r3", "vault", "admin")
        rules = [{"rule_name": "sum_rule", "entitlement_ids": [e2["id"], e3["id"]], "severity": "critical"}]
        engine.detect_sod_violations(ORG, USER, rules)

        # High-risk role
        engine.create_role(ORG, "hi-risk", "privileged", [], risk_level="high")
        engine.create_role(ORG, "crit-risk", "privileged", [], risk_level="critical")
        engine.create_role(ORG, "low-risk", "business", [], risk_level="low")

        s = engine.get_access_summary(ORG)
        assert s["total_entitlements"] == 3
        assert s["active_entitlements"] == 2
        assert s["revoked_entitlements"] == 1
        assert s["violations_open"] == 1
        assert s["high_risk_roles"] == 2
