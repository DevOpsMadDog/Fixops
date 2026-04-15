"""Tests for FirewallManagementEngine — ALDECI.

Tests:
  - Firewall CRUD
  - Rule CRUD with automatic risk analysis
  - Shadowed rule detection
  - Change request lifecycle (pending → approved → implemented / rejected)
  - Compliance scan and violation detection
  - Violation management
  - Stats aggregation
  - Org isolation
"""

from __future__ import annotations

import json

import pytest

from core.firewall_management_engine import FirewallManagementEngine


@pytest.fixture
def tmp_engine(tmp_path):
    """Return a FirewallManagementEngine using a temp directory."""
    return FirewallManagementEngine(db_dir=str(tmp_path))


@pytest.fixture
def org():
    return "fw_test_org_001"


@pytest.fixture
def org2():
    return "fw_test_org_002"


@pytest.fixture
def firewall(tmp_engine, org):
    """Create a test firewall and return its record."""
    return tmp_engine.add_firewall(org, {
        "name": "Edge Firewall",
        "vendor": "palo_alto",
        "fw_type": "perimeter",
        "ip_address": "10.0.0.1",
    })


# ---------------------------------------------------------------------------
# Firewall CRUD tests
# ---------------------------------------------------------------------------

class TestFirewallCRUD:
    def test_add_firewall(self, tmp_engine, org):
        fw = tmp_engine.add_firewall(org, {
            "name": "Core FW",
            "vendor": "cisco_asa",
            "fw_type": "internal",
        })
        assert fw["id"]
        assert fw["name"] == "Core FW"
        assert fw["vendor"] == "cisco_asa"
        assert fw["status"] == "online"

    def test_add_firewall_missing_name_raises(self, tmp_engine, org):
        with pytest.raises(ValueError, match="name"):
            tmp_engine.add_firewall(org, {"vendor": "fortinet"})

    def test_add_firewall_invalid_vendor_raises(self, tmp_engine, org):
        with pytest.raises(ValueError, match="vendor"):
            tmp_engine.add_firewall(org, {"name": "FW", "vendor": "unknownvendor"})

    def test_add_firewall_invalid_type_raises(self, tmp_engine, org):
        with pytest.raises(ValueError, match="fw_type"):
            tmp_engine.add_firewall(org, {"name": "FW", "fw_type": "magic"})

    def test_list_firewalls(self, tmp_engine, org):
        tmp_engine.add_firewall(org, {"name": "FW1"})
        tmp_engine.add_firewall(org, {"name": "FW2"})
        fws = tmp_engine.list_firewalls(org)
        assert len(fws) == 2

    def test_list_firewalls_filter_by_status(self, tmp_engine, org):
        tmp_engine.add_firewall(org, {"name": "FW1"})
        fws = tmp_engine.list_firewalls(org, status="online")
        assert len(fws) == 1
        assert fws[0]["status"] == "online"

    def test_get_firewall(self, tmp_engine, org, firewall):
        fw = tmp_engine.get_firewall(org, firewall["id"])
        assert fw is not None
        assert fw["id"] == firewall["id"]

    def test_get_firewall_nonexistent_returns_none(self, tmp_engine, org):
        assert tmp_engine.get_firewall(org, "nonexistent-id") is None


# ---------------------------------------------------------------------------
# Rule CRUD and risk analysis tests
# ---------------------------------------------------------------------------

class TestRuleCRUD:
    def test_add_rule_basic(self, tmp_engine, org, firewall):
        rule = tmp_engine.add_rule(org, {
            "firewall_id": firewall["id"],
            "rule_name": "Allow HTTP",
            "src_address": "10.0.0.0/8",
            "dst_address": "0.0.0.0/0",
            "service": ["80", "443"],
            "action": "allow",
        })
        assert rule["id"]
        assert rule["rule_name"] == "Allow HTTP"
        assert rule["action"] == "allow"
        assert isinstance(rule["service"], list)

    def test_missing_firewall_id_raises(self, tmp_engine, org):
        with pytest.raises(ValueError, match="firewall_id"):
            tmp_engine.add_rule(org, {"rule_name": "Test"})

    def test_invalid_action_raises(self, tmp_engine, org, firewall):
        with pytest.raises(ValueError, match="action"):
            tmp_engine.add_rule(org, {
                "firewall_id": firewall["id"],
                "action": "permit",
            })

    def test_rule_count_increments_on_firewall(self, tmp_engine, org, firewall):
        tmp_engine.add_rule(org, {"firewall_id": firewall["id"], "action": "allow"})
        tmp_engine.add_rule(org, {"firewall_id": firewall["id"], "action": "deny"})
        fw = tmp_engine.get_firewall(org, firewall["id"])
        assert fw["rule_count"] == 2

    def test_list_rules(self, tmp_engine, org, firewall):
        tmp_engine.add_rule(org, {"firewall_id": firewall["id"], "action": "allow"})
        tmp_engine.add_rule(org, {"firewall_id": firewall["id"], "action": "deny"})
        rules = tmp_engine.list_rules(org)
        assert len(rules) == 2

    def test_list_rules_filter_by_firewall(self, tmp_engine, org):
        fw1 = tmp_engine.add_firewall(org, {"name": "FW1"})
        fw2 = tmp_engine.add_firewall(org, {"name": "FW2"})
        tmp_engine.add_rule(org, {"firewall_id": fw1["id"], "action": "allow"})
        tmp_engine.add_rule(org, {"firewall_id": fw2["id"], "action": "deny"})
        rules_fw1 = tmp_engine.list_rules(org, firewall_id=fw1["id"])
        assert len(rules_fw1) == 1

    def test_disable_rule(self, tmp_engine, org, firewall):
        rule = tmp_engine.add_rule(org, {"firewall_id": firewall["id"], "action": "allow"})
        result = tmp_engine.disable_rule(org, rule["id"])
        assert result is True
        rules = tmp_engine.list_rules(org, status="disabled")
        assert any(r["id"] == rule["id"] for r in rules)

    def test_disable_nonexistent_rule_returns_false(self, tmp_engine, org):
        assert tmp_engine.disable_rule(org, "nonexistent-id") is False


# ---------------------------------------------------------------------------
# Risk analysis tests
# ---------------------------------------------------------------------------

class TestRiskAnalysis:
    def test_any_any_allow_is_critical(self, tmp_engine, org, firewall):
        rule = tmp_engine.add_rule(org, {
            "firewall_id": firewall["id"],
            "src_address": "any",
            "dst_address": "any",
            "action": "allow",
        })
        assert rule["risk_level"] == "critical"

    def test_any_src_allow_is_high(self, tmp_engine, org, firewall):
        rule = tmp_engine.add_rule(org, {
            "firewall_id": firewall["id"],
            "src_address": "any",
            "dst_address": "192.168.1.0/24",
            "action": "allow",
        })
        assert rule["risk_level"] == "high"

    def test_insecure_port_23_is_high(self, tmp_engine, org, firewall):
        rule = tmp_engine.add_rule(org, {
            "firewall_id": firewall["id"],
            "src_address": "192.168.1.0/24",
            "dst_address": "10.0.0.1",
            "service": ["23"],
            "action": "allow",
        })
        assert rule["risk_level"] == "high"

    def test_insecure_port_445_is_high(self, tmp_engine, org, firewall):
        rule = tmp_engine.add_rule(org, {
            "firewall_id": firewall["id"],
            "service": ["445"],
            "action": "allow",
            "src_address": "10.0.0.1",
            "dst_address": "10.0.0.2",
        })
        assert rule["risk_level"] == "high"

    def test_deny_rule_is_low(self, tmp_engine, org, firewall):
        rule = tmp_engine.add_rule(org, {
            "firewall_id": firewall["id"],
            "src_address": "any",
            "dst_address": "any",
            "action": "deny",
        })
        assert rule["risk_level"] == "low"

    def test_specific_src_dst_allow_is_info(self, tmp_engine, org, firewall):
        rule = tmp_engine.add_rule(org, {
            "firewall_id": firewall["id"],
            "src_address": "192.168.1.100",
            "dst_address": "10.0.0.50",
            "service": ["443"],
            "action": "allow",
        })
        assert rule["risk_level"] == "info"


# ---------------------------------------------------------------------------
# Shadowed rule detection tests
# ---------------------------------------------------------------------------

class TestShadowedRules:
    def test_detect_shadowed_rule(self, tmp_engine, org, firewall):
        fid = firewall["id"]
        # Rule A: first - covers same match
        tmp_engine.add_rule(org, {
            "firewall_id": fid,
            "src_address": "10.0.0.0/8",
            "dst_address": "0.0.0.0/0",
            "service": ["80"],
            "action": "allow",
        })
        # Rule B: same match, added after - should be shadowed
        rule_b = tmp_engine.add_rule(org, {
            "firewall_id": fid,
            "src_address": "10.0.0.0/8",
            "dst_address": "0.0.0.0/0",
            "service": ["80"],
            "action": "deny",
        })
        shadowed = tmp_engine.detect_shadowed_rules(org, fid)
        assert rule_b["id"] in shadowed

    def test_no_shadow_with_different_services(self, tmp_engine, org, firewall):
        fid = firewall["id"]
        tmp_engine.add_rule(org, {
            "firewall_id": fid,
            "src_address": "10.0.0.0/8",
            "dst_address": "any",
            "service": ["80"],
            "action": "allow",
        })
        tmp_engine.add_rule(org, {
            "firewall_id": fid,
            "src_address": "10.0.0.0/8",
            "dst_address": "any",
            "service": ["443"],
            "action": "allow",
        })
        shadowed = tmp_engine.detect_shadowed_rules(org, fid)
        assert len(shadowed) == 0

    def test_shadowed_flag_set_in_db(self, tmp_engine, org, firewall):
        fid = firewall["id"]
        tmp_engine.add_rule(org, {
            "firewall_id": fid, "src_address": "any",
            "dst_address": "any", "service": ["22"], "action": "allow",
        })
        rule_b = tmp_engine.add_rule(org, {
            "firewall_id": fid, "src_address": "any",
            "dst_address": "any", "service": ["22"], "action": "deny",
        })
        tmp_engine.detect_shadowed_rules(org, fid)
        rules = tmp_engine.list_rules(org)
        b = next(r for r in rules if r["id"] == rule_b["id"])
        assert b["is_shadowed"] is True


# ---------------------------------------------------------------------------
# Change request lifecycle tests
# ---------------------------------------------------------------------------

class TestChangeRequests:
    def test_create_change_request(self, tmp_engine, org, firewall):
        cr = tmp_engine.create_change_request(org, {
            "firewall_id": firewall["id"],
            "change_type": "add",
            "requester": "alice@corp.com",
            "business_justification": "Allow new SaaS tool",
            "rules_json": [{"action": "allow", "service": ["443"]}],
        })
        assert cr["id"]
        assert cr["status"] == "pending"
        assert cr["requester"] == "alice@corp.com"
        assert isinstance(cr["rules_json"], list)

    def test_missing_firewall_id_raises(self, tmp_engine, org):
        with pytest.raises(ValueError, match="firewall_id"):
            tmp_engine.create_change_request(org, {"change_type": "add"})

    def test_invalid_change_type_raises(self, tmp_engine, org, firewall):
        with pytest.raises(ValueError, match="change_type"):
            tmp_engine.create_change_request(org, {
                "firewall_id": firewall["id"],
                "change_type": "hack",
            })

    def test_approve_change_request(self, tmp_engine, org, firewall):
        cr = tmp_engine.create_change_request(org, {
            "firewall_id": firewall["id"],
            "change_type": "add",
        })
        result = tmp_engine.approve_change_request(org, cr["id"], approver="bob@corp.com")
        assert result is True
        crs = tmp_engine.list_change_requests(org, status="approved")
        assert any(c["id"] == cr["id"] for c in crs)

    def test_approve_nonexistent_returns_false(self, tmp_engine, org):
        result = tmp_engine.approve_change_request(org, "nonexistent-id", approver="bob")
        assert result is False

    def test_reject_change_request(self, tmp_engine, org, firewall):
        cr = tmp_engine.create_change_request(org, {
            "firewall_id": firewall["id"],
            "change_type": "delete",
        })
        result = tmp_engine.reject_change_request(org, cr["id"], approver="bob@corp.com")
        assert result is True
        crs = tmp_engine.list_change_requests(org, status="rejected")
        assert any(c["id"] == cr["id"] for c in crs)

    def test_implement_change_request(self, tmp_engine, org, firewall):
        cr = tmp_engine.create_change_request(org, {
            "firewall_id": firewall["id"],
            "change_type": "modify",
        })
        tmp_engine.approve_change_request(org, cr["id"], approver="bob")
        result = tmp_engine.implement_change_request(org, cr["id"])
        assert result is True
        crs = tmp_engine.list_change_requests(org, status="implemented")
        assert any(c["id"] == cr["id"] for c in crs)

    def test_cannot_implement_pending_request(self, tmp_engine, org, firewall):
        """Can only implement approved requests."""
        cr = tmp_engine.create_change_request(org, {
            "firewall_id": firewall["id"],
            "change_type": "add",
        })
        result = tmp_engine.implement_change_request(org, cr["id"])
        assert result is False

    def test_list_change_requests(self, tmp_engine, org, firewall):
        tmp_engine.create_change_request(org, {"firewall_id": firewall["id"], "change_type": "add"})
        tmp_engine.create_change_request(org, {"firewall_id": firewall["id"], "change_type": "delete"})
        crs = tmp_engine.list_change_requests(org)
        assert len(crs) == 2

    def test_list_change_requests_by_status(self, tmp_engine, org, firewall):
        cr = tmp_engine.create_change_request(org, {
            "firewall_id": firewall["id"], "change_type": "add"
        })
        tmp_engine.approve_change_request(org, cr["id"], approver="bob")
        pending = tmp_engine.list_change_requests(org, status="pending")
        approved = tmp_engine.list_change_requests(org, status="approved")
        assert len(pending) == 0
        assert len(approved) == 1


# ---------------------------------------------------------------------------
# Compliance scan tests
# ---------------------------------------------------------------------------

class TestComplianceScan:
    def test_scan_detects_any_any_allow(self, tmp_engine, org, firewall):
        tmp_engine.add_rule(org, {
            "firewall_id": firewall["id"],
            "src_address": "any",
            "dst_address": "any",
            "action": "allow",
        })
        violations = tmp_engine.run_compliance_scan(org, firewall["id"])
        types = [v["violation_type"] for v in violations]
        assert "any_any_allow" in types

    def test_scan_detects_insecure_protocol(self, tmp_engine, org, firewall):
        tmp_engine.add_rule(org, {
            "firewall_id": firewall["id"],
            "src_address": "10.0.0.0/8",
            "dst_address": "10.0.0.1",
            "service": ["23"],
            "action": "allow",
        })
        violations = tmp_engine.run_compliance_scan(org, firewall["id"])
        types = [v["violation_type"] for v in violations]
        assert "insecure_protocol" in types

    def test_scan_detects_unused_rule(self, tmp_engine, org, firewall):
        tmp_engine.add_rule(org, {
            "firewall_id": firewall["id"],
            "src_address": "192.168.1.0/24",
            "dst_address": "10.0.0.0/8",
            "action": "allow",
        })
        violations = tmp_engine.run_compliance_scan(org, firewall["id"])
        types = [v["violation_type"] for v in violations]
        assert "unused_rule" in types

    def test_scan_detects_overly_permissive(self, tmp_engine, org, firewall):
        tmp_engine.add_rule(org, {
            "firewall_id": firewall["id"],
            "src_address": "any",
            "dst_address": "192.168.1.0/24",
            "action": "allow",
        })
        violations = tmp_engine.run_compliance_scan(org, firewall["id"])
        types = [v["violation_type"] for v in violations]
        assert "overly_permissive" in types

    def test_scan_detects_shadowed_rule(self, tmp_engine, org, firewall):
        fid = firewall["id"]
        tmp_engine.add_rule(org, {
            "firewall_id": fid, "src_address": "10.0.0.1",
            "dst_address": "10.0.0.2", "service": ["8080"], "action": "allow",
        })
        tmp_engine.add_rule(org, {
            "firewall_id": fid, "src_address": "10.0.0.1",
            "dst_address": "10.0.0.2", "service": ["8080"], "action": "deny",
        })
        violations = tmp_engine.run_compliance_scan(org, fid)
        types = [v["violation_type"] for v in violations]
        assert "shadowed_rule" in types

    def test_scan_skips_disabled_rules(self, tmp_engine, org, firewall):
        rule = tmp_engine.add_rule(org, {
            "firewall_id": firewall["id"],
            "src_address": "any",
            "dst_address": "any",
            "action": "allow",
        })
        tmp_engine.disable_rule(org, rule["id"])
        violations = tmp_engine.run_compliance_scan(org, firewall["id"])
        assert len(violations) == 0

    def test_violations_persisted(self, tmp_engine, org, firewall):
        tmp_engine.add_rule(org, {
            "firewall_id": firewall["id"],
            "src_address": "any",
            "dst_address": "any",
            "action": "allow",
        })
        tmp_engine.run_compliance_scan(org, firewall["id"])
        violations = tmp_engine.list_violations(org)
        assert len(violations) > 0

    def test_list_violations_filter_by_severity(self, tmp_engine, org, firewall):
        tmp_engine.add_rule(org, {
            "firewall_id": firewall["id"],
            "src_address": "any",
            "dst_address": "any",
            "action": "allow",
        })
        tmp_engine.run_compliance_scan(org, firewall["id"])
        critical = tmp_engine.list_violations(org, severity="critical")
        assert len(critical) > 0
        assert all(v["severity"] == "critical" for v in critical)

    def test_resolve_violation(self, tmp_engine, org, firewall):
        tmp_engine.add_rule(org, {
            "firewall_id": firewall["id"],
            "src_address": "any",
            "dst_address": "any",
            "action": "allow",
        })
        tmp_engine.run_compliance_scan(org, firewall["id"])
        violations = tmp_engine.list_violations(org)
        assert len(violations) > 0
        result = tmp_engine.resolve_violation(org, violations[0]["id"])
        assert result is True
        resolved = tmp_engine.list_violations(org, status="resolved")
        assert any(v["id"] == violations[0]["id"] for v in resolved)

    def test_resolve_nonexistent_violation_returns_false(self, tmp_engine, org):
        result = tmp_engine.resolve_violation(org, "nonexistent-id")
        assert result is False


# ---------------------------------------------------------------------------
# Stats tests
# ---------------------------------------------------------------------------

class TestFirewallStats:
    def test_empty_stats(self, tmp_engine, org):
        stats = tmp_engine.get_firewall_stats(org)
        assert stats["total_firewalls"] == 0
        assert stats["online_firewalls"] == 0
        assert stats["total_rules"] == 0
        assert stats["shadowed_rules"] == 0
        assert stats["compliance_violations"] == 0
        assert stats["pending_changes"] == 0

    def test_stats_after_operations(self, tmp_engine, org):
        fw = tmp_engine.add_firewall(org, {"name": "FW1", "vendor": "fortinet"})
        # Add rules of varying risk
        tmp_engine.add_rule(org, {
            "firewall_id": fw["id"],
            "src_address": "any",
            "dst_address": "any",
            "action": "allow",
        })
        rule2 = tmp_engine.add_rule(org, {
            "firewall_id": fw["id"],
            "src_address": "192.168.0.0/16",
            "dst_address": "10.0.0.0/8",
            "action": "deny",
        })
        tmp_engine.disable_rule(org, rule2["id"])

        # Create a change request
        tmp_engine.create_change_request(org, {
            "firewall_id": fw["id"],
            "change_type": "add",
        })

        # Run scan to generate violations
        tmp_engine.run_compliance_scan(org, fw["id"])

        stats = tmp_engine.get_firewall_stats(org)
        assert stats["total_firewalls"] == 1
        assert stats["online_firewalls"] == 1
        assert stats["total_rules"] == 2
        assert stats["active_rules"] == 1
        assert stats["disabled_rules"] == 1
        assert stats["pending_changes"] == 1
        assert stats["compliance_violations"] > 0
        assert "critical" in stats["by_risk_level"]


# ---------------------------------------------------------------------------
# Org isolation tests
# ---------------------------------------------------------------------------

class TestOrgIsolation:
    def test_firewalls_isolated(self, tmp_engine, org, org2):
        tmp_engine.add_firewall(org, {"name": "FW-Org1"})
        assert len(tmp_engine.list_firewalls(org)) == 1
        assert len(tmp_engine.list_firewalls(org2)) == 0

    def test_rules_isolated(self, tmp_engine, org, org2):
        fw = tmp_engine.add_firewall(org, {"name": "FW-Org1"})
        tmp_engine.add_rule(org, {"firewall_id": fw["id"], "action": "allow"})
        assert len(tmp_engine.list_rules(org)) == 1
        assert len(tmp_engine.list_rules(org2)) == 0

    def test_violations_isolated(self, tmp_engine, org, org2):
        fw = tmp_engine.add_firewall(org, {"name": "FW-Org1"})
        tmp_engine.add_rule(org, {
            "firewall_id": fw["id"],
            "src_address": "any",
            "dst_address": "any",
            "action": "allow",
        })
        tmp_engine.run_compliance_scan(org, fw["id"])
        assert len(tmp_engine.list_violations(org)) > 0
        assert len(tmp_engine.list_violations(org2)) == 0

    def test_stats_isolated(self, tmp_engine, org, org2):
        tmp_engine.add_firewall(org, {"name": "FW-Org1"})
        stats_org1 = tmp_engine.get_firewall_stats(org)
        stats_org2 = tmp_engine.get_firewall_stats(org2)
        assert stats_org1["total_firewalls"] == 1
        assert stats_org2["total_firewalls"] == 0
