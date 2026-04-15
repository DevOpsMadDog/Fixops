"""Tests for DDoSProtectionEngine — 30+ tests covering all methods.

Tests use a temporary SQLite database to ensure isolation between runs.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from core.ddos_protection_engine import DDoSProtectionEngine


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "ddos_test.db")


@pytest.fixture
def engine(db_path):
    return DDoSProtectionEngine(db_path=db_path)


@pytest.fixture
def org():
    return "org-acme"


@pytest.fixture
def other_org():
    return "org-other"


@pytest.fixture
def resource(engine, org):
    return engine.register_protected_resource(org, {
        "name": "ACME Web Portal",
        "ip_or_fqdn": "portal.acme.com",
        "resource_type": "web",
        "protection_tier": "standard",
    })


# ============================================================================
# register_protected_resource
# ============================================================================


class TestRegisterProtectedResource:
    def test_returns_dict_with_id(self, engine, org):
        r = engine.register_protected_resource(org, {
            "name": "API Gateway",
            "ip_or_fqdn": "10.0.0.1",
            "resource_type": "api",
            "protection_tier": "premium",
        })
        assert r["id"]
        assert r["org_id"] == org
        assert r["name"] == "API Gateway"
        assert r["resource_type"] == "api"
        assert r["protection_tier"] == "premium"

    def test_all_resource_types_accepted(self, engine, org):
        for rt in ("web", "api", "dns", "network"):
            r = engine.register_protected_resource(org, {
                "name": f"Resource {rt}",
                "ip_or_fqdn": "1.2.3.4",
                "resource_type": rt,
                "protection_tier": "basic",
            })
            assert r["resource_type"] == rt

    def test_all_protection_tiers_accepted(self, engine, org):
        for tier in ("basic", "standard", "premium"):
            r = engine.register_protected_resource(org, {
                "name": f"Tier {tier}",
                "ip_or_fqdn": "1.2.3.4",
                "resource_type": "web",
                "protection_tier": tier,
            })
            assert r["protection_tier"] == tier

    def test_missing_name_raises(self, engine, org):
        with pytest.raises(ValueError, match="name"):
            engine.register_protected_resource(org, {
                "ip_or_fqdn": "1.2.3.4",
                "resource_type": "web",
                "protection_tier": "basic",
            })

    def test_missing_ip_or_fqdn_raises(self, engine, org):
        with pytest.raises(ValueError, match="ip_or_fqdn"):
            engine.register_protected_resource(org, {
                "name": "No IP",
                "resource_type": "web",
                "protection_tier": "basic",
            })

    def test_invalid_resource_type_raises(self, engine, org):
        with pytest.raises(ValueError, match="resource_type"):
            engine.register_protected_resource(org, {
                "name": "Bad Type",
                "ip_or_fqdn": "1.2.3.4",
                "resource_type": "ftp",
                "protection_tier": "basic",
            })

    def test_invalid_protection_tier_raises(self, engine, org):
        with pytest.raises(ValueError, match="protection_tier"):
            engine.register_protected_resource(org, {
                "name": "Bad Tier",
                "ip_or_fqdn": "1.2.3.4",
                "resource_type": "web",
                "protection_tier": "gold",
            })


# ============================================================================
# list_protected_resources
# ============================================================================


class TestListProtectedResources:
    def test_empty_org_returns_empty_list(self, engine):
        assert engine.list_protected_resources("org-unknown") == []

    def test_returns_resources_for_org(self, engine, org, resource):
        resources = engine.list_protected_resources(org)
        assert len(resources) == 1
        assert resources[0]["id"] == resource["id"]

    def test_tenant_isolation(self, engine, org, other_org, resource):
        engine.register_protected_resource(other_org, {
            "name": "Other Org Resource",
            "ip_or_fqdn": "9.9.9.9",
            "resource_type": "dns",
            "protection_tier": "basic",
        })
        assert len(engine.list_protected_resources(org)) == 1
        assert len(engine.list_protected_resources(other_org)) == 1

    def test_multiple_resources_returned(self, engine, org):
        for i in range(3):
            engine.register_protected_resource(org, {
                "name": f"Resource {i}",
                "ip_or_fqdn": f"10.0.0.{i}",
                "resource_type": "network",
                "protection_tier": "basic",
            })
        assert len(engine.list_protected_resources(org)) == 3


# ============================================================================
# record_attack_event
# ============================================================================


class TestRecordAttackEvent:
    def test_returns_event_with_id(self, engine, org, resource):
        evt = engine.record_attack_event(org, {
            "resource_id": resource["id"],
            "attack_type": "volumetric",
            "source_ips": ["1.2.3.4", "5.6.7.8"],
            "peak_gbps": 12.5,
            "duration_seconds": 300,
            "status": "detected",
        })
        assert evt["id"]
        assert evt["attack_type"] == "volumetric"
        assert evt["source_ips"] == ["1.2.3.4", "5.6.7.8"]
        assert evt["peak_gbps"] == 12.5

    def test_all_attack_types_accepted(self, engine, org, resource):
        for at in ("volumetric", "protocol", "application", "slowloris", "amplification"):
            evt = engine.record_attack_event(org, {
                "resource_id": resource["id"],
                "attack_type": at,
                "source_ips": [],
                "peak_gbps": 0.0,
                "duration_seconds": 0,
                "status": "detected",
            })
            assert evt["attack_type"] == at

    def test_all_statuses_accepted(self, engine, org, resource):
        for s in ("detected", "mitigating", "mitigated"):
            evt = engine.record_attack_event(org, {
                "resource_id": resource["id"],
                "attack_type": "volumetric",
                "source_ips": [],
                "peak_gbps": 0.0,
                "duration_seconds": 0,
                "status": s,
            })
            assert evt["status"] == s

    def test_missing_resource_id_raises(self, engine, org):
        with pytest.raises(ValueError, match="resource_id"):
            engine.record_attack_event(org, {
                "attack_type": "volumetric",
                "source_ips": [],
                "peak_gbps": 0.0,
                "duration_seconds": 0,
                "status": "detected",
            })

    def test_invalid_attack_type_raises(self, engine, org, resource):
        with pytest.raises(ValueError, match="attack_type"):
            engine.record_attack_event(org, {
                "resource_id": resource["id"],
                "attack_type": "unknown",
                "source_ips": [],
                "peak_gbps": 0.0,
                "duration_seconds": 0,
                "status": "detected",
            })

    def test_source_ips_not_list_raises(self, engine, org, resource):
        with pytest.raises(ValueError, match="source_ips"):
            engine.record_attack_event(org, {
                "resource_id": resource["id"],
                "attack_type": "volumetric",
                "source_ips": "1.2.3.4",
                "peak_gbps": 0.0,
                "duration_seconds": 0,
                "status": "detected",
            })

    def test_invalid_status_raises(self, engine, org, resource):
        with pytest.raises(ValueError, match="status"):
            engine.record_attack_event(org, {
                "resource_id": resource["id"],
                "attack_type": "volumetric",
                "source_ips": [],
                "peak_gbps": 0.0,
                "duration_seconds": 0,
                "status": "resolved",
            })


# ============================================================================
# list_attack_events
# ============================================================================


class TestListAttackEvents:
    def _make_event(self, engine, org, resource, attack_type="volumetric", status="detected"):
        return engine.record_attack_event(org, {
            "resource_id": resource["id"],
            "attack_type": attack_type,
            "source_ips": [],
            "peak_gbps": 1.0,
            "duration_seconds": 60,
            "status": status,
        })

    def test_returns_all_events_for_org(self, engine, org, resource):
        self._make_event(engine, org, resource)
        self._make_event(engine, org, resource)
        events = engine.list_attack_events(org)
        assert len(events) == 2

    def test_filter_by_resource_id(self, engine, org, resource):
        other = engine.register_protected_resource(org, {
            "name": "Other", "ip_or_fqdn": "9.9.9.9",
            "resource_type": "api", "protection_tier": "basic",
        })
        self._make_event(engine, org, resource)
        engine.record_attack_event(org, {
            "resource_id": other["id"],
            "attack_type": "protocol",
            "source_ips": [],
            "peak_gbps": 0.5,
            "duration_seconds": 30,
            "status": "detected",
        })
        events = engine.list_attack_events(org, resource_id=resource["id"])
        assert len(events) == 1
        assert events[0]["resource_id"] == resource["id"]

    def test_filter_by_status(self, engine, org, resource):
        self._make_event(engine, org, resource, status="detected")
        self._make_event(engine, org, resource, status="mitigated")
        mitigated = engine.list_attack_events(org, status="mitigated")
        assert all(e["status"] == "mitigated" for e in mitigated)

    def test_tenant_isolation(self, engine, org, other_org, resource):
        self._make_event(engine, org, resource)
        assert engine.list_attack_events(other_org) == []

    def test_limit_respected(self, engine, org, resource):
        for _ in range(10):
            self._make_event(engine, org, resource)
        assert len(engine.list_attack_events(org, limit=5)) == 5


# ============================================================================
# update_attack_status
# ============================================================================


class TestUpdateAttackStatus:
    def test_update_to_mitigating(self, engine, org, resource):
        evt = engine.record_attack_event(org, {
            "resource_id": resource["id"],
            "attack_type": "volumetric",
            "source_ips": [],
            "peak_gbps": 5.0,
            "duration_seconds": 120,
            "status": "detected",
        })
        updated = engine.update_attack_status(org, evt["id"], "mitigating")
        assert updated["status"] == "mitigating"

    def test_update_to_mitigated(self, engine, org, resource):
        evt = engine.record_attack_event(org, {
            "resource_id": resource["id"],
            "attack_type": "amplification",
            "source_ips": [],
            "peak_gbps": 100.0,
            "duration_seconds": 600,
            "status": "mitigating",
        })
        updated = engine.update_attack_status(org, evt["id"], "mitigated")
        assert updated["status"] == "mitigated"

    def test_invalid_status_raises(self, engine, org, resource):
        evt = engine.record_attack_event(org, {
            "resource_id": resource["id"],
            "attack_type": "volumetric",
            "source_ips": [],
            "peak_gbps": 1.0,
            "duration_seconds": 10,
            "status": "detected",
        })
        with pytest.raises(ValueError, match="status"):
            engine.update_attack_status(org, evt["id"], "closed")

    def test_wrong_org_raises(self, engine, org, other_org, resource):
        evt = engine.record_attack_event(org, {
            "resource_id": resource["id"],
            "attack_type": "volumetric",
            "source_ips": [],
            "peak_gbps": 1.0,
            "duration_seconds": 10,
            "status": "detected",
        })
        with pytest.raises(ValueError):
            engine.update_attack_status(other_org, evt["id"], "mitigated")

    def test_nonexistent_attack_raises(self, engine, org):
        with pytest.raises(ValueError):
            engine.update_attack_status(org, "does-not-exist", "mitigated")


# ============================================================================
# create_mitigation_rule
# ============================================================================


class TestCreateMitigationRule:
    def test_returns_rule_with_id(self, engine, org):
        rule = engine.create_mitigation_rule(org, {
            "name": "Block high-volume IPs",
            "rule_type": "rate_limit",
            "threshold": 1000,
            "action": "drop",
        })
        assert rule["id"]
        assert rule["rule_type"] == "rate_limit"
        assert rule["action"] == "drop"

    def test_all_rule_types_accepted(self, engine, org):
        for rt in ("rate_limit", "geo_block", "ip_block", "challenge"):
            rule = engine.create_mitigation_rule(org, {
                "name": f"Rule {rt}",
                "rule_type": rt,
                "threshold": "500rps",
                "action": "block",
            })
            assert rule["rule_type"] == rt

    def test_missing_name_raises(self, engine, org):
        with pytest.raises(ValueError, match="name"):
            engine.create_mitigation_rule(org, {
                "rule_type": "rate_limit",
                "threshold": 100,
                "action": "drop",
            })

    def test_invalid_rule_type_raises(self, engine, org):
        with pytest.raises(ValueError, match="rule_type"):
            engine.create_mitigation_rule(org, {
                "name": "Bad Rule",
                "rule_type": "firewall",
                "threshold": 100,
                "action": "drop",
            })

    def test_missing_action_raises(self, engine, org):
        with pytest.raises(ValueError, match="action"):
            engine.create_mitigation_rule(org, {
                "name": "No Action",
                "rule_type": "ip_block",
                "threshold": 10,
                "action": "",
            })


# ============================================================================
# list_mitigation_rules
# ============================================================================


class TestListMitigationRules:
    def test_empty_returns_empty_list(self, engine):
        assert engine.list_mitigation_rules("org-unknown") == []

    def test_returns_rules_for_org(self, engine, org):
        engine.create_mitigation_rule(org, {
            "name": "Rule A", "rule_type": "ip_block",
            "threshold": "10", "action": "block",
        })
        rules = engine.list_mitigation_rules(org)
        assert len(rules) == 1

    def test_tenant_isolation(self, engine, org, other_org):
        engine.create_mitigation_rule(org, {
            "name": "Org Rule", "rule_type": "geo_block",
            "threshold": "CN", "action": "deny",
        })
        assert engine.list_mitigation_rules(other_org) == []


# ============================================================================
# get_ddos_stats
# ============================================================================


class TestGetDdosStats:
    def test_empty_org_stats(self, engine):
        stats = engine.get_ddos_stats("org-empty")
        assert stats["resources"] == 0
        assert stats["attacks_24h"] == 0
        assert stats["mitigated_pct"] == 0.0
        assert stats["peak_gbps_today"] == 0.0

    def test_stats_with_data(self, engine, org, resource):
        engine.record_attack_event(org, {
            "resource_id": resource["id"],
            "attack_type": "volumetric",
            "source_ips": [],
            "peak_gbps": 25.0,
            "duration_seconds": 300,
            "status": "mitigated",
        })
        engine.record_attack_event(org, {
            "resource_id": resource["id"],
            "attack_type": "protocol",
            "source_ips": [],
            "peak_gbps": 5.0,
            "duration_seconds": 60,
            "status": "detected",
        })
        stats = engine.get_ddos_stats(org)
        assert stats["resources"] == 1
        assert stats["attacks_24h"] == 2
        assert stats["mitigated_pct"] == 50.0
        assert stats["peak_gbps_today"] == 25.0

    def test_mitigated_pct_all_mitigated(self, engine, org, resource):
        for _ in range(3):
            engine.record_attack_event(org, {
                "resource_id": resource["id"],
                "attack_type": "slowloris",
                "source_ips": [],
                "peak_gbps": 0.1,
                "duration_seconds": 10,
                "status": "mitigated",
            })
        stats = engine.get_ddos_stats(org)
        assert stats["mitigated_pct"] == 100.0
