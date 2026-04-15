"""Tests for FirewallRuleEngine — 25+ test cases covering all public methods."""

from __future__ import annotations

import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from core.firewall_rule_engine import FirewallRuleEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine(tmp_path: Path) -> FirewallRuleEngine:
    db = str(tmp_path / "test_firewall.db")
    return FirewallRuleEngine(db_path=db)


@pytest.fixture()
def fw(engine: FirewallRuleEngine) -> dict:
    """A pre-created firewall for org 'org1'."""
    return engine.add_firewall("org1", {
        "name": "Core FW",
        "vendor": "palo_alto",
        "ip_address": "10.0.0.1",
        "status": "active",
    })


@pytest.fixture()
def fw2(engine: FirewallRuleEngine) -> dict:
    """Second firewall for org 'org1'."""
    return engine.add_firewall("org1", {
        "name": "Edge FW",
        "vendor": "cisco",
        "ip_address": "10.0.0.2",
    })


# ===========================================================================
# 1. Initialisation
# ===========================================================================


def test_init_creates_db(tmp_path: Path) -> None:
    db_path = str(tmp_path / "sub" / "fw.db")
    engine = FirewallRuleEngine(db_path=db_path)
    assert Path(db_path).exists()


def test_init_idempotent(tmp_path: Path) -> None:
    db_path = str(tmp_path / "fw.db")
    FirewallRuleEngine(db_path=db_path)
    # Second init should not raise
    FirewallRuleEngine(db_path=db_path)


# ===========================================================================
# 2. add_firewall / list_firewalls
# ===========================================================================


def test_add_firewall_returns_record(fw: dict) -> None:
    assert "firewall_id" in fw
    assert fw["name"] == "Core FW"
    assert fw["vendor"] == "palo_alto"
    assert fw["ip_address"] == "10.0.0.1"
    assert fw["status"] == "active"
    assert fw["org_id"] == "org1"


def test_add_firewall_uuid(fw: dict) -> None:
    import uuid
    uuid.UUID(fw["firewall_id"])  # should not raise


def test_list_firewalls_returns_added(engine: FirewallRuleEngine, fw: dict) -> None:
    result = engine.list_firewalls("org1")
    assert len(result) == 1
    assert result[0]["firewall_id"] == fw["firewall_id"]


def test_list_firewalls_multiple(engine: FirewallRuleEngine, fw: dict, fw2: dict) -> None:
    result = engine.list_firewalls("org1")
    assert len(result) == 2


def test_list_firewalls_empty_for_other_org(engine: FirewallRuleEngine, fw: dict) -> None:
    assert engine.list_firewalls("org_other") == []


def test_get_firewall(engine: FirewallRuleEngine, fw: dict) -> None:
    fetched = engine.get_firewall("org1", fw["firewall_id"])
    assert fetched is not None
    assert fetched["firewall_id"] == fw["firewall_id"]


def test_get_firewall_wrong_org(engine: FirewallRuleEngine, fw: dict) -> None:
    assert engine.get_firewall("other_org", fw["firewall_id"]) is None


def test_firewall_vendors(engine: FirewallRuleEngine) -> None:
    for vendor in ("cisco", "fortinet", "checkpoint", "aws_sg", "azure_nsg"):
        rec = engine.add_firewall("org1", {"name": f"fw-{vendor}", "vendor": vendor})
        assert rec["vendor"] == vendor


# ===========================================================================
# 3. add_rule / list_rules
# ===========================================================================


def test_add_rule_returns_record(engine: FirewallRuleEngine, fw: dict) -> None:
    rule = engine.add_rule("org1", fw["firewall_id"], {
        "rule_number": 10,
        "src_ip": "192.168.1.0/24",
        "dst_ip": "10.0.0.0/8",
        "port": "443",
        "protocol": "tcp",
        "action": "allow",
        "enabled": True,
    })
    assert "rule_id" in rule
    assert rule["firewall_id"] == fw["firewall_id"]
    assert rule["port"] == "443"
    assert rule["enabled"] is True


def test_add_rule_increments_rule_count(engine: FirewallRuleEngine, fw: dict) -> None:
    engine.add_rule("org1", fw["firewall_id"], {"rule_number": 1})
    engine.add_rule("org1", fw["firewall_id"], {"rule_number": 2})
    updated_fw = engine.get_firewall("org1", fw["firewall_id"])
    assert updated_fw["rule_count"] == 2


def test_list_rules_by_firewall(engine: FirewallRuleEngine, fw: dict, fw2: dict) -> None:
    engine.add_rule("org1", fw["firewall_id"], {"rule_number": 1})
    engine.add_rule("org1", fw2["firewall_id"], {"rule_number": 1})
    result = engine.list_rules("org1", firewall_id=fw["firewall_id"])
    assert len(result) == 1
    assert result[0]["firewall_id"] == fw["firewall_id"]


def test_list_rules_all(engine: FirewallRuleEngine, fw: dict, fw2: dict) -> None:
    engine.add_rule("org1", fw["firewall_id"], {"rule_number": 1})
    engine.add_rule("org1", fw2["firewall_id"], {"rule_number": 1})
    result = engine.list_rules("org1")
    assert len(result) == 2


def test_list_rules_org_isolation(engine: FirewallRuleEngine, fw: dict) -> None:
    engine.add_rule("org1", fw["firewall_id"], {"rule_number": 1})
    assert engine.list_rules("org2") == []


# ===========================================================================
# 4. analyze_rules — detects specific issues
# ===========================================================================


def test_analyze_overly_permissive(engine: FirewallRuleEngine, fw: dict) -> None:
    engine.add_rule("org1", fw["firewall_id"], {
        "rule_number": 1,
        "src_ip": "any",
        "dst_ip": "any",
        "port": "80",
        "action": "allow",
        "enabled": True,
    })
    result = engine.analyze_rules("org1", fw["firewall_id"])
    types = [f["finding_type"] for f in result["findings"]]
    assert "overly_permissive" in types


def test_analyze_any_port(engine: FirewallRuleEngine, fw: dict) -> None:
    engine.add_rule("org1", fw["firewall_id"], {
        "rule_number": 1,
        "src_ip": "192.168.1.0/24",
        "dst_ip": "10.0.0.1",
        "port": "any",
        "action": "allow",
        "enabled": True,
    })
    result = engine.analyze_rules("org1", fw["firewall_id"])
    types = [f["finding_type"] for f in result["findings"]]
    assert "any_port" in types


def test_analyze_shadowed_rule(engine: FirewallRuleEngine, fw: dict) -> None:
    # Rule 1: any -> any, allow — shadows Rule 2 with narrower match
    engine.add_rule("org1", fw["firewall_id"], {
        "rule_number": 1,
        "src_ip": "any",
        "dst_ip": "any",
        "port": "443",
        "protocol": "tcp",
        "action": "allow",
        "enabled": True,
    })
    engine.add_rule("org1", fw["firewall_id"], {
        "rule_number": 2,
        "src_ip": "192.168.1.0/24",
        "dst_ip": "10.0.0.1",
        "port": "443",
        "protocol": "tcp",
        "action": "allow",
        "enabled": True,
    })
    result = engine.analyze_rules("org1", fw["firewall_id"])
    types = [f["finding_type"] for f in result["findings"]]
    assert "shadowed_rule" in types


def test_analyze_duplicate_rule(engine: FirewallRuleEngine, fw: dict) -> None:
    for i in range(2):
        engine.add_rule("org1", fw["firewall_id"], {
            "rule_number": i + 1,
            "src_ip": "192.168.0.0/16",
            "dst_ip": "10.0.0.0/8",
            "port": "22",
            "protocol": "tcp",
            "action": "allow",
            "enabled": True,
        })
    result = engine.analyze_rules("org1", fw["firewall_id"])
    types = [f["finding_type"] for f in result["findings"]]
    assert "duplicate_rule" in types


def test_analyze_unused_rule(engine: FirewallRuleEngine, fw: dict) -> None:
    # Rule with hit_count=0 and created_at > 90 days ago
    old_date = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
    rule = engine.add_rule("org1", fw["firewall_id"], {
        "rule_number": 1,
        "src_ip": "192.168.1.1",
        "dst_ip": "10.0.0.1",
        "port": "8080",
        "protocol": "tcp",
        "action": "allow",
        "enabled": True,
        "hit_count": 0,
    })
    # Manually backdate the created_at
    import sqlite3
    conn = sqlite3.connect(engine.db_path)
    conn.execute("UPDATE firewall_rules SET created_at=? WHERE id=?", (old_date, rule["rule_id"]))
    conn.commit()
    conn.close()

    result = engine.analyze_rules("org1", fw["firewall_id"])
    types = [f["finding_type"] for f in result["findings"]]
    assert "unused_rule" in types


def test_analyze_clean_rule_no_findings(engine: FirewallRuleEngine, fw: dict) -> None:
    engine.add_rule("org1", fw["firewall_id"], {
        "rule_number": 1,
        "src_ip": "192.168.1.0/24",
        "dst_ip": "10.0.0.5",
        "port": "443",
        "protocol": "tcp",
        "action": "allow",
        "enabled": True,
        "hit_count": 500,
    })
    result = engine.analyze_rules("org1", fw["firewall_id"])
    assert result["rule_count"] == 1
    assert result["issues_found"] == 0
    assert result["risk_score"] == 0


def test_analyze_returns_risk_score(engine: FirewallRuleEngine, fw: dict) -> None:
    engine.add_rule("org1", fw["firewall_id"], {
        "rule_number": 1, "src_ip": "any", "dst_ip": "any",
        "port": "any", "action": "allow", "enabled": True,
    })
    result = engine.analyze_rules("org1", fw["firewall_id"])
    assert 0 <= result["risk_score"] <= 100


def test_analyze_updates_last_audited(engine: FirewallRuleEngine, fw: dict) -> None:
    engine.add_rule("org1", fw["firewall_id"], {"rule_number": 1})
    engine.analyze_rules("org1", fw["firewall_id"])
    updated_fw = engine.get_firewall("org1", fw["firewall_id"])
    assert updated_fw["last_audited"] is not None


def test_analyze_disabled_rules_skipped(engine: FirewallRuleEngine, fw: dict) -> None:
    engine.add_rule("org1", fw["firewall_id"], {
        "rule_number": 1, "src_ip": "any", "dst_ip": "any",
        "port": "any", "action": "allow", "enabled": False,
    })
    result = engine.analyze_rules("org1", fw["firewall_id"])
    assert result["issues_found"] == 0


# ===========================================================================
# 5. create_finding / list_findings / resolve_finding
# ===========================================================================


def test_create_finding(engine: FirewallRuleEngine, fw: dict) -> None:
    f = engine.create_finding(
        "org1", fw["firewall_id"], None,
        "overly_permissive", "high", "Open rule detected"
    )
    assert "finding_id" in f
    assert f["status"] == "open"
    assert f["severity"] == "high"


def test_list_findings_by_org(engine: FirewallRuleEngine, fw: dict) -> None:
    engine.create_finding("org1", fw["firewall_id"], None, "dup", "low", "dup")
    assert len(engine.list_findings("org1")) == 1
    assert engine.list_findings("org2") == []


def test_list_findings_by_firewall(engine: FirewallRuleEngine, fw: dict, fw2: dict) -> None:
    engine.create_finding("org1", fw["firewall_id"], None, "t1", "low", "d1")
    engine.create_finding("org1", fw2["firewall_id"], None, "t2", "medium", "d2")
    result = engine.list_findings("org1", firewall_id=fw["firewall_id"])
    assert len(result) == 1
    assert result[0]["firewall_id"] == fw["firewall_id"]


def test_list_findings_by_severity(engine: FirewallRuleEngine, fw: dict) -> None:
    engine.create_finding("org1", fw["firewall_id"], None, "t1", "high", "d1")
    engine.create_finding("org1", fw["firewall_id"], None, "t2", "low", "d2")
    highs = engine.list_findings("org1", severity="high")
    assert len(highs) == 1
    assert highs[0]["severity"] == "high"


def test_resolve_finding(engine: FirewallRuleEngine, fw: dict) -> None:
    f = engine.create_finding("org1", fw["firewall_id"], None, "t", "medium", "d")
    assert engine.resolve_finding("org1", f["finding_id"]) is True
    remaining = engine.list_findings("org1")
    open_ones = [x for x in remaining if x["status"] == "open"]
    assert len(open_ones) == 0


def test_resolve_finding_wrong_org(engine: FirewallRuleEngine, fw: dict) -> None:
    f = engine.create_finding("org1", fw["firewall_id"], None, "t", "medium", "d")
    assert engine.resolve_finding("org2", f["finding_id"]) is False


def test_resolve_already_resolved(engine: FirewallRuleEngine, fw: dict) -> None:
    f = engine.create_finding("org1", fw["firewall_id"], None, "t", "medium", "d")
    engine.resolve_finding("org1", f["finding_id"])
    # Second resolve should return False
    assert engine.resolve_finding("org1", f["finding_id"]) is False


# ===========================================================================
# 6. get_firewall_stats
# ===========================================================================


def test_stats_empty_org(engine: FirewallRuleEngine) -> None:
    stats = engine.get_firewall_stats("empty_org")
    assert stats["total_firewalls"] == 0
    assert stats["total_rules"] == 0
    assert stats["open_findings"] == 0
    assert stats["avg_risk_score"] == 0.0


def test_stats_counts(engine: FirewallRuleEngine, fw: dict) -> None:
    engine.add_rule("org1", fw["firewall_id"], {"rule_number": 1})
    engine.add_rule("org1", fw["firewall_id"], {"rule_number": 2})
    engine.create_finding("org1", fw["firewall_id"], None, "t1", "high", "d1")
    engine.create_finding("org1", fw["firewall_id"], None, "t2", "low", "d2")

    stats = engine.get_firewall_stats("org1")
    assert stats["total_firewalls"] == 1
    assert stats["total_rules"] == 2
    assert stats["open_findings"] == 2
    assert "high" in stats["findings_by_severity"]
    assert stats["findings_by_severity"]["high"] == 1


def test_stats_resolved_not_counted(engine: FirewallRuleEngine, fw: dict) -> None:
    f = engine.create_finding("org1", fw["firewall_id"], None, "t", "medium", "d")
    engine.resolve_finding("org1", f["finding_id"])
    stats = engine.get_firewall_stats("org1")
    assert stats["open_findings"] == 0


# ===========================================================================
# 7. Org isolation — cross-org data must never leak
# ===========================================================================


def test_org_isolation_firewalls(engine: FirewallRuleEngine) -> None:
    engine.add_firewall("org_a", {"name": "FW-A", "vendor": "cisco"})
    engine.add_firewall("org_b", {"name": "FW-B", "vendor": "fortinet"})
    assert len(engine.list_firewalls("org_a")) == 1
    assert len(engine.list_firewalls("org_b")) == 1


def test_org_isolation_findings(engine: FirewallRuleEngine) -> None:
    fw_a = engine.add_firewall("org_a", {"name": "A"})
    fw_b = engine.add_firewall("org_b", {"name": "B"})
    engine.create_finding("org_a", fw_a["firewall_id"], None, "t", "high", "d")
    assert engine.list_findings("org_b") == []
