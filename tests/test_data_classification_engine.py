"""Tests for suite-core/core/data_classification_engine.py — DataClassificationEngine.

Tests cover:
- register_asset, list_assets, get_asset, classify_asset, scan_asset
- add_rule, list_rules
- log_violation, list_violations, resolve_violation
- get_stats
- Validation errors (invalid enum values, missing required fields)
- Multi-tenant org isolation

Usage:
    pytest tests/test_data_classification_engine.py -v --timeout=10
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_suite_core = str(Path(__file__).parent.parent / "suite-core")
if _suite_core not in sys.path:
    sys.path.insert(0, _suite_core)

from core.data_classification_engine import DataClassificationEngine

ORG_A = "org-alpha"
ORG_B = "org-beta"


@pytest.fixture
def engine(tmp_path):
    return DataClassificationEngine(data_dir=str(tmp_path))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _asset(name="CustomerDB", asset_type="database", **kwargs):
    return {"name": name, "asset_type": asset_type, **kwargs}


def _rule(rule_name="SSN Rule", **kwargs):
    return {
        "rule_name": rule_name,
        "pattern_type": "regex",
        "pattern_value": r"\d{3}-\d{2}-\d{4}",
        "classification_level": "restricted",
        **kwargs,
    }


# ---------------------------------------------------------------------------
# register_asset
# ---------------------------------------------------------------------------

def test_register_asset_returns_record(engine):
    rec = engine.register_asset(ORG_A, _asset())
    assert rec["id"]
    assert rec["name"] == "CustomerDB"
    assert rec["asset_type"] == "database"
    assert rec["org_id"] == ORG_A


def test_register_asset_defaults(engine):
    rec = engine.register_asset(ORG_A, _asset())
    assert rec["classification_level"] == "internal"
    assert rec["data_residency"] == "us"
    assert rec["sensitivity_score"] == 70.0  # database default


def test_register_asset_all_types(engine):
    for atype in ["database", "file_share", "api_endpoint", "cloud_storage",
                  "email_archive", "code_repo", "backup"]:
        rec = engine.register_asset(ORG_A, _asset(name=f"asset-{atype}", asset_type=atype))
        assert rec["asset_type"] == atype


def test_register_asset_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="Invalid asset_type"):
        engine.register_asset(ORG_A, _asset(asset_type="spreadsheet"))


def test_register_asset_invalid_classification_raises(engine):
    with pytest.raises(ValueError, match="Invalid classification_level"):
        engine.register_asset(ORG_A, _asset(classification_level="top_secret"))


def test_register_asset_invalid_residency_raises(engine):
    with pytest.raises(ValueError, match="Invalid data_residency"):
        engine.register_asset(ORG_A, _asset(data_residency="mars"))


def test_register_asset_missing_name_raises(engine):
    with pytest.raises(ValueError, match="name is required"):
        engine.register_asset(ORG_A, {"asset_type": "database"})


def test_register_asset_auto_classification_set(engine):
    rec = engine.register_asset(ORG_A, _asset(asset_type="backup"))
    assert rec["auto_classification_level"] == "restricted"


# ---------------------------------------------------------------------------
# list_assets / get_asset
# ---------------------------------------------------------------------------

def test_list_assets_empty(engine):
    assert engine.list_assets(ORG_A) == []


def test_list_assets_returns_all(engine):
    engine.register_asset(ORG_A, _asset("A"))
    engine.register_asset(ORG_A, _asset("B"))
    assert len(engine.list_assets(ORG_A)) == 2


def test_list_assets_filter_by_level(engine):
    engine.register_asset(ORG_A, _asset("Pub", classification_level="public"))
    engine.register_asset(ORG_A, _asset("Conf", classification_level="confidential"))
    pub = engine.list_assets(ORG_A, classification_level="public")
    assert len(pub) == 1
    assert pub[0]["name"] == "Pub"


def test_list_assets_filter_by_pii(engine):
    a = engine.register_asset(ORG_A, _asset("WithPII", pii_detected=True))
    engine.register_asset(ORG_A, _asset("NoPII"))
    pii_assets = engine.list_assets(ORG_A, pii_detected=True)
    assert any(x["id"] == a["id"] for x in pii_assets)


def test_list_assets_org_isolation(engine):
    engine.register_asset(ORG_A, _asset("OrgAAsset"))
    assert engine.list_assets(ORG_B) == []


def test_get_asset_found(engine):
    rec = engine.register_asset(ORG_A, _asset())
    fetched = engine.get_asset(ORG_A, rec["id"])
    assert fetched is not None
    assert fetched["id"] == rec["id"]


def test_get_asset_not_found(engine):
    engine.register_asset(ORG_A, _asset())
    assert engine.get_asset(ORG_A, "nonexistent-id") is None


def test_get_asset_wrong_org(engine):
    rec = engine.register_asset(ORG_A, _asset())
    assert engine.get_asset(ORG_B, rec["id"]) is None


# ---------------------------------------------------------------------------
# classify_asset
# ---------------------------------------------------------------------------

def test_classify_asset_updates_level(engine):
    rec = engine.register_asset(ORG_A, _asset())
    updated = engine.classify_asset(ORG_A, rec["id"], "secret", "manual")
    assert updated["classification_level"] == "secret"


def test_classify_asset_auto_method(engine):
    rec = engine.register_asset(ORG_A, _asset())
    updated = engine.classify_asset(ORG_A, rec["id"], "restricted", "auto")
    assert updated["classification_method"] == "auto"


def test_classify_asset_invalid_level_raises(engine):
    rec = engine.register_asset(ORG_A, _asset())
    with pytest.raises(ValueError, match="Invalid classification level"):
        engine.classify_asset(ORG_A, rec["id"], "ultra_secret")


def test_classify_asset_not_found_raises(engine):
    engine.register_asset(ORG_A, _asset())
    with pytest.raises(ValueError, match="Asset not found"):
        engine.classify_asset(ORG_A, "bad-id", "confidential")


# ---------------------------------------------------------------------------
# scan_asset
# ---------------------------------------------------------------------------

def test_scan_asset_returns_scan_record(engine):
    rec = engine.register_asset(ORG_A, _asset(asset_type="database"))
    scan = engine.scan_asset(ORG_A, rec["id"])
    assert scan["asset_id"] == rec["id"]
    assert scan["findings_count"] > 0
    assert isinstance(scan["pii_matches"], dict)


def test_scan_asset_updates_pii_detected(engine):
    rec = engine.register_asset(ORG_A, _asset(asset_type="database"))
    engine.scan_asset(ORG_A, rec["id"])
    updated = engine.get_asset(ORG_A, rec["id"])
    assert updated["pii_detected"] is True


def test_scan_asset_suggests_restricted_for_backup(engine):
    rec = engine.register_asset(ORG_A, _asset(asset_type="backup"))
    scan = engine.scan_asset(ORG_A, rec["id"])
    assert scan["classification_suggested"] == "restricted"


def test_scan_asset_not_found_raises(engine):
    with pytest.raises(ValueError, match="Asset not found"):
        engine.scan_asset(ORG_A, "bad-id")


# ---------------------------------------------------------------------------
# add_rule / list_rules
# ---------------------------------------------------------------------------

def test_add_rule_returns_record(engine):
    rule = engine.add_rule(ORG_A, _rule())
    assert rule["id"]
    assert rule["rule_name"] == "SSN Rule"
    assert rule["pattern_type"] == "regex"


def test_add_rule_invalid_pattern_type_raises(engine):
    with pytest.raises(ValueError, match="Invalid pattern_type"):
        engine.add_rule(ORG_A, _rule(pattern_type="neural_net"))


def test_add_rule_invalid_level_raises(engine):
    with pytest.raises(ValueError, match="Invalid classification_level"):
        engine.add_rule(ORG_A, _rule(classification_level="classified"))


def test_add_rule_missing_name_raises(engine):
    with pytest.raises(ValueError, match="rule_name is required"):
        engine.add_rule(ORG_A, {"pattern_type": "keyword"})


def test_list_rules_empty(engine):
    assert engine.list_rules(ORG_A) == []


def test_list_rules_returns_rules(engine):
    engine.add_rule(ORG_A, _rule("Rule1"))
    engine.add_rule(ORG_A, _rule("Rule2"))
    rules = engine.list_rules(ORG_A)
    assert len(rules) == 2


def test_list_rules_org_isolation(engine):
    engine.add_rule(ORG_A, _rule())
    assert engine.list_rules(ORG_B) == []


# ---------------------------------------------------------------------------
# log_violation / list_violations / resolve_violation
# ---------------------------------------------------------------------------

def test_log_violation_returns_record(engine):
    rec = engine.register_asset(ORG_A, _asset())
    viol = engine.log_violation(ORG_A, rec["id"], {"violation_type": "pii_exposed", "severity": "critical"})
    assert viol["id"]
    assert viol["status"] == "open"
    assert viol["violation_type"] == "pii_exposed"


def test_log_violation_invalid_type_raises(engine):
    rec = engine.register_asset(ORG_A, _asset())
    with pytest.raises(ValueError, match="Invalid violation_type"):
        engine.log_violation(ORG_A, rec["id"], {"violation_type": "wrong_type"})


def test_log_violation_invalid_severity_raises(engine):
    rec = engine.register_asset(ORG_A, _asset())
    with pytest.raises(ValueError, match="Invalid severity"):
        engine.log_violation(ORG_A, rec["id"], {"violation_type": "unclassified", "severity": "ultra"})


def test_list_violations_filter_status(engine):
    rec = engine.register_asset(ORG_A, _asset())
    engine.log_violation(ORG_A, rec["id"], {"violation_type": "unclassified"})
    open_viols = engine.list_violations(ORG_A, status="open")
    assert len(open_viols) >= 1


def test_list_violations_filter_severity(engine):
    rec = engine.register_asset(ORG_A, _asset())
    engine.log_violation(ORG_A, rec["id"], {"violation_type": "pii_exposed", "severity": "critical"})
    crit = engine.list_violations(ORG_A, severity="critical")
    assert len(crit) == 1


def test_resolve_violation_marks_resolved(engine):
    rec = engine.register_asset(ORG_A, _asset())
    viol = engine.log_violation(ORG_A, rec["id"], {"violation_type": "unclassified"})
    result = engine.resolve_violation(ORG_A, viol["id"])
    assert result is True
    resolved = engine.list_violations(ORG_A, status="resolved")
    assert any(v["id"] == viol["id"] for v in resolved)


def test_resolve_violation_not_found_returns_false(engine):
    engine.register_asset(ORG_A, _asset())
    assert engine.resolve_violation(ORG_A, "bad-id") is False


# ---------------------------------------------------------------------------
# get_stats
# ---------------------------------------------------------------------------

def test_get_stats_empty(engine):
    stats = engine.get_stats(ORG_A)
    assert stats["total_assets"] == 0
    assert stats["coverage_pct"] == 0.0
    assert stats["pii_exposed_count"] == 0


def test_get_stats_counts_assets(engine):
    engine.register_asset(ORG_A, _asset("A", classification_level="confidential"))
    engine.register_asset(ORG_A, _asset("B", classification_level="secret"))
    stats = engine.get_stats(ORG_A)
    assert stats["total_assets"] == 2
    assert "confidential" in stats["by_classification"]


def test_get_stats_open_violations(engine):
    rec = engine.register_asset(ORG_A, _asset())
    engine.log_violation(ORG_A, rec["id"], {"violation_type": "pii_exposed", "severity": "high"})
    stats = engine.get_stats(ORG_A)
    assert stats["open_violations_by_severity"].get("high", 0) >= 1


def test_get_stats_org_isolation(engine):
    engine.register_asset(ORG_A, _asset())
    stats_b = engine.get_stats(ORG_B)
    assert stats_b["total_assets"] == 0
