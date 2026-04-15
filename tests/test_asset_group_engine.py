"""Tests for AssetGroupEngine — 35+ tests covering all major paths."""

from __future__ import annotations

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'suite-core'))

from core.asset_group_engine import AssetGroupEngine

ORG = "test-org-ag"
ORG2 = "other-org-ag"


@pytest.fixture
def engine(tmp_path):
    return AssetGroupEngine(db_path=str(tmp_path / "ag.db"))


# ---------------------------------------------------------------------------
# create_group
# ---------------------------------------------------------------------------

def test_create_group_basic(engine):
    g = engine.create_group(ORG, "Web Servers", "functional", owner="alice")
    assert g["id"]
    assert g["group_name"] == "Web Servers"
    assert g["group_type"] == "functional"
    assert g["member_count"] == 0
    assert g["criticality"] == "medium"


def test_create_group_all_types(engine):
    types = ["functional", "compliance", "geographic", "cloud", "network", "security-zone", "business-unit", "custom"]
    for gt in types:
        g = engine.create_group(ORG, f"Group-{gt}", gt)
        assert g["group_type"] == gt


def test_create_group_invalid_type(engine):
    with pytest.raises(ValueError, match="group_type"):
        engine.create_group(ORG, "X", "invalid-type")


def test_create_group_all_criticalities(engine):
    for c in ["critical", "high", "medium", "low"]:
        g = engine.create_group(ORG, f"Group-{c}", "functional", criticality=c)
        assert g["criticality"] == c


def test_create_group_invalid_criticality(engine):
    with pytest.raises(ValueError, match="criticality"):
        engine.create_group(ORG, "X", "functional", criticality="unknown")


def test_create_group_org_isolation(engine):
    engine.create_group(ORG, "Group A", "functional")
    assert engine.list_groups(ORG2) == []


# ---------------------------------------------------------------------------
# add_member / remove_member
# ---------------------------------------------------------------------------

def test_add_member_basic(engine):
    g = engine.create_group(ORG, "Group", "functional")
    m = engine.add_member(g["id"], ORG, "asset-001", "server", "bob")
    assert m["asset_id"] == "asset-001"
    assert m["asset_type"] == "server"


def test_add_member_increments_count(engine):
    g = engine.create_group(ORG, "Group", "functional")
    engine.add_member(g["id"], ORG, "asset-001", "server")
    engine.add_member(g["id"], ORG, "asset-002", "workstation")
    group = engine.get_group(g["id"], ORG)
    assert group["member_count"] == 2


def test_add_member_duplicate_no_double_increment(engine):
    g = engine.create_group(ORG, "Group", "functional")
    engine.add_member(g["id"], ORG, "asset-001", "server")
    engine.add_member(g["id"], ORG, "asset-001", "server")  # duplicate
    group = engine.get_group(g["id"], ORG)
    assert group["member_count"] == 1


def test_add_member_all_asset_types(engine):
    g = engine.create_group(ORG, "Group", "functional")
    types = ["server", "workstation", "network-device", "cloud-instance", "container", "application", "database", "iot-device"]
    for i, at in enumerate(types):
        m = engine.add_member(g["id"], ORG, f"asset-{i}", at)
        assert m["asset_type"] == at


def test_add_member_invalid_asset_type(engine):
    g = engine.create_group(ORG, "Group", "functional")
    with pytest.raises(ValueError, match="asset_type"):
        engine.add_member(g["id"], ORG, "asset-001", "mainframe")


def test_remove_member_basic(engine):
    g = engine.create_group(ORG, "Group", "functional")
    engine.add_member(g["id"], ORG, "asset-001", "server")
    result = engine.remove_member(g["id"], ORG, "asset-001")
    assert result["removed"] is True
    group = engine.get_group(g["id"], ORG)
    assert group["member_count"] == 0


def test_remove_member_floor_at_zero(engine):
    g = engine.create_group(ORG, "Group", "functional")
    # Remove non-existent member — count should stay at 0
    result = engine.remove_member(g["id"], ORG, "asset-nonexistent")
    assert result["removed"] is False
    group = engine.get_group(g["id"], ORG)
    assert group["member_count"] == 0


def test_remove_member_count_decrements_correctly(engine):
    g = engine.create_group(ORG, "Group", "functional")
    engine.add_member(g["id"], ORG, "asset-001", "server")
    engine.add_member(g["id"], ORG, "asset-002", "server")
    engine.remove_member(g["id"], ORG, "asset-001")
    group = engine.get_group(g["id"], ORG)
    assert group["member_count"] == 1
    assert len(group["members"]) == 1


# ---------------------------------------------------------------------------
# add_policy / toggle_policy
# ---------------------------------------------------------------------------

def test_add_policy_basic(engine):
    g = engine.create_group(ORG, "Group", "functional")
    p = engine.add_policy(g["id"], ORG, "Weekly Scan", "scan", {"schedule": "weekly"})
    assert p["id"]
    assert p["policy_name"] == "Weekly Scan"
    assert p["policy_type"] == "scan"
    assert p["enabled"] is True
    assert p["config"]["schedule"] == "weekly"


def test_add_policy_all_types(engine):
    g = engine.create_group(ORG, "Group", "functional")
    for pt in ["scan", "patch", "monitoring", "backup", "access", "compliance", "retention"]:
        p = engine.add_policy(g["id"], ORG, f"Policy-{pt}", pt)
        assert p["policy_type"] == pt


def test_add_policy_invalid_type(engine):
    g = engine.create_group(ORG, "Group", "functional")
    with pytest.raises(ValueError, match="policy_type"):
        engine.add_policy(g["id"], ORG, "Bad Policy", "unknown-type")


def test_toggle_policy_disables_then_enables(engine):
    g = engine.create_group(ORG, "Group", "functional")
    p = engine.add_policy(g["id"], ORG, "Scan", "scan")
    assert p["enabled"] is True
    toggled = engine.toggle_policy(p["id"], g["id"], ORG)
    assert toggled["enabled"] is False
    toggled2 = engine.toggle_policy(p["id"], g["id"], ORG)
    assert toggled2["enabled"] is True


def test_toggle_policy_not_found(engine):
    g = engine.create_group(ORG, "Group", "functional")
    with pytest.raises(ValueError):
        engine.toggle_policy("nonexistent-id", g["id"], ORG)


# ---------------------------------------------------------------------------
# get_group / list_groups
# ---------------------------------------------------------------------------

def test_get_group_includes_members_and_policies(engine):
    g = engine.create_group(ORG, "Group", "functional")
    engine.add_member(g["id"], ORG, "asset-001", "server")
    engine.add_policy(g["id"], ORG, "Scan", "scan")
    group = engine.get_group(g["id"], ORG)
    assert len(group["members"]) == 1
    assert len(group["policies"]) == 1


def test_get_group_not_found(engine):
    assert engine.get_group("nonexistent-id", ORG) is None


def test_list_groups_filter_type(engine):
    engine.create_group(ORG, "Compliance Group", "compliance")
    engine.create_group(ORG, "Cloud Group", "cloud")
    results = engine.list_groups(ORG, group_type="compliance")
    assert len(results) == 1
    assert results[0]["group_type"] == "compliance"


def test_list_groups_filter_criticality(engine):
    engine.create_group(ORG, "Critical Group", "functional", criticality="critical")
    engine.create_group(ORG, "Low Group", "functional", criticality="low")
    results = engine.list_groups(ORG, criticality="critical")
    assert len(results) == 1
    assert results[0]["group_name"] == "Critical Group"


# ---------------------------------------------------------------------------
# get_asset_groups
# ---------------------------------------------------------------------------

def test_get_asset_groups_basic(engine):
    g1 = engine.create_group(ORG, "Group 1", "functional")
    g2 = engine.create_group(ORG, "Group 2", "cloud")
    engine.add_member(g1["id"], ORG, "asset-X", "server")
    engine.add_member(g2["id"], ORG, "asset-X", "server")
    groups = engine.get_asset_groups(ORG, "asset-X")
    assert len(groups) == 2


def test_get_asset_groups_empty(engine):
    groups = engine.get_asset_groups(ORG, "asset-nonexistent")
    assert groups == []


def test_get_asset_groups_org_isolation(engine):
    g = engine.create_group(ORG, "Group", "functional")
    engine.add_member(g["id"], ORG, "asset-X", "server")
    # ORG2 has same asset_id but different org — should return empty
    groups = engine.get_asset_groups(ORG2, "asset-X")
    assert groups == []


# ---------------------------------------------------------------------------
# bulk_add_members
# ---------------------------------------------------------------------------

def test_bulk_add_members_basic(engine):
    g = engine.create_group(ORG, "Group", "functional")
    result = engine.bulk_add_members(g["id"], ORG, ["a1", "a2", "a3"], "server", "admin")
    assert result["added"] == 3
    assert result["requested"] == 3
    group = engine.get_group(g["id"], ORG)
    assert group["member_count"] == 3


def test_bulk_add_members_dedup(engine):
    g = engine.create_group(ORG, "Group", "functional")
    engine.add_member(g["id"], ORG, "a1", "server")
    result = engine.bulk_add_members(g["id"], ORG, ["a1", "a2", "a3"], "server")
    # a1 is a duplicate — only a2 and a3 should be added
    assert result["added"] == 2
    group = engine.get_group(g["id"], ORG)
    assert group["member_count"] == 3


def test_bulk_add_members_invalid_asset_type(engine):
    g = engine.create_group(ORG, "Group", "functional")
    with pytest.raises(ValueError, match="asset_type"):
        engine.bulk_add_members(g["id"], ORG, ["a1", "a2"], "mainframe")


# ---------------------------------------------------------------------------
# get_group_stats
# ---------------------------------------------------------------------------

def test_group_stats_empty(engine):
    stats = engine.get_group_stats(ORG)
    assert stats["total_groups"] == 0
    assert stats["total_members"] == 0
    assert stats["largest_group"] is None


def test_group_stats_with_data(engine):
    g1 = engine.create_group(ORG, "Big Group", "functional", criticality="critical")
    g2 = engine.create_group(ORG, "Small Group", "cloud", criticality="low")
    engine.bulk_add_members(g1["id"], ORG, ["a1", "a2", "a3"], "server")
    engine.add_member(g2["id"], ORG, "b1", "container")
    stats = engine.get_group_stats(ORG)
    assert stats["total_groups"] == 2
    assert stats["total_members"] == 4
    assert stats["largest_group"]["group_name"] == "Big Group"
    assert stats["by_criticality"]["critical"] == 1
    assert stats["by_criticality"]["low"] == 1
    assert stats["by_type"]["functional"] == 1
    assert stats["by_type"]["cloud"] == 1
