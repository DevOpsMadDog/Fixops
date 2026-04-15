"""Tests for AssetTaggingEngine — ALDECI."""

from __future__ import annotations

import pytest

from core.asset_tagging_engine import AssetTaggingEngine


@pytest.fixture
def engine(tmp_path):
    return AssetTaggingEngine(db_path=str(tmp_path / "asset_tagging.db"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tag(engine, org_id="org1", **kwargs):
    data = dict(tag_key="env", tag_value="production", tag_category="environment")
    data.update(kwargs)
    return engine.create_tag(org_id, data)


def _asset(engine, org_id="org1", **kwargs):
    data = dict(asset_name="web-server-01", asset_type="server", criticality="high")
    data.update(kwargs)
    return engine.register_asset(org_id, data)


# ---------------------------------------------------------------------------
# create_tag — validation
# ---------------------------------------------------------------------------

def test_create_tag_missing_key_raises(engine):
    with pytest.raises(ValueError, match="tag_key"):
        engine.create_tag("org1", {"tag_value": "prod", "tag_category": "environment"})


def test_create_tag_empty_key_raises(engine):
    with pytest.raises(ValueError, match="tag_key"):
        engine.create_tag("org1", {"tag_key": "   ", "tag_value": "prod"})


def test_create_tag_missing_value_raises(engine):
    with pytest.raises(ValueError, match="tag_value"):
        engine.create_tag("org1", {"tag_key": "env", "tag_category": "environment"})


def test_create_tag_empty_value_raises(engine):
    with pytest.raises(ValueError, match="tag_value"):
        engine.create_tag("org1", {"tag_key": "env", "tag_value": "   "})


def test_create_tag_invalid_category_raises(engine):
    with pytest.raises(ValueError, match="tag_category"):
        engine.create_tag("org1", {"tag_key": "env", "tag_value": "prod", "tag_category": "unknown"})


# ---------------------------------------------------------------------------
# create_tag — valid categories
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("category", [
    "environment", "criticality", "data_classification", "owner",
    "compliance", "technology", "location", "department",
])
def test_create_tag_all_categories(engine, category):
    t = _tag(engine, tag_category=category)
    assert t["tag_category"] == category
    assert t["usage_count"] == 0
    assert "id" in t
    assert "created_at" in t
    assert t["org_id"] == "org1"


def test_create_tag_returns_full_record(engine):
    t = _tag(engine, tag_key="team", tag_value="security", description="Security team tag")
    assert t["tag_key"] == "team"
    assert t["tag_value"] == "security"
    assert t["description"] == "Security team tag"
    assert t["usage_count"] == 0


# ---------------------------------------------------------------------------
# list_tags
# ---------------------------------------------------------------------------

def test_list_tags_empty(engine):
    assert engine.list_tags("org1") == []


def test_list_tags_org_isolation(engine):
    _tag(engine, org_id="org1")
    _tag(engine, org_id="org2")
    assert len(engine.list_tags("org1")) == 1
    assert len(engine.list_tags("org2")) == 1


def test_list_tags_filter_category(engine):
    _tag(engine, tag_category="environment")
    _tag(engine, tag_key="owner", tag_value="team-a", tag_category="owner")
    results = engine.list_tags("org1", tag_category="owner")
    assert len(results) == 1
    assert results[0]["tag_category"] == "owner"


def test_list_tags_no_filter_returns_all(engine):
    _tag(engine, tag_category="environment")
    _tag(engine, tag_key="x", tag_value="y", tag_category="owner")
    assert len(engine.list_tags("org1")) == 2


# ---------------------------------------------------------------------------
# get_tag
# ---------------------------------------------------------------------------

def test_get_tag_found(engine):
    t = _tag(engine)
    fetched = engine.get_tag("org1", t["id"])
    assert fetched is not None
    assert fetched["id"] == t["id"]
    assert fetched["tag_key"] == "env"


def test_get_tag_not_found(engine):
    assert engine.get_tag("org1", "nonexistent") is None


def test_get_tag_wrong_org(engine):
    t = _tag(engine, org_id="org1")
    assert engine.get_tag("org2", t["id"]) is None


# ---------------------------------------------------------------------------
# register_asset — validation
# ---------------------------------------------------------------------------

def test_register_asset_missing_name_raises(engine):
    with pytest.raises(ValueError, match="asset_name"):
        engine.register_asset("org1", {"asset_type": "server"})


def test_register_asset_empty_name_raises(engine):
    with pytest.raises(ValueError, match="asset_name"):
        engine.register_asset("org1", {"asset_name": "  ", "asset_type": "server"})


def test_register_asset_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="asset_type"):
        engine.register_asset("org1", {"asset_name": "A", "asset_type": "mainframe"})


def test_register_asset_invalid_criticality_raises(engine):
    with pytest.raises(ValueError, match="criticality"):
        engine.register_asset("org1", {"asset_name": "A", "asset_type": "server", "criticality": "ultra"})


# ---------------------------------------------------------------------------
# register_asset — valid asset types and criticalities
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("asset_type", [
    "server", "workstation", "network", "application", "database",
    "cloud", "iot", "mobile", "container",
])
def test_register_asset_all_types(engine, asset_type):
    a = _asset(engine, asset_type=asset_type)
    assert a["asset_type"] == asset_type
    assert a["tag_count"] == 0
    assert "id" in a
    assert "created_at" in a


@pytest.mark.parametrize("criticality", ["mission_critical", "high", "medium", "low"])
def test_register_asset_all_criticalities(engine, criticality):
    a = _asset(engine, criticality=criticality)
    assert a["criticality"] == criticality


def test_register_asset_default_criticality(engine):
    a = engine.register_asset("org1", {"asset_name": "db-01", "asset_type": "database"})
    assert a["criticality"] == "medium"
    assert a["tag_count"] == 0


def test_register_asset_with_owner_environment(engine):
    a = _asset(engine, owner="team-ops", environment="production")
    assert a["owner"] == "team-ops"
    assert a["environment"] == "production"


# ---------------------------------------------------------------------------
# list_assets
# ---------------------------------------------------------------------------

def test_list_assets_empty(engine):
    assert engine.list_assets("org1") == []


def test_list_assets_org_isolation(engine):
    _asset(engine, org_id="org1")
    _asset(engine, org_id="org2")
    assert len(engine.list_assets("org1")) == 1
    assert len(engine.list_assets("org2")) == 1


def test_list_assets_filter_type(engine):
    _asset(engine, asset_type="server")
    _asset(engine, asset_name="app-01", asset_type="application")
    results = engine.list_assets("org1", asset_type="application")
    assert len(results) == 1
    assert results[0]["asset_type"] == "application"


def test_list_assets_filter_criticality(engine):
    _asset(engine, criticality="high")
    _asset(engine, asset_name="low-01", criticality="low")
    results = engine.list_assets("org1", criticality="low")
    assert len(results) == 1
    assert results[0]["criticality"] == "low"


def test_list_assets_filter_environment(engine):
    _asset(engine, environment="production")
    _asset(engine, asset_name="dev-01", environment="development")
    results = engine.list_assets("org1", environment="production")
    assert len(results) == 1
    assert results[0]["environment"] == "production"


# ---------------------------------------------------------------------------
# get_asset
# ---------------------------------------------------------------------------

def test_get_asset_found(engine):
    a = _asset(engine)
    fetched = engine.get_asset("org1", a["asset_id"])
    assert fetched is not None
    assert fetched["asset_id"] == a["asset_id"]


def test_get_asset_not_found(engine):
    assert engine.get_asset("org1", "nonexistent") is None


def test_get_asset_wrong_org(engine):
    a = _asset(engine, org_id="org1")
    assert engine.get_asset("org2", a["asset_id"]) is None


# ---------------------------------------------------------------------------
# assign_tag
# ---------------------------------------------------------------------------

def test_assign_tag_success(engine):
    t = _tag(engine)
    a = _asset(engine)
    assignment = engine.assign_tag("org1", a["asset_id"], t["id"])
    assert assignment["asset_id"] == a["asset_id"]
    assert assignment["tag_id"] == t["id"]
    assert assignment["assigned_by"] == "system"
    assert "assigned_at" in assignment


def test_assign_tag_increments_usage_count(engine):
    t = _tag(engine)
    a = _asset(engine)
    assert engine.get_tag("org1", t["id"])["usage_count"] == 0
    engine.assign_tag("org1", a["asset_id"], t["id"])
    assert engine.get_tag("org1", t["id"])["usage_count"] == 1


def test_assign_tag_increments_asset_tag_count(engine):
    t = _tag(engine)
    a = _asset(engine)
    assert engine.get_asset("org1", a["asset_id"])["tag_count"] == 0
    engine.assign_tag("org1", a["asset_id"], t["id"])
    assert engine.get_asset("org1", a["asset_id"])["tag_count"] == 1


def test_assign_tag_invalid_asset_raises(engine):
    t = _tag(engine)
    with pytest.raises(KeyError, match="Asset"):
        engine.assign_tag("org1", "bad-asset-id", t["id"])


def test_assign_tag_invalid_tag_raises(engine):
    a = _asset(engine)
    with pytest.raises(KeyError, match="Tag"):
        engine.assign_tag("org1", a["asset_id"], "bad-tag-id")


def test_assign_tag_wrong_org_asset_raises(engine):
    t = _tag(engine, org_id="org1")
    a = _asset(engine, org_id="org2")
    # Tag is in org1, asset is in org2 — both lookups use org1
    with pytest.raises(KeyError):
        engine.assign_tag("org1", a["asset_id"], t["id"])


def test_assign_tag_duplicate_idempotent(engine):
    """Duplicate assignment should not double-increment counters."""
    t = _tag(engine)
    a = _asset(engine)
    engine.assign_tag("org1", a["asset_id"], t["id"])
    engine.assign_tag("org1", a["asset_id"], t["id"])  # duplicate
    assert engine.get_tag("org1", t["id"])["usage_count"] == 1
    assert engine.get_asset("org1", a["asset_id"])["tag_count"] == 1


def test_assign_tag_custom_assigned_by(engine):
    t = _tag(engine)
    a = _asset(engine)
    assignment = engine.assign_tag("org1", a["asset_id"], t["id"], assigned_by="alice")
    assert assignment["assigned_by"] == "alice"


# ---------------------------------------------------------------------------
# list_asset_tags
# ---------------------------------------------------------------------------

def test_list_asset_tags_empty(engine):
    a = _asset(engine)
    assert engine.list_asset_tags("org1", a["asset_id"]) == []


def test_list_asset_tags_returns_joined_data(engine):
    t = _tag(engine, tag_key="region", tag_value="us-east-1", tag_category="location")
    a = _asset(engine)
    engine.assign_tag("org1", a["asset_id"], t["id"])
    tags = engine.list_asset_tags("org1", a["asset_id"])
    assert len(tags) == 1
    assert tags[0]["tag_key"] == "region"
    assert tags[0]["tag_value"] == "us-east-1"
    assert tags[0]["tag_category"] == "location"


def test_list_asset_tags_multiple(engine):
    t1 = _tag(engine, tag_key="env", tag_value="prod")
    t2 = _tag(engine, tag_key="team", tag_value="ops", tag_category="owner")
    a = _asset(engine)
    engine.assign_tag("org1", a["asset_id"], t1["id"])
    engine.assign_tag("org1", a["asset_id"], t2["id"])
    tags = engine.list_asset_tags("org1", a["asset_id"])
    assert len(tags) == 2


# ---------------------------------------------------------------------------
# bulk_tag_assets
# ---------------------------------------------------------------------------

def test_bulk_tag_assets_success(engine):
    t = _tag(engine)
    a1 = _asset(engine, asset_name="srv-1")
    a2 = _asset(engine, asset_name="srv-2")
    results = engine.bulk_tag_assets("org1", [a1["asset_id"], a2["asset_id"]], t["id"])
    assert len(results) == 2
    assert all(r["status"] == "ok" for r in results)


def test_bulk_tag_assets_partial_failure(engine):
    t = _tag(engine)
    a = _asset(engine)
    results = engine.bulk_tag_assets("org1", [a["asset_id"], "bad-id"], t["id"])
    assert len(results) == 2
    ok_results = [r for r in results if r["status"] == "ok"]
    err_results = [r for r in results if r["status"] == "error"]
    assert len(ok_results) == 1
    assert len(err_results) == 1


def test_bulk_tag_assets_increments_usage_count(engine):
    t = _tag(engine)
    a1 = _asset(engine, asset_name="srv-1")
    a2 = _asset(engine, asset_name="srv-2")
    engine.bulk_tag_assets("org1", [a1["asset_id"], a2["asset_id"]], t["id"])
    assert engine.get_tag("org1", t["id"])["usage_count"] == 2


def test_bulk_tag_assets_returns_asset_ids(engine):
    t = _tag(engine)
    a1 = _asset(engine, asset_name="srv-1")
    results = engine.bulk_tag_assets("org1", [a1["asset_id"]], t["id"])
    assert results[0]["asset_id"] == a1["asset_id"]


# ---------------------------------------------------------------------------
# get_tag_stats
# ---------------------------------------------------------------------------

def test_get_tag_stats_empty(engine):
    stats = engine.get_tag_stats("org1")
    assert stats["total_tags"] == 0
    assert stats["total_assets"] == 0
    assert stats["total_assignments"] == 0
    assert stats["by_category"] == {}
    assert stats["by_asset_type"] == {}
    assert stats["most_used_tag"] is None
    assert stats["untagged_assets"] == 0


def test_get_tag_stats_counts(engine):
    t1 = _tag(engine, tag_category="environment")
    t2 = _tag(engine, tag_key="x", tag_value="y", tag_category="owner")
    a1 = _asset(engine, asset_type="server")
    a2 = _asset(engine, asset_name="db-01", asset_type="database")
    engine.assign_tag("org1", a1["asset_id"], t1["id"])
    engine.assign_tag("org1", a1["asset_id"], t2["id"])
    engine.assign_tag("org1", a2["asset_id"], t1["id"])

    stats = engine.get_tag_stats("org1")
    assert stats["total_tags"] == 2
    assert stats["total_assets"] == 2
    assert stats["total_assignments"] == 3
    assert stats["by_category"]["environment"] == 1
    assert stats["by_category"]["owner"] == 1
    assert stats["by_asset_type"]["server"] == 1
    assert stats["by_asset_type"]["database"] == 1


def test_get_tag_stats_most_used_tag(engine):
    t1 = _tag(engine, tag_key="env", tag_value="prod")
    t2 = _tag(engine, tag_key="team", tag_value="ops", tag_category="owner")
    a1 = _asset(engine, asset_name="srv-1")
    a2 = _asset(engine, asset_name="srv-2")
    engine.assign_tag("org1", a1["asset_id"], t1["id"])
    engine.assign_tag("org1", a2["asset_id"], t1["id"])
    engine.assign_tag("org1", a1["asset_id"], t2["id"])

    stats = engine.get_tag_stats("org1")
    assert stats["most_used_tag"] is not None
    assert stats["most_used_tag"]["id"] == t1["id"]
    assert stats["most_used_tag"]["usage_count"] == 2


def test_get_tag_stats_untagged_assets(engine):
    _asset(engine, asset_name="untagged-1")
    _asset(engine, asset_name="untagged-2")
    t = _tag(engine)
    a = _asset(engine, asset_name="tagged-1")
    engine.assign_tag("org1", a["asset_id"], t["id"])

    stats = engine.get_tag_stats("org1")
    assert stats["untagged_assets"] == 2
    assert stats["total_assets"] == 3


def test_get_tag_stats_org_isolation(engine):
    _tag(engine, org_id="org1")
    _tag(engine, org_id="org2")
    _asset(engine, org_id="org1")
    _asset(engine, org_id="org2")

    stats1 = engine.get_tag_stats("org1")
    stats2 = engine.get_tag_stats("org2")
    assert stats1["total_tags"] == 1
    assert stats2["total_tags"] == 1
    assert stats1["total_assets"] == 1
    assert stats2["total_assets"] == 1
