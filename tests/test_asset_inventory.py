"""Tests for Asset Inventory and CMDB Integration.

Tests cover:
- Asset CRUD (register, get, update, delete)
- Lifecycle transitions (valid and invalid)
- Discover from findings
- Owner assignment
- Tag management
- Search
- Stale / unowned detection
- CMDB sync recording
- Inventory stats
- Bulk import
- Filters

Usage:
    pytest tests/test_asset_inventory.py -v --timeout=10
"""

from __future__ import annotations

import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict

import pytest

# Ensure suite-core is on sys.path
suite_core_path = str(Path(__file__).parent.parent / "suite-core")
if suite_core_path not in sys.path:
    sys.path.insert(0, suite_core_path)

from core.asset_inventory import (
    AssetCriticality,
    AssetInventory,
    AssetLifecycle,
    CMDBSyncRecord,
    Environment,
    ManagedAsset,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def inventory(tmp_path):
    """Fresh in-memory-equivalent inventory backed by a temp file."""
    db_file = str(tmp_path / "test_asset_inventory.db")
    return AssetInventory(db_path=db_file)


def _make_asset(**kwargs) -> ManagedAsset:
    defaults: Dict[str, Any] = {
        "name": "web-server-01",
        "asset_type": "server",
        "hostname": "web-server-01.internal",
        "ip_address": "10.0.0.1",
        "owner_email": "ops@example.com",
        "team": "platform",
        "criticality": AssetCriticality.HIGH,
        "environment": Environment.PRODUCTION,
        "lifecycle": AssetLifecycle.ACTIVE,
        "tags": ["web", "prod"],
        "org_id": "org-test",
    }
    defaults.update(kwargs)
    return ManagedAsset(**defaults)


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

class TestAssetCRUD:
    def test_register_and_get(self, inventory):
        asset = _make_asset()
        registered = inventory.register_asset(asset)
        assert registered.id == asset.id
        fetched = inventory.get_asset(asset.id)
        assert fetched is not None
        assert fetched.name == "web-server-01"
        assert fetched.org_id == "org-test"

    def test_get_nonexistent(self, inventory):
        assert inventory.get_asset("masset-doesnotexist") is None

    def test_list_assets(self, inventory):
        inventory.register_asset(_make_asset(name="asset-a", org_id="org-1"))
        inventory.register_asset(_make_asset(name="asset-b", org_id="org-1"))
        inventory.register_asset(_make_asset(name="asset-c", org_id="org-2"))
        results = inventory.list_assets("org-1")
        assert len(results) == 2
        names = {a.name for a in results}
        assert names == {"asset-a", "asset-b"}

    def test_update_asset(self, inventory):
        asset = inventory.register_asset(_make_asset())
        updated = inventory.update_asset(asset.id, {"team": "security", "risk_score": 0.85})
        assert updated is not None
        assert updated.team == "security"
        assert updated.risk_score == pytest.approx(0.85)

    def test_update_nonexistent(self, inventory):
        result = inventory.update_asset("masset-ghost", {"team": "nobody"})
        assert result is None

    def test_delete_asset(self, inventory):
        asset = inventory.register_asset(_make_asset())
        assert inventory.delete_asset(asset.id) is True
        assert inventory.get_asset(asset.id) is None

    def test_delete_nonexistent(self, inventory):
        assert inventory.delete_asset("masset-ghost") is False

    def test_register_updates_last_seen(self, inventory):
        asset = _make_asset()
        before = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        registered = inventory.register_asset(asset)
        assert registered.last_seen >= before


# ---------------------------------------------------------------------------
# Lifecycle transitions
# ---------------------------------------------------------------------------

class TestLifecycleTransitions:
    def test_valid_transition_discovered_to_active(self, inventory):
        asset = inventory.register_asset(_make_asset(lifecycle=AssetLifecycle.DISCOVERED))
        result = inventory.transition_lifecycle(asset.id, AssetLifecycle.ACTIVE)
        assert result.lifecycle == AssetLifecycle.ACTIVE

    def test_valid_transition_active_to_maintenance(self, inventory):
        asset = inventory.register_asset(_make_asset(lifecycle=AssetLifecycle.ACTIVE))
        result = inventory.transition_lifecycle(asset.id, AssetLifecycle.MAINTENANCE)
        assert result.lifecycle == AssetLifecycle.MAINTENANCE

    def test_valid_transition_active_to_deprecated(self, inventory):
        asset = inventory.register_asset(_make_asset(lifecycle=AssetLifecycle.ACTIVE))
        result = inventory.transition_lifecycle(asset.id, AssetLifecycle.DEPRECATED)
        assert result.lifecycle == AssetLifecycle.DEPRECATED

    def test_valid_transition_deprecated_to_decommissioned(self, inventory):
        asset = inventory.register_asset(_make_asset(lifecycle=AssetLifecycle.DEPRECATED))
        result = inventory.transition_lifecycle(asset.id, AssetLifecycle.DECOMMISSIONED)
        assert result.lifecycle == AssetLifecycle.DECOMMISSIONED

    def test_invalid_transition_decommissioned_to_active(self, inventory):
        asset = inventory.register_asset(_make_asset(lifecycle=AssetLifecycle.DECOMMISSIONED))
        with pytest.raises(ValueError, match="Invalid lifecycle transition"):
            inventory.transition_lifecycle(asset.id, AssetLifecycle.ACTIVE)

    def test_invalid_transition_discovered_to_maintenance(self, inventory):
        asset = inventory.register_asset(_make_asset(lifecycle=AssetLifecycle.DISCOVERED))
        with pytest.raises(ValueError, match="Invalid lifecycle transition"):
            inventory.transition_lifecycle(asset.id, AssetLifecycle.MAINTENANCE)

    def test_transition_nonexistent_asset(self, inventory):
        with pytest.raises(ValueError, match="not found"):
            inventory.transition_lifecycle("masset-ghost", AssetLifecycle.ACTIVE)


# ---------------------------------------------------------------------------
# Discovery from findings
# ---------------------------------------------------------------------------

class TestDiscoverFromFindings:
    def test_discover_basic(self, inventory):
        findings = [
            {"hostname": "db-01.internal", "ip_address": "10.0.0.5", "type": "database"},
            {"host": "app-01.internal", "asset_type": "server"},
        ]
        assets = inventory.discover_from_findings(findings, "org-disc")
        assert len(assets) == 2
        names = {a.name for a in assets}
        assert "db-01.internal" in names
        assert "app-01.internal" in names

    def test_discover_deduplication(self, inventory):
        findings = [
            {"hostname": "dup-host", "type": "server"},
            {"hostname": "dup-host", "type": "server"},
        ]
        assets = inventory.discover_from_findings(findings, "org-dup")
        assert len(assets) == 1

    def test_discover_increments_finding_count(self, inventory):
        findings = [{"hostname": "monitored-host", "type": "server"}]
        first = inventory.discover_from_findings(findings, "org-count")
        second = inventory.discover_from_findings(findings, "org-count")
        assert second[0].finding_count == 2

    def test_discover_sets_lifecycle_discovered(self, inventory):
        findings = [{"hostname": "new-host", "type": "server"}]
        assets = inventory.discover_from_findings(findings, "org-lc")
        assert assets[0].lifecycle == AssetLifecycle.DISCOVERED

    def test_discover_from_url_finding(self, inventory):
        findings = [{"url": "https://api.example.com", "asset_type": "api_endpoint"}]
        assets = inventory.discover_from_findings(findings, "org-url")
        assert len(assets) == 1
        assert assets[0].name == "https://api.example.com"


# ---------------------------------------------------------------------------
# Owner assignment
# ---------------------------------------------------------------------------

class TestOwnerAssignment:
    def test_assign_owner(self, inventory):
        asset = inventory.register_asset(_make_asset(owner_email=None, team=None))
        result = inventory.assign_owner(asset.id, "alice@example.com", team="security")
        assert result.owner_email == "alice@example.com"
        assert result.team == "security"

    def test_assign_owner_without_team(self, inventory):
        asset = inventory.register_asset(_make_asset(owner_email=None))
        result = inventory.assign_owner(asset.id, "bob@example.com")
        assert result.owner_email == "bob@example.com"

    def test_get_unowned_assets(self, inventory):
        inventory.register_asset(_make_asset(name="owned", owner_email="someone@x.com", org_id="org-own"))
        inventory.register_asset(_make_asset(name="unowned1", owner_email=None, org_id="org-own"))
        inventory.register_asset(_make_asset(name="unowned2", owner_email=None, org_id="org-own"))
        unowned = inventory.get_unowned_assets("org-own")
        assert len(unowned) == 2
        names = {a.name for a in unowned}
        assert "unowned1" in names
        assert "unowned2" in names


# ---------------------------------------------------------------------------
# Tag management
# ---------------------------------------------------------------------------

class TestTagManagement:
    def test_add_tags(self, inventory):
        asset = inventory.register_asset(_make_asset(tags=["web"]))
        result = inventory.tag_asset(asset.id, ["prod", "critical"])
        assert set(result.tags) == {"web", "prod", "critical"}

    def test_tags_deduplication(self, inventory):
        asset = inventory.register_asset(_make_asset(tags=["web", "prod"]))
        result = inventory.tag_asset(asset.id, ["prod", "new-tag"])
        assert result.tags.count("prod") == 1
        assert "new-tag" in result.tags

    def test_filter_by_tag(self, inventory):
        inventory.register_asset(_make_asset(name="tagged", tags=["pci"], org_id="org-tag"))
        inventory.register_asset(_make_asset(name="untagged", tags=[], org_id="org-tag"))
        results = inventory.list_assets("org-tag", tag="pci")
        assert len(results) == 1
        assert results[0].name == "tagged"


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------

class TestSearch:
    def test_search_by_name(self, inventory):
        inventory.register_asset(_make_asset(name="postgres-primary", org_id="org-s"))
        inventory.register_asset(_make_asset(name="redis-cache", org_id="org-s"))
        results = inventory.search_assets("postgres", "org-s")
        assert len(results) == 1
        assert results[0].name == "postgres-primary"

    def test_search_by_ip(self, inventory):
        inventory.register_asset(_make_asset(name="server-x", ip_address="192.168.1.100", org_id="org-s2"))
        results = inventory.search_assets("192.168.1", "org-s2")
        assert len(results) == 1

    def test_search_no_results(self, inventory):
        inventory.register_asset(_make_asset(name="server-y", org_id="org-s3"))
        results = inventory.search_assets("zzznomatch", "org-s3")
        assert results == []

    def test_search_isolated_to_org(self, inventory):
        inventory.register_asset(_make_asset(name="shared-name", org_id="org-a"))
        inventory.register_asset(_make_asset(name="shared-name", org_id="org-b"))
        results = inventory.search_assets("shared-name", "org-a")
        assert len(results) == 1


# ---------------------------------------------------------------------------
# Stale assets
# ---------------------------------------------------------------------------

class TestStaleAssets:
    def test_stale_detection(self, inventory):
        # Register with a very recent last_seen
        fresh = inventory.register_asset(_make_asset(name="fresh", org_id="org-stale"))
        # Register and manually backdate last_seen
        old_asset = _make_asset(name="old", org_id="org-stale")
        old_asset.last_seen = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
        inventory.register_asset(old_asset)

        stale = inventory.get_stale_assets("org-stale", days=30)
        names = {a.name for a in stale}
        assert "old" in names
        assert "fresh" not in names

    def test_no_stale_assets(self, inventory):
        inventory.register_asset(_make_asset(name="brand-new", org_id="org-fresh"))
        stale = inventory.get_stale_assets("org-fresh", days=7)
        assert stale == []


# ---------------------------------------------------------------------------
# CMDB sync
# ---------------------------------------------------------------------------

class TestCMDBSync:
    def test_sync_record_created(self, inventory):
        asset = inventory.register_asset(_make_asset())
        record = inventory.sync_to_cmdb(
            asset.id, cmdb_system="ServiceNow", external_id="SN-12345"
        )
        assert isinstance(record, CMDBSyncRecord)
        assert record.asset_id == asset.id
        assert record.cmdb_system == "ServiceNow"
        assert record.external_id == "SN-12345"
        assert record.sync_status == "success"

    def test_sync_with_changes(self, inventory):
        asset = inventory.register_asset(_make_asset())
        changes = {"criticality": "high", "owner": "alice@example.com"}
        record = inventory.sync_to_cmdb(
            asset.id, cmdb_system="Jira", external_id="JIRA-999", changes=changes
        )
        assert record.changes == changes

    def test_sync_history(self, inventory):
        asset = inventory.register_asset(_make_asset())
        inventory.sync_to_cmdb(asset.id, "ServiceNow", "SN-1")
        inventory.sync_to_cmdb(asset.id, "Jira", "JIRA-2")
        history = inventory.get_sync_history(asset.id)
        assert len(history) == 2
        systems = {r.cmdb_system for r in history}
        assert systems == {"ServiceNow", "Jira"}

    def test_sync_nonexistent_asset_marked_failed(self, inventory):
        record = inventory.sync_to_cmdb("masset-ghost", "ServiceNow", "SN-0")
        assert record.sync_status == "failed"


# ---------------------------------------------------------------------------
# Inventory stats
# ---------------------------------------------------------------------------

class TestInventoryStats:
    def test_stats_structure(self, inventory):
        inventory.register_asset(_make_asset(name="s1", asset_type="server", criticality=AssetCriticality.HIGH, org_id="org-stat"))
        inventory.register_asset(_make_asset(name="s2", asset_type="container", criticality=AssetCriticality.MEDIUM, org_id="org-stat"))
        inventory.register_asset(_make_asset(name="s3", asset_type="server", criticality=AssetCriticality.LOW, owner_email=None, org_id="org-stat"))

        stats = inventory.get_inventory_stats("org-stat")
        assert stats["total"] == 3
        assert stats["by_type"]["server"] == 2
        assert stats["by_type"]["container"] == 1
        assert "by_criticality" in stats
        assert "by_lifecycle" in stats
        assert "by_environment" in stats
        assert stats["unowned_count"] == 1

    def test_stats_empty_org(self, inventory):
        stats = inventory.get_inventory_stats("org-empty")
        assert stats["total"] == 0
        assert stats["unowned_count"] == 0


# ---------------------------------------------------------------------------
# Bulk import
# ---------------------------------------------------------------------------

class TestBulkImport:
    def test_bulk_import_basic(self, inventory):
        raw_assets = [
            {"name": "bulk-1", "asset_type": "server"},
            {"name": "bulk-2", "asset_type": "container"},
            {"name": "bulk-3", "asset_type": "domain"},
        ]
        count = inventory.bulk_import(raw_assets, org_id="org-bulk")
        assert count == 3
        results = inventory.list_assets("org-bulk")
        assert len(results) == 3

    def test_bulk_import_with_enums(self, inventory):
        raw_assets = [
            {
                "name": "enum-asset",
                "asset_type": "server",
                "criticality": "critical",
                "environment": "staging",
                "lifecycle": "active",
            }
        ]
        count = inventory.bulk_import(raw_assets, org_id="org-enum")
        assert count == 1
        asset = inventory.list_assets("org-enum")[0]
        assert asset.criticality == AssetCriticality.CRITICAL
        assert asset.environment == Environment.STAGING
        assert asset.lifecycle == AssetLifecycle.ACTIVE

    def test_bulk_import_skips_invalid(self, inventory):
        raw_assets = [
            {"name": "valid", "asset_type": "server"},
            {"asset_type": "missing-name-field"},  # name is required by Pydantic
            {"name": "also-valid", "asset_type": "domain"},
        ]
        count = inventory.bulk_import(raw_assets, org_id="org-skip")
        assert count == 2

    def test_bulk_import_returns_zero_on_all_invalid(self, inventory):
        raw_assets = [{"bad": "data"}, {"worse": "data"}]
        count = inventory.bulk_import(raw_assets, org_id="org-bad")
        assert count == 0


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------

class TestFilters:
    def test_filter_by_type(self, inventory):
        inventory.register_asset(_make_asset(name="sv", asset_type="server", org_id="org-f"))
        inventory.register_asset(_make_asset(name="ct", asset_type="container", org_id="org-f"))
        results = inventory.list_assets("org-f", asset_type="server")
        assert all(a.asset_type == "server" for a in results)
        assert len(results) == 1

    def test_filter_by_criticality(self, inventory):
        inventory.register_asset(_make_asset(name="crit", criticality=AssetCriticality.CRITICAL, org_id="org-fc"))
        inventory.register_asset(_make_asset(name="low", criticality=AssetCriticality.LOW, org_id="org-fc"))
        results = inventory.list_assets("org-fc", criticality="critical")
        assert len(results) == 1
        assert results[0].name == "crit"

    def test_filter_by_environment(self, inventory):
        inventory.register_asset(_make_asset(name="prod-sv", environment=Environment.PRODUCTION, org_id="org-fe"))
        inventory.register_asset(_make_asset(name="dev-sv", environment=Environment.DEVELOPMENT, org_id="org-fe"))
        results = inventory.list_assets("org-fe", environment="development")
        assert len(results) == 1
        assert results[0].name == "dev-sv"

    def test_filter_by_lifecycle(self, inventory):
        inventory.register_asset(_make_asset(name="disc", lifecycle=AssetLifecycle.DISCOVERED, org_id="org-fl"))
        inventory.register_asset(_make_asset(name="active", lifecycle=AssetLifecycle.ACTIVE, org_id="org-fl"))
        results = inventory.list_assets("org-fl", lifecycle="discovered")
        assert len(results) == 1
        assert results[0].name == "disc"

    def test_filter_by_owner(self, inventory):
        inventory.register_asset(_make_asset(name="mine", owner_email="alice@x.com", org_id="org-fo"))
        inventory.register_asset(_make_asset(name="yours", owner_email="bob@x.com", org_id="org-fo"))
        results = inventory.list_assets("org-fo", owner_email="alice@x.com")
        assert len(results) == 1
        assert results[0].name == "mine"
