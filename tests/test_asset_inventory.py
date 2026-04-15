"""Tests for Asset Inventory and CMDB Engine.

Tests cover:
- Asset CRUD (register, get, update, delete)
- Lifecycle transitions (valid and invalid), including provisioned state
- Discover from findings (dedup, increment, cloud fields, discovery_source)
- Owner assignment (email, name, team, business_unit, cost_center)
- Tag management
- Compliance tagging (auto-scope from data_classification, explicit apply)
- Relationship mapping (add, get, delete, impact graph)
- Search (name, ip, compliance_scope, business_unit)
- Stale / unowned detection
- CMDB sync recording
- Inventory stats (including new fields)
- Bulk import
- Filters (type, criticality, tier, environment, lifecycle, owner, tag,
           business_unit, cloud_provider, region, data_classification, compliance_scope)

Usage:
    pytest tests/test_asset_inventory.py -v --timeout=10
"""

from __future__ import annotations

import sys
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
    AssetRelationship,
    CMDBSyncRecord,
    ComplianceFramework,
    CriticalityTier,
    DataClassification,
    Environment,
    ManagedAsset,
    RelationshipType,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def inventory(tmp_path):
    """Fresh inventory backed by a temp file."""
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
        "criticality_tier": CriticalityTier.T2,
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

    def test_cloud_fields_persisted(self, inventory):
        asset = _make_asset(
            name="ec2-instance",
            asset_type="cloud_resource",
            cloud_provider="aws",
            region="us-east-1",
            cloud_resource_id="arn:aws:ec2:us-east-1:123:instance/i-abc",
        )
        inventory.register_asset(asset)
        fetched = inventory.get_asset(asset.id)
        assert fetched.cloud_provider == "aws"
        assert fetched.region == "us-east-1"
        assert fetched.cloud_resource_id == "arn:aws:ec2:us-east-1:123:instance/i-abc"

    def test_ownership_fields_persisted(self, inventory):
        asset = _make_asset(
            business_unit="Engineering",
            cost_center="CC-1001",
            owner_name="Alice Smith",
        )
        inventory.register_asset(asset)
        fetched = inventory.get_asset(asset.id)
        assert fetched.business_unit == "Engineering"
        assert fetched.cost_center == "CC-1001"
        assert fetched.owner_name == "Alice Smith"


# ---------------------------------------------------------------------------
# Lifecycle transitions
# ---------------------------------------------------------------------------

class TestLifecycleTransitions:
    def test_valid_transition_provisioned_to_active(self, inventory):
        asset = inventory.register_asset(_make_asset(lifecycle=AssetLifecycle.PROVISIONED))
        result = inventory.transition_lifecycle(asset.id, AssetLifecycle.ACTIVE)
        assert result.lifecycle == AssetLifecycle.ACTIVE

    def test_valid_transition_provisioned_to_discovered(self, inventory):
        asset = inventory.register_asset(_make_asset(lifecycle=AssetLifecycle.PROVISIONED))
        result = inventory.transition_lifecycle(asset.id, AssetLifecycle.DISCOVERED)
        assert result.lifecycle == AssetLifecycle.DISCOVERED

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
        inventory.discover_from_findings(findings, "org-count")
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

    def test_discover_cloud_fields(self, inventory):
        findings = [
            {
                "hostname": "ec2-node",
                "type": "cloud_resource",
                "cloud_provider": "aws",
                "region": "us-west-2",
                "arn": "arn:aws:ec2:us-west-2:123:instance/i-xyz",
            }
        ]
        assets = inventory.discover_from_findings(findings, "org-cloud", discovery_source="cloud_discovery")
        assert len(assets) == 1
        assert assets[0].cloud_provider == "aws"
        assert assets[0].region == "us-west-2"
        assert assets[0].cloud_resource_id == "arn:aws:ec2:us-west-2:123:instance/i-xyz"
        assert assets[0].discovery_source == "cloud_discovery"

    def test_discover_k8s_source(self, inventory):
        findings = [{"hostname": "pod-abc", "type": "container"}]
        assets = inventory.discover_from_findings(findings, "org-k8s", discovery_source="k8s_scan")
        assert assets[0].discovery_source == "k8s_scan"


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

    def test_assign_owner_full_accountability(self, inventory):
        asset = inventory.register_asset(_make_asset(owner_email=None))
        result = inventory.assign_owner(
            asset.id,
            owner_email="charlie@example.com",
            owner_name="Charlie Brown",
            team="infra",
            business_unit="Engineering",
            cost_center="CC-9999",
        )
        assert result.owner_email == "charlie@example.com"
        assert result.owner_name == "Charlie Brown"
        assert result.business_unit == "Engineering"
        assert result.cost_center == "CC-9999"

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
# Compliance tagging
# ---------------------------------------------------------------------------

class TestComplianceTagging:
    def test_auto_scope_restricted_classification(self, inventory):
        asset = _make_asset(
            data_classification=DataClassification.RESTRICTED,
            compliance_scope=[],
        )
        registered = inventory.register_asset(asset)
        # restricted -> pci, hipaa, itar
        assert "pci" in registered.compliance_scope
        assert "hipaa" in registered.compliance_scope
        assert "itar" in registered.compliance_scope

    def test_auto_scope_confidential_classification(self, inventory):
        asset = _make_asset(
            data_classification=DataClassification.CONFIDENTIAL,
            compliance_scope=[],
        )
        registered = inventory.register_asset(asset)
        assert "sox" in registered.compliance_scope
        assert "gdpr" in registered.compliance_scope

    def test_auto_scope_public_classification_no_frameworks(self, inventory):
        asset = _make_asset(
            data_classification=DataClassification.PUBLIC,
            compliance_scope=[],
        )
        registered = inventory.register_asset(asset)
        assert registered.compliance_scope == []

    def test_explicit_compliance_scope_preserved(self, inventory):
        asset = _make_asset(
            data_classification=DataClassification.PUBLIC,
            compliance_scope=["nist"],
        )
        registered = inventory.register_asset(asset)
        assert "nist" in registered.compliance_scope

    def test_apply_compliance_scope_additive(self, inventory):
        asset = inventory.register_asset(_make_asset(compliance_scope=["pci"]))
        result = inventory.apply_compliance_scope(asset.id, ["hipaa", "sox"])
        assert "pci" in result.compliance_scope
        assert "hipaa" in result.compliance_scope
        assert "sox" in result.compliance_scope

    def test_apply_compliance_scope_deduplication(self, inventory):
        asset = inventory.register_asset(_make_asset(compliance_scope=["pci"]))
        result = inventory.apply_compliance_scope(asset.id, ["pci", "hipaa"])
        assert result.compliance_scope.count("pci") == 1

    def test_apply_invalid_compliance_framework_raises(self, inventory):
        asset = inventory.register_asset(_make_asset())
        with pytest.raises(ValueError, match="Unknown compliance framework"):
            inventory.apply_compliance_scope(asset.id, ["not-a-framework"])

    def test_get_assets_in_compliance_scope(self, inventory):
        inventory.register_asset(_make_asset(name="pci-asset", compliance_scope=["pci"], org_id="org-comp"))
        inventory.register_asset(_make_asset(name="hipaa-asset", compliance_scope=["hipaa"], org_id="org-comp"))
        inventory.register_asset(_make_asset(name="no-scope", compliance_scope=[], org_id="org-comp"))
        results = inventory.get_assets_in_compliance_scope("org-comp", "pci")
        assert len(results) == 1
        assert results[0].name == "pci-asset"

    def test_compliance_scope_updated_when_classification_changes(self, inventory):
        asset = inventory.register_asset(_make_asset(
            data_classification=DataClassification.PUBLIC,
            compliance_scope=[],
        ))
        updated = inventory.update_asset(asset.id, {"data_classification": "confidential"})
        # confidential -> sox, gdpr
        assert "sox" in updated.compliance_scope or "gdpr" in updated.compliance_scope


# ---------------------------------------------------------------------------
# Relationship mapping
# ---------------------------------------------------------------------------

class TestRelationshipMapping:
    def test_add_relationship(self, inventory):
        app = inventory.register_asset(_make_asset(name="my-app", asset_type="application"))
        db = inventory.register_asset(_make_asset(name="my-db", asset_type="database"))
        rel = inventory.add_relationship(
            source_asset_id=app.id,
            target_asset_id=db.id,
            relationship_type=RelationshipType.DEPENDS_ON,
            org_id="org-test",
        )
        assert isinstance(rel, AssetRelationship)
        assert rel.source_asset_id == app.id
        assert rel.target_asset_id == db.id
        assert rel.relationship_type == RelationshipType.DEPENDS_ON

    def test_get_outbound_relationships(self, inventory):
        app = inventory.register_asset(_make_asset(name="svc-a", asset_type="service"))
        db = inventory.register_asset(_make_asset(name="db-a", asset_type="database"))
        cache = inventory.register_asset(_make_asset(name="cache-a", asset_type="cache"))
        inventory.add_relationship(app.id, db.id, RelationshipType.DEPENDS_ON)
        inventory.add_relationship(app.id, cache.id, RelationshipType.CONNECTS_TO)
        rels = inventory.get_relationships(app.id, direction="outbound")
        assert len(rels) == 2
        targets = {r.target_asset_id for r in rels}
        assert db.id in targets
        assert cache.id in targets

    def test_get_inbound_relationships(self, inventory):
        app = inventory.register_asset(_make_asset(name="svc-b"))
        db = inventory.register_asset(_make_asset(name="db-b", asset_type="database"))
        inventory.add_relationship(app.id, db.id, RelationshipType.DEPENDS_ON)
        rels = inventory.get_relationships(db.id, direction="inbound")
        assert len(rels) == 1
        assert rels[0].source_asset_id == app.id

    def test_relationship_idempotent(self, inventory):
        a = inventory.register_asset(_make_asset(name="a1"))
        b = inventory.register_asset(_make_asset(name="b1"))
        inventory.add_relationship(a.id, b.id, RelationshipType.RUNS_ON)
        inventory.add_relationship(a.id, b.id, RelationshipType.RUNS_ON)  # duplicate
        rels = inventory.get_relationships(a.id, direction="outbound")
        types = [r.relationship_type for r in rels if r.target_asset_id == b.id]
        assert types.count(RelationshipType.RUNS_ON) == 1

    def test_delete_relationship(self, inventory):
        a = inventory.register_asset(_make_asset(name="del-a"))
        b = inventory.register_asset(_make_asset(name="del-b"))
        rel = inventory.add_relationship(a.id, b.id, RelationshipType.DEPLOYED_IN)
        assert inventory.delete_relationship(rel.id) is True
        rels = inventory.get_relationships(a.id, direction="outbound")
        assert all(r.id != rel.id for r in rels)

    def test_delete_nonexistent_relationship(self, inventory):
        assert inventory.delete_relationship("rel-ghost") is False

    def test_impact_graph_traversal(self, inventory):
        # app -> service -> database
        app = inventory.register_asset(_make_asset(name="g-app", asset_type="application"))
        svc = inventory.register_asset(_make_asset(name="g-svc", asset_type="service"))
        db = inventory.register_asset(_make_asset(name="g-db", asset_type="database"))
        inventory.add_relationship(app.id, svc.id, RelationshipType.DEPENDS_ON)
        inventory.add_relationship(svc.id, db.id, RelationshipType.DEPENDS_ON)
        graph = inventory.get_impact_graph(app.id, max_depth=3)
        assert graph["root"] == app.id
        assert app.id in graph["nodes"]
        assert svc.id in graph["nodes"]
        assert db.id in graph["nodes"]
        assert len(graph["edges"]) >= 2

    def test_impact_graph_respects_depth(self, inventory):
        # Chain: a -> b -> c -> d
        a = inventory.register_asset(_make_asset(name="depth-a"))
        b = inventory.register_asset(_make_asset(name="depth-b"))
        c = inventory.register_asset(_make_asset(name="depth-c"))
        d = inventory.register_asset(_make_asset(name="depth-d"))
        inventory.add_relationship(a.id, b.id, RelationshipType.DEPENDS_ON)
        inventory.add_relationship(b.id, c.id, RelationshipType.DEPENDS_ON)
        inventory.add_relationship(c.id, d.id, RelationshipType.DEPENDS_ON)
        # depth=1 — only a and b visible
        graph = inventory.get_impact_graph(a.id, max_depth=1)
        assert b.id in graph["nodes"]
        assert d.id not in graph["nodes"]


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

    def test_search_by_business_unit(self, inventory):
        inventory.register_asset(_make_asset(name="bu-asset", business_unit="Finance", org_id="org-bu"))
        inventory.register_asset(_make_asset(name="other-asset", business_unit="Engineering", org_id="org-bu"))
        results = inventory.search_assets("Finance", "org-bu")
        assert len(results) == 1
        assert results[0].name == "bu-asset"


# ---------------------------------------------------------------------------
# Stale assets
# ---------------------------------------------------------------------------

class TestStaleAssets:
    def test_stale_detection(self, inventory):
        inventory.register_asset(_make_asset(name="fresh", org_id="org-stale"))
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
        assert "by_criticality_tier" in stats
        assert "by_lifecycle" in stats
        assert "by_environment" in stats
        assert "by_cloud_provider" in stats
        assert "by_data_classification" in stats
        assert stats["unowned_count"] == 1

    def test_stats_empty_org(self, inventory):
        stats = inventory.get_inventory_stats("org-empty")
        assert stats["total"] == 0
        assert stats["unowned_count"] == 0

    def test_stats_by_criticality_tier(self, inventory):
        inventory.register_asset(_make_asset(name="t1", criticality_tier=CriticalityTier.T1, org_id="org-tier"))
        inventory.register_asset(_make_asset(name="t2", criticality_tier=CriticalityTier.T2, org_id="org-tier"))
        inventory.register_asset(_make_asset(name="t3", criticality_tier=CriticalityTier.T3, org_id="org-tier"))
        stats = inventory.get_inventory_stats("org-tier")
        assert stats["by_criticality_tier"].get("T1") == 1
        assert stats["by_criticality_tier"].get("T2") == 1


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
                "criticality_tier": "T1",
                "data_classification": "confidential",
            }
        ]
        count = inventory.bulk_import(raw_assets, org_id="org-enum")
        assert count == 1
        asset = inventory.list_assets("org-enum")[0]
        assert asset.criticality == AssetCriticality.CRITICAL
        assert asset.environment == Environment.STAGING
        assert asset.lifecycle == AssetLifecycle.ACTIVE
        assert asset.criticality_tier == CriticalityTier.T1
        assert asset.data_classification == DataClassification.CONFIDENTIAL

    def test_bulk_import_skips_invalid(self, inventory):
        raw_assets = [
            {"name": "valid", "asset_type": "server"},
            {"asset_type": "missing-name-field"},  # name is required
            {"name": "also-valid", "asset_type": "domain"},
        ]
        count = inventory.bulk_import(raw_assets, org_id="org-skip")
        assert count == 2

    def test_bulk_import_returns_zero_on_all_invalid(self, inventory):
        raw_assets = [{"bad": "data"}, {"worse": "data"}]
        count = inventory.bulk_import(raw_assets, org_id="org-bad")
        assert count == 0

    def test_bulk_import_triggers_compliance_auto_scope(self, inventory):
        raw_assets = [
            {"name": "restricted-asset", "asset_type": "database", "data_classification": "restricted"},
        ]
        inventory.bulk_import(raw_assets, org_id="org-autoscope")
        results = inventory.list_assets("org-autoscope")
        assert len(results) == 1
        assert "pci" in results[0].compliance_scope


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

    def test_filter_by_criticality_tier(self, inventory):
        inventory.register_asset(_make_asset(name="t1-asset", criticality_tier=CriticalityTier.T1, org_id="org-tier-f"))
        inventory.register_asset(_make_asset(name="t4-asset", criticality_tier=CriticalityTier.T4, org_id="org-tier-f"))
        results = inventory.list_assets("org-tier-f", criticality_tier="T1")
        assert len(results) == 1
        assert results[0].name == "t1-asset"

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

    def test_filter_by_business_unit(self, inventory):
        inventory.register_asset(_make_asset(name="eng-asset", business_unit="Engineering", org_id="org-bu-f"))
        inventory.register_asset(_make_asset(name="fin-asset", business_unit="Finance", org_id="org-bu-f"))
        results = inventory.list_assets("org-bu-f", business_unit="Engineering")
        assert len(results) == 1
        assert results[0].name == "eng-asset"

    def test_filter_by_cloud_provider(self, inventory):
        inventory.register_asset(_make_asset(name="aws-asset", cloud_provider="aws", org_id="org-cloud-f"))
        inventory.register_asset(_make_asset(name="gcp-asset", cloud_provider="gcp", org_id="org-cloud-f"))
        results = inventory.list_assets("org-cloud-f", cloud_provider="aws")
        assert len(results) == 1
        assert results[0].name == "aws-asset"

    def test_filter_by_region(self, inventory):
        inventory.register_asset(_make_asset(name="us-asset", region="us-east-1", org_id="org-region-f"))
        inventory.register_asset(_make_asset(name="eu-asset", region="eu-west-1", org_id="org-region-f"))
        results = inventory.list_assets("org-region-f", region="us-east-1")
        assert len(results) == 1
        assert results[0].name == "us-asset"

    def test_filter_by_data_classification(self, inventory):
        inventory.register_asset(_make_asset(
            name="restricted-asset",
            data_classification=DataClassification.RESTRICTED,
            compliance_scope=["pci"],
            org_id="org-class-f",
        ))
        inventory.register_asset(_make_asset(
            name="public-asset",
            data_classification=DataClassification.PUBLIC,
            compliance_scope=[],
            org_id="org-class-f",
        ))
        results = inventory.list_assets("org-class-f", data_classification="restricted")
        assert len(results) == 1
        assert results[0].name == "restricted-asset"

    def test_filter_by_compliance_scope(self, inventory):
        inventory.register_asset(_make_asset(name="pci-only", compliance_scope=["pci"], org_id="org-cs-f"))
        inventory.register_asset(_make_asset(name="hipaa-only", compliance_scope=["hipaa"], org_id="org-cs-f"))
        inventory.register_asset(_make_asset(name="both", compliance_scope=["pci", "hipaa"], org_id="org-cs-f"))
        results = inventory.list_assets("org-cs-f", compliance_scope="pci")
        assert len(results) == 2
        names = {a.name for a in results}
        assert "pci-only" in names


# ---------------------------------------------------------------------------
# TestAddAsset — add_asset() alias
# ---------------------------------------------------------------------------

class TestAddAsset:
    def test_add_asset_returns_id(self, inventory):
        asset_id = inventory.add_asset("org-add", {
            "name": "web-server-01",
            "type": "server",
            "ip_address": "10.0.0.1",
            "criticality": "high",
            "environment": "production",
        })
        assert asset_id.startswith("masset-")

    def test_add_asset_persisted(self, inventory):
        asset_id = inventory.add_asset("org-add2", {
            "name": "db-server-01",
            "type": "server",
            "criticality": "critical",
        })
        fetched = inventory.get_asset(asset_id)
        assert fetched is not None
        assert fetched.name == "db-server-01"
        assert fetched.criticality.value == "critical"

    def test_add_asset_type_alias(self, inventory):
        """'type' key maps to asset_type."""
        asset_id = inventory.add_asset("org-add3", {"name": "container-x", "type": "container"})
        fetched = inventory.get_asset(asset_id)
        assert fetched.asset_type == "container"

    def test_add_asset_owner_alias(self, inventory):
        """'owner' key maps to owner_name."""
        asset_id = inventory.add_asset("org-add4", {
            "name": "iot-device",
            "type": "iot",
            "owner": "Alice",
        })
        fetched = inventory.get_asset(asset_id)
        assert fetched.owner_name == "Alice"

    def test_add_asset_os_in_metadata(self, inventory):
        """'os' key is stored inside metadata."""
        asset_id = inventory.add_asset("org-add5", {
            "name": "windows-host",
            "type": "workstation",
            "os": "Windows Server 2022",
        })
        fetched = inventory.get_asset(asset_id)
        assert fetched.metadata.get("os") == "Windows Server 2022"

    def test_add_asset_tags_and_metadata(self, inventory):
        asset_id = inventory.add_asset("org-add6", {
            "name": "cloud-vm",
            "type": "cloud_resource",
            "tags": ["prod", "aws"],
            "metadata": {"region": "us-east-1"},
        })
        fetched = inventory.get_asset(asset_id)
        assert "prod" in fetched.tags
        assert fetched.metadata.get("region") == "us-east-1"


# ---------------------------------------------------------------------------
# TestGetAssetStats — get_asset_stats()
# ---------------------------------------------------------------------------

class TestGetAssetStats:
    def test_stats_keys(self, inventory):
        inventory.add_asset("org-stats", {"name": "s1", "type": "server", "criticality": "critical"})
        stats = inventory.get_asset_stats("org-stats")
        assert "total" in stats
        assert "by_type" in stats
        assert "by_criticality" in stats
        assert "avg_risk_score" in stats
        assert "critical_exposed" in stats

    def test_stats_total(self, inventory):
        for i in range(3):
            inventory.add_asset("org-stats2", {"name": f"asset-{i}", "type": "server"})
        stats = inventory.get_asset_stats("org-stats2")
        assert stats["total"] == 3

    def test_stats_critical_exposed(self, inventory):
        inventory.add_asset("org-stats3", {
            "name": "exposed-critical",
            "type": "server",
            "criticality": "critical",
            "metadata": {"internet_facing": True},
        })
        inventory.add_asset("org-stats3", {
            "name": "internal-critical",
            "type": "server",
            "criticality": "critical",
            "metadata": {"internet_facing": False},
        })
        stats = inventory.get_asset_stats("org-stats3")
        assert stats["critical_exposed"] == 1

    def test_stats_empty_org(self, inventory):
        stats = inventory.get_asset_stats("org-stats-empty-xyz")
        assert stats["total"] == 0
        assert stats["critical_exposed"] == 0


# ---------------------------------------------------------------------------
# TestCalculateRiskScore — calculate_risk_score()
# ---------------------------------------------------------------------------

class TestCalculateRiskScore:
    def test_risk_score_structure(self, inventory):
        asset_id = inventory.add_asset("org-risk", {"name": "srv", "type": "server", "criticality": "medium"})
        result = inventory.calculate_risk_score(asset_id, "org-risk")
        assert "score" in result
        assert "factors" in result
        assert "risk_level" in result
        assert 0.0 <= result["score"] <= 10.0

    def test_risk_score_critical_higher_than_low(self, inventory):
        crit_id = inventory.add_asset("org-risk2", {"name": "crit", "type": "server", "criticality": "critical"})
        low_id = inventory.add_asset("org-risk2", {"name": "low", "type": "server", "criticality": "low"})
        crit_result = inventory.calculate_risk_score(crit_id, "org-risk2")
        low_result = inventory.calculate_risk_score(low_id, "org-risk2")
        assert crit_result["score"] > low_result["score"]

    def test_risk_score_internet_facing_raises_score(self, inventory):
        base_id = inventory.add_asset("org-risk3", {"name": "internal", "type": "server", "criticality": "medium"})
        exposed_id = inventory.add_asset("org-risk3", {
            "name": "exposed", "type": "server", "criticality": "medium",
            "metadata": {"internet_facing": True},
        })
        base_result = inventory.calculate_risk_score(base_id, "org-risk3")
        exposed_result = inventory.calculate_risk_score(exposed_id, "org-risk3")
        assert exposed_result["score"] > base_result["score"]
        assert exposed_result["factors"]["exposure"] == 1.5

    def test_risk_score_factors_present(self, inventory):
        asset_id = inventory.add_asset("org-risk4", {"name": "srv", "type": "server", "criticality": "high"})
        result = inventory.calculate_risk_score(asset_id, "org-risk4")
        factors = result["factors"]
        assert "criticality_weight" in factors
        assert "exposure" in factors
        assert "vuln_count" in factors
        assert "patch_age" in factors

    def test_risk_score_wrong_org_returns_empty(self, inventory):
        asset_id = inventory.add_asset("org-risk5", {"name": "srv", "type": "server"})
        result = inventory.calculate_risk_score(asset_id, "wrong-org")
        assert result == {}

    def test_risk_level_mapping(self, inventory):
        crit_id = inventory.add_asset("org-risk6", {"name": "crit", "type": "server", "criticality": "critical"})
        result = inventory.calculate_risk_score(crit_id, "org-risk6")
        assert result["risk_level"] in ("critical", "high", "medium", "low")

    def test_risk_score_persisted(self, inventory):
        asset_id = inventory.add_asset("org-risk7", {"name": "srv", "type": "server", "criticality": "high"})
        result = inventory.calculate_risk_score(asset_id, "org-risk7")
        fetched = inventory.get_asset(asset_id)
        assert fetched.risk_score == result["score"]


# ---------------------------------------------------------------------------
# TestFindExposedAssets — find_exposed_assets()
# ---------------------------------------------------------------------------

class TestFindExposedAssets:
    def test_returns_only_internet_facing(self, inventory):
        inventory.add_asset("org-exp", {
            "name": "exposed-srv", "type": "server", "criticality": "high",
            "metadata": {"internet_facing": True},
        })
        inventory.add_asset("org-exp", {
            "name": "internal-srv", "type": "server", "criticality": "high",
            "metadata": {"internet_facing": False},
        })
        exposed = inventory.find_exposed_assets("org-exp")
        names = [a.name for a in exposed]
        assert "exposed-srv" in names
        assert "internal-srv" not in names

    def test_low_risk_internet_facing_excluded(self, inventory):
        inventory.add_asset("org-exp2", {
            "name": "low-exposed", "type": "iot", "criticality": "low",
            "metadata": {"internet_facing": True},
        })
        exposed = inventory.find_exposed_assets("org-exp2")
        # low criticality base=2, exposure=1.5 → score=3.5 < 6.0 → excluded
        names = [a.name for a in exposed]
        assert "low-exposed" not in names

    def test_empty_org_returns_empty_list(self, inventory):
        result = inventory.find_exposed_assets("org-exp-empty-xyz")
        assert result == []

    def test_critical_internet_facing_included(self, inventory):
        inventory.add_asset("org-exp3", {
            "name": "critical-exposed", "type": "server", "criticality": "critical",
            "metadata": {"internet_facing": True},
        })
        exposed = inventory.find_exposed_assets("org-exp3")
        assert len(exposed) >= 1
        assert any(a.name == "critical-exposed" for a in exposed)


# ---------------------------------------------------------------------------
# TestGetAssetTimeline — get_asset_timeline()
# ---------------------------------------------------------------------------

class TestGetAssetTimeline:
    def test_timeline_has_discovery_event(self, inventory):
        asset_id = inventory.add_asset("org-tl", {"name": "srv", "type": "server"})
        timeline = inventory.get_asset_timeline(asset_id, "org-tl")
        assert len(timeline) >= 1
        types = [e["event_type"] for e in timeline]
        assert "discovery" in types

    def test_timeline_sorted_ascending(self, inventory):
        asset_id = inventory.add_asset("org-tl2", {"name": "srv", "type": "server"})
        timeline = inventory.get_asset_timeline(asset_id, "org-tl2")
        timestamps = [e["timestamp"] for e in timeline]
        assert timestamps == sorted(timestamps)

    def test_timeline_includes_cmdb_sync(self, inventory):
        asset_id = inventory.add_asset("org-tl3", {"name": "srv", "type": "server"})
        inventory.sync_to_cmdb(asset_id, "ServiceNow", "SN-001")
        timeline = inventory.get_asset_timeline(asset_id, "org-tl3")
        types = [e["event_type"] for e in timeline]
        assert "cmdb_sync" in types

    def test_timeline_includes_finding_update(self, inventory):
        asset_id = inventory.add_asset("org-tl4", {"name": "srv", "type": "server"})
        # Simulate findings by updating finding_count
        inventory.update_asset(asset_id, {"finding_count": 5})
        timeline = inventory.get_asset_timeline(asset_id, "org-tl4")
        types = [e["event_type"] for e in timeline]
        assert "finding_update" in types

    def test_timeline_wrong_org_returns_empty(self, inventory):
        asset_id = inventory.add_asset("org-tl5", {"name": "srv", "type": "server"})
        result = inventory.get_asset_timeline(asset_id, "wrong-org")
        assert result == []

    def test_timeline_event_has_required_keys(self, inventory):
        asset_id = inventory.add_asset("org-tl6", {"name": "srv", "type": "server"})
        timeline = inventory.get_asset_timeline(asset_id, "org-tl6")
        assert len(timeline) >= 1
        for event in timeline:
            assert "timestamp" in event
            assert "event_type" in event
            assert "description" in event
            assert "detail" in event
