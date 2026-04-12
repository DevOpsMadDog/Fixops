"""Tests for attack surface mapping module.

Covers:
- Asset CRUD (register, get, list, delete)
- Discover from findings (extract hosts, IPs, endpoints)
- Exposure path mapping
- Asset risk scoring
- Attack surface summary
- External assets filter
- Surface changes detection
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from core.attack_surface import (
    Asset,
    AssetType,
    AttackSurface,
    AttackSurfaceMapper,
    ExposureLevel,
    ExposurePath,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_path(tmp_path):
    """Return a temporary SQLite database path."""
    return str(tmp_path / "test_attack_surface.db")


@pytest.fixture
def mapper(db_path):
    """Return an AttackSurfaceMapper backed by a temp DB."""
    return AttackSurfaceMapper(db_path=db_path)


@pytest.fixture
def sample_asset():
    """A sample external domain asset."""
    return Asset(
        name="api.example.com",
        type=AssetType.DOMAIN,
        exposure_level=ExposureLevel.EXTERNAL,
        attributes={"port": 443, "protocol": "https"},
        tags=["prod", "api"],
        org_id="org_test",
    )


@pytest.fixture
def internal_asset():
    """A sample internal service asset."""
    return Asset(
        name="db.internal.example.com",
        type=AssetType.SERVICE,
        exposure_level=ExposureLevel.INTERNAL,
        attributes={"port": 5432, "protocol": "postgres"},
        tags=["db", "internal"],
        org_id="org_test",
    )


# ---------------------------------------------------------------------------
# Asset CRUD
# ---------------------------------------------------------------------------

class TestAssetCRUD:
    def test_register_asset_returns_asset(self, mapper, sample_asset):
        result = mapper.register_asset(sample_asset)
        assert isinstance(result, Asset)
        assert result.id == sample_asset.id
        assert result.name == "api.example.com"

    def test_register_asset_persists(self, mapper, sample_asset):
        mapper.register_asset(sample_asset)
        fetched = mapper.get_asset(sample_asset.id)
        assert fetched is not None
        assert fetched.name == sample_asset.name
        assert fetched.type == AssetType.DOMAIN

    def test_get_asset_returns_none_for_unknown(self, mapper):
        result = mapper.get_asset("nonexistent-id")
        assert result is None

    def test_register_asset_updates_last_seen(self, mapper, sample_asset):
        before = datetime.now(timezone.utc).isoformat()
        mapper.register_asset(sample_asset)
        fetched = mapper.get_asset(sample_asset.id)
        assert fetched.last_seen >= before

    def test_register_asset_upsert(self, mapper, sample_asset):
        mapper.register_asset(sample_asset)
        # Register again with updated name
        sample_asset.name = "updated.example.com"
        mapper.register_asset(sample_asset)
        fetched = mapper.get_asset(sample_asset.id)
        assert fetched.name == "updated.example.com"

    def test_list_assets_empty(self, mapper):
        result = mapper.list_assets("org_empty")
        assert result == []

    def test_list_assets_returns_org_assets(self, mapper, sample_asset, internal_asset):
        mapper.register_asset(sample_asset)
        mapper.register_asset(internal_asset)
        result = mapper.list_assets("org_test")
        assert len(result) == 2

    def test_list_assets_org_isolation(self, mapper, sample_asset):
        mapper.register_asset(sample_asset)
        result = mapper.list_assets("org_other")
        assert len(result) == 0

    def test_list_assets_type_filter(self, mapper, sample_asset, internal_asset):
        mapper.register_asset(sample_asset)
        mapper.register_asset(internal_asset)
        result = mapper.list_assets("org_test", type_filter=AssetType.DOMAIN)
        assert all(a.type == AssetType.DOMAIN for a in result)
        assert len(result) == 1

    def test_list_assets_exposure_filter(self, mapper, sample_asset, internal_asset):
        mapper.register_asset(sample_asset)
        mapper.register_asset(internal_asset)
        result = mapper.list_assets("org_test", exposure_filter=ExposureLevel.EXTERNAL)
        assert all(a.exposure_level == ExposureLevel.EXTERNAL for a in result)
        assert len(result) == 1

    def test_delete_asset(self, mapper, sample_asset):
        mapper.register_asset(sample_asset)
        deleted = mapper.delete_asset(sample_asset.id)
        assert deleted is True
        assert mapper.get_asset(sample_asset.id) is None

    def test_delete_nonexistent_asset_returns_false(self, mapper):
        result = mapper.delete_asset("does-not-exist")
        assert result is False

    def test_asset_attributes_preserved(self, mapper):
        asset = Asset(
            name="my-service",
            type=AssetType.SERVICE,
            exposure_level=ExposureLevel.DMZ,
            attributes={"port": 8080, "protocol": "http", "region": "us-east-1"},
            tags=["web", "v2"],
            org_id="org_test",
        )
        mapper.register_asset(asset)
        fetched = mapper.get_asset(asset.id)
        assert fetched.attributes["port"] == 8080
        assert fetched.attributes["region"] == "us-east-1"
        assert "web" in fetched.tags


# ---------------------------------------------------------------------------
# Discover from findings
# ---------------------------------------------------------------------------

class TestDiscoverFromFindings:
    def test_discover_host_field(self, mapper):
        findings = [{"host": "10.0.0.1", "org_id": "org_test"}]
        assets = mapper.discover_from_findings(findings)
        assert len(assets) >= 1
        names = [a.name for a in assets]
        assert "10.0.0.1" in names

    def test_discover_ip_gets_ip_address_type(self, mapper):
        findings = [{"host": "192.168.1.100", "org_id": "org_test"}]
        assets = mapper.discover_from_findings(findings)
        ip_assets = [a for a in assets if a.name == "192.168.1.100"]
        assert ip_assets[0].type == AssetType.IP_ADDRESS

    def test_discover_domain_gets_domain_type(self, mapper):
        findings = [{"host": "api.target.com", "org_id": "org_test"}]
        assets = mapper.discover_from_findings(findings)
        domain_assets = [a for a in assets if a.name == "api.target.com"]
        assert domain_assets[0].type == AssetType.DOMAIN

    def test_discover_url_field(self, mapper):
        findings = [{"url": "https://api.example.com/v1/users", "org_id": "org_test"}]
        assets = mapper.discover_from_findings(findings)
        endpoint_assets = [a for a in assets if a.type == AssetType.API_ENDPOINT]
        assert len(endpoint_assets) >= 1

    def test_discover_endpoint_field(self, mapper):
        findings = [{"endpoint": "/api/v1/admin", "org_id": "org_test"}]
        assets = mapper.discover_from_findings(findings)
        assert len(assets) >= 1

    def test_discover_cloud_resource(self, mapper):
        findings = [{
            "cloud_resource": "arn:aws:s3:::my-bucket",
            "cloud_provider": "aws",
            "region": "us-west-2",
            "org_id": "org_test",
        }]
        assets = mapper.discover_from_findings(findings)
        cloud_assets = [a for a in assets if a.type == AssetType.CLOUD_RESOURCE]
        assert len(cloud_assets) >= 1
        assert cloud_assets[0].attributes.get("cloud_provider") == "aws"

    def test_discover_container_image(self, mapper):
        findings = [{"container": "nginx:1.21", "org_id": "org_test"}]
        assets = mapper.discover_from_findings(findings)
        container_assets = [a for a in assets if a.type == AssetType.CONTAINER]
        assert len(container_assets) >= 1

    def test_discover_deduplicates_same_name(self, mapper):
        findings = [
            {"host": "10.0.0.1", "org_id": "org_test"},
            {"host": "10.0.0.1", "org_id": "org_test"},
        ]
        assets = mapper.discover_from_findings(findings)
        names = [a.name for a in assets if a.name == "10.0.0.1"]
        assert len(names) == 1

    def test_discover_auto_discovered_tag(self, mapper):
        findings = [{"host": "scanner.target.com", "org_id": "org_test"}]
        assets = mapper.discover_from_findings(findings)
        for a in assets:
            assert "auto-discovered" in a.tags

    def test_discover_infers_external_from_prod_env(self, mapper):
        findings = [{"host": "prod-api.example.com", "environment": "prod", "org_id": "org_test"}]
        assets = mapper.discover_from_findings(findings)
        host_assets = [a for a in assets if a.name == "prod-api.example.com"]
        assert host_assets[0].exposure_level == ExposureLevel.EXTERNAL


# ---------------------------------------------------------------------------
# Exposure path mapping
# ---------------------------------------------------------------------------

class TestExposurePaths:
    def test_map_explicit_path(self, mapper, sample_asset, internal_asset):
        mapper.register_asset(sample_asset)
        mapper.register_asset(internal_asset)
        path = mapper.map_exposure_path(
            source_id=sample_asset.id,
            target_id=internal_asset.id,
            hops=[sample_asset.id, internal_asset.id],
            protocol="https",
            org_id="org_test",
        )
        assert isinstance(path, ExposurePath)
        assert path.source_asset_id == sample_asset.id
        assert path.target_asset_id == internal_asset.id
        assert path.protocol == "https"

    def test_path_risk_score_external_to_internal(self, mapper, sample_asset, internal_asset):
        mapper.register_asset(sample_asset)
        mapper.register_asset(internal_asset)
        path = mapper.map_exposure_path(
            source_id=sample_asset.id,
            target_id=internal_asset.id,
            hops=[],
            protocol="tcp",
            org_id="org_test",
        )
        # External source should produce meaningful risk
        assert path.risk_score > 0.0
        assert path.risk_score <= 1.0

    def test_path_description_includes_asset_names(self, mapper, sample_asset, internal_asset):
        mapper.register_asset(sample_asset)
        mapper.register_asset(internal_asset)
        path = mapper.map_exposure_path(
            source_id=sample_asset.id,
            target_id=internal_asset.id,
            hops=[],
            protocol="tcp",
            org_id="org_test",
        )
        assert "api.example.com" in path.description
        assert "db.internal.example.com" in path.description

    def test_get_high_risk_paths_filter(self, mapper, sample_asset, internal_asset):
        mapper.register_asset(sample_asset)
        mapper.register_asset(internal_asset)
        mapper.map_exposure_path(
            source_id=sample_asset.id, target_id=internal_asset.id,
            hops=[], protocol="tcp", org_id="org_test",
        )
        high_risk = mapper.get_high_risk_paths("org_test", min_score=0.5)
        low_filter = mapper.get_high_risk_paths("org_test", min_score=0.0)
        assert len(low_filter) >= len(high_risk)

    def test_auto_map_paths_by_shared_port(self, mapper):
        ext = Asset(
            name="ext.example.com", type=AssetType.DOMAIN,
            exposure_level=ExposureLevel.EXTERNAL,
            attributes={"port": 443, "protocol": "https"},
            org_id="org_test",
        )
        inn = Asset(
            name="int-api", type=AssetType.SERVICE,
            exposure_level=ExposureLevel.INTERNAL,
            attributes={"port": 443, "protocol": "https"},
            org_id="org_test",
        )
        mapper.register_asset(ext)
        mapper.register_asset(inn)
        paths = mapper.auto_map_paths("org_test")
        assert len(paths) >= 1


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

class TestRiskScoring:
    def test_external_asset_higher_risk(self, mapper):
        ext = Asset(name="ext.example.com", type=AssetType.DOMAIN,
                    exposure_level=ExposureLevel.EXTERNAL, org_id="org_test")
        inn = Asset(name="int.example.com", type=AssetType.SERVICE,
                    exposure_level=ExposureLevel.ISOLATED, org_id="org_test")
        mapper.register_asset(ext)
        mapper.register_asset(inn)
        ext_score = mapper.score_asset_risk(ext.id)
        inn_score = mapper.score_asset_risk(inn.id)
        assert ext_score > inn_score

    def test_risk_score_range(self, mapper, sample_asset):
        mapper.register_asset(sample_asset)
        score = mapper.score_asset_risk(sample_asset.id)
        assert 0.0 <= score <= 1.0

    def test_risk_score_unknown_asset_returns_zero(self, mapper):
        score = mapper.score_asset_risk("nonexistent-id")
        assert score == 0.0


# ---------------------------------------------------------------------------
# Attack surface summary
# ---------------------------------------------------------------------------

class TestAttackSurfaceSummary:
    def test_surface_summary_empty_org(self, mapper):
        surface = mapper.get_attack_surface("org_empty")
        assert isinstance(surface, AttackSurface)
        assert surface.total_assets == 0
        assert surface.external_assets == 0
        assert surface.risk_score == 0.0

    def test_surface_summary_counts(self, mapper, sample_asset, internal_asset):
        mapper.register_asset(sample_asset)
        mapper.register_asset(internal_asset)
        surface = mapper.get_attack_surface("org_test")
        assert surface.total_assets == 2
        assert surface.external_assets == 1

    def test_surface_assets_by_type(self, mapper, sample_asset, internal_asset):
        mapper.register_asset(sample_asset)
        mapper.register_asset(internal_asset)
        surface = mapper.get_attack_surface("org_test")
        assert "domain" in surface.assets_by_type
        assert "service" in surface.assets_by_type

    def test_surface_assets_by_exposure(self, mapper, sample_asset, internal_asset):
        mapper.register_asset(sample_asset)
        mapper.register_asset(internal_asset)
        surface = mapper.get_attack_surface("org_test")
        assert "external" in surface.assets_by_exposure
        assert "internal" in surface.assets_by_exposure

    def test_surface_risk_score_non_negative(self, mapper, sample_asset):
        mapper.register_asset(sample_asset)
        surface = mapper.get_attack_surface("org_test")
        assert surface.risk_score >= 0.0

    def test_external_assets_filter(self, mapper, sample_asset, internal_asset):
        mapper.register_asset(sample_asset)
        mapper.register_asset(internal_asset)
        external = mapper.get_external_assets("org_test")
        assert len(external) == 1
        assert external[0].exposure_level == ExposureLevel.EXTERNAL

    def test_external_assets_empty_when_none(self, mapper, internal_asset):
        mapper.register_asset(internal_asset)
        external = mapper.get_external_assets("org_test")
        assert len(external) == 0


# ---------------------------------------------------------------------------
# Surface change detection
# ---------------------------------------------------------------------------

class TestSurfaceChanges:
    def test_changes_returns_dict(self, mapper, sample_asset):
        mapper.register_asset(sample_asset)
        changes = mapper.get_surface_changes("org_test", since_days=7)
        assert isinstance(changes, dict)
        assert "new_assets" in changes
        assert "removed_assets" in changes
        assert "new_count" in changes
        assert "removed_count" in changes

    def test_new_asset_detected(self, mapper, sample_asset):
        mapper.register_asset(sample_asset)
        changes = mapper.get_surface_changes("org_test", since_days=7)
        new_ids = [a["id"] for a in changes["new_assets"]]
        assert sample_asset.id in new_ids

    def test_stale_asset_detected_as_removed(self, mapper, db_path):
        """Asset with last_seen older than since_days appears in removed list."""
        old_mapper = AttackSurfaceMapper(db_path=db_path)
        old_time = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        asset = Asset(
            name="old.example.com", type=AssetType.DOMAIN,
            exposure_level=ExposureLevel.EXTERNAL,
            discovered_at=old_time, last_seen=old_time,
            org_id="org_test",
        )
        # Bypass register_asset to avoid last_seen update
        old_mapper._db.upsert_asset(asset)
        changes = old_mapper.get_surface_changes("org_test", since_days=7)
        removed_ids = [a["id"] for a in changes["removed_assets"]]
        assert asset.id in removed_ids

    def test_changes_since_days_param(self, mapper, sample_asset):
        mapper.register_asset(sample_asset)
        changes_7 = mapper.get_surface_changes("org_test", since_days=7)
        changes_1 = mapper.get_surface_changes("org_test", since_days=1)
        assert changes_7["since_days"] == 7
        assert changes_1["since_days"] == 1

    def test_changes_summary_string(self, mapper, sample_asset):
        mapper.register_asset(sample_asset)
        changes = mapper.get_surface_changes("org_test", since_days=7)
        assert "new" in changes["summary"].lower()
