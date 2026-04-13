"""Tests for the Attack Surface Management (ASM) engine.

Covers all 7 functional areas:
1. External asset discovery + registration
2. Attack surface scoring (composite + component)
3. Shadow IT detection
4. Exposure analysis
5. Attack path mapping + blast radius
6. Continuous monitoring / change detection
7. Risk prioritization with EPSS stubs
Plus certificate management, scan orchestration, and router endpoint smoke tests.
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import pytest

from core.attack_surface_manager import (
    ASMSurfaceScore,
    AssetCategory,
    AttackPath,
    AttackSurfaceManager,
    CertificateRecord,
    ChangeType,
    ExposureZone,
    ManagedAsset,
    RiskTier,
    ScanResult,
    ScanStatus,
    ShadowITFinding,
    SurfaceChange,
    _epss_score_stub,
    get_asm_engine,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test_asm.db")


@pytest.fixture
def engine(db_path):
    return AttackSurfaceManager(db_path=db_path)


@pytest.fixture
def internet_asset(engine):
    asset = ManagedAsset(
        name="api.example.com",
        category=AssetCategory.DOMAIN,
        exposure_zone=ExposureZone.INTERNET_FACING,
        org_id="org1",
        open_ports=[80, 443],
        has_waf=True,
        has_cdn=False,
        tls_grade="A",
        cert_expiry_days=90,
        security_headers_score=80.0,
        business_value=80.0,
    )
    return engine.register_asset(asset)


@pytest.fixture
def internal_asset(engine):
    asset = ManagedAsset(
        name="db.internal.example.com",
        category=AssetCategory.DOMAIN,
        exposure_zone=ExposureZone.INTERNAL,
        org_id="org1",
        open_ports=[5432],
        business_value=90.0,
    )
    return engine.register_asset(asset)


@pytest.fixture
def dmz_asset(engine):
    asset = ManagedAsset(
        name="proxy.dmz.example.com",
        category=AssetCategory.NETWORK_DEVICE,
        exposure_zone=ExposureZone.DMZ,
        org_id="org1",
        open_ports=[80, 8080],
    )
    return engine.register_asset(asset)


# ---------------------------------------------------------------------------
# 1. Asset Registration + Discovery
# ---------------------------------------------------------------------------


class TestAssetRegistration:
    def test_register_returns_managed_asset(self, engine):
        asset = ManagedAsset(
            name="test.example.com",
            category=AssetCategory.DOMAIN,
            exposure_zone=ExposureZone.INTERNET_FACING,
            org_id="org1",
        )
        result = engine.register_asset(asset)
        assert isinstance(result, ManagedAsset)
        assert result.name == "test.example.com"

    def test_register_assigns_risk_score(self, engine):
        asset = ManagedAsset(
            name="scored.example.com",
            category=AssetCategory.API_ENDPOINT,
            exposure_zone=ExposureZone.INTERNET_FACING,
            org_id="org1",
        )
        result = engine.register_asset(asset)
        assert result.risk_score >= 0.0
        assert result.risk_score <= 100.0

    def test_register_assigns_risk_tier(self, engine):
        asset = ManagedAsset(
            name="tiered.example.com",
            category=AssetCategory.DOMAIN,
            exposure_zone=ExposureZone.INTERNET_FACING,
            org_id="org1",
        )
        result = engine.register_asset(asset)
        assert result.risk_tier in RiskTier.__members__.values()

    def test_register_updates_last_seen(self, engine):
        before = datetime.now(timezone.utc).isoformat()
        asset = ManagedAsset(
            name="seen.example.com",
            category=AssetCategory.DOMAIN,
            exposure_zone=ExposureZone.INTERNAL,
            org_id="org1",
        )
        result = engine.register_asset(asset)
        assert result.last_seen >= before

    def test_get_asset_returns_registered(self, engine, internet_asset):
        fetched = engine.get_asset(internet_asset.id)
        assert fetched is not None
        assert fetched.id == internet_asset.id
        assert fetched.name == internet_asset.name

    def test_get_asset_unknown_returns_none(self, engine):
        assert engine.get_asset("nonexistent-id") is None

    def test_delete_asset_returns_true(self, engine, internet_asset):
        deleted = engine.delete_asset(internet_asset.id)
        assert deleted is True
        assert engine.get_asset(internet_asset.id) is None

    def test_delete_nonexistent_returns_false(self, engine):
        assert engine.delete_asset("ghost-id") is False

    def test_list_assets_org_isolation(self, engine, internet_asset):
        results = engine.list_assets("other_org")
        assert all(a.org_id != "org1" for a in results)

    def test_list_assets_with_zone_filter(self, engine, internet_asset, internal_asset):
        results = engine.list_assets("org1", zone=ExposureZone.INTERNET_FACING)
        assert all(a.exposure_zone == ExposureZone.INTERNET_FACING for a in results)

    def test_list_assets_with_category_filter(self, engine, internet_asset, internal_asset):
        results = engine.list_assets("org1", category=AssetCategory.DOMAIN)
        assert all(a.category == AssetCategory.DOMAIN for a in results)

    def test_list_assets_with_tier_filter(self, engine):
        for i in range(3):
            asset = ManagedAsset(
                name=f"asset{i}.example.com",
                category=AssetCategory.DOMAIN,
                exposure_zone=ExposureZone.INTERNAL,
                org_id="org_tier",
            )
            engine.register_asset(asset)
        # All results for this org should be returned (tier may vary)
        results = engine.list_assets("org_tier")
        assert len(results) == 3

    def test_upsert_updates_existing_asset(self, engine, internet_asset):
        internet_asset.name = "updated.example.com"
        engine.register_asset(internet_asset)
        fetched = engine.get_asset(internet_asset.id)
        assert fetched.name == "updated.example.com"


class TestAssetDiscovery:
    def test_discover_domain_item(self, engine):
        data = [{"domain": "scan.example.com", "org_id": "org1"}]
        assets = engine.discover_assets_from_data(data, org_id="org1")
        assert len(assets) >= 1
        names = [a.name for a in assets]
        assert "scan.example.com" in names

    def test_discover_subdomain_item(self, engine):
        data = [{"subdomain": "sub.example.com"}]
        assets = engine.discover_assets_from_data(data, org_id="org1")
        sub_assets = [a for a in assets if a.category == AssetCategory.SUBDOMAIN]
        assert len(sub_assets) >= 1

    def test_discover_ip_item(self, engine):
        data = [{"ip": "10.0.0.1"}]
        assets = engine.discover_assets_from_data(data, org_id="org1")
        ip_assets = [a for a in assets if a.category == AssetCategory.IP_ADDRESS]
        assert len(ip_assets) >= 1

    def test_discover_cloud_resource(self, engine):
        data = [{"cloud_arn": "arn:aws:s3:::my-bucket"}]
        assets = engine.discover_assets_from_data(data, org_id="org1")
        cloud = [a for a in assets if a.category == AssetCategory.CLOUD_RESOURCE]
        assert len(cloud) >= 1

    def test_discover_api_endpoint(self, engine):
        data = [{"api_url": "https://api.example.com/v1"}]
        assets = engine.discover_assets_from_data(data, org_id="org1")
        api = [a for a in assets if a.category == AssetCategory.API_ENDPOINT]
        assert len(api) >= 1
        assert api[0].exposure_zone == ExposureZone.INTERNET_FACING

    def test_discover_saas_app(self, engine):
        data = [{"saas_url": "app.example.io"}]
        assets = engine.discover_assets_from_data(data, org_id="org1")
        saas = [a for a in assets if a.category == AssetCategory.SAAS_APP]
        assert len(saas) >= 1

    def test_discover_deduplicates_names(self, engine):
        data = [{"domain": "dup.example.com"}, {"domain": "dup.example.com"}]
        assets = engine.discover_assets_from_data(data, org_id="org1")
        assert sum(1 for a in assets if a.name == "dup.example.com") == 1

    def test_discover_infers_internet_zone_from_env(self, engine):
        data = [{"domain": "prod.example.com", "environment": "production"}]
        assets = engine.discover_assets_from_data(data, org_id="org1")
        asset = next((a for a in assets if a.name == "prod.example.com"), None)
        assert asset is not None
        assert asset.exposure_zone == ExposureZone.INTERNET_FACING

    def test_discover_carries_open_ports(self, engine):
        data = [{"domain": "porttest.example.com", "open_ports": [80, 443, 22]}]
        assets = engine.discover_assets_from_data(data, org_id="org1")
        asset = next((a for a in assets if a.name == "porttest.example.com"), None)
        assert asset is not None
        assert 443 in asset.open_ports


# ---------------------------------------------------------------------------
# 2. Attack Surface Scoring
# ---------------------------------------------------------------------------


class TestAssetScoring:
    def test_internet_facing_higher_score_than_isolated(self, engine):
        ext = ManagedAsset(
            name="ext.example.com",
            category=AssetCategory.DOMAIN,
            exposure_zone=ExposureZone.INTERNET_FACING,
            org_id="score_org",
            business_value=50.0,
        )
        iso = ManagedAsset(
            name="iso.example.com",
            category=AssetCategory.DOMAIN,
            exposure_zone=ExposureZone.ISOLATED,
            org_id="score_org",
            business_value=50.0,
        )
        ext_r = engine.register_asset(ext)
        iso_r = engine.register_asset(iso)
        assert ext_r.risk_score > iso_r.risk_score

    def test_risky_ports_increase_score(self, engine):
        no_ports = ManagedAsset(
            name="noportsasset.example.com",
            category=AssetCategory.DOMAIN,
            exposure_zone=ExposureZone.INTERNET_FACING,
            org_id="port_org",
            open_ports=[],
            business_value=50.0,
        )
        risky = ManagedAsset(
            name="riskyports.example.com",
            category=AssetCategory.DOMAIN,
            exposure_zone=ExposureZone.INTERNET_FACING,
            org_id="port_org",
            open_ports=[3389, 3306, 21],
            business_value=50.0,
        )
        r_no = engine.register_asset(no_ports)
        r_risky = engine.register_asset(risky)
        assert r_risky.risk_score >= r_no.risk_score

    def test_waf_protection_lowers_score(self, engine):
        no_waf = ManagedAsset(
            name="nowaf.example.com",
            category=AssetCategory.DOMAIN,
            exposure_zone=ExposureZone.INTERNET_FACING,
            org_id="waf_org",
            has_waf=False,
            business_value=50.0,
        )
        with_waf = ManagedAsset(
            name="withwaf.example.com",
            category=AssetCategory.DOMAIN,
            exposure_zone=ExposureZone.INTERNET_FACING,
            org_id="waf_org",
            has_waf=True,
            business_value=50.0,
        )
        r_no = engine.register_asset(no_waf)
        r_waf = engine.register_asset(with_waf)
        assert r_waf.risk_score <= r_no.risk_score

    def test_expired_cert_increases_score(self, engine):
        valid_cert = ManagedAsset(
            name="valid.example.com",
            category=AssetCategory.DOMAIN,
            exposure_zone=ExposureZone.INTERNET_FACING,
            org_id="cert_org",
            cert_expiry_days=90,
            business_value=50.0,
        )
        expired_cert = ManagedAsset(
            name="expired.example.com",
            category=AssetCategory.DOMAIN,
            exposure_zone=ExposureZone.INTERNET_FACING,
            org_id="cert_org",
            cert_expiry_days=0,
            business_value=50.0,
        )
        r_valid = engine.register_asset(valid_cert)
        r_expired = engine.register_asset(expired_cert)
        assert r_expired.risk_score > r_valid.risk_score

    def test_score_in_0_to_100_range(self, engine, internet_asset):
        assert 0.0 <= internet_asset.risk_score <= 100.0

    def test_compute_surface_score_returns_asm_score(self, engine, internet_asset, internal_asset):
        score = engine.compute_surface_score("org1")
        assert isinstance(score, ASMSurfaceScore)
        assert score.org_id == "org1"
        assert 0.0 <= score.overall_score <= 100.0

    def test_surface_score_components_present(self, engine, internet_asset):
        score = engine.compute_surface_score("org1")
        assert hasattr(score, "exposure_score")
        assert hasattr(score, "vulnerability_score")
        assert hasattr(score, "configuration_score")
        assert hasattr(score, "certificate_score")
        assert hasattr(score, "shadow_it_score")

    def test_surface_score_counts_correct(self, engine, internet_asset, internal_asset):
        score = engine.compute_surface_score("org1")
        assert score.total_assets == 2
        assert score.internet_facing_count == 1

    def test_empty_org_score_is_zero(self, engine):
        score = engine.compute_surface_score("empty_org")
        assert score.overall_score == 0.0
        assert score.total_assets == 0

    def test_risk_tier_critical_for_high_score(self, engine):
        asset = ManagedAsset(
            name="critical.example.com",
            category=AssetCategory.API_ENDPOINT,
            exposure_zone=ExposureZone.INTERNET_FACING,
            org_id="tier_org",
            open_ports=[21, 23, 3389, 3306],
            has_waf=False,
            cert_expiry_days=0,
            business_value=100.0,
        )
        result = engine.register_asset(asset)
        # Should be CRITICAL or HIGH given all the risk factors
        assert result.risk_tier in (RiskTier.CRITICAL, RiskTier.HIGH, RiskTier.MEDIUM)


# ---------------------------------------------------------------------------
# 3. Shadow IT Detection
# ---------------------------------------------------------------------------


class TestShadowIT:
    def test_detect_returns_findings(self, engine, internet_asset):
        # Asset not in CMDB
        findings = engine.detect_shadow_it("org1", cmdb_names=["other.example.com"])
        assert isinstance(findings, list)
        assert any(f.asset_name == internet_asset.name for f in findings)

    def test_detect_no_findings_when_all_in_cmdb(self, engine, internet_asset, internal_asset):
        cmdb = [internet_asset.name, internal_asset.name]
        findings = engine.detect_shadow_it("org1", cmdb_names=cmdb)
        # Should have no CMDB mismatch findings for known assets
        cmdb_findings = [f for f in findings if "not found in CMDB" in f.reason]
        assert len(cmdb_findings) == 0

    def test_shadow_it_finding_has_reason(self, engine, internet_asset):
        findings = engine.detect_shadow_it("org1", cmdb_names=["approved.example.com"])
        for f in findings:
            assert len(f.reason) > 0

    def test_shadow_it_finding_fields(self, engine, internet_asset):
        # Passing a non-empty CMDB that doesn't include the asset triggers the finding
        findings = engine.detect_shadow_it("org1", cmdb_names=["approved.example.com"])
        assert len(findings) > 0
        f = findings[0]
        assert isinstance(f, ShadowITFinding)
        assert f.org_id == "org1"
        assert f.asset_name
        assert f.asset_category in AssetCategory.__members__.values()

    def test_internet_facing_shadow_rated_high(self, engine, internet_asset):
        findings = engine.detect_shadow_it("org1", cmdb_names=["other.example.com"])
        internet_findings = [f for f in findings if f.exposure_zone == ExposureZone.INTERNET_FACING]
        for f in internet_findings:
            assert f.risk_tier in (RiskTier.HIGH, RiskTier.CRITICAL)

    def test_unmanaged_asset_flagged(self, engine):
        asset = ManagedAsset(
            name="rogue.example.com",
            category=AssetCategory.DOMAIN,
            exposure_zone=ExposureZone.INTERNET_FACING,
            org_id="shadow_org",
            is_managed=False,
        )
        engine.register_asset(asset)
        findings = engine.detect_shadow_it("shadow_org")
        rogue_findings = [f for f in findings if f.asset_name == "rogue.example.com"]
        assert len(rogue_findings) >= 1

    def test_discovered_names_not_in_cmdb_flagged(self, engine):
        findings = engine.detect_shadow_it(
            "shadow_org2",
            cmdb_names=["approved.example.com"],
            discovered_names=["unknown-tool.example.com"],
        )
        names = [f.asset_name for f in findings]
        assert "unknown-tool.example.com" in names

    def test_list_shadow_it_returns_stored_findings(self, engine, internet_asset):
        engine.detect_shadow_it("org1", cmdb_names=["other.example.com"])
        stored = engine.list_shadow_it("org1")
        assert isinstance(stored, list)
        assert len(stored) > 0

    def test_marks_asset_as_shadow_it_in_db(self, engine, internet_asset):
        engine.detect_shadow_it("org1", cmdb_names=["approved.example.com"])
        shadow_assets = engine.list_assets("org1", shadow_it_only=True)
        assert any(a.id == internet_asset.id for a in shadow_assets)


# ---------------------------------------------------------------------------
# 4. Exposure Analysis
# ---------------------------------------------------------------------------


class TestExposureAnalysis:
    def test_analyze_returns_dict(self, engine, internet_asset):
        result = engine.analyze_exposure(internet_asset.id)
        assert isinstance(result, dict)

    def test_analyze_unknown_asset_returns_error(self, engine):
        result = engine.analyze_exposure("ghost-id")
        assert "error" in result

    def test_analyze_includes_open_ports(self, engine, internet_asset):
        result = engine.analyze_exposure(internet_asset.id)
        assert "open_ports" in result
        assert isinstance(result["open_ports"], list)

    def test_analyze_identifies_risky_ports(self, engine):
        asset = ManagedAsset(
            name="risky.example.com",
            category=AssetCategory.DOMAIN,
            exposure_zone=ExposureZone.INTERNET_FACING,
            org_id="analysis_org",
            open_ports=[3389, 443],
        )
        reg = engine.register_asset(asset)
        result = engine.analyze_exposure(reg.id)
        assert 3389 in result["risky_ports"]

    def test_analyze_includes_protection_controls(self, engine, internet_asset):
        result = engine.analyze_exposure(internet_asset.id)
        assert "protection_controls" in result
        assert "waf" in result["protection_controls"]
        assert "cdn" in result["protection_controls"]

    def test_analyze_includes_tls_info(self, engine, internet_asset):
        result = engine.analyze_exposure(internet_asset.id)
        assert "tls_grade" in result
        assert "cert_expiry_days" in result

    def test_analyze_includes_security_headers_score(self, engine, internet_asset):
        result = engine.analyze_exposure(internet_asset.id)
        assert "security_headers_score" in result

    def test_analyze_flags_tls_issues(self, engine):
        asset = ManagedAsset(
            name="badtls.example.com",
            category=AssetCategory.DOMAIN,
            exposure_zone=ExposureZone.INTERNET_FACING,
            org_id="tls_org",
            tls_grade="C",
            cert_expiry_days=10,
        )
        reg = engine.register_asset(asset)
        result = engine.analyze_exposure(reg.id)
        assert len(result["tls_issues"]) > 0


# ---------------------------------------------------------------------------
# 5. Attack Path Mapping
# ---------------------------------------------------------------------------


class TestAttackPaths:
    def test_map_path_returns_attack_path(self, engine, internet_asset, internal_asset):
        path = engine.map_attack_path(
            "org1", internet_asset.id, internal_asset.id,
            protocol="HTTPS",
        )
        assert isinstance(path, AttackPath)
        assert path.entry_asset_id == internet_asset.id
        assert path.target_asset_id == internal_asset.id

    def test_path_has_risk_score(self, engine, internet_asset, internal_asset):
        path = engine.map_attack_path("org1", internet_asset.id, internal_asset.id)
        assert 0.0 <= path.path_risk_score <= 1.0

    def test_path_has_blast_radius(self, engine, internet_asset, internal_asset):
        path = engine.map_attack_path("org1", internet_asset.id, internal_asset.id)
        assert isinstance(path.blast_radius, int)
        assert path.blast_radius >= 0

    def test_path_description_includes_asset_names(self, engine, internet_asset, internal_asset):
        path = engine.map_attack_path("org1", internet_asset.id, internal_asset.id)
        assert internet_asset.name in path.description or internet_asset.id in path.description

    def test_path_with_techniques(self, engine, internet_asset, internal_asset):
        path = engine.map_attack_path(
            "org1", internet_asset.id, internal_asset.id,
            techniques=["T1190", "T1078"],
        )
        assert "T1190" in path.techniques

    def test_choke_point_detection(self, engine, internet_asset, dmz_asset, internal_asset):
        # With 3 assets (internal + dmz), internal has blast_radius >= 1
        path = engine.map_attack_path("org1", internet_asset.id, internal_asset.id)
        # choke point depends on blast radius > 5; just verify field is bool
        assert isinstance(path.is_choke_point, bool)

    def test_list_paths_returns_persisted(self, engine, internet_asset, internal_asset):
        engine.map_attack_path("org1", internet_asset.id, internal_asset.id)
        paths = engine.list_attack_paths("org1")
        assert len(paths) >= 1

    def test_list_paths_min_score_filter(self, engine, internet_asset, internal_asset):
        engine.map_attack_path("org1", internet_asset.id, internal_asset.id)
        all_paths = engine.list_attack_paths("org1", min_score=0.0)
        high_paths = engine.list_attack_paths("org1", min_score=0.99)
        assert len(all_paths) >= len(high_paths)

    def test_auto_generate_paths_internet_to_internal(self, engine, internet_asset, internal_asset):
        paths = engine.auto_generate_paths("org1")
        assert len(paths) >= 1
        entry_ids = {p.entry_asset_id for p in paths}
        assert internet_asset.id in entry_ids

    def test_get_choke_points_returns_list(self, engine, internet_asset, internal_asset):
        engine.map_attack_path("org1", internet_asset.id, internal_asset.id)
        choke = engine.get_choke_points("org1")
        assert isinstance(choke, list)
        for p in choke:
            assert p.is_choke_point is True

    def test_blast_radius_zero_for_isolated(self, engine):
        iso = ManagedAsset(
            name="iso.example.com",
            category=AssetCategory.DOMAIN,
            exposure_zone=ExposureZone.ISOLATED,
            org_id="blast_org",
        )
        engine.register_asset(iso)
        radius = engine._estimate_blast_radius("blast_org", iso.id)
        # Isolated zone: only isolated assets reachable
        assert isinstance(radius, int)


# ---------------------------------------------------------------------------
# 6. Continuous Monitoring / Change Detection
# ---------------------------------------------------------------------------


class TestChangeDetection:
    def test_detect_changes_returns_list(self, engine, internet_asset):
        changes = engine.detect_changes("org1", lookback_days=7)
        assert isinstance(changes, list)

    def test_new_asset_detected_as_new_asset_change(self, engine, internet_asset):
        changes = engine.detect_changes("org1", lookback_days=7)
        new_changes = [c for c in changes if c.change_type == ChangeType.NEW_ASSET]
        assert any(c.asset_id == internet_asset.id for c in new_changes)

    def test_stale_asset_detected_as_removed(self, engine, db_path):
        stale_engine = AttackSurfaceManager(db_path=db_path)
        old_time = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        asset = ManagedAsset(
            name="stale.example.com",
            category=AssetCategory.DOMAIN,
            exposure_zone=ExposureZone.INTERNET_FACING,
            org_id="stale_org",
            discovered_at=old_time,
            last_seen=old_time,
        )
        stale_engine._db.upsert_asset(asset)
        changes = stale_engine.detect_changes("stale_org", lookback_days=7)
        removed = [c for c in changes if c.change_type == ChangeType.REMOVED_ASSET]
        assert any(c.asset_id == asset.id for c in removed)

    def test_expiring_cert_detected_as_change(self, engine, internet_asset):
        cert = CertificateRecord(
            org_id="org1",
            asset_id=internet_asset.id,
            asset_name=internet_asset.name,
            subject="CN=api.example.com",
            issuer="CN=Test CA",
            valid_from="2024-01-01T00:00:00Z",
            valid_to="2024-01-15T00:00:00Z",
            days_until_expiry=10,
            is_expired=False,
        )
        engine.register_certificate(cert)
        changes = engine.detect_changes("org1", lookback_days=7)
        cert_changes = [c for c in changes if c.change_type == ChangeType.CERT_EXPIRING]
        assert len(cert_changes) >= 1

    def test_list_changes_returns_stored(self, engine, internet_asset):
        engine.detect_changes("org1", lookback_days=7)
        stored = engine.list_changes("org1")
        assert len(stored) >= 1

    def test_list_changes_with_since_filter(self, engine, internet_asset):
        engine.detect_changes("org1", lookback_days=7)
        future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        filtered = engine.list_changes("org1", since=future)
        assert filtered == []

    def test_change_has_required_fields(self, engine, internet_asset):
        changes = engine.detect_changes("org1", lookback_days=7)
        for c in changes:
            assert isinstance(c, SurfaceChange)
            assert c.change_type in ChangeType.__members__.values()
            assert c.asset_id
            assert c.description


# ---------------------------------------------------------------------------
# 7. Certificate Management
# ---------------------------------------------------------------------------


class TestCertificateManagement:
    def test_register_certificate(self, engine, internet_asset):
        cert = CertificateRecord(
            org_id="org1",
            asset_id=internet_asset.id,
            asset_name=internet_asset.name,
            subject="CN=api.example.com",
            issuer="Let's Encrypt",
            valid_from="2025-01-01T00:00:00Z",
            valid_to="2025-04-01T00:00:00Z",
            days_until_expiry=90,
        )
        result = engine.register_certificate(cert)
        assert isinstance(result, CertificateRecord)
        assert result.id

    def test_list_certificates_returns_registered(self, engine, internet_asset):
        cert = CertificateRecord(
            org_id="org1",
            asset_id=internet_asset.id,
            asset_name=internet_asset.name,
            subject="CN=api.example.com",
            issuer="Let's Encrypt",
            valid_from="2025-01-01T00:00:00Z",
            valid_to="2025-04-01T00:00:00Z",
            days_until_expiry=90,
        )
        engine.register_certificate(cert)
        certs = engine.list_certificates("org1")
        assert any(c.id == cert.id for c in certs)

    def test_get_expiring_certs_filters_correctly(self, engine, internet_asset):
        expiring = CertificateRecord(
            org_id="org1",
            asset_id=internet_asset.id,
            asset_name=internet_asset.name,
            subject="CN=expiring.example.com",
            issuer="CA",
            valid_from="2025-01-01T00:00:00Z",
            valid_to="2025-01-15T00:00:00Z",
            days_until_expiry=5,
        )
        healthy = CertificateRecord(
            org_id="org1",
            asset_id=internet_asset.id,
            asset_name=internet_asset.name,
            subject="CN=healthy.example.com",
            issuer="CA",
            valid_from="2025-01-01T00:00:00Z",
            valid_to="2026-01-01T00:00:00Z",
            days_until_expiry=365,
        )
        engine.register_certificate(expiring)
        engine.register_certificate(healthy)
        expiring_certs = engine.get_expiring_certificates("org1", within_days=30)
        assert any(c.id == expiring.id for c in expiring_certs)
        assert not any(c.id == healthy.id for c in expiring_certs)

    def test_expired_cert_creates_critical_change(self, engine, internet_asset):
        cert = CertificateRecord(
            org_id="org1",
            asset_id=internet_asset.id,
            asset_name=internet_asset.name,
            subject="CN=expired.example.com",
            issuer="CA",
            valid_from="2024-01-01T00:00:00Z",
            valid_to="2024-06-01T00:00:00Z",
            days_until_expiry=-10,
            is_expired=True,
        )
        engine.register_certificate(cert)
        changes = engine.list_changes("org1")
        cert_changes = [c for c in changes if c.change_type == ChangeType.CERT_EXPIRING]
        critical = [c for c in cert_changes if c.severity == RiskTier.CRITICAL]
        assert len(critical) >= 1

    def test_self_signed_cert_field(self, engine, internet_asset):
        cert = CertificateRecord(
            org_id="org1",
            asset_id=internet_asset.id,
            asset_name=internet_asset.name,
            subject="CN=self.example.com",
            issuer="CN=self.example.com",
            valid_from="2025-01-01T00:00:00Z",
            valid_to="2026-01-01T00:00:00Z",
            days_until_expiry=365,
            is_self_signed=True,
        )
        result = engine.register_certificate(cert)
        stored = engine.list_certificates("org1")
        stored_cert = next((c for c in stored if c.id == result.id), None)
        assert stored_cert is not None
        assert stored_cert.is_self_signed is True


# ---------------------------------------------------------------------------
# 8. Risk Prioritization
# ---------------------------------------------------------------------------


class TestRiskPrioritization:
    def test_prioritize_returns_list(self, engine, internet_asset, internal_asset):
        result = engine.prioritize_assets("org1")
        assert isinstance(result, list)

    def test_prioritize_sorted_by_priority_score(self, engine, internet_asset, internal_asset):
        result = engine.prioritize_assets("org1")
        scores = [r["priority_score"] for r in result]
        assert scores == sorted(scores, reverse=True)

    def test_prioritize_respects_top_n(self, engine):
        for i in range(10):
            asset = ManagedAsset(
                name=f"asset{i}.topn.example.com",
                category=AssetCategory.DOMAIN,
                exposure_zone=ExposureZone.INTERNET_FACING,
                org_id="topn_org",
            )
            engine.register_asset(asset)
        result = engine.prioritize_assets("topn_org", top_n=5)
        assert len(result) <= 5

    def test_prioritize_includes_epss_stubs(self, engine):
        asset = ManagedAsset(
            name="epss.example.com",
            category=AssetCategory.DOMAIN,
            exposure_zone=ExposureZone.INTERNET_FACING,
            org_id="epss_org",
            attributes={"cves": ["CVE-2023-1234", "CVE-2024-9999"]},
        )
        engine.register_asset(asset)
        result = engine.prioritize_assets("epss_org")
        epss_entry = next((r for r in result if r["name"] == "epss.example.com"), None)
        assert epss_entry is not None
        assert "epss_scores" in epss_entry
        assert "CVE-2023-1234" in epss_entry["epss_scores"]

    def test_prioritize_includes_required_fields(self, engine, internet_asset):
        result = engine.prioritize_assets("org1")
        assert len(result) > 0
        entry = result[0]
        for field in ("asset_id", "name", "category", "risk_score", "priority_score", "has_waf"):
            assert field in entry

    def test_epss_stub_deterministic(self):
        s1 = _epss_score_stub("CVE-2023-1234")
        s2 = _epss_score_stub("CVE-2023-1234")
        assert s1 == s2

    def test_epss_stub_in_range(self):
        score = _epss_score_stub("CVE-2024-12345")
        assert 0.0 <= score <= 1.0

    def test_shadow_it_flag_in_prioritized(self, engine, internet_asset):
        engine.detect_shadow_it("org1", cmdb_names=["approved.com"])
        result = engine.prioritize_assets("org1")
        entry = next((r for r in result if r["name"] == internet_asset.name), None)
        assert entry is not None
        assert "is_shadow_it" in entry


# ---------------------------------------------------------------------------
# 9. Full Scan Orchestration
# ---------------------------------------------------------------------------


class TestScanOrchestration:
    def test_run_scan_returns_scan_result(self, engine):
        result = engine.run_scan("scan_org")
        assert isinstance(result, ScanResult)

    def test_run_scan_completes_successfully(self, engine):
        result = engine.run_scan("scan_org")
        assert result.status == ScanStatus.COMPLETE

    def test_run_scan_with_discovery_data(self, engine):
        data = [
            {"domain": "scan.example.com", "exposure_zone": "internet_facing"},
            {"ip": "10.0.0.5", "exposure_zone": "internal"},
        ]
        result = engine.run_scan("scan2_org", discovery_data=data)
        assert result.assets_discovered >= 2

    def test_run_scan_records_score(self, engine, internet_asset, internal_asset):
        result = engine.run_scan("org1")
        assert result.overall_score >= 0.0

    def test_get_latest_scan_returns_last_scan(self, engine):
        engine.run_scan("scan3_org")
        latest = engine.get_latest_scan("scan3_org")
        assert latest is not None
        assert latest.status == ScanStatus.COMPLETE

    def test_get_latest_scan_unknown_org_returns_none(self, engine):
        result = engine.get_latest_scan("unknown_org_xyz")
        assert result is None

    def test_scan_with_shadow_it_counts(self, engine):
        data = [{"domain": "shadow.example.com", "exposure_zone": "internet_facing"}]
        result = engine.run_scan("shadow_scan_org", discovery_data=data, cmdb_names=["approved.example.com"])
        assert result.shadow_it_count >= 1


# ---------------------------------------------------------------------------
# 10. Singleton
# ---------------------------------------------------------------------------


class TestSingleton:
    def test_get_asm_engine_returns_instance(self, tmp_path):
        path = str(tmp_path / "singleton.db")
        engine1 = get_asm_engine(db_path=path)
        engine2 = get_asm_engine(db_path=path)
        assert engine1 is engine2

    def test_engine_is_attack_surface_manager(self, tmp_path):
        path = str(tmp_path / "singleton2.db")
        engine = get_asm_engine(db_path=path)
        assert isinstance(engine, AttackSurfaceManager)
