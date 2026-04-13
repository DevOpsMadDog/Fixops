"""Tests for AssetEnricher — auto-discovery, classification, and risk scoring.

Tests cover:
- enrich_asset: full enrichment pipeline
- discover_local_services: socket scanning (mocked)
- classify_asset_criticality: all rule branches
- calculate_asset_risk: base + finding scoring, capping
- _classify_data_sensitivity: keyword and explicit-field paths
- _lookup_cves_nvd: network call (mocked)
- Service and EnrichedAsset dataclasses

Usage:
    pytest tests/test_asset_enricher.py -v --timeout=10
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

# Ensure suite-core is on sys.path
suite_core_path = str(Path(__file__).parent.parent / "suite-core")
if suite_core_path not in sys.path:
    sys.path.insert(0, suite_core_path)

from core.asset_enricher import AssetEnricher, EnrichedAsset, Service


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def enricher():
    """AssetEnricher with a short socket timeout for fast tests."""
    return AssetEnricher(socket_timeout=0.1, max_workers=5)


def _asset(name: str = "web-server-01", **kwargs: Any) -> Dict[str, Any]:
    base = {
        "name": name,
        "asset_type": "server",
        "environment": "production",
        "org_id": "default",
    }
    base.update(kwargs)
    return base


# ---------------------------------------------------------------------------
# classify_asset_criticality
# ---------------------------------------------------------------------------

class TestClassifyAssetCriticality:
    def test_production_auth_is_critical(self, enricher):
        asset = _asset(name="auth-service", environment="production")
        assert enricher.classify_asset_criticality(asset) == "critical"

    def test_production_payment_is_critical(self, enricher):
        asset = _asset(name="payment-gateway", environment="production")
        assert enricher.classify_asset_criticality(asset) == "critical"

    def test_production_database_is_critical(self, enricher):
        asset = _asset(name="postgres-primary", environment="production", asset_type="database")
        assert enricher.classify_asset_criticality(asset) == "critical"

    def test_production_public_api_is_high(self, enricher):
        asset = _asset(name="public-api", environment="production")
        assert enricher.classify_asset_criticality(asset) == "high"

    def test_production_web_is_high(self, enricher):
        asset = _asset(name="web-frontend", environment="production")
        assert enricher.classify_asset_criticality(asset) == "high"

    def test_production_generic_is_medium(self, enricher):
        asset = _asset(name="internal-scheduler", environment="production")
        assert enricher.classify_asset_criticality(asset) == "medium"

    def test_dev_environment_is_low(self, enricher):
        asset = _asset(name="web-server-01", environment="development")
        assert enricher.classify_asset_criticality(asset) == "low"

    def test_staging_environment_is_low(self, enricher):
        asset = _asset(name="staging-api", environment="staging")
        assert enricher.classify_asset_criticality(asset) == "low"

    def test_name_with_dev_keyword_is_low(self, enricher):
        asset = _asset(name="dev-mysql", environment="production")
        assert enricher.classify_asset_criticality(asset) == "low"

    def test_default_environment_treated_as_production(self, enricher):
        asset = {"name": "web-server", "asset_type": "server"}
        # default is production, web → high
        assert enricher.classify_asset_criticality(asset) == "high"


# ---------------------------------------------------------------------------
# calculate_asset_risk
# ---------------------------------------------------------------------------

class TestCalculateAssetRisk:
    def test_no_findings_critical_asset(self, enricher):
        asset = _asset(name="auth-service", environment="production")
        score = enricher.calculate_asset_risk(asset, [])
        assert score == 40.0

    def test_no_findings_low_asset(self, enricher):
        asset = _asset(name="dev-server", environment="development")
        score = enricher.calculate_asset_risk(asset, [])
        assert score == 2.0

    def test_critical_findings_add_to_score(self, enricher):
        asset = _asset(name="web-01", environment="production")
        findings = [{"severity": "critical"}, {"severity": "high"}]
        score = enricher.calculate_asset_risk(asset, findings)
        # web-01 → high base=25, critical=+15, high=+10 → 50
        assert score == 50.0

    def test_risk_score_capped_at_100(self, enricher):
        asset = _asset(name="auth-service", environment="production")
        findings = [{"severity": "critical"}] * 20
        score = enricher.calculate_asset_risk(asset, findings)
        assert score == 100.0

    def test_risk_score_rounded_to_2dp(self, enricher):
        asset = _asset(name="dev-svc", environment="development")
        findings = [{"severity": "informational"}]
        score = enricher.calculate_asset_risk(asset, findings)
        assert score == round(score, 2)

    def test_empty_findings_list(self, enricher):
        asset = _asset()
        score = enricher.calculate_asset_risk(asset, [])
        assert isinstance(score, float)
        assert 0.0 <= score <= 100.0


# ---------------------------------------------------------------------------
# _classify_data_sensitivity
# ---------------------------------------------------------------------------

class TestClassifyDataSensitivity:
    def test_explicit_public(self, enricher):
        asset = _asset(data_classification="public")
        assert enricher._classify_data_sensitivity(asset) == "PUBLIC"

    def test_explicit_confidential(self, enricher):
        asset = _asset(data_classification="confidential")
        assert enricher._classify_data_sensitivity(asset) == "CONFIDENTIAL"

    def test_explicit_restricted_maps_to_confidential(self, enricher):
        asset = _asset(data_classification="restricted")
        assert enricher._classify_data_sensitivity(asset) == "CONFIDENTIAL"

    def test_explicit_secret(self, enricher):
        asset = _asset(data_classification="secret")
        assert enricher._classify_data_sensitivity(asset) == "SECRET"

    def test_name_with_secret_keyword(self, enricher):
        asset = _asset(name="credential-store")
        assert enricher._classify_data_sensitivity(asset) == "SECRET"

    def test_name_with_pii_keyword(self, enricher):
        asset = _asset(name="customer-pii-db")
        assert enricher._classify_data_sensitivity(asset) == "CONFIDENTIAL"

    def test_default_returns_internal(self, enricher):
        asset = _asset(name="worker-node")
        assert enricher._classify_data_sensitivity(asset) == "INTERNAL"


# ---------------------------------------------------------------------------
# discover_local_services (socket mocked)
# ---------------------------------------------------------------------------

class TestDiscoverLocalServices:
    def test_returns_empty_when_no_ports_open(self, enricher):
        with patch.object(enricher, "_probe_port", return_value=None):
            services = enricher.discover_local_services("192.0.2.1")
        assert services == []

    def test_returns_open_services_sorted_by_port(self, enricher):
        def mock_probe(host, port):
            if port in (80, 443):
                return Service(host=host, port=port, service_name=_name(port))
            return None

        def _name(p):
            return {80: "http", 443: "https"}.get(p)

        with patch.object(enricher, "_probe_port", side_effect=mock_probe):
            services = enricher.discover_local_services("127.0.0.1")

        assert len(services) == 2
        assert services[0].port == 80
        assert services[1].port == 443

    def test_service_has_correct_fields(self, enricher):
        svc = Service(host="127.0.0.1", port=22, service_name="ssh")
        assert svc.host == "127.0.0.1"
        assert svc.port == 22
        assert svc.service_name == "ssh"
        assert svc.protocol == "tcp"


# ---------------------------------------------------------------------------
# enrich_asset (integration — sockets and NVD mocked)
# ---------------------------------------------------------------------------

class TestEnrichAsset:
    def test_enrich_basic_asset_no_host(self, enricher):
        """Asset without hostname/IP should still return criticality + sensitivity."""
        asset = _asset(name="internal-scheduler")
        with patch.object(enricher, "_lookup_cves_nvd", return_value=[]):
            enriched = enricher.enrich_asset(asset)
        assert isinstance(enriched, EnrichedAsset)
        assert enriched.criticality in ("critical", "high", "medium", "low")
        assert enriched.data_sensitivity in ("PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET")
        assert isinstance(enriched.risk_score, float)

    def test_enrich_with_hostname_triggers_port_scan(self, enricher):
        asset = _asset(hostname="127.0.0.1")
        open_svc = Service(host="127.0.0.1", port=80, service_name="http")
        with patch.object(enricher, "discover_local_services", return_value=[open_svc]):
            enriched = enricher.enrich_asset(asset)
        assert len(enriched.open_ports) == 1
        assert "socket_scan" in enriched.enrichment_source

    def test_enrich_software_asset_triggers_cve_lookup(self, enricher):
        asset = _asset(asset_type="application", metadata={"software": "apache"})
        with patch.object(enricher, "_lookup_cves_nvd", return_value=["CVE-2024-0001"]):
            enriched = enricher.enrich_asset(asset)
        assert "CVE-2024-0001" in enriched.cve_ids
        assert "nvd_cve_lookup" in enriched.enrichment_source

    def test_enrich_cloud_asset_calls_cspm(self, enricher):
        asset = _asset(cloud_provider="aws", cloud_resource_id="arn:aws:ec2:us-east-1:123:instance/i-abc")
        cspm_finding = {"id": "cspm-001", "severity": "high", "rule": "public-s3"}
        with patch.object(enricher, "_get_cspm_findings", return_value=[cspm_finding]):
            enriched = enricher.enrich_asset(asset)
        assert len(enriched.cspm_findings) == 1
        assert "cspm" in enriched.enrichment_source

    def test_enrich_risk_score_increases_with_findings(self, enricher):
        asset = _asset(name="web-01")
        with patch.object(enricher, "_lookup_cves_nvd", return_value=[]):
            enriched_no_findings = enricher.enrich_asset(asset)

        asset2 = _asset(name="web-01", cloud_provider="aws")
        cspm = [{"severity": "critical"}, {"severity": "high"}]
        with patch.object(enricher, "_get_cspm_findings", return_value=cspm):
            enriched_with_findings = enricher.enrich_asset(asset2)

        assert enriched_with_findings.risk_score > enriched_no_findings.risk_score
