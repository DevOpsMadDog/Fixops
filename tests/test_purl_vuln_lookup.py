"""Tests for PURL-based vulnerability lookup and SCA test endpoint.

Covers:
  1. VulnIntelligenceEngine.lookup_package_issues — PURL → CVE list + risk score
  2. SoftwareCompositionAnalysisEngine.test_package_version — safe/vulnerable detection
  3. SCA engine test_package_version recommended_upgrade version bump logic
"""

from __future__ import annotations

import pytest

from core.vuln_intelligence_engine import VulnIntelligenceEngine
from core.software_composition_analysis_engine import SoftwareCompositionAnalysisEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def vuln_engine(tmp_path):
    return VulnIntelligenceEngine(db_path=str(tmp_path / "vuln_intel.db"))


@pytest.fixture
def sca_engine(tmp_path):
    return SoftwareCompositionAnalysisEngine(
        db_path=str(tmp_path / "sca.db")
    )


ORG = "test-org"


# ---------------------------------------------------------------------------
# Test 1: lookup_package_issues returns CVEs from cve_intel for known package
# ---------------------------------------------------------------------------

def test_lookup_package_issues_with_cve_intel(vuln_engine):
    """PURL lookup finds CVEs stored in cve_intel via affected_products match."""
    # Seed a CVE that lists lodash as an affected product
    vuln_engine.add_cve(ORG, {
        "cve_id": "CVE-2021-23337",
        "title": "Lodash command injection",
        "description": "Prototype pollution in lodash",
        "cvss_score": 7.2,
        "severity": "high",
        "affected_products": [{"vendor": "lodash", "product": "lodash"}],
        "patch_available": True,
        "patch_url": "",
    })

    result = vuln_engine.lookup_package_issues(
        org_id=ORG,
        ecosystem="npm",
        name="lodash",
        version="4.17.20",
    )

    assert result["vulnerable"] is True
    assert result["cve_count"] >= 1
    assert any(c["cve_id"] == "CVE-2021-23337" for c in result["cves"])
    assert result["risk_score"] >= 7.0
    assert result["package"]["ecosystem"] == "npm"
    assert result["package"]["name"] == "lodash"
    assert result["package"]["version"] == "4.17.20"
    assert result["package"]["purl"] == "pkg:npm/lodash@4.17.20"


# ---------------------------------------------------------------------------
# Test 2: test_package_version detects known vulnerable package
# ---------------------------------------------------------------------------

def test_sca_test_package_version_vulnerable(sca_engine):
    """test_package_version flags lodash as vulnerable via _KNOWN_VULNERABLE."""
    result = sca_engine.test_package_version(
        org_id=ORG,
        ecosystem="npm",
        package="lodash",
        version="4.17.20",
    )

    assert result["vulnerable"] is True
    assert result["safe"] is False
    assert len(result["cves"]) >= 1
    assert any("CVE" in c["cve_id"] for c in result["cves"])
    assert result["package"]["name"] == "lodash"
    assert result["package"]["version"] == "4.17.20"
    # Recommended upgrade should suggest a bumped minor version
    assert result["recommended_upgrade"] is not None
    assert result["recommended_upgrade"].startswith("4.")


# ---------------------------------------------------------------------------
# Test 3: test_package_version returns safe for unknown package
# ---------------------------------------------------------------------------

def test_sca_test_package_version_safe(sca_engine):
    """test_package_version returns safe=True for an unknown/safe package."""
    result = sca_engine.test_package_version(
        org_id=ORG,
        ecosystem="npm",
        package="totally-safe-pkg-xyz",
        version="1.0.0",
    )

    assert result["safe"] is True
    assert result["vulnerable"] is False
    assert result["cves"] == []
    assert result["recommended_upgrade"] is None
    assert result["package"]["ecosystem"] == "npm"
    assert result["package"]["name"] == "totally-safe-pkg-xyz"
