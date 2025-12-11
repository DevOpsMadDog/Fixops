"""Rigorous tests for License Compliance functionality.

These tests verify license analysis, compatibility checking, and risk assessment
with realistic scenarios and proper assertions.
"""

from datetime import datetime, timezone

from risk.license_compliance import (
    LicenseComplianceAnalyzer,
    LicenseComplianceResult,
    LicenseFinding,
    LicenseRisk,
    LicenseType,
)


class TestLicenseType:
    """Tests for LicenseType enum."""

    def test_license_type_values(self):
        """Verify all license types have expected string values."""
        assert LicenseType.PERMISSIVE.value == "permissive"
        assert LicenseType.WEAK_COPYLEFT.value == "weak_copyleft"
        assert LicenseType.STRONG_COPYLEFT.value == "strong_copyleft"
        assert LicenseType.PROPRIETARY.value == "proprietary"
        assert LicenseType.UNKNOWN.value == "unknown"


class TestLicenseRisk:
    """Tests for LicenseRisk enum."""

    def test_license_risk_values(self):
        """Verify all risk levels have expected string values."""
        assert LicenseRisk.LOW.value == "low"
        assert LicenseRisk.MEDIUM.value == "medium"
        assert LicenseRisk.HIGH.value == "high"
        assert LicenseRisk.CRITICAL.value == "critical"


class TestLicenseFinding:
    """Tests for LicenseFinding dataclass."""

    def test_finding_defaults(self):
        """Verify LicenseFinding has correct default values."""
        finding = LicenseFinding(
            package_name="test-package",
            license_type=LicenseType.PERMISSIVE,
            license_name="MIT",
            risk_level=LicenseRisk.LOW,
        )
        assert finding.package_name == "test-package"
        assert finding.license_type == LicenseType.PERMISSIVE
        assert finding.license_name == "MIT"
        assert finding.risk_level == LicenseRisk.LOW
        assert finding.compatibility_issues == []
        assert finding.recommendation == ""
        assert isinstance(finding.timestamp, datetime)

    def test_finding_with_all_fields(self):
        """Verify LicenseFinding stores all fields correctly."""
        timestamp = datetime.now(timezone.utc)
        finding = LicenseFinding(
            package_name="gpl-package",
            license_type=LicenseType.STRONG_COPYLEFT,
            license_name="GPL-3.0",
            risk_level=LicenseRisk.HIGH,
            compatibility_issues=["Incompatible with MIT"],
            recommendation="Consider alternative package",
            timestamp=timestamp,
        )
        assert finding.package_name == "gpl-package"
        assert finding.license_type == LicenseType.STRONG_COPYLEFT
        assert len(finding.compatibility_issues) == 1
        assert finding.recommendation == "Consider alternative package"
        assert finding.timestamp == timestamp


class TestLicenseComplianceResult:
    """Tests for LicenseComplianceResult dataclass."""

    def test_result_structure(self):
        """Verify LicenseComplianceResult has correct structure."""
        findings = [
            LicenseFinding(
                package_name="pkg1",
                license_type=LicenseType.PERMISSIVE,
                license_name="MIT",
                risk_level=LicenseRisk.LOW,
            ),
            LicenseFinding(
                package_name="pkg2",
                license_type=LicenseType.STRONG_COPYLEFT,
                license_name="GPL-3.0",
                risk_level=LicenseRisk.HIGH,
            ),
        ]
        result = LicenseComplianceResult(
            findings=findings,
            total_findings=2,
            findings_by_risk={"low": 1, "high": 1},
            findings_by_type={"permissive": 1, "strong_copyleft": 1},
            incompatible_licenses=["GPL-3.0"],
        )
        assert result.total_findings == 2
        assert result.findings_by_risk["low"] == 1
        assert result.findings_by_type["permissive"] == 1
        assert "GPL-3.0" in result.incompatible_licenses


class TestLicenseComplianceAnalyzerInit:
    """Tests for LicenseComplianceAnalyzer initialization."""

    def test_default_initialization(self):
        """Verify analyzer initializes with default settings."""
        analyzer = LicenseComplianceAnalyzer()
        assert analyzer.config == {}
        assert analyzer.license_database is not None
        assert analyzer.compatibility_matrix is not None
        assert analyzer.policy == {}

    def test_custom_config(self):
        """Verify analyzer uses custom configuration."""
        config = {
            "policy": {
                "project_license": "Apache-2.0",
                "allowed_licenses": ["MIT", "Apache-2.0"],
                "blocked_licenses": ["GPL-3.0", "AGPL-3.0"],
            }
        }
        analyzer = LicenseComplianceAnalyzer(config=config)
        assert analyzer.policy["project_license"] == "Apache-2.0"
        assert "MIT" in analyzer.policy["allowed_licenses"]


class TestLicenseDatabase:
    """Tests for license database."""

    def test_mit_license_info(self):
        """Verify MIT license information is correct."""
        analyzer = LicenseComplianceAnalyzer()
        mit_info = analyzer.license_database.get("MIT")
        assert mit_info is not None
        assert mit_info["type"] == LicenseType.PERMISSIVE
        assert mit_info["risk"] == LicenseRisk.LOW
        assert mit_info["commercial_use"] is True
        assert mit_info["modification"] is True
        assert mit_info["distribution"] is True

    def test_apache_license_info(self):
        """Verify Apache-2.0 license information is correct."""
        analyzer = LicenseComplianceAnalyzer()
        apache_info = analyzer.license_database.get("Apache-2.0")
        assert apache_info is not None
        assert apache_info["type"] == LicenseType.PERMISSIVE
        assert apache_info["risk"] == LicenseRisk.LOW
        assert apache_info["patent_use"] is True

    def test_gpl_license_info(self):
        """Verify GPL-3.0 license information is correct."""
        analyzer = LicenseComplianceAnalyzer()
        gpl_info = analyzer.license_database.get("GPL-3.0")
        assert gpl_info is not None
        assert gpl_info["type"] == LicenseType.STRONG_COPYLEFT
        assert gpl_info["risk"] == LicenseRisk.HIGH
        assert gpl_info["copyleft"] is True

    def test_agpl_license_info(self):
        """Verify AGPL-3.0 license information is correct."""
        analyzer = LicenseComplianceAnalyzer()
        agpl_info = analyzer.license_database.get("AGPL-3.0")
        assert agpl_info is not None
        assert agpl_info["type"] == LicenseType.STRONG_COPYLEFT
        assert agpl_info["risk"] == LicenseRisk.CRITICAL
        assert agpl_info["network_use"] is True

    def test_lgpl_license_info(self):
        """Verify LGPL-2.1 license information is correct."""
        analyzer = LicenseComplianceAnalyzer()
        lgpl_info = analyzer.license_database.get("LGPL-2.1")
        assert lgpl_info is not None
        assert lgpl_info["type"] == LicenseType.WEAK_COPYLEFT
        assert lgpl_info["risk"] == LicenseRisk.MEDIUM

    def test_mpl_license_info(self):
        """Verify MPL-2.0 license information is correct."""
        analyzer = LicenseComplianceAnalyzer()
        mpl_info = analyzer.license_database.get("MPL-2.0")
        assert mpl_info is not None
        assert mpl_info["type"] == LicenseType.WEAK_COPYLEFT
        assert mpl_info["risk"] == LicenseRisk.MEDIUM


class TestCompatibilityMatrix:
    """Tests for license compatibility matrix."""

    def test_mit_compatibility(self):
        """Verify MIT license compatibility."""
        analyzer = LicenseComplianceAnalyzer()
        compatible = analyzer.compatibility_matrix.get("MIT", [])
        assert "MIT" in compatible
        assert "Apache-2.0" in compatible
        assert "BSD-3-Clause" in compatible
        assert "LGPL-2.1" in compatible

    def test_gpl_compatibility(self):
        """Verify GPL license compatibility (restrictive)."""
        analyzer = LicenseComplianceAnalyzer()
        gpl2_compatible = analyzer.compatibility_matrix.get("GPL-2.0", [])
        gpl3_compatible = analyzer.compatibility_matrix.get("GPL-3.0", [])
        assert "GPL-2.0" in gpl2_compatible
        assert "GPL-3.0" in gpl2_compatible
        assert "MIT" not in gpl2_compatible
        assert "GPL-3.0" in gpl3_compatible
        assert len(gpl3_compatible) == 1  # Only GPL-3.0

    def test_agpl_compatibility(self):
        """Verify AGPL license compatibility (most restrictive)."""
        analyzer = LicenseComplianceAnalyzer()
        agpl_compatible = analyzer.compatibility_matrix.get("AGPL-3.0", [])
        assert "AGPL-3.0" in agpl_compatible
        assert len(agpl_compatible) == 1  # Only AGPL-3.0


class TestLicenseAnalysis:
    """Tests for license analysis."""

    def test_analyze_permissive_licenses(self):
        """Verify analysis of permissive licenses."""
        analyzer = LicenseComplianceAnalyzer()
        packages = [
            {"name": "package1", "license": "MIT"},
            {"name": "package2", "license": "Apache-2.0"},
            {"name": "package3", "license": "BSD-3-Clause"},
        ]
        result = analyzer.analyze(packages)

        assert result.total_findings == 3
        assert result.findings_by_risk.get("low", 0) == 3
        assert result.findings_by_type.get("permissive", 0) == 3
        assert len(result.incompatible_licenses) == 0

    def test_analyze_copyleft_licenses(self):
        """Verify analysis of copyleft licenses."""
        analyzer = LicenseComplianceAnalyzer()
        packages = [
            {"name": "gpl-pkg", "license": "GPL-3.0"},
            {"name": "lgpl-pkg", "license": "LGPL-2.1"},
        ]
        result = analyzer.analyze(packages)

        assert result.total_findings == 2
        assert result.findings_by_risk.get("high", 0) == 1
        assert result.findings_by_risk.get("medium", 0) == 1
        assert result.findings_by_type.get("strong_copyleft", 0) == 1
        assert result.findings_by_type.get("weak_copyleft", 0) == 1

    def test_analyze_blocked_license(self):
        """Verify blocked licenses are flagged as critical."""
        analyzer = LicenseComplianceAnalyzer()
        packages = [
            {"name": "agpl-pkg", "license": "AGPL-3.0"},
        ]
        result = analyzer.analyze(packages)

        assert result.total_findings == 1
        assert result.findings_by_risk.get("critical", 0) == 1
        assert "AGPL-3.0" in result.incompatible_licenses

    def test_analyze_unknown_license(self):
        """Verify unknown licenses are handled correctly."""
        analyzer = LicenseComplianceAnalyzer()
        packages = [
            {"name": "unknown-pkg", "license": "CUSTOM-LICENSE"},
        ]
        result = analyzer.analyze(packages)

        assert result.total_findings == 1
        finding = result.findings[0]
        assert finding.license_type == LicenseType.UNKNOWN
        assert finding.risk_level == LicenseRisk.MEDIUM

    def test_analyze_with_policy(self):
        """Verify analysis respects policy configuration."""
        config = {
            "policy": {
                "project_license": "MIT",
                "allowed_licenses": ["MIT", "Apache-2.0"],
                "blocked_licenses": ["GPL-3.0"],
            }
        }
        analyzer = LicenseComplianceAnalyzer(config=config)
        packages = [
            {"name": "mit-pkg", "license": "MIT"},
            {"name": "gpl-pkg", "license": "GPL-3.0"},
            {"name": "bsd-pkg", "license": "BSD-3-Clause"},
        ]
        result = analyzer.analyze(packages)

        # MIT should be fine
        mit_finding = next(f for f in result.findings if f.package_name == "mit-pkg")
        assert mit_finding.risk_level == LicenseRisk.LOW
        assert len(mit_finding.compatibility_issues) == 0

        # GPL should be blocked
        gpl_finding = next(f for f in result.findings if f.package_name == "gpl-pkg")
        assert gpl_finding.risk_level == LicenseRisk.CRITICAL
        assert "GPL-3.0" in result.incompatible_licenses

        # BSD should have compatibility issue (not in allowed list)
        bsd_finding = next(f for f in result.findings if f.package_name == "bsd-pkg")
        assert "Not in allowed licenses list" in bsd_finding.compatibility_issues

    def test_analyze_compatibility_issues(self):
        """Verify compatibility issues are detected."""
        config = {
            "policy": {
                "project_license": "GPL-3.0",
            }
        }
        analyzer = LicenseComplianceAnalyzer(config=config)
        packages = [
            {"name": "mit-pkg", "license": "MIT"},
        ]
        result = analyzer.analyze(packages)

        finding = result.findings[0]
        assert len(finding.compatibility_issues) > 0
        assert (
            "Incompatible with project license GPL-3.0"
            in finding.compatibility_issues[0]
        )


class TestRecommendations:
    """Tests for license recommendations."""

    def test_critical_recommendation(self):
        """Verify critical risk recommendation."""
        analyzer = LicenseComplianceAnalyzer()
        recommendation = analyzer._get_recommendation("AGPL-3.0", LicenseRisk.CRITICAL)
        assert "replacing" in recommendation.lower()
        assert "AGPL-3.0" in recommendation

    def test_high_recommendation(self):
        """Verify high risk recommendation."""
        analyzer = LicenseComplianceAnalyzer()
        recommendation = analyzer._get_recommendation("GPL-3.0", LicenseRisk.HIGH)
        assert "review" in recommendation.lower()
        assert "GPL-3.0" in recommendation

    def test_medium_recommendation(self):
        """Verify medium risk recommendation."""
        analyzer = LicenseComplianceAnalyzer()
        recommendation = analyzer._get_recommendation("LGPL-2.1", LicenseRisk.MEDIUM)
        assert "monitor" in recommendation.lower()
        assert "LGPL-2.1" in recommendation

    def test_low_recommendation(self):
        """Verify low risk recommendation."""
        analyzer = LicenseComplianceAnalyzer()
        recommendation = analyzer._get_recommendation("MIT", LicenseRisk.LOW)
        assert "safe" in recommendation.lower()
        assert "MIT" in recommendation


class TestBuildResult:
    """Tests for result building."""

    def test_build_result_aggregation(self):
        """Verify result aggregation is correct."""
        analyzer = LicenseComplianceAnalyzer()
        findings = [
            LicenseFinding(
                package_name="pkg1",
                license_type=LicenseType.PERMISSIVE,
                license_name="MIT",
                risk_level=LicenseRisk.LOW,
            ),
            LicenseFinding(
                package_name="pkg2",
                license_type=LicenseType.PERMISSIVE,
                license_name="Apache-2.0",
                risk_level=LicenseRisk.LOW,
            ),
            LicenseFinding(
                package_name="pkg3",
                license_type=LicenseType.STRONG_COPYLEFT,
                license_name="GPL-3.0",
                risk_level=LicenseRisk.HIGH,
            ),
        ]
        incompatible = ["GPL-3.0"]

        result = analyzer._build_result(findings, incompatible)

        assert result.total_findings == 3
        assert result.findings_by_risk["low"] == 2
        assert result.findings_by_risk["high"] == 1
        assert result.findings_by_type["permissive"] == 2
        assert result.findings_by_type["strong_copyleft"] == 1
        assert result.incompatible_licenses == ["GPL-3.0"]

    def test_build_result_deduplicates_incompatible(self):
        """Verify incompatible licenses are deduplicated."""
        analyzer = LicenseComplianceAnalyzer()
        findings = []
        incompatible = ["GPL-3.0", "GPL-3.0", "AGPL-3.0", "GPL-3.0"]

        result = analyzer._build_result(findings, incompatible)

        # Should be deduplicated
        assert len(result.incompatible_licenses) == 2
        assert "GPL-3.0" in result.incompatible_licenses
        assert "AGPL-3.0" in result.incompatible_licenses


class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_packages_list(self):
        """Verify handling of empty packages list."""
        analyzer = LicenseComplianceAnalyzer()
        result = analyzer.analyze([])

        assert result.total_findings == 0
        assert result.findings == []
        assert result.findings_by_risk == {}
        assert result.findings_by_type == {}

    def test_package_missing_name(self):
        """Verify handling of package without name."""
        analyzer = LicenseComplianceAnalyzer()
        packages = [{"license": "MIT"}]
        result = analyzer.analyze(packages)

        assert result.total_findings == 1
        assert result.findings[0].package_name == "unknown"

    def test_package_missing_license(self):
        """Verify handling of package without license."""
        analyzer = LicenseComplianceAnalyzer()
        packages = [{"name": "no-license-pkg"}]
        result = analyzer.analyze(packages)

        assert result.total_findings == 1
        assert result.findings[0].license_name == "UNKNOWN"
        assert result.findings[0].license_type == LicenseType.UNKNOWN
