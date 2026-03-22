"""Unit tests for License Compliance — suite-evidence-risk/risk/license_compliance.py

Covers: LicenseComplianceAnalyzer, license database, compatibility matrix
Target: 241 LOC, 0% baseline → high coverage ROI
Pillar: V3 (decision intelligence), V10 (compliance evidence)
"""


from risk.license_compliance import (
    LicenseComplianceAnalyzer,
    LicenseComplianceResult,
    LicenseFinding,
    LicenseRisk,
    LicenseType,
)


# ── Enums ──────────────────────────────────────────────────────────────────

class TestLicenseType:
    def test_all_types(self):
        assert LicenseType.PERMISSIVE.value == "permissive"
        assert LicenseType.WEAK_COPYLEFT.value == "weak_copyleft"
        assert LicenseType.STRONG_COPYLEFT.value == "strong_copyleft"
        assert LicenseType.PROPRIETARY.value == "proprietary"
        assert LicenseType.UNKNOWN.value == "unknown"

    def test_enum_count(self):
        assert len(LicenseType) == 8


class TestLicenseRisk:
    def test_all_risks(self):
        assert LicenseRisk.LOW.value == "low"
        assert LicenseRisk.MEDIUM.value == "medium"
        assert LicenseRisk.HIGH.value == "high"
        assert LicenseRisk.CRITICAL.value == "critical"


# ── LicenseFinding Dataclass ──────────────────────────────────────────────

class TestLicenseFinding:
    def test_create_finding(self):
        finding = LicenseFinding(
            package_name="flask",
            license_type=LicenseType.PERMISSIVE,
            license_name="MIT",
            risk_level=LicenseRisk.LOW,
        )
        assert finding.package_name == "flask"
        assert finding.license_type == LicenseType.PERMISSIVE
        assert finding.license_name == "MIT"
        assert finding.risk_level == LicenseRisk.LOW
        assert finding.compatibility_issues == []
        assert finding.recommendation == ""
        assert finding.timestamp is not None

    def test_finding_with_issues(self):
        finding = LicenseFinding(
            package_name="gpl-lib",
            license_type=LicenseType.STRONG_COPYLEFT,
            license_name="GPL-3.0",
            risk_level=LicenseRisk.HIGH,
            compatibility_issues=["Incompatible with MIT project"],
            recommendation="Replace with permissive alternative",
        )
        assert len(finding.compatibility_issues) == 1
        assert finding.recommendation == "Replace with permissive alternative"


# ── LicenseComplianceResult Dataclass ──────────────────────────────────────

class TestLicenseComplianceResult:
    def test_create_result(self):
        result = LicenseComplianceResult(
            findings=[],
            total_findings=0,
            findings_by_risk={},
            findings_by_type={},
        )
        assert result.total_findings == 0
        assert result.incompatible_licenses == []
        assert result.timestamp is not None

    def test_result_with_data(self):
        result = LicenseComplianceResult(
            findings=[],
            total_findings=3,
            findings_by_risk={"low": 2, "high": 1},
            findings_by_type={"permissive": 2, "strong_copyleft": 1},
            incompatible_licenses=["GPL-3.0"],
        )
        assert result.total_findings == 3
        assert result.incompatible_licenses == ["GPL-3.0"]


# ── LicenseComplianceAnalyzer ──────────────────────────────────────────────

class TestLicenseComplianceAnalyzer:
    def setup_method(self):
        self.analyzer = LicenseComplianceAnalyzer()

    def test_init_default(self):
        a = LicenseComplianceAnalyzer()
        assert a.config == {}
        assert len(a.license_database) > 0
        assert len(a.compatibility_matrix) > 0

    def test_init_custom_config(self):
        a = LicenseComplianceAnalyzer(config={"policy": {"project_license": "Apache-2.0"}})
        assert a.policy == {"project_license": "Apache-2.0"}

    def test_license_database_contains_common_licenses(self):
        db = self.analyzer.license_database
        assert "MIT" in db
        assert "Apache-2.0" in db
        assert "BSD-3-Clause" in db
        assert "GPL-2.0" in db
        assert "GPL-3.0" in db
        assert "AGPL-3.0" in db
        assert "LGPL-2.1" in db
        assert "MPL-2.0" in db

    def test_license_database_types(self):
        db = self.analyzer.license_database
        assert db["MIT"]["type"] == LicenseType.PERMISSIVE
        assert db["GPL-3.0"]["type"] == LicenseType.STRONG_COPYLEFT
        assert db["LGPL-2.1"]["type"] == LicenseType.WEAK_COPYLEFT
        assert db["AGPL-3.0"]["risk"] == LicenseRisk.CRITICAL

    def test_compatibility_matrix_mit_compatible(self):
        matrix = self.analyzer.compatibility_matrix
        assert "Apache-2.0" in matrix["MIT"]
        assert "BSD-3-Clause" in matrix["MIT"]
        assert "LGPL-2.1" in matrix["MIT"]

    def test_analyze_permissive_packages(self):
        packages = [
            {"name": "flask", "license": "MIT"},
            {"name": "requests", "license": "Apache-2.0"},
        ]
        result = self.analyzer.analyze(packages)
        assert isinstance(result, LicenseComplianceResult)
        assert result.total_findings == 2
        assert all(f.risk_level == LicenseRisk.LOW for f in result.findings)

    def test_analyze_gpl_package(self):
        packages = [{"name": "gpl-lib", "license": "GPL-3.0"}]
        result = self.analyzer.analyze(packages)
        assert result.total_findings == 1
        finding = result.findings[0]
        assert finding.risk_level == LicenseRisk.HIGH
        assert finding.license_type == LicenseType.STRONG_COPYLEFT
        # GPL-3.0 is not compatible with default MIT project
        assert len(finding.compatibility_issues) > 0

    def test_analyze_agpl_blocked_by_default(self):
        packages = [{"name": "agpl-lib", "license": "AGPL-3.0"}]
        result = self.analyzer.analyze(packages)
        assert result.total_findings == 1
        finding = result.findings[0]
        assert finding.risk_level == LicenseRisk.CRITICAL
        assert "AGPL-3.0" in result.incompatible_licenses

    def test_analyze_unknown_license(self):
        packages = [{"name": "mystery-lib", "license": "UNKNOWN"}]
        result = self.analyzer.analyze(packages)
        assert result.total_findings == 1
        finding = result.findings[0]
        assert finding.license_type == LicenseType.UNKNOWN
        assert finding.risk_level == LicenseRisk.MEDIUM

    def test_analyze_empty_packages(self):
        result = self.analyzer.analyze([])
        assert result.total_findings == 0
        assert result.findings == []

    def test_analyze_findings_by_risk(self):
        packages = [
            {"name": "a", "license": "MIT"},
            {"name": "b", "license": "GPL-3.0"},
            {"name": "c", "license": "Apache-2.0"},
        ]
        result = self.analyzer.analyze(packages)
        assert "low" in result.findings_by_risk
        assert "high" in result.findings_by_risk

    def test_analyze_findings_by_type(self):
        packages = [
            {"name": "a", "license": "MIT"},
            {"name": "b", "license": "GPL-3.0"},
        ]
        result = self.analyzer.analyze(packages)
        assert "permissive" in result.findings_by_type
        assert "strong_copyleft" in result.findings_by_type

    def test_analyze_with_custom_project_license(self):
        analyzer = LicenseComplianceAnalyzer(config={"policy": {"project_license": "GPL-3.0"}})
        # Use a license that is genuinely incompatible with GPL-3.0
        packages = [{"name": "proprietary-lib", "license": "SSPL-1.0"}]
        result = analyzer.analyze(packages)
        finding = result.findings[0]
        assert len(finding.compatibility_issues) > 0

    def test_analyze_with_allowed_licenses(self):
        analyzer = LicenseComplianceAnalyzer(config={"policy": {"allowed_licenses": ["MIT", "Apache-2.0"]}})
        packages = [
            {"name": "ok-lib", "license": "MIT"},
            {"name": "not-allowed", "license": "BSD-3-Clause"},
        ]
        result = analyzer.analyze(packages)
        bsd_finding = [f for f in result.findings if f.package_name == "not-allowed"][0]
        assert "Not in allowed licenses list" in bsd_finding.compatibility_issues

    def test_analyze_with_blocked_licenses(self):
        analyzer = LicenseComplianceAnalyzer(config={"policy": {"blocked_licenses": ["GPL-3.0", "AGPL-3.0"]}})
        packages = [{"name": "gpl-lib", "license": "GPL-3.0"}]
        result = analyzer.analyze(packages)
        assert result.findings[0].risk_level == LicenseRisk.CRITICAL
        assert "GPL-3.0" in result.incompatible_licenses

    def test_get_recommendation_critical(self):
        rec = self.analyzer._get_recommendation("AGPL-3.0", LicenseRisk.CRITICAL)
        assert "replace" in rec.lower() or "critical" in rec.lower()

    def test_get_recommendation_high(self):
        rec = self.analyzer._get_recommendation("GPL-3.0", LicenseRisk.HIGH)
        assert "Review" in rec

    def test_get_recommendation_medium(self):
        rec = self.analyzer._get_recommendation("LGPL-2.1", LicenseRisk.MEDIUM)
        assert "copyleft" in rec.lower() or "monitor" in rec.lower()

    def test_get_recommendation_low(self):
        rec = self.analyzer._get_recommendation("MIT", LicenseRisk.LOW)
        assert "safe" in rec.lower()

    def test_build_result(self):
        findings = [
            LicenseFinding(
                package_name="a",
                license_type=LicenseType.PERMISSIVE,
                license_name="MIT",
                risk_level=LicenseRisk.LOW,
            ),
            LicenseFinding(
                package_name="b",
                license_type=LicenseType.STRONG_COPYLEFT,
                license_name="GPL-3.0",
                risk_level=LicenseRisk.HIGH,
            ),
        ]
        result = self.analyzer._build_result(findings, ["GPL-3.0"])
        assert result.total_findings == 2
        assert result.findings_by_risk["low"] == 1
        assert result.findings_by_risk["high"] == 1
        assert result.findings_by_type["permissive"] == 1
        assert result.findings_by_type["strong_copyleft"] == 1
        assert "GPL-3.0" in result.incompatible_licenses

    def test_duplicate_incompatible_deduplicated(self):
        # When same blocked license appears multiple times
        analyzer = LicenseComplianceAnalyzer(config={"policy": {"blocked_licenses": ["GPL-3.0"]}})
        packages = [
            {"name": "lib1", "license": "GPL-3.0"},
            {"name": "lib2", "license": "GPL-3.0"},
        ]
        result = analyzer.analyze(packages)
        assert len(result.incompatible_licenses) == 1

    def test_missing_package_name(self):
        packages = [{"license": "MIT"}]
        result = self.analyzer.analyze(packages)
        assert result.findings[0].package_name == "unknown"

    def test_missing_license(self):
        packages = [{"name": "noinfo"}]
        result = self.analyzer.analyze(packages)
        finding = result.findings[0]
        assert finding.license_name == "UNKNOWN"
        assert finding.license_type == LicenseType.UNKNOWN
