"""Unit tests for ALdeci Supply Chain Security Engine."""

from __future__ import annotations

import pytest

from core.supply_chain_engine import (
    SupplyChainEngine,
    SupplyChainRiskCategory,
    SupplyChainRiskLevel,
    SupplyChainAnalysisResult,
    SupplyChainFinding,
    PackageRiskScore,
    levenshtein_distance,
    get_supply_chain_engine,
    KNOWN_NPM_PACKAGES,
    KNOWN_PYPI_PACKAGES,
)


# ── Levenshtein Distance Tests ────────────────────────────────────


class TestLevenshteinDistance:
    def test_identical(self):
        assert levenshtein_distance("hello", "hello") == 0

    def test_empty_strings(self):
        assert levenshtein_distance("", "") == 0

    def test_one_empty(self):
        assert levenshtein_distance("abc", "") == 3
        assert levenshtein_distance("", "abc") == 3

    def test_one_char_diff(self):
        assert levenshtein_distance("lodash", "1odash") == 1

    def test_two_char_diff(self):
        assert levenshtein_distance("express", "exprass") == 1

    def test_substitution(self):
        assert levenshtein_distance("kitten", "sitting") == 3

    def test_symmetry(self):
        assert levenshtein_distance("abc", "xyz") == levenshtein_distance("xyz", "abc")


# ── Typosquatting Detection Tests ─────────────────────────────────


class TestTyposquatting:
    def test_exact_known_package_no_finding(self):
        engine = SupplyChainEngine()
        findings = engine._check_typosquatting("lodash", "npm")
        assert len(findings) == 0

    def test_one_char_typosquat_npm(self):
        engine = SupplyChainEngine(typosquat_threshold=2)
        findings = engine._check_typosquatting("1odash", "npm")
        assert len(findings) >= 1
        assert any(f.category == SupplyChainRiskCategory.TYPOSQUATTING for f in findings)
        assert any("lodash" in f.title for f in findings)

    def test_two_char_typosquat(self):
        engine = SupplyChainEngine(typosquat_threshold=2)
        findings = engine._check_typosquatting("reqeusts", "pypi")
        assert len(findings) >= 1

    def test_no_typosquat_for_distant_name(self):
        engine = SupplyChainEngine(typosquat_threshold=2)
        findings = engine._check_typosquatting("totally-unique-pkg-xyz", "npm")
        assert len(findings) == 0

    def test_unknown_pm_no_findings(self):
        engine = SupplyChainEngine()
        findings = engine._check_typosquatting("anything", "cargo")
        assert len(findings) == 0


# ── Known Malicious Detection ────────────────────────────────────


class TestKnownMalicious:
    def test_malicious_pattern_match(self):
        engine = SupplyChainEngine()
        findings = engine._check_known_malicious("flatmap-stream", "1.0.0", "npm")
        assert len(findings) == 1
        assert findings[0].risk_level == SupplyChainRiskLevel.CRITICAL

    def test_backdoor_pattern(self):
        engine = SupplyChainEngine()
        findings = engine._check_known_malicious("my-backdoor-lib", "0.1", "npm")
        assert len(findings) == 1

    def test_clean_package(self):
        engine = SupplyChainEngine()
        findings = engine._check_known_malicious("my-cool-lib", "1.0", "npm")
        assert len(findings) == 0


# ── Provenance Check ─────────────────────────────────────────────


class TestProvenance:
    def test_no_provenance(self):
        engine = SupplyChainEngine()
        findings = engine._check_provenance("pkg", "1.0", "npm", {"has_provenance": False})
        assert len(findings) == 1
        assert findings[0].category == SupplyChainRiskCategory.PROVENANCE

    def test_has_provenance(self):
        engine = SupplyChainEngine()
        findings = engine._check_provenance("pkg", "1.0", "npm", {"has_provenance": True})
        assert len(findings) == 0

    def test_unknown_provenance(self):
        engine = SupplyChainEngine()
        findings = engine._check_provenance("pkg", "1.0", "npm", {})
        assert len(findings) == 0


# ── Health Check ─────────────────────────────────────────────────


class TestHealth:
    def test_new_package(self):
        engine = SupplyChainEngine(min_age_days=30)
        findings = engine._check_health("new-pkg", "0.1", "npm", {"age_days": 5})
        assert any(f.category == SupplyChainRiskCategory.PACKAGE_AGE for f in findings)

    def test_old_enough_package(self):
        engine = SupplyChainEngine(min_age_days=30)
        findings = engine._check_health("pkg", "1.0", "npm", {"age_days": 365})
        age_findings = [f for f in findings if f.category == SupplyChainRiskCategory.PACKAGE_AGE]
        assert len(age_findings) == 0

    def test_low_downloads(self):
        engine = SupplyChainEngine(min_downloads=100)
        findings = engine._check_health("pkg", "1.0", "npm", {"download_count": 10})
        assert any(f.category == SupplyChainRiskCategory.POPULARITY for f in findings)

    def test_abandoned(self):
        engine = SupplyChainEngine()
        findings = engine._check_health("pkg", "1.0", "npm", {"last_update_days": 800})
        assert any(f.category == SupplyChainRiskCategory.ABANDONED for f in findings)


# ── Full Analysis Tests ──────────────────────────────────────────


class TestAnalyzePackages:
    def test_clean_packages(self):
        engine = SupplyChainEngine()
        result = engine.analyze_packages([
            {"name": "lodash", "version": "4.17.21", "package_manager": "npm"},
            {"name": "requests", "version": "2.31.0", "package_manager": "pypi"},
        ])
        assert isinstance(result, SupplyChainAnalysisResult)
        assert result.total_packages == 2
        assert result.packages_analyzed == 2
        assert result.duration_ms > 0

    def test_risky_packages(self):
        engine = SupplyChainEngine()
        result = engine.analyze_packages([
            {"name": "1odash", "version": "0.0.1", "package_manager": "npm", "age_days": 2, "download_count": 5},
        ])
        assert len(result.findings) > 0
        # Should have typosquatting + age + popularity findings
        categories = {f.category for f in result.findings}
        assert SupplyChainRiskCategory.TYPOSQUATTING in categories

    def test_result_to_dict(self):
        engine = SupplyChainEngine()
        result = engine.analyze_packages([
            {"name": "lodash", "version": "4.17.21", "package_manager": "npm"},
        ])
        d = result.to_dict()
        assert "analysis_id" in d
        assert "total_packages" in d
        assert "risk_scores" in d
        assert "findings" in d
        assert "duration_ms" in d

    def test_risk_score_calculation(self):
        engine = SupplyChainEngine()
        result = engine.analyze_packages([
            {"name": "lodash", "version": "4.17.21", "package_manager": "npm"},
        ])
        score = result.risk_scores[0]
        assert score.overall_score == 100.0  # Known good, no risk signals

    def test_risk_score_with_findings(self):
        engine = SupplyChainEngine()
        result = engine.analyze_packages([
            {
                "name": "1odash",
                "version": "0.0.1",
                "package_manager": "npm",
                "age_days": 2,
                "download_count": 5,
                "has_provenance": False,
                "maintainer_count": 1,
            },
        ])
        score = result.risk_scores[0]
        assert score.overall_score < 100.0
        assert score.typosquatting_score < 100.0


class TestAnalyzeSBOM:
    def test_cyclonedx_sbom(self):
        engine = SupplyChainEngine()
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {"name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"},
                {"name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"},
            ],
        }
        result = engine.analyze_sbom(sbom)
        assert result.total_packages == 2
        assert result.packages_analyzed == 2

    def test_spdx_sbom(self):
        engine = SupplyChainEngine()
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {"name": "express", "version": "4.18.2", "purl": "pkg:npm/express@4.18.2"},
            ],
        }
        result = engine.analyze_sbom(sbom)
        assert result.total_packages == 1

    def test_empty_sbom(self):
        engine = SupplyChainEngine()
        result = engine.analyze_sbom({"components": []})
        assert result.total_packages == 0


class TestSingleton:
    def test_singleton(self):
        e1 = get_supply_chain_engine()
        e2 = get_supply_chain_engine()
        assert e1 is e2


class TestDataclasses:
    def test_finding_to_dict(self):
        f = SupplyChainFinding(
            finding_id="SC-abc",
            package_name="test",
            package_version="1.0",
            package_manager="npm",
            risk_level=SupplyChainRiskLevel.HIGH,
            category=SupplyChainRiskCategory.TYPOSQUATTING,
            title="Test finding",
        )
        d = f.to_dict()
        assert d["risk_level"] == "high"
        assert d["category"] == "typosquatting"

    def test_risk_score_to_dict(self):
        score = PackageRiskScore(
            package_name="test",
            package_version="1.0",
            package_manager="npm",
        )
        d = score.to_dict()
        assert d["overall_score"] == 100.0
        assert d["findings_count"] == 0

class TestMaintainer:
    def test_single_maintainer(self):
        engine = SupplyChainEngine()
        findings = engine._check_maintainer("pkg", "1.0", "npm", {"maintainer_count": 1})
        assert any(f.category == SupplyChainRiskCategory.MAINTAINER for f in findings)

    def test_ownership_transfer(self):
        engine = SupplyChainEngine()
        findings = engine._check_maintainer("pkg", "1.0", "npm", {"ownership_changed": True})
        assert any(f.category == SupplyChainRiskCategory.OWNERSHIP_TRANSFER for f in findings)
        assert any(f.risk_level == SupplyChainRiskLevel.HIGH for f in findings)

