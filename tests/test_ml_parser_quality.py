"""
Tests for scanner parser data quality validator.

[V7] MCP-Native Platform — validates that ParserQualityValidator correctly
identifies data quality issues in normalized scanner findings.

Tests cover:
  - Required field validation
  - Severity value validation
  - Distribution anomaly detection
  - CVE/CWE format validation
  - Field completeness computation
  - Quality score calculation
  - Batch validation
  - Report generation
"""

import json
import sys

import pytest

sys.path.insert(0, ".")

from core.ml.parser_quality import (
    ParserQualityResult,
    ParserQualityValidator,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def validator():
    return ParserQualityValidator()


@pytest.fixture
def strict_validator():
    return ParserQualityValidator(strict=True)


@pytest.fixture
def good_sast_findings():
    """Well-formed SAST findings with good coverage."""
    return [
        {"title": "SQL Injection in login.py", "severity": "critical", "cve_id": "CVE-2023-12345", "cwe_id": "CWE-89", "description": "SQL injection via user input", "scanner_source": "bandit", "finding_type": "sast", "file_path": "src/login.py"},
        {"title": "XSS in search.py", "severity": "high", "cve_id": "CVE-2023-12346", "cwe_id": "CWE-79", "description": "Cross-site scripting", "scanner_source": "bandit", "finding_type": "sast", "file_path": "src/search.py"},
        {"title": "Hardcoded password", "severity": "medium", "cwe_id": "CWE-798", "description": "Password found in source", "scanner_source": "bandit", "finding_type": "sast", "file_path": "src/config.py"},
        {"title": "Missing input validation", "severity": "medium", "cwe_id": "CWE-20", "description": "No input validation", "scanner_source": "bandit", "finding_type": "sast", "file_path": "src/api.py"},
        {"title": "Debug mode enabled", "severity": "low", "description": "Debug flag in production", "scanner_source": "bandit", "finding_type": "sast", "file_path": "src/app.py"},
        {"title": "Unused import", "severity": "low", "description": "Unused module import", "scanner_source": "bandit", "finding_type": "sast", "file_path": "src/utils.py"},
        {"title": "Print statement", "severity": "info", "description": "Print found in production code", "scanner_source": "bandit", "finding_type": "sast", "file_path": "src/debug.py"},
    ]


@pytest.fixture
def bad_findings():
    """Poorly formed findings with issues."""
    return [
        {},  # Empty
        {"severity": "INVALID"},  # No title, invalid severity
        {"title": "Something"},  # No severity
        {"title": "OK", "severity": "medium", "cve_id": "not-a-cve"},  # Bad CVE
    ]


@pytest.fixture
def dast_findings():
    """DAST scanner findings."""
    return [
        {"title": "Reflected XSS", "severity": "high", "cve_id": "CVE-2024-001", "description": "XSS via parameter", "scanner_source": "zap", "finding_type": "dast", "url": "https://example.com/search"},
        {"title": "Missing HSTS", "severity": "medium", "description": "No HSTS header", "scanner_source": "zap", "finding_type": "dast", "url": "https://example.com"},
        {"title": "Cookie no HttpOnly", "severity": "medium", "description": "Cookie missing HttpOnly", "scanner_source": "zap", "finding_type": "dast", "url": "https://example.com/login"},
        {"title": "Server info leak", "severity": "low", "description": "Server header exposed", "scanner_source": "zap", "finding_type": "dast", "url": "https://example.com"},
        {"title": "Content-Type missing", "severity": "low", "description": "Missing content type", "scanner_source": "zap", "finding_type": "dast", "url": "https://example.com/api"},
    ]


# ---------------------------------------------------------------------------
# Tests: Basic validation
# ---------------------------------------------------------------------------


class TestBasicValidation:
    def test_good_findings_pass(self, validator, good_sast_findings):
        result = validator.validate_findings(good_sast_findings, "bandit")
        assert isinstance(result, ParserQualityResult)
        assert result.passes is True

    def test_empty_findings_pass(self, validator):
        result = validator.validate_findings([], "zap")
        assert result.passes is True
        assert result.total_findings == 0
        assert result.quality_score == 100.0

    def test_scanner_type_captured(self, validator, good_sast_findings):
        result = validator.validate_findings(good_sast_findings, "bandit")
        assert result.scanner_type == "bandit"
        assert result.scanner_category == "sast"

    def test_dast_category_detected(self, validator, dast_findings):
        result = validator.validate_findings(dast_findings, "zap")
        assert result.scanner_category == "dast"


# ---------------------------------------------------------------------------
# Tests: Required field validation
# ---------------------------------------------------------------------------


class TestRequiredFields:
    def test_missing_title_is_error(self, validator, bad_findings):
        result = validator.validate_findings(bad_findings, "unknown")
        errors = [i for i in result.issues if i.category == "missing_field" and "title" in i.message]
        assert len(errors) >= 1

    def test_missing_severity_is_error(self, validator, bad_findings):
        result = validator.validate_findings(bad_findings, "unknown")
        errors = [i for i in result.issues if i.category == "missing_field" and "severity" in i.message]
        assert len(errors) >= 1

    def test_bad_findings_fail(self, validator, bad_findings):
        result = validator.validate_findings(bad_findings, "unknown")
        assert result.passes is False
        assert result.error_count >= 1


# ---------------------------------------------------------------------------
# Tests: Severity validation
# ---------------------------------------------------------------------------


class TestSeverityValidation:
    def test_invalid_severity_detected(self, validator):
        findings = [{"title": "Test", "severity": "INVALID"}]
        result = validator.validate_findings(findings, "test")
        errors = [i for i in result.issues if i.category == "invalid_severity"]
        assert len(errors) >= 1

    def test_valid_severities_accepted(self, validator):
        findings = [
            {"title": f"Test {s}", "severity": s}
            for s in ["critical", "high", "medium", "low", "info"]
        ]
        result = validator.validate_findings(findings, "test")
        sev_errors = [i for i in result.issues if i.category == "invalid_severity"]
        assert len(sev_errors) == 0


# ---------------------------------------------------------------------------
# Tests: Distribution checks
# ---------------------------------------------------------------------------


class TestDistribution:
    def test_severity_distribution_computed(self, validator, good_sast_findings):
        result = validator.validate_findings(good_sast_findings, "bandit")
        assert isinstance(result.severity_distribution, dict)
        assert sum(result.severity_distribution.values()) == pytest.approx(1.0, abs=0.01)

    def test_extreme_distribution_flagged(self, validator):
        """All critical findings should trigger distribution warning."""
        findings = [
            {"title": f"Critical {i}", "severity": "critical"}
            for i in range(10)
        ]
        result = validator.validate_findings(findings, "bandit")
        dist_issues = [i for i in result.issues if i.category == "distribution_anomaly"]
        assert len(dist_issues) >= 1  # Should flag abnormal distribution

    def test_strict_mode_elevates_to_error(self, strict_validator):
        findings = [
            {"title": f"Critical {i}", "severity": "critical"}
            for i in range(10)
        ]
        result = strict_validator.validate_findings(findings, "bandit")
        dist_errors = [
            i for i in result.issues
            if i.category == "distribution_anomaly" and i.severity == "error"
        ]
        assert len(dist_errors) >= 1


# ---------------------------------------------------------------------------
# Tests: Identifier validation
# ---------------------------------------------------------------------------


class TestIdentifiers:
    def test_valid_cve_accepted(self, validator):
        findings = [{"title": "Test", "severity": "high", "cve_id": "CVE-2023-12345"}]
        result = validator.validate_findings(findings, "test")
        cve_issues = [i for i in result.issues if i.category == "malformed_cve"]
        assert len(cve_issues) == 0

    def test_malformed_cve_flagged(self, validator):
        findings = [{"title": "Test", "severity": "high", "cve_id": "not-a-cve"}]
        result = validator.validate_findings(findings, "test")
        cve_issues = [i for i in result.issues if i.category == "malformed_cve"]
        assert len(cve_issues) >= 1

    def test_cve_coverage_computed(self, validator, good_sast_findings):
        result = validator.validate_findings(good_sast_findings, "bandit")
        assert 0 <= result.cve_coverage <= 1.0

    def test_cwe_coverage_computed(self, validator, good_sast_findings):
        result = validator.validate_findings(good_sast_findings, "bandit")
        assert 0 <= result.cwe_coverage <= 1.0


# ---------------------------------------------------------------------------
# Tests: Quality score
# ---------------------------------------------------------------------------


class TestQualityScore:
    def test_good_findings_high_score(self, validator, good_sast_findings):
        result = validator.validate_findings(good_sast_findings, "bandit")
        assert result.quality_score >= 80  # Good findings should score well

    def test_bad_findings_low_score(self, validator, bad_findings):
        result = validator.validate_findings(bad_findings, "unknown")
        assert result.quality_score < 70  # Bad findings should score low

    def test_score_bounded_0_100(self, validator, good_sast_findings):
        result = validator.validate_findings(good_sast_findings, "bandit")
        assert 0 <= result.quality_score <= 100


# ---------------------------------------------------------------------------
# Tests: Batch validation and reports
# ---------------------------------------------------------------------------


class TestBatchValidation:
    def test_batch_validation(self, validator, good_sast_findings, dast_findings):
        results = validator.validate_batch({
            "bandit": good_sast_findings,
            "zap": dast_findings,
        })
        assert len(results) == 2
        assert "bandit" in results
        assert "zap" in results

    def test_quality_report(self, validator, good_sast_findings, dast_findings):
        results = validator.validate_batch({
            "bandit": good_sast_findings,
            "zap": dast_findings,
        })
        report = validator.generate_quality_report(results)
        assert isinstance(report, dict)
        assert "overall_pass" in report
        assert "total_scanners" in report
        assert "total_findings" in report
        assert report["total_scanners"] == 2
        assert report["total_findings"] == len(good_sast_findings) + len(dast_findings)


# ---------------------------------------------------------------------------
# Tests: Serialization
# ---------------------------------------------------------------------------


class TestSerialization:
    def test_result_to_dict(self, validator, good_sast_findings):
        result = validator.validate_findings(good_sast_findings, "bandit")
        d = result.to_dict()
        assert isinstance(d, dict)
        assert "quality_score" in d
        assert "severity_distribution" in d

    def test_result_json_serializable(self, validator, good_sast_findings):
        result = validator.validate_findings(good_sast_findings, "bandit")
        d = result.to_dict()
        json_str = json.dumps(d)
        parsed = json.loads(json_str)
        assert parsed["scanner_type"] == "bandit"

    def test_issue_to_dict(self, validator, bad_findings):
        result = validator.validate_findings(bad_findings, "unknown")
        if result.issues:
            issue_dict = result.issues[0].to_dict()
            assert "severity" in issue_dict
            assert "message" in issue_dict
