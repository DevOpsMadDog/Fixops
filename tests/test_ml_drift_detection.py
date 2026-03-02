"""
Tests for scan-over-scan drift detection in anomaly detector.

[V3] Decision Intelligence — validates that detect_drift() correctly
identifies regressions, improvements, and stability in scan results.

Tests cover:
  - Regression detection (new findings, severity upgrades)
  - Improvement detection (resolved findings)
  - Stable detection (no changes)
  - Severity change tracking
  - Feature delta computation
  - DriftResult serialization
"""

import json
import sys

import pytest

sys.path.insert(0, ".")

from core.ml.anomaly_detector import AnomalyDetector, DriftResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def detector():
    return AnomalyDetector()


@pytest.fixture
def baseline_scan():
    return [
        {"title": "SQL Injection", "severity": "critical", "cve_id": "CVE-2023-001", "file_path": "app.py"},
        {"title": "XSS", "severity": "high", "cve_id": "CVE-2023-002", "file_path": "search.py"},
        {"title": "Open redirect", "severity": "medium", "cve_id": "CVE-2023-003", "url": "/redirect"},
        {"title": "Info disclosure", "severity": "low", "cve_id": "CVE-2023-004", "host": "api.example.com"},
        {"title": "Missing header", "severity": "low", "cve_id": "CVE-2023-005", "url": "/api"},
    ]


@pytest.fixture
def regressed_scan():
    """Scan with new critical findings and severity upgrades."""
    return [
        {"title": "SQL Injection", "severity": "critical", "cve_id": "CVE-2023-001", "file_path": "app.py"},
        {"title": "XSS", "severity": "critical", "cve_id": "CVE-2023-002", "file_path": "search.py"},  # Upgraded!
        {"title": "Open redirect", "severity": "medium", "cve_id": "CVE-2023-003", "url": "/redirect"},
        {"title": "RCE via deserialization", "severity": "critical", "cve_id": "CVE-2023-010", "file_path": "api.py"},  # New!
        {"title": "SSRF in proxy", "severity": "high", "cve_id": "CVE-2023-011", "url": "/proxy"},  # New!
        {"title": "Path traversal", "severity": "high", "cve_id": "CVE-2023-012", "file_path": "upload.py"},  # New!
    ]


@pytest.fixture
def improved_scan():
    """Scan with fewer findings — some resolved."""
    return [
        {"title": "Info disclosure", "severity": "low", "cve_id": "CVE-2023-004", "host": "api.example.com"},
        {"title": "Missing header", "severity": "low", "cve_id": "CVE-2023-005", "url": "/api"},
    ]


@pytest.fixture
def stable_scan():
    """Same scan, no changes."""
    return [
        {"title": "SQL Injection", "severity": "critical", "cve_id": "CVE-2023-001", "file_path": "app.py"},
        {"title": "XSS", "severity": "high", "cve_id": "CVE-2023-002", "file_path": "search.py"},
        {"title": "Open redirect", "severity": "medium", "cve_id": "CVE-2023-003", "url": "/redirect"},
        {"title": "Info disclosure", "severity": "low", "cve_id": "CVE-2023-004", "host": "api.example.com"},
        {"title": "Missing header", "severity": "low", "cve_id": "CVE-2023-005", "url": "/api"},
    ]


# ---------------------------------------------------------------------------
# Tests: Regression detection
# ---------------------------------------------------------------------------


class TestRegressionDetection:
    def test_detects_regression(self, detector, regressed_scan, baseline_scan):
        result = detector.detect_drift(regressed_scan, baseline_scan)
        assert isinstance(result, DriftResult)
        assert result.drift_type == "regression"

    def test_new_findings_counted(self, detector, regressed_scan, baseline_scan):
        result = detector.detect_drift(regressed_scan, baseline_scan)
        assert result.new_findings_count >= 2  # At least CVE-010 and CVE-011

    def test_is_regression_property(self, detector, regressed_scan, baseline_scan):
        result = detector.detect_drift(regressed_scan, baseline_scan)
        assert result.is_regression is True
        assert result.is_improvement is False

    def test_severity_changes_tracked(self, detector, regressed_scan, baseline_scan):
        result = detector.detect_drift(regressed_scan, baseline_scan)
        # CVE-2023-002 was upgraded from high to critical
        upgraded = [sc for sc in result.severity_changes if sc["direction"] == "upgraded"]
        assert len(upgraded) >= 1

    def test_net_change_positive(self, detector, regressed_scan, baseline_scan):
        result = detector.detect_drift(regressed_scan, baseline_scan)
        assert result.net_change > 0  # More new than resolved


# ---------------------------------------------------------------------------
# Tests: Improvement detection
# ---------------------------------------------------------------------------


class TestImprovementDetection:
    def test_detects_improvement(self, detector, improved_scan, baseline_scan):
        result = detector.detect_drift(improved_scan, baseline_scan)
        assert result.drift_type == "improvement"

    def test_resolved_findings_counted(self, detector, improved_scan, baseline_scan):
        result = detector.detect_drift(improved_scan, baseline_scan)
        assert result.resolved_findings_count >= 2  # SQL Injection, XSS, Open redirect resolved

    def test_is_improvement_property(self, detector, improved_scan, baseline_scan):
        result = detector.detect_drift(improved_scan, baseline_scan)
        assert result.is_improvement is True
        assert result.is_regression is False

    def test_net_change_negative(self, detector, improved_scan, baseline_scan):
        result = detector.detect_drift(improved_scan, baseline_scan)
        assert result.net_change < 0  # More resolved than new


# ---------------------------------------------------------------------------
# Tests: Stable detection
# ---------------------------------------------------------------------------


class TestStableDetection:
    def test_detects_stable(self, detector, stable_scan, baseline_scan):
        result = detector.detect_drift(stable_scan, baseline_scan)
        assert result.drift_type == "stable"

    def test_no_new_findings(self, detector, stable_scan, baseline_scan):
        result = detector.detect_drift(stable_scan, baseline_scan)
        assert result.new_findings_count == 0

    def test_no_resolved_findings(self, detector, stable_scan, baseline_scan):
        result = detector.detect_drift(stable_scan, baseline_scan)
        assert result.resolved_findings_count == 0

    def test_all_persistent(self, detector, stable_scan, baseline_scan):
        result = detector.detect_drift(stable_scan, baseline_scan)
        assert result.persistent_findings_count == len(baseline_scan)

    def test_no_drift_alerts(self, detector, stable_scan, baseline_scan):
        result = detector.detect_drift(stable_scan, baseline_scan)
        assert len(result.drift_alerts) == 0


# ---------------------------------------------------------------------------
# Tests: Feature deltas
# ---------------------------------------------------------------------------


class TestFeatureDeltas:
    def test_feature_deltas_computed(self, detector, regressed_scan, baseline_scan):
        result = detector.detect_drift(regressed_scan, baseline_scan)
        assert "finding_count" in result.feature_deltas
        assert "critical_ratio" in result.feature_deltas

    def test_finding_count_delta(self, detector, regressed_scan, baseline_scan):
        result = detector.detect_drift(regressed_scan, baseline_scan)
        fc_delta = result.feature_deltas["finding_count"]
        assert fc_delta["current"] == len(regressed_scan)
        assert fc_delta["previous"] == len(baseline_scan)
        assert fc_delta["delta"] == len(regressed_scan) - len(baseline_scan)

    def test_critical_ratio_increases_on_regression(self, detector, regressed_scan, baseline_scan):
        result = detector.detect_drift(regressed_scan, baseline_scan)
        cr_delta = result.feature_deltas["critical_ratio"]
        assert cr_delta["current"] > cr_delta["previous"]


# ---------------------------------------------------------------------------
# Tests: Serialization
# ---------------------------------------------------------------------------


class TestDriftSerialization:
    def test_to_dict(self, detector, regressed_scan, baseline_scan):
        result = detector.detect_drift(regressed_scan, baseline_scan)
        d = result.to_dict()
        assert isinstance(d, dict)
        assert "drift_type" in d
        assert "new_findings_count" in d
        assert "resolved_findings_count" in d
        assert "feature_deltas" in d

    def test_json_serializable(self, detector, regressed_scan, baseline_scan):
        result = detector.detect_drift(regressed_scan, baseline_scan)
        d = result.to_dict()
        json_str = json.dumps(d)
        parsed = json.loads(json_str)
        assert parsed["drift_type"] == d["drift_type"]

    def test_detection_time_recorded(self, detector, regressed_scan, baseline_scan):
        result = detector.detect_drift(regressed_scan, baseline_scan)
        assert result.detection_time_ms > 0
        assert result.detection_time_ms < 100  # Should be fast


# ---------------------------------------------------------------------------
# Tests: Edge cases
# ---------------------------------------------------------------------------


class TestDriftEdgeCases:
    def test_empty_current_scan(self, detector, baseline_scan):
        result = detector.detect_drift([], baseline_scan)
        assert result.drift_type == "improvement"
        assert result.resolved_findings_count == len(baseline_scan)

    def test_empty_previous_scan(self, detector, baseline_scan):
        result = detector.detect_drift(baseline_scan, [])
        assert result.new_findings_count == len(baseline_scan)

    def test_both_empty(self, detector):
        result = detector.detect_drift([], [])
        assert result.drift_type == "stable"
