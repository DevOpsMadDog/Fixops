"""
Tests for ALdeci Anomaly Detection Engine.

[V3] Decision Intelligence — Validates scan anomaly detection.

Tests cover:
1. Scan feature extraction
2. Baseline fitting (historical and synthetic)
3. Normal scan detection (should NOT be anomalous)
4. Anomalous scan detection (spikes, new categories)
5. Baseline updates (streaming)
6. Heuristic detection (when no baseline fitted)
7. Edge cases (empty scans, single finding)
"""

import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.ml.anomaly_detector import (
    SCAN_FEATURE_NAMES,
    AnomalyDetector,
    AnomalyResult,
    extract_scan_features,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def normal_findings():
    """Typical enterprise scan findings."""
    return [
        {
            "severity": "medium",
            "cvss_score": 5.0,
            "epss_score": 0.05,
            "in_kev": False,
            "cve_id": f"CVE-2023-{i}",
            "exploit_available": False,
            "network_exposure": "internal",
            "asset_name": f"app-{i % 5}",
        }
        for i in range(25)
    ]


@pytest.fixture
def anomalous_findings():
    """Clearly anomalous scan — all critical, all KEV."""
    return [
        {
            "severity": "critical",
            "cvss_score": 9.8,
            "epss_score": 0.95,
            "in_kev": True,
            "cve_id": f"CVE-2024-{i}",
            "exploit_available": True,
            "network_exposure": "internet",
            "asset_name": f"asset-{i}",
        }
        for i in range(200)
    ]


@pytest.fixture
def fitted_detector():
    """An anomaly detector fitted with synthetic baseline."""
    det = AnomalyDetector(random_seed=42)
    det.fit_from_synthetic_baseline(n_scans=50)
    return det


# ---------------------------------------------------------------------------
# Feature extraction tests
# ---------------------------------------------------------------------------

class TestScanFeatureExtraction:
    """Test extraction of scan-level features."""

    def test_feature_shape(self, normal_findings):
        features = extract_scan_features(normal_findings)
        assert features.shape == (len(SCAN_FEATURE_NAMES),)

    def test_empty_scan(self):
        features = extract_scan_features([])
        assert features.shape == (len(SCAN_FEATURE_NAMES),)
        assert np.all(features == 0)

    def test_finding_count(self, normal_findings):
        features = extract_scan_features(normal_findings)
        assert features[0] == 25  # finding_count

    def test_severity_ratios_sum_approximately_one(self, normal_findings):
        features = extract_scan_features(normal_findings)
        # critical + high + medium + low (indices 1-4)
        total = features[1] + features[2] + features[3] + features[4]
        assert total == pytest.approx(1.0, abs=0.01)

    def test_kev_ratio(self, anomalous_findings):
        features = extract_scan_features(anomalous_findings)
        assert features[6] == pytest.approx(1.0, abs=0.01)  # All KEV

    def test_unique_assets(self, normal_findings):
        features = extract_scan_features(normal_findings)
        assert features[11] == 5  # 5 unique assets (app-0 to app-4)


# ---------------------------------------------------------------------------
# Baseline fitting tests
# ---------------------------------------------------------------------------

class TestBaselineFitting:
    """Test baseline fitting from historical data."""

    def test_fit_from_synthetic(self):
        det = AnomalyDetector(random_seed=42)
        stats = det.fit_from_synthetic_baseline(n_scans=30)
        assert det.is_fitted
        assert "scans_fitted" in stats
        assert stats["scans_fitted"] == 30

    def test_fit_from_historical(self, normal_findings):
        det = AnomalyDetector(random_seed=42)
        historical = [normal_findings] * 10
        det.fit_baseline(historical)
        assert det.is_fitted

    def test_fit_too_few_scans(self, normal_findings):
        det = AnomalyDetector()
        with pytest.raises(ValueError, match="at least 3"):
            det.fit_baseline([normal_findings])


# ---------------------------------------------------------------------------
# Detection tests
# ---------------------------------------------------------------------------

class TestDetection:
    """Test anomaly detection."""

    def test_anomalous_scan_detected(self, fitted_detector, anomalous_findings):
        result = fitted_detector.detect(anomalous_findings)
        assert isinstance(result, AnomalyResult)
        assert result.is_anomalous is True
        assert len(result.anomaly_reasons) > 0

    def test_detection_returns_result(self, fitted_detector, normal_findings):
        result = fitted_detector.detect(normal_findings)
        assert isinstance(result, AnomalyResult)

    def test_anomaly_has_score(self, fitted_detector, anomalous_findings):
        result = fitted_detector.detect(anomalous_findings)
        assert isinstance(result.anomaly_score, float)

    def test_anomaly_has_reasons(self, fitted_detector, anomalous_findings):
        result = fitted_detector.detect(anomalous_findings)
        assert len(result.anomaly_reasons) > 0

    def test_anomaly_has_deviations(self, fitted_detector, anomalous_findings):
        result = fitted_detector.detect(anomalous_findings)
        assert len(result.feature_deviations) == len(SCAN_FEATURE_NAMES)

    def test_to_dict(self, fitted_detector, anomalous_findings):
        result = fitted_detector.detect(anomalous_findings)
        d = result.to_dict()
        assert "is_anomalous" in d
        assert "anomaly_score" in d
        assert "anomaly_reasons" in d

    def test_detection_time_fast(self, fitted_detector, normal_findings):
        result = fitted_detector.detect(normal_findings)
        assert result.detection_time_ms < 100


# ---------------------------------------------------------------------------
# Heuristic detection tests
# ---------------------------------------------------------------------------

class TestHeuristicDetection:
    """Test heuristic detection when no baseline is fitted."""

    def test_unfitted_heuristic(self, anomalous_findings):
        det = AnomalyDetector()
        result = det.detect(anomalous_findings)
        assert result.is_anomalous is True
        assert len(result.anomaly_reasons) > 0

    def test_unfitted_normal_scan(self, normal_findings):
        det = AnomalyDetector()
        result = det.detect(normal_findings)
        # Normal scan should not trigger heuristics
        assert result.is_anomalous is False


# ---------------------------------------------------------------------------
# Baseline update tests
# ---------------------------------------------------------------------------

class TestBaselineUpdate:
    """Test streaming baseline updates."""

    def test_update_doesnt_crash(self, fitted_detector, normal_findings):
        fitted_detector.update_baseline(normal_findings)

    def test_update_adds_to_history(self, fitted_detector, normal_findings):
        initial_count = len(fitted_detector._baseline_features)
        fitted_detector.update_baseline(normal_findings)
        assert len(fitted_detector._baseline_features) == initial_count + 1
