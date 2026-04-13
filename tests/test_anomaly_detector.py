"""
Tests for AnomalyDetector engine and anomaly_router.

Covers:
- AnomalyDetector: record_metric, detect_spike, detect_drop, detect_drift,
  get_anomalies, acknowledge_anomaly, get_baseline, get_anomaly_stats,
  detect_anomalies (full scan)
- anomaly_router: all 8 endpoints via FastAPI TestClient

30+ tests total.
"""

from __future__ import annotations

import sys
import os
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Generator

import pytest

# Ensure suite-core and suite-api are importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))

from core.anomaly_detector import (
    Anomaly,
    AnomalyDetector,
    AnomalySeverity,
    AnomalyStats,
    AnomalyType,
    BaselineStats,
)


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def tmp_db(tmp_path) -> str:
    """Return a path to a fresh temporary SQLite database."""
    return str(tmp_path / "test_anomaly.db")


@pytest.fixture
def detector(tmp_db: str) -> AnomalyDetector:
    """AnomalyDetector backed by a temp SQLite database."""
    return AnomalyDetector(db_path=tmp_db, org_id="test-org")


def _record_many(det: AnomalyDetector, name: str, values: list, org: str = "test-org") -> None:
    """Helper: record a list of values as metric data points."""
    for v in values:
        det.record_metric(name=name, value=v, org_id=org)


# ============================================================================
# UNIT TESTS — AnomalyDetector
# ============================================================================


class TestRecordMetric:
    def test_record_returns_row_id(self, detector: AnomalyDetector) -> None:
        row_id = detector.record_metric("cpu", 42.0)
        assert isinstance(row_id, int)
        assert row_id > 0

    def test_record_multiple_increments(self, detector: AnomalyDetector) -> None:
        id1 = detector.record_metric("mem", 10.0)
        id2 = detector.record_metric("mem", 20.0)
        assert id2 > id1

    def test_record_different_orgs_isolated(self, detector: AnomalyDetector) -> None:
        detector.record_metric("cpu", 100.0, org_id="org-a")
        detector.record_metric("cpu", 1.0, org_id="org-b")
        baseline_a = detector.get_baseline("cpu", org_id="org-a")
        baseline_b = detector.get_baseline("cpu", org_id="org-b")
        # Both should be None (only 1 point each — need >= 2)
        assert baseline_a is None
        assert baseline_b is None

    def test_record_with_explicit_org(self, detector: AnomalyDetector) -> None:
        row_id = detector.record_metric("latency", 5.5, org_id="custom-org")
        assert row_id > 0


class TestGetBaseline:
    def test_baseline_none_with_single_point(self, detector: AnomalyDetector) -> None:
        detector.record_metric("x", 50.0)
        result = detector.get_baseline("x")
        assert result is None

    def test_baseline_computed_with_multiple_points(self, detector: AnomalyDetector) -> None:
        _record_many(detector, "x", [10.0, 20.0, 30.0, 40.0, 50.0])
        result = detector.get_baseline("x")
        assert result is not None
        assert isinstance(result, BaselineStats)
        assert result.mean == pytest.approx(30.0)
        assert result.min_value == 10.0
        assert result.max_value == 50.0
        assert result.sample_count == 5

    def test_baseline_std_dev_nonzero(self, detector: AnomalyDetector) -> None:
        _record_many(detector, "y", [1.0, 2.0, 3.0, 4.0, 5.0])
        result = detector.get_baseline("y")
        assert result is not None
        assert result.std_dev > 0

    def test_baseline_respects_org(self, detector: AnomalyDetector) -> None:
        _record_many(detector, "z", [1.0, 2.0], org="org-a")
        result = detector.get_baseline("z", org_id="org-b")
        assert result is None  # org-b has no data


class TestDetectSpike:
    def test_spike_detected_on_large_increase(self, detector: AnomalyDetector) -> None:
        # Baseline of ~10, then spike to 500
        _record_many(detector, "req_rate", [10.0, 10.5, 9.5, 10.2, 9.8])
        detector.record_metric("req_rate", 500.0)
        anomalies = detector.detect_spike("req_rate", threshold_pct=100.0)
        assert len(anomalies) == 1
        assert anomalies[0].type == AnomalyType.SPIKE
        assert anomalies[0].actual_value == 500.0

    def test_spike_not_detected_within_threshold(self, detector: AnomalyDetector) -> None:
        _record_many(detector, "req_rate", [10.0, 11.0, 10.5, 10.8, 10.2])
        detector.record_metric("req_rate", 12.0)
        anomalies = detector.detect_spike("req_rate", threshold_pct=200.0)
        assert len(anomalies) == 0

    def test_spike_persisted_in_db(self, detector: AnomalyDetector) -> None:
        _record_many(detector, "errors", [1.0, 1.0, 1.0, 1.0])
        detector.record_metric("errors", 1000.0)
        detector.detect_spike("errors", threshold_pct=100.0)
        persisted = detector.get_anomalies()
        spikes = [a for a in persisted if a.type == AnomalyType.SPIKE]
        assert len(spikes) >= 1

    def test_spike_severity_high_on_large_deviation(self, detector: AnomalyDetector) -> None:
        _record_many(detector, "s", [1.0, 1.0, 1.0, 1.0, 1.0])
        detector.record_metric("s", 1000.0)
        anomalies = detector.detect_spike("s", threshold_pct=100.0)
        assert anomalies[0].severity in (AnomalySeverity.HIGH, AnomalySeverity.CRITICAL)

    def test_spike_no_data_returns_empty(self, detector: AnomalyDetector) -> None:
        result = detector.detect_spike("nonexistent_metric", threshold_pct=100.0)
        assert result == []


class TestDetectDrop:
    def test_drop_detected_on_large_decrease(self, detector: AnomalyDetector) -> None:
        _record_many(detector, "uptime", [100.0, 99.0, 100.0, 98.0, 99.5])
        detector.record_metric("uptime", 1.0)
        anomalies = detector.detect_drop("uptime", threshold_pct=50.0)
        assert len(anomalies) == 1
        assert anomalies[0].type == AnomalyType.DROP
        assert anomalies[0].deviation_pct < 0

    def test_drop_not_detected_within_threshold(self, detector: AnomalyDetector) -> None:
        _record_many(detector, "uptime", [100.0, 100.0, 100.0, 100.0])
        detector.record_metric("uptime", 95.0)
        anomalies = detector.detect_drop("uptime", threshold_pct=50.0)
        assert len(anomalies) == 0

    def test_drop_no_data_returns_empty(self, detector: AnomalyDetector) -> None:
        result = detector.detect_drop("no_metric", threshold_pct=50.0)
        assert result == []


class TestDetectDrift:
    def test_drift_detected_on_trend_change(self, detector: AnomalyDetector) -> None:
        # Simulate rising trend: first half ~10, second half ~50
        now = datetime.now(timezone.utc)
        for i in range(5):
            ts = now - timedelta(days=6 - i)
            detector.record_metric("throughput", 10.0, recorded_at=ts)
        for i in range(5):
            ts = now - timedelta(days=2 - i * 0.3)
            detector.record_metric("throughput", 50.0, recorded_at=ts)

        anomalies = detector.detect_drift("throughput", window_days=7)
        assert len(anomalies) == 1
        assert anomalies[0].type == AnomalyType.DRIFT

    def test_drift_not_detected_on_stable_metric(self, detector: AnomalyDetector) -> None:
        now = datetime.now(timezone.utc)
        for i in range(10):
            ts = now - timedelta(days=9 - i)
            detector.record_metric("stable", 42.0, recorded_at=ts)
        anomalies = detector.detect_drift("stable", window_days=7)
        assert len(anomalies) == 0

    def test_drift_no_data_returns_empty(self, detector: AnomalyDetector) -> None:
        result = detector.detect_drift("no_metric", window_days=7)
        assert result == []


class TestGetAnomalies:
    def test_get_returns_empty_initially(self, detector: AnomalyDetector) -> None:
        result = detector.get_anomalies()
        assert result == []

    def test_get_returns_persisted_anomalies(self, detector: AnomalyDetector) -> None:
        _record_many(detector, "cpu", [5.0, 5.0, 5.0, 5.0])
        detector.record_metric("cpu", 500.0)
        detector.detect_spike("cpu", threshold_pct=100.0)
        result = detector.get_anomalies()
        assert len(result) >= 1

    def test_severity_filter_high(self, detector: AnomalyDetector) -> None:
        _record_many(detector, "m", [1.0, 1.0, 1.0, 1.0])
        detector.record_metric("m", 10000.0)
        detector.detect_spike("m", threshold_pct=100.0)
        result = detector.get_anomalies(severity_filter=AnomalySeverity.CRITICAL)
        for a in result:
            assert a.severity == AnomalySeverity.CRITICAL

    def test_org_isolation(self, detector: AnomalyDetector) -> None:
        _record_many(detector, "cpu", [1.0, 1.0, 1.0, 1.0], org="org-x")
        detector.record_metric("cpu", 9999.0, org_id="org-x")
        detector.detect_spike("cpu", threshold_pct=100.0, org_id="org-x")
        result = detector.get_anomalies(org_id="org-y")
        assert result == []


class TestAcknowledgeAnomaly:
    def test_acknowledge_returns_true(self, detector: AnomalyDetector) -> None:
        _record_many(detector, "net", [1.0, 1.0, 1.0, 1.0])
        detector.record_metric("net", 5000.0)
        anomalies = detector.detect_spike("net", threshold_pct=100.0)
        assert len(anomalies) == 1
        result = detector.acknowledge_anomaly(anomalies[0].id)
        assert result is True

    def test_acknowledge_idempotent_returns_false(self, detector: AnomalyDetector) -> None:
        _record_many(detector, "net2", [1.0, 1.0, 1.0, 1.0])
        detector.record_metric("net2", 5000.0)
        anomalies = detector.detect_spike("net2", threshold_pct=100.0)
        detector.acknowledge_anomaly(anomalies[0].id)
        result = detector.acknowledge_anomaly(anomalies[0].id)
        assert result is False

    def test_acknowledge_nonexistent_returns_false(self, detector: AnomalyDetector) -> None:
        result = detector.acknowledge_anomaly("00000000-0000-0000-0000-000000000000")
        assert result is False


class TestGetAnomalyStats:
    def test_stats_empty_org(self, detector: AnomalyDetector) -> None:
        stats = detector.get_anomaly_stats()
        assert isinstance(stats, AnomalyStats)
        assert stats.total == 0
        assert stats.unacknowledged == 0
        assert stats.by_type == {}
        assert stats.by_severity == {}

    def test_stats_populated(self, detector: AnomalyDetector) -> None:
        _record_many(detector, "x", [1.0, 1.0, 1.0, 1.0])
        detector.record_metric("x", 9999.0)
        detector.detect_spike("x", threshold_pct=100.0)
        stats = detector.get_anomaly_stats()
        assert stats.total >= 1
        assert stats.unacknowledged >= 1
        assert "spike" in stats.by_type

    def test_stats_after_ack(self, detector: AnomalyDetector) -> None:
        _record_many(detector, "y", [1.0, 1.0, 1.0, 1.0])
        detector.record_metric("y", 9999.0)
        anomalies = detector.detect_spike("y", threshold_pct=100.0)
        detector.acknowledge_anomaly(anomalies[0].id)
        stats = detector.get_anomaly_stats()
        assert stats.unacknowledged == 0


class TestDetectAnomaliesFull:
    def test_detect_anomalies_returns_list(self, detector: AnomalyDetector) -> None:
        result = detector.detect_anomalies()
        assert isinstance(result, list)

    def test_detect_anomalies_finds_spike(self, detector: AnomalyDetector) -> None:
        _record_many(detector, "full_scan_metric", [2.0, 2.0, 2.0, 2.0])
        detector.record_metric("full_scan_metric", 9999.0)
        result = detector.detect_anomalies()
        spikes = [a for a in result if a.type == AnomalyType.SPIKE]
        assert len(spikes) >= 1


# ============================================================================
# ROUTER TESTS — FastAPI TestClient
# ============================================================================


@pytest.fixture
def client(tmp_db: str):
    """FastAPI TestClient with anomaly_router mounted, using temp DB and no auth."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    # Patch the detector singleton to use tmp DB
    import apps.api.anomaly_router as ar_module
    ar_module._detector = AnomalyDetector(db_path=tmp_db, org_id="default")

    app = FastAPI()
    from apps.api.anomaly_router import router
    app.include_router(router)

    # Bypass auth by overriding the dependency if it loaded
    try:
        from apps.api.auth_deps import api_key_auth
        app.dependency_overrides[api_key_auth] = lambda: None
    except ImportError:
        pass

    return TestClient(app)


class TestAnomalyRouter:
    def test_record_metric_endpoint(self, client) -> None:
        resp = client.post(
            "/api/v1/anomalies/metrics",
            json={"name": "cpu", "value": 55.0, "org_id": "default"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["message"] == "Metric recorded"
        assert data["row_id"] > 0

    def test_record_metric_multiple(self, client) -> None:
        for v in [10.0, 20.0, 30.0]:
            resp = client.post(
                "/api/v1/anomalies/metrics",
                json={"name": "mem", "value": v, "org_id": "default"},
            )
            assert resp.status_code == 200

    def test_list_anomalies_empty(self, client) -> None:
        resp = client.get("/api/v1/anomalies?org_id=default")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_get_stats_empty(self, client) -> None:
        resp = client.get("/api/v1/anomalies/stats?org_id=default")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0

    def test_get_baseline_404_no_data(self, client) -> None:
        resp = client.get("/api/v1/anomalies/baseline/no_metric?org_id=default")
        assert resp.status_code == 404

    def test_get_baseline_success(self, client) -> None:
        for v in [10.0, 20.0, 30.0, 40.0, 50.0]:
            client.post(
                "/api/v1/anomalies/metrics",
                json={"name": "latency", "value": v, "org_id": "default"},
            )
        resp = client.get("/api/v1/anomalies/baseline/latency?org_id=default")
        assert resp.status_code == 200
        data = resp.json()
        assert data["mean"] == pytest.approx(30.0)
        assert data["sample_count"] == 5

    def test_detect_spike_endpoint_no_anomaly(self, client) -> None:
        for v in [10.0, 10.0, 10.0, 10.0, 10.0]:
            client.post(
                "/api/v1/anomalies/metrics",
                json={"name": "stable", "value": v, "org_id": "default"},
            )
        resp = client.post(
            "/api/v1/anomalies/detect/spike",
            json={"metric_name": "stable", "threshold_pct": 500.0, "org_id": "default"},
        )
        assert resp.status_code == 200
        assert resp.json()["anomalies_found"] == 0

    def test_detect_spike_endpoint_finds_anomaly(self, client) -> None:
        for v in [5.0, 5.0, 5.0, 5.0]:
            client.post(
                "/api/v1/anomalies/metrics",
                json={"name": "spiky", "value": v, "org_id": "default"},
            )
        client.post(
            "/api/v1/anomalies/metrics",
            json={"name": "spiky", "value": 5000.0, "org_id": "default"},
        )
        resp = client.post(
            "/api/v1/anomalies/detect/spike",
            json={"metric_name": "spiky", "threshold_pct": 100.0, "org_id": "default"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["anomalies_found"] == 1
        assert data["anomalies"][0]["type"] == "spike"

    def test_detect_drop_endpoint_finds_anomaly(self, client) -> None:
        for v in [100.0, 100.0, 100.0, 100.0]:
            client.post(
                "/api/v1/anomalies/metrics",
                json={"name": "dropper", "value": v, "org_id": "default"},
            )
        client.post(
            "/api/v1/anomalies/metrics",
            json={"name": "dropper", "value": 1.0, "org_id": "default"},
        )
        resp = client.post(
            "/api/v1/anomalies/detect/drop",
            json={"metric_name": "dropper", "threshold_pct": 50.0, "org_id": "default"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["anomalies_found"] == 1
        assert data["anomalies"][0]["type"] == "drop"

    def test_detect_full_scan_endpoint(self, client) -> None:
        resp = client.post(
            "/api/v1/anomalies/detect",
            json={"org_id": "default"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "anomalies_found" in data
        assert "anomalies" in data

    def test_acknowledge_anomaly_404_on_unknown(self, client) -> None:
        resp = client.post(
            "/api/v1/anomalies/00000000-0000-0000-0000-000000000000/ack"
        )
        assert resp.status_code == 404

    def test_acknowledge_anomaly_success(self, client) -> None:
        for v in [1.0, 1.0, 1.0, 1.0]:
            client.post(
                "/api/v1/anomalies/metrics",
                json={"name": "ack_metric", "value": v, "org_id": "default"},
            )
        client.post(
            "/api/v1/anomalies/metrics",
            json={"name": "ack_metric", "value": 99999.0, "org_id": "default"},
        )
        spike_resp = client.post(
            "/api/v1/anomalies/detect/spike",
            json={"metric_name": "ack_metric", "threshold_pct": 100.0, "org_id": "default"},
        )
        anomaly_id = spike_resp.json()["anomalies"][0]["id"]
        ack_resp = client.post(f"/api/v1/anomalies/{anomaly_id}/ack")
        assert ack_resp.status_code == 200
        assert ack_resp.json()["acknowledged"] is True

    def test_list_anomalies_severity_filter_invalid(self, client) -> None:
        resp = client.get("/api/v1/anomalies?org_id=default&severity=badvalue")
        assert resp.status_code == 422

    def test_list_anomalies_severity_filter_valid(self, client) -> None:
        resp = client.get("/api/v1/anomalies?org_id=default&severity=high")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_stats_after_spike(self, client) -> None:
        for v in [2.0, 2.0, 2.0, 2.0]:
            client.post(
                "/api/v1/anomalies/metrics",
                json={"name": "stat_test", "value": v, "org_id": "default"},
            )
        client.post(
            "/api/v1/anomalies/metrics",
            json={"name": "stat_test", "value": 9999.0, "org_id": "default"},
        )
        client.post(
            "/api/v1/anomalies/detect/spike",
            json={"metric_name": "stat_test", "threshold_pct": 100.0, "org_id": "default"},
        )
        resp = client.get("/api/v1/anomalies/stats?org_id=default")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        assert data["unacknowledged"] >= 1
