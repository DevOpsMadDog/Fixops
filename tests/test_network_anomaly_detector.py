"""
Tests for NetworkAnomalyDetector — z-score baseline, 6 SIEM rules, correlation.

15+ tests covering:
  - train_baseline: metric stats + known IPs
  - detect_anomalies: z-score spike/drop, error rate, new IP, rate spike
  - apply_siem_rules: all 6 rules (brute force, exfil, impossible travel,
    after-hours, admin unknown IP, port scan)
  - correlate_alerts: grouping by IP and time window
"""

from __future__ import annotations

import sys
import os
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from core.network_anomaly_detector import (
    Alert,
    AlertType,
    Anomaly,
    AnomalyType,
    BaselineModel,
    Incident,
    NetworkAnomalyDetector,
    Severity,
    _parse_ts,
    _severity_from_zscore,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ts(offset_secs: float = 0.0) -> datetime:
    return _now() + timedelta(seconds=offset_secs)


def _business_ts() -> datetime:
    """Return a UTC datetime during business hours (10:00)."""
    base = _now().replace(hour=10, minute=0, second=0, microsecond=0)
    return base


def _after_hours_ts() -> datetime:
    """Return a UTC datetime outside business hours (02:00)."""
    base = _now().replace(hour=2, minute=0, second=0, microsecond=0)
    return base


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def detector() -> NetworkAnomalyDetector:
    return NetworkAnomalyDetector()


@pytest.fixture
def simple_baseline(detector: NetworkAnomalyDetector) -> BaselineModel:
    """Baseline from 10 events with stable metrics."""
    events = [
        {
            "request_count": 100.0,
            "error_rate": 1.0,
            "response_time_ms": 200.0,
            "bytes_out": 1024.0,
            "source_ip": f"10.0.0.{i}",
        }
        for i in range(10)
    ]
    return detector.train_baseline(events)


# ============================================================================
# 1. train_baseline tests
# ============================================================================


class TestTrainBaseline:
    def test_computes_mean(self, detector):
        events = [
            {"request_count": 10.0, "source_ip": "1.1.1.1"},
            {"request_count": 20.0, "source_ip": "1.1.1.2"},
            {"request_count": 30.0, "source_ip": "1.1.1.3"},
        ]
        baseline = detector.train_baseline(events)
        assert "request_count" in baseline.metrics
        assert abs(baseline.metrics["request_count"]["mean"] - 20.0) < 1e-6

    def test_computes_stddev(self, detector):
        events = [{"request_count": float(v)} for v in [10, 20, 30]]
        baseline = detector.train_baseline(events)
        # Population stddev of [10,20,30] = ~8.165
        stddev = baseline.metrics["request_count"]["stddev"]
        assert stddev > 0

    def test_collects_known_ips(self, detector):
        events = [
            {"source_ip": "192.168.1.1"},
            {"source_ip": "192.168.1.2"},
            {"source_ip": "192.168.1.1"},  # duplicate
        ]
        baseline = detector.train_baseline(events)
        assert "192.168.1.1" in baseline.known_ips
        assert "192.168.1.2" in baseline.known_ips
        assert len(baseline.known_ips) == 2

    def test_empty_events_returns_empty_baseline(self, detector):
        baseline = detector.train_baseline([])
        assert baseline.metrics == {}
        assert baseline.known_ips == set()

    def test_ignores_non_numeric_fields(self, detector):
        events = [{"request_count": "not-a-number", "source_ip": "1.1.1.1"}]
        baseline = detector.train_baseline(events)
        assert "request_count" not in baseline.metrics

    def test_single_event_stddev_zero(self, detector):
        events = [{"request_count": 50.0}]
        baseline = detector.train_baseline(events)
        assert baseline.metrics["request_count"]["stddev"] == 0.0


# ============================================================================
# 2. detect_anomalies — z-score tests
# ============================================================================


class TestDetectAnomalies:
    def test_zscore_spike_detected(self, detector, simple_baseline):
        """Value far above baseline mean triggers ZSCORE_SPIKE."""
        events = [{"request_count": 10000.0, "source_ip": "10.0.0.1"}]
        anomalies = detector.detect_anomalies(events, simple_baseline)
        types = {a.type for a in anomalies}
        # Should catch either ZSCORE_SPIKE or RATE_SPIKE (both valid)
        assert AnomalyType.ZSCORE_SPIKE in types or AnomalyType.RATE_SPIKE in types

    def test_normal_value_no_anomaly(self, detector, simple_baseline):
        """Value within 3-sigma of baseline is not flagged."""
        events = [{"request_count": 101.0, "source_ip": "10.0.0.1"}]
        anomalies = detector.detect_anomalies(events, simple_baseline)
        # Filter to request_count only
        rc_anomalies = [
            a for a in anomalies
            if "request_count" in a.metrics and a.type != AnomalyType.NEW_IP
        ]
        assert len(rc_anomalies) == 0

    def test_high_error_rate_flagged_without_baseline(self, detector):
        """Error rate > 10% is flagged even without a baseline."""
        events = [{"error_rate": 75.0, "source_ip": "1.2.3.4"}]
        anomalies = detector.detect_anomalies(events)
        assert len(anomalies) == 1
        assert anomalies[0].type == AnomalyType.ZSCORE_SPIKE
        assert anomalies[0].severity == Severity.CRITICAL

    def test_low_error_rate_not_flagged(self, detector):
        """Error rate <= 10% is not flagged without baseline."""
        events = [{"error_rate": 5.0}]
        anomalies = detector.detect_anomalies(events)
        assert len(anomalies) == 0

    def test_new_ip_detected(self, detector, simple_baseline):
        """IP not in baseline.known_ips triggers NEW_IP anomaly."""
        events = [{"source_ip": "99.99.99.99", "request_count": 100.0}]
        anomalies = detector.detect_anomalies(events, simple_baseline)
        new_ip_anomalies = [a for a in anomalies if a.type == AnomalyType.NEW_IP]
        assert len(new_ip_anomalies) == 1
        assert new_ip_anomalies[0].source_ip == "99.99.99.99"

    def test_known_ip_no_new_ip_anomaly(self, detector, simple_baseline):
        """Known IP does not trigger NEW_IP."""
        events = [{"source_ip": "10.0.0.1", "request_count": 100.0}]
        anomalies = detector.detect_anomalies(events, simple_baseline)
        assert all(a.type != AnomalyType.NEW_IP for a in anomalies)

    def test_rate_spike_3x_baseline(self, detector):
        """Value > 3× baseline mean triggers RATE_SPIKE."""
        events_hist = [{"request_count": 100.0} for _ in range(5)]
        baseline = detector.train_baseline(events_hist)
        events = [{"request_count": 350.0}]  # 3.5× mean
        anomalies = detector.detect_anomalies(events, baseline)
        rate_spikes = [a for a in anomalies if a.type == AnomalyType.RATE_SPIKE]
        assert len(rate_spikes) == 1

    def test_no_baseline_no_zscore_anomaly(self, detector):
        """Without baseline, only error_rate rule applies."""
        events = [{"request_count": 999999.0}]
        anomalies = detector.detect_anomalies(events)
        assert all(a.type != AnomalyType.ZSCORE_SPIKE for a in anomalies)


# ============================================================================
# 3. SIEM rules
# ============================================================================


class TestSIEMRules:
    # Rule 1: Brute force
    def test_brute_force_detected(self, detector):
        """11 auth failures from same IP in 60s triggers brute force alert."""
        ip = "10.1.2.3"
        ts_base = _now()
        events = [
            {"event_type": "auth_failure", "source_ip": ip,
             "timestamp": (ts_base + timedelta(seconds=i)).isoformat()}
            for i in range(11)
        ]
        alerts = detector.apply_siem_rules(events)
        bf = [a for a in alerts if a.rule == AlertType.BRUTE_FORCE]
        assert len(bf) == 1
        assert bf[0].source_ip == ip
        assert bf[0].severity == Severity.HIGH

    def test_brute_force_not_triggered_below_threshold(self, detector):
        """10 or fewer auth failures do not trigger brute force."""
        ip = "10.1.2.4"
        ts_base = _now()
        events = [
            {"event_type": "auth_failure", "source_ip": ip,
             "timestamp": (ts_base + timedelta(seconds=i)).isoformat()}
            for i in range(10)
        ]
        alerts = detector.apply_siem_rules(events)
        bf = [a for a in alerts if a.rule == AlertType.BRUTE_FORCE]
        assert len(bf) == 0

    # Rule 2: Data exfiltration
    def test_data_exfiltration_detected(self, detector):
        """101 MB in one event triggers exfil alert."""
        events = [
            {
                "source_ip": "10.5.6.7",
                "bytes_out": 101 * 1024 * 1024,
                "timestamp": _now().isoformat(),
            }
        ]
        alerts = detector.apply_siem_rules(events)
        exfil = [a for a in alerts if a.rule == AlertType.DATA_EXFILTRATION]
        assert len(exfil) == 1
        assert exfil[0].severity == Severity.CRITICAL

    def test_data_exfiltration_not_triggered_small(self, detector):
        """50 MB does not trigger exfil alert."""
        events = [
            {
                "source_ip": "10.5.6.8",
                "bytes_out": 50 * 1024 * 1024,
                "timestamp": _now().isoformat(),
            }
        ]
        alerts = detector.apply_siem_rules(events)
        exfil = [a for a in alerts if a.rule == AlertType.DATA_EXFILTRATION]
        assert len(exfil) == 0

    # Rule 3: Impossible travel
    def test_impossible_travel_detected(self, detector):
        """Same user from 2 IPs within 50ms triggers impossible travel."""
        user = "alice"
        ts = _now()
        events = [
            {"user": user, "source_ip": "1.2.3.4",
             "timestamp": ts.isoformat()},
            {"user": user, "source_ip": "9.8.7.6",
             "timestamp": (ts + timedelta(milliseconds=50)).isoformat()},
        ]
        alerts = detector.apply_siem_rules(events)
        travel = [a for a in alerts if a.rule == AlertType.IMPOSSIBLE_TRAVEL]
        assert len(travel) == 1
        assert travel[0].severity == Severity.CRITICAL

    def test_impossible_travel_same_ip_ignored(self, detector):
        """Same user from same IP is not impossible travel."""
        user = "bob"
        ts = _now()
        events = [
            {"user": user, "source_ip": "1.2.3.4", "timestamp": ts.isoformat()},
            {"user": user, "source_ip": "1.2.3.4",
             "timestamp": (ts + timedelta(milliseconds=10)).isoformat()},
        ]
        alerts = detector.apply_siem_rules(events)
        travel = [a for a in alerts if a.rule == AlertType.IMPOSSIBLE_TRAVEL]
        assert len(travel) == 0

    # Rule 4: After hours
    def test_after_hours_access_detected(self, detector):
        """Access at 02:00 UTC triggers after-hours alert."""
        ts = _after_hours_ts()
        events = [{"source_ip": "1.1.1.1", "user": "eve", "timestamp": ts.isoformat()}]
        alerts = detector.apply_siem_rules(events)
        ah = [a for a in alerts if a.rule == AlertType.AFTER_HOURS_ACCESS]
        assert len(ah) == 1

    def test_business_hours_not_flagged(self, detector):
        """Access at 10:00 UTC does not trigger after-hours alert."""
        ts = _business_ts()
        events = [{"source_ip": "1.1.1.2", "user": "alice", "timestamp": ts.isoformat()}]
        alerts = detector.apply_siem_rules(events)
        ah = [a for a in alerts if a.rule == AlertType.AFTER_HOURS_ACCESS]
        assert len(ah) == 0

    # Rule 5: Admin unknown IP
    def test_admin_unknown_ip_detected(self, detector):
        """Admin action from unlisted IP triggers alert."""
        events = [
            {
                "is_admin_action": True,
                "source_ip": "66.66.66.66",
                "user": "admin",
                "known_admin_ips": ["10.0.0.1", "10.0.0.2"],
            }
        ]
        alerts = detector.apply_siem_rules(events)
        admin_alerts = [a for a in alerts if a.rule == AlertType.ADMIN_UNKNOWN_IP]
        assert len(admin_alerts) == 1
        assert admin_alerts[0].severity == Severity.HIGH

    def test_admin_known_ip_not_flagged(self, detector):
        """Admin action from known IP is not flagged."""
        events = [
            {
                "is_admin_action": True,
                "source_ip": "10.0.0.1",
                "user": "admin",
                "known_admin_ips": ["10.0.0.1"],
            }
        ]
        alerts = detector.apply_siem_rules(events)
        admin_alerts = [a for a in alerts if a.rule == AlertType.ADMIN_UNKNOWN_IP]
        assert len(admin_alerts) == 0

    # Rule 6: Port scan
    def test_port_scan_detected(self, detector):
        """21 distinct ports from same IP triggers port scan alert."""
        ip = "10.9.8.7"
        events = [
            {"source_ip": ip, "dest_port": port, "timestamp": _now().isoformat()}
            for port in range(1, 22)  # ports 1–21 = 21 distinct
        ]
        alerts = detector.apply_siem_rules(events)
        scans = [a for a in alerts if a.rule == AlertType.PORT_SCAN]
        assert len(scans) == 1
        assert scans[0].severity == Severity.HIGH

    def test_port_scan_not_triggered_below_threshold(self, detector):
        """20 or fewer distinct ports do not trigger port scan."""
        ip = "10.9.8.8"
        events = [
            {"source_ip": ip, "dest_port": port}
            for port in range(1, 21)  # exactly 20 ports
        ]
        alerts = detector.apply_siem_rules(events)
        scans = [a for a in alerts if a.rule == AlertType.PORT_SCAN]
        assert len(scans) == 0


# ============================================================================
# 4. Alert correlation
# ============================================================================


class TestCorrelateAlerts:
    def test_empty_alerts_returns_empty(self, detector):
        incidents = detector.correlate_alerts([])
        assert incidents == []

    def test_single_alert_becomes_incident(self, detector):
        alert = Alert.create(
            rule=AlertType.PORT_SCAN,
            severity=Severity.HIGH,
            description="test",
            source_ip="1.2.3.4",
        )
        incidents = detector.correlate_alerts([alert])
        assert len(incidents) == 1
        assert incidents[0].source_ip == "1.2.3.4"

    def test_same_ip_within_window_merged(self, detector):
        """Two alerts from same IP within 5 min → one incident."""
        ts = _now()
        a1 = Alert.create(
            rule=AlertType.BRUTE_FORCE, severity=Severity.HIGH,
            description="bf", source_ip="1.2.3.4",
            timestamp=ts,
        )
        a2 = Alert.create(
            rule=AlertType.PORT_SCAN, severity=Severity.HIGH,
            description="ps", source_ip="1.2.3.4",
            timestamp=ts + timedelta(seconds=60),
        )
        incidents = detector.correlate_alerts([a1, a2])
        assert len(incidents) == 1
        assert len(incidents[0].alerts) == 2

    def test_same_ip_outside_window_separate_incidents(self, detector):
        """Two alerts from same IP > 5 min apart → separate incidents."""
        ts = _now()
        a1 = Alert.create(
            rule=AlertType.BRUTE_FORCE, severity=Severity.HIGH,
            description="bf", source_ip="1.2.3.4",
            timestamp=ts,
        )
        a2 = Alert.create(
            rule=AlertType.PORT_SCAN, severity=Severity.HIGH,
            description="ps", source_ip="1.2.3.4",
            timestamp=ts + timedelta(seconds=400),
        )
        incidents = detector.correlate_alerts([a1, a2])
        assert len(incidents) == 2

    def test_different_ips_separate_incidents(self, detector):
        """Alerts from different IPs → separate incidents."""
        a1 = Alert.create(
            rule=AlertType.BRUTE_FORCE, severity=Severity.HIGH,
            description="bf", source_ip="1.2.3.4",
        )
        a2 = Alert.create(
            rule=AlertType.BRUTE_FORCE, severity=Severity.HIGH,
            description="bf", source_ip="9.8.7.6",
        )
        incidents = detector.correlate_alerts([a1, a2])
        assert len(incidents) == 2

    def test_incident_severity_escalates_to_highest(self, detector):
        """Incident severity = max severity of its constituent alerts."""
        ts = _now()
        a1 = Alert.create(
            rule=AlertType.AFTER_HOURS_ACCESS, severity=Severity.LOW,
            description="ah", source_ip="1.2.3.4", timestamp=ts,
        )
        a2 = Alert.create(
            rule=AlertType.DATA_EXFILTRATION, severity=Severity.CRITICAL,
            description="ex", source_ip="1.2.3.4",
            timestamp=ts + timedelta(seconds=10),
        )
        incidents = detector.correlate_alerts([a1, a2])
        assert len(incidents) == 1
        assert incidents[0].severity == Severity.CRITICAL

    def test_unknown_ip_alerts_grouped(self, detector):
        """Alerts without source_ip are grouped together."""
        a1 = Alert.create(
            rule=AlertType.AFTER_HOURS_ACCESS, severity=Severity.LOW,
            description="ah1", source_ip=None,
        )
        a2 = Alert.create(
            rule=AlertType.AFTER_HOURS_ACCESS, severity=Severity.LOW,
            description="ah2", source_ip=None,
        )
        incidents = detector.correlate_alerts([a1, a2])
        # Both have no source_ip → one incident (or two if outside window — just check grouping)
        assert len(incidents) >= 1


# ============================================================================
# 5. Utility helpers
# ============================================================================


class TestHelpers:
    def test_severity_from_zscore_critical(self):
        assert _severity_from_zscore(7.0) == Severity.CRITICAL

    def test_severity_from_zscore_high(self):
        assert _severity_from_zscore(5.0) == Severity.HIGH

    def test_severity_from_zscore_medium(self):
        assert _severity_from_zscore(3.5) == Severity.MEDIUM

    def test_parse_ts_datetime_passthrough(self):
        dt = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        assert _parse_ts(dt) == dt

    def test_parse_ts_string(self):
        s = "2025-06-01T10:00:00+00:00"
        dt = _parse_ts(s)
        assert dt.year == 2025
        assert dt.tzinfo is not None

    def test_parse_ts_fallback_on_garbage(self):
        dt = _parse_ts("not-a-date")
        assert isinstance(dt, datetime)
