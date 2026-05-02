"""
Network Anomaly Detector — ALDECI.

Statistical baseline + SIEM-style rule-based anomaly detection for
network/API events.

Components:
  - BaselineModel: rolling 7-day statistical profile (mean/stddev per metric)
  - NetworkAnomalyDetector.train_baseline(): build baseline from event history
  - NetworkAnomalyDetector.detect_anomalies(): z-score detection (threshold 3.0)
  - NetworkAnomalyDetector.apply_siem_rules(): 6 predefined SIEM rules
  - NetworkAnomalyDetector.correlate_alerts(): group related alerts into incidents

Pure Python (stdlib math/statistics only). No external ML deps.

Compliance: SOC2 CC7.2 (continuous monitoring), NIST 800-53 SI-4
"""

from __future__ import annotations

import statistics
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class AnomalyType(str, Enum):
    ZSCORE_SPIKE = "zscore_spike"
    ZSCORE_DROP = "zscore_drop"
    RATE_SPIKE = "rate_spike"
    NEW_IP = "new_ip"


class AlertType(str, Enum):
    BRUTE_FORCE = "brute_force"
    DATA_EXFILTRATION = "data_exfiltration"
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    AFTER_HOURS_ACCESS = "after_hours_access"
    ADMIN_UNKNOWN_IP = "admin_unknown_ip"
    PORT_SCAN = "port_scan"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Data models (dataclasses — lightweight, no SQLite dep here)
# ---------------------------------------------------------------------------


@dataclass
class BaselineModel:
    """Per-metric statistical baseline derived from historical events."""

    metrics: Dict[str, Dict[str, float]] = field(default_factory=dict)
    # metrics[metric_name] = {"mean": ..., "stddev": ..., "min": ..., "max": ..., "count": ...}
    known_ips: set = field(default_factory=set)
    trained_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Anomaly:
    """A statistical deviation detected vs the baseline."""

    anomaly_id: str
    type: AnomalyType
    severity: Severity
    description: str
    metrics: Dict[str, float]
    z_score: float
    source_ip: Optional[str]
    timestamp: datetime

    @classmethod
    def create(
        cls,
        anomaly_type: AnomalyType,
        severity: Severity,
        description: str,
        metrics: Dict[str, float],
        z_score: float,
        source_ip: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ) -> "Anomaly":
        return cls(
            anomaly_id=str(uuid.uuid4()),
            type=anomaly_type,
            severity=severity,
            description=description,
            metrics=metrics,
            z_score=z_score,
            source_ip=source_ip,
            timestamp=timestamp or datetime.now(timezone.utc),
        )


@dataclass
class Alert:
    """A rule-triggered SIEM alert."""

    alert_id: str
    rule: AlertType
    severity: Severity
    description: str
    source_ip: Optional[str]
    user: Optional[str]
    metadata: Dict[str, Any]
    timestamp: datetime

    @classmethod
    def create(
        cls,
        rule: AlertType,
        severity: Severity,
        description: str,
        source_ip: Optional[str] = None,
        user: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        timestamp: Optional[datetime] = None,
    ) -> "Alert":
        return cls(
            alert_id=str(uuid.uuid4()),
            rule=rule,
            severity=severity,
            description=description,
            source_ip=source_ip,
            user=user,
            metadata=metadata or {},
            timestamp=timestamp or datetime.now(timezone.utc),
        )


@dataclass
class Incident:
    """A correlated group of related alerts."""

    incident_id: str
    alerts: List[Alert]
    severity: Severity
    source_ip: Optional[str]
    description: str
    started_at: datetime
    ended_at: datetime

    @classmethod
    def from_alerts(cls, alerts: List[Alert], source_ip: Optional[str]) -> "Incident":
        severities = [a.severity for a in alerts]
        # Escalate to highest severity in group
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        max_sev = max(severities, key=lambda s: order.index(s))
        return cls(
            incident_id=str(uuid.uuid4()),
            alerts=alerts,
            severity=max_sev,
            source_ip=source_ip,
            description=f"{len(alerts)} correlated alerts from {source_ip or 'unknown'}",
            started_at=min(a.timestamp for a in alerts),
            ended_at=max(a.timestamp for a in alerts),
        )


# ---------------------------------------------------------------------------
# Constants — SIEM rule thresholds
# ---------------------------------------------------------------------------

_BRUTE_FORCE_THRESHOLD = 10        # auth failures per window
_BRUTE_FORCE_WINDOW_SECS = 60      # 60-second sliding window
_EXFIL_BYTES_THRESHOLD = 100 * 1024 * 1024   # 100 MB
_EXFIL_WINDOW_SECS = 300           # 5-minute window
_TRAVEL_LATENCY_MS_THRESHOLD = 100 # impossibly fast travel if < 100ms apart
_AFTER_HOURS_START = 8             # business hours start (inclusive)
_AFTER_HOURS_END = 20              # business hours end (exclusive)
_PORT_SCAN_THRESHOLD = 20          # distinct ports probed
_ZSCORE_THRESHOLD = 3.0            # standard sigma cutoff
_CORRELATION_WINDOW_SECS = 300     # 5-minute window for incident correlation


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class NetworkAnomalyDetector:
    """Statistical baseline + rule-based anomaly detection for network/API events.

    Usage::

        detector = NetworkAnomalyDetector()
        baseline = detector.train_baseline(historical_events)
        anomalies = detector.detect_anomalies(current_events, baseline)
        alerts = detector.apply_siem_rules(current_events)
        incidents = detector.correlate_alerts(alerts)
    """

    # ------------------------------------------------------------------
    # Baseline training
    # ------------------------------------------------------------------

    def train_baseline(self, events: List[Dict[str, Any]]) -> BaselineModel:
        """Build a statistical baseline from historical event data.

        Each event dict may contain numeric fields:
          - request_count, error_rate, response_time_ms, bytes_out
        Non-numeric / absent fields are silently skipped.

        IP addresses in ``source_ip`` are collected as the known-IP set.

        Returns:
            BaselineModel with per-metric mean/stddev/min/max/count
            and the set of known source IPs.
        """
        metric_buckets: Dict[str, List[float]] = defaultdict(list)
        known_ips: set = set()

        _numeric_fields = ("request_count", "error_rate", "response_time_ms", "bytes_out")

        for event in events:
            for f in _numeric_fields:
                val = event.get(f)
                if val is not None:
                    try:
                        metric_buckets[f].append(float(val))
                    except (TypeError, ValueError):
                        pass
            ip = event.get("source_ip")
            if ip:
                known_ips.add(str(ip))

        metrics: Dict[str, Dict[str, float]] = {}
        for metric_name, values in metric_buckets.items():
            if not values:
                continue
            mean = statistics.mean(values)
            stddev = statistics.pstdev(values) if len(values) >= 2 else 0.0
            metrics[metric_name] = {
                "mean": mean,
                "stddev": stddev,
                "min": min(values),
                "max": max(values),
                "count": float(len(values)),
            }

        return BaselineModel(metrics=metrics, known_ips=known_ips)

    # ------------------------------------------------------------------
    # Z-score anomaly detection
    # ------------------------------------------------------------------

    def detect_anomalies(
        self,
        current_events: List[Dict[str, Any]],
        baseline: Optional[BaselineModel] = None,
    ) -> List[Anomaly]:
        """Detect anomalies in current_events relative to the baseline.

        Algorithm:
          For each numeric metric in each event, compute the z-score vs
          the baseline mean/stddev. Flag if |z| > ZSCORE_THRESHOLD (3.0).

        Additional rules (no baseline needed):
          - ``error_rate`` > 10% → flagged regardless of baseline
          - ``source_ip`` not in baseline known-IP set → NEW_IP anomaly
          - metric value > 3× baseline mean → RATE_SPIKE

        Returns:
            List of Anomaly objects (one per triggered metric per event).
        """
        anomalies: List[Anomaly] = []
        _numeric_fields = ("request_count", "error_rate", "response_time_ms", "bytes_out")

        for event in current_events:
            source_ip = event.get("source_ip")
            ts = _parse_ts(event.get("timestamp"))

            # New IP detection (requires baseline)
            if baseline and source_ip and source_ip not in baseline.known_ips:
                anomalies.append(
                    Anomaly.create(
                        anomaly_type=AnomalyType.NEW_IP,
                        severity=Severity.MEDIUM,
                        description=f"New source IP not seen in baseline: {source_ip}",
                        metrics={"new_ip": 1.0},
                        z_score=0.0,
                        source_ip=source_ip,
                        timestamp=ts,
                    )
                )

            for metric_name in _numeric_fields:
                val = event.get(metric_name)
                if val is None:
                    continue
                try:
                    val = float(val)
                except (TypeError, ValueError):
                    continue

                # High error rate rule (always apply)
                if metric_name == "error_rate" and val > 10.0:
                    anomalies.append(
                        Anomaly.create(
                            anomaly_type=AnomalyType.ZSCORE_SPIKE,
                            severity=_severity_from_error_rate(val),
                            description=f"Error rate {val:.1f}% exceeds 10% threshold",
                            metrics={metric_name: val},
                            z_score=0.0,
                            source_ip=source_ip,
                            timestamp=ts,
                        )
                    )
                    continue

                if not baseline or metric_name not in baseline.metrics:
                    continue

                bm = baseline.metrics[metric_name]
                mean = bm["mean"]
                stddev = bm["stddev"]

                # Rate spike: value > 3× baseline mean
                if mean > 0 and val > 3.0 * mean:
                    anomalies.append(
                        Anomaly.create(
                            anomaly_type=AnomalyType.RATE_SPIKE,
                            severity=Severity.HIGH,
                            description=(
                                f"{metric_name} value {val:.2f} is >3× baseline mean {mean:.2f}"
                            ),
                            metrics={metric_name: val, "baseline_mean": mean},
                            z_score=0.0,
                            source_ip=source_ip,
                            timestamp=ts,
                        )
                    )
                    continue

                # Z-score detection
                if stddev == 0:
                    continue
                z = (val - mean) / stddev
                if abs(z) <= _ZSCORE_THRESHOLD:
                    continue

                anomaly_type = (
                    AnomalyType.ZSCORE_SPIKE if z > 0 else AnomalyType.ZSCORE_DROP
                )
                severity = _severity_from_zscore(abs(z))
                anomalies.append(
                    Anomaly.create(
                        anomaly_type=anomaly_type,
                        severity=severity,
                        description=(
                            f"{metric_name} z-score {z:.2f} exceeds threshold "
                            f"±{_ZSCORE_THRESHOLD} (mean={mean:.2f}, stddev={stddev:.2f})"
                        ),
                        metrics={
                            metric_name: val,
                            "baseline_mean": mean,
                            "baseline_stddev": stddev,
                        },
                        z_score=z,
                        source_ip=source_ip,
                        timestamp=ts,
                    )
                )

        return anomalies

    # ------------------------------------------------------------------
    # SIEM rules
    # ------------------------------------------------------------------

    def apply_siem_rules(self, events: List[Dict[str, Any]]) -> List[Alert]:
        """Apply predefined SIEM detection rules to a list of events.

        Rules implemented:
          1. Brute force — >10 auth failures in 60 s from same IP
          2. Data exfiltration — >100 MB outbound in 5 min
          3. Impossible travel — same user from 2 IPs < 100 ms apart
          4. After-hours access — access outside 08:00–20:00
          5. Admin access from unknown IP (requires event["is_admin_action"] + known_ips)
          6. Port scanning — >20 distinct ports probed by same IP

        Returns:
            List of Alert objects.
        """
        alerts: List[Alert] = []
        alerts.extend(self._rule_brute_force(events))
        alerts.extend(self._rule_data_exfiltration(events))
        alerts.extend(self._rule_impossible_travel(events))
        alerts.extend(self._rule_after_hours(events))
        alerts.extend(self._rule_admin_unknown_ip(events))
        alerts.extend(self._rule_port_scan(events))
        return alerts

    # ------------------------------------------------------------------
    # Alert correlation
    # ------------------------------------------------------------------

    def correlate_alerts(self, alerts: List[Alert]) -> List[Incident]:
        """Correlate related alerts into incidents.

        Grouping logic: alerts from the same source_ip within a
        5-minute sliding window are merged into a single Incident.
        Alerts with no source_ip are grouped together as a single
        'unknown' incident if there are multiple.

        Returns:
            List of Incident objects (one per correlated group).
        """
        if not alerts:
            return []

        # Sort by timestamp for window comparison
        sorted_alerts = sorted(alerts, key=lambda a: a.timestamp)

        # Group by source_ip
        by_ip: Dict[str, List[Alert]] = defaultdict(list)
        for alert in sorted_alerts:
            key = alert.source_ip or "__unknown__"
            by_ip[key].append(alert)

        incidents: List[Incident] = []
        for ip, ip_alerts in by_ip.items():
            # Sliding window grouping within _CORRELATION_WINDOW_SECS
            groups: List[List[Alert]] = []
            current_group: List[Alert] = []
            window_start: Optional[datetime] = None

            for alert in ip_alerts:
                if window_start is None:
                    window_start = alert.timestamp
                    current_group = [alert]
                else:
                    delta = (alert.timestamp - window_start).total_seconds()
                    if delta <= _CORRELATION_WINDOW_SECS:
                        current_group.append(alert)
                    else:
                        groups.append(current_group)
                        current_group = [alert]
                        window_start = alert.timestamp

            if current_group:
                groups.append(current_group)

            for group in groups:
                source = None if ip == "__unknown__" else ip
                incidents.append(Incident.from_alerts(group, source_ip=source))

        return incidents

    # ------------------------------------------------------------------
    # Private rule implementations
    # ------------------------------------------------------------------

    def _rule_brute_force(self, events: List[Dict[str, Any]]) -> List[Alert]:
        """Rule 1: >10 auth failures in 60 s from same source IP."""
        # Map: ip -> list of failure timestamps
        failures: Dict[str, List[datetime]] = defaultdict(list)
        for event in events:
            if event.get("event_type") == "auth_failure" or event.get("auth_failure"):
                ip = event.get("source_ip", "unknown")
                ts = _parse_ts(event.get("timestamp"))
                failures[ip].append(ts)

        alerts: List[Alert] = []
        for ip, timestamps in failures.items():
            timestamps.sort()
            # Sliding window count
            for i, ts in enumerate(timestamps):
                window = [
                    t for t in timestamps[i:]
                    if (t - ts).total_seconds() <= _BRUTE_FORCE_WINDOW_SECS
                ]
                if len(window) > _BRUTE_FORCE_THRESHOLD:
                    alerts.append(
                        Alert.create(
                            rule=AlertType.BRUTE_FORCE,
                            severity=Severity.HIGH,
                            description=(
                                f"Brute force detected: {len(window)} auth failures "
                                f"in {_BRUTE_FORCE_WINDOW_SECS}s from {ip}"
                            ),
                            source_ip=ip,
                            metadata={
                                "failure_count": len(window),
                                "window_secs": _BRUTE_FORCE_WINDOW_SECS,
                            },
                        )
                    )
                    break  # one alert per IP per rule run
        return alerts

    def _rule_data_exfiltration(self, events: List[Dict[str, Any]]) -> List[Alert]:
        """Rule 2: >100 MB outbound in 5 min."""
        # Group bytes_out by source_ip in 5-minute windows
        by_ip: Dict[str, List[Tuple[datetime, float]]] = defaultdict(list)
        for event in events:
            bytes_out = event.get("bytes_out")
            if bytes_out is None:
                continue
            try:
                bytes_out = float(bytes_out)
            except (TypeError, ValueError):
                continue
            ip = event.get("source_ip", "unknown")
            ts = _parse_ts(event.get("timestamp"))
            by_ip[ip].append((ts, bytes_out))

        alerts: List[Alert] = []
        for ip, entries in by_ip.items():
            entries.sort(key=lambda x: x[0])
            for i, (ts, _) in enumerate(entries):
                window_bytes = sum(
                    b for t, b in entries[i:]
                    if (t - ts).total_seconds() <= _EXFIL_WINDOW_SECS
                )
                if window_bytes > _EXFIL_BYTES_THRESHOLD:
                    alerts.append(
                        Alert.create(
                            rule=AlertType.DATA_EXFILTRATION,
                            severity=Severity.CRITICAL,
                            description=(
                                f"Data exfiltration: {window_bytes / (1024*1024):.1f} MB "
                                f"outbound in {_EXFIL_WINDOW_SECS}s from {ip}"
                            ),
                            source_ip=ip,
                            metadata={
                                "bytes_out": window_bytes,
                                "threshold_bytes": _EXFIL_BYTES_THRESHOLD,
                                "window_secs": _EXFIL_WINDOW_SECS,
                            },
                        )
                    )
                    break  # one alert per IP
        return alerts

    def _rule_impossible_travel(self, events: List[Dict[str, Any]]) -> List[Alert]:
        """Rule 3: Same user from 2 different IPs within 100 ms."""
        # Map user -> list of (timestamp, ip)
        user_sessions: Dict[str, List[Tuple[datetime, str]]] = defaultdict(list)
        for event in events:
            user = event.get("user") or event.get("username")
            ip = event.get("source_ip")
            if not user or not ip:
                continue
            ts = _parse_ts(event.get("timestamp"))
            user_sessions[user].append((ts, ip))

        alerts: List[Alert] = []
        for user, sessions in user_sessions.items():
            sessions.sort(key=lambda x: x[0])
            for i in range(len(sessions) - 1):
                ts1, ip1 = sessions[i]
                ts2, ip2 = sessions[i + 1]
                if ip1 == ip2:
                    continue
                delta_ms = (ts2 - ts1).total_seconds() * 1000
                if 0 <= delta_ms < _TRAVEL_LATENCY_MS_THRESHOLD:
                    alerts.append(
                        Alert.create(
                            rule=AlertType.IMPOSSIBLE_TRAVEL,
                            severity=Severity.CRITICAL,
                            description=(
                                f"Impossible travel: user '{user}' accessed from "
                                f"{ip1} and {ip2} with only {delta_ms:.1f}ms gap"
                            ),
                            source_ip=ip2,
                            user=user,
                            metadata={
                                "ip1": ip1,
                                "ip2": ip2,
                                "delta_ms": delta_ms,
                            },
                        )
                    )
        return alerts

    def _rule_after_hours(self, events: List[Dict[str, Any]]) -> List[Alert]:
        """Rule 4: Access outside 08:00–20:00 local (UTC hour)."""
        alerts: List[Alert] = []
        for event in events:
            ts = _parse_ts(event.get("timestamp"))
            hour = ts.hour
            if not (_AFTER_HOURS_START <= hour < _AFTER_HOURS_END):
                ip = event.get("source_ip")
                user = event.get("user") or event.get("username")
                alerts.append(
                    Alert.create(
                        rule=AlertType.AFTER_HOURS_ACCESS,
                        severity=Severity.LOW,
                        description=(
                            f"After-hours access at {ts.strftime('%H:%M UTC')} "
                            f"by {user or 'unknown'} from {ip or 'unknown'}"
                        ),
                        source_ip=ip,
                        user=user,
                        metadata={"hour_utc": hour, "timestamp": ts.isoformat()},
                        timestamp=ts,
                    )
                )
        return alerts

    def _rule_admin_unknown_ip(self, events: List[Dict[str, Any]]) -> List[Alert]:
        """Rule 5: Admin action from an IP not in the known-admin IP list."""
        alerts: List[Alert] = []
        for event in events:
            if not event.get("is_admin_action"):
                continue
            known_admin_ips = event.get("known_admin_ips") or []
            ip = event.get("source_ip")
            if ip and known_admin_ips and ip not in known_admin_ips:
                user = event.get("user") or event.get("username")
                alerts.append(
                    Alert.create(
                        rule=AlertType.ADMIN_UNKNOWN_IP,
                        severity=Severity.HIGH,
                        description=(
                            f"Admin action by '{user or 'unknown'}' from unrecognised IP {ip}"
                        ),
                        source_ip=ip,
                        user=user,
                        metadata={"known_admin_ips": known_admin_ips},
                    )
                )
        return alerts

    def _rule_port_scan(self, events: List[Dict[str, Any]]) -> List[Alert]:
        """Rule 6: Same source IP probes >20 distinct destination ports."""
        ports_by_ip: Dict[str, set] = defaultdict(set)
        for event in events:
            ip = event.get("source_ip")
            port = event.get("dest_port")
            if ip and port is not None:
                ports_by_ip[ip].add(port)

        alerts: List[Alert] = []
        for ip, ports in ports_by_ip.items():
            if len(ports) > _PORT_SCAN_THRESHOLD:
                alerts.append(
                    Alert.create(
                        rule=AlertType.PORT_SCAN,
                        severity=Severity.HIGH,
                        description=(
                            f"Port scan detected from {ip}: "
                            f"{len(ports)} distinct ports probed"
                        ),
                        source_ip=ip,
                        metadata={
                            "distinct_ports": len(ports),
                            "threshold": _PORT_SCAN_THRESHOLD,
                        },
                    )
                )
        return alerts


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_ts(value: Any) -> datetime:
    """Parse a timestamp value into a timezone-aware datetime (UTC)."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _severity_from_zscore(z: float) -> Severity:
    """Map absolute z-score to severity."""
    if z >= 6.0:
        return Severity.CRITICAL
    if z >= 4.0:
        return Severity.HIGH
    if z >= 3.0:
        return Severity.MEDIUM
    return Severity.LOW


def _severity_from_error_rate(rate: float) -> Severity:
    """Map error rate % to severity."""
    if rate >= 50.0:
        return Severity.CRITICAL
    if rate >= 25.0:
        return Severity.HIGH
    if rate >= 10.0:
        return Severity.MEDIUM
    return Severity.LOW
