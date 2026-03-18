"""
ALdeci ML EventBus Integration — Anomaly Detection & Parser Quality Alerts.

[V3] Decision Intelligence — Wires ML anomaly detection into the EventBus
so scan anomalies and parser quality failures automatically emit events
consumed by downstream systems (UI alerts, notifications, audit logs).

Event Flow:
    1. SCAN_COMPLETED event arrives from scanner routers
    2. AnomalyDetector.detect() runs on the scan findings
    3. If anomalous → emit SCAN_ANOMALY_DETECTED event
    4. AnomalyDetector.update_baseline() adds scan to rolling baseline
    5. ParserQualityValidator results → emit PARSER_QUALITY_FAILED if below threshold
    6. DriftResult (if previous scan exists) → emit SCAN_DRIFT_DETECTED on regression

Architecture:
    - EventBus subscribers are async (required by EventBus API)
    - ML detection runs synchronously inside async handlers (CPU-bound, <100ms)
    - Per-org scan history maintained for drift detection (up to 50 scans per org)
    - Module auto-registers handlers on first import via register_ml_handlers()

Usage:
    from core.ml.eventbus_integration import register_ml_handlers
    bus = get_event_bus()
    register_ml_handlers(bus)
    # Now SCAN_COMPLETED events automatically trigger anomaly detection
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from core.event_bus import Event

logger = logging.getLogger(__name__)

# Maximum scan history per org for drift detection
MAX_SCAN_HISTORY_PER_ORG = 50

# Quality score threshold below which PARSER_QUALITY_FAILED is emitted
PARSER_QUALITY_THRESHOLD = 50.0

# Track whether handlers have been registered (prevent double-registration)
_handlers_registered = False

# Per-org scan history for drift detection
_org_scan_history: Dict[str, List[List[Dict[str, Any]]]] = defaultdict(list)


def _store_scan_history(org_id: str, findings: List[Dict[str, Any]]) -> Optional[List[Dict[str, Any]]]:
    """Store scan findings in per-org history and return previous scan if available.

    Parameters
    ----------
    org_id : str
        Organization identifier.
    findings : list of dict
        Current scan findings.

    Returns
    -------
    list of dict or None
        Previous scan's findings if available, else None.
    """
    history = _org_scan_history[org_id]
    previous = history[-1] if history else None

    history.append(findings)
    if len(history) > MAX_SCAN_HISTORY_PER_ORG:
        _org_scan_history[org_id] = history[-MAX_SCAN_HISTORY_PER_ORG:]

    return previous


async def _handle_scan_completed(event: "Event") -> None:
    """Handle SCAN_COMPLETED events — run anomaly detection and drift analysis.

    [V3] Decision Intelligence — Automatic anomaly detection on every scan.

    This handler:
    1. Extracts findings from the event data
    2. Runs anomaly detection (Isolation Forest + Z-scores)
    3. If anomalous, emits SCAN_ANOMALY_DETECTED
    4. Updates the detector baseline with this scan
    5. If previous scan exists, runs drift detection
    6. If regression detected, emits SCAN_DRIFT_DETECTED
    """
    from core.event_bus import Event, EventType, get_event_bus

    t0 = time.monotonic()
    bus = get_event_bus()

    findings = event.data.get("findings", [])
    org_id = event.org_id or event.data.get("org_id", "unknown")
    scanner_type = event.data.get("scanner_type", event.source or "unknown")

    if not findings:
        logger.debug("SCAN_COMPLETED with no findings, skipping anomaly detection")
        return

    try:
        from core.ml.anomaly_detector import get_anomaly_detector
        detector = get_anomaly_detector()

        # Run anomaly detection
        anomaly_result = detector.detect(findings)

        if anomaly_result.is_anomalous:
            logger.warning(
                "ANOMALY DETECTED in %s scan for org=%s: %s",
                scanner_type,
                org_id,
                "; ".join(anomaly_result.anomaly_reasons),
            )
            await bus.emit(Event(
                event_type=EventType.SCAN_ANOMALY_DETECTED,
                source="ml.anomaly_detector",
                org_id=org_id,
                data={
                    "anomaly_score": anomaly_result.anomaly_score,
                    "anomaly_reasons": anomaly_result.anomaly_reasons,
                    "scan_features": anomaly_result.scan_features,
                    "feature_deviations": anomaly_result.feature_deviations,
                    "scanner_type": scanner_type,
                    "finding_count": len(findings),
                    "detection_time_ms": anomaly_result.detection_time_ms,
                },
            ))

        # Update baseline with this scan (streaming update)
        detector.update_baseline(findings)

        # Drift detection against previous scan
        previous_findings = _store_scan_history(org_id, findings)
        if previous_findings:
            drift_result = detector.detect_drift(findings, previous_findings)
            if drift_result.is_regression:
                logger.warning(
                    "REGRESSION detected in %s scan for org=%s: %s",
                    scanner_type,
                    org_id,
                    "; ".join(drift_result.drift_alerts),
                )
                await bus.emit(Event(
                    event_type=EventType.SCAN_DRIFT_DETECTED,
                    source="ml.anomaly_detector",
                    org_id=org_id,
                    data={
                        "drift_type": drift_result.drift_type,
                        "new_findings_count": drift_result.new_findings_count,
                        "resolved_findings_count": drift_result.resolved_findings_count,
                        "severity_changes": drift_result.severity_changes,
                        "drift_alerts": drift_result.drift_alerts,
                        "net_change": drift_result.net_change,
                        "scanner_type": scanner_type,
                        "detection_time_ms": drift_result.detection_time_ms,
                    },
                ))

        elapsed_ms = (time.monotonic() - t0) * 1000
        logger.debug(
            "ML anomaly handler completed in %.1fms for org=%s scanner=%s anomalous=%s",
            elapsed_ms, org_id, scanner_type, anomaly_result.is_anomalous,
        )

    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        logger.error("ML anomaly detection failed for event %s: %s", event.event_id, e)


async def _handle_parser_quality(event: "Event") -> None:
    """Handle SCAN_COMPLETED events — validate parser quality and emit alerts.

    [V7] MCP-Native Platform — validates scanner parser output quality.

    This handler checks parser quality for the scan findings and emits
    PARSER_QUALITY_FAILED if the quality score falls below threshold.
    """
    from core.event_bus import Event, EventType, get_event_bus

    findings = event.data.get("findings", [])
    scanner_type = event.data.get("scanner_type", event.source or "unknown")
    org_id = event.org_id or event.data.get("org_id", "unknown")

    if not findings:
        return

    try:
        from core.ml.parser_quality import ParserQualityValidator
        validator = ParserQualityValidator()
        quality_result = validator.validate_findings(findings, scanner_type=scanner_type)

        if quality_result.quality_score < PARSER_QUALITY_THRESHOLD:
            bus = get_event_bus()
            logger.warning(
                "PARSER QUALITY FAILED for scanner=%s org=%s: score=%.1f (threshold=%.1f)",
                scanner_type,
                org_id,
                quality_result.quality_score,
                PARSER_QUALITY_THRESHOLD,
            )
            await bus.emit(Event(
                event_type=EventType.PARSER_QUALITY_FAILED,
                source="ml.parser_quality",
                org_id=org_id,
                data={
                    "scanner_type": scanner_type,
                    "quality_score": quality_result.quality_score,
                    "error_count": quality_result.error_count,
                    "warning_count": quality_result.warning_count,
                    "issues": [i.to_dict() for i in quality_result.issues[:10]],
                    "severity_distribution": quality_result.severity_distribution,
                    "cve_coverage": quality_result.cve_coverage,
                    "cwe_coverage": quality_result.cwe_coverage,
                },
            ))

    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        logger.error("Parser quality check failed for event %s: %s", event.event_id, e)


def register_ml_handlers(bus: Optional[Any] = None) -> bool:
    """Register ML event handlers on the EventBus.

    [V3] Decision Intelligence — auto-registers anomaly detection and parser
    quality validation handlers for SCAN_COMPLETED events.

    Parameters
    ----------
    bus : EventBus, optional
        EventBus instance. If None, uses global singleton.

    Returns
    -------
    bool
        True if handlers were registered, False if already registered.
    """
    global _handlers_registered
    if _handlers_registered:
        logger.debug("ML EventBus handlers already registered, skipping")
        return False

    try:
        from core.event_bus import EventType, get_event_bus
        if bus is None:
            bus = get_event_bus()

        bus.subscribe(EventType.SCAN_COMPLETED, _handle_scan_completed)
        bus.subscribe(EventType.SCAN_COMPLETED, _handle_parser_quality)

        _handlers_registered = True
        logger.info(
            "ML EventBus handlers registered: anomaly_detector, parser_quality on SCAN_COMPLETED"
        )
        return True

    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        logger.error("Failed to register ML EventBus handlers: %s", e)
        return False


def reset_handlers() -> None:
    """Reset handler registration state (for testing)."""
    global _handlers_registered, _org_scan_history
    _handlers_registered = False
    _org_scan_history = defaultdict(list)


def get_scan_history(org_id: str) -> List[List[Dict[str, Any]]]:
    """Get scan history for an organization (for testing/debugging).

    Parameters
    ----------
    org_id : str
        Organization identifier.

    Returns
    -------
    list of list of dict
        List of historical scans, each being a list of findings.
    """
    return list(_org_scan_history.get(org_id, []))


__all__ = [
    "register_ml_handlers",
    "reset_handlers",
    "get_scan_history",
    "PARSER_QUALITY_THRESHOLD",
    "MAX_SCAN_HISTORY_PER_ORG",
]
