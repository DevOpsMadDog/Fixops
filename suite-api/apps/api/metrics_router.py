"""Prometheus Metrics Router — ALDECI.

Exposes a Prometheus-compatible text endpoint for Grafana/monitoring integration.
No external dependencies — uses Prometheus exposition format (text/plain).

Routes:
  GET  /api/v1/metrics/prometheus   Prometheus text format metrics
  GET  /api/v1/metrics/summary      JSON summary of key metrics (convenience)
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/metrics", tags=["Metrics"])

_START_TIME = time.monotonic()

# Approximate engine count — updated as engines are added
_ENGINE_COUNT = 344

# Known frameworks for compliance metrics
_COMPLIANCE_FRAMEWORKS = ["SOC2", "PCI-DSS", "HIPAA", "ISO27001", "NIST"]

# Default org used when pulling aggregated cross-org metrics
_METRICS_ORG = os.getenv("METRICS_ORG_ID", "default")


# ---------------------------------------------------------------------------
# Lazy engine accessors
# ---------------------------------------------------------------------------

_alert_engine = None
_posture_engine = None
_compliance_engine = None


def _get_alert_engine():
    global _alert_engine
    if _alert_engine is None:
        from core.alert_triage_engine import AlertTriageEngine
        _alert_engine = AlertTriageEngine()
    return _alert_engine


def _get_posture_engine():
    global _posture_engine
    if _posture_engine is None:
        from core.posture_score_engine import PostureScoreEngine
        _posture_engine = PostureScoreEngine()
    return _posture_engine


def _get_compliance_engine():
    global _compliance_engine
    if _compliance_engine is None:
        try:
            from core.compliance_scanner_engine import ComplianceScannerEngine
            _compliance_engine = ComplianceScannerEngine()
        except Exception:
            _compliance_engine = None
    return _compliance_engine


# ---------------------------------------------------------------------------
# Metric collection helpers
# ---------------------------------------------------------------------------

def _collect_alert_metrics(org_id: str) -> Dict[str, Any]:
    """Pull severity counts from AlertTriageEngine stats."""
    try:
        stats = _get_alert_engine().get_triage_stats(org_id)
        by_severity = stats.get("by_severity", {})
        return {
            "critical": int(by_severity.get("critical", 0)),
            "high": int(by_severity.get("high", 0)),
            "medium": int(by_severity.get("medium", 0)),
            "low": int(by_severity.get("low", 0)),
            "info": int(by_severity.get("info", 0)),
            "total": int(stats.get("total", 0)),
            "false_positive_rate": float(stats.get("false_positive_rate", 0.0)),
            "avg_triage_time_minutes": float(stats.get("avg_triage_time_minutes", 0.0)),
        }
    except Exception as exc:
        _logger.warning("metrics: alert engine unavailable: %s", exc)
        return {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
                "total": 0, "false_positive_rate": 0.0, "avg_triage_time_minutes": 0.0}


def _collect_posture_metrics(org_id: str) -> Dict[str, Any]:
    """Pull overall posture score from PostureScoreEngine."""
    try:
        result = _get_posture_engine().compute_posture_score(org_id)
        return {
            "overall_score": float(result.get("overall_score", 0.0)),
            "grade": result.get("grade", "F"),
        }
    except Exception as exc:
        _logger.warning("metrics: posture engine unavailable: %s", exc)
        return {"overall_score": 0.0, "grade": "F"}


def _collect_compliance_metrics(org_id: str) -> Dict[str, float]:
    """Pull per-framework compliance scores."""
    scores: Dict[str, float] = {}
    try:
        engine = _get_compliance_engine()
        if engine is None:
            return scores
        stats = engine.get_compliance_stats(org_id)
        framework_scores = stats.get("framework_scores", {})
        for framework, score in framework_scores.items():
            scores[str(framework).upper()] = float(score)
    except Exception as exc:
        _logger.warning("metrics: compliance engine unavailable: %s", exc)
    return scores


def _uptime_seconds() -> float:
    return round(time.monotonic() - _START_TIME, 2)


# ---------------------------------------------------------------------------
# Prometheus exposition format builder
# ---------------------------------------------------------------------------

def _prom_line(metric: str, labels: Dict[str, str], value: float) -> str:
    """Format a single Prometheus metric line with optional labels."""
    if labels:
        label_str = ",".join(f'{k}="{v}"' for k, v in labels.items())
        return f"{metric}{{{label_str}}} {value}"
    return f"{metric} {value}"


def _build_prometheus_text(org_id: str) -> str:
    """Build the full Prometheus exposition text body."""
    lines: List[str] = []

    # ── Alert metrics ────────────────────────────────────────────────────────
    alerts = _collect_alert_metrics(org_id)

    lines.append("# HELP aldeci_alerts_total Total alerts by severity")
    lines.append("# TYPE aldeci_alerts_total gauge")
    for sev in ("critical", "high", "medium", "low", "info"):
        lines.append(_prom_line("aldeci_alerts_total", {"severity": sev}, alerts[sev]))

    lines.append("# HELP aldeci_alerts_false_positive_rate False positive rate percent")
    lines.append("# TYPE aldeci_alerts_false_positive_rate gauge")
    lines.append(_prom_line("aldeci_alerts_false_positive_rate", {}, alerts["false_positive_rate"]))

    lines.append("# HELP aldeci_alert_triage_time_minutes Average triage time in minutes")
    lines.append("# TYPE aldeci_alert_triage_time_minutes gauge")
    lines.append(_prom_line("aldeci_alert_triage_time_minutes", {}, alerts["avg_triage_time_minutes"]))

    # ── Posture score ────────────────────────────────────────────────────────
    posture = _collect_posture_metrics(org_id)

    lines.append("# HELP aldeci_posture_score Overall security posture score (0-100)")
    lines.append("# TYPE aldeci_posture_score gauge")
    lines.append(_prom_line("aldeci_posture_score", {}, posture["overall_score"]))

    # ── Compliance scores ────────────────────────────────────────────────────
    compliance = _collect_compliance_metrics(org_id)

    lines.append("# HELP aldeci_compliance_score Compliance score by framework (0-100)")
    lines.append("# TYPE aldeci_compliance_score gauge")
    for framework, score in compliance.items():
        lines.append(_prom_line("aldeci_compliance_score", {"framework": framework}, score))

    # ── Engine count ─────────────────────────────────────────────────────────
    lines.append("# HELP aldeci_engine_count Number of active backend engines")
    lines.append("# TYPE aldeci_engine_count gauge")
    lines.append(_prom_line("aldeci_engine_count", {}, float(_ENGINE_COUNT)))

    # ── Uptime ───────────────────────────────────────────────────────────────
    lines.append("# HELP aldeci_uptime_seconds API process uptime in seconds")
    lines.append("# TYPE aldeci_uptime_seconds counter")
    lines.append(_prom_line("aldeci_uptime_seconds", {}, _uptime_seconds()))

    # ── Scrape timestamp ─────────────────────────────────────────────────────
    lines.append("# HELP aldeci_scrape_timestamp_seconds Unix timestamp of last scrape")
    lines.append("# TYPE aldeci_scrape_timestamp_seconds gauge")
    now_ts = datetime.now(timezone.utc).timestamp()
    lines.append(_prom_line("aldeci_scrape_timestamp_seconds", {}, round(now_ts, 3)))

    # Prometheus exposition format ends with a trailing newline
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get(
    "/prometheus",
    response_class=PlainTextResponse,
    dependencies=[Depends(api_key_auth)],
    summary="Prometheus metrics endpoint",
    description=(
        "Returns metrics in Prometheus text exposition format. "
        "Scrape with Prometheus or Grafana Agent. "
        "Pass ?org_id=<id> to scope metrics to a specific organisation."
    ),
)
def prometheus_metrics(org_id: str = _METRICS_ORG) -> PlainTextResponse:
    """Return Prometheus exposition format metrics for Grafana/monitoring."""
    body = _build_prometheus_text(org_id)
    return PlainTextResponse(
        content=body,
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@router.get(
    "/summary",
    dependencies=[Depends(api_key_auth)],
    summary="JSON metrics summary",
)
def metrics_summary(org_id: str = _METRICS_ORG) -> Dict[str, Any]:
    """Return key metrics as JSON — convenience endpoint for dashboards."""
    alerts = _collect_alert_metrics(org_id)
    posture = _collect_posture_metrics(org_id)
    compliance = _collect_compliance_metrics(org_id)
    return {
        "org_id": org_id,
        "alerts": alerts,
        "posture": posture,
        "compliance": compliance,
        "engine_count": _ENGINE_COUNT,
        "uptime_seconds": _uptime_seconds(),
        "scraped_at": datetime.now(timezone.utc).isoformat(),
    }
