"""Observability API router — health, metrics, traces, alerts, logs.

Endpoints:
    GET  /api/v1/observability/healthz          — liveness probe
    GET  /api/v1/observability/readyz           — readiness probe
    GET  /api/v1/observability/startupz         — startup probe
    GET  /api/v1/observability/metrics          — Prometheus text format
    GET  /api/v1/observability/metrics/json     — metrics snapshot as JSON
    GET  /api/v1/observability/traces           — recent completed traces (JSON)
    GET  /api/v1/observability/alerts           — active alerts
    GET  /api/v1/observability/alerts/history   — alert history
    POST /api/v1/observability/alerts/rules     — add alert rule
    DELETE /api/v1/observability/alerts/rules/{name} — remove alert rule
    GET  /api/v1/observability/logs             — log search
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from core.observability import (
    AlertRule,
    ProbeResult,
    get_alert_manager,
    get_health_probe,
    get_log_aggregator,
    get_metrics_collector,
    get_tracing_context,
)
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/observability", tags=["observability"])

# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class AlertRuleRequest(BaseModel):
    """Input model for creating an alert rule."""

    name: str = Field(..., min_length=1, max_length=128)
    metric_key: str = Field(..., min_length=1)
    condition: str = Field(..., description="gt | lt | gte | lte | eq")
    threshold: float
    action: str = Field(default="log")
    cooldown_seconds: float = Field(default=300.0, ge=0.0)
    severity: str = Field(default="warning")


class AlertRuleResponse(BaseModel):
    status: str
    rule_name: str


class MetricsSnapshotResponse(BaseModel):
    timestamp: str
    metrics: Dict[str, Any]


# ---------------------------------------------------------------------------
# Health probes
# ---------------------------------------------------------------------------


@router.get(
    "/healthz",
    response_model=ProbeResult,
    summary="Liveness probe — is the process alive?",
    tags=["observability"],
)
async def healthz() -> ProbeResult:
    """Liveness check. Returns 200 OK when the process is running.
    Returns 503 if memory is exhausted or the event loop is blocked.
    """
    probe = get_health_probe()
    result = probe.liveness()
    if result.status != "ok":
        raise HTTPException(status_code=503, detail=result.model_dump())
    return result


@router.get(
    "/readyz",
    response_model=ProbeResult,
    summary="Readiness probe — can the service handle traffic?",
    tags=["observability"],
)
async def readyz() -> ProbeResult:
    """Readiness check. Returns 200 when DB and queue are healthy.
    Returns 503 if any subsystem is degraded.
    """
    probe = get_health_probe()
    result = probe.readiness()
    if result.status not in ("ok",):
        raise HTTPException(status_code=503, detail=result.model_dump())
    return result


@router.get(
    "/startupz",
    response_model=ProbeResult,
    summary="Startup probe — has initialisation completed?",
    tags=["observability"],
)
async def startupz() -> ProbeResult:
    """Startup check. Returns 200 once mark_startup_complete() has been called.
    Returns 503 while the application is still initialising.
    """
    probe = get_health_probe()
    result = probe.startup()
    if result.status != "ok":
        raise HTTPException(status_code=503, detail=result.model_dump())
    return result


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


@router.get(
    "/metrics",
    response_class=PlainTextResponse,
    summary="Prometheus metrics endpoint",
    tags=["observability"],
)
async def prometheus_metrics() -> PlainTextResponse:
    """Return metrics in Prometheus text exposition format.
    Compatible with any Prometheus scraper pointing at this endpoint.
    """
    collector = get_metrics_collector()
    return PlainTextResponse(
        content=collector.prometheus_text(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@router.get(
    "/metrics/json",
    summary="Metrics snapshot as JSON",
    tags=["observability"],
)
async def metrics_json() -> Dict[str, Any]:
    """Return the full metrics snapshot as structured JSON.
    Includes request counts, latency histograms, error rates, queue depth, and DB times.
    """
    from datetime import datetime, timezone

    collector = get_metrics_collector()
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "metrics": collector.snapshot(),
    }


# ---------------------------------------------------------------------------
# Traces
# ---------------------------------------------------------------------------


@router.get(
    "/traces",
    summary="Recent completed traces",
    tags=["observability"],
)
async def list_traces(
    limit: int = Query(default=50, ge=1, le=500, description="Max traces to return"),
) -> Dict[str, Any]:
    """Return summaries of recently completed request traces."""
    tracer = get_tracing_context()
    traces = tracer.recent_traces(limit=limit)
    return {"count": len(traces), "traces": traces}


@router.get(
    "/traces/{trace_id}",
    summary="Get full trace by ID",
    tags=["observability"],
)
async def get_trace(trace_id: str) -> Dict[str, Any]:
    """Return the full span tree for a specific trace ID."""
    tracer = get_tracing_context()
    exported = tracer.export_trace(trace_id)
    if not exported["spans"]:
        raise HTTPException(status_code=404, detail=f"Trace '{trace_id}' not found")
    return exported


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


@router.get(
    "/alerts",
    summary="Active alerts",
    tags=["observability"],
)
async def active_alerts() -> Dict[str, Any]:
    """Return all currently active (unresolved) alerts."""
    mgr = get_alert_manager()
    # Evaluate rules first to refresh active state
    mgr.evaluate()
    alerts = mgr.active_alerts()
    return {"count": len(alerts), "alerts": [a.model_dump() for a in alerts]}


@router.get(
    "/alerts/history",
    summary="Alert history",
    tags=["observability"],
)
async def alert_history(
    limit: int = Query(default=100, ge=1, le=1000),
) -> Dict[str, Any]:
    """Return historical alert records (newest first)."""
    mgr = get_alert_manager()
    history = mgr.alert_history(limit=limit)
    return {"count": len(history), "history": [a.model_dump() for a in history]}


@router.post(
    "/alerts/rules",
    summary="Create alert rule",
    status_code=201,
    tags=["observability"],
)
async def create_alert_rule(body: AlertRuleRequest) -> AlertRuleResponse:
    """Add or replace an alert rule evaluated against live metrics."""
    valid_conditions = {"gt", "lt", "gte", "lte", "eq"}
    if body.condition not in valid_conditions:
        raise HTTPException(
            status_code=422,
            detail=f"condition must be one of {sorted(valid_conditions)}",
        )
    rule = AlertRule(
        name=body.name,
        metric_key=body.metric_key,
        condition=body.condition,
        threshold=body.threshold,
        action=body.action,
        cooldown_seconds=body.cooldown_seconds,
        severity=body.severity,
    )
    get_alert_manager().add_rule(rule)
    logger.info("Alert rule created: %s", rule.name)
    return AlertRuleResponse(status="created", rule_name=rule.name)


@router.delete(
    "/alerts/rules/{rule_name}",
    summary="Delete alert rule",
    tags=["observability"],
)
async def delete_alert_rule(rule_name: str) -> Dict[str, str]:
    """Remove an alert rule by name."""
    removed = get_alert_manager().remove_rule(rule_name)
    if not removed:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_name}' not found")
    logger.info("Alert rule deleted: %s", rule_name)
    return {"status": "deleted", "rule_name": rule_name}


@router.get(
    "/alerts/rules",
    summary="List alert rules",
    tags=["observability"],
)
async def list_alert_rules() -> Dict[str, Any]:
    """Return all registered alert rules."""
    rules = get_alert_manager().list_rules()
    return {"count": len(rules), "rules": [r.model_dump() for r in rules]}


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------


@router.get(
    "/logs",
    summary="Search structured logs",
    tags=["observability"],
)
async def search_logs(
    query: Optional[str] = Query(default=None, description="Substring to search in message"),
    level: Optional[str] = Query(default=None, description="Filter by level: debug|info|warning|error|critical"),
    correlation_id: Optional[str] = Query(default=None, description="Filter by correlation ID"),
    service: Optional[str] = Query(default=None, description="Filter by service name"),
    limit: int = Query(default=100, ge=1, le=1000),
) -> Dict[str, Any]:
    """Search structured log entries. All filters are ANDed. Results are newest-first."""
    agg = get_log_aggregator()
    entries = agg.search(
        query=query,
        level=level,
        correlation_id=correlation_id,
        service=service,
        limit=limit,
    )
    return {
        "count": len(entries),
        "logs": [e.model_dump() for e in entries],
    }


@router.get(
    "/logs/stats",
    summary="Log counts by level",
    tags=["observability"],
)
async def log_stats() -> Dict[str, Any]:
    """Return log entry counts grouped by level."""
    try:
        return get_log_aggregator().stats()
    except Exception:
        return {"by_level": {}, "total": 0, "since": None}
