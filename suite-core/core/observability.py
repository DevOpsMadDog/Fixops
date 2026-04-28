"""Monitoring and observability module for ALDECI/FixOps.

Provides:
- HealthProbe: liveness, readiness, startup checks
- MetricsCollector: Prometheus-compatible metrics
- AlertRule / AlertManager: rule evaluation, firing, dedup, history
- LogAggregator: structured JSON logging with correlation IDs and search
- TracingContext: request tracing with span IDs and parent-child relationships
"""

from __future__ import annotations

import logging
import statistics
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# HealthProbe
# ---------------------------------------------------------------------------


class SubsystemStatus(BaseModel):
    """Status of a single subsystem."""

    name: str
    healthy: bool
    latency_ms: float = 0.0
    detail: Optional[str] = None


class ProbeResult(BaseModel):
    """Result of a health probe check."""

    status: str  # "ok" | "degraded" | "unavailable"
    timestamp: str
    checks: List[SubsystemStatus] = Field(default_factory=list)
    uptime_seconds: float = 0.0


class HealthProbe:
    """Liveness, readiness, and startup health probes.

    Each probe checks different subsystems:
    - liveness (/healthz):  Is the process alive? Checks memory and event loop.
    - readiness (/readyz):  Can the service handle traffic? Checks DB, queue depth.
    - startup (/startupz):  Has initialisation completed? One-shot flag.
    """

    def __init__(self) -> None:
        self._started_at: float = time.monotonic()
        self._startup_complete: bool = False
        self._db_check: Optional[Callable[[], bool]] = None
        self._queue_check: Optional[Callable[[], int]] = None
        self._max_queue_depth: int = 10_000

    # ------------------------------------------------------------------
    # Configuration helpers
    # ------------------------------------------------------------------

    def set_db_check(self, fn: Callable[[], bool]) -> None:
        """Register a callable that returns True when the DB is reachable."""
        self._db_check = fn

    def set_queue_check(self, fn: Callable[[], int]) -> None:
        """Register a callable that returns the current queue depth."""
        self._queue_check = fn

    def mark_startup_complete(self) -> None:
        """Signal that application initialisation has finished."""
        self._startup_complete = True

    # ------------------------------------------------------------------
    # Probes
    # ------------------------------------------------------------------

    def liveness(self) -> ProbeResult:
        """Liveness check — is the process alive?

        Checks:
        - Process memory is accessible (trivially true if we're running)
        - Event loop is responsive (we're executing synchronously)
        """
        checks: List[SubsystemStatus] = []
        uptime = time.monotonic() - self._started_at

        # Memory check — try allocating a small object
        t0 = time.monotonic()
        try:
            _ = bytearray(1024)
            checks.append(SubsystemStatus(name="memory", healthy=True, latency_ms=round((time.monotonic() - t0) * 1000, 2)))
        except MemoryError as exc:
            checks.append(SubsystemStatus(name="memory", healthy=False, detail=str(exc)))

        # Process time check (confirms event loop isn't blocked)
        t0 = time.monotonic()
        _ = time.process_time()
        checks.append(SubsystemStatus(name="event_loop", healthy=True, latency_ms=round((time.monotonic() - t0) * 1000, 2)))

        all_healthy = all(c.healthy for c in checks)
        return ProbeResult(
            status="ok" if all_healthy else "unavailable",
            timestamp=datetime.now(timezone.utc).isoformat(),
            checks=checks,
            uptime_seconds=round(uptime, 2),
        )

    def readiness(self) -> ProbeResult:
        """Readiness check — can the service handle traffic?

        Checks:
        - Database connectivity (if db_check registered)
        - Queue depth within acceptable bounds (if queue_check registered)
        """
        checks: List[SubsystemStatus] = []
        uptime = time.monotonic() - self._started_at

        # DB check
        t0 = time.monotonic()
        if self._db_check is not None:
            try:
                ok = self._db_check()
                latency = round((time.monotonic() - t0) * 1000, 2)
                checks.append(SubsystemStatus(name="database", healthy=ok, latency_ms=latency, detail=None if ok else "DB check returned False"))
            except Exception as exc:
                latency = round((time.monotonic() - t0) * 1000, 2)
                checks.append(SubsystemStatus(name="database", healthy=False, latency_ms=latency, detail=str(exc)))
        else:
            checks.append(SubsystemStatus(name="database", healthy=True, detail="no check registered"))

        # Queue depth check
        if self._queue_check is not None:
            t0 = time.monotonic()
            try:
                depth = self._queue_check()
                latency = round((time.monotonic() - t0) * 1000, 2)
                ok = depth < self._max_queue_depth
                checks.append(SubsystemStatus(name="queue", healthy=ok, latency_ms=latency, detail=f"depth={depth}" if not ok else None))
            except Exception as exc:
                checks.append(SubsystemStatus(name="queue", healthy=False, detail=str(exc)))
        else:
            checks.append(SubsystemStatus(name="queue", healthy=True, detail="no check registered"))

        all_healthy = all(c.healthy for c in checks)
        return ProbeResult(
            status="ok" if all_healthy else "degraded",
            timestamp=datetime.now(timezone.utc).isoformat(),
            checks=checks,
            uptime_seconds=round(uptime, 2),
        )

    def startup(self) -> ProbeResult:
        """Startup check — has initialisation completed?"""
        uptime = time.monotonic() - self._started_at
        checks = [
            SubsystemStatus(
                name="startup",
                healthy=self._startup_complete,
                detail="complete" if self._startup_complete else "initialising",
            )
        ]
        return ProbeResult(
            status="ok" if self._startup_complete else "unavailable",
            timestamp=datetime.now(timezone.utc).isoformat(),
            checks=checks,
            uptime_seconds=round(uptime, 2),
        )


# ---------------------------------------------------------------------------
# MetricsCollector
# ---------------------------------------------------------------------------

_HISTOGRAM_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)


class MetricsCollector:
    """Prometheus-compatible metrics collector.

    Tracks:
    - request_count: total HTTP requests by method/path/status
    - request_latency: latency histogram (seconds)
    - error_rate: errors per second (rolling 60 s window)
    - active_connections: current concurrent connections
    - queue_depth: current queue depth
    - db_query_time: DB query latency histogram
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()

        # Counters: (method, path, status_code) -> count
        self._request_counts: Dict[Tuple[str, str, int], int] = defaultdict(int)

        # Histograms: name -> list of observed values
        self._latency_samples: Deque[float] = deque(maxlen=10_000)
        self._db_query_samples: Deque[float] = deque(maxlen=10_000)

        # Gauges
        self._active_connections: int = 0
        self._queue_depth: int = 0

        # Error window: timestamps of errors in last 60 s
        self._error_timestamps: Deque[float] = deque(maxlen=50_000)

        # Total request + error counters (monotonic)
        self._total_requests: int = 0
        self._total_errors: int = 0

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record_request(self, method: str, path: str, status_code: int, latency_seconds: float) -> None:
        """Record a completed HTTP request."""
        with self._lock:
            self._request_counts[(method.upper(), path, status_code)] += 1
            self._total_requests += 1
            self._latency_samples.append(latency_seconds)
            if status_code >= 500:
                self._error_timestamps.append(time.monotonic())
                self._total_errors += 1

    def record_db_query(self, latency_seconds: float) -> None:
        """Record a DB query latency sample."""
        with self._lock:
            self._db_query_samples.append(latency_seconds)

    def inc_connections(self) -> None:
        """Increment active connection gauge."""
        with self._lock:
            self._active_connections += 1

    def dec_connections(self) -> None:
        """Decrement active connection gauge."""
        with self._lock:
            self._active_connections = max(0, self._active_connections - 1)

    def set_queue_depth(self, depth: int) -> None:
        """Set current queue depth gauge."""
        with self._lock:
            self._queue_depth = depth

    # ------------------------------------------------------------------
    # Reading
    # ------------------------------------------------------------------

    def _histogram_buckets(self, samples: Deque[float]) -> Dict[str, int]:
        """Return bucket counts for Prometheus histogram."""
        buckets: Dict[str, int] = {}
        sample_list = list(samples)
        for le in _HISTOGRAM_BUCKETS:
            buckets[str(le)] = sum(1 for s in sample_list if s <= le)
        buckets["+Inf"] = len(sample_list)
        return buckets

    def error_rate(self, window_seconds: float = 60.0) -> float:
        """Errors per second over the last ``window_seconds``."""
        with self._lock:
            now = time.monotonic()
            cutoff = now - window_seconds
            recent = sum(1 for ts in self._error_timestamps if ts >= cutoff)
            return round(recent / window_seconds, 4)

    def snapshot(self) -> Dict[str, Any]:
        """Return a full metrics snapshot."""
        with self._lock:
            latency_list = list(self._latency_samples)
            db_list = list(self._db_query_samples)
            request_counts = dict(self._request_counts)
            active = self._active_connections
            queue = self._queue_depth
            total_req = self._total_requests
            total_err = self._total_errors

        lat_mean = round(statistics.mean(latency_list), 6) if latency_list else 0.0
        lat_p50 = round(statistics.median(latency_list), 6) if latency_list else 0.0
        lat_p95 = round(sorted(latency_list)[int(len(latency_list) * 0.95)], 6) if len(latency_list) >= 20 else lat_p50
        lat_p99 = round(sorted(latency_list)[int(len(latency_list) * 0.99)], 6) if len(latency_list) >= 100 else lat_p95

        db_mean = round(statistics.mean(db_list), 6) if db_list else 0.0

        return {
            "total_requests": total_req,
            "total_errors": total_err,
            "active_connections": active,
            "queue_depth": queue,
            "error_rate_per_sec": self.error_rate(),
            "latency": {
                "mean_seconds": lat_mean,
                "p50_seconds": lat_p50,
                "p95_seconds": lat_p95,
                "p99_seconds": lat_p99,
                "sample_count": len(latency_list),
                "histogram_buckets": self._histogram_buckets(self._latency_samples),
            },
            "db_query_time": {
                "mean_seconds": db_mean,
                "sample_count": len(db_list),
                "histogram_buckets": self._histogram_buckets(self._db_query_samples),
            },
            "request_counts": {
                f"{m} {p} {s}": c for (m, p, s), c in request_counts.items()
            },
        }

    def prometheus_text(self) -> str:
        """Render metrics in Prometheus text exposition format."""
        snap = self.snapshot()
        lines: List[str] = []

        def _counter(name: str, value: Any, labels: str = "") -> None:
            lines.append(f"# TYPE {name} counter")
            label_str = f"{{{labels}}}" if labels else ""
            lines.append(f"{name}{label_str} {value}")

        def _gauge(name: str, value: Any, labels: str = "") -> None:
            lines.append(f"# TYPE {name} gauge")
            label_str = f"{{{labels}}}" if labels else ""
            lines.append(f"{name}{label_str} {value}")

        def _histogram(name: str, buckets: Dict[str, int], count: int, mean: float) -> None:
            lines.append(f"# TYPE {name} histogram")
            for le, c in buckets.items():
                lines.append(f'{name}_bucket{{le="{le}"}} {c}')
            lines.append(f"{name}_count {count}")
            lines.append(f"{name}_sum {round(mean * count, 6)}")

        _counter("fixops_requests_total", snap["total_requests"])
        _counter("fixops_errors_total", snap["total_errors"])
        _gauge("fixops_active_connections", snap["active_connections"])
        _gauge("fixops_queue_depth", snap["queue_depth"])
        _gauge("fixops_error_rate", snap["error_rate_per_sec"])

        lat = snap["latency"]
        _histogram("fixops_request_duration_seconds", lat["histogram_buckets"], lat["sample_count"], lat["mean_seconds"])

        db = snap["db_query_time"]
        _histogram("fixops_db_query_duration_seconds", db["histogram_buckets"], db["sample_count"], db["mean_seconds"])

        for label, count in snap["request_counts"].items():
            parts = label.split(" ", 2)
            if len(parts) == 3:
                method, path, status = parts
                lines.append(f'fixops_requests_by_endpoint_total{{method="{method}",path="{path}",status="{status}"}} {count}')

        return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# AlertRule / AlertManager
# ---------------------------------------------------------------------------

_VALID_CONDITIONS = {"gt", "lt", "gte", "lte", "eq"}


class AlertRule(BaseModel):
    """Definition of an alert rule evaluated against collected metrics."""

    name: str = Field(..., min_length=1, max_length=128)
    metric_key: str = Field(..., description="Dot-path into MetricsCollector.snapshot() output")
    condition: str = Field(..., description="Comparison: gt | lt | gte | lte | eq")
    threshold: float
    action: str = Field(default="log", description="What to do when fired: log | webhook | page")
    cooldown_seconds: float = Field(default=300.0, ge=0.0, description="Min seconds between repeated fires")
    severity: str = Field(default="warning", description="critical | warning | info")

    def evaluate(self, value: float) -> bool:
        """Return True if the rule condition is met."""
        if self.condition == "gt":
            return value > self.threshold
        if self.condition == "lt":
            return value < self.threshold
        if self.condition == "gte":
            return value >= self.threshold
        if self.condition == "lte":
            return value <= self.threshold
        if self.condition == "eq":
            return value == self.threshold
        return False


class FiredAlert(BaseModel):
    """A record of a fired alert."""

    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_name: str
    metric_key: str
    metric_value: float
    threshold: float
    condition: str
    severity: str
    action: str
    fired_at: str
    resolved: bool = False
    resolved_at: Optional[str] = None


def _get_nested(data: Dict[str, Any], dot_path: str) -> Optional[float]:
    """Retrieve a nested value from a dict using dot notation."""
    parts = dot_path.split(".")
    current: Any = data
    for part in parts:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    if current is None:
        return None
    try:
        return float(current)
    except (TypeError, ValueError):
        return None


class AlertManager:
    """Evaluate alert rules against live metrics, fire alerts, track history.

    Features:
    - Rule CRUD
    - Metric snapshot evaluation
    - Cooldown deduplication (won't re-fire within cooldown window)
    - Active + historical alert tracking
    """

    _MAX_HISTORY = 1000

    def __init__(self, metrics: MetricsCollector) -> None:
        self._metrics = metrics
        self._rules: Dict[str, AlertRule] = {}
        self._active_alerts: Dict[str, FiredAlert] = {}  # rule_name -> latest active
        self._history: Deque[FiredAlert] = deque(maxlen=self._MAX_HISTORY)
        self._last_fired: Dict[str, float] = {}  # rule_name -> monotonic timestamp
        self._lock = threading.Lock()

    def add_rule(self, rule: AlertRule) -> None:
        """Add or replace an alert rule."""
        with self._lock:
            self._rules[rule.name] = rule

    def remove_rule(self, name: str) -> bool:
        """Remove a rule by name. Returns True if it existed."""
        with self._lock:
            return self._rules.pop(name, None) is not None

    def list_rules(self) -> List[AlertRule]:
        """Return all registered rules."""
        with self._lock:
            return list(self._rules.values())

    def evaluate(self) -> List[FiredAlert]:
        """Evaluate all rules against current metrics. Returns newly fired alerts."""
        snap = self._metrics.snapshot()
        newly_fired: List[FiredAlert] = []
        now_mono = time.monotonic()
        now_iso = datetime.now(timezone.utc).isoformat()

        with self._lock:
            for rule in self._rules.values():
                value = _get_nested(snap, rule.metric_key)
                if value is None:
                    continue

                triggered = rule.evaluate(value)

                if triggered:
                    # Check cooldown
                    last = self._last_fired.get(rule.name, 0.0)
                    if (now_mono - last) < rule.cooldown_seconds:
                        continue  # still in cooldown, skip

                    alert = FiredAlert(
                        rule_name=rule.name,
                        metric_key=rule.metric_key,
                        metric_value=value,
                        threshold=rule.threshold,
                        condition=rule.condition,
                        severity=rule.severity,
                        action=rule.action,
                        fired_at=now_iso,
                    )
                    self._active_alerts[rule.name] = alert
                    self._history.append(alert)
                    self._last_fired[rule.name] = now_mono
                    newly_fired.append(alert)

                    logger.warning(
                        "Alert fired: rule=%s metric=%s value=%s threshold=%s action=%s",
                        rule.name, rule.metric_key, value, rule.threshold, rule.action,
                    )
                else:
                    # Resolve active alert if condition no longer met
                    if rule.name in self._active_alerts:
                        resolved = self._active_alerts.pop(rule.name)
                        resolved.resolved = True
                        resolved.resolved_at = now_iso

        return newly_fired

    def active_alerts(self) -> List[FiredAlert]:
        """Return currently active (unresolved) alerts."""
        with self._lock:
            return list(self._active_alerts.values())

    def alert_history(self, limit: int = 100) -> List[FiredAlert]:
        """Return recent alert history (newest first)."""
        with self._lock:
            items = list(self._history)
        return list(reversed(items))[:limit]

    def clear_active(self, rule_name: str) -> bool:
        """Manually resolve an active alert. Returns True if it was active."""
        with self._lock:
            if rule_name in self._active_alerts:
                alert = self._active_alerts.pop(rule_name)
                alert.resolved = True
                alert.resolved_at = datetime.now(timezone.utc).isoformat()
                return True
            return False


# ---------------------------------------------------------------------------
# LogAggregator
# ---------------------------------------------------------------------------

_LOG_LEVEL_ORDER = {"debug": 0, "info": 1, "warning": 2, "error": 3, "critical": 4}


class LogEntry(BaseModel):
    """A single structured log record."""

    log_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    level: str = "info"
    message: str
    correlation_id: Optional[str] = None
    trace_id: Optional[str] = None
    service: str = "fixops"
    extra: Dict[str, Any] = Field(default_factory=dict)


class LogAggregator:
    """In-memory structured JSON log aggregator with search capability.

    Supports:
    - emit(): write a log entry at a given level
    - search(): filter by level, correlation_id, substring
    - Bounded ring-buffer (default 10,000 entries)
    """

    def __init__(self, max_entries: int = 10_000, min_level: str = "debug") -> None:
        self._entries: Deque[LogEntry] = deque(maxlen=max_entries)
        self._min_level = min_level.lower()
        self._lock = threading.Lock()

    def _level_ok(self, level: str) -> bool:
        return _LOG_LEVEL_ORDER.get(level.lower(), 0) >= _LOG_LEVEL_ORDER.get(self._min_level, 0)

    def emit(
        self,
        message: str,
        level: str = "info",
        correlation_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        service: str = "fixops",
        **kwargs: Any,
    ) -> LogEntry:
        """Emit a structured log entry."""
        entry = LogEntry(
            level=level.lower(),
            message=message,
            correlation_id=correlation_id,
            trace_id=trace_id,
            service=service,
            extra=kwargs,
        )
        if self._level_ok(level):
            with self._lock:
                self._entries.append(entry)
            # Also forward to Python stdlib logger
            stdlib_level = _LOG_LEVEL_ORDER.get(level.lower(), 1)
            logger.log(max(10, stdlib_level * 10), "%s [cid=%s] %s", level.upper(), correlation_id, message)
        return entry

    def search(
        self,
        query: Optional[str] = None,
        level: Optional[str] = None,
        correlation_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        service: Optional[str] = None,
        limit: int = 100,
    ) -> List[LogEntry]:
        """Search log entries. All filters are ANDed."""
        with self._lock:
            entries = list(self._entries)

        results: List[LogEntry] = []
        for entry in reversed(entries):  # newest first
            if level and entry.level != level.lower():
                continue
            if correlation_id and entry.correlation_id != correlation_id:
                continue
            if trace_id and entry.trace_id != trace_id:
                continue
            if service and entry.service != service:
                continue
            if query and query.lower() not in entry.message.lower():
                continue
            results.append(entry)
            if len(results) >= limit:
                break
        return results

    def all_entries(self, limit: int = 500) -> List[LogEntry]:
        """Return recent log entries newest-first."""
        with self._lock:
            entries = list(self._entries)
        return list(reversed(entries))[:limit]

    def as_json_lines(self, limit: int = 500) -> str:
        """Return entries as newline-delimited JSON (NDJSON)."""
        entries = self.all_entries(limit=limit)
        return "\n".join(entry.model_dump_json() for entry in entries)

    def set_min_level(self, level: str) -> None:
        """Update the minimum log level filter."""
        self._min_level = level.lower()

    def stats(self) -> Dict[str, Any]:
        """Return counts by log level."""
        with self._lock:
            entries = list(self._entries)
        counts: Dict[str, int] = defaultdict(int)
        for e in entries:
            counts[e.level] += 1
        return {"total": len(entries), "by_level": dict(counts)}


# ---------------------------------------------------------------------------
# TracingContext
# ---------------------------------------------------------------------------


class Span(BaseModel):
    """A single tracing span."""

    span_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    trace_id: str
    parent_span_id: Optional[str] = None
    operation: str
    service: str = "fixops"
    started_at: float = Field(default_factory=time.monotonic)
    finished_at: Optional[float] = None
    duration_ms: Optional[float] = None
    tags: Dict[str, Any] = Field(default_factory=dict)
    status: str = "in_progress"  # "in_progress" | "ok" | "error"
    error: Optional[str] = None

    def finish(self, status: str = "ok", error: Optional[str] = None) -> None:
        """Mark span as finished."""
        self.finished_at = time.monotonic()
        self.duration_ms = round((self.finished_at - self.started_at) * 1000, 3)
        self.status = status
        self.error = error


class TracingContext:
    """Request tracing with span IDs and parent-child relationships.

    Usage::

        tracer = TracingContext()
        trace_id = tracer.start_trace("handle_request", service="api")
        child_span_id = tracer.start_span(trace_id, "db_query", parent_span_id=root_span_id)
        tracer.finish_span(child_span_id)
        tracer.finish_trace(trace_id)
    """

    _MAX_TRACES = 1000

    def __init__(self) -> None:
        self._spans: Dict[str, Span] = {}  # span_id -> Span
        self._traces: Dict[str, List[str]] = {}  # trace_id -> [span_ids]
        self._completed: Deque[str] = deque(maxlen=self._MAX_TRACES)
        self._lock = threading.Lock()

    def start_trace(
        self,
        operation: str,
        service: str = "fixops",
        tags: Optional[Dict[str, Any]] = None,
        trace_id: Optional[str] = None,
    ) -> Tuple[str, str]:
        """Start a new trace. Returns (trace_id, root_span_id)."""
        trace_id = trace_id or str(uuid.uuid4())
        span = Span(
            trace_id=trace_id,
            operation=operation,
            service=service,
            tags=tags or {},
        )
        with self._lock:
            self._spans[span.span_id] = span
            self._traces[trace_id] = [span.span_id]
        return trace_id, span.span_id

    def start_span(
        self,
        trace_id: str,
        operation: str,
        parent_span_id: Optional[str] = None,
        service: str = "fixops",
        tags: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Add a child span to an existing trace. Returns span_id."""
        span = Span(
            trace_id=trace_id,
            parent_span_id=parent_span_id,
            operation=operation,
            service=service,
            tags=tags or {},
        )
        with self._lock:
            self._spans[span.span_id] = span
            if trace_id in self._traces:
                self._traces[trace_id].append(span.span_id)
            else:
                self._traces[trace_id] = [span.span_id]
        return span.span_id

    def finish_span(
        self,
        span_id: str,
        status: str = "ok",
        error: Optional[str] = None,
        tags: Optional[Dict[str, Any]] = None,
    ) -> Optional[Span]:
        """Finish a span by ID."""
        with self._lock:
            span = self._spans.get(span_id)
        if span is None:
            return None
        span.finish(status=status, error=error)
        if tags:
            span.tags.update(tags)
        return span

    def finish_trace(self, trace_id: str) -> List[Span]:
        """Mark all unfinished spans in a trace as finished and archive it."""
        with self._lock:
            span_ids = self._traces.get(trace_id, [])
            spans: List[Span] = []
            for sid in span_ids:
                span = self._spans.get(sid)
                if span:
                    if span.finished_at is None:
                        span.finish(status="ok")
                    spans.append(span)
            self._completed.append(trace_id)
        return spans

    def get_trace(self, trace_id: str) -> List[Span]:
        """Return all spans for a trace."""
        with self._lock:
            span_ids = self._traces.get(trace_id, [])
            return [self._spans[sid] for sid in span_ids if sid in self._spans]

    def get_span(self, span_id: str) -> Optional[Span]:
        """Return a span by ID."""
        with self._lock:
            return self._spans.get(span_id)

    def recent_traces(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return summaries of recently completed traces."""
        with self._lock:
            completed = list(self._completed)
        results = []
        for trace_id in reversed(completed[-limit:]):
            spans = self.get_trace(trace_id)
            if not spans:
                continue
            root = next((s for s in spans if s.parent_span_id is None), spans[0])
            total_ms = sum(s.duration_ms or 0.0 for s in spans)
            # Collect span attributes for enrichment (org_id, engine_name etc.)
            attrs: Dict[str, Any] = {}
            for s in spans:
                attrs.update(s.tags)
            results.append({
                "trace_id": trace_id,
                "operation": root.operation,
                "service": root.service,
                "span_count": len(spans),
                "total_duration_ms": round(total_ms, 3),
                "status": root.status,
                "started_at": root.started_at,
                "org_id": attrs.get("org_id"),
                "engine_name": attrs.get("engine_name"),
            })
        return results

    def export_trace(self, trace_id: str) -> Dict[str, Any]:
        """Export a full trace as a JSON-serialisable dict."""
        spans = self.get_trace(trace_id)
        return {
            "trace_id": trace_id,
            "spans": [
                {
                    "span_id": s.span_id,
                    "parent_span_id": s.parent_span_id,
                    "operation": s.operation,
                    "service": s.service,
                    "status": s.status,
                    "duration_ms": s.duration_ms,
                    "tags": s.tags,
                    "error": s.error,
                }
                for s in spans
            ],
        }


# ---------------------------------------------------------------------------
# Module-level singletons (shared across the application)
# ---------------------------------------------------------------------------

_health_probe = HealthProbe()
_metrics_collector = MetricsCollector()
_alert_manager = AlertManager(_metrics_collector)
_log_aggregator = LogAggregator()
_tracing_context = TracingContext()


def get_health_probe() -> HealthProbe:
    """Return the global HealthProbe instance."""
    return _health_probe


def get_metrics_collector() -> MetricsCollector:
    """Return the global MetricsCollector instance."""
    return _metrics_collector


def get_alert_manager() -> AlertManager:
    """Return the global AlertManager instance."""
    return _alert_manager


def get_log_aggregator() -> LogAggregator:
    """Return the global LogAggregator instance."""
    return _log_aggregator


def get_tracing_context() -> TracingContext:
    """Return the global TracingContext instance."""
    return _tracing_context
