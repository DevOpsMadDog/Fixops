"""Prometheus metrics utilities for FixOps."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, MutableMapping, Optional

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

_registry = CollectorRegistry()
HTTP_REQUESTS = Counter(
    "fixops_http_requests_total",
    "Total HTTP requests",
    ["endpoint", "method", "status"],
    registry=_registry,
)
HTTP_LATENCY = Histogram(
    "fixops_http_request_seconds",
    "HTTP request duration seconds",
    ["endpoint"],
    registry=_registry,
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5),
)
HTTP_ERROR_RATIO = Gauge(
    "fixops_http_error_ratio",
    "Rolling error ratio for grouped API families",
    ["family"],
    registry=_registry,
)
HTTP_INFLIGHT = Gauge(
    "fixops_http_inflight_requests",
    "Current in-flight HTTP requests",
    ["family"],
    registry=_registry,
)
HOT_PATH_LATENCY = Gauge(
    "fixops_hot_path_latency_us",
    "Last recorded latency for DecisionFactory hot-path endpoints (microseconds)",
    ["endpoint"],
    registry=_registry,
)
RATE_LIMIT_TRIGGER = Counter(
    "fixops_rate_limit_trigger_total",
    "Total requests rejected by rate limiting",
    registry=_registry,
)
SIGNING_KEY_AGE = Gauge(
    "fixops_signing_key_rotation_age_days",
    "Age of the active signing key material in days",
    ["provider"],
    registry=_registry,
)
SIGNING_KEY_HEALTH = Gauge(
    "fixops_signing_key_rotation_healthy",
    "Health indicator for signing key rotation SLAs",
    ["provider"],
    registry=_registry,
)
ENGINE_DECISIONS = Counter(
    "fixops_engine_decisions_total",
    "Decisions produced",
    ["verdict"],
    registry=_registry,
)
UPLOADS_COMPLETED = Counter(
    "fixops_uploads_completed_total",
    "Completed uploads",
    ["scan_type"],
    registry=_registry,
)


class FixOpsMetrics:
    """Facade for recording and interrogating observability metrics."""

    _family_totals: MutableMapping[str, Dict[str, int]] = defaultdict(
        lambda: {"total": 0, "errors": 0}
    )
    _inflight_counts: MutableMapping[str, int] = defaultdict(int)
    _observed_families: set[str] = set()
    _observed_hot_paths: set[str] = set()
    _hot_path_latency_us: MutableMapping[str, float] = {}
    _observed_key_providers: set[str] = set()
    _key_rotation_age: MutableMapping[str, float] = {}
    _key_rotation_health: MutableMapping[str, bool] = {}

    _HOT_PATH_PREFIXES = {
        "/api/v1/decisions/make-decision": "decision",
        "/api/v1/policy/evaluate": "policy",
        "/api/v1/decisions/evidence": "evidence",
    }

    @staticmethod
    def get_metrics() -> bytes:
        return generate_latest(_registry)

    # ------------------------------------------------------------------
    # HTTP instrumentation helpers
    # ------------------------------------------------------------------
    @staticmethod
    def request_started(endpoint: str) -> None:
        """Record that a request started so gauges reflect in-flight work."""

        family = FixOpsMetrics._classify_family(endpoint)
        FixOpsMetrics._observed_families.add(family)
        FixOpsMetrics._inflight_counts[family] += 1
        try:
            HTTP_INFLIGHT.labels(family=family).set(
                FixOpsMetrics._inflight_counts[family]
            )
        except Exception:
            pass

    @staticmethod
    def request_finished(endpoint: str) -> None:
        """Mark the request as finished for in-flight accounting."""

        family = FixOpsMetrics._classify_family(endpoint)
        FixOpsMetrics._observed_families.add(family)
        FixOpsMetrics._inflight_counts[family] = max(
            0, FixOpsMetrics._inflight_counts[family] - 1
        )
        try:
            HTTP_INFLIGHT.labels(family=family).set(
                FixOpsMetrics._inflight_counts[family]
            )
        except Exception:
            pass

    @staticmethod
    def record_request(
        endpoint: str, method: str, status: int, duration: float
    ) -> None:
        """Capture counters, ratios, and hot-path gauges for an HTTP request."""

        family = FixOpsMetrics._classify_family(endpoint)
        FixOpsMetrics._observed_families.add(family)
        try:
            HTTP_REQUESTS.labels(
                endpoint=endpoint,
                method=method,
                status=str(status),
            ).inc()
            HTTP_LATENCY.labels(endpoint=endpoint).observe(duration)
        except Exception:
            # Metrics must never break the hot path
            pass

        totals = FixOpsMetrics._family_totals[family]
        totals["total"] += 1
        if status >= 400:
            totals["errors"] += 1

        try:
            ratio = totals["errors"] / totals["total"] if totals["total"] > 0 else 0.0
            HTTP_ERROR_RATIO.labels(family=family).set(ratio)
        except Exception:
            pass

        hot_path_label = FixOpsMetrics._resolve_hot_path(endpoint)
        if hot_path_label:
            FixOpsMetrics._observed_hot_paths.add(hot_path_label)
            latency_us = duration * 1_000_000
            FixOpsMetrics._hot_path_latency_us[hot_path_label] = latency_us
            try:
                HOT_PATH_LATENCY.labels(endpoint=hot_path_label).set(latency_us)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Convenience accessors for testing and health diagnostics
    # ------------------------------------------------------------------
    @staticmethod
    def get_error_ratio(family: str) -> float:
        totals = FixOpsMetrics._family_totals.get(family, {"total": 0, "errors": 0})
        if totals["total"] == 0:
            return 0.0
        return totals["errors"] / totals["total"]

    @staticmethod
    def get_inflight(family: str) -> int:
        return FixOpsMetrics._inflight_counts.get(family, 0)

    @staticmethod
    def get_hot_path_latency_us(endpoint: str) -> Optional[float]:
        return FixOpsMetrics._hot_path_latency_us.get(endpoint)

    @staticmethod
    def reset_runtime_stats() -> None:
        """Reset derived runtime metrics so tests can assert fresh state."""

        for family in list(FixOpsMetrics._observed_families):
            FixOpsMetrics._family_totals[family] = {"total": 0, "errors": 0}
            FixOpsMetrics._inflight_counts[family] = 0
            try:
                HTTP_ERROR_RATIO.labels(family=family).set(0)
                HTTP_INFLIGHT.labels(family=family).set(0)
            except Exception:
                pass
        FixOpsMetrics._observed_families.clear()

    @staticmethod
    def rate_limit_triggered() -> None:
        """Increment the rate limiting counter, ignoring instrumentation failures."""

        try:
            RATE_LIMIT_TRIGGER.inc()
        except Exception:
            pass

        for endpoint in list(FixOpsMetrics._observed_hot_paths):
            FixOpsMetrics._hot_path_latency_us.pop(endpoint, None)
            try:
                HOT_PATH_LATENCY.labels(endpoint=endpoint).set(0)
            except Exception:
                pass
        FixOpsMetrics._observed_hot_paths.clear()

        for provider in list(FixOpsMetrics._observed_key_providers):
            FixOpsMetrics._key_rotation_age.pop(provider, None)
            FixOpsMetrics._key_rotation_health.pop(provider, None)
            try:
                SIGNING_KEY_AGE.labels(provider=provider).set(0)
                SIGNING_KEY_HEALTH.labels(provider=provider).set(0)
            except Exception:
                pass
        FixOpsMetrics._observed_key_providers.clear()

    # ------------------------------------------------------------------
    # Domain specific metrics
    # ------------------------------------------------------------------
    @staticmethod
    def record_decision(verdict: str) -> None:
        try:
            ENGINE_DECISIONS.labels(verdict=verdict).inc()
            DECISION_LATENCY.labels(verdict=verdict).observe(duration_seconds)
            DECISION_CONFIDENCE.set(confidence)
        except Exception:
            pass

    @staticmethod
    def record_decision_error(reason: str = "unknown") -> None:
        try:
            DECISION_ERRORS.labels(reason=reason).inc()
        except Exception:
            pass

    @staticmethod
    def record_evidence_request(
        source: str, status: str, duration_seconds: float
    ) -> None:
        try:
            EVIDENCE_REQUESTS.labels(source=source, status=status).inc()
            EVIDENCE_LATENCY.labels(source=source, status=status).observe(
                duration_seconds
            )
        except Exception:
            pass

    @classmethod
    def record_policy_evaluation(cls, outcome: str, duration_seconds: float) -> None:
        try:
            POLICY_EVALUATIONS.labels(outcome=outcome).inc()
            POLICY_LATENCY.labels(outcome=outcome).observe(duration_seconds)

            cls._policy_total += 1
            if outcome == "block":
                cls._policy_blocked += 1

            if cls._policy_total:
                POLICY_BLOCK_RATIO.set(cls._policy_blocked / cls._policy_total)
        except Exception:
            pass

    @staticmethod
    def record_upload(scan_type: str) -> None:
        try:
            UPLOADS_COMPLETED.labels(scan_type=scan_type).inc()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Key management helpers
    # ------------------------------------------------------------------
    @staticmethod
    def record_key_rotation(provider: str, age_days: float, healthy: bool) -> None:
        FixOpsMetrics._observed_key_providers.add(provider)
        FixOpsMetrics._key_rotation_age[provider] = age_days
        FixOpsMetrics._key_rotation_health[provider] = healthy
        try:
            SIGNING_KEY_AGE.labels(provider=provider).set(age_days)
            SIGNING_KEY_HEALTH.labels(provider=provider).set(1.0 if healthy else 0.0)
        except Exception:
            pass

    @staticmethod
    def get_key_rotation_age(provider: str) -> Optional[float]:
        return FixOpsMetrics._key_rotation_age.get(provider)

    @staticmethod
    def get_key_rotation_health(provider: str) -> Optional[bool]:
        return FixOpsMetrics._key_rotation_health.get(provider)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _classify_family(endpoint: str) -> str:
        if endpoint.startswith("/api/v1/policy"):
            return "policy"
        if endpoint.startswith("/api/v1/decisions/evidence"):
            return "evidence"
        if endpoint.startswith("/api/v1/decisions"):
            return "decision"
        return "other"

    @staticmethod
    def _resolve_hot_path(endpoint: str) -> Optional[str]:
        for prefix in FixOpsMetrics._HOT_PATH_PREFIXES:
            if endpoint.startswith(prefix):
                return prefix
        return None
