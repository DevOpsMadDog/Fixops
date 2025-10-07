"""Prometheus metrics utilities for FixOps observability."""

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

_registry = CollectorRegistry()

# HTTP surface metrics
HTTP_REQUESTS = Counter(
    "fixops_http_requests_total",
    "Total HTTP requests processed",
    ["endpoint", "method", "status"],
    registry=_registry,
)
HTTP_LATENCY = Histogram(
    "fixops_http_request_seconds",
    "HTTP request duration in seconds",
    ["endpoint"],
    registry=_registry,
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5),
)

# Decision engine metrics
ENGINE_DECISIONS = Counter(
    "fixops_engine_decisions_total",
    "Decisions produced by verdict",
    ["verdict"],
    registry=_registry,
)
DECISION_LATENCY = Histogram(
    "fixops_decision_latency_seconds",
    "Decision engine processing latency",
    ["verdict"],
    registry=_registry,
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2, 5),
)
DECISION_CONFIDENCE = Gauge(
    "fixops_decision_confidence_latest",
    "Confidence score of the most recent decision",
    registry=_registry,
)
DECISION_ERRORS = Counter(
    "fixops_decision_errors_total",
    "Decision engine errors by reason",
    ["reason"],
    registry=_registry,
)

# Evidence lake metrics
EVIDENCE_REQUESTS = Counter(
    "fixops_evidence_requests_total",
    "Evidence retrieval outcomes",
    ["source", "status"],
    registry=_registry,
)
EVIDENCE_LATENCY = Histogram(
    "fixops_evidence_request_seconds",
    "Evidence retrieval duration in seconds",
    ["source", "status"],
    registry=_registry,
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2),
)

# Policy gate metrics
POLICY_EVALUATIONS = Counter(
    "fixops_policy_evaluations_total",
    "Total policy evaluations by outcome",
    ["outcome"],
    registry=_registry,
)
POLICY_LATENCY = Histogram(
    "fixops_policy_evaluation_seconds",
    "Policy evaluation latency",
    ["outcome"],
    registry=_registry,
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1),
)
POLICY_BLOCK_RATIO = Gauge(
    "fixops_policy_block_ratio",
    "Rolling ratio of blocked policy evaluations",
    registry=_registry,
)

# Miscellaneous operational metrics
UPLOADS_COMPLETED = Counter(
    "fixops_uploads_completed_total",
    "Completed uploads by scan type",
    ["scan_type"],
    registry=_registry,
)


class FixOpsMetrics:
    """Static helpers for recording FixOps metrics safely."""

    _policy_total: int = 0
    _policy_blocked: int = 0

    @staticmethod
    def get_metrics() -> bytes:
        return generate_latest(_registry)

    @staticmethod
    def record_request(endpoint: str, method: str, status: int, duration: float) -> None:
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

    @staticmethod
    def record_decision(verdict: str, confidence: float, duration_seconds: float) -> None:
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
    def record_evidence_request(source: str, status: str, duration_seconds: float) -> None:
        try:
            EVIDENCE_REQUESTS.labels(source=source, status=status).inc()
            EVIDENCE_LATENCY.labels(source=source, status=status).observe(duration_seconds)
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
