"""Enterprise monitoring and observability for reachability analysis."""

from __future__ import annotations

import logging
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, Mapping, Optional

from telemetry import get_meter, get_tracer

logger = logging.getLogger(__name__)

_TRACER = get_tracer("fixops.reachability")
_METER = get_meter("fixops.reachability")

# Metrics
_ANALYSIS_COUNTER = _METER.create_counter(
    "fixops_reachability_analyses_total",
    description="Total number of reachability analyses",
)

_ANALYSIS_DURATION = _METER.create_histogram(
    "fixops_reachability_analysis_duration_seconds",
    description="Duration of reachability analysis in seconds",
)

_ANALYSIS_ERRORS = _METER.create_counter(
    "fixops_reachability_analysis_errors_total",
    description="Total number of analysis errors",
)

_REPO_CLONE_DURATION = _METER.create_histogram(
    "fixops_reachability_repo_clone_duration_seconds",
    description="Duration of repository cloning in seconds",
)

_CACHE_HITS = _METER.create_counter(
    "fixops_reachability_cache_hits_total",
    description="Total number of cache hits",
)

_CACHE_MISSES = _METER.create_counter(
    "fixops_reachability_cache_misses_total",
    description="Total number of cache misses",
)


@dataclass
class AnalysisMetrics:
    """Metrics for a single analysis."""

    cve_id: str
    component_name: str
    analysis_duration: float
    is_reachable: bool
    confidence: str
    cache_hit: bool = False
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class ReachabilityMonitor:
    """Enterprise monitoring for reachability analysis."""

    def __init__(self, config: Optional[Mapping[str, Any]] = None):
        """Initialize monitor.

        Parameters
        ----------
        config
            Configuration for monitoring.
        """
        self.config = config or {}
        self.enable_tracing = self.config.get("enable_tracing", True)
        self.enable_metrics = self.config.get("enable_metrics", True)

    @contextmanager
    def track_analysis(
        self, cve_id: str, component_name: str
    ) -> Iterator[AnalysisMetrics]:
        """Track an analysis operation.

        Parameters
        ----------
        cve_id
            CVE identifier.
        component_name
            Component name.

        Yields
        ------
        AnalysisMetrics
            Metrics object to update.
        """
        start_time = time.time()
        metrics = AnalysisMetrics(
            cve_id=cve_id,
            component_name=component_name,
            analysis_duration=0.0,
            is_reachable=False,
            confidence="unknown",
        )

        span = None
        if self.enable_tracing:
            span = _TRACER.start_as_current_span(
                "reachability.analyze",
                attributes={
                    "fixops.reachability.cve_id": cve_id,
                    "fixops.reachability.component": component_name,
                },
            )

        try:
            yield metrics

            # Record success
            if self.enable_metrics:
                _ANALYSIS_COUNTER.add(
                    1,
                    {
                        "status": "success",
                        "cve_id": cve_id,
                        "is_reachable": str(metrics.is_reachable),
                        "confidence": metrics.confidence,
                    },
                )

            if span:
                span.set_attribute(
                    "fixops.reachability.is_reachable", metrics.is_reachable
                )
                span.set_attribute("fixops.reachability.confidence", metrics.confidence)
                span.set_status("ok")

        except Exception as e:
            # Record error
            metrics.error = str(e)

            if self.enable_metrics:
                _ANALYSIS_ERRORS.add(
                    1, {"cve_id": cve_id, "error_type": type(e).__name__}
                )

            if span:
                span.set_status("error", str(e))
                span.record_exception(e)

            raise

        finally:
            metrics.analysis_duration = time.time() - start_time

            if self.enable_metrics:
                _ANALYSIS_DURATION.record(
                    metrics.analysis_duration,
                    {
                        "cve_id": cve_id,
                        "component": component_name,
                    },
                )

            if span:
                span.end()

    @contextmanager
    def track_repo_clone(self, repo_url: str) -> Iterator[None]:
        """Track repository cloning operation.

        Parameters
        ----------
        repo_url
            Repository URL.
        """
        start_time = time.time()

        span = None
        if self.enable_tracing:
            span = _TRACER.start_as_current_span(
                "reachability.clone_repo",
                attributes={"fixops.reachability.repo_url": repo_url},
            )

        try:
            yield

            if span:
                span.set_status("ok")

        except Exception as e:
            if span:
                span.set_status("error", str(e))
                span.record_exception(e)
            raise

        finally:
            duration = time.time() - start_time

            if self.enable_metrics:
                _REPO_CLONE_DURATION.record(duration, {"repo_url": repo_url})

            if span:
                span.end()

    def record_cache_hit(self, cve_id: str) -> None:
        """Record cache hit."""
        if self.enable_metrics:
            _CACHE_HITS.add(1, {"cve_id": cve_id})

    def record_cache_miss(self, cve_id: str) -> None:
        """Record cache miss."""
        if self.enable_metrics:
            _CACHE_MISSES.add(1, {"cve_id": cve_id})

    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get metrics summary."""
        # This would query the metrics backend
        # For now, return placeholder
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "analyses_total": "N/A",  # Would query from metrics backend
            "cache_hit_rate": "N/A",
            "average_duration": "N/A",
        }
