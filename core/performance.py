"""Performance simulation utilities for FixOps pipeline runs."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, Mapping, Optional

if TYPE_CHECKING:  # pragma: no cover - typing only
    from core.configuration import OverlayConfig


class PerformanceSimulator:
    """Estimate near real-time performance characteristics."""

    def __init__(self, settings: Mapping[str, Any]):
        self.settings = dict(settings or {})
        self.baseline = self._coerce_mapping(self.settings.get("baseline"))
        self.capacity = self._coerce_mapping(self.settings.get("capacity"))
        self.module_latency = self._coerce_mapping(
            self.settings.get("module_latency_ms")
        )
        self.threshold_ms = self._to_int(
            self.settings.get("near_real_time_threshold_ms"), 5000
        )
        self.ingestion_rate = self._to_float(
            self.settings.get("ingestion_throughput_per_minute"), 30.0
        )

    @staticmethod
    def _coerce_mapping(value: Any) -> Dict[str, Any]:
        if isinstance(value, Mapping):
            return dict(value)
        return {}

    @staticmethod
    def _to_int(value: Any, default: int) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _to_float(value: Any, default: float) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    def simulate(
        self,
        pipeline_result: Mapping[str, Any],
        overlay: Optional["OverlayConfig"] = None,
    ) -> Dict[str, Any]:
        modules_status = (
            pipeline_result.get("modules", {})
            if isinstance(pipeline_result, Mapping)
            else {}
        )
        executed = (
            modules_status.get("executed", [])
            if isinstance(modules_status, Mapping)
            else []
        )
        crosswalk = (
            pipeline_result.get("crosswalk", [])
            if isinstance(pipeline_result, Mapping)
            else []
        )
        severity_counts = pipeline_result.get("severity_overview", {}).get("counts", {})

        baseline_per_module = self._to_int(self.baseline.get("per_module_ms"), 200)
        cumulative = 0
        timeline = []
        for module in executed:
            module_name = str(module)
            latency = self._to_int(
                self.module_latency.get(module_name), baseline_per_module
            )
            cumulative += latency
            timeline.append(
                {
                    "module": module_name,
                    "duration_ms": latency,
                    "cumulative_ms": cumulative,
                }
            )

        records = len(crosswalk)
        throughput = max(self.ingestion_rate, 1.0)
        processing_minutes = records / throughput
        processing_ms = int(processing_minutes * 60_000)
        total_ms = cumulative + processing_ms

        concurrency = self._to_int(self.capacity.get("concurrent_runs"), 3)
        burst_capacity = self._to_int(self.capacity.get("burst_runs"), concurrency * 2)
        backlog = max(records - concurrency * 5, 0)

        meets_threshold = total_ms <= self.threshold_ms
        status = "realtime" if meets_threshold else "capacity-plan"

        recommendations = []
        if not meets_threshold:
            recommendations.append(
                "Increase concurrency or disable heavy modules for near real-time execution"
            )
        if backlog:
            recommendations.append(
                f"Backlog detected for {backlog} artefact(s); consider scaling ingestion workers"
            )
        if severity_counts:
            high = int(
                severity_counts.get("high", 0) + severity_counts.get("critical", 0)
            )
            if high > 0 and not meets_threshold:
                recommendations.append(
                    "Prioritise high/critical findings queue to preserve response SLAs"
                )

        overlay_metadata = {}
        if overlay is not None:
            overlay_metadata = {
                "mode": overlay.mode,
                "profile": overlay.metadata.get("profile_applied"),
            }

        return {
            "summary": {
                "total_estimated_latency_ms": total_ms,
                "module_execution_ms": cumulative,
                "artefact_processing_ms": processing_ms,
                "threshold_ms": self.threshold_ms,
                "status": status,
            },
            "timeline": timeline,
            "capacity": {
                "concurrent_runs": concurrency,
                "burst_runs": burst_capacity,
                "ingestion_throughput_per_minute": throughput,
                "artefact_backlog": backlog,
            },
            "recommendations": recommendations,
            "overlay": overlay_metadata,
        }


__all__ = ["PerformanceSimulator"]
