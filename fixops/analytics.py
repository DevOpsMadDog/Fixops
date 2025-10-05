"""Analytics and ROI computations for FixOps pipeline runs."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, TYPE_CHECKING

from fixops.paths import ensure_secure_directory

if TYPE_CHECKING:  # pragma: no cover - imported for type checking only
    from fixops.configuration import OverlayConfig


class ROIDashboard:
    """Calculate ROI and analytics insights from pipeline outputs."""

    def __init__(self, settings: Mapping[str, Any]):
        self.settings = dict(settings or {})
        self.baseline = self._coerce_mapping(self.settings.get("baseline"))
        self.targets = self._coerce_mapping(self.settings.get("targets"))
        self.costs = self._coerce_mapping(self.settings.get("costs"))
        self.module_weights = self._coerce_mapping(self.settings.get("module_weights"))
        self.additional_metrics = self._coerce_mapping(self.settings.get("metrics"))
        self.time_to_value_minutes = self._to_float(
            self.settings.get("time_to_value_minutes"), 30.0
        )
        self.automation_hours_saved = self._to_float(
            self.settings.get("automation_hours_saved"), 8.0
        )

    @staticmethod
    def _coerce_mapping(value: Any) -> Dict[str, Any]:
        if isinstance(value, Mapping):
            return dict(value)
        return {}

    @staticmethod
    def _to_float(value: Any, default: float = 0.0) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    def evaluate(
        self,
        pipeline_result: Mapping[str, Any],
        overlay: Optional["OverlayConfig"] = None,
        *,
        context_summary: Optional[Mapping[str, Any]] = None,
        compliance_status: Optional[Mapping[str, Any]] = None,
        policy_summary: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        severity_counts = (
            pipeline_result.get("severity_overview", {}).get("counts", {})
            if isinstance(pipeline_result, Mapping)
            else {}
        )
        total_findings = sum(
            int(self._to_float(count, 0)) for count in severity_counts.values()
        )
        baseline_findings = self._to_float(
            self.baseline.get("findings_per_interval"),
            float(total_findings) if total_findings else 100.0,
        )
        if baseline_findings <= 0:
            baseline_findings = float(total_findings or 100.0)

        review_minutes = self._to_float(
            self.baseline.get("review_minutes_per_finding"), 15.0
        )
        baseline_review_hours = (baseline_findings * review_minutes) / 60.0
        actual_review_hours = (total_findings * review_minutes) / 60.0
        noise_hours_saved = max(baseline_review_hours - actual_review_hours, 0.0)
        noise_reduction_percent = max(
            0.0, (baseline_findings - float(total_findings)) / baseline_findings * 100.0
        )

        mttr_baseline = self._to_float(self.baseline.get("mttr_hours"), 72.0)
        mttr_target = self._to_float(
            self.targets.get("mttr_hours"), max(mttr_baseline - 24.0, 0.0)
        )
        mttr_improvement = max(mttr_baseline - mttr_target, 0.0)

        audit_baseline = self._to_float(self.baseline.get("audit_hours"), 40.0)
        audit_target = self._to_float(
            self.targets.get("audit_hours"), max(audit_baseline - 24.0, 0.0)
        )
        audit_hours_saved = max(audit_baseline - audit_target, 0.0)

        hourly_rate = self._to_float(self.costs.get("hourly_rate"), 150.0)
        currency = str(self.costs.get("currency") or "USD")
        total_hours_saved = noise_hours_saved + self.automation_hours_saved + audit_hours_saved
        estimated_value = round(total_hours_saved * hourly_rate, 2)

        executed_modules = (
            pipeline_result.get("modules", {}).get("executed", [])
            if isinstance(pipeline_result, Mapping)
            else []
        )
        if not isinstance(executed_modules, Iterable):
            executed_modules = []
        executed_list = [str(module) for module in executed_modules]

        weight_total = sum(
            self._to_float(self.module_weights.get(module), 0.0)
            for module in executed_list
        )
        module_values = []
        if weight_total <= 0:
            weight_total = float(len(executed_list) or 1)
            self.module_weights = {
                module: 1.0 for module in executed_list
            }
        for module in executed_list:
            weight = self._to_float(self.module_weights.get(module), 1.0)
            module_share = (weight / weight_total) * estimated_value if weight_total else 0.0
            module_values.append(
                {
                    "module": module,
                    "weight": round(weight, 2),
                    "estimated_value": round(module_share, 2),
                }
            )

        insights: list[str] = []
        if noise_reduction_percent >= 50.0:
            insights.append(
                "Noise reduced by at least half compared to historical scanning volume"
            )
        if mttr_improvement >= 24.0:
            insights.append("Projected MTTR improvement exceeds one day")
        if audit_hours_saved:
            insights.append(
                f"Audit preparation hours reduced by {round(audit_hours_saved, 1)}"
            )
        if context_summary:
            summary = context_summary.get("summary", {}) if isinstance(context_summary, Mapping) else {}
            components = summary.get("components_evaluated")
            if components:
                insights.append(
                    f"Context engine evaluated {components} components for business impact"
                )
        if compliance_status:
            frameworks = compliance_status.get("frameworks", []) if isinstance(compliance_status, Mapping) else []
            if frameworks:
                names = {
                    str(item.get("id", "framework"))
                    for item in frameworks
                    if isinstance(item, Mapping)
                }
                if names:
                    insights.append(
                        "Compliance coverage confirmed for: " + ", ".join(sorted(names))
                    )
        if policy_summary:
            actions = policy_summary.get("actions", []) if isinstance(policy_summary, Mapping) else []
            if actions:
                insights.append(
                    f"Policy automation prepared {len(list(actions))} remediation playbook(s)"
                )

        analytics_summary = {
            "overview": {
                "currency": currency,
                "estimated_value": estimated_value,
                "total_hours_saved": round(total_hours_saved, 2),
                "noise_reduction_percent": round(noise_reduction_percent, 2),
                "mttr_improvement_hours": round(mttr_improvement, 2),
                "audit_hours_saved": round(audit_hours_saved, 2),
                "time_to_value_minutes": round(self.time_to_value_minutes, 2),
            },
            "roi": {
                "hourly_rate": hourly_rate,
                "noise_hours_saved": round(noise_hours_saved, 2),
                "automation_hours_saved": round(self.automation_hours_saved, 2),
                "audit_hours_saved": round(audit_hours_saved, 2),
                "estimated_value": estimated_value,
            },
            "value_by_module": module_values,
            "assumptions": {
                "baseline": self.baseline,
                "targets": self.targets,
                "metrics": self.additional_metrics,
            },
            "insights": insights,
        }

        overlay_metadata = {}
        if overlay is not None:
            overlay_metadata = {
                "mode": overlay.mode,
                "profile": overlay.metadata.get("profile_applied"),
            }
        analytics_summary["overlay"] = overlay_metadata

        return analytics_summary


class FeedbackOutcomeStore:
    """Persist connector delivery outcomes for ROI analytics correlation."""

    def __init__(self, base_directory: Path):
        self.base_directory = ensure_secure_directory(base_directory)

    def record(self, run_id: str, outcomes: Mapping[str, Mapping[str, Any]]) -> Path:
        if not isinstance(run_id, str) or not run_id.strip():
            raise ValueError("run_id must be a non-empty string for outcome persistence")

        serialised: Dict[str, Dict[str, Any]] = {}
        for name, outcome in outcomes.items():
            if isinstance(outcome, Mapping):
                data = dict(outcome)
            else:
                data = {"result": str(outcome)}
            data.setdefault("status", data.get("status", "unknown"))
            serialised[str(name)] = data

        run_directory = ensure_secure_directory(self.base_directory / run_id.strip())
        record_path = run_directory / "feedback_forwarding.jsonl"
        payload = {
            "run_id": run_id.strip(),
            "timestamp": int(time.time()),
            "outcomes": serialised,
        }
        with record_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
        return record_path


__all__ = ["FeedbackOutcomeStore", "ROIDashboard"]
