"""Analytics and ROI computations for FixOps pipeline runs."""

from __future__ import annotations

import json
import time
import uuid
from collections import Counter
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
)

from core.paths import ensure_secure_directory, verify_allowlisted_path

if TYPE_CHECKING:  # pragma: no cover - imported for type checking only
    from core.configuration import OverlayConfig


_SAFE_RUN_ID_CHARACTERS = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
)


def _validate_run_id(run_id: str) -> str:
    if not isinstance(run_id, str) or not run_id.strip():
        raise ValueError("run_id must be a non-empty string for analytics persistence")
    candidate = run_id.strip()
    if not set(candidate) <= _SAFE_RUN_ID_CHARACTERS:
        raise ValueError(
            "run_id contains unsupported characters for analytics persistence"
        )
    return candidate


class AnalyticsStore:
    """Persist analytics artefacts (forecasts, exploit snapshots, tickets, feedback)."""

    _FORECASTS = "forecasts"
    _EXPLOIT = "exploit_snapshots"
    _TICKETS = "ticket_metrics"
    _FEEDBACK_EVENTS = "feedback_events"
    _FEEDBACK_OUTCOMES = "feedback_outcomes"

    def __init__(
        self,
        base_directory: Path,
        *,
        allowlist: Optional[Sequence[Path]] = None,
    ) -> None:
        self._allowlist: tuple[Path, ...] = (
            tuple(Path(entry).resolve() for entry in allowlist)
            if allowlist
            else tuple()
        )
        if self._allowlist:
            base_directory = verify_allowlisted_path(base_directory, self._allowlist)
        self.base_directory = ensure_secure_directory(base_directory)

    # ------------------------------------------------------------------
    # Generic helpers
    # ------------------------------------------------------------------
    def _category_directory(self, category: str, run_id: Optional[str] = None) -> Path:
        directory = self.base_directory / category
        if self._allowlist:
            directory = verify_allowlisted_path(directory, self._allowlist)
        directory = ensure_secure_directory(directory)
        if run_id is not None:
            safe_run_id = _validate_run_id(run_id)
            directory = directory / safe_run_id
            if self._allowlist:
                directory = verify_allowlisted_path(directory, self._allowlist)
            directory = ensure_secure_directory(directory)
        return directory

    @staticmethod
    def _timestamp() -> int:
        return int(time.time())

    def _write_entry(
        self,
        category: str,
        run_id: str,
        payload: Mapping[str, Any],
    ) -> Path:
        directory = self._category_directory(category, run_id)
        filename = f"{self._timestamp()}-{uuid.uuid4().hex}.json"
        path = directory / filename
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return path

    def _load_entries(self, category: str) -> List[Dict[str, Any]]:
        directory = self._category_directory(category)
        entries: List[Dict[str, Any]] = []
        if not directory.exists():
            return entries
        for run_dir in directory.iterdir():
            if not run_dir.is_dir():
                continue
            for path in run_dir.glob("*.json"):
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except Exception:  # pragma: no cover - corrupted entry ignored
                    continue
                if isinstance(data, Mapping):
                    record = dict(data)
                    record.setdefault("_path", str(path))
                    entries.append(record)  # type: ignore[arg-type]
        entries.sort(key=lambda entry: entry.get("timestamp", 0), reverse=True)
        return entries

    def _load_run_entries(self, category: str, run_id: str) -> List[Dict[str, Any]]:
        directory = self._category_directory(category, run_id)
        entries: List[Dict[str, Any]] = []
        if not directory.exists():
            return entries
        for path in directory.glob("*.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:  # pragma: no cover - corrupted entry ignored
                continue
            if isinstance(data, Mapping):
                record = dict(data)
                record.setdefault("_path", str(path))
                entries.append(record)  # type: ignore[arg-type]
        entries.sort(key=lambda entry: entry.get("timestamp", 0), reverse=True)
        return entries

    @staticmethod
    def _slice(
        entries: Sequence[Mapping[str, Any]], limit: int
    ) -> List[Dict[str, Any]]:
        limited: List[Dict[str, Any]] = []
        for entry in entries[: max(limit, 0)]:
            limited.append(
                {key: value for key, value in entry.items() if key not in {"_path"}}
            )
        return limited

    # ------------------------------------------------------------------
    # Record helpers
    # ------------------------------------------------------------------
    def record_forecast(
        self,
        run_id: str,
        forecast: Mapping[str, Any],
        *,
        severity_overview: Optional[Mapping[str, Any]] = None,
    ) -> Path:
        safe_run_id = _validate_run_id(run_id)
        metrics = (
            forecast.get("metrics")
            if isinstance(forecast.get("metrics"), Mapping)
            else {}
        )
        components = forecast.get("components")
        component_count = len(components) if isinstance(components, Sequence) else 0
        hotspots = (
            [
                entry
                for entry in components
                if isinstance(entry, Mapping)
                and entry.get("escalation_probability", 0) >= 0.2
            ]
            if isinstance(components, Sequence)
            else []
        )
        summary = {
            "expected_high_or_critical": float(
                metrics.get("expected_high_or_critical", 0.0)
                if isinstance(metrics, Mapping)
                else 0.0
            ),
            "expected_critical_next_cycle": float(
                metrics.get("expected_critical_next_cycle", 0.0)
                if isinstance(metrics, Mapping)
                else 0.0
            ),
            "entropy_bits": float(
                metrics.get("entropy_bits", 0.0)
                if isinstance(metrics, Mapping)
                else 0.0
            ),
            "exploited_records": int(
                metrics.get("exploited_records", 0)
                if isinstance(metrics, Mapping)
                else 0
            ),
            "component_count": component_count,
            "hotspot_count": len(hotspots),
        }
        payload = {
            "run_id": safe_run_id,
            "timestamp": self._timestamp(),
            "forecast": dict(forecast),
            "summary": summary,
            "severity_overview": (
                dict(severity_overview)
                if isinstance(severity_overview, Mapping)
                else None
            ),
        }
        return self._write_entry(self._FORECASTS, safe_run_id, payload)

    def record_exploit_snapshot(
        self,
        run_id: str,
        snapshot: Mapping[str, Any],
    ) -> Path:
        safe_run_id = _validate_run_id(run_id)
        overview = (
            snapshot.get("overview")
            if isinstance(snapshot.get("overview"), Mapping)
            else {}
        )
        signals = (
            snapshot.get("signals")
            if isinstance(snapshot.get("signals"), Mapping)
            else {}
        )
        escalations = (
            snapshot.get("escalations")
            if isinstance(snapshot.get("escalations"), Sequence)
            else []
        )
        summary = {
            "signals_configured": int(overview.get("signals_configured", len(signals)) if isinstance(overview, Mapping) else 0),  # type: ignore[arg-type]
            "matched_records": int(
                overview.get("matched_records", 0)
                if isinstance(overview, Mapping)
                else 0
            ),
            "status": overview.get("status", "unknown")
            if isinstance(overview, Mapping)
            else "unknown",
            "escalation_count": len(escalations)
            if isinstance(escalations, Sequence)
            else 0,
        }
        payload = {
            "run_id": safe_run_id,
            "timestamp": self._timestamp(),
            "snapshot": dict(snapshot),
            "summary": summary,
        }
        return self._write_entry(self._EXPLOIT, safe_run_id, payload)

    def record_ticket_metrics(
        self,
        run_id: str,
        policy_summary: Mapping[str, Any],
    ) -> Path:
        safe_run_id = _validate_run_id(run_id)
        execution = (
            policy_summary.get("execution")
            if isinstance(policy_summary.get("execution"), Mapping)
            else {}
        )
        delivered = (
            execution.get("delivery_results")
            if isinstance(execution, Mapping)
            else None
        )
        delivery_results = delivered if isinstance(delivered, Sequence) else []
        status_counts: Counter[str] = Counter()
        connectors: Counter[str] = Counter()
        for entry in delivery_results:
            if not isinstance(entry, Mapping):
                continue
            status = str(entry.get("status") or "unknown")
            status_counts[status] += 1
            provider = str(entry.get("provider") or entry.get("type") or "unknown")
            connectors[provider] += 1
        summary = {
            "planned_actions": len(
                policy_summary.get("actions", [])
                if isinstance(policy_summary.get("actions"), Sequence)
                else []
            ),
            "dispatched_count": int(
                execution.get("dispatched_count", 0)
                if isinstance(execution, Mapping)
                else 0
            ),
            "failed_count": int(
                execution.get("failed_count", 0)
                if isinstance(execution, Mapping)
                else 0
            ),
            "execution_status": execution.get("status", "unknown")
            if isinstance(execution, Mapping)
            else "unknown",
            "delivery_status": dict(status_counts),
            "connector_usage": dict(connectors),
        }
        payload = {
            "run_id": safe_run_id,
            "timestamp": self._timestamp(),
            "policy_summary": dict(policy_summary),
            "summary": summary,
        }
        return self._write_entry(self._TICKETS, safe_run_id, payload)

    def record_feedback_event(self, entry: Mapping[str, Any]) -> Path:
        run_id = entry.get("run_id")
        safe_run_id = _validate_run_id(str(run_id))
        tags = entry.get("tags") if isinstance(entry.get("tags"), Sequence) else []
        summary = {
            "decision": entry.get("decision"),
            "submitted_by": entry.get("submitted_by"),
            "tag_count": len(tags) if isinstance(tags, Sequence) else 0,
        }
        payload = {
            "run_id": safe_run_id,
            "timestamp": int(entry.get("timestamp") or self._timestamp()),
            "feedback": {
                key: entry.get(key)
                for key in ("decision", "notes", "submitted_by", "tags")
            },
            "summary": summary,
        }
        return self._write_entry(self._FEEDBACK_EVENTS, safe_run_id, payload)

    def record_feedback_outcomes(
        self,
        run_id: str,
        outcomes: Mapping[str, Mapping[str, Any]],
    ) -> Path:
        safe_run_id = _validate_run_id(run_id)
        status_counts: Counter[str] = Counter()
        for outcome in outcomes.values():
            if not isinstance(outcome, Mapping):
                continue
            status_counts[str(outcome.get("status") or "unknown")] += 1
        payload = {
            "run_id": safe_run_id,
            "timestamp": self._timestamp(),
            "outcomes": {name: dict(value) for name, value in outcomes.items()},
            "summary": {"delivery_status": dict(status_counts)},
        }
        return self._write_entry(self._FEEDBACK_OUTCOMES, safe_run_id, payload)

    def persist_run(
        self,
        run_id: str,
        pipeline_result: Mapping[str, Any],
    ) -> Dict[str, str]:
        """Persist supported analytics artefacts from a pipeline result."""

        records: MutableMapping[str, str] = {}
        forecast = pipeline_result.get("probabilistic_forecast")
        if isinstance(forecast, Mapping):
            severity_overview = pipeline_result.get("severity_overview")
            path = self.record_forecast(
                run_id, forecast, severity_overview=severity_overview
            )
            records["forecasts"] = str(path)

        exploit_snapshot = pipeline_result.get("exploitability_insights")
        if isinstance(exploit_snapshot, Mapping):
            path = self.record_exploit_snapshot(run_id, exploit_snapshot)
            records["exploit_snapshots"] = str(path)

        policy_summary = pipeline_result.get("policy_automation")
        if isinstance(policy_summary, Mapping):
            path = self.record_ticket_metrics(run_id, policy_summary)
            records["ticket_metrics"] = str(path)

        return dict(records)

    # ------------------------------------------------------------------
    # Dashboard helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _average(values: Iterable[float]) -> float:
        items = [float(value) for value in values]
        if not items:
            return 0.0
        return sum(items) / len(items)

    def _forecast_dashboard(self, limit: int) -> Dict[str, Any]:
        entries = self._load_entries(self._FORECASTS)
        recent = self._slice(entries, limit)
        averages = {
            "expected_high_or_critical": round(
                self._average(
                    entry.get("summary", {}).get("expected_high_or_critical", 0.0)
                    for entry in entries
                ),
                4,
            ),
            "entropy_bits": round(
                self._average(
                    entry.get("summary", {}).get("entropy_bits", 0.0)
                    for entry in entries
                ),
                4,
            ),
        }
        hotspots = sum(
            entry.get("summary", {}).get("hotspot_count", 0) for entry in entries
        )
        return {
            "recent": recent,
            "totals": {
                "entries": len(entries),
                "aggregate_hotspots": hotspots,
            },
            "averages": averages,
        }

    def _exploit_dashboard(self, limit: int) -> Dict[str, Any]:
        entries = self._load_entries(self._EXPLOIT)
        recent = self._slice(entries, limit)
        status_counts: Counter[str] = Counter(
            str(entry.get("summary", {}).get("status", "unknown")) for entry in entries
        )
        matches = sum(
            entry.get("summary", {}).get("matched_records", 0) for entry in entries
        )
        return {
            "recent": recent,
            "totals": {
                "entries": len(entries),
                "matched_records": matches,
            },
            "statuses": dict(status_counts),
        }

    def _ticket_dashboard(self, limit: int) -> Dict[str, Any]:
        entries = self._load_entries(self._TICKETS)
        recent = self._slice(entries, limit)
        dispatched = sum(
            entry.get("summary", {}).get("dispatched_count", 0) for entry in entries
        )
        failed = sum(
            entry.get("summary", {}).get("failed_count", 0) for entry in entries
        )
        status_counts: Counter[str] = Counter()
        connector_usage: Counter[str] = Counter()
        for entry in entries:
            summary = entry.get("summary", {})
            if isinstance(summary, Mapping):
                status_counts.update(summary.get("delivery_status", {}))
                connector_usage.update(summary.get("connector_usage", {}))
        return {
            "recent": recent,
            "totals": {
                "entries": len(entries),
                "dispatched": dispatched,
                "failed": failed,
            },
            "delivery_status": dict(status_counts),
            "connector_usage": dict(connector_usage),
        }

    def _feedback_dashboard(self, limit: int) -> Dict[str, Any]:
        events = self._load_entries(self._FEEDBACK_EVENTS)
        outcomes = self._load_entries(self._FEEDBACK_OUTCOMES)
        recent_events = self._slice(events, limit)
        decision_counts: Counter[str] = Counter(
            str(entry.get("summary", {}).get("decision", "unknown")) for entry in events
        )
        delivery_counts: Counter[str] = Counter()
        for entry in outcomes:
            summary = entry.get("summary", {})
            if isinstance(summary, Mapping):
                delivery_counts.update(summary.get("delivery_status", {}))
        return {
            "events": {
                "recent": recent_events,
                "totals": {
                    "entries": len(events),
                },
                "decisions": dict(decision_counts),
            },
            "outcomes": {
                "totals": {
                    "entries": len(outcomes),
                },
                "delivery_status": dict(delivery_counts),
            },
        }

    def load_dashboard(self, limit: int = 10) -> Dict[str, Any]:
        """Return aggregated analytics dashboard data."""

        limit = max(limit, 1)
        return {
            "forecasts": self._forecast_dashboard(limit),
            "exploit_snapshots": self._exploit_dashboard(limit),
            "ticket_metrics": self._ticket_dashboard(limit),
            "feedback": self._feedback_dashboard(limit),
        }

    def load_run(self, run_id: str) -> Dict[str, Any]:
        """Return analytics artefacts for a specific run."""

        safe_run_id = _validate_run_id(run_id)
        return {
            "run_id": safe_run_id,
            "forecasts": self._load_run_entries(self._FORECASTS, safe_run_id),
            "exploit_snapshots": self._load_run_entries(self._EXPLOIT, safe_run_id),
            "ticket_metrics": self._load_run_entries(self._TICKETS, safe_run_id),
            "feedback": {
                "events": self._load_run_entries(self._FEEDBACK_EVENTS, safe_run_id),
                "outcomes": self._load_run_entries(
                    self._FEEDBACK_OUTCOMES, safe_run_id
                ),
            },
        }


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
        total_hours_saved = (
            noise_hours_saved + self.automation_hours_saved + audit_hours_saved
        )
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
            self.module_weights = {module: 1.0 for module in executed_list}
        for module in executed_list:
            weight = self._to_float(self.module_weights.get(module), 1.0)
            module_share = (
                (weight / weight_total) * estimated_value if weight_total else 0.0
            )
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
            summary = (
                context_summary.get("summary", {})
                if isinstance(context_summary, Mapping)
                else {}
            )
            components = summary.get("components_evaluated")
            if components:
                insights.append(
                    f"Context engine evaluated {components} components for business impact"
                )
        if compliance_status:
            frameworks = (
                compliance_status.get("frameworks", [])
                if isinstance(compliance_status, Mapping)
                else []
            )
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
            actions = (
                policy_summary.get("actions", [])
                if isinstance(policy_summary, Mapping)
                else []
            )
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

    def __init__(
        self,
        base_directory: Path,
        *,
        analytics_store: Optional[AnalyticsStore] = None,
    ) -> None:
        self.base_directory = ensure_secure_directory(base_directory)
        self._analytics_store = analytics_store

    def record(self, run_id: str, outcomes: Mapping[str, Mapping[str, Any]]) -> Path:
        safe_run_id = _validate_run_id(run_id)

        serialised: Dict[str, Dict[str, Any]] = {}
        for name, outcome in outcomes.items():
            if isinstance(outcome, Mapping):
                data = dict(outcome)
            else:
                data = {"result": str(outcome)}
            data.setdefault("status", data.get("status", "unknown"))
            serialised[str(name)] = data

        run_directory = ensure_secure_directory(self.base_directory / safe_run_id)
        record_path = run_directory / "feedback_forwarding.jsonl"
        payload = {
            "run_id": safe_run_id,
            "timestamp": int(time.time()),
            "outcomes": serialised,
        }
        with record_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")

        if self._analytics_store is not None:
            try:  # pragma: no cover - analytics persistence is best-effort
                self._analytics_store.record_feedback_outcomes(safe_run_id, serialised)
            except Exception:
                pass
        return record_path

    def record_feedback_event(self, entry: Mapping[str, Any]) -> Optional[Path]:
        if self._analytics_store is None:
            return None
        try:
            return self._analytics_store.record_feedback_event(entry)
        except Exception:  # pragma: no cover - best-effort persistence
            return None


__all__ = ["AnalyticsStore", "FeedbackOutcomeStore", "ROIDashboard"]
