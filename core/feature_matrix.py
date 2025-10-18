"""Feature matrix aggregation utilities for FixOps pipeline runs."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Callable, Dict


def _as_mapping(value: Any) -> Dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    return {}


def _as_sequence(value: Any) -> list[Any]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return list(value)
    return []


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _guardrail_metrics(pipeline_result: Mapping[str, Any]) -> Dict[str, Any]:
    evaluation = _as_mapping(pipeline_result.get("guardrail_evaluation"))
    return {
        "maturity": evaluation.get("maturity"),
        "highest_detected": evaluation.get("highest_detected"),
        "severity_counts": _as_mapping(evaluation.get("severity_counts")),
    }


def _context_metrics(pipeline_result: Mapping[str, Any]) -> Dict[str, Any]:
    context_summary = _as_mapping(pipeline_result.get("context_summary"))
    summary = _as_mapping(context_summary.get("summary"))
    highest_component = _as_mapping(summary.get("highest_component"))
    playbook = _as_mapping(highest_component.get("playbook"))
    return {
        "components_evaluated": _to_int(summary.get("components_evaluated")),
        "average_score": _to_float(summary.get("average_score")),
        "top_component": highest_component.get("name"),
        "top_playbook": playbook.get("name"),
    }


def _onboarding_metrics(pipeline_result: Mapping[str, Any]) -> Dict[str, Any]:
    onboarding = _as_mapping(pipeline_result.get("onboarding"))
    steps = _as_sequence(onboarding.get("steps"))
    integrations = _as_mapping(onboarding.get("integrations"))
    return {
        "mode": onboarding.get("mode"),
        "step_count": len(steps),
        "time_to_value_minutes": _to_float(
            onboarding.get("time_to_value_minutes"), 0.0
        ),
        "integrations_configured": len(integrations),
    }


def _compliance_metrics(pipeline_result: Mapping[str, Any]) -> Dict[str, Any]:
    compliance = _as_mapping(pipeline_result.get("compliance_status"))
    frameworks = _as_sequence(compliance.get("frameworks"))
    satisfied = sum(
        1
        for framework in frameworks
        if _as_mapping(framework).get("status") == "satisfied"
    )
    return {
        "framework_count": len(frameworks),
        "satisfied_frameworks": satisfied,
        "gap_count": len(_as_sequence(compliance.get("gaps"))),
    }


def _policy_metrics(pipeline_result: Mapping[str, Any]) -> Dict[str, Any]:
    policy = _as_mapping(pipeline_result.get("policy_automation"))
    actions = _as_sequence(policy.get("actions"))
    execution = _as_mapping(policy.get("execution"))
    results = _as_sequence(execution.get("results"))
    delivered = 0
    for result in results:
        delivery = _as_mapping(result).get("delivery")
        if _as_mapping(delivery).get("status") == "sent":
            delivered += 1
    return {
        "action_count": len(actions),
        "execution_status": execution.get("status"),
        "results_recorded": len(results),
        "deliveries_sent": delivered,
    }


def _evidence_metrics(pipeline_result: Mapping[str, Any]) -> Dict[str, Any]:
    bundle = _as_mapping(pipeline_result.get("evidence_bundle"))
    files = _as_mapping(bundle.get("files"))
    sections = _as_sequence(bundle.get("sections"))
    return {
        "bundle_id": bundle.get("bundle_id"),
        "file_count": len(files),
        "section_count": len(sections),
        "compressed": bool(bundle.get("compressed")),
        "encrypted": bool(bundle.get("encrypted")),
    }


def _analytics_metrics(pipeline_result: Mapping[str, Any]) -> Dict[str, Any]:
    analytics = _as_mapping(pipeline_result.get("analytics"))
    overview = _as_mapping(analytics.get("overview"))
    insights = _as_sequence(analytics.get("insights"))
    return {
        "estimated_value": _to_float(overview.get("estimated_value")),
        "noise_reduction_percent": _to_float(overview.get("noise_reduction_percent")),
        "insight_count": len(insights),
    }


def _ai_metrics(pipeline_result: Mapping[str, Any]) -> Dict[str, Any]:
    ai_analysis = _as_mapping(pipeline_result.get("ai_agent_analysis"))
    summary = _as_mapping(ai_analysis.get("summary"))
    frameworks = summary.get("frameworks_detected")
    frameworks_list = (
        list(frameworks)
        if isinstance(frameworks, Sequence) and not isinstance(frameworks, (str, bytes))
        else []
    )
    return {
        "components_with_agents": _to_int(summary.get("components_with_agents")),
        "total_matches": _to_int(summary.get("total_matches")),
        "frameworks_detected": frameworks_list,
    }


def _exploit_metrics(pipeline_result: Mapping[str, Any]) -> Dict[str, Any]:
    exploit = _as_mapping(pipeline_result.get("exploitability_insights"))
    overview = _as_mapping(exploit.get("overview"))
    escalations = _as_sequence(exploit.get("escalations"))
    return {
        "matched_records": _to_int(overview.get("matched_records")),
        "signals_configured": _to_int(overview.get("signals_configured")),
        "escalation_count": len(escalations),
    }


def _probabilistic_metrics(pipeline_result: Mapping[str, Any]) -> Dict[str, Any]:
    forecast = _as_mapping(pipeline_result.get("probabilistic_forecast"))
    metrics = _as_mapping(forecast.get("metrics"))
    components = _as_sequence(forecast.get("components"))
    return {
        "expected_high_or_critical": _to_float(
            metrics.get("expected_high_or_critical")
        ),
        "entropy_bits": _to_float(metrics.get("entropy_bits")),
        "hotspot_count": len(
            [
                entry
                for entry in components
                if _to_float(_as_mapping(entry).get("escalation_probability")) >= 0.2
            ]
        ),
    }


def _ssdlc_metrics(pipeline_result: Mapping[str, Any]) -> Dict[str, Any]:
    ssdlc = _as_mapping(pipeline_result.get("ssdlc_assessment"))
    summary = _as_mapping(ssdlc.get("summary"))
    recommendations = _as_sequence(summary.get("recommendations"))
    return {
        "total_stages": _to_int(summary.get("total_stages")),
        "gaps": _to_int(summary.get("gaps")),
        "recommendation_count": len(recommendations),
    }


def _iac_metrics(pipeline_result: Mapping[str, Any]) -> Dict[str, Any]:
    iac = _as_mapping(pipeline_result.get("iac_posture"))
    targets = _as_sequence(iac.get("targets"))
    unmatched = _as_sequence(iac.get("unmatched_components"))
    issue_count = 0
    for target in targets:
        issue_count += len(_as_sequence(_as_mapping(target).get("artifacts_missing")))
    return {
        "target_count": len(targets),
        "unmatched_components": unmatched,
        "artifact_gaps": issue_count,
    }


def _tenancy_metrics(pipeline_result: Mapping[str, Any]) -> Dict[str, Any]:
    lifecycle = _as_mapping(pipeline_result.get("tenant_lifecycle"))
    summary = _as_mapping(lifecycle.get("summary"))
    return {
        "total_tenants": _to_int(summary.get("total_tenants")),
        "status_counts": _as_mapping(summary.get("status_counts")),
        "stage_counts": _as_mapping(summary.get("stage_counts")),
    }


def _performance_metrics(pipeline_result: Mapping[str, Any]) -> Dict[str, Any]:
    performance = _as_mapping(pipeline_result.get("performance_profile"))
    summary = _as_mapping(performance.get("summary"))
    timeline = _as_sequence(performance.get("timeline"))
    return {
        "total_estimated_latency_ms": _to_float(
            summary.get("total_estimated_latency_ms")
        ),
        "module_execution_ms": _to_float(summary.get("module_execution_ms")),
        "timeline_events": len(timeline),
        "status": summary.get("status"),
    }


def _pricing_metrics(pipeline_result: Mapping[str, Any]) -> Dict[str, Any]:
    pricing = _as_mapping(pipeline_result.get("pricing_summary"))
    plans = _as_sequence(pricing.get("plans"))
    return {
        "plan_count": len(plans),
    }


_MODULE_BUILDERS: Dict[str, Callable[[Mapping[str, Any]], Dict[str, Any]]] = {
    "guardrails": _guardrail_metrics,
    "context_engine": _context_metrics,
    "onboarding": _onboarding_metrics,
    "compliance": _compliance_metrics,
    "policy_automation": _policy_metrics,
    "evidence": _evidence_metrics,
    "analytics": _analytics_metrics,
    "ai_agents": _ai_metrics,
    "exploit_signals": _exploit_metrics,
    "probabilistic": _probabilistic_metrics,
    "ssdlc": _ssdlc_metrics,
    "iac_posture": _iac_metrics,
    "tenancy": _tenancy_metrics,
    "performance": _performance_metrics,
    "pricing": _pricing_metrics,
}


def build_feature_matrix(pipeline_result: Mapping[str, Any]) -> Dict[str, Any]:
    """Return a feature coverage matrix derived from a pipeline run result."""

    modules = _as_mapping(pipeline_result.get("modules"))
    status_map = _as_mapping(modules.get("status"))
    execution_order = _as_sequence(modules.get("executed"))

    features: Dict[str, Dict[str, Any]] = {}
    for name, status in status_map.items():
        status_text = str(status)
        available = status_text == "executed"
        metrics_builder = _MODULE_BUILDERS.get(name)
        metrics = (
            metrics_builder(pipeline_result) if (metrics_builder and available) else {}
        )
        features[name] = {
            "status": status_text,
            "available": available,
            "metrics": metrics,
        }

    executed = [name for name, payload in features.items() if payload["available"]]
    missing = [name for name, payload in features.items() if not payload["available"]]

    summary = {
        "features_tracked": len(features),
        "features_available": len(executed),
        "features_missing": sorted(missing),
        "executed_modules": sorted(executed),
        "execution_order": [str(entry) for entry in execution_order],
    }

    return {"summary": summary, "features": features}


__all__ = ["build_feature_matrix"]
