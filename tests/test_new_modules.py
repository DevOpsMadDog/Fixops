import types

from core.analytics import ROIDashboard
from core.tenancy import TenantLifecycleManager
from core.performance import PerformanceSimulator


def _overlay_stub(mode: str = "demo") -> object:
    return types.SimpleNamespace(mode=mode, metadata={"profile_applied": mode})


def test_roi_dashboard_calculates_value() -> None:
    dashboard = ROIDashboard(
        {
            "baseline": {
                "findings_per_interval": 100,
                "review_minutes_per_finding": 10,
                "mttr_hours": 72,
                "audit_hours": 40,
            },
            "targets": {"mttr_hours": 24, "audit_hours": 16},
            "costs": {"currency": "USD", "hourly_rate": 150},
            "module_weights": {"guardrails": 3, "analytics": 1},
            "automation_hours_saved": 12,
        }
    )

    pipeline_result = {
        "severity_overview": {"counts": {"high": 5, "medium": 2}},
        "modules": {"executed": ["guardrails", "analytics"]},
    }
    context_summary = {"summary": {"components_evaluated": 3}}
    compliance_status = {"frameworks": [{"id": "SOC2"}]}
    policy_summary = {"actions": [{"type": "jira"}]}

    analytics = dashboard.evaluate(
        pipeline_result,
        _overlay_stub(),
        context_summary=context_summary,
        compliance_status=compliance_status,
        policy_summary=policy_summary,
    )

    assert analytics["overview"]["estimated_value"] > 0
    assert analytics["roi"]["noise_hours_saved"] >= 0
    assert analytics["overlay"]["mode"] == "demo"
    assert any(entry["module"] == "guardrails" for entry in analytics["value_by_module"])
    assert analytics["insights"]


def test_tenant_lifecycle_summary() -> None:
    manager = TenantLifecycleManager(
        {
            "defaults": {"modules": ["guardrails", "analytics"]},
            "tenants": [
                {
                    "id": "demo",
                    "name": "Demo",
                    "status": "active",
                    "stage": "steady_state",
                    "environments": ["sandbox"],
                }
            ],
            "lifecycle": {
                "stages": [
                    {"id": "onboarding", "name": "Onboarding"},
                    {"id": "steady_state", "name": "Steady State"},
                ],
                "stage_defaults": {"steady_state": ["performance"]},
                "transitions": {"onboarding": ["steady_state"], "steady_state": []},
            },
        }
    )

    result = manager.evaluate({"modules": {"executed": ["guardrails", "performance"]}}, _overlay_stub())

    assert result["summary"]["total_tenants"] == 1
    tenant = result["tenants"][0]
    assert tenant["modules_required"]
    assert "performance" in tenant["modules_required"]
    assert result["overlay"]["mode"] == "demo"


def test_performance_simulation_estimates_latency() -> None:
    simulator = PerformanceSimulator(
        {
            "baseline": {"per_module_ms": 200},
            "module_latency_ms": {"guardrails": 150, "analytics": 180},
            "ingestion_throughput_per_minute": 60,
            "near_real_time_threshold_ms": 4000,
            "capacity": {"concurrent_runs": 2, "burst_runs": 4},
        }
    )

    pipeline_result = {
        "modules": {"executed": ["guardrails", "analytics"]},
        "crosswalk": [{}, {}, {}],
        "severity_overview": {"counts": {"high": 1}},
    }

    profile = simulator.simulate(pipeline_result, _overlay_stub())

    assert profile["summary"]["total_estimated_latency_ms"] > 0
    assert profile["summary"]["threshold_ms"] == 4000
    assert "recommendations" in profile
    assert profile["overlay"]["mode"] == "demo"
