from pathlib import Path

import pytest

from backend.pipeline import PipelineOrchestrator
from backend.normalizers import (
    CVERecordSummary,
    NormalizedCVEFeed,
    NormalizedSARIF,
    NormalizedSBOM,
    SBOMComponent,
    SarifFinding,
)
from fixops.configuration import load_overlay


@pytest.mark.parametrize("customer_impact,data_classification,exposure", [
    ("mission_critical", "pii", "internet"),
    ("external", "financial", "partner"),
])
def test_feature_matrix_alignment(tmp_path, monkeypatch, customer_impact, data_classification, exposure):
    monkeypatch.setenv("FIXOPS_API_TOKEN", "matrix-token")
    monkeypatch.setenv("FIXOPS_DATA_ROOT_ALLOWLIST", str(tmp_path))

    overlay = load_overlay()

    overlay.data = {
        "evidence_dir": str(tmp_path / "evidence" / overlay.mode),
        "archive_dir": str(tmp_path / "archive" / overlay.mode),
        "analytics_dir": str(tmp_path / "analytics" / overlay.mode),
        "automation_dir": str(tmp_path / "automation" / overlay.mode),
        "feedback_dir": str(tmp_path / "feedback" / overlay.mode),
        "feeds_dir": str(tmp_path / "feeds" / overlay.mode),
    }
    overlay.exploit_signals.setdefault("auto_refresh", {})["enabled"] = False
    overlay.exploit_signals.get("auto_refresh", {}).setdefault("feeds", [])

    design_dataset = {
        "columns": [
            "component",
            "owner",
            "customer_impact",
            "data_classification",
            "exposure",
            "notes",
        ],
        "rows": [
            {
                "component": "payment-service",
                "owner": "app-team",
                "customer_impact": customer_impact,
                "data_classification": data_classification,
                "exposure": exposure,
                "notes": "Handles card processing with LangChain agent",
            },
            {
                "component": "notification-service",
                "owner": "platform",
                "customer_impact": "internal",
                "data_classification": "internal",
                "exposure": "partner",
                "notes": "Sends transactional messages",
            },
        ],
    }

    sbom = NormalizedSBOM(
        format="CycloneDX",
        document={"bomFormat": "CycloneDX", "specVersion": "1.4"},
        components=[
            SBOMComponent(name="payment-service", version="1.0.0"),
            SBOMComponent(name="notification-service", version="2.0.0"),
        ],
        relationships=[],
        services=[],
        vulnerabilities=[],
        metadata={"component_count": 2},
    )

    sarif = NormalizedSARIF(
        version="2.1.0",
        schema_uri="https://json.schemastore.org/sarif-2.1.0.json",
        tool_names=["DemoScanner"],
        findings=[
            SarifFinding(
                rule_id="DEMO001",
                message="SQL injection risk",
                level="error",
                file="services/payment-service/app.py",
                line=42,
                raw={
                    "analysisTarget": {
                        "uri": "services/payment-service/app.py",
                        "index": 0,
                    }
                },
            )
        ],
        metadata={"finding_count": 1},
    )

    cve = NormalizedCVEFeed(
        records=[
            CVERecordSummary(
                cve_id="CVE-2024-0001",
                title="Demo vulnerability",
                severity="high",
                exploited=True,
                raw={
                    "cvssV3Severity": "HIGH",
                    "knownExploited": True,
                    "epss": 0.72,
                },
            )
        ],
        errors=[],
        metadata={"record_count": 1},
    )

    orchestrator = PipelineOrchestrator()
    result = orchestrator.run(
        design_dataset=design_dataset,
        sbom=sbom,
        sarif=sarif,
        cve=cve,
        overlay=overlay,
    )

    assert result["status"] == "ok"
    assert len(result["crosswalk"]) == len(design_dataset["rows"])
    assert result["context_summary"]["summary"]["components_evaluated"] == len(design_dataset["rows"])

    evidence_bundle = result["evidence_bundle"]
    assert evidence_bundle["files"]
    for file_path in evidence_bundle["files"].values():
        path = Path(file_path)
        assert path.is_file()

    guardrail = result["guardrail_evaluation"]
    assert guardrail["status"] in {"pass", "warn", "fail"}
    assert result["policy_automation"]["execution"]["results"]

    analytics = result["analytics"]
    assert analytics["overview"]["estimated_value"] >= 0
    performance = result["performance_profile"]
    assert performance["summary"]["total_estimated_latency_ms"] >= 0

    ai_analysis = result["ai_agent_analysis"]
    assert ai_analysis["summary"]["components_with_agents"] >= 1

    exploit_summary = result["exploitability_insights"]
    assert exploit_summary["overview"]["matched_records"] >= 1

    automation_delivery = result["policy_automation"]["execution"]["results"][0]["delivery"]
    assert automation_delivery["status"] in {"sent", "skipped", "failed"}

    modules = result["modules"]["status"]
    expected_modules = {
        "context_engine",
        "compliance",
        "policy_automation",
        "evidence",
        "analytics",
        "ai_agents",
        "exploit_signals",
        "probabilistic",
        "iac_posture",
        "tenancy",
        "performance",
    }
    assert expected_modules.issubset(modules.keys())
    assert all(modules[name] == "executed" for name in expected_modules)

    assert result["tenant_lifecycle"]["summary"]
    assert result["probabilistic_forecast"]["metrics"]["expected_high_or_critical"] >= 0
    assert result["iac_posture"]["targets"]

    matrix = result["feature_matrix"]
    assert matrix["summary"]["features_available"] >= len(expected_modules)
    assert not matrix["summary"]["features_missing"]
    assert set(matrix["summary"]["executed_modules"]) >= expected_modules
    assert matrix["summary"]["execution_order"] == result["modules"]["executed"]

    guardrail_metrics = matrix["features"]["guardrails"]["metrics"]
    assert guardrail_metrics["highest_detected"] == guardrail["highest_detected"]

    context_metrics = matrix["features"]["context_engine"]["metrics"]
    assert (
        context_metrics["components_evaluated"]
        == result["context_summary"]["summary"]["components_evaluated"]
    )

    compliance_metrics = matrix["features"]["compliance"]["metrics"]
    assert (
        compliance_metrics["framework_count"]
        == len(result["compliance_status"]["frameworks"])
    )

    policy_metrics = matrix["features"]["policy_automation"]["metrics"]
    assert policy_metrics["action_count"] == len(result["policy_automation"]["actions"])
    assert (
        policy_metrics["results_recorded"]
        == len(result["policy_automation"]["execution"]["results"])
    )

    evidence_metrics = matrix["features"]["evidence"]["metrics"]
    assert evidence_metrics["file_count"] >= len(evidence_bundle["files"])
    assert evidence_metrics["section_count"] == len(evidence_bundle["sections"])

    analytics_metrics = matrix["features"]["analytics"]["metrics"]
    assert (
        analytics_metrics["estimated_value"]
        == analytics["overview"]["estimated_value"]
    )

    ai_metrics = matrix["features"]["ai_agents"]["metrics"]
    assert (
        ai_metrics["components_with_agents"]
        == ai_analysis["summary"]["components_with_agents"]
    )

    exploit_metrics = matrix["features"]["exploit_signals"]["metrics"]
    assert (
        exploit_metrics["matched_records"]
        == exploit_summary["overview"]["matched_records"]
    )

    probabilistic_metrics = matrix["features"]["probabilistic"]["metrics"]
    assert (
        probabilistic_metrics["expected_high_or_critical"]
        == result["probabilistic_forecast"]["metrics"]["expected_high_or_critical"]
    )

    ssdlc_metrics = matrix["features"]["ssdlc"]["metrics"]
    assert (
        ssdlc_metrics["total_stages"]
        == result["ssdlc_assessment"]["summary"]["total_stages"]
    )

    iac_metrics = matrix["features"]["iac_posture"]["metrics"]
    assert iac_metrics["target_count"] == len(result["iac_posture"]["targets"])

    tenancy_metrics = matrix["features"]["tenancy"]["metrics"]
    assert (
        tenancy_metrics["total_tenants"]
        == result["tenant_lifecycle"]["summary"]["total_tenants"]
    )

    performance_metrics = matrix["features"]["performance"]["metrics"]
    assert (
        performance_metrics["total_estimated_latency_ms"]
        == performance["summary"]["total_estimated_latency_ms"]
    )

    onboarding_metrics = matrix["features"]["onboarding"]["metrics"]
    assert onboarding_metrics["step_count"] == len(result["onboarding"]["steps"])

    pricing_metrics = matrix["features"]["pricing"]["metrics"]
    assert pricing_metrics["plan_count"] == len(result["pricing_summary"]["plans"])
