from __future__ import annotations

from backend.pipeline import PipelineOrchestrator
from backend.normalizers import (
    CVERecordSummary,
    NormalizedCVEFeed,
    NormalizedSARIF,
    NormalizedSBOM,
    SBOMComponent,
    SarifFinding,
)
from fixops.configuration import OverlayConfig


def build_orchestrator_payload():
    design_dataset = {
        "columns": ["component"],
        "rows": [
            {"component": "Payment-Service"},
            {"component": " inventory "},
            {"component": "Auth"},
        ],
    }

    sbom = NormalizedSBOM(
        format="cyclonedx",
        document={"name": "demo"},
        components=[
            SBOMComponent(name="payment-service", version="1.0.0"),
            SBOMComponent(name="inventory", version="2.3.1"),
        ],
        relationships=[],
        services=[],
        vulnerabilities=[],
        metadata={"component_count": 2},
    )

    sarif = NormalizedSARIF(
        version="2.1.0",
        schema_uri=None,
        tool_names=["StaticAnalyzer"],
        findings=[
            SarifFinding(
                rule_id="CWE-79",
                message="Reflected XSS in payment-service template",
                level="error",
                file="services/payment-service/app.py",
                line=42,
                raw={"analysisTarget": {"uri": "payment-service"}},
            ),
            SarifFinding(
                rule_id="CWE-20",
                message="Validate input handling",
                level="warning",
                file="services/auth/forms.py",
                line=12,
                raw={"analysisTarget": {"uri": "auth"}},
            ),
        ],
        metadata={"run_count": 1, "finding_count": 2},
    )

    cve = NormalizedCVEFeed(
        records=[
            CVERecordSummary(
                cve_id="CVE-2023-0001",
                title="Auth credential leak",
                severity="HIGH",
                exploited=True,
                raw={"systems": ["auth"], "details": "credential exposure"},
            ),
            CVERecordSummary(
                cve_id="CVE-2023-7777",
                title="Inventory overflow",
                severity="MEDIUM",
                exploited=False,
                raw={"component": "inventory"},
            ),
        ],
        errors=[],
        metadata={"record_count": 2},
    )

    return design_dataset, sbom, sarif, cve


def test_pipeline_crosswalk_reuses_precomputed_matches():
    orchestrator = PipelineOrchestrator()
    design_dataset, sbom, sarif, cve = build_orchestrator_payload()

    result = orchestrator.run(
        design_dataset=design_dataset, sbom=sbom, sarif=sarif, cve=cve
    )

    assert result["design_summary"]["row_count"] == 3
    crosswalk = result["crosswalk"]

    payment_entry = crosswalk[0]
    assert payment_entry["sbom_component"]["name"] == "payment-service"
    assert payment_entry["findings"][0]["rule_id"] == "CWE-79"
    assert not payment_entry["cves"]

    inventory_entry = crosswalk[1]
    assert inventory_entry["sbom_component"]["name"] == "inventory"
    assert inventory_entry["cves"][0]["cve_id"] == "CVE-2023-7777"

    auth_entry = crosswalk[2]
    assert auth_entry["findings"][0]["rule_id"] == "CWE-20"
    assert auth_entry["cves"][0]["cve_id"] == "CVE-2023-0001"
    assert result["cve_summary"]["exploited_count"] == 1
    assert result["sarif_summary"]["severity_breakdown"]["error"] == 1


def test_pipeline_guardrail_evaluation_uses_overlay_policy():
    orchestrator = PipelineOrchestrator()
    design_dataset, sbom, sarif, cve = build_orchestrator_payload()

    overlay = OverlayConfig(
        mode="enterprise",
        guardrails={
            "maturity": "advanced",
            "profiles": {"advanced": {"fail_on": "medium", "warn_on": "low"}},
        },
    )

    result = orchestrator.run(
        design_dataset=design_dataset,
        sbom=sbom,
        sarif=sarif,
        cve=cve,
        overlay=overlay,
    )

    guardrail = result["guardrail_evaluation"]
    assert guardrail["maturity"] == "advanced"
    assert guardrail["status"] == "fail"
    assert guardrail["trigger"]["source"] in {"sarif", "cve"}


def test_pipeline_emits_ai_agent_analysis_when_enabled():
    orchestrator = PipelineOrchestrator()
    design_dataset, sbom, sarif, cve = build_orchestrator_payload()
    # Embed a LangChain reference in the design row to trigger detection
    design_dataset["rows"][0]["notes"] = "LangChain agent handling payments"

    overlay = OverlayConfig(
        mode="enterprise",
        ai_agents={
            "framework_signatures": [
                {"name": "LangChain", "keywords": ["langchain"]}
            ],
            "controls": {"default": {"recommended_controls": ["audit"]}},
        },
    )

    result = orchestrator.run(
        design_dataset=design_dataset,
        sbom=sbom,
        sarif=sarif,
        cve=cve,
        overlay=overlay,
    )

    ai_analysis = result.get("ai_agent_analysis")
    assert ai_analysis is not None
    assert ai_analysis["summary"]["components_with_agents"] >= 1
    assert ai_analysis["matches"][0]["framework"] == "LangChain"


def test_pipeline_emits_exploitability_summary():
    orchestrator = PipelineOrchestrator()
    design_dataset = {
        "columns": ["component"],
        "rows": [{"component": "RiskService"}],
    }
    sbom = NormalizedSBOM(
        format="cyclonedx",
        document={"name": "demo"},
        components=[SBOMComponent(name="riskservice", version="1.0.0")],
        relationships=[],
        services=[],
        vulnerabilities=[],
        metadata={"component_count": 1},
    )
    sarif = NormalizedSARIF(
        version="2.1.0",
        schema_uri=None,
        tool_names=["Analyzer"],
        findings=[],
        metadata={"run_count": 1, "finding_count": 0},
    )
    cve = NormalizedCVEFeed(
        records=[
            CVERecordSummary(
                cve_id="CVE-2024-9999",
                title="RiskService flaw",
                severity="medium",
                exploited=True,
                raw={"knownExploited": True, "epss": 0.72},
            )
        ],
        errors=[],
        metadata={"record_count": 1},
    )

    overlay = OverlayConfig(
        exploit_signals={
            "signals": {
                "kev": {"mode": "boolean", "fields": ["knownExploited"], "escalate_to": "critical"},
                "epss": {"mode": "probability", "fields": ["epss"], "threshold": 0.5},
            }
        }
    )

    result = orchestrator.run(
        design_dataset=design_dataset,
        sbom=sbom,
        sarif=sarif,
        cve=cve,
        overlay=overlay,
    )

    exploitability = result.get("exploitability_insights")
    assert exploitability is not None
    assert exploitability["overview"]["signals_configured"] == 2
    assert exploitability["overview"]["matched_records"] >= 2
    assert exploitability["signals"]["kev"]["match_count"] == 1
    assert exploitability["signals"]["epss"]["match_count"] == 1
    assert any(entry["recommended_severity"] == "critical" for entry in exploitability.get("escalations", []))


def test_pipeline_supports_design_rows_with_name_column():
    orchestrator = PipelineOrchestrator()
    design_dataset = {
        "columns": ["name", "notes"],
        "rows": [
            {"name": "Agent Service", "notes": "Critical"},
        ],
    }
    sbom = NormalizedSBOM(
        format="cyclonedx",
        document={"name": "demo"},
        components=[SBOMComponent(name="agent service", version="1.0.0")],
        relationships=[],
        services=[],
        vulnerabilities=[],
        metadata={"component_count": 1},
    )
    sarif = NormalizedSARIF(
        version="2.1.0",
        schema_uri=None,
        tool_names=["StaticAnalyzer"],
        findings=[
            SarifFinding(
                rule_id="AI-001",
                message="Issue in Agent Service",
                level="error",
                file="services/agent-service/app.py",
                line=10,
                raw={"analysisTarget": {"uri": "Agent Service"}},
            )
        ],
        metadata={"run_count": 1, "finding_count": 1},
    )
    cve = NormalizedCVEFeed(
        records=[
            CVERecordSummary(
                cve_id="CVE-2024-0001",
                title="Agent Service flaw",
                severity="high",
                exploited=False,
                raw={"component": "Agent Service"},
            )
        ],
        errors=[],
        metadata={"record_count": 1},
    )

    result = orchestrator.run(
        design_dataset=design_dataset,
        sbom=sbom,
        sarif=sarif,
        cve=cve,
    )

    crosswalk_entry = result["crosswalk"][0]
    assert crosswalk_entry["sbom_component"]["name"] == "agent service"
    assert crosswalk_entry["findings"]
    assert crosswalk_entry["cves"]
