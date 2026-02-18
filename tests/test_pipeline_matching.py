from __future__ import annotations

from pathlib import Path

import pytest

from apps.api.normalizers import (
    CVERecordSummary,
    InputNormalizer,
    NormalizedCVEFeed,
    NormalizedSARIF,
    NormalizedSBOM,
    SarifFinding,
    SBOMComponent,
)
from apps.api.pipeline import PipelineOrchestrator
from core.configuration import OverlayConfig

FIXTURE_DIR = Path(__file__).parent / "fixtures"


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


def test_provider_specific_sbom_parser_enables_pipeline(monkeypatch):
    monkeypatch.setattr("backend.normalizers.sbom_parser", None, raising=False)
    monkeypatch.setattr(
        "backend.normalizers.LIB4SBOM_IMPORT_ERROR",
        ImportError("lib4sbom not installed"),
        raising=False,
    )

    normalizer = InputNormalizer()
    payload = (FIXTURE_DIR / "github_dependency_snapshot.json").read_text()
    sbom = normalizer.load_sbom(payload)

    assert sbom.format == "github-dependency-snapshot"
    assert sbom.metadata["component_count"] == 2
    assert sbom.metadata["parser"] == "github-dependency-snapshot"

    design_dataset = {
        "columns": ["component"],
        "rows": [
            {"component": "payments-service"},
            {"component": "inventory-service"},
        ],
    }

    sarif = NormalizedSARIF(
        version="2.1.0",
        schema_uri=None,
        tool_names=["StaticAnalyzer"],
        findings=[
            SarifFinding(
                rule_id="CWE-89",
                message="SQL injection risk",
                level="error",
                file="services/payments-service/app.py",
                line=12,
                raw={"analysisTarget": {"uri": "payments-service"}},
            )
        ],
        metadata={"run_count": 1, "finding_count": 1},
    )

    cve = NormalizedCVEFeed(
        records=[
            CVERecordSummary(
                cve_id="CVE-2024-1111",
                title="Inventory flaw",
                severity="high",
                exploited=False,
                raw={"component": "inventory-service"},
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
    )

    crosswalk = result["crosswalk"]
    assert crosswalk[0]["sbom_component"]["name"] == "payments-service"
    assert crosswalk[0]["findings"][0]["rule_id"] == "CWE-89"
    assert crosswalk[1]["cves"][0]["cve_id"] == "CVE-2024-1111"


def test_provider_specific_syft_parser(monkeypatch):
    monkeypatch.setattr("backend.normalizers.sbom_parser", None, raising=False)
    monkeypatch.setattr(
        "backend.normalizers.LIB4SBOM_IMPORT_ERROR",
        ImportError("lib4sbom unavailable"),
        raising=False,
    )

    normalizer = InputNormalizer()
    payload = (FIXTURE_DIR / "syft_sample_sbom.json").read_text()
    sbom = normalizer.load_sbom(payload)

    component_names = {component.name for component in sbom.components}
    assert sbom.format == "syft-json"
    assert component_names == {"openssl", "libssl"}
    assert sbom.metadata["parser"] == "syft-json"


def test_provider_parser_surfaces_error_code(monkeypatch):
    monkeypatch.setattr("backend.normalizers.sbom_parser", None, raising=False)
    monkeypatch.setattr(
        "backend.normalizers.LIB4SBOM_IMPORT_ERROR",
        ImportError("lib4sbom missing for tests"),
        raising=False,
    )

    normalizer = InputNormalizer()
    with pytest.raises(RuntimeError) as excinfo:
        normalizer.load_sbom("{}")

    assert "SBOM_PARSER_MISSING" in str(excinfo.value)


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


def test_crosswalk_retains_design_indices_for_duplicates():
    orchestrator = PipelineOrchestrator()
    design_dataset = {
        "columns": ["component", "owner"],
        "rows": [
            {"component": "api-gateway", "owner": "team-a"},
            {"component": "api-gateway", "owner": "team-b"},
        ],
    }
    sbom = NormalizedSBOM(
        format="cyclonedx",
        document={"name": "duplicate"},
        components=[
            SBOMComponent(name="api-gateway", version="1.0.0", raw={}),
        ],
        relationships=[],
        services=[],
        vulnerabilities=[],
        metadata={"component_count": 1},
    )
    sarif = NormalizedSARIF(
        version="2.1.0",
        schema_uri=None,
        findings=[],
        tool_names=[],
        metadata={"finding_count": 0},
    )
    cve = NormalizedCVEFeed(records=[], errors=[], metadata={})

    result = orchestrator.run(
        design_dataset=design_dataset,
        sbom=sbom,
        sarif=sarif,
        cve=cve,
    )

    indices = [entry.get("design_index") for entry in result["crosswalk"]]
    assert indices == [0, 1]
    owners = [entry["design_row"]["owner"] for entry in result["crosswalk"]]
    assert owners == ["team-a", "team-b"]


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
            "framework_signatures": [{"name": "LangChain", "keywords": ["langchain"]}],
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
                "kev": {
                    "mode": "boolean",
                    "fields": ["knownExploited"],
                    "escalate_to": "critical",
                },
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
    assert any(
        entry["recommended_severity"] == "critical"
        for entry in exploitability.get("escalations", [])
    )


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


def test_pipeline_respects_module_toggles():
    orchestrator = PipelineOrchestrator()
    design_dataset, sbom, sarif, cve = build_orchestrator_payload()

    overlay = OverlayConfig(
        modules={
            "context_engine": {"enabled": False},
            "ai_agents": {"enabled": False},
        }
    )

    result = orchestrator.run(
        design_dataset=design_dataset,
        sbom=sbom,
        sarif=sarif,
        cve=cve,
        overlay=overlay,
    )

    assert "context_summary" not in result
    assert "ai_agent_analysis" not in result
    assert result["modules"]["status"]["context_engine"] == "disabled"


def test_pipeline_executes_custom_modules():
    orchestrator = PipelineOrchestrator()
    design_dataset, sbom, sarif, cve = build_orchestrator_payload()

    overlay = OverlayConfig(
        modules={
            "custom": [
                {
                    "name": "marker",
                    "entrypoint": "tests.sample_modules:record_outcome",
                    "config": {"marker": "observed"},
                }
            ]
        }
    )

    result = orchestrator.run(
        design_dataset=design_dataset,
        sbom=sbom,
        sarif=sarif,
        cve=cve,
        overlay=overlay,
    )

    assert result["custom_markers"] == ["observed"]
    custom_status = result["modules"]["custom"][0]
    assert custom_status["status"] == "executed"


def test_pipeline_emits_iac_posture_summary():
    orchestrator = PipelineOrchestrator()
    design_dataset = {
        "columns": ["component", "cloud", "environment"],
        "rows": [
            {"component": "Payments", "cloud": "aws", "environment": "prod"},
            {"component": "Analytics", "cloud": "gcp", "environment": "stage"},
            {"component": "Legacy", "cloud": "on-prem", "environment": "datacenter"},
        ],
    }
    sbom = NormalizedSBOM(
        format="cyclonedx",
        document={"name": "demo"},
        components=[],
        relationships=[],
        services=[],
        vulnerabilities=[],
        metadata={"component_count": 0},
    )
    sarif = NormalizedSARIF(
        version="2.1.0",
        schema_uri=None,
        tool_names=["Analyzer"],
        findings=[],
        metadata={"run_count": 1, "finding_count": 0},
    )
    cve = NormalizedCVEFeed(records=[], errors=[], metadata={"record_count": 0})

    overlay = OverlayConfig(
        modules={"iac_posture": {"enabled": True}},
        iac={
            "targets": [
                {
                    "id": "aws",
                    "match": ["aws"],
                    "required_artifacts": ["policy_automation"],
                    "recommended_controls": ["iam"],
                    "environments": ["prod"],
                },
                {
                    "id": "on_prem",
                    "match": ["on-prem"],
                    "required_artifacts": [],
                    "recommended_controls": ["patching"],
                    "environments": ["datacenter"],
                },
            ]
        },
    )

    result = orchestrator.run(
        design_dataset=design_dataset,
        sbom=sbom,
        sarif=sarif,
        cve=cve,
        overlay=overlay,
    )

    iac_posture = result.get("iac_posture")
    assert iac_posture is not None
    aws_entry = next(entry for entry in iac_posture["targets"] if entry["id"] == "aws")
    assert aws_entry["matched"] is True
    assert "Payments" in aws_entry["matched_components"]
    assert aws_entry["artifacts_missing"] == []
    assert iac_posture["unmatched_components"]
