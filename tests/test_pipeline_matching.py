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


