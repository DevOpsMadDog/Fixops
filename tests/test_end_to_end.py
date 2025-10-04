import json

import csv
import json
import os
from io import StringIO

try:
    from fastapi.testclient import TestClient  # type: ignore
except Exception:  # pragma: no cover - fastapi is optional in some environments
    TestClient = None  # type: ignore

try:
    from backend.app import create_app
except Exception:  # pragma: no cover - allow environments without FastAPI
    create_app = None  # type: ignore
from backend.normalizers import InputNormalizer
from backend.pipeline import PipelineOrchestrator


def test_end_to_end_demo_pipeline():
    design_csv = """component,owner,criticality,notes\npayment-service,app-team,high,Handles card processing\nnotification-service,platform,medium,Sends emails\nai-orchestrator,ml-team,high,LangChain agent orchestrator for support bots\n"""

    sbom_document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "components": [
            {
                "type": "library",
                "name": "payment-service",
                "version": "1.0.0",
                "purl": "pkg:pypi/payment-service@1.0.0",
                "licenses": [{"license": "MIT"}],
            },
            {
                "type": "application",
                "name": "ai-orchestrator",
                "version": "0.4.0",
                "purl": "pkg:npm/langchain-agent@0.4.0",
                "licenses": [{"license": "Apache-2.0"}],
                "description": "LangChain powered support agent",
            },
        ],
    }

    cve_feed = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-0001",
                "title": "Example vulnerability in payment-service",
                "knownExploited": True,
                "severity": "high",
            }
        ]
    }

    sarif_document = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "DemoScanner"}},
                "results": [
                    {
                        "ruleId": "DEMO001",
                        "level": "error",
                        "message": {"text": "SQL injection risk"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "services/payment-service/app.py"
                                    },
                                    "region": {"startLine": 42},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }

    if TestClient is not None and create_app is not None:
        os.environ["FIXOPS_API_TOKEN"] = "demo-token"
        app = create_app()
        client = TestClient(app)

        response = client.post(
            "/inputs/design",
            headers={"X-API-Key": "demo-token"},
            files={"file": ("design.csv", design_csv, "text/csv")},
        )
        assert response.status_code == 200
        design_payload = response.json()
        assert design_payload["row_count"] == 3

        response = client.post(
            "/inputs/sbom",
            headers={"X-API-Key": "demo-token"},
            files={
                "file": (
                    "sbom.json",
                    json.dumps(sbom_document),
                    "application/json",
                )
            },
        )
        assert response.status_code == 200
        sbom_payload = response.json()
        assert sbom_payload["metadata"]["component_count"] == 2

        response = client.post(
            "/inputs/cve",
            headers={"X-API-Key": "demo-token"},
            files={
                "file": (
                    "kev.json",
                    json.dumps(cve_feed),
                    "application/json",
                )
            },
        )
        assert response.status_code == 200
        cve_payload = response.json()
        assert cve_payload["record_count"] == 1

        response = client.post(
            "/inputs/sarif",
            headers={"X-API-Key": "demo-token"},
            files={
                "file": (
                    "scan.sarif",
                    json.dumps(sarif_document),
                    "application/json",
                )
            },
        )
        assert response.status_code == 200
        sarif_payload = response.json()
        assert sarif_payload["metadata"]["finding_count"] == 1

        response = client.post("/pipeline/run", headers={"X-API-Key": "demo-token"})
        assert response.status_code == 200
        pipeline_payload = response.json()
        assert pipeline_payload["status"] == "ok"
        assert pipeline_payload["design_summary"]["row_count"] == 3
        assert len(pipeline_payload["crosswalk"]) == 3
        assert pipeline_payload["crosswalk"][0]["findings"]
        assert pipeline_payload["guardrail_evaluation"]["status"] in {"pass", "warn", "fail"}
        assert pipeline_payload["context_summary"]["summary"]["components_evaluated"] >= 1
        assert pipeline_payload["onboarding"]["mode"] == "demo"
        assert pipeline_payload["compliance_status"]["frameworks"]
        assert "bundle" in pipeline_payload["evidence_bundle"]["files"]
        assert "plans" in pipeline_payload["pricing_summary"]
        ai_analysis = pipeline_payload.get("ai_agent_analysis")
        assert ai_analysis and ai_analysis["summary"]["components_with_agents"] >= 1
        overlay = pipeline_payload["overlay"]
        assert overlay["mode"] == "demo"
        assert overlay["metadata"]["profile_applied"] == "demo"
        assert "required_inputs" in overlay
        os.environ.pop("FIXOPS_API_TOKEN", None)
    else:
        normalizer = InputNormalizer()
        reader = csv.DictReader(StringIO(design_csv))
        design_dataset = {"columns": reader.fieldnames or [], "rows": list(reader)}
        sbom = normalizer.load_sbom(json.dumps(sbom_document))
        cve_norm = normalizer.load_cve_feed(json.dumps(cve_feed))
        sarif_norm = normalizer.load_sarif(json.dumps(sarif_document))

        orchestrator = PipelineOrchestrator()
        pipeline_payload = orchestrator.run(
            design_dataset=design_dataset,
            sbom=sbom,
            sarif=sarif_norm,
            cve=cve_norm,
        )

        assert pipeline_payload["status"] == "ok"
        assert pipeline_payload["design_summary"]["row_count"] == 3
        assert len(pipeline_payload["crosswalk"]) == 3
        assert isinstance(pipeline_payload["crosswalk"][0]["findings"], list)
        if "ai_agent_analysis" in pipeline_payload:
            assert pipeline_payload["ai_agent_analysis"]["summary"]["components_with_agents"] >= 1
