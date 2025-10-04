import json

import csv
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
    design_csv = """component,owner,criticality\npayment-service,app-team,high\nnotification-service,platform,medium\n"""

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
            }
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
        app = create_app()
        client = TestClient(app)

        response = client.post(
            "/inputs/design",
            files={"file": ("design.csv", design_csv, "text/csv")},
        )
        assert response.status_code == 200
        design_payload = response.json()
        assert design_payload["row_count"] == 2

        response = client.post(
            "/inputs/sbom",
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
        assert sbom_payload["metadata"]["component_count"] == 1

        response = client.post(
            "/inputs/cve",
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

        response = client.post("/pipeline/run")
        assert response.status_code == 200
        pipeline_payload = response.json()
        assert pipeline_payload["status"] == "ok"
        assert pipeline_payload["design_summary"]["row_count"] == 2
        assert len(pipeline_payload["crosswalk"]) == 2
        assert pipeline_payload["crosswalk"][0]["findings"]
        overlay = pipeline_payload["overlay"]
        assert overlay["mode"] == "demo"
        assert overlay["metadata"]["profile_applied"] == "demo"
        assert "required_inputs" in overlay
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
        assert pipeline_payload["design_summary"]["row_count"] == 2
        assert len(pipeline_payload["crosswalk"]) == 2
        assert isinstance(pipeline_payload["crosswalk"][0]["findings"], list)
