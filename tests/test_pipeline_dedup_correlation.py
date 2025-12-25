import json

from apps.api.normalizers import InputNormalizer
from apps.api.pipeline import PipelineOrchestrator
from core.configuration import OverlayConfig


def test_pipeline_emits_cases_when_correlation_engine_enabled():
    normalizer = InputNormalizer()

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [{"name": "demo-lib", "version": "1.0.0"}],
    }

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "demo-sast"}},
                "results": [
                    {
                        "ruleId": "SAST-001",
                        "level": "error",
                        "message": {"text": "SQL injection"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "services/users.py"},
                                    "region": {"startLine": 10},
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "SAST-001",
                        "level": "error",
                        "message": {"text": "SQL injection"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "services/users.py"},
                                    "region": {"startLine": 10},
                                }
                            }
                        ],
                    },
                ],
            }
        ],
    }

    cve_feed = [
        {
            "cveID": "CVE-2024-1234",
            "shortDescription": "Demo CVE",
            "severity": "high",
            "knownExploited": False,
        }
    ]

    normalized_sbom = normalizer.load_sbom(json.dumps(sbom).encode("utf-8"))
    normalized_sarif = normalizer.load_sarif(json.dumps(sarif).encode("utf-8"))
    normalized_cve = normalizer.load_cve_feed(json.dumps(cve_feed).encode("utf-8"))

    overlay = OverlayConfig()
    overlay.modules["correlation_engine"] = {
        "enabled": True,
        "dedup_window_seconds": 3600,
    }

    orchestrator = PipelineOrchestrator()
    result = orchestrator.run(
        design_dataset={"columns": [], "rows": []},
        sbom=normalized_sbom,
        sarif=normalized_sarif,
        cve=normalized_cve,
        overlay=overlay,
    )

    assert "deduplication" in result
    assert "input_count" in result["deduplication"]
    assert "output_count" in result["deduplication"]
    assert "cases" in result
    assert isinstance(result["cases"], list)
    assert result["cases"]

