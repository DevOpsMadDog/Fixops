import json
import os

import pytest
from apps.api.normalizers import InputNormalizer
from apps.api.pipeline import PipelineOrchestrator
from core.configuration import load_overlay


@pytest.fixture(autouse=True)
def set_env_vars(monkeypatch):
    """Set required environment variables for overlay loading."""
    monkeypatch.setenv(
        "FIXOPS_API_TOKEN", os.getenv("FIXOPS_API_TOKEN", "test-token-12345")
    )
    monkeypatch.setenv("FIXOPS_MODE", os.getenv("FIXOPS_MODE", "enterprise"))


def test_pipeline_emits_compliance_results(tmp_path):
    normalizer = InputNormalizer()
    sbom = normalizer.load_sbom(
        json.dumps({"bomFormat": "CycloneDX", "components": []}).encode("utf-8")
    )
    sarif = normalizer.load_sarif(
        json.dumps(
            {"runs": [{"results": [], "tool": {"driver": {"name": "scanner"}}}]}
        ).encode("utf-8")
    )
    cve = normalizer.load_cve_feed(json.dumps({"vulnerabilities": []}).encode("utf-8"))

    design_dataset = {
        "rows": [
            {"component": "identity", "owner": "appsec"},
        ]
    }

    overlay = load_overlay()
    overlay.modules.setdefault("compliance", True)
    overlay.modules.setdefault("guardrails", True)
    overlay.compliance.setdefault("control_map", {"AC-1": ["guardrails:status"]})

    orchestrator = PipelineOrchestrator()
    result = orchestrator.run(design_dataset, sbom, sarif, cve, overlay=overlay)

    assert "compliance_results" in result
    assert any(item["control_id"] == "AC-1" for item in result["compliance_results"])
