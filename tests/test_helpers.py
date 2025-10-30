"""Helper functions for comprehensive tests."""

import json

from apps.api.normalizers import InputNormalizer


def get_minimal_design_dataset():
    """Get minimal valid design dataset."""
    return {
        "columns": ["component", "owner", "criticality"],
        "rows": [
            {"component": "test-component", "owner": "test-team", "criticality": "low"}
        ],
    }


def get_minimal_sbom():
    """Get minimal valid SBOM."""
    normalizer = InputNormalizer()
    sbom_doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "components": [{"type": "application", "name": "test-app", "version": "1.0.0"}],
    }
    return normalizer.load_sbom(json.dumps(sbom_doc))


def get_minimal_sarif():
    """Get minimal valid SARIF."""
    normalizer = InputNormalizer()
    sarif_doc = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "TestScanner"}}, "results": []}],
    }
    return normalizer.load_sarif(json.dumps(sarif_doc))


def get_minimal_cve():
    """Get minimal valid CVE feed."""
    normalizer = InputNormalizer()
    cve_doc = {"vulnerabilities": []}
    return normalizer.load_cve_feed(json.dumps(cve_doc))


def get_all_minimal_params():
    """Get all minimal parameters required for PipelineOrchestrator.run()."""
    return {
        "design_dataset": get_minimal_design_dataset(),
        "sbom": get_minimal_sbom(),
        "sarif": get_minimal_sarif(),
        "cve": get_minimal_cve(),
    }
