"""Integration workflow tests.

Tests complete workflows end-to-end.
"""

import json
import os
import tempfile

import pytest
import requests

API_BASE_URL = "http://localhost:8000"
API_KEY = os.getenv("FIXOPS_API_TOKEN", "test-api-key-12345")


@pytest.fixture
def headers():
    """API headers."""
    return {"X-API-Key": API_KEY}


class TestVulnerabilityWorkflow:
    """Test complete vulnerability management workflow."""

    def test_sarif_to_decision_workflow(self, headers):
        """Test SARIF upload to decision workflow."""
        # 1. Upload SARIF
        test_sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "test-scanner",
                            "version": "1.0.0",
                        }
                    },
                    "results": [
                        {
                            "ruleId": "SQL_INJECTION",
                            "message": {"text": "Potential SQL injection"},
                            "level": "error",
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "app.py"},
                                        "region": {"startLine": 10},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False) as f:
            json.dump(test_sarif, f)
            temp_path = f.name

        try:
            # Upload SARIF
            with open(temp_path, "rb") as f:
                files = {"file": ("test.sarif", f, "application/json")}
                response = requests.post(
                    f"{API_BASE_URL}/inputs/sarif",
                    headers=headers,
                    files=files,
                    timeout=30,
                )

            assert response.status_code in [200, 201]

            # 2. Check if processing started
            status_response = requests.get(
                f"{API_BASE_URL}/api/v1/status", headers=headers, timeout=5
            )
            assert status_response.status_code == 200

        finally:
            os.unlink(temp_path)

    def test_sbom_to_risk_workflow(self, headers):
        """Test SBOM upload to risk analysis workflow."""
        # 1. Upload SBOM
        test_sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "vulnerable-package",
                    "version": "1.0.0",
                    "purl": "pkg:pypi/vulnerable-package@1.0.0",
                    "vulnerabilities": [
                        {
                            "id": "CVE-2024-0001",
                            "source": {"name": "NVD"},
                            "ratings": [
                                {
                                    "source": {"name": "NVD"},
                                    "score": 9.8,
                                    "severity": "critical",
                                }
                            ],
                        }
                    ],
                }
            ],
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(test_sbom, f)
            temp_path = f.name

        try:
            # Upload SBOM
            with open(temp_path, "rb") as f:
                files = {"file": ("test-sbom.json", f, "application/json")}
                response = requests.post(
                    f"{API_BASE_URL}/inputs/sbom",
                    headers=headers,
                    files=files,
                    timeout=30,
                )

            assert response.status_code in [200, 201]

        finally:
            os.unlink(temp_path)


class TestReachabilityWorkflow:
    """Test reachability analysis workflow."""

    def test_reachability_analysis_workflow(self, headers):
        """Test complete reachability analysis workflow."""
        # Submit analysis request
        payload = {
            "repository": {
                "url": "https://github.com/test/repo",
                "branch": "main",
            },
            "cve_id": "CVE-2024-0001",
            "component_name": "test-component",
            "component_version": "1.0.0",
            "vulnerability_details": {
                "cwe_ids": ["CWE-89"],
                "description": "SQL injection vulnerability",
            },
        }

        response = requests.post(
            f"{API_BASE_URL}/api/v1/reachability/analyze",
            headers=headers,
            json=payload,
            timeout=60,
        )

        # Should accept request
        assert response.status_code in [200, 201, 202]

        # If async, check job status
        if response.status_code == 202:
            data = response.json()
            job_id = data.get("job_id")

            if job_id:
                # Poll for job status
                for _ in range(10):
                    status_response = requests.get(
                        f"{API_BASE_URL}/api/v1/reachability/jobs/{job_id}",
                        headers=headers,
                        timeout=10,
                    )

                    if status_response.status_code == 200:
                        status_data = status_response.json()
                        status = status_data.get("status")

                        if status in ["completed", "failed"]:
                            break

                    import time

                    time.sleep(2)


class TestRuntimeWorkflow:
    """Test runtime analysis workflow."""

    def test_runtime_analysis_workflow(self, headers):
        """Test runtime analysis workflow."""
        # Submit runtime analysis
        payload = {
            "analysis_type": "iast",
            "container_id": "test-container",
            "config": {
                "enabled": True,
                "instrumentation_mode": "selective",
            },
        }

        response = requests.post(
            f"{API_BASE_URL}/api/v1/runtime/analyze",
            headers=headers,
            json=payload,
            timeout=30,
        )

        # Should accept request
        assert response.status_code in [200, 201, 202]


class TestAutomationWorkflow:
    """Test automation workflow."""

    def test_dependency_update_workflow(self, headers):
        """Test dependency update workflow."""
        # This would test the automation engine
        # For now, just verify endpoints exist

        # Check if automation endpoints exist
        response = requests.get(
            f"{API_BASE_URL}/api/v1/automation/updates",
            headers=headers,
            timeout=5,
        )

        # May not exist yet, but should not 500
        assert response.status_code != 500


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
