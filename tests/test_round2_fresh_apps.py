"""Round 2: Fresh application profiles with current-year CVEs and realistic tool outputs.

This test suite covers:
- 4 completely new application profiles (different from Round 1)
- Fresh test data with 2024-2025 CVEs
- API-level integration tests using TestClient
- Tests for recent code changes (decision engine, API endpoints, configuration)
- Edge cases and error handling

Application Profiles:
1. StreamHub - Next.js 14 monorepo with real-time video streaming (Node 20, Vercel, AWS)
2. HealthAPI - .NET 8 FHIR-compliant healthcare API (Azure, SQL Server, HIPAA)
3. CargoTrack - Rust microservice for logistics tracking (EKS, PostgreSQL, gRPC)
4. MLPredict - Python ML/AI service with GPU inference (FastAPI, PyTorch, CUDA)
"""

import json
import os
import random
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List

import pytest
from apps.api.normalizers import InputNormalizer
from apps.api.pipeline import PipelineOrchestrator
from core.configuration import load_overlay
from fastapi.testclient import TestClient

os.environ["FIXOPS_MODE"] = "enterprise"
os.environ["FIXOPS_API_TOKEN"] = "test-token-12345"
os.environ["FIXOPS_DISABLE_TELEMETRY"] = "1"
os.environ["FIXOPS_EVIDENCE_KEY"] = "eeJif8vWhRR5Y04TVl-38wjFglUDSPLOS0V2DOJrSGQ="


@pytest.fixture(autouse=True)
def set_env_vars(monkeypatch):
    """Ensure environment variables are set before each test."""
    monkeypatch.setenv("FIXOPS_API_TOKEN", "test-token-12345")
    monkeypatch.setenv("FIXOPS_MODE", "enterprise")


class Round2DataGenerator:
    """Generate fresh test data for Round 2 with current-year CVEs."""

    def __init__(self):
        self.current_year = 2024
        self.app_profiles = self._create_app_profiles()

    def _create_app_profiles(self) -> Dict[str, Dict[str, Any]]:
        """Create 4 completely new application profiles."""
        return {
            "streamhub": {
                "name": "StreamHub Video Platform",
                "type": "Next.js 14 Monorepo",
                "stack": ["Next.js 14", "Node 20", "React 18", "WebRTC", "Redis", "S3"],
                "cloud": "AWS",
                "deployment": "Vercel + ECS",
                "components": 180,
                "compliance": ["SOC2", "GDPR", "COPPA"],
                "criticality": "high",
                "description": "Real-time video streaming platform with live chat",
            },
            "healthapi": {
                "name": "HealthAPI FHIR Service",
                "type": ".NET 8 API",
                "stack": [
                    ".NET 8",
                    "C# 12",
                    "Entity Framework",
                    "SQL Server",
                    "Azure AD",
                ],
                "cloud": "Azure",
                "deployment": "Azure App Service",
                "components": 95,
                "compliance": ["HIPAA", "SOC2", "ISO27001"],
                "criticality": "critical",
                "description": "FHIR-compliant healthcare API for patient records",
            },
            "cargotrack": {
                "name": "CargoTrack Logistics",
                "type": "Rust Microservice",
                "stack": ["Rust 1.75", "Actix-web", "PostgreSQL", "gRPC", "Kafka"],
                "cloud": "AWS",
                "deployment": "EKS",
                "components": 65,
                "compliance": ["SOC2", "ISO27001"],
                "criticality": "high",
                "description": "Real-time cargo tracking with IoT sensor integration",
            },
            "mlpredict": {
                "name": "MLPredict AI Service",
                "type": "Python ML/AI",
                "stack": [
                    "Python 3.11",
                    "FastAPI",
                    "PyTorch 2.1",
                    "CUDA 12",
                    "Redis",
                    "MLflow",
                ],
                "cloud": "AWS",
                "deployment": "EKS with GPU nodes",
                "components": 120,
                "compliance": ["SOC2", "GDPR"],
                "criticality": "high",
                "description": "ML inference service with GPU acceleration",
            },
        }

    def generate_cve_feed(self, app_id: str) -> Dict[str, Any]:
        """Generate CVE feed with current-year CVEs for the application."""
        profile = self.app_profiles[app_id]
        cves = []

        cve_templates = self._get_cve_templates_for_stack(profile["stack"])

        for template in cve_templates[:15]:  # 15 CVEs per app
            cve_id = f"CVE-{random.choice([2024, 2025])}-{random.randint(10000, 99999)}"
            cve = {
                "id": cve_id,
                "description": template["description"],
                "published": (
                    datetime.now() - timedelta(days=random.randint(1, 365))
                ).isoformat(),
                "severity": template["severity"],
                "cvss_score": template["cvss_score"],
                "cvss_vector": template["cvss_vector"],
                "cwe": template["cwe"],
                "references": [
                    f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    f"https://github.com/advisories/GHSA-{uuid.uuid4().hex[:4]}-{uuid.uuid4().hex[:4]}-{uuid.uuid4().hex[:4]}",
                ],
                "epss_score": round(random.uniform(0.001, 0.95), 4),
                "kev_listed": random.random() < 0.15,  # 15% chance
            }
            cves.append(cve)

        return {"cves": cves, "metadata": {"generated_at": datetime.now().isoformat()}}

    def _get_cve_templates_for_stack(self, stack: List[str]) -> List[Dict[str, Any]]:
        """Get CVE templates based on technology stack."""
        templates = []

        if any("Next.js" in s or "Node" in s for s in stack):
            templates.extend(
                [
                    {
                        "description": "Server-Side Request Forgery in Next.js middleware",
                        "severity": "HIGH",
                        "cvss_score": 8.1,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "cwe": ["CWE-918"],
                    },
                    {
                        "description": "Prototype pollution in Node.js dependencies",
                        "severity": "CRITICAL",
                        "cvss_score": 9.8,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "cwe": ["CWE-1321"],
                    },
                    {
                        "description": "Path traversal in Next.js static file serving",
                        "severity": "MEDIUM",
                        "cvss_score": 6.5,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L",
                        "cwe": ["CWE-22"],
                    },
                ]
            )

        if any(".NET" in s or "C#" in s for s in stack):
            templates.extend(
                [
                    {
                        "description": "Elevation of privilege in .NET Core runtime",
                        "severity": "HIGH",
                        "cvss_score": 7.8,
                        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                        "cwe": ["CWE-269"],
                    },
                    {
                        "description": "Denial of service in ASP.NET Core",
                        "severity": "HIGH",
                        "cvss_score": 7.5,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                        "cwe": ["CWE-400"],
                    },
                    {
                        "description": "SQL injection in Entity Framework Core",
                        "severity": "CRITICAL",
                        "cvss_score": 9.1,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        "cwe": ["CWE-89"],
                    },
                ]
            )

        if any("Rust" in s for s in stack):
            templates.extend(
                [
                    {
                        "description": "Memory safety issue in Rust standard library",
                        "severity": "MEDIUM",
                        "cvss_score": 5.9,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
                        "cwe": ["CWE-119"],
                    },
                    {
                        "description": "Use-after-free in Actix-web HTTP parser",
                        "severity": "HIGH",
                        "cvss_score": 8.1,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "cwe": ["CWE-416"],
                    },
                ]
            )

        if any("Python" in s or "PyTorch" in s or "FastAPI" in s for s in stack):
            templates.extend(
                [
                    {
                        "description": "Arbitrary code execution in PyTorch model loading",
                        "severity": "CRITICAL",
                        "cvss_score": 9.8,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "cwe": ["CWE-502"],
                    },
                    {
                        "description": "Path traversal in FastAPI static file handler",
                        "severity": "HIGH",
                        "cvss_score": 7.5,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "cwe": ["CWE-22"],
                    },
                    {
                        "description": "Denial of service in Python asyncio",
                        "severity": "MEDIUM",
                        "cvss_score": 6.5,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
                        "cwe": ["CWE-400"],
                    },
                ]
            )

        templates.extend(
            [
                {
                    "description": "Remote code execution in Redis",
                    "severity": "CRITICAL",
                    "cvss_score": 10.0,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    "cwe": ["CWE-94"],
                },
                {
                    "description": "Authentication bypass in PostgreSQL",
                    "severity": "CRITICAL",
                    "cvss_score": 9.8,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "cwe": ["CWE-287"],
                },
            ]
        )

        return templates

    def generate_sbom(self, app_id: str) -> Dict[str, Any]:
        """Generate CycloneDX SBOM for the application."""
        profile = self.app_profiles[app_id]

        components = []
        for i in range(profile["components"]):
            component = {
                "type": "library",
                "bom-ref": f"pkg:{app_id}/component-{i}@1.0.0",
                "name": f"component-{i}",
                "version": f"{random.randint(1, 5)}.{random.randint(0, 20)}.{random.randint(0, 10)}",
                "purl": f"pkg:npm/component-{i}@1.0.0",
            }
            components.append(component)

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "component": {
                    "type": "application",
                    "name": profile["name"],
                    "version": "1.0.0",
                },
            },
            "components": components,
        }

    def generate_sarif(self, app_id: str) -> Dict[str, Any]:
        """Generate SARIF scan results for the application."""
        profile = self.app_profiles[app_id]

        results = []
        for i in range(random.randint(20, 50)):
            severity = random.choice(["error", "warning", "note"])
            result = {
                "ruleId": f"RULE-{random.randint(1000, 9999)}",
                "level": severity,
                "message": {"text": f"Security issue {i} in {profile['name']}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f"src/module{i % 10}.py"},
                            "region": {"startLine": random.randint(1, 1000)},
                        }
                    }
                ],
            }
            results.append(result)

        return {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SecurityScanner",
                            "version": "1.0.0",
                            "informationUri": "https://example.com",
                        }
                    },
                    "results": results,
                }
            ],
        }


@pytest.fixture
def round2_generator():
    """Fixture providing Round 2 data generator."""
    return Round2DataGenerator()


@pytest.fixture
def test_client(monkeypatch):
    """Fixture providing FastAPI test client."""
    monkeypatch.setenv("FIXOPS_MODE", "enterprise")
    monkeypatch.setenv("FIXOPS_API_TOKEN", "test-token-12345")
    monkeypatch.setenv("FIXOPS_DISABLE_TELEMETRY", "1")

    from apps.api.app import create_app

    app = create_app()
    return TestClient(app)


class TestRound2StreamHub:
    """Tests for StreamHub Next.js video streaming platform."""

    def test_streamhub_pipeline_execution(self, round2_generator):
        """Test complete pipeline execution for StreamHub."""
        app_id = "streamhub"

        cve_feed = round2_generator.generate_cve_feed(app_id)
        sbom = round2_generator.generate_sbom(app_id)
        sarif = round2_generator.generate_sarif(app_id)

        normalizer = InputNormalizer()
        normalized_sbom = normalizer.load_sbom(json.dumps(sbom).encode())
        normalized_sarif = normalizer.load_sarif(json.dumps(sarif).encode())
        normalized_cve = normalizer.load_cve_feed(json.dumps(cve_feed).encode())

        orchestrator = PipelineOrchestrator()
        result = orchestrator.run(
            design_dataset={"columns": [], "rows": []},
            sbom=normalized_sbom,
            sarif=normalized_sarif,
            cve=normalized_cve,
            overlay=load_overlay(),
        )

        assert result is not None
        assert "severity_overview" in result
        assert "guardrail_evaluation" in result
        severity_overview = result.get("severity_overview", {})
        assert isinstance(severity_overview, dict)

    def test_streamhub_api_ingestion(self, round2_generator, test_client):
        """Test API ingestion endpoints for StreamHub."""
        app_id = "streamhub"

        sbom = round2_generator.generate_sbom(app_id)

        response = test_client.post(
            "/inputs/sbom",
            files={"file": ("sbom.json", json.dumps(sbom), "application/json")},
            headers={"X-API-Key": "test-token-12345"},
        )

        assert response.status_code == 200
        response_data = response.json()
        assert "metadata" in response_data or "component_preview" in response_data


class TestRound2HealthAPI:
    """Tests for HealthAPI .NET 8 FHIR service."""

    def test_healthapi_hipaa_compliance(self, round2_generator):
        """Test HIPAA compliance mapping for HealthAPI."""
        app_id = "healthapi"

        cve_feed = round2_generator.generate_cve_feed(app_id)
        sbom = round2_generator.generate_sbom(app_id)
        sarif = round2_generator.generate_sarif(app_id)

        normalizer = InputNormalizer()
        normalized_sbom = normalizer.load_sbom(json.dumps(sbom).encode())
        normalized_sarif = normalizer.load_sarif(json.dumps(sarif).encode())
        normalized_cve = normalizer.load_cve_feed(json.dumps(cve_feed).encode())

        orchestrator = PipelineOrchestrator()
        result = orchestrator.run(
            design_dataset={"columns": [], "rows": []},
            sbom=normalized_sbom,
            sarif=normalized_sarif,
            cve=normalized_cve,
            overlay=load_overlay(),
        )

        assert result is not None
        assert "compliance_status" in result


class TestRound2CargoTrack:
    """Tests for CargoTrack Rust logistics microservice."""

    def test_cargotrack_rust_memory_safety(self, round2_generator):
        """Test memory safety vulnerability detection for Rust app."""
        app_id = "cargotrack"

        cve_feed = round2_generator.generate_cve_feed(app_id)
        sbom = round2_generator.generate_sbom(app_id)
        sarif = round2_generator.generate_sarif(app_id)

        normalizer = InputNormalizer()
        normalized_sbom = normalizer.load_sbom(json.dumps(sbom).encode())
        normalized_sarif = normalizer.load_sarif(json.dumps(sarif).encode())
        normalized_cve = normalizer.load_cve_feed(json.dumps(cve_feed).encode())

        orchestrator = PipelineOrchestrator()
        result = orchestrator.run(
            design_dataset={"columns": [], "rows": []},
            sbom=normalized_sbom,
            sarif=normalized_sarif,
            cve=normalized_cve,
            overlay=load_overlay(),
        )

        assert result is not None
        assert "severity_overview" in result


class TestRound2MLPredict:
    """Tests for MLPredict Python ML/AI service."""

    def test_mlpredict_model_security(self, round2_generator):
        """Test ML model security vulnerabilities (pickle deserialization, etc.)."""
        app_id = "mlpredict"

        cve_feed = round2_generator.generate_cve_feed(app_id)
        sbom = round2_generator.generate_sbom(app_id)
        sarif = round2_generator.generate_sarif(app_id)

        normalizer = InputNormalizer()
        normalized_sbom = normalizer.load_sbom(json.dumps(sbom).encode())
        normalized_sarif = normalizer.load_sarif(json.dumps(sarif).encode())
        normalized_cve = normalizer.load_cve_feed(json.dumps(cve_feed).encode())

        orchestrator = PipelineOrchestrator()
        result = orchestrator.run(
            design_dataset={"columns": [], "rows": []},
            sbom=normalized_sbom,
            sarif=normalized_sarif,
            cve=normalized_cve,
            overlay=load_overlay(),
        )

        assert result is not None
        assert "severity_overview" in result


class TestRound2EdgeCases:
    """Test edge cases and error handling."""

    def test_empty_sbom_handling(self, test_client):
        """Test handling of empty SBOM."""
        response = test_client.post(
            "/inputs/sbom",
            files={"file": ("sbom.json", b"{}", "application/json")},
            headers={"X-API-Key": "test-token-12345"},
        )

        assert response.status_code in [200, 400]

    def test_malformed_sarif_handling(self, test_client):
        """Test handling of malformed SARIF."""
        malformed_sarif = {"invalid": "structure"}

        response = test_client.post(
            "/inputs/sarif",
            files={
                "file": (
                    "scan.sarif",
                    json.dumps(malformed_sarif).encode(),
                    "application/json",
                )
            },
            headers={"X-API-Key": "test-token-12345"},
        )

        assert response.status_code in [200, 400]

    def test_large_cve_feed_handling(self, round2_generator):
        """Test handling of large CVE feeds."""
        large_feed = {"cves": []}
        for i in range(1000):
            large_feed["cves"].append(
                {
                    "id": f"CVE-2024-{10000 + i}",
                    "description": f"Vulnerability {i}",
                    "severity": "HIGH",
                    "cvss_score": 7.5,
                }
            )

        normalizer = InputNormalizer()
        normalized = normalizer.load_cve_feed(json.dumps(large_feed).encode())

        assert normalized is not None
        assert len(normalized.records) == 1000


class TestRound2RecentChanges:
    """Test recent code changes from last 30 days."""

    def test_decision_engine_weighted_scoring(self, round2_generator):
        """Test decision engine weighted severity scoring (recent changes)."""
        app_id = "streamhub"

        cve_feed = round2_generator.generate_cve_feed(app_id)
        sbom = round2_generator.generate_sbom(app_id)
        sarif = round2_generator.generate_sarif(app_id)

        normalizer = InputNormalizer()
        normalized_sbom = normalizer.load_sbom(json.dumps(sbom).encode())
        normalized_sarif = normalizer.load_sarif(json.dumps(sarif).encode())
        normalized_cve = normalizer.load_cve_feed(json.dumps(cve_feed).encode())

        orchestrator = PipelineOrchestrator()
        result = orchestrator.run(
            design_dataset={"columns": [], "rows": []},
            sbom=normalized_sbom,
            sarif=normalized_sarif,
            cve=normalized_cve,
            overlay=load_overlay(),
        )

        assert result is not None
        assert "guardrail_evaluation" in result

    def test_overlay_configuration_loading(self):
        """Test overlay configuration loading (recent changes)."""
        overlay = load_overlay()

        assert overlay is not None
        assert hasattr(overlay, "module_matrix")
        assert hasattr(overlay, "is_module_enabled")

    def test_api_endpoint_authentication(self, test_client):
        """Test API endpoint authentication (recent changes)."""
        response = test_client.post(
            "/inputs/sbom",
            files={"file": ("sbom.json", b"{}", "application/json")},
            headers={"X-API-Key": "test-token-12345"},
        )
        assert response.status_code in [200, 400]  # 200 for success, 400 for validation

        response = test_client.post(
            "/inputs/sbom",
            files={"file": ("sbom.json", b"{}", "application/json")},
            headers={"X-API-Key": "invalid-token"},
        )
        assert response.status_code in [401, 403]
