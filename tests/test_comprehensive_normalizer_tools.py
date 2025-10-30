"""Comprehensive tests for normalizer with all security tool formats."""

import json

from apps.api.normalizers import InputNormalizer
from apps.api.pipeline import PipelineOrchestrator
from tests.test_helpers import get_all_minimal_params


class TestSonarQubeNormalizer:
    """Test SonarQube SAST normalization."""

    def test_sonarqube_sarif_format(self):
        """Test SonarQube SARIF format normalization."""
        normalizer = InputNormalizer()

        sonarqube_sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "SonarQube"}},
                    "results": [
                        {
                            "ruleId": "java:S1234",
                            "level": "error",
                            "message": {"text": "Security vulnerability"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/Main.java"},
                                        "region": {"startLine": 42},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }

        normalized = normalizer.load_sarif(json.dumps(sonarqube_sarif))

        assert normalized.metadata["finding_count"] == 1
        assert "SonarQube" in normalized.tool_names


class TestSnykNormalizer:
    """Test SNYK SCA normalization."""

    def test_snyk_json_format(self):
        """Test SNYK JSON format normalization."""
        normalizer = InputNormalizer()

        snyk_sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Snyk"}},
                    "results": [
                        {
                            "ruleId": "SNYK-JS-LODASH-1234",
                            "level": "warning",
                            "message": {"text": "Vulnerable dependency"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "package.json"},
                                        "region": {"startLine": 10},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }

        normalized = normalizer.load_sarif(json.dumps(snyk_sarif))

        assert normalized.metadata["finding_count"] == 1
        assert "Snyk" in normalized.tool_names


class TestVeracodeNormalizer:
    """Test Veracode SAST/SCA/DAST normalization."""

    def test_veracode_sarif_format(self):
        """Test Veracode SARIF format normalization."""
        normalizer = InputNormalizer()

        veracode_sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Veracode"}},
                    "results": [
                        {
                            "ruleId": "CWE-89",
                            "level": "error",
                            "message": {"text": "SQL Injection"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/db.py"},
                                        "region": {"startLine": 100},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }

        normalized = normalizer.load_sarif(json.dumps(veracode_sarif))

        assert normalized.metadata["finding_count"] == 1
        assert "Veracode" in normalized.tool_names


class TestInvictiNormalizer:
    """Test Invicti DAST normalization."""

    def test_invicti_sarif_format(self):
        """Test Invicti DAST SARIF format normalization."""
        normalizer = InputNormalizer()

        invicti_sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Invicti"}},
                    "results": [
                        {
                            "ruleId": "XSS",
                            "level": "error",
                            "message": {"text": "Cross-site scripting"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": "https://example.com/page"
                                        },
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }

        normalized = normalizer.load_sarif(json.dumps(invicti_sarif))

        assert normalized.metadata["finding_count"] == 1
        assert "Invicti" in normalized.tool_names


class TestCNAPPTools:
    """Test CNAPP tools (WIZ, Palo Alto, CrowdStrike, SentinelOne)."""

    def test_wiz_cnapp_format(self):
        """Test WIZ CNAPP format normalization."""
        normalizer = InputNormalizer()

        wiz_cnapp = {
            "assets": [
                {
                    "id": "vm-prod-001",
                    "type": "VirtualMachine",
                    "cloud_provider": "AWS",
                }
            ],
            "findings": [
                {
                    "asset": "vm-prod-001",
                    "type": "Vulnerability",
                    "severity": "HIGH",
                    "title": "Unpatched CVE",
                }
            ],
        }

        normalized = normalizer.load_cnapp(json.dumps(wiz_cnapp))

        assert len(normalized.assets) == 1
        assert len(normalized.findings) == 1


class TestCWPPTools:
    """Test Cloud Workload Protection Platform (CWPP) - Orca Security."""

    def test_orca_security_cwpp(self):
        """Test Orca Security CWPP format."""
        normalizer = InputNormalizer()

        orca_cnapp = {
            "assets": [
                {
                    "id": "vm-prod-001",
                    "type": "VirtualMachine",
                    "cloud_provider": "AWS",
                }
            ],
            "findings": [
                {
                    "asset": "vm-prod-001",
                    "type": "Vulnerability",
                    "severity": "CRITICAL",
                    "title": "Unpatched kernel vulnerability",
                }
            ],
        }

        normalized = normalizer.load_cnapp(json.dumps(orca_cnapp))

        assert len(normalized.assets) == 1
        assert len(normalized.findings) == 1


class TestCSPMTools:
    """Test Cloud Security Posture Management (CSPM) - Tenable, Rapid7."""

    def test_tenable_cspm(self):
        """Test Tenable CSPM format."""
        normalizer = InputNormalizer()

        tenable_cnapp = {
            "assets": [{"id": "s3-bucket-prod", "type": "Storage"}],
            "findings": [
                {
                    "asset": "s3-bucket-prod",
                    "type": "Misconfiguration",
                    "severity": "HIGH",
                    "title": "S3 bucket publicly accessible",
                }
            ],
        }

        normalized = normalizer.load_cnapp(json.dumps(tenable_cnapp))

        assert len(normalized.assets) == 1
        assert len(normalized.findings) == 1

    def test_rapid7_cspm(self):
        """Test Rapid7 CSPM format."""
        normalizer = InputNormalizer()

        rapid7_cnapp = {
            "assets": [{"id": "azure-vm-001", "type": "VirtualMachine"}],
            "findings": [
                {
                    "asset": "azure-vm-001",
                    "type": "Misconfiguration",
                    "severity": "MEDIUM",
                    "title": "NSG allows unrestricted SSH",
                }
            ],
        }

        normalized = normalizer.load_cnapp(json.dumps(rapid7_cnapp))

        assert len(normalized.assets) == 1
        assert len(normalized.findings) == 1


class TestDSPMTools:
    """Test Data Security Posture Management (DSPM) - Sentra."""

    def test_sentra_dspm(self):
        """Test Sentra DSPM format."""
        normalizer = InputNormalizer()

        sentra_cnapp = {
            "assets": [{"id": "database-prod-001", "type": "Database"}],
            "findings": [
                {
                    "asset": "database-prod-001",
                    "type": "DataExposure",
                    "severity": "CRITICAL",
                    "title": "Unencrypted PII data",
                }
            ],
        }

        normalized = normalizer.load_cnapp(json.dumps(sentra_cnapp))

        assert len(normalized.assets) == 1
        assert len(normalized.findings) == 1


class TestEDRTools:
    """Test Endpoint Detection and Response (EDR) - Microsoft Defender."""

    def test_microsoft_defender_edr(self):
        """Test Microsoft Defender EDR format."""
        normalizer = InputNormalizer()

        defender_cnapp = {
            "assets": [{"id": "endpoint-win-001", "type": "Endpoint"}],
            "findings": [
                {
                    "asset": "endpoint-win-001",
                    "type": "Malware",
                    "severity": "CRITICAL",
                    "title": "Trojan detected",
                }
            ],
        }

        normalized = normalizer.load_cnapp(json.dumps(defender_cnapp))

        assert len(normalized.assets) == 1
        assert len(normalized.findings) == 1


class TestAPISecurityTools:
    """Test API Security tools - SALT."""

    def test_salt_api_security(self):
        """Test SALT API Security format."""
        normalizer = InputNormalizer()

        salt_sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "SALT"}},
                    "results": [
                        {
                            "ruleId": "API-001",
                            "level": "error",
                            "message": {"text": "API endpoint missing authentication"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "api/users.py"},
                                        "region": {"startLine": 45},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }

        normalized = normalizer.load_sarif(json.dumps(salt_sarif))

        assert normalized.metadata["finding_count"] == 1
        assert "SALT" in normalized.tool_names


class TestADRTools:
    """Test Application Detection and Response (ADR) - Contrast Security."""

    def test_contrast_security_adr(self):
        """Test Contrast Security ADR format."""
        normalizer = InputNormalizer()

        contrast_sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Contrast Security"}},
                    "results": [
                        {
                            "ruleId": "IAST-001",
                            "level": "error",
                            "message": {"text": "SQL injection at runtime"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/database.py"},
                                        "region": {"startLine": 123},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }

        normalized = normalizer.load_sarif(json.dumps(contrast_sarif))

        assert normalized.metadata["finding_count"] == 1
        assert "Contrast Security" in normalized.tool_names


class TestSBOMFormats:
    """Test SBOM format normalization."""

    def test_cyclonedx_sbom(self):
        """Test CycloneDX SBOM format."""
        normalizer = InputNormalizer()

        cyclonedx_doc = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "lodash",
                    "version": "4.17.20",
                    "purl": "pkg:npm/lodash@4.17.20",
                }
            ],
        }

        normalized = normalizer.load_sbom(json.dumps(cyclonedx_doc))

        assert normalized.metadata["component_count"] == 1
        assert any(c.name == "lodash" for c in normalized.components)

    def test_spdx_sbom(self):
        """Test SPDX SBOM format."""
        normalizer = InputNormalizer()

        spdx_document = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test-sbom",
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package-requests",
                    "name": "requests",
                    "versionInfo": "2.28.0",
                }
            ],
        }

        normalized = normalizer.load_sbom(json.dumps(spdx_document))

        assert normalized.metadata["component_count"] == 1
        assert any(c.name == "requests" for c in normalized.components)


class TestPipelineIntegration:
    """Test pipeline integration with all tools."""

    def test_pipeline_with_all_tools(self):
        """Test pipeline orchestrator with comprehensive tool data."""
        params = get_all_minimal_params()
        orchestrator = PipelineOrchestrator()

        result = orchestrator.run(
            design_dataset=params["design_dataset"],
            sbom=params["sbom"],
            sarif=params["sarif"],
            cve=params["cve"],
        )

        assert result["status"] == "ok"
        assert "processing_layer" in result
        assert "crosswalk" in result
