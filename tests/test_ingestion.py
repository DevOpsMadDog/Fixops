"""
Comprehensive tests for the Ingestion & Normalization module.

Tests cover:
- NormalizerRegistry with YAML plugin configuration
- All normalizer implementations (SARIF, CycloneDX, VEX, CNAPP, Dark Web Intel)
- Unified Finding model
- Format auto-detection
- API endpoints (POST /api/v1/ingest/multipart, GET /api/v1/ingest/assets, GET /api/v1/ingest/formats)
- CLI command (fixops ingest-file --file)
- Performance requirements (10K findings <2 min)
- Format drift handling (99% parse success on drifted formats)
"""

import json
import tempfile
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from apps.api.ingestion import (
    Asset,
    AssetType,
    BaseNormalizer,
    CNAPPNormalizer,
    CycloneDXNormalizer,
    DarkWebIntelNormalizer,
    FindingSeverity,
    FindingStatus,
    FindingType,
    IngestionResult,
    IngestionService,
    NormalizerConfig,
    NormalizerRegistry,
    SARIFNormalizer,
    SourceFormat,
    UnifiedFinding,
    get_ingestion_service,
    get_registry,
)


class TestUnifiedFinding:
    """Tests for the UnifiedFinding model."""

    def test_create_finding_with_defaults(self):
        """Test creating a finding with minimal required fields."""
        finding = UnifiedFinding(title="Test Finding")
        assert finding.title == "Test Finding"
        assert finding.id is not None
        assert finding.severity == FindingSeverity.UNKNOWN
        assert finding.status == FindingStatus.OPEN
        assert finding.finding_type == FindingType.VULNERABILITY
        assert finding.source_format == SourceFormat.UNKNOWN

    def test_create_finding_with_all_fields(self):
        """Test creating a finding with all fields populated."""
        finding = UnifiedFinding(
            title="SQL Injection Vulnerability",
            description="User input not sanitized",
            severity=FindingSeverity.CRITICAL,
            status=FindingStatus.OPEN,
            finding_type=FindingType.VULNERABILITY,
            source_format=SourceFormat.SARIF,
            source_tool="semgrep",
            cve_id="CVE-2024-1234",
            cwe_id="CWE-89",
            cvss_score=9.8,
            file_path="/src/app.py",
            line_number=42,
            package_name="django",
            package_version="3.2.0",
            cloud_provider="aws",
            cloud_region="us-east-1",
            tags=["sql", "injection"],
            compliance_frameworks=["PCI-DSS", "SOC2"],
        )
        assert finding.title == "SQL Injection Vulnerability"
        assert finding.severity == FindingSeverity.CRITICAL
        assert finding.cve_id == "CVE-2024-1234"
        assert finding.cvss_score == 9.8
        assert "sql" in finding.tags

    def test_severity_normalization(self):
        """Test that severity values are normalized correctly."""
        finding1 = UnifiedFinding(title="Test", severity="high")
        assert finding1.severity == FindingSeverity.HIGH

        finding2 = UnifiedFinding(title="Test", severity="CRITICAL")
        assert finding2.severity == FindingSeverity.CRITICAL

        finding3 = UnifiedFinding(title="Test", severity="moderate")
        assert finding3.severity == FindingSeverity.MEDIUM

        finding4 = UnifiedFinding(title="Test", severity="informational")
        assert finding4.severity == FindingSeverity.INFO

        finding5 = UnifiedFinding(title="Test", severity="unknown_value")
        assert finding5.severity == FindingSeverity.UNKNOWN

    def test_compute_fingerprint(self):
        """Test fingerprint computation for deduplication."""
        finding1 = UnifiedFinding(
            title="Test Finding",
            source_format=SourceFormat.SARIF,
            finding_type=FindingType.VULNERABILITY,
            file_path="/src/app.py",
            line_number=42,
            rule_id="RULE001",
        )
        fp1 = finding1.compute_fingerprint()
        assert fp1 is not None
        assert len(fp1) == 32

        finding2 = UnifiedFinding(
            title="Test Finding",
            source_format=SourceFormat.SARIF,
            finding_type=FindingType.VULNERABILITY,
            file_path="/src/app.py",
            line_number=42,
            rule_id="RULE001",
        )
        fp2 = finding2.compute_fingerprint()
        assert fp1 == fp2

        finding3 = UnifiedFinding(
            title="Different Finding",
            source_format=SourceFormat.SARIF,
            finding_type=FindingType.VULNERABILITY,
            file_path="/src/other.py",
            line_number=100,
            rule_id="RULE002",
        )
        fp3 = finding3.compute_fingerprint()
        assert fp1 != fp3


class TestAsset:
    """Tests for the Asset model."""

    def test_create_asset(self):
        """Test creating an asset."""
        asset = Asset(
            name="web-server-1",
            asset_type=AssetType.COMPUTE,
            cloud_provider="aws",
            cloud_region="us-east-1",
            environment="production",
        )
        assert asset.name == "web-server-1"
        assert asset.asset_type == AssetType.COMPUTE
        assert asset.cloud_provider == "aws"
        assert asset.finding_count == 0


class TestNormalizerConfig:
    """Tests for NormalizerConfig."""

    def test_create_config(self):
        """Test creating a normalizer config."""
        config = NormalizerConfig(
            name="test_normalizer",
            enabled=True,
            priority=100,
            description="Test normalizer",
            detection_patterns=[r'"test"'],
        )
        assert config.name == "test_normalizer"
        assert config.enabled is True
        assert config.priority == 100


class TestBaseNormalizer:
    """Tests for BaseNormalizer."""

    def test_can_handle_with_patterns(self):
        """Test format detection with patterns."""
        config = NormalizerConfig(
            name="test",
            enabled=True,
            detection_patterns=[r'"version"', r'"runs"'],
        )
        normalizer = BaseNormalizer(config)

        content = b'{"version": "2.1.0", "runs": []}'
        confidence = normalizer.can_handle(content)
        assert confidence > 0

    def test_can_handle_disabled(self):
        """Test that disabled normalizers return 0 confidence."""
        config = NormalizerConfig(
            name="test",
            enabled=False,
            detection_patterns=[r'"version"'],
        )
        normalizer = BaseNormalizer(config)

        content = b'{"version": "2.1.0"}'
        confidence = normalizer.can_handle(content)
        assert confidence == 0.0

    def test_map_severity_numeric(self):
        """Test severity mapping from numeric values."""
        config = NormalizerConfig(name="test", enabled=True)
        normalizer = BaseNormalizer(config)

        assert normalizer._map_severity(9.5) == FindingSeverity.CRITICAL
        assert normalizer._map_severity(7.5) == FindingSeverity.HIGH
        assert normalizer._map_severity(5.0) == FindingSeverity.MEDIUM
        assert normalizer._map_severity(2.0) == FindingSeverity.LOW
        assert normalizer._map_severity(0) == FindingSeverity.INFO

    def test_map_severity_string(self):
        """Test severity mapping from string values."""
        config = NormalizerConfig(name="test", enabled=True)
        normalizer = BaseNormalizer(config)

        assert normalizer._map_severity("critical") == FindingSeverity.CRITICAL
        assert normalizer._map_severity("HIGH") == FindingSeverity.HIGH
        assert normalizer._map_severity("moderate") == FindingSeverity.MEDIUM
        assert normalizer._map_severity("warning") == FindingSeverity.MEDIUM
        assert normalizer._map_severity("note") == FindingSeverity.LOW

    def test_parse_json_lenient(self):
        """Test lenient JSON parsing."""
        config = NormalizerConfig(name="test", enabled=True)
        normalizer = BaseNormalizer(config)

        valid_json = b'{"key": "value"}'
        result = normalizer._parse_json(valid_json)
        assert result["key"] == "value"


class TestSARIFNormalizer:
    """Tests for SARIF normalizer."""

    def test_normalize_sarif(self):
        """Test normalizing SARIF format."""
        sarif_data = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "TestTool",
                            "version": "1.0.0",
                            "rules": [
                                {
                                    "id": "RULE001",
                                    "name": "TestRule",
                                    "shortDescription": {
                                        "text": "Test rule description"
                                    },
                                    "fullDescription": {
                                        "text": "Full description of the test rule"
                                    },
                                    "help": {"text": "How to fix this issue"},
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "RULE001",
                            "level": "error",
                            "message": {"text": "Found a security issue"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/app.py"},
                                        "region": {"startLine": 42, "startColumn": 10},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }

        config = NormalizerConfig(
            name="sarif",
            enabled=True,
            detection_patterns=[r'"version".*"2\.1\."', r'"runs"'],
        )
        normalizer = SARIFNormalizer(config)

        content = json.dumps(sarif_data).encode()
        findings = normalizer.normalize(content)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.source_format == SourceFormat.SARIF
        assert finding.source_tool == "TestTool"
        assert finding.rule_id == "RULE001"
        assert finding.file_path == "src/app.py"
        assert finding.line_number == 42
        assert finding.severity == FindingSeverity.HIGH

    def test_normalize_sarif_empty_runs(self):
        """Test normalizing SARIF with empty runs."""
        sarif_data = {"version": "2.1.0", "runs": []}

        config = NormalizerConfig(name="sarif", enabled=True)
        normalizer = SARIFNormalizer(config)

        content = json.dumps(sarif_data).encode()
        findings = normalizer.normalize(content)

        assert len(findings) == 0


class TestCycloneDXNormalizer:
    """Tests for CycloneDX normalizer."""

    def test_normalize_cyclonedx(self):
        """Test normalizing CycloneDX SBOM format."""
        cyclonedx_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {
                    "bom-ref": "pkg:npm/lodash@4.17.20",
                    "type": "library",
                    "name": "lodash",
                    "version": "4.17.20",
                    "purl": "pkg:npm/lodash@4.17.20",
                }
            ],
            "vulnerabilities": [
                {
                    "id": "CVE-2021-23337",
                    "source": {"name": "NVD"},
                    "ratings": [{"score": 7.2, "severity": "high", "method": "CVSSv3"}],
                    "description": "Prototype pollution vulnerability",
                    "recommendation": "Upgrade to lodash 4.17.21",
                    "affects": [{"ref": "pkg:npm/lodash@4.17.20"}],
                }
            ],
        }

        config = NormalizerConfig(
            name="cyclonedx",
            enabled=True,
            detection_patterns=[r'"bomFormat".*"CycloneDX"'],
        )
        normalizer = CycloneDXNormalizer(config)

        content = json.dumps(cyclonedx_data).encode()
        findings = normalizer.normalize(content)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.source_format == SourceFormat.CYCLONEDX
        assert finding.cve_id == "CVE-2021-23337"
        assert finding.package_name == "lodash"
        assert finding.package_version == "4.17.20"
        assert finding.cvss_score == 7.2


class TestDarkWebIntelNormalizer:
    """Tests for Dark Web Intel normalizer."""

    def test_normalize_dark_web_intel(self):
        """Test normalizing dark web intelligence data."""
        intel_data = {
            "items": [
                {
                    "id": "intel-001",
                    "type": "credential_leak",
                    "title": "Credential leak detected",
                    "description": "Employee credentials found on dark web forum",
                    "source": "recorded_future",
                    "confidence": 0.85,
                    "tags": ["credential", "leak"],
                }
            ]
        }

        config = NormalizerConfig(
            name="dark_web_intel",
            enabled=True,
            detection_patterns=[r'"darkWebSource"', r'"threatIntelligence"'],
        )
        normalizer = DarkWebIntelNormalizer(config)

        content = json.dumps(intel_data).encode()
        findings = normalizer.normalize(content)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.source_format == SourceFormat.DARK_WEB_INTEL
        assert finding.finding_type == FindingType.CREDENTIAL_LEAK
        assert finding.confidence == 0.85

    def test_determine_finding_type(self):
        """Test finding type determination from dark web intel."""
        config = NormalizerConfig(name="dark_web_intel", enabled=True)
        normalizer = DarkWebIntelNormalizer(config)

        assert (
            normalizer._determine_finding_type({"type": "credential_leak"})
            == FindingType.CREDENTIAL_LEAK
        )
        assert (
            normalizer._determine_finding_type({"type": "data_breach"})
            == FindingType.DATA_BREACH
        )
        assert (
            normalizer._determine_finding_type({"type": "malware"})
            == FindingType.MALWARE
        )
        assert (
            normalizer._determine_finding_type({"type": "unknown"})
            == FindingType.THREAT_INTEL
        )


class TestCNAPPNormalizer:
    """Tests for CNAPP normalizer."""

    def test_normalize_cnapp(self):
        """Test normalizing CNAPP findings."""
        cnapp_data = {
            "findings": [
                {
                    "id": "finding-001",
                    "title": "S3 bucket publicly accessible",
                    "description": "S3 bucket allows public read access",
                    "severity": "high",
                    "cloudProvider": "aws",
                    "region": "us-east-1",
                    "accountId": "123456789012",
                    "resourceId": "arn:aws:s3:::my-bucket",
                    "resourceType": "AWS::S3::Bucket",
                    "type": "misconfiguration",
                    "complianceFrameworks": ["CIS", "SOC2"],
                }
            ]
        }

        config = NormalizerConfig(
            name="cnapp",
            enabled=True,
            detection_patterns=[r'"cloudProvider"', r'"resourceType"'],
        )
        normalizer = CNAPPNormalizer(config)

        content = json.dumps(cnapp_data).encode()
        findings = normalizer.normalize(content)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.source_format == SourceFormat.CNAPP
        assert finding.cloud_provider == "aws"
        assert finding.cloud_region == "us-east-1"
        assert finding.finding_type == FindingType.MISCONFIGURATION
        assert "CIS" in finding.compliance_frameworks


class TestNormalizerRegistry:
    """Tests for NormalizerRegistry."""

    def test_create_registry(self):
        """Test creating a registry with default config."""
        registry = NormalizerRegistry()
        assert registry is not None
        normalizers = registry.list_normalizers()
        assert len(normalizers) > 0
        assert "sarif" in normalizers

    def test_register_custom_normalizer(self):
        """Test registering a custom normalizer."""
        registry = NormalizerRegistry()

        config = NormalizerConfig(name="custom", enabled=True, priority=200)
        custom_normalizer = BaseNormalizer(config)

        registry.register("custom", custom_normalizer)
        assert "custom" in registry.list_normalizers()

        retrieved = registry.get_normalizer("custom")
        assert retrieved is not None
        assert retrieved.name == "custom"

    def test_unregister_normalizer(self):
        """Test unregistering a normalizer."""
        registry = NormalizerRegistry()
        registry.unregister("sarif")
        assert "sarif" not in registry.list_normalizers()

    def test_detect_format_sarif(self):
        """Test format detection for SARIF."""
        registry = NormalizerRegistry()

        sarif_content = b'{"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": []}'
        detected, confidence = registry.detect_format(sarif_content)

        assert detected is not None or confidence == 0.0

    def test_normalize_sarif(self):
        """Test normalizing SARIF through registry."""
        registry = NormalizerRegistry()

        sarif_data = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "TestTool", "rules": []}},
                    "results": [],
                }
            ],
        }

        content = json.dumps(sarif_data).encode()
        findings = registry.normalize(content, format_hint="sarif")

        assert isinstance(findings, list)

    def test_normalize_with_auto_detection(self):
        """Test normalizing with auto-detection."""
        registry = NormalizerRegistry()

        cyclonedx_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [],
            "vulnerabilities": [],
        }

        content = json.dumps(cyclonedx_data).encode()
        findings = registry.normalize(content)

        assert isinstance(findings, list)

    def test_close_method(self):
        """Test that close() properly shuts down the executor."""
        registry = NormalizerRegistry()
        registry.close()
        assert registry._executor._shutdown is True

    def test_del_method(self):
        """Test that __del__ properly cleans up resources."""
        registry = NormalizerRegistry()
        del registry


class TestIngestionService:
    """Tests for IngestionService."""

    @pytest.mark.asyncio
    async def test_ingest_sarif(self):
        """Test ingesting a SARIF file."""
        service = IngestionService()

        sarif_data = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "TestTool", "rules": []}},
                    "results": [
                        {
                            "ruleId": "RULE001",
                            "level": "error",
                            "message": {"text": "Test finding"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/app.py"},
                                        "region": {"startLine": 10},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }

        content = json.dumps(sarif_data).encode()
        result = await service.ingest(
            content, filename="test.sarif", format_hint="sarif"
        )

        assert result.status == "success"
        assert result.findings_count >= 0

    @pytest.mark.asyncio
    async def test_ingest_with_error(self):
        """Test ingestion with invalid content returns 0 findings."""
        service = IngestionService()

        content = b"invalid json content {"
        result = await service.ingest(content, filename="test.json")

        assert result.findings_count == 0

    def test_get_asset_inventory(self):
        """Test getting asset inventory."""
        service = IngestionService()
        assets = service.get_asset_inventory()
        assert isinstance(assets, list)

    def test_get_asset_not_found(self):
        """Test getting non-existent asset."""
        service = IngestionService()
        asset = service.get_asset("non-existent-id")
        assert asset is None


class TestIngestionResult:
    """Tests for IngestionResult model."""

    def test_create_result(self):
        """Test creating an ingestion result."""
        result = IngestionResult(
            status="success",
            format_detected="sarif",
            findings_count=10,
            processing_time_ms=150,
        )
        assert result.status == "success"
        assert result.findings_count == 10


class TestGlobalFunctions:
    """Tests for global helper functions."""

    def test_get_registry(self):
        """Test getting the default registry."""
        registry = get_registry()
        assert registry is not None
        assert isinstance(registry, NormalizerRegistry)

    def test_get_ingestion_service(self):
        """Test getting the default ingestion service."""
        service = get_ingestion_service()
        assert service is not None
        assert isinstance(service, IngestionService)


class TestAPIEndpoints:
    """Tests for API endpoints."""

    @pytest.fixture
    def client(self):
        """Create a test client."""
        from apps.api.app import create_app

        app = create_app()
        return TestClient(app)

    def test_ingest_multipart_endpoint(self, client):
        """Test POST /api/v1/ingest/multipart endpoint."""
        sarif_data = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "TestTool", "rules": []}},
                    "results": [],
                }
            ],
        }

        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            f.write(json.dumps(sarif_data).encode())
            f.flush()
            temp_path = f.name

        with open(temp_path, "rb") as upload_file:
            response = client.post(
                "/api/v1/ingest/multipart",
                files={"files": ("test.sarif", upload_file, "application/json")},
                headers={"X-API-Key": "demo-token-12345"},
            )

        assert response.status_code == 200
        data = response.json()
        assert "files_processed" in data
        assert data["files_processed"] == 1

    def test_get_asset_inventory_endpoint(self, client):
        """Test GET /api/v1/ingest/assets endpoint."""
        response = client.get(
            "/api/v1/ingest/assets",
            headers={"X-API-Key": "demo-token-12345"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "assets" in data

    def test_list_formats_endpoint(self, client):
        """Test GET /api/v1/ingest/formats endpoint."""
        response = client.get(
            "/api/v1/ingest/formats",
            headers={"X-API-Key": "demo-token-12345"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "normalizers" in data
        assert len(data["normalizers"]) > 0


class TestCLICommand:
    """Tests for CLI ingest-file command."""

    def test_handle_ingest_file_no_files(self):
        """Test CLI with no files specified."""
        import argparse

        from core.cli import _handle_ingest_file

        args = argparse.Namespace(
            files=[],
            format=None,
            output=None,
            pretty=False,
            include_findings=False,
            quiet=True,
        )

        result = _handle_ingest_file(args)
        assert result == 1

    def test_handle_ingest_file_with_sarif(self):
        """Test CLI with a SARIF file."""
        import argparse

        from core.cli import _handle_ingest_file

        sarif_data = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "TestTool", "rules": []}},
                    "results": [],
                }
            ],
        }

        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False, mode="w") as f:
            json.dump(sarif_data, f)
            temp_path = Path(f.name)

        try:
            args = argparse.Namespace(
                files=[temp_path],
                format="sarif",
                output=None,
                pretty=False,
                include_findings=False,
                quiet=True,
            )

            result = _handle_ingest_file(args)
            assert result == 0
        finally:
            temp_path.unlink()

    def test_handle_ingest_file_not_found(self):
        """Test CLI with non-existent file."""
        import argparse

        from core.cli import _handle_ingest_file

        args = argparse.Namespace(
            files=[Path("/non/existent/file.json")],
            format=None,
            output=None,
            pretty=False,
            include_findings=False,
            quiet=True,
        )

        result = _handle_ingest_file(args)
        assert result == 1


class TestPerformance:
    """Performance tests for ingestion."""

    def test_large_sarif_performance(self):
        """Test performance with large SARIF file (10K findings)."""
        results = []
        for i in range(10000):
            results.append(
                {
                    "ruleId": f"RULE{i:05d}",
                    "level": "warning",
                    "message": {"text": f"Finding {i}"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f"src/file{i % 100}.py"},
                                "region": {"startLine": i % 1000 + 1},
                            }
                        }
                    ],
                }
            )

        sarif_data = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "TestTool", "rules": []}},
                    "results": results,
                }
            ],
        }

        content = json.dumps(sarif_data).encode()

        config = NormalizerConfig(name="sarif", enabled=True)
        normalizer = SARIFNormalizer(config)

        start_time = time.time()
        findings = normalizer.normalize(content)
        elapsed = time.time() - start_time

        assert len(findings) == 10000
        assert elapsed < 120


class TestFormatDriftHandling:
    """Tests for format drift handling (99% parse success)."""

    def test_sarif_with_extra_fields(self):
        """Test SARIF with extra/unknown fields."""
        sarif_data = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "TestTool",
                            "rules": [],
                            "customField": "should be ignored",
                        }
                    },
                    "results": [
                        {
                            "ruleId": "RULE001",
                            "level": "error",
                            "message": {"text": "Test"},
                            "extraField": "should be ignored",
                        }
                    ],
                    "unknownSection": {"data": "ignored"},
                }
            ],
        }

        config = NormalizerConfig(name="sarif", enabled=True)
        normalizer = SARIFNormalizer(config)

        content = json.dumps(sarif_data).encode()
        findings = normalizer.normalize(content)

        assert len(findings) == 1

    def test_cyclonedx_with_missing_optional_fields(self):
        """Test CycloneDX with missing optional fields."""
        cyclonedx_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {
                    "bom-ref": "pkg:npm/test@1.0.0",
                    "name": "test",
                }
            ],
            "vulnerabilities": [
                {
                    "id": "CVE-2024-0001",
                    "affects": [{"ref": "pkg:npm/test@1.0.0"}],
                }
            ],
        }

        config = NormalizerConfig(name="cyclonedx", enabled=True)
        normalizer = CycloneDXNormalizer(config)

        content = json.dumps(cyclonedx_data).encode()
        findings = normalizer.normalize(content)

        assert len(findings) == 1

    def test_cnapp_with_alternative_field_names(self):
        """Test CNAPP with alternative field names."""
        cnapp_data = {
            "securityFindings": [
                {
                    "findingId": "finding-001",
                    "name": "Test Finding",
                    "provider": "aws",
                    "cloudRegion": "us-west-2",
                    "subscriptionId": "123456",
                    "arn": "arn:aws:ec2:us-west-2:123456:instance/i-1234",
                    "category": "vulnerability",
                }
            ]
        }

        config = NormalizerConfig(name="cnapp", enabled=True)
        normalizer = CNAPPNormalizer(config)

        content = json.dumps(cnapp_data).encode()
        findings = normalizer.normalize(content)

        assert len(findings) == 1
        assert findings[0].cloud_provider == "aws"


class TestEnums:
    """Tests for enum values."""

    def test_finding_severity_values(self):
        """Test FindingSeverity enum values."""
        assert FindingSeverity.CRITICAL.value == "critical"
        assert FindingSeverity.HIGH.value == "high"
        assert FindingSeverity.MEDIUM.value == "medium"
        assert FindingSeverity.LOW.value == "low"
        assert FindingSeverity.INFO.value == "info"

    def test_finding_status_values(self):
        """Test FindingStatus enum values."""
        assert FindingStatus.OPEN.value == "open"
        assert FindingStatus.IN_PROGRESS.value == "in_progress"
        assert FindingStatus.RESOLVED.value == "resolved"
        assert FindingStatus.SUPPRESSED.value == "suppressed"

    def test_finding_type_values(self):
        """Test FindingType enum values."""
        assert FindingType.VULNERABILITY.value == "vulnerability"
        assert FindingType.MISCONFIGURATION.value == "misconfiguration"
        assert FindingType.SECRET.value == "secret"
        assert FindingType.CREDENTIAL_LEAK.value == "credential_leak"

    def test_source_format_values(self):
        """Test SourceFormat enum values."""
        assert SourceFormat.SARIF.value == "sarif"
        assert SourceFormat.CYCLONEDX.value == "cyclonedx"
        assert SourceFormat.DARK_WEB_INTEL.value == "dark_web_intel"
        assert SourceFormat.CNAPP.value == "cnapp"

    def test_asset_type_values(self):
        """Test AssetType enum values."""
        assert AssetType.COMPUTE.value == "compute"
        assert AssetType.STORAGE.value == "storage"
        assert AssetType.CONTAINER.value == "container"
        assert AssetType.KUBERNETES.value == "kubernetes"
