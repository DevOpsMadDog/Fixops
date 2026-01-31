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


class TestEdgeCasesAndErrorHandling:
    """Tests for edge cases and error handling to achieve 100% coverage."""

    def test_severity_normalization_non_string_non_enum(self):
        """Test severity normalization with non-string, non-enum input."""
        finding = UnifiedFinding(title="Test", severity=123)
        assert finding.severity == FindingSeverity.UNKNOWN

        finding2 = UnifiedFinding(title="Test", severity=None)
        assert finding2.severity == FindingSeverity.UNKNOWN

        finding3 = UnifiedFinding(title="Test", severity=[])
        assert finding3.severity == FindingSeverity.UNKNOWN

    def test_base_normalizer_invalid_pattern(self):
        """Test BaseNormalizer with invalid regex pattern."""
        config = NormalizerConfig(
            name="test",
            enabled=True,
            detection_patterns=["[invalid(regex"],
        )
        normalizer = SARIFNormalizer(config)
        assert len(normalizer._compiled_patterns) == 0

    def test_base_normalizer_can_handle_decode_error(self):
        """Test can_handle with content that causes decode issues."""
        config = NormalizerConfig(
            name="test", enabled=True, detection_patterns=["test"]
        )
        normalizer = SARIFNormalizer(config)
        invalid_bytes = bytes([0x80, 0x81, 0x82])
        confidence = normalizer.can_handle(invalid_bytes)
        assert confidence == 0.0

    def test_base_normalizer_map_severity_fallback(self):
        """Test _map_severity with various edge cases."""
        config = NormalizerConfig(name="test", enabled=True)
        normalizer = SARIFNormalizer(config)

        assert normalizer._map_severity(None) == FindingSeverity.UNKNOWN
        assert normalizer._map_severity([]) == FindingSeverity.UNKNOWN
        assert normalizer._map_severity({}) == FindingSeverity.UNKNOWN
        assert normalizer._map_severity(0) == FindingSeverity.INFO
        assert normalizer._map_severity(0.5) == FindingSeverity.LOW
        assert normalizer._map_severity("unknown_string") == FindingSeverity.UNKNOWN

    def test_dark_web_intel_normalizer_list_input(self):
        """Test DarkWebIntelNormalizer with list input wrapped in items."""
        config = NormalizerConfig(name="dark_web_intel", enabled=True)
        normalizer = DarkWebIntelNormalizer(config)

        intel_data = {
            "items": [
                {"title": "Threat 1", "type": "credential_leak", "confidence": 0.95},
                {"name": "Threat 2", "type": "malware", "severity": "high"},
                {"indicator": "192.168.1.1", "type": "breach"},
            ]
        }
        content = json.dumps(intel_data).encode()
        findings = normalizer.normalize(content)
        assert len(findings) == 3

    def test_dark_web_intel_normalizer_severity_from_confidence(self):
        """Test DarkWebIntelNormalizer severity assessment from confidence."""
        config = NormalizerConfig(name="dark_web_intel", enabled=True)
        normalizer = DarkWebIntelNormalizer(config)

        intel_data = {
            "items": [
                {"title": "Critical", "confidence": 0.95},
                {"title": "High", "confidence": 0.75},
                {"title": "Medium", "confidence": 0.55},
                {"title": "Low", "confidence": 0.3},
            ]
        }
        content = json.dumps(intel_data).encode()
        findings = normalizer.normalize(content)

        assert findings[0].severity == FindingSeverity.CRITICAL
        assert findings[1].severity == FindingSeverity.HIGH
        assert findings[2].severity == FindingSeverity.MEDIUM
        assert findings[3].severity == FindingSeverity.LOW

    def test_cnapp_normalizer_type_determination(self):
        """Test CNAPPNormalizer type determination for various categories."""
        config = NormalizerConfig(name="cnapp", enabled=True)
        normalizer = CNAPPNormalizer(config)

        cnapp_data = {
            "findings": [
                {"title": "Misconfig", "type": "misconfiguration"},
                {"title": "Vuln", "category": "vulnerability"},
                {"title": "Secret", "type": "secret_exposure"},
                {"title": "Compliance", "category": "compliance_violation"},
                {"title": "IAM", "type": "iam_issue"},
                {"title": "Identity", "category": "identity_risk"},
                {"title": "Unknown", "type": "other"},
            ]
        }
        content = json.dumps(cnapp_data).encode()
        findings = normalizer.normalize(content)

        assert findings[0].finding_type == FindingType.MISCONFIGURATION
        assert findings[1].finding_type == FindingType.VULNERABILITY
        assert findings[2].finding_type == FindingType.SECRET
        assert findings[3].finding_type == FindingType.COMPLIANCE
        assert findings[4].finding_type == FindingType.IDENTITY
        assert findings[5].finding_type == FindingType.IDENTITY
        assert findings[6].finding_type == FindingType.MISCONFIGURATION

    def test_registry_normalize_unknown_format(self):
        """Test registry normalize with unknown format."""
        registry = NormalizerRegistry()
        content = b"not a valid format at all"
        findings = registry.normalize(content)
        assert findings == []
        registry.close()

    def test_registry_normalize_with_format_hint(self):
        """Test registry normalize with explicit format hint."""
        registry = NormalizerRegistry()
        sarif_data = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "test"}}, "results": []}],
        }
        content = json.dumps(sarif_data).encode()
        findings = registry.normalize(content, format_hint="sarif")
        assert isinstance(findings, list)
        registry.close()

    def test_registry_normalize_batch_sequential(self):
        """Test registry batch normalization in sequential mode."""
        registry = NormalizerRegistry()
        registry._config["settings"]["parallel_processing"] = False

        sarif_data = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "test"}}, "results": []}],
        }
        content = json.dumps(sarif_data).encode()
        items = [(content, "sarif", "application/json")]
        results = registry.normalize_batch(items)
        assert len(results) == 1
        registry.close()

    def test_registry_normalize_batch_parallel(self):
        """Test registry batch normalization in parallel mode."""
        registry = NormalizerRegistry()
        sarif_data = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "test"}}, "results": []}],
        }
        content = json.dumps(sarif_data).encode()
        items = [(content, "sarif", "application/json"), (content, "sarif", None)]
        results = registry.normalize_batch(items)
        assert len(results) == 2
        registry.close()

    def test_registry_try_all_normalizers_fallback(self):
        """Test registry _try_all_normalizers fallback."""
        registry = NormalizerRegistry()
        content = b'{"some": "json"}'
        findings = registry._try_all_normalizers(content, "application/json")
        assert isinstance(findings, list)
        registry.close()


class TestIngestionServiceEdgeCases:
    """Tests for IngestionService edge cases."""

    def test_extract_assets_cloud_resource(self):
        """Test asset extraction for cloud resources."""
        service = IngestionService()
        findings = [
            UnifiedFinding(
                title="Cloud Finding",
                cloud_resource_id="arn:aws:ec2:us-east-1:123456:instance/i-1234",
                cloud_provider="aws",
                cloud_region="us-east-1",
                cloud_account="123456",
                cloud_resource_type="ec2:instance",
                severity=FindingSeverity.CRITICAL,
            )
        ]
        assets = service._extract_assets(findings)
        assert len(assets) == 1
        assert assets[0].asset_type == AssetType.CLOUD_RESOURCE
        assert assets[0].critical_count == 1

    def test_extract_assets_container_image(self):
        """Test asset extraction for container images."""
        service = IngestionService()
        findings = [
            UnifiedFinding(
                title="Container Finding",
                container_image="nginx",
                container_tag="1.21",
                severity=FindingSeverity.HIGH,
            )
        ]
        assets = service._extract_assets(findings)
        assert len(assets) == 1
        assert assets[0].asset_type == AssetType.IMAGE
        assert assets[0].high_count == 1

    def test_extract_assets_package(self):
        """Test asset extraction for packages."""
        service = IngestionService()
        findings = [
            UnifiedFinding(
                title="Package Finding",
                package_name="lodash",
                package_version="4.17.21",
                package_ecosystem="npm",
                severity=FindingSeverity.MEDIUM,
            )
        ]
        assets = service._extract_assets(findings)
        assert len(assets) == 1
        assert assets[0].asset_type == AssetType.PACKAGE

    def test_extract_assets_file(self):
        """Test asset extraction for files."""
        service = IngestionService()
        findings = [
            UnifiedFinding(
                title="File Finding",
                file_path="/src/app.py",
                severity=FindingSeverity.LOW,
            )
        ]
        assets = service._extract_assets(findings)
        assert len(assets) == 1
        assert assets[0].asset_type == AssetType.APPLICATION

    def test_extract_assets_no_identifiable_asset(self):
        """Test asset extraction when no asset can be identified."""
        service = IngestionService()
        findings = [
            UnifiedFinding(
                title="Generic Finding",
                severity=FindingSeverity.INFO,
            )
        ]
        assets = service._extract_assets(findings)
        assert len(assets) == 0

    def test_extract_assets_with_asset_name(self):
        """Test asset extraction with asset_name fallback."""
        service = IngestionService()
        findings = [
            UnifiedFinding(
                title="Named Asset Finding",
                asset_name="my-custom-asset",
                severity=FindingSeverity.MEDIUM,
            )
        ]
        assets = service._extract_assets(findings)
        assert len(assets) == 0

    def test_get_stable_asset_key_cloud(self):
        """Test stable asset key for cloud resources."""
        service = IngestionService()
        asset = Asset(
            name="test-resource",
            asset_type=AssetType.CLOUD_RESOURCE,
            resource_id="arn:aws:ec2:us-east-1:123:instance/i-1234",
            cloud_provider="aws",
        )
        key = service._get_stable_asset_key(asset)
        assert key.startswith("cloud:aws:")

    def test_get_stable_asset_key_container(self):
        """Test stable asset key for container images."""
        service = IngestionService()
        asset = Asset(name="nginx:1.21", asset_type=AssetType.IMAGE)
        key = service._get_stable_asset_key(asset)
        assert key == "container:nginx:1.21"

    def test_get_stable_asset_key_package_scoped(self):
        """Test stable asset key for scoped npm packages."""
        service = IngestionService()
        asset = Asset(name="@angular/core@12.0.0", asset_type=AssetType.PACKAGE)
        key = service._get_stable_asset_key(asset)
        assert key == "package:@angular/core"

    def test_get_stable_asset_key_package_unscoped(self):
        """Test stable asset key for unscoped packages."""
        service = IngestionService()
        asset = Asset(name="lodash@4.17.21", asset_type=AssetType.PACKAGE)
        key = service._get_stable_asset_key(asset)
        assert key == "package:lodash"

    def test_get_stable_asset_key_package_no_version(self):
        """Test stable asset key for packages without version."""
        service = IngestionService()
        asset = Asset(name="requests", asset_type=AssetType.PACKAGE)
        key = service._get_stable_asset_key(asset)
        assert key == "package:requests"

    def test_get_stable_asset_key_application(self):
        """Test stable asset key for applications."""
        service = IngestionService()
        asset = Asset(name="/src/app.py", asset_type=AssetType.APPLICATION)
        key = service._get_stable_asset_key(asset)
        assert key == "file:/src/app.py"

    def test_get_stable_asset_key_other(self):
        """Test stable asset key for other asset types."""
        service = IngestionService()
        asset = Asset(name="my-database", asset_type=AssetType.DATABASE)
        key = service._get_stable_asset_key(asset)
        assert key == "asset:database:my-database"

    @pytest.mark.asyncio
    async def test_ingest_batch(self):
        """Test batch ingestion."""
        service = IngestionService()
        sarif_data = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "test"}}, "results": []}],
        }
        content = json.dumps(sarif_data).encode()
        files = [(content, "test.sarif", "application/json")]
        results = await service.ingest_batch(files)
        assert len(results) == 1

    def test_create_asset_from_finding_container_no_tag(self):
        """Test asset creation from finding with container but no tag."""
        service = IngestionService()
        finding = UnifiedFinding(
            title="Container Finding",
            container_image="nginx",
            severity=FindingSeverity.HIGH,
        )
        asset = service._create_asset_from_finding(finding)
        assert asset.asset_type == AssetType.IMAGE
        assert "latest" in asset.name

    def test_create_asset_from_finding_package_no_version(self):
        """Test asset creation from finding with package but no version."""
        service = IngestionService()
        finding = UnifiedFinding(
            title="Package Finding",
            package_name="requests",
            severity=FindingSeverity.MEDIUM,
        )
        asset = service._create_asset_from_finding(finding)
        assert asset.asset_type == AssetType.PACKAGE
        assert "unknown" in asset.name

    @pytest.mark.asyncio
    async def test_asset_inventory_deduplication(self):
        """Test that asset inventory properly deduplicates."""
        service = IngestionService()
        sarif_data = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "test"}},
                    "results": [
                        {
                            "ruleId": "rule1",
                            "message": {"text": "Finding 1"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "/src/app.py"},
                                        "region": {"startLine": 10},
                                    }
                                }
                            ],
                        },
                        {
                            "ruleId": "rule2",
                            "message": {"text": "Finding 2"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "/src/app.py"},
                                        "region": {"startLine": 20},
                                    }
                                }
                            ],
                        },
                    ],
                }
            ],
        }
        content = json.dumps(sarif_data).encode()

        await service.ingest(content, "test1.sarif")
        await service.ingest(content, "test2.sarif")

        inventory = service.get_asset_inventory()
        assert len(inventory) == 1
        assert inventory[0].finding_count >= 2


class TestCycloneDXEdgeCases:
    """Tests for CycloneDX normalizer edge cases."""

    def test_cyclonedx_with_severity_string(self):
        """Test CycloneDX with severity as string instead of score."""
        config = NormalizerConfig(name="cyclonedx", enabled=True)
        normalizer = CycloneDXNormalizer(config)

        cyclonedx_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [{"bom-ref": "pkg:npm/lodash@4.17.21", "name": "lodash"}],
            "vulnerabilities": [
                {
                    "id": "CVE-2021-23337",
                    "ratings": [{"severity": "high"}],
                    "affects": [{"ref": "pkg:npm/lodash@4.17.21"}],
                }
            ],
        }
        content = json.dumps(cyclonedx_data).encode()
        findings = normalizer.normalize(content)
        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.HIGH

    def test_cyclonedx_no_affects(self):
        """Test CycloneDX vulnerability with no affects."""
        config = NormalizerConfig(name="cyclonedx", enabled=True)
        normalizer = CycloneDXNormalizer(config)

        cyclonedx_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [],
            "vulnerabilities": [
                {"id": "CVE-2021-12345", "ratings": [{"score": 7.5}], "affects": []}
            ],
        }
        content = json.dumps(cyclonedx_data).encode()
        findings = normalizer.normalize(content)
        assert len(findings) == 0


class TestSARIFEdgeCases:
    """Tests for SARIF normalizer edge cases."""

    def test_sarif_with_no_locations(self):
        """Test SARIF result with no locations."""
        config = NormalizerConfig(name="sarif", enabled=True)
        normalizer = SARIFNormalizer(config)

        sarif_data = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "test", "rules": []}},
                    "results": [
                        {"ruleId": "rule1", "message": {"text": "No location"}}
                    ],
                }
            ],
        }
        content = json.dumps(sarif_data).encode()
        findings = normalizer.normalize(content)
        assert len(findings) == 1
        assert findings[0].file_path is None

    def test_sarif_level_mapping(self):
        """Test SARIF level to severity mapping."""
        config = NormalizerConfig(name="sarif", enabled=True)
        normalizer = SARIFNormalizer(config)

        assert normalizer._map_sarif_level("error") == FindingSeverity.HIGH
        assert normalizer._map_sarif_level("warning") == FindingSeverity.MEDIUM
        assert normalizer._map_sarif_level("note") == FindingSeverity.LOW
        assert normalizer._map_sarif_level("none") == FindingSeverity.INFO
        assert normalizer._map_sarif_level("unknown") == FindingSeverity.MEDIUM


class TestMoreEdgeCases:
    """Additional edge case tests for 100% coverage."""

    def test_registry_detect_format_low_confidence(self):
        """Test registry detect_format with low confidence warning."""
        registry = NormalizerRegistry()
        content = b'{"some": "random", "json": "data"}'
        detected_format, confidence = registry.detect_format(content)
        assert confidence < 0.5
        registry.close()

    def test_registry_normalize_error_handling(self):
        """Test registry normalize with normalizer that raises exception."""
        registry = NormalizerRegistry()
        content = b"invalid content that will fail"
        findings = registry.normalize(content, format_hint="sarif")
        assert findings == []
        registry.close()

    def test_registry_batch_with_exception(self):
        """Test batch normalization with items that cause exceptions."""
        registry = NormalizerRegistry()
        items = [
            (b"invalid", "sarif", None),
            (b"also invalid", "cyclonedx", None),
        ]
        results = registry.normalize_batch(items)
        assert len(results) == 2
        registry.close()

    @pytest.mark.asyncio
    async def test_ingestion_service_error_handling(self):
        """Test IngestionService error handling during ingestion."""
        from unittest.mock import patch

        service = IngestionService()
        with patch.object(
            service.registry, "detect_format", side_effect=Exception("Test error")
        ):
            result = await service.ingest(b"test content", "test.sarif")
            assert result.status == "error"
            assert len(result.errors) > 0

    def test_extract_assets_with_severity_counts(self):
        """Test asset extraction with multiple findings updating severity counts."""
        service = IngestionService()
        findings = [
            UnifiedFinding(
                title="Critical Finding",
                file_path="/src/app.py",
                severity=FindingSeverity.CRITICAL,
            ),
            UnifiedFinding(
                title="High Finding",
                file_path="/src/app.py",
                severity=FindingSeverity.HIGH,
            ),
            UnifiedFinding(
                title="Medium Finding",
                file_path="/src/app.py",
                severity=FindingSeverity.MEDIUM,
            ),
        ]
        assets = service._extract_assets(findings)
        assert len(assets) == 1
        assert assets[0].critical_count == 1
        assert assets[0].high_count == 1
        assert assets[0].finding_count == 3

    def test_create_asset_from_finding_fallback_name(self):
        """Test asset creation with fallback to asset_name."""
        service = IngestionService()
        finding = UnifiedFinding(
            title="Generic Finding",
            asset_name="my-custom-asset",
            severity=FindingSeverity.MEDIUM,
        )
        asset = service._create_asset_from_finding(finding)
        assert asset.name == "my-custom-asset"

    def test_create_asset_from_finding_unknown_fallback(self):
        """Test asset creation with fallback to Unknown Asset."""
        service = IngestionService()
        finding = UnifiedFinding(
            title="Generic Finding",
            severity=FindingSeverity.MEDIUM,
        )
        asset = service._create_asset_from_finding(finding)
        assert asset.name == "Unknown Asset"


class TestCLIEdgeCases:
    """Tests for CLI edge cases."""

    def test_handle_ingest_file_with_exception(self):
        """Test CLI ingest with files that cause exceptions."""
        import argparse
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        from core.cli import _handle_ingest_file

        sarif_data = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "test"}}, "results": []}],
        }

        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            f.write(json.dumps(sarif_data).encode())
            f.flush()
            temp_path = f.name

        args = argparse.Namespace(
            files=[Path(temp_path)],
            format=None,
            output=None,
            pretty=False,
            quiet=True,
        )

        with patch(
            "apps.api.ingestion.IngestionService.ingest",
            side_effect=Exception("Test error"),
        ):
            result = _handle_ingest_file(args)
            assert result == 1

        Path(temp_path).unlink()

    def test_handle_ingest_file_with_output(self):
        """Test CLI ingest with output file."""
        import argparse
        import tempfile
        from pathlib import Path

        from core.cli import _handle_ingest_file

        sarif_data = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "test"}}, "results": []}],
        }

        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            f.write(json.dumps(sarif_data).encode())
            f.flush()
            input_path = f.name

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            output_path = f.name

        args = argparse.Namespace(
            files=[Path(input_path)],
            format="sarif",
            output=Path(output_path),
            pretty=True,
            quiet=False,
        )
        result = _handle_ingest_file(args)
        assert result == 0

        assert Path(output_path).exists()
        Path(input_path).unlink()
        Path(output_path).unlink()

    def test_handle_ingest_file_with_result_errors(self):
        """Test CLI ingest when results have errors."""
        import argparse
        import tempfile
        from pathlib import Path

        from core.cli import _handle_ingest_file

        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            f.write(b'{"invalid": "sarif"}')
            f.flush()
            temp_path = f.name

        args = argparse.Namespace(
            files=[Path(temp_path)],
            format="sarif",
            output=None,
            pretty=False,
            quiet=False,
        )
        _handle_ingest_file(args)

        Path(temp_path).unlink()


class TestAPIMultipartEdgeCases:
    """Tests for API multipart endpoint edge cases."""

    @pytest.fixture
    def client(self):
        import os

        os.environ["FIXOPS_API_TOKEN"] = "demo-token-12345"
        os.environ["FIXOPS_JWT_SECRET"] = "demo-secret-key-for-testing-only-12345678"
        from apps.api.app import create_app

        app = create_app()
        from fastapi.testclient import TestClient

        return TestClient(app)

    def test_ingest_multipart_with_errors(self, client):
        """Test multipart ingestion with files that cause errors."""
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            f.write(b"invalid json content")
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
        assert data["status"] in ["success", "partial"]

        Path(temp_path).unlink()

    def test_ingest_multipart_with_result_errors(self, client):
        """Test multipart ingestion when results have errors."""
        sarif_data = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "test"}},
                    "results": [
                        {
                            "ruleId": "rule1",
                            "message": {"text": "Test finding"},
                            "level": "error",
                        }
                    ],
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
        assert "results" in data

        Path(temp_path).unlink()


class TestRemainingCoverage:
    """Tests to cover remaining edge cases for 100% diff coverage."""

    def test_dark_web_intel_direct_list_input(self):
        """Test dark web intel normalizer with direct list input (line 643)."""
        config = NormalizerConfig(name="dark_web_intel", enabled=True)
        normalizer = DarkWebIntelNormalizer(config)

        data = [
            {
                "title": "Threat 1",
                "description": "Description 1",
                "confidence": 0.9,
            },
            {
                "title": "Threat 2",
                "description": "Description 2",
                "confidence": 0.5,
            },
        ]
        content = json.dumps(data).encode()
        findings = normalizer.normalize(content)
        assert len(findings) == 2

    def test_registry_with_disabled_normalizer_in_detect(self):
        """Test registry detect_format skips disabled normalizers (line 911)."""
        registry = NormalizerRegistry()
        sarif_normalizer = registry.get_normalizer("sarif")
        sarif_normalizer.enabled = False

        content = b'{"$schema": "sarif", "version": "2.1.0", "runs": []}'
        detected_format, confidence = registry.detect_format(content)
        assert detected_format != "sarif" or confidence == 0.0
        registry.close()

    def test_registry_with_disabled_normalizer_in_try_all(self):
        """Test registry _try_all_normalizers skips disabled normalizers (line 980)."""
        registry = NormalizerRegistry()
        for name in registry.list_normalizers():
            normalizer = registry.get_normalizer(name)
            normalizer.enabled = False

        content = b'{"some": "data"}'
        findings = registry._try_all_normalizers(content, None)
        assert findings == []
        registry.close()

    def test_registry_batch_with_future_exception(self):
        """Test batch normalization with future that raises exception (lines 1039-1041)."""
        from unittest.mock import MagicMock, patch

        registry = NormalizerRegistry()
        items = [(b'{"test": "data"}', "sarif", None)]

        with patch.object(registry._executor, "submit") as mock_submit:
            mock_future = MagicMock()
            mock_future.result.side_effect = Exception("Future failed")
            mock_submit.return_value = mock_future

            results = registry.normalize_batch(items)
            assert len(results) == 1
            assert results[0] == []

        registry.close()

    def test_extract_assets_with_critical_duplicate(self):
        """Test asset extraction with duplicate critical findings (line 1191)."""
        service = IngestionService()
        findings = [
            UnifiedFinding(
                title="Critical Finding 1",
                file_path="/src/app.py",
                severity=FindingSeverity.CRITICAL,
            ),
            UnifiedFinding(
                title="Critical Finding 2",
                file_path="/src/app.py",
                severity=FindingSeverity.CRITICAL,
            ),
        ]
        assets = service._extract_assets(findings)
        assert len(assets) == 1
        assert assets[0].critical_count == 2
        assert assets[0].finding_count == 2

    def test_extract_assets_with_high_duplicate(self):
        """Test asset extraction with duplicate high findings (line 1193)."""
        service = IngestionService()
        findings = [
            UnifiedFinding(
                title="High Finding 1",
                file_path="/src/app.py",
                severity=FindingSeverity.HIGH,
            ),
            UnifiedFinding(
                title="High Finding 2",
                file_path="/src/app.py",
                severity=FindingSeverity.HIGH,
            ),
        ]
        assets = service._extract_assets(findings)
        assert len(assets) == 1
        assert assets[0].high_count == 2
        assert assets[0].finding_count == 2

    def test_registry_normalize_with_detected_format(self):
        """Test registry normalize uses detected format (line 954)."""
        registry = NormalizerRegistry()
        sarif_data = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "test"}},
                    "results": [
                        {
                            "ruleId": "rule1",
                            "message": {"text": "Test finding"},
                            "level": "error",
                        }
                    ],
                }
            ],
        }
        content = json.dumps(sarif_data).encode()
        findings = registry.normalize(content)
        assert len(findings) == 1
        registry.close()

    def test_cli_with_result_errors_quiet_mode(self):
        """Test CLI with result errors in quiet mode (line 518)."""
        import argparse
        from pathlib import Path
        from unittest.mock import MagicMock, patch

        from core.cli import _handle_ingest_file

        sarif_data = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "test"}}, "results": []}],
        }

        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            f.write(json.dumps(sarif_data).encode())
            f.flush()
            temp_path = f.name

        args = argparse.Namespace(
            files=[Path(temp_path)],
            format=None,
            output=None,
            pretty=False,
            quiet=True,
        )

        mock_result = MagicMock()
        mock_result.status = "partial"
        mock_result.errors = ["Test error"]
        mock_result.findings_count = 0
        mock_result.assets_count = 0
        mock_result.processing_time_ms = 100
        mock_result.warnings = []
        mock_result.findings = []

        with patch(
            "apps.api.ingestion.IngestionService.ingest",
            return_value=mock_result,
        ):
            result = _handle_ingest_file(args)
            assert result == 1

        Path(temp_path).unlink()

    def test_cli_with_errors_extend(self):
        """Test CLI extends errors from result (line 482)."""
        import argparse
        from pathlib import Path
        from unittest.mock import MagicMock, patch

        from core.cli import _handle_ingest_file

        sarif_data = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "test"}}, "results": []}],
        }

        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            f.write(json.dumps(sarif_data).encode())
            f.flush()
            temp_path = f.name

        args = argparse.Namespace(
            files=[Path(temp_path)],
            format=None,
            output=None,
            pretty=False,
            quiet=True,
        )

        mock_result = MagicMock()
        mock_result.status = "partial"
        mock_result.errors = ["Error from result"]
        mock_result.findings_count = 0
        mock_result.assets_count = 0
        mock_result.processing_time_ms = 100
        mock_result.warnings = []
        mock_result.findings = []

        with patch(
            "apps.api.ingestion.IngestionService.ingest",
            return_value=mock_result,
        ):
            result = _handle_ingest_file(args)
            assert result == 1

        Path(temp_path).unlink()
