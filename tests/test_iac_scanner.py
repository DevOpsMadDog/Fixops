"""
Comprehensive tests for the IaC scanner module.

Tests cover:
- Scanner configuration and initialization
- Path validation and security
- Provider detection
- Checkov and tfsec output parsing
- Async scanning functionality
- Error handling and edge cases
"""

import asyncio
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from core.iac_models import IaCProvider
from core.iac_scanner import (
    IaCScanner,
    ScannerConfig,
    ScannerType,
    ScanResult,
    ScanStatus,
    get_iac_scanner,
)


class TestScannerConfig:
    """Tests for ScannerConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = ScannerConfig()
        assert config.checkov_path == "checkov"
        assert config.tfsec_path == "tfsec"
        assert config.timeout_seconds == 300
        assert config.max_file_size_mb == 50
        assert config.skip_download is False
        assert config.custom_policies_dir is None
        assert config.excluded_checks == []
        assert config.soft_fail is False

    def test_config_from_env(self):
        """Test configuration from environment variables."""
        with patch.dict(
            os.environ,
            {
                "FIXOPS_CHECKOV_PATH": "/custom/checkov",
                "FIXOPS_TFSEC_PATH": "/custom/tfsec",
                "FIXOPS_SCAN_TIMEOUT": "600",
                "FIXOPS_MAX_FILE_SIZE_MB": "100",
                "FIXOPS_SKIP_DOWNLOAD": "true",
                "FIXOPS_CUSTOM_POLICIES_DIR": "/policies",
                "FIXOPS_EXCLUDED_CHECKS": "CKV_AWS_1,CKV_AWS_2",
                "FIXOPS_SOFT_FAIL": "true",
            },
        ):
            config = ScannerConfig.from_env()
            assert config.checkov_path == "/custom/checkov"
            assert config.tfsec_path == "/custom/tfsec"
            assert config.timeout_seconds == 600
            assert config.max_file_size_mb == 100
            assert config.skip_download is True
            assert config.custom_policies_dir == "/policies"
            assert config.excluded_checks == ["CKV_AWS_1", "CKV_AWS_2"]
            assert config.soft_fail is True

    def test_config_from_env_empty_excluded_checks(self):
        """Test configuration with empty excluded checks."""
        with patch.dict(os.environ, {}, clear=False):
            if "FIXOPS_EXCLUDED_CHECKS" in os.environ:
                del os.environ["FIXOPS_EXCLUDED_CHECKS"]
            config = ScannerConfig.from_env()
            assert config.excluded_checks == []


class TestIaCScanner:
    """Tests for IaCScanner class."""

    @pytest.fixture
    def scanner(self):
        """Create a scanner instance for testing."""
        config = ScannerConfig(timeout_seconds=30)
        return IaCScanner(config)

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    def test_scanner_initialization(self, scanner):
        """Test scanner initialization."""
        assert scanner.config is not None
        assert scanner.config.timeout_seconds == 30

    def test_get_available_scanners(self, scanner):
        """Test getting available scanners."""
        with patch.object(scanner, "_is_checkov_available", return_value=True):
            with patch.object(scanner, "_is_tfsec_available", return_value=True):
                available = scanner.get_available_scanners()
                assert ScannerType.CHECKOV in available
                assert ScannerType.TFSEC in available

    def test_get_available_scanners_none_available(self, scanner):
        """Test when no scanners are available."""
        with patch.object(scanner, "_is_checkov_available", return_value=False):
            with patch.object(scanner, "_is_tfsec_available", return_value=False):
                available = scanner.get_available_scanners()
                assert len(available) == 0

    def test_validate_path_valid(self, scanner, temp_dir):
        """Test path validation with valid path."""
        test_file = Path(temp_dir) / "test.tf"
        test_file.write_text("resource {}")

        result = scanner._validate_path(str(test_file))
        assert result.exists()

    def test_validate_path_with_base_path(self, scanner, temp_dir):
        """Test path validation with base path."""
        test_file = Path(temp_dir) / "test.tf"
        test_file.write_text("resource {}")

        result = scanner._validate_path("test.tf", temp_dir)
        assert result.exists()

    def test_validate_path_traversal_attack(self, scanner, temp_dir):
        """Test path validation prevents traversal attacks."""
        with pytest.raises(ValueError, match="Path traversal detected"):
            scanner._validate_path("../../../etc/passwd", temp_dir)

    def test_validate_path_nonexistent(self, scanner):
        """Test path validation with nonexistent path."""
        with pytest.raises(FileNotFoundError):
            scanner._validate_path("/nonexistent/path/file.tf")

    def test_detect_provider_terraform(self, scanner, temp_dir):
        """Test provider detection for Terraform files."""
        test_file = Path(temp_dir) / "main.tf"
        test_file.write_text('resource "aws_instance" "example" {}')

        provider = scanner._detect_provider(test_file)
        assert provider == IaCProvider.TERRAFORM

    def test_detect_provider_cloudformation(self, scanner, temp_dir):
        """Test provider detection for CloudFormation files."""
        test_file = Path(temp_dir) / "template.yaml"
        test_file.write_text("AWSTemplateFormatVersion: '2010-09-09'\nResources:")

        provider = scanner._detect_provider(test_file)
        assert provider == IaCProvider.CLOUDFORMATION

    def test_detect_provider_kubernetes(self, scanner, temp_dir):
        """Test provider detection for Kubernetes files."""
        test_file = Path(temp_dir) / "deployment.yaml"
        test_file.write_text("apiVersion: apps/v1\nkind: Deployment")

        provider = scanner._detect_provider(test_file)
        assert provider == IaCProvider.KUBERNETES

    def test_detect_provider_ansible(self, scanner, temp_dir):
        """Test provider detection for Ansible files."""
        test_file = Path(temp_dir) / "playbook.yaml"
        test_file.write_text("hosts: all\ntasks:")

        provider = scanner._detect_provider(test_file)
        assert provider == IaCProvider.ANSIBLE

    def test_detect_provider_helm(self, scanner, temp_dir):
        """Test provider detection for Helm charts."""
        test_file = Path(temp_dir) / "Chart.yaml"
        test_file.write_text("name: mychart\nversion: 1.0.0")

        provider = scanner._detect_provider(test_file)
        assert provider == IaCProvider.HELM

    def test_detect_provider_directory(self, scanner, temp_dir):
        """Test provider detection for directory with Terraform files."""
        test_file = Path(temp_dir) / "main.tf"
        test_file.write_text('resource "aws_instance" "example" {}')

        provider = scanner._detect_provider(Path(temp_dir))
        assert provider == IaCProvider.TERRAFORM

    def test_map_severity(self, scanner):
        """Test severity mapping."""
        assert scanner._map_severity("CRITICAL") == "high"
        assert scanner._map_severity("HIGH") == "high"
        assert scanner._map_severity("MEDIUM") == "medium"
        assert scanner._map_severity("MODERATE") == "medium"
        assert scanner._map_severity("LOW") == "low"
        assert scanner._map_severity("INFO") == "low"
        assert scanner._map_severity("UNKNOWN") == "medium"

    def test_parse_checkov_output_valid(self, scanner):
        """Test parsing valid checkov output."""
        checkov_output = json.dumps(
            {
                "results": {
                    "failed_checks": [
                        {
                            "check_id": "CKV_AWS_1",
                            "check": {"name": "Ensure S3 bucket has encryption"},
                            "file_path": "/test/main.tf",
                            "file_line_range": [10, 20],
                            "resource": "aws_s3_bucket",
                            "resource_address": "aws_s3_bucket.example",
                            "guideline": "Enable encryption",
                            "check_type": "terraform",
                            "check_result": {"result": "FAILED"},
                        }
                    ]
                }
            }
        )

        findings = scanner._parse_checkov_output(
            checkov_output, IaCProvider.TERRAFORM, "/test/main.tf"
        )

        assert len(findings) == 1
        assert findings[0].rule_id == "CKV_AWS_1"
        assert findings[0].file_path == "/test/main.tf"
        assert findings[0].line_number == 10
        assert findings[0].resource_type == "aws_s3_bucket"

    def test_parse_checkov_output_invalid_json(self, scanner):
        """Test parsing invalid JSON from checkov."""
        findings = scanner._parse_checkov_output(
            "not valid json", IaCProvider.TERRAFORM, "/test/main.tf"
        )
        assert len(findings) == 0

    def test_parse_checkov_output_empty(self, scanner):
        """Test parsing empty checkov output."""
        checkov_output = json.dumps({"results": {"failed_checks": []}})
        findings = scanner._parse_checkov_output(
            checkov_output, IaCProvider.TERRAFORM, "/test/main.tf"
        )
        assert len(findings) == 0

    def test_parse_tfsec_output_valid(self, scanner):
        """Test parsing valid tfsec output."""
        tfsec_output = json.dumps(
            {
                "results": [
                    {
                        "rule_id": "aws-s3-enable-bucket-encryption",
                        "long_id": "aws-s3-enable-bucket-encryption",
                        "description": "S3 bucket should have encryption enabled",
                        "severity": "HIGH",
                        "resolution": "Enable encryption",
                        "resource": "aws_s3_bucket.example",
                        "location": {
                            "filename": "/test/main.tf",
                            "start_line": 10,
                            "end_line": 20,
                        },
                        "rule_provider": "aws",
                        "rule_service": "s3",
                        "impact": "Data may be exposed",
                        "links": ["https://example.com"],
                    }
                ]
            }
        )

        findings = scanner._parse_tfsec_output(
            tfsec_output, IaCProvider.TERRAFORM, "/test/main.tf"
        )

        assert len(findings) == 1
        assert findings[0].rule_id == "aws-s3-enable-bucket-encryption"
        assert findings[0].file_path == "/test/main.tf"
        assert findings[0].line_number == 10
        assert findings[0].severity == "high"

    def test_parse_tfsec_output_invalid_json(self, scanner):
        """Test parsing invalid JSON from tfsec."""
        findings = scanner._parse_tfsec_output(
            "not valid json", IaCProvider.TERRAFORM, "/test/main.tf"
        )
        assert len(findings) == 0

    def test_parse_tfsec_output_null_results(self, scanner):
        """Test parsing tfsec output with null results."""
        tfsec_output = json.dumps({"results": None})
        findings = scanner._parse_tfsec_output(
            tfsec_output, IaCProvider.TERRAFORM, "/test/main.tf"
        )
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_scan_no_scanner_available(self, scanner, temp_dir):
        """Test scan when no scanner is available."""
        test_file = Path(temp_dir) / "main.tf"
        test_file.write_text('resource "aws_instance" "example" {}')

        with patch.object(scanner, "_is_checkov_available", return_value=False):
            with patch.object(scanner, "_is_tfsec_available", return_value=False):
                result = await scanner.scan(str(test_file))

                assert result.status == ScanStatus.FAILED
                assert "No IaC scanner available" in result.error_message

    @pytest.mark.asyncio
    async def test_scan_invalid_path(self, scanner):
        """Test scan with invalid path."""
        result = await scanner.scan("/nonexistent/path/file.tf")

        assert result.status == ScanStatus.FAILED
        assert "does not exist" in result.error_message

    @pytest.mark.asyncio
    async def test_scan_path_traversal(self, scanner, temp_dir):
        """Test scan with path traversal attempt."""
        result = await scanner.scan("../../../etc/passwd", base_path=temp_dir)

        assert result.status == ScanStatus.FAILED
        assert "Path traversal detected" in result.error_message

    @pytest.mark.asyncio
    async def test_scan_with_checkov(self, scanner, temp_dir):
        """Test scan using checkov."""
        test_file = Path(temp_dir) / "main.tf"
        test_file.write_text('resource "aws_instance" "example" {}')

        mock_output = json.dumps({"results": {"failed_checks": []}})

        with patch.object(scanner, "_is_checkov_available", return_value=True):
            with patch.object(scanner, "_is_tfsec_available", return_value=False):
                with patch("asyncio.create_subprocess_exec") as mock_exec:
                    mock_process = AsyncMock()
                    mock_process.communicate.return_value = (
                        mock_output.encode(),
                        b"",
                    )
                    mock_process.returncode = 0
                    mock_exec.return_value = mock_process

                    result = await scanner.scan(str(test_file))

                    assert result.status == ScanStatus.COMPLETED
                    assert result.scanner == ScannerType.CHECKOV

    @pytest.mark.asyncio
    async def test_scan_with_tfsec(self, scanner, temp_dir):
        """Test scan using tfsec for Terraform files."""
        test_file = Path(temp_dir) / "main.tf"
        test_file.write_text('resource "aws_instance" "example" {}')

        mock_output = json.dumps({"results": []})

        with patch.object(scanner, "_is_tfsec_available", return_value=True):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_process = AsyncMock()
                mock_process.communicate.return_value = (
                    mock_output.encode(),
                    b"",
                )
                mock_process.returncode = 0
                mock_exec.return_value = mock_process

                result = await scanner.scan(str(test_file), scanner=ScannerType.TFSEC)

                assert result.status == ScanStatus.COMPLETED
                assert result.scanner == ScannerType.TFSEC

    @pytest.mark.asyncio
    async def test_scan_timeout(self, scanner, temp_dir):
        """Test scan timeout handling."""
        test_file = Path(temp_dir) / "main.tf"
        test_file.write_text('resource "aws_instance" "example" {}')

        with patch.object(scanner, "_is_checkov_available", return_value=True):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_process = AsyncMock()
                mock_process.communicate.side_effect = asyncio.TimeoutError()
                mock_exec.return_value = mock_process

                result = await scanner.scan(str(test_file))

                assert result.status == ScanStatus.FAILED
                assert "timed out" in result.error_message

    @pytest.mark.asyncio
    async def test_scan_content(self, scanner):
        """Test scanning content as string."""
        content = 'resource "aws_instance" "example" {}'

        mock_output = json.dumps({"results": {"failed_checks": []}})

        with patch.object(scanner, "_is_checkov_available", return_value=True):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_process = AsyncMock()
                mock_process.communicate.return_value = (
                    mock_output.encode(),
                    b"",
                )
                mock_process.returncode = 0
                mock_exec.return_value = mock_process

                result = await scanner.scan_content(content, "main.tf")

                assert result.status == ScanStatus.COMPLETED
                for finding in result.findings:
                    assert finding.file_path == "main.tf"

    @pytest.mark.asyncio
    async def test_scan_multiple(self, scanner, temp_dir):
        """Test scanning multiple paths concurrently."""
        files = []
        for i in range(3):
            test_file = Path(temp_dir) / f"main{i}.tf"
            test_file.write_text(f'resource "aws_instance" "example{i}" {{}}')
            files.append(str(test_file))

        mock_output = json.dumps({"results": {"failed_checks": []}})

        with patch.object(scanner, "_is_checkov_available", return_value=True):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_process = AsyncMock()
                mock_process.communicate.return_value = (
                    mock_output.encode(),
                    b"",
                )
                mock_process.returncode = 0
                mock_exec.return_value = mock_process

                results = await scanner.scan_multiple(files, max_concurrent=2)

                assert len(results) == 3
                for result in results:
                    assert result.status == ScanStatus.COMPLETED


class TestScanResult:
    """Tests for ScanResult dataclass."""

    def test_scan_result_to_dict(self):
        """Test ScanResult to_dict method."""
        from datetime import datetime

        result = ScanResult(
            scan_id="test-123",
            status=ScanStatus.COMPLETED,
            scanner=ScannerType.CHECKOV,
            provider=IaCProvider.TERRAFORM,
            target_path="/test/main.tf",
            findings=[],
            started_at=datetime(2024, 1, 1, 12, 0, 0),
            completed_at=datetime(2024, 1, 1, 12, 0, 30),
            duration_seconds=30.0,
            metadata={"key": "value"},
        )

        result_dict = result.to_dict()

        assert result_dict["scan_id"] == "test-123"
        assert result_dict["status"] == "completed"
        assert result_dict["scanner"] == "checkov"
        assert result_dict["provider"] == "terraform"
        assert result_dict["findings_count"] == 0
        assert result_dict["duration_seconds"] == 30.0


class TestGetIaCScanner:
    """Tests for get_iac_scanner function."""

    def test_get_iac_scanner_singleton(self):
        """Test that get_iac_scanner returns singleton instance."""
        import core.iac_scanner as scanner_module

        scanner_module._default_scanner = None

        scanner1 = get_iac_scanner()
        scanner2 = get_iac_scanner()

        assert scanner1 is scanner2

        scanner_module._default_scanner = None


class TestTfsecNonTerraform:
    """Tests for tfsec with non-Terraform providers."""

    @pytest.fixture
    def scanner(self):
        """Create a scanner instance for testing."""
        return IaCScanner()

    @pytest.mark.asyncio
    async def test_tfsec_rejects_non_terraform(self, scanner):
        """Test that tfsec rejects non-Terraform providers."""
        findings, output, error = await scanner._run_tfsec(
            Path("/test"), IaCProvider.KUBERNETES
        )

        assert len(findings) == 0
        assert "only supports Terraform" in error


class TestCheckovFrameworkMapping:
    """Tests for checkov framework mapping."""

    @pytest.fixture
    def scanner(self):
        """Create a scanner instance for testing."""
        return IaCScanner()

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    @pytest.mark.asyncio
    async def test_checkov_cloudformation_framework(self, scanner, temp_dir):
        """Test checkov uses cloudformation framework for CloudFormation files."""
        test_file = Path(temp_dir) / "template.yaml"
        test_file.write_text("AWSTemplateFormatVersion: '2010-09-09'\nResources:")

        mock_output = json.dumps({"results": {"failed_checks": []}})

        with patch.object(scanner, "_is_checkov_available", return_value=True):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_process = AsyncMock()
                mock_process.communicate.return_value = (
                    mock_output.encode(),
                    b"",
                )
                mock_process.returncode = 0
                mock_exec.return_value = mock_process

                await scanner.scan(str(test_file), provider=IaCProvider.CLOUDFORMATION)

                call_args = mock_exec.call_args[0]
                assert "--framework" in call_args
                framework_idx = call_args.index("--framework")
                assert call_args[framework_idx + 1] == "cloudformation"
