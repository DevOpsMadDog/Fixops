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
import shutil
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from core.iac_models import IaCFinding, IaCFindingStatus, IaCProvider
from core.iac_scanner import (
    IaCScanner,
    ScannerConfig,
    ScannerType,
    ScanResult,
    ScanStatus,
    get_iac_scanner,
)

TRUSTED_TEST_ROOT = "/var/fixops/test-scans"


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
    def temp_dir(self):
        """Create a temporary directory under TRUSTED_TEST_ROOT for testing."""
        test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    @pytest.fixture
    def scanner(self, temp_dir):
        """Create a scanner instance for testing with temp_dir as base_path."""
        config = ScannerConfig(timeout_seconds=30, base_path=temp_dir)
        return IaCScanner(config)

    def test_scanner_initialization(self, scanner, temp_dir):
        """Test scanner initialization."""
        assert scanner.config is not None
        assert scanner.config.timeout_seconds == 30
        assert scanner.config.base_path == temp_dir

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
        """Test path validation with valid relative path."""
        test_file = Path(temp_dir) / "test.tf"
        test_file.write_text("resource {}")

        # Use relative path (relative to base_path which is temp_dir)
        result = scanner._validate_path("test.tf")
        # _validate_path now returns str instead of Path
        assert os.path.exists(result)

    def test_validate_path_null_bytes(self, scanner, temp_dir):
        """Test path validation rejects null bytes."""
        with pytest.raises(ValueError, match="contains null bytes"):
            scanner._validate_path("test/file\x00.tf")

    def test_validate_path_absolute_outside_base_rejected(self, scanner, temp_dir):
        """Test path validation rejects absolute paths outside base directory."""
        # Absolute path outside TRUSTED_ROOT should be rejected
        with pytest.raises(ValueError, match="Path escapes trusted root"):
            scanner._validate_path("/absolute/path/file.tf")

    def test_validate_path_absolute_inside_base_accepted(self, scanner, temp_dir):
        """Test path validation accepts absolute paths inside base directory."""
        # Create a test file inside the base directory
        test_file = Path(temp_dir) / "test_absolute.tf"
        test_file.write_text("resource {}")

        # Absolute path inside base directory should be accepted
        result = scanner._validate_path(str(test_file))
        # _validate_path now returns str instead of Path
        assert os.path.exists(result)
        assert result == str(test_file)

    def test_validate_path_traversal_rejected(self, scanner, temp_dir):
        """Test path validation rejects path traversal."""
        with pytest.raises(ValueError, match="Path traversal detected"):
            scanner._validate_path("../../../etc/passwd")

    def test_validate_path_nonexistent(self, scanner, temp_dir):
        """Test path validation with nonexistent relative path."""
        with pytest.raises(FileNotFoundError):
            scanner._validate_path("nonexistent/path/file.tf")

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
                # Use relative path (relative to base_path which is temp_dir)
                result = await scanner.scan("main.tf")

                assert result.status == ScanStatus.FAILED
                assert "No IaC scanner available" in result.error_message

    @pytest.mark.asyncio
    async def test_scan_invalid_path(self, scanner, temp_dir):
        """Test scan with invalid (absolute) path outside base directory."""
        result = await scanner.scan("/nonexistent/path/file.tf")

        assert result.status == ScanStatus.FAILED
        assert "Path escapes trusted root" in result.error_message

    @pytest.mark.asyncio
    async def test_scan_nonexistent_path(self, scanner, temp_dir):
        """Test scan with nonexistent relative path returns failed status."""
        result = await scanner.scan("nonexistent/path/to/file.tf")

        assert result.status == ScanStatus.FAILED
        assert "does not exist" in result.error_message

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

                    # Use relative path (relative to base_path which is temp_dir)
                    result = await scanner.scan("main.tf")

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

                # Use relative path (relative to base_path which is temp_dir)
                result = await scanner.scan("main.tf", scanner=ScannerType.TFSEC)

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

                # Use relative path (relative to base_path which is temp_dir)
                result = await scanner.scan("main.tf")

                assert result.status == ScanStatus.FAILED
                assert "timed out" in result.error_message

    @pytest.mark.asyncio
    async def test_scan_content(self, scanner):
        """Test scanning content as string."""
        content = 'resource "aws_instance" "example" {}'

        with patch.object(scanner, "_is_checkov_available", return_value=True):
            with patch.object(
                scanner,
                "_run_checkov",
                return_value=([], '{"results": {"failed_checks": []}}', None),
            ):
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
            # Use relative paths (relative to base_path which is temp_dir)
            files.append(f"main{i}.tf")

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
    def temp_dir(self):
        """Create a temporary directory under TRUSTED_TEST_ROOT for testing."""
        test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    @pytest.fixture
    def scanner(self, temp_dir):
        """Create a scanner instance for testing with temp_dir as base_path."""
        config = ScannerConfig(base_path=temp_dir)
        return IaCScanner(config)

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

                # Use relative path (relative to base_path which is temp_dir)
                await scanner.scan("template.yaml", provider=IaCProvider.CLOUDFORMATION)

                call_args = mock_exec.call_args[0]
                assert "--framework" in call_args
                framework_idx = call_args.index("--framework")
                assert call_args[framework_idx + 1] == "cloudformation"


class TestProviderDetectionEdgeCases:
    """Test edge cases for provider detection."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under TRUSTED_TEST_ROOT for testing."""
        test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    @pytest.fixture
    def scanner(self, temp_dir):
        """Create a scanner instance for testing with temp_dir as base_path."""
        config = ScannerConfig(timeout_seconds=30, base_path=temp_dir)
        return IaCScanner(config)

    def test_detect_provider_json_cloudformation(self, scanner, temp_dir):
        """Test provider detection for JSON CloudFormation files."""
        test_file = Path(temp_dir) / "template.json"
        test_file.write_text('{"AWSTemplateFormatVersion": "2010-09-09"}')

        provider = scanner._detect_provider(test_file)
        assert provider == IaCProvider.CLOUDFORMATION

    def test_detect_provider_json_non_cloudformation(self, scanner, temp_dir):
        """Test provider detection for non-CloudFormation JSON files."""
        test_file = Path(temp_dir) / "config.json"
        test_file.write_text('{"key": "value"}')

        provider = scanner._detect_provider(test_file)
        assert provider == IaCProvider.TERRAFORM

    def test_detect_provider_directory_with_helm(self, scanner, temp_dir):
        """Test provider detection for directory with Helm Chart.yaml."""
        chart_file = Path(temp_dir) / "Chart.yaml"
        chart_file.write_text("name: mychart\nversion: 1.0.0")

        provider = scanner._detect_provider(Path(temp_dir))
        assert provider == IaCProvider.HELM

    def test_detect_provider_empty_directory(self, scanner, temp_dir):
        """Test provider detection for empty directory defaults to Terraform."""
        provider = scanner._detect_provider(Path(temp_dir))
        assert provider == IaCProvider.TERRAFORM


class TestScannerConfigOptions:
    """Test scanner configuration options."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under TRUSTED_TEST_ROOT for testing."""
        test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    @pytest.mark.asyncio
    async def test_checkov_skip_download_option(self, temp_dir):
        """Test checkov --skip-download option."""
        config = ScannerConfig(
            timeout_seconds=30, base_path=temp_dir, skip_download=True
        )
        scanner = IaCScanner(config)

        test_file = Path(temp_dir) / "main.tf"
        test_file.write_text('resource "aws_instance" "example" {}')

        with patch.object(scanner, "_is_checkov_available", return_value=True):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_process = AsyncMock()
                mock_process.communicate.return_value = (
                    b'{"results": {"failed_checks": []}}',
                    b"",
                )
                mock_process.returncode = 0
                mock_exec.return_value = mock_process

                await scanner.scan("main.tf")

                call_args = mock_exec.call_args[0]
                assert "--skip-download" in call_args

    @pytest.mark.asyncio
    async def test_checkov_custom_policies_dir(self, temp_dir):
        """Test checkov --external-checks-dir option."""
        config = ScannerConfig(
            timeout_seconds=30,
            base_path=temp_dir,
            custom_policies_dir="/custom/policies",
        )
        scanner = IaCScanner(config)

        test_file = Path(temp_dir) / "main.tf"
        test_file.write_text('resource "aws_instance" "example" {}')

        with patch.object(scanner, "_is_checkov_available", return_value=True):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_process = AsyncMock()
                mock_process.communicate.return_value = (
                    b'{"results": {"failed_checks": []}}',
                    b"",
                )
                mock_process.returncode = 0
                mock_exec.return_value = mock_process

                await scanner.scan("main.tf")

                call_args = mock_exec.call_args[0]
                assert "--external-checks-dir" in call_args
                idx = call_args.index("--external-checks-dir")
                assert call_args[idx + 1] == "/custom/policies"

    @pytest.mark.asyncio
    async def test_checkov_excluded_checks(self, temp_dir):
        """Test checkov --skip-check option."""
        config = ScannerConfig(
            timeout_seconds=30,
            base_path=temp_dir,
            excluded_checks=["CKV_AWS_1", "CKV_AWS_2"],
        )
        scanner = IaCScanner(config)

        test_file = Path(temp_dir) / "main.tf"
        test_file.write_text('resource "aws_instance" "example" {}')

        with patch.object(scanner, "_is_checkov_available", return_value=True):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_process = AsyncMock()
                mock_process.communicate.return_value = (
                    b'{"results": {"failed_checks": []}}',
                    b"",
                )
                mock_process.returncode = 0
                mock_exec.return_value = mock_process

                await scanner.scan("main.tf")

                call_args = mock_exec.call_args[0]
                assert "--skip-check" in call_args

    @pytest.mark.asyncio
    async def test_tfsec_soft_fail_option(self, temp_dir):
        """Test tfsec --soft-fail option."""
        config = ScannerConfig(timeout_seconds=30, base_path=temp_dir, soft_fail=True)
        scanner = IaCScanner(config)

        test_file = Path(temp_dir) / "main.tf"
        test_file.write_text('resource "aws_instance" "example" {}')

        with patch.object(scanner, "_is_tfsec_available", return_value=True):
            with patch.object(scanner, "_is_checkov_available", return_value=False):
                with patch("asyncio.create_subprocess_exec") as mock_exec:
                    mock_process = AsyncMock()
                    mock_process.communicate.return_value = (
                        b'{"results": []}',
                        b"",
                    )
                    mock_process.returncode = 0
                    mock_exec.return_value = mock_process

                    await scanner.scan("main.tf")

                    call_args = mock_exec.call_args[0]
                    assert "--soft-fail" in call_args

    @pytest.mark.asyncio
    async def test_tfsec_excluded_checks(self, temp_dir):
        """Test tfsec --exclude option."""
        config = ScannerConfig(
            timeout_seconds=30,
            base_path=temp_dir,
            excluded_checks=["aws-s3-enable-bucket-encryption"],
        )
        scanner = IaCScanner(config)

        test_file = Path(temp_dir) / "main.tf"
        test_file.write_text('resource "aws_instance" "example" {}')

        with patch.object(scanner, "_is_tfsec_available", return_value=True):
            with patch.object(scanner, "_is_checkov_available", return_value=False):
                with patch("asyncio.create_subprocess_exec") as mock_exec:
                    mock_process = AsyncMock()
                    mock_process.communicate.return_value = (
                        b'{"results": []}',
                        b"",
                    )
                    mock_process.returncode = 0
                    mock_exec.return_value = mock_process

                    await scanner.scan("main.tf")

                    call_args = mock_exec.call_args[0]
                    assert "--exclude" in call_args


class TestScannerErrorHandling:
    """Test scanner error handling paths."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under TRUSTED_TEST_ROOT for testing."""
        test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    @pytest.fixture
    def scanner(self, temp_dir):
        """Create a scanner instance for testing with temp_dir as base_path."""
        config = ScannerConfig(timeout_seconds=30, base_path=temp_dir)
        return IaCScanner(config)

    @pytest.mark.asyncio
    async def test_checkov_nonzero_exit_code(self, scanner, temp_dir):
        """Test checkov with non-zero/non-one exit code."""
        test_file = Path(temp_dir) / "main.tf"
        test_file.write_text('resource "aws_instance" "example" {}')

        with patch.object(scanner, "_is_checkov_available", return_value=True):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_process = AsyncMock()
                mock_process.communicate.return_value = (b"", b"Error occurred")
                mock_process.returncode = 2
                mock_exec.return_value = mock_process

                result = await scanner.scan("main.tf")

                assert result.status == ScanStatus.FAILED
                assert "exited with code 2" in result.error_message

    @pytest.mark.asyncio
    async def test_checkov_not_installed(self, scanner, temp_dir):
        """Test checkov when not installed."""
        test_file = Path(temp_dir) / "main.tf"
        test_file.write_text('resource "aws_instance" "example" {}')

        with patch.object(scanner, "_is_checkov_available", return_value=True):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_exec.side_effect = FileNotFoundError("checkov not found")

                result = await scanner.scan("main.tf")

                assert result.status == ScanStatus.FAILED
                assert "not installed" in result.error_message

    @pytest.mark.asyncio
    async def test_checkov_generic_exception(self, scanner, temp_dir):
        """Test checkov with generic exception."""
        test_file = Path(temp_dir) / "main.tf"
        test_file.write_text('resource "aws_instance" "example" {}')

        with patch.object(scanner, "_is_checkov_available", return_value=True):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_exec.side_effect = RuntimeError("Unexpected error")

                result = await scanner.scan("main.tf")

                assert result.status == ScanStatus.FAILED
                assert "failed" in result.error_message.lower()

    @pytest.mark.asyncio
    async def test_tfsec_nonzero_exit_code(self, scanner, temp_dir):
        """Test tfsec with non-zero/non-one exit code."""
        test_file = Path(temp_dir) / "main.tf"
        test_file.write_text('resource "aws_instance" "example" {}')

        with patch.object(scanner, "_is_tfsec_available", return_value=True):
            with patch.object(scanner, "_is_checkov_available", return_value=False):
                with patch("asyncio.create_subprocess_exec") as mock_exec:
                    mock_process = AsyncMock()
                    mock_process.communicate.return_value = (b"", b"Error occurred")
                    mock_process.returncode = 2
                    mock_exec.return_value = mock_process

                    result = await scanner.scan("main.tf")

                    assert result.status == ScanStatus.FAILED
                    assert "exited with code 2" in result.error_message

    @pytest.mark.asyncio
    async def test_tfsec_timeout(self, scanner, temp_dir):
        """Test tfsec timeout handling."""
        test_file = Path(temp_dir) / "main.tf"
        test_file.write_text('resource "aws_instance" "example" {}')

        with patch.object(scanner, "_is_tfsec_available", return_value=True):
            with patch.object(scanner, "_is_checkov_available", return_value=False):
                with patch("asyncio.create_subprocess_exec") as mock_exec:
                    mock_process = AsyncMock()
                    mock_process.communicate.side_effect = asyncio.TimeoutError()
                    mock_exec.return_value = mock_process

                    result = await scanner.scan("main.tf")

                    assert result.status == ScanStatus.FAILED
                    assert "timed out" in result.error_message

    @pytest.mark.asyncio
    async def test_tfsec_not_installed(self, scanner, temp_dir):
        """Test tfsec when not installed."""
        test_file = Path(temp_dir) / "main.tf"
        test_file.write_text('resource "aws_instance" "example" {}')

        with patch.object(scanner, "_is_tfsec_available", return_value=True):
            with patch.object(scanner, "_is_checkov_available", return_value=False):
                with patch("asyncio.create_subprocess_exec") as mock_exec:
                    mock_exec.side_effect = FileNotFoundError("tfsec not found")

                    result = await scanner.scan("main.tf")

                    assert result.status == ScanStatus.FAILED
                    assert "not installed" in result.error_message

    @pytest.mark.asyncio
    async def test_tfsec_generic_exception(self, scanner, temp_dir):
        """Test tfsec with generic exception."""
        test_file = Path(temp_dir) / "main.tf"
        test_file.write_text('resource "aws_instance" "example" {}')

        with patch.object(scanner, "_is_tfsec_available", return_value=True):
            with patch.object(scanner, "_is_checkov_available", return_value=False):
                with patch("asyncio.create_subprocess_exec") as mock_exec:
                    mock_exec.side_effect = RuntimeError("Unexpected error")

                    result = await scanner.scan("main.tf")

                    assert result.status == ScanStatus.FAILED
                    assert "failed" in result.error_message.lower()


class TestScanContentEdgeCases:
    """Test scan_content edge cases."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under TRUSTED_TEST_ROOT for testing."""
        test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    @pytest.fixture
    def scanner(self, temp_dir):
        """Create a scanner instance for testing with temp_dir as base_path."""
        config = ScannerConfig(timeout_seconds=30, base_path=temp_dir)
        return IaCScanner(config)

    @pytest.mark.asyncio
    async def test_scan_content_no_scanner_available(self, scanner):
        """Test scan_content when no scanner is available."""
        with patch.object(scanner, "get_available_scanners", return_value=[]):
            result = await scanner.scan_content(
                content='resource "aws_instance" "example" {}',
                filename="main.tf",
            )

            assert result.status == ScanStatus.FAILED
            assert "No IaC scanner available" in result.error_message

    @pytest.mark.asyncio
    async def test_scan_content_invalid_extension(self, scanner):
        """Test scan_content with invalid extension defaults to .tf."""
        with patch.object(
            scanner, "get_available_scanners", return_value=[ScannerType.CHECKOV]
        ):
            with patch.object(scanner, "_run_checkov") as mock_run:
                mock_run.return_value = ([], "", None)

                result = await scanner.scan_content(
                    content='resource "aws_instance" "example" {}',
                    filename="main.invalid",
                )

                assert result.status == ScanStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_scan_content_with_tfsec(self, scanner):
        """Test scan_content using tfsec scanner."""
        with patch.object(
            scanner, "get_available_scanners", return_value=[ScannerType.TFSEC]
        ):
            with patch.object(scanner, "_run_tfsec") as mock_run:
                mock_run.return_value = ([], "", None)

                result = await scanner.scan_content(
                    content='resource "aws_instance" "example" {}',
                    filename="main.tf",
                )

                assert result.status == ScanStatus.COMPLETED
                mock_run.assert_called_once()

    @pytest.mark.asyncio
    async def test_scan_content_with_error(self, scanner):
        """Test scan_content when scanner returns error."""
        with patch.object(
            scanner, "get_available_scanners", return_value=[ScannerType.CHECKOV]
        ):
            with patch.object(scanner, "_run_checkov") as mock_run:
                mock_run.return_value = ([], "raw output", "Scanner error")

                result = await scanner.scan_content(
                    content='resource "aws_instance" "example" {}',
                    filename="main.tf",
                )

                assert result.status == ScanStatus.FAILED
                assert result.error_message == "Scanner error"

    @pytest.mark.asyncio
    async def test_scan_content_with_findings(self, scanner):
        """Test scan_content with findings updates file_path."""
        finding = IaCFinding(
            id="test-id",
            provider=IaCProvider.TERRAFORM,
            status=IaCFindingStatus.OPEN,
            severity="high",
            title="Test Finding",
            description="Test description",
            file_path="/tmp/content.tf",
            line_number=1,
            resource_type="aws_instance",
            resource_name="example",
            rule_id="TEST001",
        )

        with patch.object(
            scanner, "get_available_scanners", return_value=[ScannerType.CHECKOV]
        ):
            with patch.object(scanner, "_run_checkov") as mock_run:
                mock_run.return_value = ([finding], "", None)

                result = await scanner.scan_content(
                    content='resource "aws_instance" "example" {}',
                    filename="main.tf",
                )

                assert result.status == ScanStatus.COMPLETED
                assert len(result.findings) == 1
                assert result.findings[0].file_path == "main.tf"

    @pytest.mark.asyncio
    async def test_scan_content_exception(self, scanner):
        """Test scan_content with exception."""
        with patch.object(scanner, "get_available_scanners") as mock_get:
            mock_get.side_effect = RuntimeError("Unexpected error")

            result = await scanner.scan_content(
                content='resource "aws_instance" "example" {}',
                filename="main.tf",
            )

            assert result.status == ScanStatus.FAILED
            assert "Unexpected error" in result.error_message


class TestPathContainmentErrorHandling:
    """Test PathContainmentError handling in various methods."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under TRUSTED_TEST_ROOT for testing."""
        test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    @pytest.fixture
    def scanner(self, temp_dir):
        """Create a scanner instance for testing with temp_dir as base_path."""
        config = ScannerConfig(timeout_seconds=30, base_path=temp_dir)
        return IaCScanner(config)

    def test_verify_containment_valid_path(self, scanner, temp_dir):
        """Test _verify_containment with a valid path."""
        test_file = os.path.join(temp_dir, "test.tf")
        with open(test_file, "w") as f:
            f.write('resource "aws_instance" "example" {}')
        result = scanner._verify_containment(Path(test_file))
        assert result == os.path.realpath(test_file)

    def test_verify_containment_path_escape(self, scanner, temp_dir):
        """Test _verify_containment raises ValueError when path escapes base."""
        with pytest.raises(ValueError) as exc_info:
            scanner._verify_containment(Path("/tmp/outside.tf"))
        assert "Path escapes base directory" in str(exc_info.value)

    def test_validate_path_containment_error(self, scanner, temp_dir):
        """Test _validate_path raises ValueError for paths outside trusted root."""
        # Test that paths outside TRUSTED_ROOT are rejected
        with pytest.raises(ValueError) as exc_info:
            scanner._validate_path("/tmp/outside/test.tf")
        assert "Path escapes trusted root" in str(exc_info.value)

    def test_detect_provider_containment_error(self, scanner, temp_dir):
        """Test _detect_provider handles PathContainmentError."""
        test_file = os.path.join(temp_dir, "test.tf")
        with open(test_file, "w") as f:
            f.write('resource "aws_instance" "example" {}')

        with patch("core.iac_scanner.safe_isfile") as mock_safe_isfile:
            from core.safe_path_ops import PathContainmentError

            mock_safe_isfile.side_effect = PathContainmentError("Path escapes")
            with pytest.raises(ValueError) as exc_info:
                scanner._detect_provider(Path(test_file))
            assert "Path escapes base directory" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_run_checkov_containment_error(self, scanner, temp_dir):
        """Test _run_checkov handles PathContainmentError from safe_isdir."""
        test_file = os.path.join(temp_dir, "test.tf")
        with open(test_file, "w") as f:
            f.write('resource "aws_instance" "example" {}')

        with patch("core.iac_scanner.safe_isdir") as mock_safe_isdir:
            from core.safe_path_ops import PathContainmentError

            mock_safe_isdir.side_effect = PathContainmentError("Path escapes")
            with pytest.raises(ValueError) as exc_info:
                await scanner._run_checkov(Path(test_file), IaCProvider.TERRAFORM)
            assert "Path escapes base directory" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_run_tfsec_containment_check(self, scanner, temp_dir):
        """Test _run_tfsec inline containment check."""
        with patch.object(scanner, "_is_tfsec_available", return_value=True):
            with pytest.raises(ValueError) as exc_info:
                await scanner._run_tfsec(Path("/tmp/outside.tf"), IaCProvider.TERRAFORM)
            assert "Path escapes base directory" in str(exc_info.value)

    def test_verify_containment_base_path_escapes_trusted_root(self):
        """Test _verify_containment raises ValueError when base_path escapes TRUSTED_ROOT."""
        # Create scanner with base_path outside TRUSTED_ROOT (/var/fixops)
        config = ScannerConfig(timeout_seconds=30, base_path="/tmp/untrusted")
        scanner = IaCScanner(config)
        os.makedirs("/tmp/untrusted", exist_ok=True)
        test_file = "/tmp/untrusted/test.tf"
        with open(test_file, "w") as f:
            f.write('resource "aws_instance" "example" {}')
        try:
            with pytest.raises(ValueError) as exc_info:
                scanner._verify_containment(Path(test_file))
            assert "Base path escapes trusted root" in str(exc_info.value)
        finally:
            shutil.rmtree("/tmp/untrusted", ignore_errors=True)

    @pytest.mark.asyncio
    async def test_run_tfsec_base_path_escapes_trusted_root(self):
        """Test _run_tfsec raises ValueError when base_path escapes TRUSTED_ROOT."""
        # Create scanner with base_path outside TRUSTED_ROOT (/var/fixops)
        config = ScannerConfig(timeout_seconds=30, base_path="/tmp/untrusted")
        scanner = IaCScanner(config)
        os.makedirs("/tmp/untrusted", exist_ok=True)
        test_file = "/tmp/untrusted/test.tf"
        with open(test_file, "w") as f:
            f.write('resource "aws_instance" "example" {}')
        try:
            with patch.object(scanner, "_is_tfsec_available", return_value=True):
                with pytest.raises(ValueError) as exc_info:
                    await scanner._run_tfsec(Path(test_file), IaCProvider.TERRAFORM)
                assert "Base path escapes trusted root" in str(exc_info.value)
        finally:
            shutil.rmtree("/tmp/untrusted", ignore_errors=True)

    @pytest.mark.asyncio
    async def test_scan_content_base_path_escapes_trusted_root(self):
        """Test scan_content raises ValueError when base_path escapes TRUSTED_ROOT."""
        # Create scanner with base_path outside TRUSTED_ROOT (/var/fixops)
        config = ScannerConfig(timeout_seconds=30, base_path="/tmp/untrusted")
        scanner = IaCScanner(config)
        try:
            with pytest.raises(ValueError) as exc_info:
                await scanner.scan_content(
                    content='resource "aws_instance" "example" {}',
                    filename="test.tf",
                )
            assert "Base path escapes trusted root" in str(exc_info.value)
        finally:
            shutil.rmtree("/tmp/untrusted", ignore_errors=True)
