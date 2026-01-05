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

import json
import os
import shutil
import uuid
from pathlib import Path
from unittest.mock import patch

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
        # custom_policies_dir is hardcoded to /var/fixops/policies (not configurable)
        assert config.custom_policies_dir == "/var/fixops/policies"
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
                # Note: FIXOPS_CUSTOM_POLICIES_DIR is no longer used - hardcoded for security
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
            # custom_policies_dir is hardcoded to /var/fixops/policies (not configurable)
            assert config.custom_policies_dir == "/var/fixops/policies"
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
        """Test _run_checkov three-stage containment check - Stage 3 (candidate outside base)."""
        # Create scanner with base_path as a subdirectory under TRUSTED_ROOT
        sub_dir = os.path.join(temp_dir, "subdir")
        os.makedirs(sub_dir, exist_ok=True)
        config = ScannerConfig(timeout_seconds=30, base_path=sub_dir)
        scanner_with_subdir = IaCScanner(config)
        # Create a file in temp_dir (parent of sub_dir, but still under TRUSTED_ROOT)
        test_file = os.path.join(temp_dir, "outside.tf")
        with open(test_file, "w") as f:
            f.write('resource "aws_instance" "example" {}')
        # Stage 1 passes (file is under TRUSTED_ROOT)
        # Stage 2 passes (base is under TRUSTED_ROOT)
        # Stage 3 fails (file is not under sub_dir)
        with pytest.raises(ValueError) as exc_info:
            await scanner_with_subdir._run_checkov(test_file, IaCProvider.TERRAFORM)
        assert "Path escapes base directory" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_run_tfsec_containment_check(self, scanner, temp_dir):
        """Test _run_tfsec three-stage containment check - Stage 1 (candidate outside trusted root)."""
        # /tmp/outside.tf is outside TRUSTED_ROOT (/var/fixops), so Stage 1 fails
        with patch.object(scanner, "_is_tfsec_available", return_value=True):
            with pytest.raises(ValueError) as exc_info:
                await scanner._run_tfsec("/tmp/outside.tf", IaCProvider.TERRAFORM)
            assert "Path escapes trusted root" in str(exc_info.value)

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
    async def test_run_tfsec_base_path_escapes_trusted_root(self, temp_dir):
        """Test _run_tfsec three-stage containment check - Stage 2 (base outside trusted root)."""
        # Create scanner with base_path outside TRUSTED_ROOT (/var/fixops)
        # but target_path inside TRUSTED_ROOT so Stage 1 passes and Stage 2 fails
        config = ScannerConfig(timeout_seconds=30, base_path="/tmp/untrusted")
        scanner = IaCScanner(config)
        os.makedirs("/tmp/untrusted", exist_ok=True)
        # Use a file under TRUSTED_ROOT (temp_dir is under /var/fixops/test-scans)
        test_file = os.path.join(temp_dir, "test.tf")
        with open(test_file, "w") as f:
            f.write('resource "aws_instance" "example" {}')
        try:
            with patch.object(scanner, "_is_tfsec_available", return_value=True):
                with pytest.raises(ValueError) as exc_info:
                    await scanner._run_tfsec(test_file, IaCProvider.TERRAFORM)
                # Stage 1 passes (file is under TRUSTED_ROOT)
                # Stage 2 fails (base is outside TRUSTED_ROOT)
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
