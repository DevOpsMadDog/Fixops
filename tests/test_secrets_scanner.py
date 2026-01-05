"""
Comprehensive tests for the secrets scanner module.

Tests cover:
- Scanner configuration and initialization
- Path validation and security
- Secret type mapping
- Gitleaks and trufflehog output parsing
- Async scanning functionality
- Error handling and edge cases
"""

import asyncio
import json
import os
import shutil
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.secrets_models import SecretFinding, SecretStatus, SecretType
from core.secrets_scanner import (
    SecretsDetector,
    SecretsScanner,
    SecretsScannerConfig,
    SecretsScanResult,
    SecretsScanStatus,
    get_secrets_detector,
)

TRUSTED_TEST_ROOT = "/var/fixops/test-scans"


class TestSecretsScannerConfig:
    """Tests for SecretsScannerConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = SecretsScannerConfig()
        assert config.gitleaks_path == "gitleaks"
        assert config.trufflehog_path == "trufflehog"
        assert config.timeout_seconds == 300
        assert config.max_file_size_mb == 50
        assert config.custom_config_path is None
        assert config.entropy_threshold == 4.5
        assert config.scan_history is True
        assert config.max_depth == 1000

    def test_config_from_env(self):
        """Test configuration from environment variables."""
        with patch.dict(
            os.environ,
            {
                "FIXOPS_GITLEAKS_PATH": "/custom/gitleaks",
                "FIXOPS_TRUFFLEHOG_PATH": "/custom/trufflehog",
                "FIXOPS_SECRETS_SCAN_TIMEOUT": "600",
                "FIXOPS_MAX_FILE_SIZE_MB": "100",
                "FIXOPS_SECRETS_CONFIG_PATH": "/config/gitleaks.toml",
                "FIXOPS_ENTROPY_THRESHOLD": "5.0",
                "FIXOPS_SCAN_HISTORY": "false",
                "FIXOPS_SCAN_MAX_DEPTH": "500",
            },
        ):
            config = SecretsScannerConfig.from_env()
            assert config.gitleaks_path == "/custom/gitleaks"
            assert config.trufflehog_path == "/custom/trufflehog"
            assert config.timeout_seconds == 600
            assert config.max_file_size_mb == 100
            assert config.custom_config_path == "/config/gitleaks.toml"
            assert config.entropy_threshold == 5.0
            assert config.scan_history is False
            assert config.max_depth == 500


class TestSecretsDetector:
    """Tests for SecretsDetector class."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under TRUSTED_TEST_ROOT for testing."""
        test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    @pytest.fixture
    def detector(self, temp_dir):
        """Create a detector instance for testing with temp_dir as base_path."""
        config = SecretsScannerConfig(timeout_seconds=30, base_path=temp_dir)
        return SecretsDetector(config)

    def test_detector_initialization(self, detector, temp_dir):
        """Test detector initialization."""
        assert detector.config is not None
        assert detector.config.timeout_seconds == 30
        assert detector.config.base_path == temp_dir

    def test_get_available_scanners(self, detector):
        """Test getting available scanners."""
        with patch.object(detector, "_is_gitleaks_available", return_value=True):
            with patch.object(detector, "_is_trufflehog_available", return_value=True):
                available = detector.get_available_scanners()
                assert SecretsScanner.GITLEAKS in available
                assert SecretsScanner.TRUFFLEHOG in available

    def test_get_available_scanners_none_available(self, detector):
        """Test when no scanners are available."""
        with patch.object(detector, "_is_gitleaks_available", return_value=False):
            with patch.object(detector, "_is_trufflehog_available", return_value=False):
                available = detector.get_available_scanners()
                assert len(available) == 0

    def test_validate_path_valid(self, detector, temp_dir):
        """Test path validation with valid relative path."""
        test_file = Path(temp_dir) / "config.py"
        test_file.write_text("API_KEY = 'secret'")

        # Use relative path (relative to base_path which is temp_dir)
        result = detector._validate_path("config.py")
        # _validate_path now returns str instead of Path
        assert os.path.exists(result)

    def test_validate_path_null_bytes(self, detector, temp_dir):
        """Test path validation rejects null bytes."""
        with pytest.raises(ValueError, match="contains null bytes"):
            detector._validate_path("test/file\x00.py")

    def test_validate_path_absolute_outside_base_rejected(self, detector, temp_dir):
        """Test path validation rejects absolute paths outside base directory."""
        # Absolute path outside TRUSTED_ROOT should be rejected
        with pytest.raises(ValueError, match="Path escapes trusted root"):
            detector._validate_path("/absolute/path/file.py")

    def test_validate_path_absolute_inside_base_accepted(self, detector, temp_dir):
        """Test path validation accepts absolute paths inside base directory."""
        # Create a test file inside the base directory
        test_file = Path(temp_dir) / "test_absolute.py"
        test_file.write_text("API_KEY = 'secret'")

        # Absolute path inside base directory should be accepted
        result = detector._validate_path(str(test_file))
        # _validate_path now returns str instead of Path
        assert os.path.exists(result)
        assert result == str(test_file)

    def test_validate_path_traversal_rejected(self, detector, temp_dir):
        """Test path validation rejects path traversal."""
        with pytest.raises(ValueError, match="Path traversal detected"):
            detector._validate_path("../../../etc/passwd")

    def test_validate_path_nonexistent(self, detector, temp_dir):
        """Test path validation with nonexistent relative path."""
        with pytest.raises(FileNotFoundError):
            detector._validate_path("nonexistent/path/file.py")

    def test_map_secret_type_aws(self, detector):
        """Test secret type mapping for AWS keys."""
        assert detector._map_secret_type("aws-access-key") == SecretType.AWS_KEY
        assert (
            detector._map_secret_type("generic", "AWS Secret Key") == SecretType.AWS_KEY
        )

    def test_map_secret_type_api_key(self, detector):
        """Test secret type mapping for API keys."""
        assert detector._map_secret_type("api-key") == SecretType.API_KEY
        assert (
            detector._map_secret_type("generic", "API Key detected")
            == SecretType.API_KEY
        )

    def test_map_secret_type_password(self, detector):
        """Test secret type mapping for passwords."""
        assert detector._map_secret_type("password") == SecretType.PASSWORD
        assert (
            detector._map_secret_type("generic", "Password found")
            == SecretType.PASSWORD
        )

    def test_map_secret_type_token(self, detector):
        """Test secret type mapping for tokens."""
        assert detector._map_secret_type("github-token") == SecretType.TOKEN
        assert (
            detector._map_secret_type("generic", "Token detected") == SecretType.TOKEN
        )

    def test_map_secret_type_private_key(self, detector):
        """Test secret type mapping for private keys."""
        assert detector._map_secret_type("private-key") == SecretType.PRIVATE_KEY

    def test_map_secret_type_certificate(self, detector):
        """Test secret type mapping for certificates."""
        assert detector._map_secret_type("certificate") == SecretType.CERTIFICATE
        assert detector._map_secret_type("ssl-cert") == SecretType.CERTIFICATE

    def test_map_secret_type_database(self, detector):
        """Test secret type mapping for database credentials."""
        assert (
            detector._map_secret_type("database-password")
            == SecretType.DATABASE_CREDENTIAL
        )
        assert (
            detector._map_secret_type("mysql-password")
            == SecretType.DATABASE_CREDENTIAL
        )
        assert (
            detector._map_secret_type("postgres-uri") == SecretType.DATABASE_CREDENTIAL
        )

    def test_map_secret_type_generic(self, detector):
        """Test secret type mapping for generic secrets."""
        assert detector._map_secret_type("unknown-type") == SecretType.GENERIC

    def test_parse_gitleaks_output_valid(self, detector):
        """Test parsing valid gitleaks output."""
        gitleaks_output = json.dumps(
            [
                {
                    "RuleID": "aws-access-key",
                    "Description": "AWS Access Key",
                    "File": "config.py",
                    "StartLine": 10,
                    "Commit": "abc123",
                    "Match": "AKIAIOSFODNN7EXAMPLE",
                    "Entropy": 4.5,
                    "Author": "test@example.com",
                    "Email": "test@example.com",
                    "Date": "2024-01-01",
                    "Message": "Add config",
                    "Fingerprint": "fp123",
                    "Tags": ["aws"],
                }
            ]
        )

        findings = detector._parse_gitleaks_output(gitleaks_output, "test-repo", "main")

        assert len(findings) == 1
        assert findings[0].secret_type == SecretType.AWS_KEY
        assert findings[0].file_path == "config.py"
        assert findings[0].line_number == 10
        assert findings[0].commit_hash == "abc123"
        assert findings[0].entropy_score == 4.5

    def test_parse_gitleaks_output_invalid_json(self, detector):
        """Test parsing invalid JSON from gitleaks."""
        findings = detector._parse_gitleaks_output(
            "not valid json", "test-repo", "main"
        )
        assert len(findings) == 0

    def test_parse_gitleaks_output_empty(self, detector):
        """Test parsing empty gitleaks output."""
        findings = detector._parse_gitleaks_output("", "test-repo", "main")
        assert len(findings) == 0

    def test_parse_gitleaks_output_empty_array(self, detector):
        """Test parsing empty array from gitleaks."""
        findings = detector._parse_gitleaks_output("[]", "test-repo", "main")
        assert len(findings) == 0

    def test_parse_trufflehog_output_valid(self, detector):
        """Test parsing valid trufflehog output."""
        trufflehog_output = json.dumps(
            {
                "DetectorName": "AWS",
                "DecoderName": "PLAIN",
                "Raw": "AKIAIOSFODNN7EXAMPLE",
                "Verified": True,
                "SourceMetadata": {
                    "Data": {
                        "Filesystem": {
                            "file": "config.py",
                            "line": 10,
                        }
                    }
                },
                "ExtraData": {"account": "123456789"},
            }
        )

        findings = detector._parse_trufflehog_output(
            trufflehog_output, "test-repo", "main"
        )

        assert len(findings) == 1
        assert findings[0].secret_type == SecretType.AWS_KEY
        assert findings[0].file_path == "config.py"
        assert findings[0].line_number == 10
        assert findings[0].metadata["verified"] is True

    def test_parse_trufflehog_output_git_source(self, detector):
        """Test parsing trufflehog output with Git source."""
        trufflehog_output = json.dumps(
            {
                "DetectorName": "Github",
                "DecoderName": "PLAIN",
                "Raw": "ghp_xxxxxxxxxxxx",
                "Verified": False,
                "SourceMetadata": {
                    "Data": {
                        "Git": {
                            "file": "config.py",
                            "line": 5,
                            "commit": "abc123",
                        }
                    }
                },
            }
        )

        findings = detector._parse_trufflehog_output(
            trufflehog_output, "test-repo", "main"
        )

        assert len(findings) == 1
        assert findings[0].commit_hash == "abc123"

    def test_parse_trufflehog_output_invalid_json(self, detector):
        """Test parsing invalid JSON from trufflehog."""
        findings = detector._parse_trufflehog_output(
            "not valid json", "test-repo", "main"
        )
        assert len(findings) == 0

    def test_parse_trufflehog_output_empty(self, detector):
        """Test parsing empty trufflehog output."""
        findings = detector._parse_trufflehog_output("", "test-repo", "main")
        assert len(findings) == 0

    def test_parse_trufflehog_output_multiline(self, detector):
        """Test parsing multiline trufflehog output (NDJSON)."""
        line1 = json.dumps(
            {
                "DetectorName": "AWS",
                "Raw": "AKIAIOSFODNN7EXAMPLE",
                "SourceMetadata": {
                    "Data": {"Filesystem": {"file": "config1.py", "line": 1}}
                },
            }
        )
        line2 = json.dumps(
            {
                "DetectorName": "Github",
                "Raw": "ghp_xxxxxxxxxxxx",
                "SourceMetadata": {
                    "Data": {"Filesystem": {"file": "config2.py", "line": 2}}
                },
            }
        )
        trufflehog_output = f"{line1}\n{line2}"

        findings = detector._parse_trufflehog_output(
            trufflehog_output, "test-repo", "main"
        )

        assert len(findings) == 2

    def test_is_git_repo(self, detector, temp_dir):
        """Test git repository detection."""
        assert detector._is_git_repo(Path(temp_dir)) is False

        git_dir = Path(temp_dir) / ".git"
        git_dir.mkdir()
        assert detector._is_git_repo(Path(temp_dir)) is True

    def test_get_repo_info_non_git(self, detector, temp_dir):
        """Test repo info extraction for non-git directory."""
        repo, branch = detector._get_repo_info(Path(temp_dir))
        assert repo == temp_dir
        assert branch == "main"

    @pytest.mark.asyncio
    async def test_scan_no_scanner_available(self, detector, temp_dir):
        """Test scan when no scanner is available."""
        test_file = Path(temp_dir) / "config.py"
        test_file.write_text("API_KEY = 'secret'")

        with patch.object(detector, "_is_gitleaks_available", return_value=False):
            with patch.object(detector, "_is_trufflehog_available", return_value=False):
                # Use relative path (relative to base_path which is temp_dir)
                result = await detector.scan("config.py")

                assert result.status == SecretsScanStatus.FAILED
                assert "No secrets scanner available" in result.error_message

    @pytest.mark.asyncio
    async def test_scan_invalid_path(self, detector, temp_dir):
        """Test scan with invalid (absolute) path outside base directory."""
        result = await detector.scan("/nonexistent/path/file.py")

        assert result.status == SecretsScanStatus.FAILED
        assert "Path escapes trusted root" in result.error_message

    @pytest.mark.asyncio
    async def test_scan_nonexistent_path(self, detector, temp_dir):
        """Test scan with nonexistent relative path returns failed status."""
        result = await detector.scan("nonexistent/path/to/file.py")

        assert result.status == SecretsScanStatus.FAILED
        assert "does not exist" in result.error_message

    @pytest.mark.asyncio
    async def test_scan_with_gitleaks(self, detector, temp_dir):
        """Test scan using gitleaks."""
        test_file = Path(temp_dir) / "config.py"
        test_file.write_text("API_KEY = 'secret'")

        mock_output = json.dumps([])

        with patch.object(detector, "_is_gitleaks_available", return_value=True):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_process = AsyncMock()
                mock_process.communicate.return_value = (
                    mock_output.encode(),
                    b"",
                )
                mock_process.returncode = 0
                mock_exec.return_value = mock_process

                # Use relative path (relative to base_path which is temp_dir)
                result = await detector.scan("config.py")

                assert result.status == SecretsScanStatus.COMPLETED
                assert result.scanner == SecretsScanner.GITLEAKS

    @pytest.mark.asyncio
    async def test_scan_with_trufflehog(self, detector, temp_dir):
        """Test scan using trufflehog."""
        test_file = Path(temp_dir) / "config.py"
        test_file.write_text("API_KEY = 'secret'")

        mock_output = ""

        with patch.object(detector, "_is_gitleaks_available", return_value=False):
            with patch.object(detector, "_is_trufflehog_available", return_value=True):
                with patch("asyncio.create_subprocess_exec") as mock_exec:
                    mock_process = AsyncMock()
                    mock_process.communicate.return_value = (
                        mock_output.encode(),
                        b"",
                    )
                    mock_process.returncode = 0
                    mock_exec.return_value = mock_process

                    # Use relative path (relative to base_path which is temp_dir)
                    result = await detector.scan("config.py")

                    assert result.status == SecretsScanStatus.COMPLETED
                    assert result.scanner == SecretsScanner.TRUFFLEHOG

    @pytest.mark.asyncio
    async def test_scan_timeout(self, detector, temp_dir):
        """Test scan timeout handling."""
        test_file = Path(temp_dir) / "config.py"
        test_file.write_text("API_KEY = 'secret'")

        with patch.object(detector, "_is_gitleaks_available", return_value=True):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_process = AsyncMock()
                mock_process.communicate.side_effect = asyncio.TimeoutError()
                mock_exec.return_value = mock_process

                # Use relative path (relative to base_path which is temp_dir)
                result = await detector.scan("config.py")

                assert result.status == SecretsScanStatus.FAILED
                assert "timed out" in result.error_message

    @pytest.mark.asyncio
    async def test_scan_content(self, detector):
        """Test scanning content as string."""
        content = "API_KEY = 'AKIAIOSFODNN7EXAMPLE'"

        with patch.object(detector, "_is_gitleaks_available", return_value=True):
            with patch.object(detector, "_run_gitleaks", return_value=([], "[]", None)):
                result = await detector.scan_content(content, "config.py")

                assert result.status == SecretsScanStatus.COMPLETED
                for finding in result.findings:
                    assert finding.file_path == "config.py"

    @pytest.mark.asyncio
    async def test_scan_multiple(self, detector, temp_dir):
        """Test scanning multiple paths concurrently."""
        files = []
        for i in range(3):
            test_file = Path(temp_dir) / f"config{i}.py"
            test_file.write_text(f"API_KEY_{i} = 'secret{i}'")
            # Use relative paths (relative to base_path which is temp_dir)
            files.append(f"config{i}.py")

        mock_output = json.dumps([])

        with patch.object(detector, "_is_gitleaks_available", return_value=True):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_process = AsyncMock()
                mock_process.communicate.return_value = (
                    mock_output.encode(),
                    b"",
                )
                mock_process.returncode = 0
                mock_exec.return_value = mock_process

                results = await detector.scan_multiple(files, max_concurrent=2)

                assert len(results) == 3
                for result in results:
                    assert result.status == SecretsScanStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_scan_with_explicit_scanner(self, detector, temp_dir):
        """Test scan with explicitly specified scanner."""
        test_file = Path(temp_dir) / "config.py"
        test_file.write_text("API_KEY = 'secret'")

        mock_output = ""

        with patch.object(detector, "_is_trufflehog_available", return_value=True):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_process = AsyncMock()
                mock_process.communicate.return_value = (
                    mock_output.encode(),
                    b"",
                )
                mock_process.returncode = 0
                mock_exec.return_value = mock_process

                # Use relative path (relative to base_path which is temp_dir)
                result = await detector.scan(
                    "config.py", scanner=SecretsScanner.TRUFFLEHOG
                )

                assert result.scanner == SecretsScanner.TRUFFLEHOG


class TestSecretsScanResult:
    """Tests for SecretsScanResult dataclass."""

    def test_scan_result_to_dict(self):
        """Test SecretsScanResult to_dict method."""
        from datetime import datetime

        result = SecretsScanResult(
            scan_id="test-123",
            status=SecretsScanStatus.COMPLETED,
            scanner=SecretsScanner.GITLEAKS,
            target_path="/test/config.py",
            repository="test-repo",
            branch="main",
            findings=[],
            started_at=datetime(2024, 1, 1, 12, 0, 0),
            completed_at=datetime(2024, 1, 1, 12, 0, 30),
            duration_seconds=30.0,
            metadata={"key": "value"},
        )

        result_dict = result.to_dict()

        assert result_dict["scan_id"] == "test-123"
        assert result_dict["status"] == "completed"
        assert result_dict["scanner"] == "gitleaks"
        assert result_dict["repository"] == "test-repo"
        assert result_dict["branch"] == "main"
        assert result_dict["findings_count"] == 0
        assert result_dict["duration_seconds"] == 30.0


class TestGetSecretsDetector:
    """Tests for get_secrets_detector function."""

    def test_get_secrets_detector_singleton(self):
        """Test that get_secrets_detector returns singleton instance."""
        import core.secrets_scanner as scanner_module

        scanner_module._default_detector = None

        detector1 = get_secrets_detector()
        detector2 = get_secrets_detector()

        assert detector1 is detector2

        scanner_module._default_detector = None


class TestGitleaksNoGit:
    """Tests for gitleaks with --no-git flag."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under TRUSTED_TEST_ROOT for testing."""
        test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    @pytest.fixture
    def detector(self, temp_dir):
        """Create a detector instance for testing with temp_dir as base_path."""
        config = SecretsScannerConfig(scan_history=False, base_path=temp_dir)
        return SecretsDetector(config)

    @pytest.mark.asyncio
    async def test_gitleaks_no_git_flag(self, detector, temp_dir):
        """Test that gitleaks uses --no-git flag when scan_history is False."""
        test_file = Path(temp_dir) / "config.py"
        test_file.write_text("API_KEY = 'secret'")

        mock_output = json.dumps([])

        with patch.object(detector, "_is_gitleaks_available", return_value=True):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_process = AsyncMock()
                mock_process.communicate.return_value = (
                    mock_output.encode(),
                    b"",
                )
                mock_process.returncode = 0
                mock_exec.return_value = mock_process

                # Use relative path (relative to base_path which is temp_dir)
                await detector.scan("config.py")

                call_args = mock_exec.call_args[0]
                assert "--no-git" in call_args


class TestTrufflehogModes:
    """Tests for trufflehog filesystem vs git modes."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under TRUSTED_TEST_ROOT for testing."""
        test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    @pytest.fixture
    def detector(self, temp_dir):
        """Create a detector instance for testing with temp_dir as base_path."""
        config = SecretsScannerConfig(base_path=temp_dir)
        return SecretsDetector(config)

    @pytest.mark.asyncio
    async def test_trufflehog_filesystem_mode(self, detector, temp_dir):
        """Test trufflehog uses filesystem mode for non-git directories."""
        test_file = Path(temp_dir) / "config.py"
        test_file.write_text("API_KEY = 'secret'")

        mock_output = ""

        with patch.object(detector, "_is_gitleaks_available", return_value=False):
            with patch.object(detector, "_is_trufflehog_available", return_value=True):
                with patch("asyncio.create_subprocess_exec") as mock_exec:
                    mock_process = AsyncMock()
                    mock_process.communicate.return_value = (
                        mock_output.encode(),
                        b"",
                    )
                    mock_process.returncode = 0
                    mock_exec.return_value = mock_process

                    # Use relative path (relative to base_path which is temp_dir)
                    await detector.scan("config.py")

                    call_args = mock_exec.call_args[0]
                    assert "filesystem" in call_args

    @pytest.mark.asyncio
    async def test_trufflehog_git_mode(self, detector, temp_dir):
        """Test trufflehog uses git mode for git repositories."""
        git_dir = Path(temp_dir) / ".git"
        git_dir.mkdir()
        test_file = Path(temp_dir) / "config.py"
        test_file.write_text("API_KEY = 'secret'")

        mock_output = ""

        with patch.object(detector, "_is_gitleaks_available", return_value=False):
            with patch.object(detector, "_is_trufflehog_available", return_value=True):
                with patch("asyncio.create_subprocess_exec") as mock_exec:
                    mock_process = AsyncMock()
                    mock_process.communicate.return_value = (
                        mock_output.encode(),
                        b"",
                    )
                    mock_process.returncode = 0
                    mock_exec.return_value = mock_process

                    # Use "." to scan the base_path directory (which is temp_dir)
                    await detector.scan(".")

                    call_args = mock_exec.call_args[0]
                    assert "git" in call_args


class TestMatchedPatternTruncation:
    """Tests for matched pattern truncation."""

    @pytest.fixture
    def detector(self):
        """Create a detector instance for testing."""
        return SecretsDetector()

    def test_gitleaks_match_truncation(self, detector):
        """Test that long matches are truncated in gitleaks output."""
        long_match = "A" * 200
        gitleaks_output = json.dumps(
            [
                {
                    "RuleID": "generic-secret",
                    "File": "config.py",
                    "StartLine": 1,
                    "Match": long_match,
                }
            ]
        )

        findings = detector._parse_gitleaks_output(gitleaks_output, "test-repo", "main")

        assert len(findings) == 1
        assert len(findings[0].matched_pattern) == 100

    def test_trufflehog_raw_truncation(self, detector):
        """Test that long raw values are truncated in trufflehog output."""
        long_raw = "B" * 200
        trufflehog_output = json.dumps(
            {
                "DetectorName": "Generic",
                "Raw": long_raw,
                "SourceMetadata": {
                    "Data": {"Filesystem": {"file": "config.py", "line": 1}}
                },
            }
        )

        findings = detector._parse_trufflehog_output(
            trufflehog_output, "test-repo", "main"
        )

        assert len(findings) == 1
        assert len(findings[0].matched_pattern) == 100


class TestSecretsDetectorErrorHandling:
    """Test secrets detector error handling paths."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under TRUSTED_TEST_ROOT for testing."""
        test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    @pytest.fixture
    def detector(self, temp_dir):
        """Create a detector instance for testing with temp_dir as base_path."""
        config = SecretsScannerConfig(timeout_seconds=30, base_path=temp_dir)
        return SecretsDetector(config)

    @pytest.mark.asyncio
    async def test_gitleaks_nonzero_exit_code(self, detector, temp_dir):
        """Test gitleaks with non-zero/non-one exit code."""
        test_file = Path(temp_dir) / "config.py"
        test_file.write_text("API_KEY = 'secret'")

        with patch.object(detector, "_is_gitleaks_available", return_value=True):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_process = AsyncMock()
                mock_process.communicate.return_value = (b"", b"Error occurred")
                mock_process.returncode = 2
                mock_exec.return_value = mock_process

                result = await detector.scan("config.py")

                assert result.status == SecretsScanStatus.FAILED
                assert "exited with code 2" in result.error_message

    @pytest.mark.asyncio
    async def test_gitleaks_not_installed(self, detector, temp_dir):
        """Test gitleaks when not installed."""
        test_file = Path(temp_dir) / "config.py"
        test_file.write_text("API_KEY = 'secret'")

        with patch.object(detector, "_is_gitleaks_available", return_value=True):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_exec.side_effect = FileNotFoundError("gitleaks not found")

                result = await detector.scan("config.py")

                assert result.status == SecretsScanStatus.FAILED
                assert "not installed" in result.error_message

    @pytest.mark.asyncio
    async def test_gitleaks_generic_exception(self, detector, temp_dir):
        """Test gitleaks with generic exception."""
        test_file = Path(temp_dir) / "config.py"
        test_file.write_text("API_KEY = 'secret'")

        with patch.object(detector, "_is_gitleaks_available", return_value=True):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_exec.side_effect = RuntimeError("Unexpected error")

                result = await detector.scan("config.py")

                assert result.status == SecretsScanStatus.FAILED
                assert "failed" in result.error_message.lower()

    @pytest.mark.asyncio
    async def test_trufflehog_nonzero_exit_code(self, detector, temp_dir):
        """Test trufflehog with non-zero/non-one exit code."""
        test_file = Path(temp_dir) / "config.py"
        test_file.write_text("API_KEY = 'secret'")

        with patch.object(detector, "_is_trufflehog_available", return_value=True):
            with patch.object(detector, "_is_gitleaks_available", return_value=False):
                with patch("asyncio.create_subprocess_exec") as mock_exec:
                    mock_process = AsyncMock()
                    mock_process.communicate.return_value = (b"", b"Error occurred")
                    mock_process.returncode = 2
                    mock_exec.return_value = mock_process

                    result = await detector.scan("config.py")

                    assert result.status == SecretsScanStatus.FAILED
                    assert "exited with code 2" in result.error_message

    @pytest.mark.asyncio
    async def test_trufflehog_timeout(self, detector, temp_dir):
        """Test trufflehog timeout handling."""
        test_file = Path(temp_dir) / "config.py"
        test_file.write_text("API_KEY = 'secret'")

        with patch.object(detector, "_is_trufflehog_available", return_value=True):
            with patch.object(detector, "_is_gitleaks_available", return_value=False):
                with patch("asyncio.create_subprocess_exec") as mock_exec:
                    mock_process = AsyncMock()
                    mock_process.communicate.side_effect = asyncio.TimeoutError()
                    mock_exec.return_value = mock_process

                    result = await detector.scan("config.py")

                    assert result.status == SecretsScanStatus.FAILED
                    assert "timed out" in result.error_message

    @pytest.mark.asyncio
    async def test_trufflehog_not_installed(self, detector, temp_dir):
        """Test trufflehog when not installed."""
        test_file = Path(temp_dir) / "config.py"
        test_file.write_text("API_KEY = 'secret'")

        with patch.object(detector, "_is_trufflehog_available", return_value=True):
            with patch.object(detector, "_is_gitleaks_available", return_value=False):
                with patch("asyncio.create_subprocess_exec") as mock_exec:
                    mock_exec.side_effect = FileNotFoundError("trufflehog not found")

                    result = await detector.scan("config.py")

                    assert result.status == SecretsScanStatus.FAILED
                    assert "not installed" in result.error_message

    @pytest.mark.asyncio
    async def test_trufflehog_generic_exception(self, detector, temp_dir):
        """Test trufflehog with generic exception."""
        test_file = Path(temp_dir) / "config.py"
        test_file.write_text("API_KEY = 'secret'")

        with patch.object(detector, "_is_trufflehog_available", return_value=True):
            with patch.object(detector, "_is_gitleaks_available", return_value=False):
                with patch("asyncio.create_subprocess_exec") as mock_exec:
                    mock_exec.side_effect = RuntimeError("Unexpected error")

                    result = await detector.scan("config.py")

                    assert result.status == SecretsScanStatus.FAILED
                    assert "failed" in result.error_message.lower()


class TestScanContentSecretsEdgeCases:
    """Test scan_content edge cases for secrets scanner."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under TRUSTED_TEST_ROOT for testing."""
        test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    @pytest.fixture
    def detector(self, temp_dir):
        """Create a detector instance for testing with temp_dir as base_path."""
        config = SecretsScannerConfig(timeout_seconds=30, base_path=temp_dir)
        return SecretsDetector(config)

    @pytest.mark.asyncio
    async def test_scan_content_no_scanner_available(self, detector):
        """Test scan_content when no scanner is available."""
        with patch.object(detector, "get_available_scanners", return_value=[]):
            result = await detector.scan_content(
                content="API_KEY = 'secret'",
                filename="config.py",
            )

            assert result.status == SecretsScanStatus.FAILED
            assert "No secrets scanner available" in result.error_message

    @pytest.mark.asyncio
    async def test_scan_content_invalid_extension(self, detector):
        """Test scan_content with invalid extension defaults to .py."""
        with patch.object(
            detector, "get_available_scanners", return_value=[SecretsScanner.GITLEAKS]
        ):
            with patch.object(detector, "_run_gitleaks") as mock_run:
                mock_run.return_value = ([], "", None)

                result = await detector.scan_content(
                    content="API_KEY = 'secret'",
                    filename="config.invalid",
                )

                assert result.status == SecretsScanStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_scan_content_with_trufflehog(self, detector):
        """Test scan_content using trufflehog scanner."""
        with patch.object(
            detector, "get_available_scanners", return_value=[SecretsScanner.TRUFFLEHOG]
        ):
            with patch.object(detector, "_run_trufflehog") as mock_run:
                mock_run.return_value = ([], "", None)

                result = await detector.scan_content(
                    content="API_KEY = 'secret'",
                    filename="config.py",
                )

                assert result.status == SecretsScanStatus.COMPLETED
                mock_run.assert_called_once()

    @pytest.mark.asyncio
    async def test_scan_content_with_error(self, detector):
        """Test scan_content when scanner returns error."""
        with patch.object(
            detector, "get_available_scanners", return_value=[SecretsScanner.GITLEAKS]
        ):
            with patch.object(detector, "_run_gitleaks") as mock_run:
                mock_run.return_value = ([], "raw output", "Scanner error")

                result = await detector.scan_content(
                    content="API_KEY = 'secret'",
                    filename="config.py",
                )

                assert result.status == SecretsScanStatus.FAILED
                assert result.error_message == "Scanner error"

    @pytest.mark.asyncio
    async def test_scan_content_with_findings(self, detector):
        """Test scan_content with findings updates file_path."""
        finding = SecretFinding(
            id="test-id",
            secret_type=SecretType.API_KEY,
            status=SecretStatus.ACTIVE,
            file_path="/tmp/content.py",
            line_number=1,
            repository="test-repo",
            branch="main",
        )

        with patch.object(
            detector, "get_available_scanners", return_value=[SecretsScanner.GITLEAKS]
        ):
            with patch.object(detector, "_run_gitleaks") as mock_run:
                mock_run.return_value = ([finding], "", None)

                result = await detector.scan_content(
                    content="API_KEY = 'secret'",
                    filename="config.py",
                )

                assert result.status == SecretsScanStatus.COMPLETED
                assert len(result.findings) == 1
                assert result.findings[0].file_path == "config.py"

    @pytest.mark.asyncio
    async def test_scan_content_exception(self, detector):
        """Test scan_content with exception."""
        with patch.object(detector, "get_available_scanners") as mock_get:
            mock_get.side_effect = RuntimeError("Unexpected error")

            result = await detector.scan_content(
                content="API_KEY = 'secret'",
                filename="config.py",
            )

            assert result.status == SecretsScanStatus.FAILED
            assert "Unexpected error" in result.error_message


class TestSecretsParsingEdgeCases:
    """Test edge cases in parsing gitleaks and trufflehog output."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under TRUSTED_TEST_ROOT for testing."""
        test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    @pytest.fixture
    def detector(self, temp_dir):
        """Create a detector instance for testing with temp_dir as base_path."""
        config = SecretsScannerConfig(timeout_seconds=30, base_path=temp_dir)
        return SecretsDetector(config)

    def test_parse_gitleaks_output_single_object(self, detector):
        """Test parsing gitleaks output when it's a single object instead of array."""
        # Line 253: data = [data] if data else []
        single_finding = json.dumps(
            {
                "RuleID": "generic-api-key",
                "Description": "API key detected",
                "File": "config.py",
                "StartLine": 10,
                "Match": "api_key=secret123",
            }
        )

        findings = detector._parse_gitleaks_output(single_finding, "test-repo", "main")

        assert len(findings) == 1
        assert findings[0].file_path == "config.py"
        assert findings[0].line_number == 10

    def test_parse_trufflehog_output_with_empty_lines(self, detector):
        """Test parsing trufflehog output with empty lines between JSON objects."""
        # Line 298: continue (empty line)
        output_with_empty_lines = (
            '{"DetectorName": "AWS", "Raw": "AKIAIOSFODNN7EXAMPLE", '
            '"SourceMetadata": {"Data": {"Filesystem": {"file": "config.py", "line": 5}}}}\n'
            "\n"
            "\n"
            '{"DetectorName": "Generic", "Raw": "secret123", '
            '"SourceMetadata": {"Data": {"Filesystem": {"file": "app.py", "line": 10}}}}'
        )

        findings = detector._parse_trufflehog_output(
            output_with_empty_lines, "test-repo", "main"
        )

        assert len(findings) == 2
        assert findings[0].file_path == "config.py"
        assert findings[1].file_path == "app.py"


class TestGitleaksCustomConfig:
    """Test gitleaks with custom config path."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under TRUSTED_TEST_ROOT for testing."""
        test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    @pytest.fixture
    def detector_with_custom_config(self, temp_dir):
        """Create a detector with custom config path."""
        # Line 358: cmd.extend(["--config", self.config.custom_config_path])
        config = SecretsScannerConfig(
            timeout_seconds=30,
            base_path=temp_dir,
            custom_config_path="/path/to/custom/.gitleaks.toml",
        )
        return SecretsDetector(config)

    @pytest.mark.asyncio
    async def test_gitleaks_with_custom_config(
        self, detector_with_custom_config, temp_dir
    ):
        """Test that custom config path is passed to gitleaks."""
        # Create a test file
        test_file = Path(temp_dir) / "test.py"
        test_file.write_text("API_KEY = 'secret'")

        with patch.object(
            detector_with_custom_config, "_is_gitleaks_available", return_value=True
        ):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_process = MagicMock()
                mock_process.communicate = AsyncMock(return_value=(b"[]", b""))
                mock_process.returncode = 0
                mock_exec.return_value = mock_process

                await detector_with_custom_config._run_gitleaks(
                    Path(temp_dir), "test-repo", "main", False
                )

                # Verify custom config was passed
                call_args = mock_exec.call_args[0]
                assert "--config" in call_args
                assert "/path/to/custom/.gitleaks.toml" in call_args


class TestGetRepoInfoException:
    """Test _get_repo_info exception handling."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under TRUSTED_TEST_ROOT for testing."""
        test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    @pytest.fixture
    def detector(self, temp_dir):
        """Create a detector instance for testing with temp_dir as base_path."""
        config = SecretsScannerConfig(timeout_seconds=30, base_path=temp_dir)
        return SecretsDetector(config)

    def test_get_repo_info_exception(self, detector, temp_dir):
        """Test _get_repo_info returns defaults when subprocess raises exception."""
        # Lines 494-495: except Exception: return str(path), "main"
        test_path = Path(temp_dir) / "test.py"
        test_path.write_text("content")

        # Mock _is_git_repo to return True so we enter the try block
        with patch.object(detector, "_is_git_repo", return_value=True):
            # Mock subprocess.run to raise an exception
            # Note: subprocess is imported inside the function, so we patch it globally
            import subprocess as subprocess_module

            original_run = subprocess_module.run

            def mock_run(*args, **kwargs):
                raise Exception("Subprocess failed")

            subprocess_module.run = mock_run
            try:
                repo_name, branch = detector._get_repo_info(test_path)
                assert repo_name == str(test_path)
                assert branch == "main"
            finally:
                subprocess_module.run = original_run

    def test_get_repo_info_timeout(self, detector, temp_dir):
        """Test _get_repo_info returns defaults on timeout."""
        import subprocess as subprocess_module

        test_path = Path(temp_dir) / "test.py"
        test_path.write_text("content")

        # Mock _is_git_repo to return True so we enter the try block
        with patch.object(detector, "_is_git_repo", return_value=True):
            original_run = subprocess_module.run

            def mock_run(*args, **kwargs):
                raise subprocess_module.TimeoutExpired(cmd="git", timeout=5)

            subprocess_module.run = mock_run
            try:
                repo_name, branch = detector._get_repo_info(test_path)
                assert repo_name == str(test_path)
                assert branch == "main"
            finally:
                subprocess_module.run = original_run


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
    def detector(self, temp_dir):
        """Create a detector instance for testing with temp_dir as base_path."""
        config = SecretsScannerConfig(timeout_seconds=30, base_path=temp_dir)
        return SecretsDetector(config)

    def test_verify_containment_valid_path(self, detector, temp_dir):
        """Test _verify_containment with a valid path."""
        test_file = os.path.join(temp_dir, "test.py")
        with open(test_file, "w") as f:
            f.write("content")
        result = detector._verify_containment(Path(test_file))
        assert result == os.path.realpath(test_file)

    def test_verify_containment_path_escape(self, detector, temp_dir):
        """Test _verify_containment raises ValueError when path escapes base."""
        with pytest.raises(ValueError) as exc_info:
            detector._verify_containment(Path("/tmp/outside.py"))
        assert "Path escapes base directory" in str(exc_info.value)

    def test_validate_path_containment_error(self, detector, temp_dir):
        """Test _validate_path raises ValueError for paths outside trusted root."""
        # Test that paths outside TRUSTED_ROOT are rejected
        with pytest.raises(ValueError) as exc_info:
            detector._validate_path("/tmp/outside/test.py")
        assert "Path escapes trusted root" in str(exc_info.value)

    def test_validate_path_base_path_escapes_trusted_root(self, temp_dir):
        """Test _validate_path raises ValueError when base_path escapes TRUSTED_ROOT.

        This tests Stage 2 of the three-stage containment check.
        To reach Stage 2, we need:
        - Stage 1 to pass: candidate must be under TRUSTED_ROOT
        - Stage 2 to fail: base_path must NOT be under TRUSTED_ROOT

        We achieve this by passing an absolute path under TRUSTED_ROOT
        to a detector configured with base_path outside TRUSTED_ROOT.
        """
        # Create detector with base_path outside TRUSTED_ROOT (/var/fixops)
        config = SecretsScannerConfig(timeout_seconds=30, base_path="/tmp/untrusted")
        detector = SecretsDetector(config)
        # Create a test file under TRUSTED_ROOT (temp_dir is under /var/fixops/test-scans)
        test_file = os.path.join(temp_dir, "test.py")
        with open(test_file, "w") as f:
            f.write("API_KEY = 'secret'")
        # Pass absolute path under TRUSTED_ROOT to detector with base_path outside TRUSTED_ROOT
        with pytest.raises(ValueError) as exc_info:
            detector._validate_path(test_file)
        assert "Base path escapes trusted root" in str(exc_info.value)

    def test_validate_path_escapes_base_directory(self, temp_dir):
        """Test _validate_path raises ValueError when path escapes base directory."""
        # Create detector with base_path under TRUSTED_ROOT
        # Create a subdirectory to use as base_path
        sub_dir = os.path.join(temp_dir, "subdir")
        os.makedirs(sub_dir, exist_ok=True)
        config = SecretsScannerConfig(timeout_seconds=30, base_path=sub_dir)
        detector = SecretsDetector(config)
        # Create a file in temp_dir (parent of sub_dir)
        test_file = os.path.join(temp_dir, "outside.py")
        with open(test_file, "w") as f:
            f.write("API_KEY = 'secret'")
        # Try to access the file from detector with sub_dir as base_path
        with pytest.raises(ValueError) as exc_info:
            detector._validate_path(test_file)
        assert "Path escapes base directory" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_run_gitleaks_containment_check(self, detector, temp_dir):
        """Test _run_gitleaks three-stage containment check - Stage 1 (candidate outside trusted root)."""
        # /tmp/outside.py is outside TRUSTED_ROOT (/var/fixops), so Stage 1 fails
        with patch.object(detector, "_is_gitleaks_available", return_value=True):
            with pytest.raises(ValueError) as exc_info:
                await detector._run_gitleaks("/tmp/outside.py", "repo", "main", False)
            assert "Path escapes trusted root" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_run_trufflehog_containment_check(self, detector, temp_dir):
        """Test _run_trufflehog three-stage containment check - Stage 1 (candidate outside trusted root)."""
        # /tmp/outside.py is outside TRUSTED_ROOT (/var/fixops), so Stage 1 fails
        with patch.object(detector, "_is_trufflehog_available", return_value=True):
            with pytest.raises(ValueError) as exc_info:
                await detector._run_trufflehog("/tmp/outside.py", "repo", "main", False)
            assert "Path escapes trusted root" in str(exc_info.value)

    def test_is_git_repo_containment_error(self, detector, temp_dir):
        """Test _is_git_repo handles PathContainmentError."""
        test_file = os.path.join(temp_dir, "test.py")
        with open(test_file, "w") as f:
            f.write("content")

        with patch("core.secrets_scanner.safe_get_parent_dirs") as mock_parent_dirs:
            from core.safe_path_ops import PathContainmentError

            mock_parent_dirs.side_effect = PathContainmentError("Path escapes")
            with pytest.raises(ValueError) as exc_info:
                detector._is_git_repo(Path(test_file))
            assert "Path escapes base directory" in str(exc_info.value)

    def test_get_repo_info_safe_isdir_containment_error(self, detector, temp_dir):
        """Test _get_repo_info handles PathContainmentError from safe_isdir by raising ValueError."""
        test_file = os.path.join(temp_dir, "test.py")
        with open(test_file, "w") as f:
            f.write("content")

        with patch.object(detector, "_is_git_repo", return_value=True):
            with patch("core.secrets_scanner.safe_isdir") as mock_safe_isdir:
                from core.safe_path_ops import PathContainmentError

                mock_safe_isdir.side_effect = PathContainmentError("Path escapes")
                repo_name, branch = detector._get_repo_info(Path(test_file))
                assert repo_name == str(Path(test_file))
                assert branch == "main"

    def test_get_repo_info_subprocess_containment_error(self, detector, temp_dir):
        """Test _get_repo_info handles PathContainmentError from safe_subprocess_run."""
        test_file = os.path.join(temp_dir, "test.py")
        with open(test_file, "w") as f:
            f.write("content")

        with patch.object(detector, "_is_git_repo", return_value=True):
            with patch("core.secrets_scanner.safe_isdir", return_value=False):
                with patch("core.secrets_scanner.safe_subprocess_run") as mock_run:
                    from core.safe_path_ops import PathContainmentError

                    mock_run.side_effect = PathContainmentError("Path escapes")
                    repo_name, branch = detector._get_repo_info(Path(test_file))
                    assert repo_name == str(Path(test_file))
                    assert branch == "main"

    def test_verify_containment_base_path_escapes_trusted_root(self):
        """Test _verify_containment raises ValueError when base_path escapes TRUSTED_ROOT."""
        # Create detector with base_path outside TRUSTED_ROOT (/var/fixops)
        config = SecretsScannerConfig(timeout_seconds=30, base_path="/tmp/untrusted")
        detector = SecretsDetector(config)
        os.makedirs("/tmp/untrusted", exist_ok=True)
        test_file = "/tmp/untrusted/test.py"
        with open(test_file, "w") as f:
            f.write("content")
        try:
            with pytest.raises(ValueError) as exc_info:
                detector._verify_containment(Path(test_file))
            assert "Base path escapes trusted root" in str(exc_info.value)
        finally:
            shutil.rmtree("/tmp/untrusted", ignore_errors=True)

    @pytest.mark.asyncio
    async def test_run_gitleaks_base_path_escapes_trusted_root(self, temp_dir):
        """Test _run_gitleaks three-stage containment check - Stage 2 (base outside trusted root)."""
        # Create detector with base_path outside TRUSTED_ROOT (/var/fixops)
        # but target_path inside TRUSTED_ROOT so Stage 1 passes and Stage 2 fails
        config = SecretsScannerConfig(timeout_seconds=30, base_path="/tmp/untrusted")
        detector = SecretsDetector(config)
        os.makedirs("/tmp/untrusted", exist_ok=True)
        # Use a file under TRUSTED_ROOT (temp_dir is under /var/fixops/test-scans)
        test_file = os.path.join(temp_dir, "test.py")
        with open(test_file, "w") as f:
            f.write("content")
        try:
            with patch.object(detector, "_is_gitleaks_available", return_value=True):
                with pytest.raises(ValueError) as exc_info:
                    await detector._run_gitleaks(test_file, "repo", "main", False)
                # Stage 1 passes (file is under TRUSTED_ROOT)
                # Stage 2 fails (base is outside TRUSTED_ROOT)
                assert "Base path escapes trusted root" in str(exc_info.value)
        finally:
            shutil.rmtree("/tmp/untrusted", ignore_errors=True)

    @pytest.mark.asyncio
    async def test_run_trufflehog_base_path_escapes_trusted_root(self, temp_dir):
        """Test _run_trufflehog three-stage containment check - Stage 2 (base outside trusted root)."""
        # Create detector with base_path outside TRUSTED_ROOT (/var/fixops)
        # but target_path inside TRUSTED_ROOT so Stage 1 passes and Stage 2 fails
        config = SecretsScannerConfig(timeout_seconds=30, base_path="/tmp/untrusted")
        detector = SecretsDetector(config)
        os.makedirs("/tmp/untrusted", exist_ok=True)
        # Use a file under TRUSTED_ROOT (temp_dir is under /var/fixops/test-scans)
        test_file = os.path.join(temp_dir, "test.py")
        with open(test_file, "w") as f:
            f.write("content")
        try:
            with patch.object(detector, "_is_trufflehog_available", return_value=True):
                with pytest.raises(ValueError) as exc_info:
                    await detector._run_trufflehog(test_file, "repo", "main", False)
                # Stage 1 passes (file is under TRUSTED_ROOT)
                # Stage 2 fails (base is outside TRUSTED_ROOT)
                assert "Base path escapes trusted root" in str(exc_info.value)
        finally:
            shutil.rmtree("/tmp/untrusted", ignore_errors=True)

    @pytest.mark.asyncio
    async def test_scan_content_base_path_escapes_trusted_root(self):
        """Test scan_content raises ValueError when base_path escapes TRUSTED_ROOT."""
        # Create detector with base_path outside TRUSTED_ROOT (/var/fixops)
        config = SecretsScannerConfig(timeout_seconds=30, base_path="/tmp/untrusted")
        detector = SecretsDetector(config)
        try:
            with pytest.raises(ValueError) as exc_info:
                await detector.scan_content(
                    content="aws_secret_access_key = AKIAIOSFODNN7EXAMPLE",
                    filename="test.py",
                )
            assert "Base path escapes trusted root" in str(exc_info.value)
        finally:
            shutil.rmtree("/tmp/untrusted", ignore_errors=True)
