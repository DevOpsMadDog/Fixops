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
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from core.secrets_models import SecretType
from core.secrets_scanner import (
    SecretsDetector,
    SecretsScanner,
    SecretsScannerConfig,
    SecretsScanResult,
    SecretsScanStatus,
    get_secrets_detector,
)


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
        """Create a temporary directory for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

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
        assert result.exists()

    def test_validate_path_null_bytes(self, detector, temp_dir):
        """Test path validation rejects null bytes."""
        with pytest.raises(ValueError, match="contains null bytes"):
            detector._validate_path("test/file\x00.py")

    def test_validate_path_absolute_outside_base_rejected(self, detector, temp_dir):
        """Test path validation rejects absolute paths outside base directory."""
        # Absolute path outside base directory should be rejected
        with pytest.raises(ValueError, match="Path escapes base directory"):
            detector._validate_path("/absolute/path/file.py")

    def test_validate_path_absolute_inside_base_accepted(self, detector, temp_dir):
        """Test path validation accepts absolute paths inside base directory."""
        # Create a test file inside the base directory
        test_file = Path(temp_dir) / "test_absolute.py"
        test_file.write_text("API_KEY = 'secret'")

        # Absolute path inside base directory should be accepted
        result = detector._validate_path(str(test_file))
        assert result.exists()
        assert str(result) == str(test_file)

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
        assert "Path escapes base directory" in result.error_message

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
        """Create a temporary directory for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

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
        """Create a temporary directory for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

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
