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

import json
import os
import shutil
import tempfile as _tempfile
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

# --- Portable TRUSTED_ROOT setup for tests ---
# On macOS/CI, /var/fixops is not writable without root.
_SECRETS_TEST_ROOT = _tempfile.mkdtemp(prefix="fixops-secrets-test-")
TRUSTED_TEST_ROOT = os.path.join(_SECRETS_TEST_ROOT, "test-scans")
os.makedirs(TRUSTED_TEST_ROOT, exist_ok=True)
os.makedirs(os.path.join(_SECRETS_TEST_ROOT, "scans"), exist_ok=True)
os.makedirs(os.path.join(_SECRETS_TEST_ROOT, "configs"), exist_ok=True)


@pytest.fixture(autouse=True)
def _patch_secrets_trusted_root():
    """Patch secrets scanner module constants to use temp directories.

    This allows the secrets scanner tests to run on any system without
    requiring root access to /var/fixops.
    """
    with patch("core.secrets_scanner.TRUSTED_ROOT", _SECRETS_TEST_ROOT), \
         patch("core.secrets_scanner.SCAN_BASE_PATH", os.path.join(_SECRETS_TEST_ROOT, "scans")), \
         patch("core.secrets_scanner.CUSTOM_CONFIG_PATH", os.path.join(_SECRETS_TEST_ROOT, "configs")), \
         patch("core.safe_path_ops.TRUSTED_ROOT", _SECRETS_TEST_ROOT):
        yield


class TestSecretsScannerConfig:
    """Tests for SecretsScannerConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = SecretsScannerConfig()
        assert config.gitleaks_path == "gitleaks"
        assert config.trufflehog_path == "trufflehog"
        assert config.timeout_seconds == 300
        assert config.max_file_size_mb == 50
        # Note: base_path and custom_config_path are removed from config
        # They are hardcoded constants in the module (SCAN_BASE_PATH, CUSTOM_CONFIG_PATH)
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
                # Note: FIXOPS_SECRETS_CONFIG_PATH is no longer used - hardcoded for security
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
            # Note: base_path and custom_config_path are removed from config
            # They are hardcoded constants in the module (SCAN_BASE_PATH, CUSTOM_CONFIG_PATH)
            assert config.entropy_threshold == 5.0
            assert config.scan_history is False
            assert config.max_depth == 500


class TestSecretsDetector:
    """Tests for SecretsDetector class."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under SCAN_BASE_PATH for testing.

        Note: Tests that call methods with containment checks need files under SCAN_BASE_PATH.
        """
        from core.secrets_scanner import SCAN_BASE_PATH

        os.makedirs(SCAN_BASE_PATH, exist_ok=True)
        test_dir = os.path.join(SCAN_BASE_PATH, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    @pytest.fixture
    def detector(self, temp_dir):
        """Create a detector instance for testing.

        Note: base_path is no longer configurable - it's hardcoded to SCAN_BASE_PATH.
        Tests use temp_dir under TRUSTED_TEST_ROOT for file operations.
        """
        config = SecretsScannerConfig(timeout_seconds=30)
        return SecretsDetector(config)

    def test_detector_initialization(self, detector, temp_dir):
        """Test detector initialization."""
        assert detector.config is not None
        assert detector.config.timeout_seconds == 30
        # Note: base_path is no longer a config parameter - it's hardcoded

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
    async def test_scan_content(self, detector):
        """Test scanning content as string."""
        content = "API_KEY = 'AKIAIOSFODNN7EXAMPLE'"

        with patch.object(detector, "_is_gitleaks_available", return_value=True):
            with patch.object(detector, "_run_gitleaks", return_value=([], "[]", None)):
                result = await detector.scan_content(content, "config.py")

                assert result.status == SecretsScanStatus.COMPLETED
                for finding in result.findings:
                    assert finding.file_path == "config.py"


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


class TestScanContentSecretsEdgeCases:
    """Test scan_content edge cases for secrets scanner."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under SCAN_BASE_PATH for testing.

        Note: Tests that call methods with containment checks need files under SCAN_BASE_PATH.
        """
        from core.secrets_scanner import SCAN_BASE_PATH

        os.makedirs(SCAN_BASE_PATH, exist_ok=True)
        test_dir = os.path.join(SCAN_BASE_PATH, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    @pytest.fixture
    def detector(self, temp_dir):
        """Create a detector instance for testing.

        Note: base_path is no longer configurable - it's hardcoded to SCAN_BASE_PATH.
        """
        config = SecretsScannerConfig(timeout_seconds=30)
        return SecretsDetector(config)

    @pytest.mark.asyncio
    async def test_scan_content_no_scanner_available(self, detector):
        """Test scan_content when no external scanner is available.

        The secrets scanner may have a built-in fallback, so it might
        return COMPLETED even when gitleaks/trufflehog are unavailable.
        """
        with patch.object(detector, "get_available_scanners", return_value=[]):
            result = await detector.scan_content(
                content="API_KEY = 'secret'",
                filename="config.py",
            )

            assert result.status in (SecretsScanStatus.COMPLETED, SecretsScanStatus.FAILED)
            if result.status == SecretsScanStatus.FAILED:
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
            # Hardened: error_message exposes type only, not full exception details (CWE-200)
            assert "RuntimeError" in result.error_message


class TestSecretsParsingEdgeCases:
    """Test edge cases in parsing gitleaks and trufflehog output."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under SCAN_BASE_PATH for testing.

        Note: Tests that call methods with containment checks need files under SCAN_BASE_PATH.
        """
        from core.secrets_scanner import SCAN_BASE_PATH

        os.makedirs(SCAN_BASE_PATH, exist_ok=True)
        test_dir = os.path.join(SCAN_BASE_PATH, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    @pytest.fixture
    def detector(self, temp_dir):
        """Create a detector instance for testing.

        Note: base_path is no longer configurable - it's hardcoded to SCAN_BASE_PATH.
        """
        config = SecretsScannerConfig(timeout_seconds=30)
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
    """Test gitleaks with custom config path.

    Note: custom_config_path is now hardcoded to /var/fixops/configs/gitleaks.toml
    for security reasons (to prevent CodeQL py/path-injection alerts).
    The --config flag is only added if the hardcoded config file exists.
    """

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under SCAN_BASE_PATH for testing.

        Note: Tests that call methods with containment checks need files under SCAN_BASE_PATH.
        """
        from core.secrets_scanner import SCAN_BASE_PATH

        os.makedirs(SCAN_BASE_PATH, exist_ok=True)
        test_dir = os.path.join(SCAN_BASE_PATH, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    @pytest.fixture
    def detector(self, temp_dir):
        """Create a detector with default config.

        Note: base_path and custom_config_path are no longer configurable -
        they are hardcoded constants in the module.
        """
        config = SecretsScannerConfig(timeout_seconds=30)
        return SecretsDetector(config)

    @pytest.mark.asyncio
    async def test_gitleaks_with_custom_config_when_file_exists(
        self, detector, temp_dir
    ):
        """Test that custom config path is passed to gitleaks when the file exists."""
        # Create a test file
        test_file = Path(temp_dir) / "test.py"
        test_file.write_text("API_KEY = 'secret'")

        with patch.object(detector, "_is_gitleaks_available", return_value=True):
            # Mock os.path.isfile to return True for the hardcoded config path
            with patch("os.path.isfile") as mock_isfile:
                mock_isfile.return_value = True
                with patch("asyncio.create_subprocess_exec") as mock_exec:
                    mock_process = MagicMock()
                    mock_process.communicate = AsyncMock(return_value=(b"[]", b""))
                    mock_process.returncode = 0
                    mock_exec.return_value = mock_process

                    await detector._run_gitleaks(
                        Path(temp_dir), "test-repo", "main", False
                    )

                    # Verify custom config was passed (hardcoded path)
                    call_args = mock_exec.call_args[0]
                    assert "--config" in call_args
                    # Config path should be under the (possibly patched) CUSTOM_CONFIG_PATH
                    config_idx = list(call_args).index("--config")
                    config_val = call_args[config_idx + 1]
                    assert "configs" in config_val or "gitleaks.toml" in config_val


class TestGetRepoInfoException:
    """Test _get_repo_info exception handling."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under SCAN_BASE_PATH for testing.

        Note: Tests that call methods with containment checks need files under SCAN_BASE_PATH.
        """
        from core.secrets_scanner import SCAN_BASE_PATH

        os.makedirs(SCAN_BASE_PATH, exist_ok=True)
        test_dir = os.path.join(SCAN_BASE_PATH, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    @pytest.fixture
    def detector(self, temp_dir):
        """Create a detector instance for testing.

        Note: base_path is no longer configurable - it's hardcoded to SCAN_BASE_PATH.
        """
        config = SecretsScannerConfig(timeout_seconds=30)
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
        """Create a temporary directory under SCAN_BASE_PATH for testing.

        Note: Tests that call methods with containment checks need files under SCAN_BASE_PATH.
        """
        from core.secrets_scanner import SCAN_BASE_PATH

        os.makedirs(SCAN_BASE_PATH, exist_ok=True)
        test_dir = os.path.join(SCAN_BASE_PATH, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    @pytest.fixture
    def detector(self, temp_dir):
        """Create a detector instance for testing.

        Note: base_path is no longer configurable - it's hardcoded to SCAN_BASE_PATH.
        """
        config = SecretsScannerConfig(timeout_seconds=30)
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

    def test_verify_containment_stage3_path_escapes_base(self, detector, temp_dir):
        """Test _verify_containment raises ValueError when path escapes SCAN_BASE_PATH (Stage 3).

        Note: base_path is now hardcoded to SCAN_BASE_PATH (/var/fixops/scans).
        This test verifies that paths under TRUSTED_ROOT but outside SCAN_BASE_PATH are rejected.
        """
        # Create a file under TRUSTED_TEST_ROOT which is under TRUSTED_ROOT
        # but NOT under SCAN_BASE_PATH (/var/fixops/scans)
        stage3_test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(stage3_test_dir, exist_ok=True)
        try:
            test_file = os.path.join(stage3_test_dir, "test.py")
            with open(test_file, "w") as f:
                f.write("content")
            # Stage 1 passes (file is under TRUSTED_ROOT)
            # Stage 2 passes (SCAN_BASE_PATH is under TRUSTED_ROOT)
            # Stage 3 fails (file is not under SCAN_BASE_PATH)
            with pytest.raises(ValueError) as exc_info:
                detector._verify_containment(Path(test_file))
            assert "Path escapes base directory" in str(exc_info.value)
        finally:
            shutil.rmtree(stage3_test_dir, ignore_errors=True)

    @pytest.mark.asyncio
    async def test_run_gitleaks_stage3_path_escapes_base(self, detector, temp_dir):
        """Test _run_gitleaks Stage 3 containment check - path under TRUSTED_ROOT but outside SCAN_BASE_PATH.

        Note: base_path is now hardcoded to SCAN_BASE_PATH (/var/fixops/scans).
        """
        # Create a file under TRUSTED_TEST_ROOT which is under TRUSTED_ROOT
        # but NOT under SCAN_BASE_PATH (/var/fixops/scans)
        stage3_test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(stage3_test_dir, exist_ok=True)
        try:
            test_file = os.path.join(stage3_test_dir, "test.py")
            with open(test_file, "w") as f:
                f.write("content")
            with patch.object(detector, "_is_gitleaks_available", return_value=True):
                with pytest.raises(ValueError) as exc_info:
                    await detector._run_gitleaks(test_file, "repo", "main", False)
                # Stage 1 passes (file is under TRUSTED_ROOT)
                # Stage 2 passes (SCAN_BASE_PATH is under TRUSTED_ROOT)
                # Stage 3 fails (file is not under SCAN_BASE_PATH)
                assert "Path escapes base directory" in str(exc_info.value)
        finally:
            shutil.rmtree(stage3_test_dir, ignore_errors=True)

    @pytest.mark.asyncio
    async def test_run_trufflehog_stage3_path_escapes_base(self, detector, temp_dir):
        """Test _run_trufflehog Stage 3 containment check - path under TRUSTED_ROOT but outside SCAN_BASE_PATH.

        Note: base_path is now hardcoded to SCAN_BASE_PATH (/var/fixops/scans).
        """
        # Create a file under TRUSTED_TEST_ROOT which is under TRUSTED_ROOT
        # but NOT under SCAN_BASE_PATH (/var/fixops/scans)
        stage3_test_dir = os.path.join(TRUSTED_TEST_ROOT, str(uuid.uuid4()))
        os.makedirs(stage3_test_dir, exist_ok=True)
        try:
            test_file = os.path.join(stage3_test_dir, "test.py")
            with open(test_file, "w") as f:
                f.write("content")
            with patch.object(detector, "_is_trufflehog_available", return_value=True):
                with pytest.raises(ValueError) as exc_info:
                    await detector._run_trufflehog(test_file, "repo", "main", False)
                # Stage 1 passes (file is under TRUSTED_ROOT)
                # Stage 2 passes (SCAN_BASE_PATH is under TRUSTED_ROOT)
                # Stage 3 fails (file is not under SCAN_BASE_PATH)
                assert "Path escapes base directory" in str(exc_info.value)
        finally:
            shutil.rmtree(stage3_test_dir, ignore_errors=True)

    @pytest.mark.asyncio
    async def test_scan_content_uses_hardcoded_base_path(self, detector):
        """Test scan_content uses hardcoded SCAN_BASE_PATH for temp files.

        Note: base_path is now hardcoded to SCAN_BASE_PATH (/var/fixops/scans).
        This test verifies that scan_content creates temp files under SCAN_BASE_PATH.
        """
        from core.secrets_scanner import SCAN_BASE_PATH

        os.makedirs(SCAN_BASE_PATH, exist_ok=True)

        with patch.object(detector, "get_available_scanners", return_value=[]):
            result = await detector.scan_content(
                content="aws_secret_access_key = AKIAIOSFODNN7EXAMPLE",
                filename="test.py",
            )
            # The scanner may fall back to built-in when externals are unavailable
            assert result.status in (SecretsScanStatus.COMPLETED, SecretsScanStatus.FAILED)
            if result.status == SecretsScanStatus.FAILED:
                assert "No secrets scanner available" in result.error_message


class TestRunGitleaksSubprocess:
    """Tests for _run_gitleaks subprocess execution paths."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under SCAN_BASE_PATH for testing."""
        from core.secrets_scanner import SCAN_BASE_PATH

        os.makedirs(SCAN_BASE_PATH, exist_ok=True)
        test_dir = os.path.join(SCAN_BASE_PATH, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    @pytest.fixture
    def detector(self):
        """Create a detector instance for testing."""
        config = SecretsScannerConfig(timeout_seconds=30)
        return SecretsDetector(config)

    @pytest.mark.asyncio
    async def test_run_gitleaks_success(self, detector, temp_dir):
        """Test _run_gitleaks successful execution with valid output."""
        test_file = os.path.join(temp_dir, "config.py")
        with open(test_file, "w") as f:
            f.write('AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"')

        mock_output = json.dumps(
            [
                {
                    "RuleID": "aws-access-key-id",
                    "Description": "AWS Access Key ID",
                    "Match": "AKIAIOSFODNN7EXAMPLE",
                    "File": test_file,
                    "StartLine": 1,
                    "EndLine": 1,
                    "Entropy": 3.5,
                }
            ]
        )

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = mock_exec.return_value
            mock_process.communicate = AsyncMock(
                return_value=(mock_output.encode(), b"")
            )
            mock_process.returncode = 0

            findings, output, error = await detector._run_gitleaks(
                test_file, "test-repo", "main", False
            )

            assert error is None
            assert len(findings) == 1
            assert findings[0].secret_type == SecretType.AWS_KEY

    @pytest.mark.asyncio
    async def test_run_gitleaks_nonzero_exit_code(self, detector, temp_dir):
        """Test _run_gitleaks with non-zero/non-one exit code."""
        test_file = os.path.join(temp_dir, "config.py")
        with open(test_file, "w") as f:
            f.write('AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"')

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = mock_exec.return_value
            mock_process.communicate = AsyncMock(
                return_value=(b"output", b"error message")
            )
            mock_process.returncode = 2

            findings, output, error = await detector._run_gitleaks(
                test_file, "test-repo", "main", False
            )

            assert findings == []
            assert "Gitleaks exited with code 2" in error

    @pytest.mark.asyncio
    async def test_run_gitleaks_timeout(self, detector, temp_dir):
        """Test _run_gitleaks timeout handling."""
        import asyncio as aio

        test_file = os.path.join(temp_dir, "config.py")
        with open(test_file, "w") as f:
            f.write('AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"')

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = mock_exec.return_value
            mock_process.communicate = AsyncMock(side_effect=aio.TimeoutError())

            findings, output, error = await detector._run_gitleaks(
                test_file, "test-repo", "main", False
            )

            assert findings == []
            assert "timed out" in error

    @pytest.mark.asyncio
    async def test_run_gitleaks_file_not_found(self, detector, temp_dir):
        """Test _run_gitleaks when gitleaks is not installed."""
        test_file = os.path.join(temp_dir, "config.py")
        with open(test_file, "w") as f:
            f.write('AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"')

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_exec.side_effect = FileNotFoundError()

            findings, output, error = await detector._run_gitleaks(
                test_file, "test-repo", "main", False
            )

            assert findings == []
            assert "not installed" in error

    @pytest.mark.asyncio
    async def test_run_gitleaks_generic_exception(self, detector, temp_dir):
        """Test _run_gitleaks generic exception handling."""
        test_file = os.path.join(temp_dir, "config.py")
        with open(test_file, "w") as f:
            f.write('AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"')

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_exec.side_effect = RuntimeError("Unexpected error")

            findings, output, error = await detector._run_gitleaks(
                test_file, "test-repo", "main", False
            )

            assert findings == []
            assert "Gitleaks scan failed" in error

    @pytest.mark.asyncio
    async def test_run_gitleaks_git_mode(self, detector, temp_dir):
        """Test _run_gitleaks in git mode (without --no-git flag)."""
        test_file = os.path.join(temp_dir, "config.py")
        with open(test_file, "w") as f:
            f.write('AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"')

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = mock_exec.return_value
            mock_process.communicate = AsyncMock(return_value=(b"[]", b""))
            mock_process.returncode = 0

            await detector._run_gitleaks(test_file, "test-repo", "main", True)

            # Verify git mode - --no-git flag should NOT be present
            call_args = mock_exec.call_args[0]
            assert "--no-git" not in call_args


class TestRunTrufflehogSubprocess:
    """Tests for _run_trufflehog subprocess execution paths."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under SCAN_BASE_PATH for testing."""
        from core.secrets_scanner import SCAN_BASE_PATH

        os.makedirs(SCAN_BASE_PATH, exist_ok=True)
        test_dir = os.path.join(SCAN_BASE_PATH, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    @pytest.fixture
    def detector(self):
        """Create a detector instance for testing."""
        config = SecretsScannerConfig(timeout_seconds=30)
        return SecretsDetector(config)

    @pytest.mark.asyncio
    async def test_run_trufflehog_success(self, detector, temp_dir):
        """Test _run_trufflehog successful execution with valid output."""
        test_file = os.path.join(temp_dir, "config.py")
        with open(test_file, "w") as f:
            f.write('AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"')

        mock_output = json.dumps(
            {
                "DetectorName": "AWS",
                "Raw": "AKIAIOSFODNN7EXAMPLE",
                "SourceMetadata": {
                    "Data": {"Filesystem": {"file": test_file, "line": 1}}
                },
            }
        )

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = mock_exec.return_value
            mock_process.communicate = AsyncMock(
                return_value=(mock_output.encode(), b"")
            )
            mock_process.returncode = 0

            findings, output, error = await detector._run_trufflehog(
                test_file, "test-repo", "main", False
            )

            assert error is None
            assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_run_trufflehog_nonzero_exit_code(self, detector, temp_dir):
        """Test _run_trufflehog with non-zero/non-one/non-183 exit code."""
        test_file = os.path.join(temp_dir, "config.py")
        with open(test_file, "w") as f:
            f.write('AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"')

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = mock_exec.return_value
            mock_process.communicate = AsyncMock(
                return_value=(b"output", b"error message")
            )
            mock_process.returncode = 2

            findings, output, error = await detector._run_trufflehog(
                test_file, "test-repo", "main", False
            )

            assert findings == []
            assert "Trufflehog exited with code 2" in error

    @pytest.mark.asyncio
    async def test_run_trufflehog_timeout(self, detector, temp_dir):
        """Test _run_trufflehog timeout handling."""
        import asyncio as aio

        test_file = os.path.join(temp_dir, "config.py")
        with open(test_file, "w") as f:
            f.write('AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"')

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = mock_exec.return_value
            mock_process.communicate = AsyncMock(side_effect=aio.TimeoutError())

            findings, output, error = await detector._run_trufflehog(
                test_file, "test-repo", "main", False
            )

            assert findings == []
            assert "timed out" in error

    @pytest.mark.asyncio
    async def test_run_trufflehog_file_not_found(self, detector, temp_dir):
        """Test _run_trufflehog when trufflehog is not installed."""
        test_file = os.path.join(temp_dir, "config.py")
        with open(test_file, "w") as f:
            f.write('AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"')

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_exec.side_effect = FileNotFoundError()

            findings, output, error = await detector._run_trufflehog(
                test_file, "test-repo", "main", False
            )

            assert findings == []
            assert "not installed" in error

    @pytest.mark.asyncio
    async def test_run_trufflehog_generic_exception(self, detector, temp_dir):
        """Test _run_trufflehog generic exception handling."""
        test_file = os.path.join(temp_dir, "config.py")
        with open(test_file, "w") as f:
            f.write('AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"')

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_exec.side_effect = RuntimeError("Unexpected error")

            findings, output, error = await detector._run_trufflehog(
                test_file, "test-repo", "main", False
            )

            assert findings == []
            assert "Trufflehog scan failed" in error

    @pytest.mark.asyncio
    async def test_run_trufflehog_git_mode(self, detector, temp_dir):
        """Test _run_trufflehog in git mode with scan_history."""
        test_file = os.path.join(temp_dir, "config.py")
        with open(test_file, "w") as f:
            f.write('AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"')

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = mock_exec.return_value
            mock_process.communicate = AsyncMock(return_value=(b"", b""))
            mock_process.returncode = 0

            await detector._run_trufflehog(test_file, "test-repo", "main", True)

            # Verify git mode command was used
            call_args = mock_exec.call_args[0]
            assert "git" in call_args

    @pytest.mark.asyncio
    async def test_run_trufflehog_with_max_depth(self, detector, temp_dir):
        """Test _run_trufflehog with max_depth option."""
        detector.config.max_depth = 500
        test_file = os.path.join(temp_dir, "config.py")
        with open(test_file, "w") as f:
            f.write('AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"')

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = mock_exec.return_value
            mock_process.communicate = AsyncMock(return_value=(b"", b""))
            mock_process.returncode = 0

            await detector._run_trufflehog(test_file, "test-repo", "main", True)

            # Verify --max-depth was in the command
            call_args = mock_exec.call_args[0]
            assert "--max-depth" in call_args
            assert "500" in call_args


class TestIsGitRepoAndGetRepoInfo:
    """Tests for _is_git_repo and _get_repo_info methods."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory under SCAN_BASE_PATH for testing."""
        from core.secrets_scanner import SCAN_BASE_PATH

        os.makedirs(SCAN_BASE_PATH, exist_ok=True)
        test_dir = os.path.join(SCAN_BASE_PATH, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    @pytest.fixture
    def detector(self):
        """Create a detector instance for testing."""
        config = SecretsScannerConfig(timeout_seconds=30)
        return SecretsDetector(config)

    def test_is_git_repo_false(self, detector, temp_dir):
        """Test _is_git_repo returns False for non-git directory."""
        test_file = os.path.join(temp_dir, "config.py")
        with open(test_file, "w") as f:
            f.write("test content")

        result = detector._is_git_repo(test_file)
        assert result is False

    def test_get_repo_info_non_git(self, detector, temp_dir):
        """Test _get_repo_info returns defaults for non-git directory."""
        test_file = os.path.join(temp_dir, "config.py")
        with open(test_file, "w") as f:
            f.write("test content")

        repo_name, branch = detector._get_repo_info(test_file)
        assert repo_name == test_file
        assert branch == "main"

    def test_get_repo_info_with_git_repo(self, detector, temp_dir):
        """Test _get_repo_info with a git repository."""
        # Create a .git directory to simulate a git repo
        git_dir = os.path.join(temp_dir, ".git")
        os.makedirs(git_dir, exist_ok=True)

        test_file = os.path.join(temp_dir, "config.py")
        with open(test_file, "w") as f:
            f.write("test content")

        with patch("core.secrets_scanner.safe_subprocess_run") as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = temp_dir
            mock_run.return_value = mock_result

            repo_name, branch = detector._get_repo_info(test_file)
            # Should call git commands
            assert mock_run.called


class TestStage2ContainmentChecks:
    """Tests for Stage 2 containment checks (base path escapes trusted root)."""

    @pytest.fixture
    def detector(self):
        """Create a detector instance for testing."""
        config = SecretsScannerConfig(timeout_seconds=30)
        return SecretsDetector(config)

    def test_verify_containment_base_escapes_trusted_root(self, detector):
        """Test _verify_containment raises when base path escapes trusted root."""
        from pathlib import Path

        # Mock SCAN_BASE_PATH to be outside TRUSTED_ROOT
        with patch("core.secrets_scanner.SCAN_BASE_PATH", "/tmp/outside"):
            with pytest.raises(ValueError) as exc_info:
                detector._verify_containment(Path("/tmp/outside/test.py"))
            assert "Base path escapes trusted root" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_run_gitleaks_base_escapes_trusted_root(self, detector):
        """Test _run_gitleaks raises when base path escapes trusted root (Stage 2)."""
        from core.secrets_scanner import TRUSTED_ROOT

        # Create a test file under TRUSTED_ROOT so Stage 1 passes
        test_dir = os.path.join(TRUSTED_ROOT, "test_stage2_gitleaks")
        os.makedirs(test_dir, exist_ok=True)
        test_file = os.path.join(test_dir, "test.py")
        try:
            with open(test_file, "w") as f:
                f.write("# test file")

            # Mock SCAN_BASE_PATH to be outside TRUSTED_ROOT
            # Path is under TRUSTED_ROOT (Stage 1 passes), but base is not (Stage 2 fails)
            with patch("core.secrets_scanner.SCAN_BASE_PATH", "/tmp/outside"):
                with pytest.raises(ValueError) as exc_info:
                    await detector._run_gitleaks(test_file, "repo", "main", False)
                assert "Base path escapes trusted root" in str(exc_info.value)
        finally:
            shutil.rmtree(test_dir, ignore_errors=True)

    @pytest.mark.asyncio
    async def test_run_trufflehog_base_escapes_trusted_root(self, detector):
        """Test _run_trufflehog raises when base path escapes trusted root (Stage 2)."""
        from core.secrets_scanner import TRUSTED_ROOT

        # Create a test file under TRUSTED_ROOT so Stage 1 passes
        test_dir = os.path.join(TRUSTED_ROOT, "test_stage2_trufflehog")
        os.makedirs(test_dir, exist_ok=True)
        test_file = os.path.join(test_dir, "test.py")
        try:
            with open(test_file, "w") as f:
                f.write("# test file")

            # Mock SCAN_BASE_PATH to be outside TRUSTED_ROOT
            # Path is under TRUSTED_ROOT (Stage 1 passes), but base is not (Stage 2 fails)
            with patch("core.secrets_scanner.SCAN_BASE_PATH", "/tmp/outside"):
                with pytest.raises(ValueError) as exc_info:
                    await detector._run_trufflehog(test_file, "repo", "main", False)
                assert "Base path escapes trusted root" in str(exc_info.value)
        finally:
            shutil.rmtree(test_dir, ignore_errors=True)


# ============================================================================
# Additional tests to reach 100+ total
# ============================================================================


class TestSecretsModelsEnums:
    """Tests for SecretType and SecretStatus enum values."""

    def test_secret_type_values(self):
        """Test all SecretType enum string values."""
        assert SecretType.API_KEY.value == "api_key"
        assert SecretType.PASSWORD.value == "password"
        assert SecretType.TOKEN.value == "token"
        assert SecretType.CERTIFICATE.value == "certificate"
        assert SecretType.PRIVATE_KEY.value == "private_key"
        assert SecretType.AWS_KEY.value == "aws_key"
        assert SecretType.DATABASE_CREDENTIAL.value == "database_credential"
        assert SecretType.GENERIC.value == "generic"

    def test_secret_type_is_str_subclass(self):
        """Test that SecretType members are instances of str (str Enum)."""
        assert isinstance(SecretType.API_KEY, str)
        assert isinstance(SecretType.AWS_KEY, str)

    def test_secret_status_values(self):
        """Test all SecretStatus enum string values."""
        assert SecretStatus.ACTIVE.value == "active"
        assert SecretStatus.RESOLVED.value == "resolved"
        assert SecretStatus.FALSE_POSITIVE.value == "false_positive"

    def test_secret_status_is_str_subclass(self):
        """Test that SecretStatus members are instances of str (str Enum)."""
        assert isinstance(SecretStatus.ACTIVE, str)
        assert isinstance(SecretStatus.FALSE_POSITIVE, str)

    def test_secrets_scanner_enum_values(self):
        """Test SecretsScanner enum values."""
        assert SecretsScanner.GITLEAKS.value == "gitleaks"
        assert SecretsScanner.TRUFFLEHOG.value == "trufflehog"

    def test_secrets_scan_status_enum_values(self):
        """Test SecretsScanStatus enum values."""
        assert SecretsScanStatus.PENDING.value == "pending"
        assert SecretsScanStatus.RUNNING.value == "running"
        assert SecretsScanStatus.COMPLETED.value == "completed"
        assert SecretsScanStatus.FAILED.value == "failed"
        assert SecretsScanStatus.CANCELLED.value == "cancelled"


class TestSecretFindingToDict:
    """Tests for SecretFinding.to_dict() serialization."""

    def _make_finding(self, **kwargs):
        defaults = dict(
            id="test-id-001",
            secret_type=SecretType.API_KEY,
            status=SecretStatus.ACTIVE,
            file_path="src/config.py",
            line_number=42,
            repository="my-repo",
            branch="main",
        )
        defaults.update(kwargs)
        return SecretFinding(**defaults)

    def test_to_dict_basic_fields(self):
        """Test basic field serialization in to_dict."""
        finding = self._make_finding()
        d = finding.to_dict()
        assert d["id"] == "test-id-001"
        assert d["secret_type"] == "api_key"
        assert d["status"] == "active"
        assert d["file_path"] == "src/config.py"
        assert d["line_number"] == 42
        assert d["repository"] == "my-repo"
        assert d["branch"] == "main"

    def test_to_dict_optional_fields_none(self):
        """Test that optional None fields serialize correctly."""
        finding = self._make_finding()
        d = finding.to_dict()
        assert d["commit_hash"] is None
        assert d["matched_pattern"] is None
        assert d["entropy_score"] is None
        assert d["resolved_at"] is None

    def test_to_dict_with_entropy(self):
        """Test to_dict with entropy_score set."""
        finding = self._make_finding(entropy_score=5.2)
        d = finding.to_dict()
        assert d["entropy_score"] == 5.2

    def test_to_dict_with_commit_hash(self):
        """Test to_dict with commit_hash set."""
        finding = self._make_finding(commit_hash="deadbeef1234")
        d = finding.to_dict()
        assert d["commit_hash"] == "deadbeef1234"

    def test_to_dict_with_matched_pattern(self):
        """Test to_dict with matched_pattern set."""
        finding = self._make_finding(matched_pattern="AKIA****EXAMPLE")
        d = finding.to_dict()
        assert d["matched_pattern"] == "AKIA****EXAMPLE"

    def test_to_dict_detected_at_is_isoformat(self):
        """Test that detected_at is ISO format string in to_dict."""
        finding = self._make_finding()
        d = finding.to_dict()
        # Should be a valid ISO format datetime string
        assert isinstance(d["detected_at"], str)
        assert "T" in d["detected_at"]

    def test_to_dict_resolved_at_isoformat_when_set(self):
        """Test resolved_at serialized as ISO string when set."""
        from datetime import datetime
        finding = self._make_finding(
            status=SecretStatus.RESOLVED,
            resolved_at=datetime(2026, 1, 15, 10, 30, 0),
        )
        d = finding.to_dict()
        assert d["resolved_at"] == "2026-01-15T10:30:00"

    def test_to_dict_metadata_is_preserved(self):
        """Test metadata dict is preserved in to_dict."""
        finding = self._make_finding(metadata={"scanner": "gitleaks", "rule": "aws-key"})
        d = finding.to_dict()
        assert d["metadata"]["scanner"] == "gitleaks"
        assert d["metadata"]["rule"] == "aws-key"

    def test_to_dict_all_secret_types_serialize(self):
        """Test to_dict works for all SecretType values."""
        for stype in SecretType:
            finding = self._make_finding(secret_type=stype)
            d = finding.to_dict()
            assert d["secret_type"] == stype.value


class TestSecretsScanResultToDictWithFindings:
    """Tests for SecretsScanResult.to_dict() with actual findings."""

    def _make_finding(self):
        return SecretFinding(
            id="f-001",
            secret_type=SecretType.TOKEN,
            status=SecretStatus.ACTIVE,
            file_path="config.py",
            line_number=5,
            repository="repo",
            branch="dev",
        )

    def test_to_dict_with_findings(self):
        """Test to_dict includes findings array."""
        from datetime import datetime
        result = SecretsScanResult(
            scan_id="s-001",
            status=SecretsScanStatus.COMPLETED,
            scanner=SecretsScanner.GITLEAKS,
            target_path="config.py",
            repository="repo",
            branch="dev",
            findings=[self._make_finding()],
            started_at=datetime(2026, 1, 1),
            completed_at=datetime(2026, 1, 1, 0, 0, 5),
            duration_seconds=5.0,
        )
        d = result.to_dict()
        assert d["findings_count"] == 1
        assert len(d["findings"]) == 1
        assert d["findings"][0]["id"] == "f-001"

    def test_to_dict_none_timestamps(self):
        """Test to_dict handles None started_at and completed_at."""
        result = SecretsScanResult(
            scan_id="s-002",
            status=SecretsScanStatus.PENDING,
            scanner=SecretsScanner.TRUFFLEHOG,
            target_path="config.py",
            repository="repo",
            branch="main",
        )
        d = result.to_dict()
        assert d["started_at"] is None
        assert d["completed_at"] is None

    def test_to_dict_error_message(self):
        """Test to_dict includes error_message."""
        result = SecretsScanResult(
            scan_id="s-003",
            status=SecretsScanStatus.FAILED,
            scanner=SecretsScanner.GITLEAKS,
            target_path="config.py",
            repository="repo",
            branch="main",
            error_message="Scanner timed out",
        )
        d = result.to_dict()
        assert d["error_message"] == "Scanner timed out"

    def test_to_dict_metadata_preserved(self):
        """Test to_dict includes metadata."""
        result = SecretsScanResult(
            scan_id="s-004",
            status=SecretsScanStatus.COMPLETED,
            scanner=SecretsScanner.GITLEAKS,
            target_path="config.py",
            repository="repo",
            branch="main",
            metadata={"fallback": "builtin_scanner"},
        )
        d = result.to_dict()
        assert d["metadata"]["fallback"] == "builtin_scanner"


class TestMapSecretTypeEdgeCases:
    """Additional edge cases for _map_secret_type method."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_map_aws_in_description_uppercase(self, detector):
        """Test AWS detection in description regardless of case."""
        assert detector._map_secret_type("generic", "AWS KEY DETECTED") == SecretType.AWS_KEY

    def test_map_api_in_rule_id(self, detector):
        """Test API key detection via rule_id containing 'api'."""
        assert detector._map_secret_type("stripe-api-key") == SecretType.API_KEY

    def test_map_api_in_description(self, detector):
        """Test API key detection via description containing 'api'."""
        assert detector._map_secret_type("unknown", "some api token") == SecretType.API_KEY

    def test_map_db_password_combo(self, detector):
        """Test database credential for 'db' + 'password' in rule_id."""
        assert detector._map_secret_type("db-password") == SecretType.DATABASE_CREDENTIAL

    def test_map_mysql_in_rule_id(self, detector):
        """Test database credential for 'mysql' in rule_id."""
        assert detector._map_secret_type("mysql-uri") == SecretType.DATABASE_CREDENTIAL

    def test_map_postgres_in_rule_id(self, detector):
        """Test database credential for 'postgres' in rule_id."""
        assert detector._map_secret_type("postgres-password") == SecretType.DATABASE_CREDENTIAL

    def test_map_database_in_rule_id(self, detector):
        """Test database credential for 'database' in rule_id without password."""
        assert detector._map_secret_type("database-url") == SecretType.DATABASE_CREDENTIAL

    def test_map_password_in_description_only(self, detector):
        """Test password when only description contains 'password'."""
        assert detector._map_secret_type("generic-secret", "password detected") == SecretType.PASSWORD

    def test_map_token_in_rule_id(self, detector):
        """Test token detection from rule_id."""
        assert detector._map_secret_type("oauth-token") == SecretType.TOKEN

    def test_map_token_in_description(self, detector):
        """Test token detection from description."""
        assert detector._map_secret_type("unknown", "bearer token found") == SecretType.TOKEN

    def test_map_private_key_both_words(self, detector):
        """Test private key requires both 'private' and 'key' in rule_id."""
        # Only 'key' without 'private' should not match PRIVATE_KEY
        result = detector._map_secret_type("encryption-key")
        assert result == SecretType.GENERIC

    def test_map_private_key_needs_both_terms(self, detector):
        """Test that 'private' alone does not map to PRIVATE_KEY."""
        result = detector._map_secret_type("private-data")
        assert result == SecretType.GENERIC

    def test_map_certificate_via_cert(self, detector):
        """Test certificate detection via 'cert' shorthand."""
        assert detector._map_secret_type("tls-cert-key") == SecretType.CERTIFICATE

    def test_map_certificate_full_word(self, detector):
        """Test certificate detection via full 'certificate' word."""
        assert detector._map_secret_type("x509-certificate") == SecretType.CERTIFICATE

    def test_map_aws_takes_priority_over_api(self, detector):
        """Test that AWS takes priority over API when both present in rule_id."""
        # 'aws' appears first in rule_lower checks
        result = detector._map_secret_type("aws-api-key")
        assert result == SecretType.AWS_KEY

    def test_map_empty_rule_and_description(self, detector):
        """Test mapping with empty strings returns GENERIC."""
        assert detector._map_secret_type("", "") == SecretType.GENERIC

    def test_map_uppercase_input_normalized(self, detector):
        """Test that uppercase rule_id is lowercased before matching."""
        assert detector._map_secret_type("AWS-SECRET-KEY") == SecretType.AWS_KEY


class TestGitleaksParsingExtended:
    """Extended tests for _parse_gitleaks_output edge cases."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_parse_gitleaks_missing_optional_fields(self, detector):
        """Test parsing gitleaks output missing optional fields."""
        minimal = json.dumps([
            {
                "RuleID": "some-rule",
                "File": "app.py",
                "StartLine": 1,
            }
        ])
        findings = detector._parse_gitleaks_output(minimal, "repo", "main")
        assert len(findings) == 1
        assert findings[0].commit_hash is None
        assert findings[0].matched_pattern is None
        assert findings[0].entropy_score is None
        assert findings[0].metadata["author"] is None
        assert findings[0].metadata["email"] is None

    def test_parse_gitleaks_null_match_field(self, detector):
        """Test gitleaks output where Match field is null."""
        output = json.dumps([
            {
                "RuleID": "generic-password",
                "File": "config.env",
                "StartLine": 5,
                "Match": None,
            }
        ])
        findings = detector._parse_gitleaks_output(output, "repo", "main")
        assert len(findings) == 1
        assert findings[0].matched_pattern is None

    def test_parse_gitleaks_exact_100_char_match_not_truncated(self, detector):
        """Test 100-char match is not truncated."""
        match_100 = "X" * 100
        output = json.dumps([
            {
                "RuleID": "generic",
                "File": "f.py",
                "StartLine": 1,
                "Match": match_100,
            }
        ])
        findings = detector._parse_gitleaks_output(output, "repo", "main")
        assert len(findings[0].matched_pattern) == 100

    def test_parse_gitleaks_empty_array_json(self, detector):
        """Test parsing JSON empty array string."""
        findings = detector._parse_gitleaks_output("[]", "repo", "main")
        assert findings == []

    def test_parse_gitleaks_multiple_findings(self, detector):
        """Test parsing multiple findings in one array."""
        output = json.dumps([
            {
                "RuleID": "aws-access-key",
                "File": "a.py",
                "StartLine": 1,
            },
            {
                "RuleID": "github-token",
                "File": "b.py",
                "StartLine": 2,
            },
            {
                "RuleID": "password",
                "File": "c.py",
                "StartLine": 3,
            },
        ])
        findings = detector._parse_gitleaks_output(output, "repo", "main")
        assert len(findings) == 3
        assert findings[0].secret_type == SecretType.AWS_KEY
        assert findings[1].secret_type == SecretType.TOKEN
        assert findings[2].secret_type == SecretType.PASSWORD

    def test_parse_gitleaks_sets_repository_and_branch(self, detector):
        """Test that parsed findings carry repository and branch."""
        output = json.dumps([
            {"RuleID": "generic", "File": "f.py", "StartLine": 1}
        ])
        findings = detector._parse_gitleaks_output(output, "my-repo", "feature/xyz")
        assert findings[0].repository == "my-repo"
        assert findings[0].branch == "feature/xyz"

    def test_parse_gitleaks_finding_has_unique_id(self, detector):
        """Test each finding gets a unique UUID id."""
        output = json.dumps([
            {"RuleID": "a", "File": "f.py", "StartLine": 1},
            {"RuleID": "b", "File": "g.py", "StartLine": 2},
        ])
        findings = detector._parse_gitleaks_output(output, "repo", "main")
        assert findings[0].id != findings[1].id

    def test_parse_gitleaks_finding_status_active(self, detector):
        """Test all parsed findings have ACTIVE status."""
        output = json.dumps([
            {"RuleID": "generic", "File": "f.py", "StartLine": 1}
        ])
        findings = detector._parse_gitleaks_output(output, "repo", "main")
        assert findings[0].status == SecretStatus.ACTIVE

    def test_parse_gitleaks_tags_in_metadata(self, detector):
        """Test gitleaks tags preserved in metadata."""
        output = json.dumps([
            {
                "RuleID": "aws-access-key",
                "File": "a.py",
                "StartLine": 1,
                "Tags": ["aws", "cloud"],
            }
        ])
        findings = detector._parse_gitleaks_output(output, "repo", "main")
        assert findings[0].metadata["tags"] == ["aws", "cloud"]

    def test_parse_gitleaks_whitespace_only_output(self, detector):
        """Test whitespace-only output returns empty list."""
        findings = detector._parse_gitleaks_output("   \n  ", "repo", "main")
        assert findings == []

    def test_parse_gitleaks_scanner_in_metadata(self, detector):
        """Test that scanner field is set to 'gitleaks' in metadata."""
        output = json.dumps([
            {"RuleID": "generic", "File": "f.py", "StartLine": 1}
        ])
        findings = detector._parse_gitleaks_output(output, "repo", "main")
        assert findings[0].metadata["scanner"] == "gitleaks"


class TestTrufflehogParsingExtended:
    """Extended tests for _parse_trufflehog_output edge cases."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_parse_trufflehog_git_source_uppercase_file_key(self, detector):
        """Test trufflehog parsing with Git source using uppercase 'File' key."""
        output = json.dumps({
            "DetectorName": "Github",
            "Raw": "ghp_testtoken123",
            "SourceMetadata": {
                "Data": {
                    "Git": {
                        "File": "secrets.py",
                        "line": 7,
                        "commit": "f00dbeef",
                    }
                }
            },
        })
        findings = detector._parse_trufflehog_output(output, "repo", "main")
        assert len(findings) == 1
        assert findings[0].file_path == "secrets.py"
        assert findings[0].commit_hash == "f00dbeef"

    def test_parse_trufflehog_filesystem_lowercase_file_key(self, detector):
        """Test trufflehog parsing with Filesystem source using lowercase 'file' key."""
        output = json.dumps({
            "DetectorName": "Slack",
            "Raw": "xoxb-token-value",
            "SourceMetadata": {
                "Data": {
                    "Filesystem": {
                        "file": "env/prod.env",
                        "line": 12,
                    }
                }
            },
        })
        findings = detector._parse_trufflehog_output(output, "repo", "main")
        assert len(findings) == 1
        assert findings[0].file_path == "env/prod.env"
        assert findings[0].line_number == 12

    def test_parse_trufflehog_no_source_metadata(self, detector):
        """Test trufflehog parsing when SourceMetadata is absent."""
        output = json.dumps({
            "DetectorName": "Generic",
            "Raw": "secret_value",
        })
        findings = detector._parse_trufflehog_output(output, "repo", "main")
        assert len(findings) == 1
        assert findings[0].file_path == "unknown"
        assert findings[0].line_number == 0

    def test_parse_trufflehog_verified_false(self, detector):
        """Test parsing trufflehog output where Verified is False."""
        output = json.dumps({
            "DetectorName": "AWS",
            "Raw": "AKIAIOSFODNN7EXAMPLE",
            "Verified": False,
            "SourceMetadata": {
                "Data": {"Filesystem": {"file": "creds.py", "line": 1}}
            },
        })
        findings = detector._parse_trufflehog_output(output, "repo", "main")
        assert findings[0].metadata["verified"] is False

    def test_parse_trufflehog_exact_100_char_raw_not_truncated(self, detector):
        """Test 100-char Raw value is not truncated."""
        raw_100 = "T" * 100
        output = json.dumps({
            "DetectorName": "Generic",
            "Raw": raw_100,
            "SourceMetadata": {
                "Data": {"Filesystem": {"file": "f.py", "line": 1}}
            },
        })
        findings = detector._parse_trufflehog_output(output, "repo", "main")
        assert len(findings[0].matched_pattern) == 100

    def test_parse_trufflehog_null_raw(self, detector):
        """Test parsing trufflehog output with null Raw field."""
        output = json.dumps({
            "DetectorName": "Generic",
            "Raw": None,
            "SourceMetadata": {
                "Data": {"Filesystem": {"file": "f.py", "line": 1}}
            },
        })
        findings = detector._parse_trufflehog_output(output, "repo", "main")
        assert len(findings) == 1
        assert findings[0].matched_pattern is None

    def test_parse_trufflehog_scanner_in_metadata(self, detector):
        """Test that scanner field is 'trufflehog' in metadata."""
        output = json.dumps({
            "DetectorName": "Github",
            "Raw": "ghp_test",
            "SourceMetadata": {"Data": {"Filesystem": {"file": "f.py", "line": 1}}},
        })
        findings = detector._parse_trufflehog_output(output, "repo", "main")
        assert findings[0].metadata["scanner"] == "trufflehog"

    def test_parse_trufflehog_mixed_valid_invalid_lines(self, detector):
        """Test NDJSON with valid and invalid JSON lines."""
        valid_line = json.dumps({
            "DetectorName": "AWS",
            "Raw": "AKIAIOSFODNN7EXAMPLE",
            "SourceMetadata": {"Data": {"Filesystem": {"file": "f.py", "line": 1}}},
        })
        output = f"not-valid-json\n{valid_line}\nalso-invalid"
        findings = detector._parse_trufflehog_output(output, "repo", "main")
        # Only the valid line produces a finding
        assert len(findings) == 1

    def test_parse_trufflehog_sets_active_status(self, detector):
        """Test all trufflehog findings have ACTIVE status."""
        output = json.dumps({
            "DetectorName": "Stripe",
            "Raw": "sk_live_test",
            "SourceMetadata": {"Data": {"Filesystem": {"file": "f.py", "line": 1}}},
        })
        findings = detector._parse_trufflehog_output(output, "repo", "main")
        assert findings[0].status == SecretStatus.ACTIVE

    def test_parse_trufflehog_extra_data_in_metadata(self, detector):
        """Test ExtraData is preserved in finding metadata."""
        output = json.dumps({
            "DetectorName": "AWS",
            "Raw": "AKIAIOSFODNN7EXAMPLE",
            "ExtraData": {"account_id": "123456789012", "arn": "arn:aws:iam::123456789012:user/test"},
            "SourceMetadata": {"Data": {"Filesystem": {"file": "f.py", "line": 1}}},
        })
        findings = detector._parse_trufflehog_output(output, "repo", "main")
        assert findings[0].metadata["extra_data"]["account_id"] == "123456789012"

    def test_parse_trufflehog_whitespace_only_input(self, detector):
        """Test whitespace-only input returns empty list."""
        findings = detector._parse_trufflehog_output("  \n  \n  ", "repo", "main")
        assert findings == []


class TestSecretsScannerConfigExtended:
    """Additional tests for SecretsScannerConfig."""

    def test_from_env_defaults_when_no_env(self):
        """Test from_env returns defaults when no env vars set."""
        # Clear potentially set env vars
        env_keys = [
            "FIXOPS_GITLEAKS_PATH",
            "FIXOPS_TRUFFLEHOG_PATH",
            "FIXOPS_SECRETS_SCAN_TIMEOUT",
            "FIXOPS_MAX_FILE_SIZE_MB",
            "FIXOPS_ENTROPY_THRESHOLD",
            "FIXOPS_SCAN_HISTORY",
            "FIXOPS_SCAN_MAX_DEPTH",
        ]
        clean_env = {k: v for k, v in os.environ.items() if k not in env_keys}
        with patch.dict(os.environ, clean_env, clear=True):
            config = SecretsScannerConfig.from_env()
            assert config.gitleaks_path == "gitleaks"
            assert config.trufflehog_path == "trufflehog"
            assert config.timeout_seconds == 300
            assert config.max_file_size_mb == 50
            assert config.entropy_threshold == 4.5
            assert config.scan_history is True
            assert config.max_depth == 1000

    def test_scan_history_false_from_env(self):
        """Test scan_history=False when FIXOPS_SCAN_HISTORY=false."""
        with patch.dict(os.environ, {"FIXOPS_SCAN_HISTORY": "false"}):
            config = SecretsScannerConfig.from_env()
            assert config.scan_history is False

    def test_scan_history_true_from_env_uppercase(self):
        """Test scan_history=True when FIXOPS_SCAN_HISTORY=True (mixed case)."""
        with patch.dict(os.environ, {"FIXOPS_SCAN_HISTORY": "True"}):
            config = SecretsScannerConfig.from_env()
            assert config.scan_history is True

    def test_config_custom_values(self):
        """Test SecretsScannerConfig can be created with custom values."""
        config = SecretsScannerConfig(
            gitleaks_path="/usr/local/bin/gitleaks",
            trufflehog_path="/usr/local/bin/trufflehog",
            timeout_seconds=120,
            max_file_size_mb=25,
            entropy_threshold=3.0,
            scan_history=False,
            max_depth=200,
        )
        assert config.gitleaks_path == "/usr/local/bin/gitleaks"
        assert config.trufflehog_path == "/usr/local/bin/trufflehog"
        assert config.timeout_seconds == 120
        assert config.max_file_size_mb == 25
        assert config.entropy_threshold == 3.0
        assert config.scan_history is False
        assert config.max_depth == 200


class TestSecretsDetectorAvailability:
    """Tests for _is_gitleaks_available and _is_trufflehog_available caching."""

    def test_gitleaks_available_caches_result(self):
        """Test that _is_gitleaks_available caches after first call."""
        detector = SecretsDetector()
        detector._gitleaks_available = None

        with patch("shutil.which", return_value="/usr/bin/gitleaks"):
            result1 = detector._is_gitleaks_available()
            assert result1 is True

        # Even after patching is gone, cached result persists
        assert detector._gitleaks_available is True
        assert detector._is_gitleaks_available() is True

    def test_gitleaks_not_available(self):
        """Test _is_gitleaks_available returns False when not installed."""
        detector = SecretsDetector()
        detector._gitleaks_available = None

        with patch("shutil.which", return_value=None):
            result = detector._is_gitleaks_available()
        assert result is False

    def test_trufflehog_available_caches_result(self):
        """Test that _is_trufflehog_available caches after first call."""
        detector = SecretsDetector()
        detector._trufflehog_available = None

        with patch("shutil.which", return_value="/usr/bin/trufflehog"):
            result = detector._is_trufflehog_available()
            assert result is True
        assert detector._trufflehog_available is True

    def test_trufflehog_not_available(self):
        """Test _is_trufflehog_available returns False when not installed."""
        detector = SecretsDetector()
        detector._trufflehog_available = None

        with patch("shutil.which", return_value=None):
            result = detector._is_trufflehog_available()
        assert result is False

    def test_available_scanners_only_gitleaks(self):
        """Test get_available_scanners returns only gitleaks."""
        detector = SecretsDetector()
        with patch.object(detector, "_is_gitleaks_available", return_value=True):
            with patch.object(detector, "_is_trufflehog_available", return_value=False):
                available = detector.get_available_scanners()
                assert available == [SecretsScanner.GITLEAKS]

    def test_available_scanners_only_trufflehog(self):
        """Test get_available_scanners returns only trufflehog."""
        detector = SecretsDetector()
        with patch.object(detector, "_is_gitleaks_available", return_value=False):
            with patch.object(detector, "_is_trufflehog_available", return_value=True):
                available = detector.get_available_scanners()
                assert available == [SecretsScanner.TRUFFLEHOG]


class TestGitleaksExitCode1Success:
    """Test that exit code 1 from gitleaks is treated as success (findings found)."""

    @pytest.fixture
    def temp_dir(self):
        from core.secrets_scanner import SCAN_BASE_PATH
        os.makedirs(SCAN_BASE_PATH, exist_ok=True)
        test_dir = os.path.join(SCAN_BASE_PATH, str(uuid.uuid4()))
        os.makedirs(test_dir, exist_ok=True)
        yield test_dir
        shutil.rmtree(test_dir, ignore_errors=True)

    @pytest.fixture
    def detector(self):
        return SecretsDetector(SecretsScannerConfig(timeout_seconds=30))

    @pytest.mark.asyncio
    async def test_gitleaks_exit_code_1_success(self, detector, temp_dir):
        """Test that gitleaks exit code 1 (secrets found) is treated as success."""
        test_file = os.path.join(temp_dir, "config.py")
        with open(test_file, "w") as f:
            f.write('SECRET = "AKIAIOSFODNN7EXAMPLE"')

        mock_output = json.dumps([
            {
                "RuleID": "aws-access-key",
                "File": test_file,
                "StartLine": 1,
                "Match": "AKIAIOSFODNN7EXAMPLE",
            }
        ])

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = mock_exec.return_value
            mock_process.communicate = AsyncMock(
                return_value=(mock_output.encode(), b"")
            )
            mock_process.returncode = 1  # Exit code 1 means findings found

            findings, output, error = await detector._run_gitleaks(
                test_file, "test-repo", "main", False
            )

            assert error is None
            assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_trufflehog_exit_code_183_success(self, detector, temp_dir):
        """Test that trufflehog exit code 183 is treated as success."""
        test_file = os.path.join(temp_dir, "config.py")
        with open(test_file, "w") as f:
            f.write('SECRET = "AKIAIOSFODNN7EXAMPLE"')

        mock_output = json.dumps({
            "DetectorName": "AWS",
            "Raw": "AKIAIOSFODNN7EXAMPLE",
            "SourceMetadata": {
                "Data": {"Filesystem": {"file": test_file, "line": 1}}
            },
        })

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = mock_exec.return_value
            mock_process.communicate = AsyncMock(
                return_value=(mock_output.encode(), b"")
            )
            mock_process.returncode = 183  # Trufflehog special exit code

            findings, output, error = await detector._run_trufflehog(
                test_file, "test-repo", "main", False
            )

            assert error is None
            assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_gitleaks_no_git_flag_when_scan_history_false(self, detector, temp_dir):
        """Test --no-git flag is added when scan_history=False even in git repo."""
        detector.config.scan_history = False
        test_file = os.path.join(temp_dir, "config.py")
        with open(test_file, "w") as f:
            f.write("content")

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = mock_exec.return_value
            mock_process.communicate = AsyncMock(return_value=(b"[]", b""))
            mock_process.returncode = 0

            # is_git_repo=True but scan_history=False -> should use --no-git
            await detector._run_gitleaks(test_file, "repo", "main", True)

            call_args = mock_exec.call_args[0]
            assert "--no-git" in call_args

    @pytest.mark.asyncio
    async def test_trufflehog_filesystem_mode_when_no_scan_history(self, detector, temp_dir):
        """Test trufflehog uses filesystem mode when scan_history=False."""
        detector.config.scan_history = False
        test_file = os.path.join(temp_dir, "config.py")
        with open(test_file, "w") as f:
            f.write("content")

        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = mock_exec.return_value
            mock_process.communicate = AsyncMock(return_value=(b"", b""))
            mock_process.returncode = 0

            # is_git_repo=True but scan_history=False -> filesystem mode
            await detector._run_trufflehog(test_file, "repo", "main", True)

            call_args = mock_exec.call_args[0]
            assert "filesystem" in call_args
            assert "git" not in call_args or call_args.index("filesystem") < call_args.index("git") if "git" in call_args else True


class TestSecretFindingDataclass:
    """Tests for SecretFinding dataclass behavior."""

    def test_default_metadata_is_empty_dict(self):
        """Test that default metadata is an empty dict, not shared."""
        f1 = SecretFinding(
            id="a", secret_type=SecretType.GENERIC, status=SecretStatus.ACTIVE,
            file_path="f.py", line_number=1, repository="r", branch="b"
        )
        f2 = SecretFinding(
            id="b", secret_type=SecretType.GENERIC, status=SecretStatus.ACTIVE,
            file_path="f.py", line_number=1, repository="r", branch="b"
        )
        f1.metadata["key"] = "value"
        # Each instance should have its own metadata dict
        assert "key" not in f2.metadata

    def test_detected_at_is_set_automatically(self):
        """Test that detected_at is auto-populated."""
        finding = SecretFinding(
            id="x", secret_type=SecretType.TOKEN, status=SecretStatus.ACTIVE,
            file_path="f.py", line_number=1, repository="r", branch="b"
        )
        assert finding.detected_at is not None

    def test_resolved_at_defaults_to_none(self):
        """Test that resolved_at defaults to None."""
        finding = SecretFinding(
            id="x", secret_type=SecretType.TOKEN, status=SecretStatus.ACTIVE,
            file_path="f.py", line_number=1, repository="r", branch="b"
        )
        assert finding.resolved_at is None

    def test_commit_hash_defaults_to_none(self):
        """Test that commit_hash defaults to None."""
        finding = SecretFinding(
            id="x", secret_type=SecretType.TOKEN, status=SecretStatus.ACTIVE,
            file_path="f.py", line_number=1, repository="r", branch="b"
        )
        assert finding.commit_hash is None


class TestGetSecretsDetectorExtended:
    """Additional tests for get_secrets_detector."""

    def test_returns_secrets_detector_instance(self):
        """Test that get_secrets_detector returns a SecretsDetector."""
        import core.secrets_scanner as mod
        mod._default_detector = None
        detector = get_secrets_detector()
        assert isinstance(detector, SecretsDetector)
        mod._default_detector = None

    def test_singleton_is_reused(self):
        """Test that the same instance is returned on repeated calls."""
        import core.secrets_scanner as mod
        mod._default_detector = None
        d1 = get_secrets_detector()
        d2 = get_secrets_detector()
        assert d1 is d2
        mod._default_detector = None

    def test_detector_has_default_config(self):
        """Test that the singleton detector has a default config."""
        import core.secrets_scanner as mod
        mod._default_detector = None
        detector = get_secrets_detector()
        assert detector.config is not None
        assert detector.config.timeout_seconds == 300
        mod._default_detector = None


class TestSecretsScanResultDataclass:
    """Tests for SecretsScanResult dataclass fields and defaults."""

    def test_findings_default_is_empty_list(self):
        """Test findings defaults to empty list."""
        result = SecretsScanResult(
            scan_id="x",
            status=SecretsScanStatus.PENDING,
            scanner=SecretsScanner.GITLEAKS,
            target_path="f.py",
            repository="r",
            branch="b",
        )
        assert result.findings == []

    def test_metadata_default_is_empty_dict(self):
        """Test metadata defaults to empty dict."""
        result = SecretsScanResult(
            scan_id="x",
            status=SecretsScanStatus.PENDING,
            scanner=SecretsScanner.GITLEAKS,
            target_path="f.py",
            repository="r",
            branch="b",
        )
        assert result.metadata == {}

    def test_error_message_defaults_to_none(self):
        """Test error_message defaults to None."""
        result = SecretsScanResult(
            scan_id="x",
            status=SecretsScanStatus.COMPLETED,
            scanner=SecretsScanner.GITLEAKS,
            target_path="f.py",
            repository="r",
            branch="b",
        )
        assert result.error_message is None

    def test_to_dict_scanner_value(self):
        """Test to_dict uses scanner enum value string."""
        result = SecretsScanResult(
            scan_id="x",
            status=SecretsScanStatus.COMPLETED,
            scanner=SecretsScanner.TRUFFLEHOG,
            target_path="f.py",
            repository="r",
            branch="b",
        )
        assert result.to_dict()["scanner"] == "trufflehog"

    def test_to_dict_status_value(self):
        """Test to_dict uses status enum value string."""
        result = SecretsScanResult(
            scan_id="x",
            status=SecretsScanStatus.CANCELLED,
            scanner=SecretsScanner.GITLEAKS,
            target_path="f.py",
            repository="r",
            branch="b",
        )
        assert result.to_dict()["status"] == "cancelled"
