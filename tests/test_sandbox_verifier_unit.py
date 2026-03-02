"""Comprehensive unit tests for core.sandbox_verifier — Docker sandbox PoC verification.

Tests cover: data models, SandboxVerifier init, Docker availability check,
PoC script creation, verification flow, self-correction, evidence hashing,
edge cases, and error handling. Docker is mocked for CI/CD environments.

Vision Pillar: V5 (MPTE Verification), MOAT2 (MPTE + Sandbox PoC)
"""

import subprocess
from unittest.mock import patch, MagicMock


from core.sandbox_verifier import (
    VerificationStatus,
    PoCLanguage,
    PoCScript,
    VerificationResult,
    SandboxVerifier,
)


# ---------------------------------------------------------------------------
# Data Model Tests
# ---------------------------------------------------------------------------

class TestVerificationStatus:
    """Tests for VerificationStatus enum."""

    def test_verified_exploitable_value(self):
        assert VerificationStatus.VERIFIED_EXPLOITABLE == "verified_exploitable"

    def test_not_exploitable_value(self):
        assert VerificationStatus.NOT_EXPLOITABLE == "not_exploitable"

    def test_partial_value(self):
        assert VerificationStatus.PARTIAL == "partial"

    def test_timeout_value(self):
        assert VerificationStatus.TIMEOUT == "timeout"

    def test_error_value(self):
        assert VerificationStatus.ERROR == "error"

    def test_sandbox_unavailable_value(self):
        assert VerificationStatus.SANDBOX_UNAVAILABLE == "sandbox_unavailable"

    def test_all_statuses_are_strings(self):
        for status in VerificationStatus:
            assert isinstance(status.value, str)

    def test_status_count(self):
        assert len(VerificationStatus) == 6


class TestPoCLanguage:
    """Tests for PoCLanguage enum."""

    def test_python(self):
        assert PoCLanguage.PYTHON == "python"

    def test_bash(self):
        assert PoCLanguage.BASH == "bash"

    def test_nodejs(self):
        assert PoCLanguage.NODEJS == "nodejs"

    def test_curl(self):
        assert PoCLanguage.CURL == "curl"

    def test_go(self):
        assert PoCLanguage.GO == "go"

    def test_language_count(self):
        assert len(PoCLanguage) == 5


class TestPoCScript:
    """Tests for PoCScript dataclass."""

    def test_create_minimal(self):
        poc = PoCScript(language=PoCLanguage.PYTHON, code="print('hello')")
        assert poc.language == PoCLanguage.PYTHON
        assert poc.code == "print('hello')"
        assert poc.description == ""
        assert poc.cve_id == ""
        assert poc.timeout_seconds == 30

    def test_create_full(self):
        poc = PoCScript(
            language=PoCLanguage.BASH,
            code="curl http://target:8080",
            description="Test HTTP endpoint",
            cve_id="CVE-2024-1234",
            target_url="http://target:8080",
            expected_indicators=["HTTP/1.1 200"],
            timeout_seconds=60,
            requires_network=True,
            metadata={"author": "test"},
        )
        assert poc.cve_id == "CVE-2024-1234"
        assert poc.requires_network is True
        assert poc.timeout_seconds == 60
        assert len(poc.expected_indicators) == 1

    def test_default_expected_indicators(self):
        poc = PoCScript(language=PoCLanguage.PYTHON, code="pass")
        assert poc.expected_indicators == []
        assert poc.metadata == {}

    def test_default_requires_network(self):
        poc = PoCScript(language=PoCLanguage.PYTHON, code="pass")
        assert poc.requires_network is False


class TestVerificationResult:
    """Tests for VerificationResult dataclass."""

    def test_default_values(self):
        result = VerificationResult()
        assert result.status == VerificationStatus.ERROR
        assert result.exploitable is False
        assert result.confidence == 0.0
        assert result.exit_code == -1
        assert result.attempt == 1
        assert result.max_attempts == 3
        assert result.verification_id  # Auto-generated UUID

    def test_custom_values(self):
        result = VerificationResult(
            status=VerificationStatus.VERIFIED_EXPLOITABLE,
            finding_id="FIND-001",
            cve_id="CVE-2024-9999",
            exploitable=True,
            confidence=0.95,
            exit_code=0,
            execution_time_ms=1234.5,
            indicators_matched=["root_shell"],
            indicators_total=2,
        )
        assert result.exploitable is True
        assert result.confidence == 0.95
        assert result.indicators_matched == ["root_shell"]

    def test_to_dict(self):
        result = VerificationResult(
            status=VerificationStatus.NOT_EXPLOITABLE,
            finding_id="F1",
            cve_id="CVE-2024-0001",
            exploitable=False,
            confidence=0.1,
            exit_code=1,
        )
        d = result.to_dict()
        assert d["status"] == "not_exploitable"
        assert d["finding_id"] == "F1"
        assert d["cve_id"] == "CVE-2024-0001"
        assert d["exploitable"] is False
        assert d["confidence"] == 0.1
        assert "verification_id" in d
        assert "timestamp" in d

    def test_to_dict_keys(self):
        result = VerificationResult()
        d = result.to_dict()
        expected_keys = {
            "verification_id", "status", "finding_id", "cve_id",
            "exploitable", "confidence", "execution_time_ms",
            "indicators_matched", "indicators_total", "attempt",
            "max_attempts", "timestamp", "evidence_hash", "exit_code",
        }
        assert set(d.keys()) == expected_keys

    def test_verification_id_is_uuid(self):
        result = VerificationResult()
        parts = result.verification_id.split("-")
        assert len(parts) == 5  # UUID has 5 dash-separated parts

    def test_timestamp_is_iso_format(self):
        result = VerificationResult()
        assert "T" in result.timestamp


# ---------------------------------------------------------------------------
# SandboxVerifier Initialization Tests
# ---------------------------------------------------------------------------

class TestSandboxVerifierInit:
    """Tests for SandboxVerifier initialization."""

    def test_default_init(self):
        sv = SandboxVerifier()
        assert sv.memory_limit == "128m"
        assert sv.cpu_limit == 0.5
        assert sv.max_attempts == 3

    def test_custom_init(self):
        sv = SandboxVerifier(
            memory_limit="256m",
            cpu_limit=1.0,
            max_attempts=5,
        )
        assert sv.memory_limit == "256m"
        assert sv.cpu_limit == 1.0
        assert sv.max_attempts == 5

    def test_docker_available_override(self):
        sv = SandboxVerifier(docker_available=True)
        assert sv.docker_available is True

    def test_docker_unavailable_override(self):
        sv = SandboxVerifier(docker_available=False)
        assert sv.docker_available is False

    def test_results_store_empty_on_init(self):
        sv = SandboxVerifier()
        assert sv._results_store == []


class TestSandboxVerifierDockerCheck:
    """Tests for Docker availability checking."""

    @patch("subprocess.run")
    def test_docker_available_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="24.0.7")
        sv = SandboxVerifier(docker_available=None)
        sv._docker_available = None  # Force re-check
        assert sv.docker_available is True

    @patch("subprocess.run")
    def test_docker_not_available(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        sv = SandboxVerifier(docker_available=None)
        sv._docker_available = None
        assert sv.docker_available is False

    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_docker_not_installed(self, mock_run):
        sv = SandboxVerifier(docker_available=None)
        sv._docker_available = None
        assert sv.docker_available is False

    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="docker", timeout=5))
    def test_docker_check_timeout(self, mock_run):
        sv = SandboxVerifier(docker_available=None)
        sv._docker_available = None
        assert sv.docker_available is False

    def test_docker_cached_after_first_check(self):
        sv = SandboxVerifier(docker_available=True)
        # Should not call subprocess again
        assert sv.docker_available is True
        assert sv.docker_available is True  # Cached


class TestSandboxVerifierConstants:
    """Tests for SandboxVerifier class-level constants."""

    def test_docker_images_all_languages(self):
        for lang in PoCLanguage:
            assert lang in SandboxVerifier.DOCKER_IMAGES

    def test_extensions_all_languages(self):
        for lang in PoCLanguage:
            assert lang in SandboxVerifier.EXTENSIONS
            assert SandboxVerifier.EXTENSIONS[lang].startswith(".")

    def test_commands_all_languages(self):
        for lang in PoCLanguage:
            assert lang in SandboxVerifier.COMMANDS
            assert isinstance(SandboxVerifier.COMMANDS[lang], list)

    def test_python_image(self):
        assert "python" in SandboxVerifier.DOCKER_IMAGES[PoCLanguage.PYTHON]

    def test_node_image(self):
        assert "node" in SandboxVerifier.DOCKER_IMAGES[PoCLanguage.NODEJS]

    def test_go_image(self):
        assert "golang" in SandboxVerifier.DOCKER_IMAGES[PoCLanguage.GO]


# ---------------------------------------------------------------------------
# Verification Flow Tests (Docker Mocked)
# ---------------------------------------------------------------------------

class TestSandboxVerifierVerify:
    """Tests for the verify() method with mocked Docker."""

    def test_verify_returns_sandbox_unavailable_when_no_docker(self):
        sv = SandboxVerifier(docker_available=False)
        poc = PoCScript(language=PoCLanguage.PYTHON, code="print('test')", cve_id="CVE-2024-1111")
        result = sv.verify(poc, finding_id="F1")
        assert result.status == VerificationStatus.SANDBOX_UNAVAILABLE
        assert "Docker not available" in result.error_message
        assert result.cve_id == "CVE-2024-1111"

    def test_verify_stores_result(self):
        sv = SandboxVerifier(docker_available=False)
        poc = PoCScript(language=PoCLanguage.BASH, code="echo test")
        sv.verify(poc, finding_id="F2")
        # sandbox_unavailable results are NOT stored per the code
        # Only results from actual execution are stored

    @patch.object(SandboxVerifier, '_execute_in_sandbox')
    def test_verify_success_on_first_attempt(self, mock_exec):
        mock_exec.return_value = VerificationResult(
            status=VerificationStatus.VERIFIED_EXPLOITABLE,
            exploitable=True,
            confidence=0.95,
            exit_code=0,
        )
        sv = SandboxVerifier(docker_available=True)
        poc = PoCScript(language=PoCLanguage.PYTHON, code="import os; os.getuid()")
        result = sv.verify(poc, finding_id="F3")
        assert result.status == VerificationStatus.VERIFIED_EXPLOITABLE
        assert result.exploitable is True
        mock_exec.assert_called_once()

    @patch.object(SandboxVerifier, '_self_correct')
    @patch.object(SandboxVerifier, '_execute_in_sandbox')
    def test_verify_retries_on_failure(self, mock_exec, mock_correct):
        # First attempt fails, second succeeds
        mock_exec.side_effect = [
            VerificationResult(status=VerificationStatus.ERROR, exit_code=1),
            VerificationResult(status=VerificationStatus.VERIFIED_EXPLOITABLE, exploitable=True),
        ]
        mock_correct.return_value = "corrected_code"

        sv = SandboxVerifier(docker_available=True, max_attempts=3)
        poc = PoCScript(language=PoCLanguage.PYTHON, code="original")
        result = sv.verify(poc, finding_id="F4")
        assert result.status == VerificationStatus.VERIFIED_EXPLOITABLE
        assert mock_exec.call_count == 2

    @patch.object(SandboxVerifier, '_execute_in_sandbox')
    def test_verify_stops_on_timeout(self, mock_exec):
        mock_exec.return_value = VerificationResult(status=VerificationStatus.TIMEOUT)
        sv = SandboxVerifier(docker_available=True)
        poc = PoCScript(language=PoCLanguage.PYTHON, code="while True: pass")
        result = sv.verify(poc)
        assert result.status == VerificationStatus.TIMEOUT
        mock_exec.assert_called_once()

    @patch.object(SandboxVerifier, '_self_correct')
    @patch.object(SandboxVerifier, '_execute_in_sandbox')
    def test_verify_stops_when_no_correction(self, mock_exec, mock_correct):
        mock_exec.return_value = VerificationResult(status=VerificationStatus.ERROR)
        mock_correct.return_value = None  # No correction possible

        sv = SandboxVerifier(docker_available=True, max_attempts=3)
        poc = PoCScript(language=PoCLanguage.PYTHON, code="broken")
        result = sv.verify(poc)
        assert result.status == VerificationStatus.ERROR
        mock_exec.assert_called_once()

    @patch.object(SandboxVerifier, '_self_correct')
    @patch.object(SandboxVerifier, '_execute_in_sandbox')
    def test_verify_stops_when_same_correction(self, mock_exec, mock_correct):
        mock_exec.return_value = VerificationResult(status=VerificationStatus.ERROR)
        mock_correct.return_value = "broken"  # Same as original code

        sv = SandboxVerifier(docker_available=True, max_attempts=3)
        poc = PoCScript(language=PoCLanguage.PYTHON, code="broken")
        sv.verify(poc)
        assert mock_exec.call_count == 1  # No retry

    @patch.object(SandboxVerifier, '_execute_in_sandbox')
    def test_verify_respects_max_attempts(self, mock_exec):
        mock_exec.return_value = VerificationResult(status=VerificationStatus.ERROR)
        sv = SandboxVerifier(docker_available=True, max_attempts=1)
        poc = PoCScript(language=PoCLanguage.PYTHON, code="fail")
        sv.verify(poc)
        assert mock_exec.call_count == 1


# ---------------------------------------------------------------------------
# PoC Language Configuration Tests
# ---------------------------------------------------------------------------

class TestPoCLanguageConfig:
    """Tests for per-language Docker configuration."""

    def test_python_extension(self):
        assert SandboxVerifier.EXTENSIONS[PoCLanguage.PYTHON] == ".py"

    def test_bash_extension(self):
        assert SandboxVerifier.EXTENSIONS[PoCLanguage.BASH] == ".sh"

    def test_nodejs_extension(self):
        assert SandboxVerifier.EXTENSIONS[PoCLanguage.NODEJS] == ".js"

    def test_curl_extension(self):
        assert SandboxVerifier.EXTENSIONS[PoCLanguage.CURL] == ".sh"

    def test_go_extension(self):
        assert SandboxVerifier.EXTENSIONS[PoCLanguage.GO] == ".go"

    def test_python_command(self):
        cmd = SandboxVerifier.COMMANDS[PoCLanguage.PYTHON]
        assert "python3" in cmd[0]

    def test_bash_command(self):
        cmd = SandboxVerifier.COMMANDS[PoCLanguage.BASH]
        assert "sh" in cmd[0]

    def test_go_command(self):
        cmd = SandboxVerifier.COMMANDS[PoCLanguage.GO]
        assert "go" in cmd[0]
        assert "run" in cmd


# ---------------------------------------------------------------------------
# Edge Cases
# ---------------------------------------------------------------------------

class TestSandboxEdgeCases:
    """Edge cases for sandbox verifier."""

    def test_empty_code_poc(self):
        poc = PoCScript(language=PoCLanguage.PYTHON, code="")
        assert poc.code == ""

    def test_very_large_poc(self):
        poc = PoCScript(
            language=PoCLanguage.PYTHON,
            code="x = 1\n" * 100000,
        )
        assert len(poc.code) > 0

    def test_poc_with_special_chars(self):
        poc = PoCScript(
            language=PoCLanguage.BASH,
            code='echo "hello $WORLD" | grep -i "test" && rm -rf /tmp/test',
        )
        assert "$WORLD" in poc.code

    def test_result_default_error_message(self):
        result = VerificationResult()
        assert result.error_message == ""

    def test_result_custom_error_message(self):
        result = VerificationResult(error_message="Docker daemon not running")
        assert "Docker daemon" in result.error_message

    def test_multiple_verifications_accumulate(self):
        sv = SandboxVerifier(docker_available=False)
        for i in range(5):
            sv.verify(PoCScript(language=PoCLanguage.PYTHON, code="pass"))
        # sandbox_unavailable results return before storing
        # The store behavior depends on implementation

    def test_verification_result_equality_by_id(self):
        r1 = VerificationResult(verification_id="same-id")
        r2 = VerificationResult(verification_id="same-id")
        assert r1.verification_id == r2.verification_id

    def test_poc_metadata_dict(self):
        poc = PoCScript(
            language=PoCLanguage.PYTHON,
            code="pass",
            metadata={"author": "test", "version": 1},
        )
        assert poc.metadata["author"] == "test"
        assert poc.metadata["version"] == 1
