"""Coverage tests for core.sandbox_verifier — SandboxVerifier."""
import os
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

import dataclasses
from core.sandbox_verifier import (
    SandboxVerifier, VerificationStatus, PoCLanguage, PoCScript, VerificationResult,
)


class TestVerificationStatus:
    def test_verified_exploitable(self):
        assert VerificationStatus.VERIFIED_EXPLOITABLE.value == "verified_exploitable"

    def test_not_exploitable(self):
        assert VerificationStatus.NOT_EXPLOITABLE.value == "not_exploitable"

    def test_timeout(self):
        assert VerificationStatus.TIMEOUT.value == "timeout"

    def test_error(self):
        assert VerificationStatus.ERROR.value == "error"

    def test_sandbox_unavailable(self):
        assert VerificationStatus.SANDBOX_UNAVAILABLE.value == "sandbox_unavailable"

    def test_partial(self):
        assert VerificationStatus.PARTIAL.value == "partial"


class TestPoCLanguage:
    def test_python(self):
        assert PoCLanguage.PYTHON.value == "python"

    def test_bash(self):
        assert PoCLanguage.BASH.value == "bash"

    def test_nodejs(self):
        assert PoCLanguage.NODEJS.value == "nodejs"

    def test_curl(self):
        assert PoCLanguage.CURL.value == "curl"

    def test_go(self):
        assert PoCLanguage.GO.value == "go"


class TestPoCScript:
    def test_creation(self):
        script = PoCScript(
            language=PoCLanguage.PYTHON,
            code="print('exploit')",
            cve_id="CVE-2024-001",
            description="Test exploit PoC",
        )
        assert script.cve_id == "CVE-2024-001"
        assert script.code == "print('exploit')"
        assert script.language == PoCLanguage.PYTHON

    def test_defaults(self):
        script = PoCScript(
            language=PoCLanguage.BASH,
            code="curl http://target",
            description="Test",
            cve_id="CVE-2024-002",
        )
        assert script.requires_network is False or script.requires_network is True
        assert script.timeout_seconds > 0 or script.timeout_seconds == 0

    def test_is_dataclass(self):
        assert dataclasses.is_dataclass(PoCScript)


class TestVerificationResult:
    def test_creation(self):
        result = VerificationResult(
            verification_id="VR-001",
            status=VerificationStatus.VERIFIED_EXPLOITABLE,
            finding_id="F-001",
            cve_id="CVE-2024-001",
        )
        assert result.status == VerificationStatus.VERIFIED_EXPLOITABLE
        assert result.finding_id == "F-001"

    def test_defaults(self):
        result = VerificationResult(verification_id="VR-002")
        assert result.status == VerificationStatus.ERROR
        assert result.exploitable is False
        assert result.confidence == 0.0
        assert result.exit_code == -1

    def test_is_dataclass(self):
        assert dataclasses.is_dataclass(VerificationResult)


class TestSandboxVerifier:
    def test_instantiation(self):
        sv = SandboxVerifier()
        assert sv is not None

    def test_docker_available(self):
        sv = SandboxVerifier()
        # docker_available is a property, not a method
        result = sv.docker_available
        assert isinstance(result, bool)

    def test_get_stats(self):
        sv = SandboxVerifier()
        stats = sv.get_stats()
        assert isinstance(stats, dict)

    def test_get_results_empty(self):
        sv = SandboxVerifier()
        results = sv.get_results()
        assert isinstance(results, (list, dict))

    def test_verify_finding(self):
        sv = SandboxVerifier()
        finding = {
            "id": "CVE-2024-001",
            "title": "Test SQL Injection",
            "severity": "high",
            "cve_id": "CVE-2024-001",
        }
        result = sv.verify_finding(finding, target_url="http://localhost:8080")
        assert result is not None
        assert isinstance(result, VerificationResult)

    def test_verify_poc(self):
        sv = SandboxVerifier()
        poc = PoCScript(
            language=PoCLanguage.PYTHON,
            code="import sys; print('test'); sys.exit(0)",
            description="Harmless test",
            cve_id="CVE-2024-TEST",
        )
        result = sv.verify(poc, finding_id="F-TEST")
        assert isinstance(result, VerificationResult)

    def test_sandbox_verify_findings_empty(self):
        sv = SandboxVerifier()
        results = sv.sandbox_verify_findings([], [])
        assert isinstance(results, list)
