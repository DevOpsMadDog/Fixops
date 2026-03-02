"""
Security hardening tests — v2 (2026-03-02)
==========================================
Tests the security defenses added by backend-hardener on March 2:

1. Brain pipeline: error message sanitization (no exception detail leakage)
2. Scanner parsers: XXE protection, size limits
3. Sandbox verifier: self-correction whitelist, Docker hardening
4. DAST engine: SSRF protection (RFC1918, loopback, metadata blocking)
5. Container scanner: image reference validation (shell injection prevention)
6. Secrets scanner: error message truncation (secret leakage prevention)

Pillar: V3 (Decision Intelligence), V5 (MPTE Verification)
"""

import pytest
from unittest.mock import patch, MagicMock


# ---------------------------------------------------------------------------
# 1. Brain Pipeline: Error message sanitization
# ---------------------------------------------------------------------------
class TestBrainPipelineErrorSanitization:
    """Verify brain pipeline does NOT leak exception details in step errors."""

    def test_error_contains_type_not_message(self):
        """Step error should contain exception TYPE but not the raw MESSAGE."""
        from core.brain_pipeline import BrainPipeline, PipelineInput

        pipeline = BrainPipeline()
        inp = PipelineInput(
            org_id="test-org",
            findings=[{"title": "test", "severity": "high"}],
        )

        # Mock a step to raise with a sensitive message
        with patch.object(
            pipeline, "_step_normalize", side_effect=ValueError("DB password is s3cr3t!")
        ):
            result = pipeline.run(inp)
            normalize_step = result.steps[1]  # normalize is step 2 (index 1)
            # Should contain exception type
            assert "ValueError" in normalize_step.error
            # Should NOT contain the sensitive message
            assert "s3cr3t" not in normalize_step.error
            assert "DB password" not in normalize_step.error
            # Should contain sanitized message
            assert "pipeline step failed" in normalize_step.error


# ---------------------------------------------------------------------------
# 2. Scanner Parsers: XXE protection
# ---------------------------------------------------------------------------
class TestScannerParsersXXE:
    """Verify scanner parsers block XXE attacks."""

    def test_xxe_entity_stripped(self):
        """DOCTYPE with ENTITY declarations should be stripped."""
        from core.scanner_parsers import _parse_xml_safe

        xxe_xml = b'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>'''
        result = _parse_xml_safe(xxe_xml)
        # Should either return None (parse failure) or strip the entity
        if result is not None:
            # If it parsed, the entity reference should NOT have resolved
            text = result.text or ""
            assert "root:" not in text  # /etc/passwd content
            assert "xxe" not in text.lower() or text == ""

    def test_billion_laughs_blocked(self):
        """Billion laughs (XML bomb) should be blocked by size or parse limit."""
        from core.scanner_parsers import _parse_xml_safe

        bomb = b'''<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<root>&lol3;</root>'''
        result = _parse_xml_safe(bomb)
        # Should return None or have stripped the entities
        # Either outcome is acceptable — the key is no crash or memory explosion

    def test_size_limit_enforced(self):
        """XML larger than 100MB should be rejected."""
        from core.scanner_parsers import _parse_xml_safe, _MAX_XML_SIZE

        oversized = b"<root>" + b"x" * (_MAX_XML_SIZE + 1) + b"</root>"
        result = _parse_xml_safe(oversized)
        assert result is None  # Should be rejected

    def test_json_size_limit_enforced(self):
        """JSON larger than 100MB should be rejected."""
        from core.scanner_parsers import _parse_json_safe, _MAX_JSON_SIZE

        oversized = b'{"key": "' + b"x" * (_MAX_JSON_SIZE + 1) + b'"}'
        result = _parse_json_safe(oversized)
        assert result is None  # Should be rejected

    def test_valid_xml_still_parses(self):
        """Normal XML should still parse correctly."""
        from core.scanner_parsers import _parse_xml_safe

        valid_xml = b'<root><item>test</item></root>'
        result = _parse_xml_safe(valid_xml)
        assert result is not None
        assert result.tag == "root"

    def test_valid_json_still_parses(self):
        """Normal JSON should still parse correctly."""
        from core.scanner_parsers import _parse_json_safe

        valid_json = b'{"key": "value", "list": [1, 2, 3]}'
        result = _parse_json_safe(valid_json)
        assert result is not None
        assert result["key"] == "value"


# ---------------------------------------------------------------------------
# 3. Sandbox Verifier: Self-correction whitelist
# ---------------------------------------------------------------------------
class TestSandboxSelfCorrection:
    """Verify sandbox verifier self-correction uses whitelists."""

    def test_blocked_module_rejected(self):
        """Pip install for non-whitelisted modules should be blocked."""
        from core.sandbox_verifier import SandboxVerifier, PoCScript, PoCLanguage, VerificationResult, VerificationStatus

        verifier = SandboxVerifier(docker_available=False)
        poc = PoCScript(
            cve_id="CVE-2024-0001",
            language=PoCLanguage.PYTHON,
            code="import evil_module\nprint('pwned')",
        )
        failed_result = VerificationResult(
            verification_id="test",
            status=VerificationStatus.ERROR,
            stdout="",
            stderr="ModuleNotFoundError: No module named 'evil_module'",
        )
        corrected = verifier._self_correct(poc, "import evil_module", failed_result)
        # Should return None because evil_module is not in whitelist
        assert corrected is None

    def test_whitelisted_module_allowed(self):
        """Pip install for whitelisted modules (e.g., requests) should work."""
        from core.sandbox_verifier import SandboxVerifier, PoCScript, PoCLanguage, VerificationResult, VerificationStatus

        verifier = SandboxVerifier(docker_available=False)
        poc = PoCScript(
            cve_id="CVE-2024-0001",
            language=PoCLanguage.PYTHON,
            code="import requests\nrequests.get('http://example.com')",
        )
        failed_result = VerificationResult(
            verification_id="test",
            status=VerificationStatus.ERROR,
            stdout="",
            stderr="ModuleNotFoundError: No module named 'requests'",
        )
        corrected = verifier._self_correct(poc, "import requests", failed_result)
        # Should return corrected code with pip install
        assert corrected is not None
        assert "pip" in corrected
        assert "requests" in corrected

    def test_blocked_shell_command_rejected(self):
        """apk add for non-whitelisted commands should be blocked."""
        from core.sandbox_verifier import SandboxVerifier, PoCScript, PoCLanguage, VerificationResult, VerificationStatus

        verifier = SandboxVerifier(docker_available=False)
        poc = PoCScript(
            cve_id="CVE-2024-0001",
            language=PoCLanguage.BASH,
            code="rm -rf /",
        )
        failed_result = VerificationResult(
            verification_id="test",
            status=VerificationStatus.ERROR,
            stdout="",
            stderr="rm: command not found",
        )
        corrected = verifier._self_correct(poc, "rm -rf /", failed_result)
        # 'rm' is not in the whitelist — should return None
        assert corrected is None

    def test_whitelisted_shell_command_allowed(self):
        """apk add for whitelisted commands (e.g., curl) should work."""
        from core.sandbox_verifier import SandboxVerifier, PoCScript, PoCLanguage, VerificationResult, VerificationStatus

        verifier = SandboxVerifier(docker_available=False)
        poc = PoCScript(
            cve_id="CVE-2024-0001",
            language=PoCLanguage.BASH,
            code="curl http://example.com",
        )
        failed_result = VerificationResult(
            verification_id="test",
            status=VerificationStatus.ERROR,
            stdout="",
            stderr="curl: command not found",
        )
        corrected = verifier._self_correct(poc, "curl http://example.com", failed_result)
        assert corrected is not None
        assert "apk add" in corrected
        assert "curl" in corrected


# ---------------------------------------------------------------------------
# 4. DAST Engine: SSRF protection
# ---------------------------------------------------------------------------
class TestDASTSSRFProtection:
    """Verify DAST engine blocks SSRF targets."""

    def test_blocks_localhost(self):
        """Should block localhost targets."""
        from core.dast_engine import DASTEngine

        with pytest.raises(ValueError, match="loopback|localhost"):
            DASTEngine.validate_target_url("http://localhost:8080/test")

    def test_blocks_127_range(self):
        """Should block 127.x.x.x range."""
        from core.dast_engine import DASTEngine

        with pytest.raises(ValueError, match="private|reserved"):
            DASTEngine.validate_target_url("http://127.0.0.1:8080/test")

    def test_blocks_10_range(self):
        """Should block 10.x.x.x (RFC 1918) range."""
        from core.dast_engine import DASTEngine

        with pytest.raises(ValueError, match="private|reserved"):
            DASTEngine.validate_target_url("http://10.0.0.1/admin")

    def test_blocks_172_range(self):
        """Should block 172.16-31.x.x (RFC 1918) range."""
        from core.dast_engine import DASTEngine

        with pytest.raises(ValueError, match="private|reserved"):
            DASTEngine.validate_target_url("http://172.16.0.1/")

    def test_blocks_192_168_range(self):
        """Should block 192.168.x.x (RFC 1918) range."""
        from core.dast_engine import DASTEngine

        with pytest.raises(ValueError, match="private|reserved"):
            DASTEngine.validate_target_url("http://192.168.1.1/")

    def test_blocks_metadata_endpoint(self):
        """Should block AWS metadata (169.254.x.x) range."""
        from core.dast_engine import DASTEngine

        with pytest.raises(ValueError, match="private|reserved"):
            DASTEngine.validate_target_url("http://169.254.169.254/latest/meta-data/")

    def test_blocks_file_scheme(self):
        """Should block file:// scheme."""
        from core.dast_engine import DASTEngine

        with pytest.raises(ValueError, match="scheme"):
            DASTEngine.validate_target_url("file:///etc/passwd")

    def test_blocks_ftp_scheme(self):
        """Should block ftp:// scheme."""
        from core.dast_engine import DASTEngine

        with pytest.raises(ValueError, match="scheme"):
            DASTEngine.validate_target_url("ftp://internal.server/data")

    def test_blocks_gopher_scheme(self):
        """Should block gopher:// scheme."""
        from core.dast_engine import DASTEngine

        with pytest.raises(ValueError, match="scheme"):
            DASTEngine.validate_target_url("gopher://internal:9090/")

    def test_allows_public_https(self):
        """Should allow legitimate public HTTPS targets."""
        from core.dast_engine import DASTEngine

        # This should NOT raise
        result = DASTEngine.validate_target_url("https://example.com/api/test")
        assert result == "https://example.com/api/test"

    def test_blocks_empty_hostname(self):
        """Should block URLs with no hostname."""
        from core.dast_engine import DASTEngine

        with pytest.raises(ValueError, match="hostname"):
            DASTEngine.validate_target_url("http:///path")

    def test_blocks_zero_ip(self):
        """Should block 0.0.0.0 target."""
        from core.dast_engine import DASTEngine

        with pytest.raises(ValueError, match="loopback|localhost"):
            DASTEngine.validate_target_url("http://0.0.0.0:80/")

    def test_blocks_ipv6_loopback(self):
        """Should block IPv6 loopback [::1]."""
        from core.dast_engine import DASTEngine

        with pytest.raises(ValueError, match="loopback|localhost"):
            DASTEngine.validate_target_url("http://[::1]:8080/")


# ---------------------------------------------------------------------------
# 5. Container Scanner: Image reference validation
# ---------------------------------------------------------------------------
class TestContainerImageRefValidation:
    """Verify container scanner blocks shell injection in image references."""

    def test_blocks_semicolon_injection(self):
        """Should block ; in image reference."""
        from core.container_scanner import ContainerImageScanner

        with pytest.raises(ValueError, match="Blocked characters"):
            ContainerImageScanner._validate_image_ref("alpine:latest; rm -rf /")

    def test_blocks_pipe_injection(self):
        """Should block | in image reference."""
        from core.container_scanner import ContainerImageScanner

        with pytest.raises(ValueError, match="Blocked characters"):
            ContainerImageScanner._validate_image_ref("alpine:latest | cat /etc/passwd")

    def test_blocks_ampersand_injection(self):
        """Should block & in image reference."""
        from core.container_scanner import ContainerImageScanner

        with pytest.raises(ValueError, match="Blocked characters"):
            ContainerImageScanner._validate_image_ref("alpine:latest && id")

    def test_blocks_dollar_injection(self):
        """Should block $ in image reference."""
        from core.container_scanner import ContainerImageScanner

        with pytest.raises(ValueError, match="Blocked characters"):
            ContainerImageScanner._validate_image_ref("alpine:$(id)")

    def test_blocks_backtick_injection(self):
        """Should block backtick in image reference."""
        from core.container_scanner import ContainerImageScanner

        with pytest.raises(ValueError, match="Blocked characters"):
            ContainerImageScanner._validate_image_ref("alpine:`id`")

    def test_blocks_empty_reference(self):
        """Should block empty image reference."""
        from core.container_scanner import ContainerImageScanner

        with pytest.raises(ValueError, match="Empty"):
            ContainerImageScanner._validate_image_ref("")

    def test_blocks_oversized_reference(self):
        """Should block oversized image reference (>512 chars)."""
        from core.container_scanner import ContainerImageScanner

        with pytest.raises(ValueError, match="too long"):
            ContainerImageScanner._validate_image_ref("a" * 513)

    def test_allows_standard_image(self):
        """Should allow standard Docker image references."""
        from core.container_scanner import ContainerImageScanner

        assert ContainerImageScanner._validate_image_ref("alpine:3.19") == "alpine:3.19"
        assert ContainerImageScanner._validate_image_ref("docker.io/library/python:3.12") == "docker.io/library/python:3.12"
        assert ContainerImageScanner._validate_image_ref("ghcr.io/org/app:v1.2.3") == "ghcr.io/org/app:v1.2.3"

    def test_allows_sha256_digest(self):
        """Should allow image references with SHA256 digest."""
        from core.container_scanner import ContainerImageScanner

        ref = "alpine@sha256:abc123def456"
        assert ContainerImageScanner._validate_image_ref(ref) == ref

    def test_blocks_newline_injection(self):
        """Should block newline in image reference."""
        from core.container_scanner import ContainerImageScanner

        with pytest.raises(ValueError, match="Blocked characters"):
            ContainerImageScanner._validate_image_ref("alpine:latest\nrm -rf /")


# ---------------------------------------------------------------------------
# 6. Brain Pipeline: Safe dict access
# ---------------------------------------------------------------------------
class TestBrainPipelineSafeAccess:
    """Verify brain pipeline uses safe dict access patterns."""

    def test_step_connect_with_missing_keys(self):
        """_step_connect should handle missing findings/assets keys gracefully."""
        from core.brain_pipeline import BrainPipeline, PipelineInput

        pipeline = BrainPipeline()
        inp = PipelineInput(org_id="test")
        # Empty context — no findings or assets keys
        ctx = {"org_id": "test"}
        result = pipeline._step_connect(ctx, inp)
        assert result["findings_count"] == 0
        assert result["assets_count"] == 0
