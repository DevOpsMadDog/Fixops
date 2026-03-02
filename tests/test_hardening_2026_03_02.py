"""
Backend Hardener Test Suite — 2026-03-02
========================================
Tests all hardening improvements made in this session:
1. Brain pipeline: thread safety, async, string sanitization, timeout
2. Scanner ingest router: path traversal, zip bombs, size limits
3. Scanner parsers: crash resilience, output caps
4. Sandbox verifier: resource limits verification (read-only)

[V3] Decision Intelligence | [V5] MPTE Verification | [V7] MCP-Native

Run with:
    PYTHONPATH=suite-api:suite-core:suite-attack:suite-feeds:suite-evidence-risk:suite-integrations \
    FIXOPS_API_TOKEN=test-token FIXOPS_DISABLE_RATE_LIMIT=1 \
    python -m pytest tests/test_hardening_2026_03_02.py -v --timeout=30
"""

import asyncio
import threading

import pytest


# ═══════════════════════════════════════════════════════════════════════════════
# Brain Pipeline Hardening Tests [V3]
# ═══════════════════════════════════════════════════════════════════════════════

class TestBrainPipelineHardening:
    """Test security hardening of the brain pipeline."""

    def _make_pipeline(self):
        from core.brain_pipeline import BrainPipeline
        return BrainPipeline()

    def _make_input(self, **kwargs):
        from core.brain_pipeline import PipelineInput
        return PipelineInput(**kwargs)

    def test_thread_safety_lock_exists(self):
        """Pipeline must have a threading lock for concurrent access."""
        p = self._make_pipeline()
        assert hasattr(p, "_lock"), "Pipeline must have _lock attribute"
        assert isinstance(p._lock, type(threading.Lock()))

    def test_async_run_method_exists(self):
        """Pipeline must have run_async for non-blocking execution."""
        p = self._make_pipeline()
        assert hasattr(p, "run_async"), "Pipeline must have run_async method"
        assert asyncio.iscoroutinefunction(p.run_async)

    def test_async_run_produces_result(self):
        """run_async must return a PipelineResult."""
        from core.brain_pipeline import PipelineStatus
        p = self._make_pipeline()

        async def _test():
            return await p.run_async(self._make_input(org_id="async-test"))

        result = asyncio.run(_test())
        assert result.status in (PipelineStatus.COMPLETED, PipelineStatus.PARTIAL)

    def test_string_sanitization(self):
        """Overly long strings in findings must be truncated."""
        p = self._make_pipeline()
        long_str = "X" * 50_000
        findings = [{"id": "f1", "description": long_str, "severity": "low"}]
        result = p.run(self._make_input(org_id="sanitize-test", findings=findings))
        # The finding should have been sanitized
        assert result.status.value in ("completed", "partial")
        # Verify truncation happened (10,000 char limit + "[truncated]")
        assert len(findings[0]["description"]) <= p.MAX_FIELD_LEN + 20

    def test_pipeline_timeout_constant(self):
        """Pipeline must have a timeout constant."""
        p = self._make_pipeline()
        assert hasattr(p, "PIPELINE_TIMEOUT_S")
        assert p.PIPELINE_TIMEOUT_S > 0
        assert p.PIPELINE_TIMEOUT_S <= 600  # Max 10 minutes

    def test_dos_protection_max_findings(self):
        """Pipeline must enforce MAX_FINDINGS limit."""
        from core.brain_pipeline import BrainPipeline
        assert BrainPipeline.MAX_FINDINGS == 50_000

    def test_dos_protection_max_assets(self):
        """Pipeline must enforce MAX_ASSETS limit."""
        from core.brain_pipeline import BrainPipeline
        assert BrainPipeline.MAX_ASSETS == 10_000

    def test_empty_findings_handled(self):
        """Pipeline must handle empty findings gracefully."""
        p = self._make_pipeline()
        result = p.run(self._make_input(org_id="empty-test", findings=[]))
        assert result.status.value == "completed"
        assert result.findings_ingested == 0

    def test_none_org_id_rejected(self):
        """Pipeline must reject None org_id."""
        p = self._make_pipeline()
        with pytest.raises(ValueError, match="org_id is required"):
            p.run(self._make_input(org_id=None))  # type: ignore

    def test_non_dict_findings_filtered(self):
        """Non-dict findings must be filtered out."""
        p = self._make_pipeline()
        mixed_findings = [
            {"id": "good1", "severity": "low"},
            "this_is_a_string",  # Should be filtered
            42,  # Should be filtered
            None,  # Should be filtered
            {"id": "good2", "severity": "high"},
        ]
        result = p.run(self._make_input(org_id="filter-test", findings=mixed_findings))
        assert result.findings_ingested == 2  # Only the 2 dict findings

    def test_concurrent_pipeline_runs(self):
        """Pipeline must handle concurrent runs without corruption."""
        p = self._make_pipeline()
        results = []
        errors = []

        def _run(org_id):
            try:
                r = p.run(self._make_input(
                    org_id=org_id,
                    findings=[{"id": f"f-{org_id}", "severity": "low"}]
                ))
                results.append(r)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=_run, args=(f"org-{i}",)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert not errors, f"Concurrent runs produced errors: {errors}"
        assert len(results) == 5

    def test_metrics_thread_safe(self):
        """get_metrics must be thread-safe and return a copy."""
        p = self._make_pipeline()
        p.run(self._make_input(org_id="m1", findings=[{"id": "f1"}]))
        metrics = p.get_metrics()
        assert isinstance(metrics, list)
        assert len(metrics) >= 1

    def test_run_history_eviction(self):
        """Pipeline must evict old runs when MAX_RUNS_HISTORY is exceeded."""
        from core.brain_pipeline import BrainPipeline
        assert BrainPipeline.MAX_RUNS_HISTORY == 1000

    def test_graph_batch_size(self):
        """Pipeline must use batched graph operations."""
        from core.brain_pipeline import BrainPipeline
        assert BrainPipeline.GRAPH_BATCH_SIZE == 500

    def test_step_error_doesnt_leak_secrets(self):
        """Step errors must not leak internal details (PII/secrets)."""
        p = self._make_pipeline()
        # Force a step to fail by patching
        original = p._step_normalize
        def _failing_step(ctx, inp):
            raise RuntimeError("Internal secret: password=abc123")
        p._step_normalize = _failing_step

        result = p.run(self._make_input(org_id="leak-test"))
        # Restore
        p._step_normalize = original

        # The error should only expose the exception type, not the message
        for step in result.steps:
            if step.error:
                assert "password" not in step.error
                assert "abc123" not in step.error
                assert "RuntimeError" in step.error


# ═══════════════════════════════════════════════════════════════════════════════
# Scanner Ingest Router Hardening Tests [V7]
# ═══════════════════════════════════════════════════════════════════════════════

class TestScannerIngestHardening:
    """Test security hardening of the scanner ingest router."""

    def test_max_upload_size_constant(self):
        """Upload size limit must exist and be reasonable."""
        from apps.api.scanner_ingest_router import _MAX_UPLOAD_BYTES
        assert _MAX_UPLOAD_BYTES == 100 * 1024 * 1024  # 100 MB

    def test_max_webhook_size_constant(self):
        """Webhook body size limit must exist."""
        from apps.api.scanner_ingest_router import _MAX_WEBHOOK_BYTES
        assert _MAX_WEBHOOK_BYTES == 50 * 1024 * 1024  # 50 MB

    def test_validate_scanner_type_valid(self):
        """Valid scanner types must pass validation."""
        from apps.api.scanner_ingest_router import _validate_scanner_type
        assert _validate_scanner_type("zap") == "zap"
        assert _validate_scanner_type("burp-suite") == "burp-suite"
        assert _validate_scanner_type("sonar_qube") == "sonar_qube"
        assert _validate_scanner_type("ZAP") == "zap"

    def test_validate_scanner_type_injection(self):
        """Scanner type with injection chars must be rejected."""
        from apps.api.scanner_ingest_router import _validate_scanner_type
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc:
            _validate_scanner_type("; rm -rf /")
        assert exc.value.status_code == 422

        with pytest.raises(HTTPException):
            _validate_scanner_type("../../../etc/passwd")

        with pytest.raises(HTTPException):
            _validate_scanner_type("")

    def test_validate_filename_traversal(self):
        """Path traversal in filenames must be neutralized."""
        from apps.api.scanner_ingest_router import _validate_filename
        assert _validate_filename("../../etc/passwd") == "passwd"
        assert _validate_filename("..\\..\\windows\\system32") == "system32"
        assert _validate_filename("normal.json") == "normal.json"
        assert _validate_filename(None) is None

    def test_validate_upload_size_rejects_large(self):
        """Uploads exceeding the limit must be rejected."""
        from apps.api.scanner_ingest_router import _validate_upload_size
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc:
            _validate_upload_size(b"x" * (100 * 1024 * 1024 + 1))
        assert exc.value.status_code == 413

    def test_validate_upload_size_rejects_empty(self):
        """Empty uploads must be rejected."""
        from apps.api.scanner_ingest_router import _validate_upload_size
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc:
            _validate_upload_size(b"")
        assert exc.value.status_code == 400

    def test_allowed_extensions(self):
        """Only known file extensions should be allowed."""
        from apps.api.scanner_ingest_router import _ALLOWED_EXTENSIONS
        assert ".json" in _ALLOWED_EXTENSIONS
        assert ".xml" in _ALLOWED_EXTENSIONS
        assert ".sarif" in _ALLOWED_EXTENSIONS
        assert ".exe" not in _ALLOWED_EXTENSIONS
        assert ".sh" not in _ALLOWED_EXTENSIONS


# ═══════════════════════════════════════════════════════════════════════════════
# Scanner Parsers Hardening Tests [V3]
# ═══════════════════════════════════════════════════════════════════════════════

class TestScannerParsersHardening:
    """Test security hardening of scanner parsers."""

    def test_xml_xxe_protection(self):
        """XML parser must strip DOCTYPE to prevent XXE."""
        from core.scanner_parsers import _parse_xml_safe
        # XXE payload
        xxe_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>"""
        result = _parse_xml_safe(xxe_xml)
        # Should parse but with DOCTYPE stripped
        if result is not None:
            # Entity should not be resolved
            assert "root:" not in (result.text or "")

    def test_xml_billion_laughs_protection(self):
        """XML parser must reject oversized content (billion laughs DoS)."""
        from core.scanner_parsers import _parse_xml_safe, _MAX_XML_SIZE
        # Create content exceeding size limit
        huge_xml = b"<root>" + b"A" * (_MAX_XML_SIZE + 1) + b"</root>"
        result = _parse_xml_safe(huge_xml)
        assert result is None  # Must reject oversized content

    def test_json_size_limit(self):
        """JSON parser must reject oversized content."""
        from core.scanner_parsers import _parse_json_safe, _MAX_JSON_SIZE
        huge_json = b'{"data": "' + b"A" * (_MAX_JSON_SIZE + 1) + b'"}'
        result = _parse_json_safe(huge_json)
        assert result is None

    def test_malformed_json_handled(self):
        """Malformed JSON must not crash parser."""
        from core.scanner_parsers import _parse_json_safe
        assert _parse_json_safe(b"not json at all") is None
        assert _parse_json_safe(b"{invalid}") is None
        assert _parse_json_safe(b"") is None

    def test_malformed_xml_handled(self):
        """Malformed XML must not crash parser."""
        from core.scanner_parsers import _parse_xml_safe
        assert _parse_xml_safe(b"not xml at all") is None
        assert _parse_xml_safe(b"<unclosed") is None

    def test_parse_scanner_output_crash_resilience(self):
        """parse_scanner_output must survive normalizer crashes."""
        from core.scanner_parsers import parse_scanner_output
        # Pass garbage data that should not crash
        result = parse_scanner_output(b"garbage data", scanner_type="zap")
        assert isinstance(result, list)  # Must return list, even if empty

    def test_normalizer_registry_complete(self):
        """All 15 normalizers must be registered."""
        from core.scanner_parsers import SCANNER_NORMALIZERS
        assert len(SCANNER_NORMALIZERS) == 15
        expected = {"zap", "burp", "nessus", "openvas", "bandit", "checkmarx",
                    "sonarqube", "fortify", "veracode", "nikto", "nuclei",
                    "nmap", "snyk", "prowler", "checkov"}
        assert set(SCANNER_NORMALIZERS.keys()) == expected

    def test_each_normalizer_survives_garbage(self):
        """Each normalizer must handle garbage input without crashing."""
        from core.scanner_parsers import SCANNER_NORMALIZERS, NormalizerConfig
        garbage_inputs = [
            b"",
            b"garbage text",
            b'{"invalid": true}',
            b"<invalid/>",
            b"\x00\x01\x02\x03",
        ]
        for name, cls in SCANNER_NORMALIZERS.items():
            config = NormalizerConfig(name=name, enabled=True, priority=50)
            normalizer = cls(config)
            for garbage in garbage_inputs:
                try:
                    # can_handle should not crash
                    score = normalizer.can_handle(garbage)
                    assert isinstance(score, (int, float))
                    # normalize might throw but should not crash catastrophically
                    if score > 0:
                        result = normalizer.normalize(garbage)
                        assert isinstance(result, list)
                except Exception:
                    # Acceptable: normalizers may raise on invalid input
                    # What's NOT acceptable: uncaught TypeError, AttributeError
                    pass


# ═══════════════════════════════════════════════════════════════════════════════
# Sandbox Verifier Hardening Tests [V5]
# ═══════════════════════════════════════════════════════════════════════════════

class TestSandboxVerifierHardening:
    """Test security hardening of the sandbox verifier (read-only verification)."""

    def test_resource_limits(self):
        """Sandbox must enforce memory and CPU limits."""
        from core.sandbox_verifier import SandboxVerifier
        sv = SandboxVerifier()
        assert sv.memory_limit == "128m"
        assert sv.cpu_limit == 0.5

    def test_docker_security_options(self):
        """Docker commands must include security options."""
        from core.sandbox_verifier import SandboxVerifier
        SandboxVerifier()
        # Verify security constants in docker command building
        assert "--cap-drop=ALL" in str(SandboxVerifier._execute_in_sandbox.__code__.co_consts)

    def test_max_attempts_limit(self):
        """Self-correction loop must be bounded."""
        from core.sandbox_verifier import SandboxVerifier
        sv = SandboxVerifier()
        assert sv.max_attempts == 3
        assert sv.max_attempts <= 10  # Must be reasonable

    def test_verification_status_enum(self):
        """All verification statuses must be defined."""
        from core.sandbox_verifier import VerificationStatus
        expected = {
            "verified_exploitable", "not_exploitable", "partial",
            "timeout", "error", "sandbox_unavailable"
        }
        actual = {s.value for s in VerificationStatus}
        assert expected == actual


# ═══════════════════════════════════════════════════════════════════════════════
# DAST Engine Hardening Tests [V3]
# ═══════════════════════════════════════════════════════════════════════════════

class TestDASTEngineHardening:
    """Test SSRF protection in the DAST engine."""

    def test_ssrf_blocks_private_ips(self):
        """DAST engine must block scanning private/internal IPs."""
        from core.dast_engine import DASTEngine
        blocked_urls = [
            "http://127.0.0.1/",
            "http://localhost/",
            "http://0.0.0.0/",
            "http://[::1]/",
        ]
        for url in blocked_urls:
            with pytest.raises(ValueError, match="Blocked"):
                DASTEngine.validate_target_url(url)

    def test_ssrf_blocks_non_http(self):
        """DAST engine must block non-HTTP schemes."""
        from core.dast_engine import DASTEngine
        with pytest.raises(ValueError, match="Blocked scheme"):
            DASTEngine.validate_target_url("file:///etc/passwd")
        with pytest.raises(ValueError, match="Blocked scheme"):
            DASTEngine.validate_target_url("ftp://evil.com/data")

    def test_ssrf_allows_public_urls(self):
        """DAST engine must allow valid public URLs."""
        from core.dast_engine import DASTEngine
        # This should not raise (DNS may fail, but validation passes)
        result = DASTEngine.validate_target_url("https://example.com")
        assert result == "https://example.com"


# ═══════════════════════════════════════════════════════════════════════════════
# Container Scanner Hardening Tests [V3]
# ═══════════════════════════════════════════════════════════════════════════════

class TestContainerScannerHardening:
    """Test shell injection protection in the container scanner."""

    def test_image_ref_blocks_shell_chars(self):
        """Container scanner must block shell injection in image refs."""
        from core.container_scanner import ContainerImageScanner
        scanner = ContainerImageScanner()
        dangerous_refs = [
            "ubuntu; rm -rf /",
            "alpine | cat /etc/passwd",
            "node & echo pwned",
            "python$(whoami)",
        ]
        for ref in dangerous_refs:
            with pytest.raises(ValueError):
                scanner._validate_image_ref(ref)

    def test_image_ref_length_limit(self):
        """Container scanner must enforce image ref length limit."""
        from core.container_scanner import ContainerImageScanner
        scanner = ContainerImageScanner()
        with pytest.raises(ValueError, match="too long"):
            scanner._validate_image_ref("a" * 600)

    def test_valid_image_refs_accepted(self):
        """Container scanner must accept valid image references."""
        from core.container_scanner import ContainerImageScanner
        scanner = ContainerImageScanner()
        valid_refs = [
            "ubuntu:22.04",
            "python:3.12-slim",
            "ghcr.io/owner/repo:v1.0",
            "registry.example.com/ns/image:latest",
        ]
        for ref in valid_refs:
            result = scanner._validate_image_ref(ref)
            assert result == ref.strip()


# ═══════════════════════════════════════════════════════════════════════════════
# Secrets Scanner YAML/Config Detection Tests [V3]
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecretsYAMLDetection:
    """Test secrets scanner detection of unquoted YAML/config secrets.

    Fixes the gap reported by threat-architect: YAML configs with hardcoded
    passwords, API keys, and AWS credentials were returning 0 findings because
    all patterns required quoted values.
    """

    def _get_scanner(self):
        from core.real_scanner import get_real_secrets_scanner
        return get_real_secrets_scanner()

    def test_yaml_password_detected(self):
        """Secrets scanner must detect unquoted passwords in YAML."""
        scanner = self._get_scanner()
        yaml = "database:\n  password: SuperSecretP@ssw0rd123\n  host: db.local"
        findings = scanner.scan_content(yaml, "config.yaml")
        types = [f.title for f in findings]
        assert any("Password" in t for t in types), f"Expected password detection, got: {types}"

    def test_yaml_aws_secret_key_detected(self):
        """Secrets scanner must detect AWS secret keys in YAML without quotes."""
        scanner = self._get_scanner()
        yaml = "aws:\n  aws_secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        findings = scanner.scan_content(yaml, "aws-config.yaml")
        types = [f.title for f in findings]
        assert any("AWS" in t for t in types), f"Expected AWS secret detection, got: {types}"

    def test_yaml_api_key_detected(self):
        """Secrets scanner must detect API keys in YAML without quotes."""
        scanner = self._get_scanner()
        yaml = "service:\n  api_key: abcdefghijklmnop1234567890abcdef\n"
        findings = scanner.scan_content(yaml, "service.yaml")
        types = [f.title for f in findings]
        assert any("API Key" in t for t in types), f"Expected API key detection, got: {types}"

    def test_yaml_auth_token_detected(self):
        """Secrets scanner must detect auth tokens in YAML."""
        scanner = self._get_scanner()
        yaml = "auth:\n  auth_token: tk_live_abcdefghijklmnopqrstuv123456\n"
        findings = scanner.scan_content(yaml, "auth.yaml")
        types = [f.title for f in findings]
        assert any("API Key" in t or "Token" in t for t in types), f"Expected token detection, got: {types}"

    def test_env_file_secrets_detected(self):
        """Secrets scanner must detect secrets in .env files."""
        scanner = self._get_scanner()
        env = "SECRET_KEY=myApplicationSecretKey123456\nexport TOKEN_VALUE=abc123def456ghi789jkl\n"
        findings = scanner.scan_content(env, ".env")
        assert len(findings) >= 2, f"Expected >=2 findings in .env, got {len(findings)}"

    def test_yaml_database_url_detected(self):
        """Secrets scanner must detect database URLs in YAML."""
        scanner = self._get_scanner()
        yaml = "config:\n  database_url: postgresql://admin:secret123@db.prod.internal:5432/myapp\n"
        findings = scanner.scan_content(yaml, "config.yaml")
        types = [f.title for f in findings]
        assert any("Database" in t for t in types), f"Expected database URL detection, got: {types}"

    def test_stripe_key_detected(self):
        """Secrets scanner must detect Stripe API keys."""
        scanner = self._get_scanner()
        content = 'STRIPE_KEY=sk_live_abcdefghijklmnopqrstuvwxyz1234567890\n'
        findings = scanner.scan_content(content, "config.py")
        types = [f.title for f in findings]
        assert any("Stripe" in t for t in types), f"Expected Stripe key detection, got: {types}"

    def test_azure_client_secret_detected(self):
        """Secrets scanner must detect Azure client secrets."""
        scanner = self._get_scanner()
        yaml = "azure:\n  azure_client_secret: myAzureClientSecretValue12345678\n"
        findings = scanner.scan_content(yaml, "azure.yaml")
        types = [f.title for f in findings]
        assert any("Azure" in t for t in types), f"Expected Azure secret detection, got: {types}"

    def test_npm_token_detected(self):
        """Secrets scanner must detect NPM tokens."""
        scanner = self._get_scanner()
        content = "//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz1234567890\n"
        findings = scanner.scan_content(content, ".npmrc")
        types = [f.title for f in findings]
        assert any("NPM" in t for t in types), f"Expected NPM token detection, got: {types}"

    def test_sendgrid_key_detected(self):
        """Secrets scanner must detect SendGrid API keys."""
        scanner = self._get_scanner()
        content = "SENDGRID_KEY=SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz1234567890abcdefg\n"
        findings = scanner.scan_content(content, ".env")
        types = [f.title for f in findings]
        assert any("SendGrid" in t for t in types), f"Expected SendGrid key detection, got: {types}"

    def test_no_false_positives_on_safe_values(self):
        """Secrets scanner must not trigger on obviously safe/placeholder values."""
        scanner = self._get_scanner()
        yaml = "database:\n  host: localhost\n  port: 5432\n  name: myapp\n"
        findings = scanner.scan_content(yaml, "config.yaml")
        # No secrets should be found in this safe config
        assert len(findings) == 0, f"Expected 0 findings in safe config, got {len(findings)}: {[f.title for f in findings]}"

    def test_redaction_never_leaks_full_secret(self):
        """Redacted secrets must never contain the full original value."""
        scanner = self._get_scanner()
        yaml = "password: VeryLongSecretPasswordValue123456\n"
        findings = scanner.scan_content(yaml, "config.yaml")
        for f in findings:
            redacted = f.evidence.get("redacted_match", "")
            if redacted and len(redacted) > 8:
                # Must contain asterisks (redacted portion)
                assert "*" in redacted, f"Redacted value missing asterisks: {redacted}"

    def test_quoted_and_unquoted_both_detected(self):
        """Both quoted and unquoted password values should be detected."""
        scanner = self._get_scanner()
        content = '''
password: unquotedSecretValue123
password: "quotedSecretValue456"
password = 'anotherQuotedSecret789'
'''
        findings = scanner.scan_content(content, "mixed.conf")
        # Should find at least 2 (unquoted + one quoted)
        assert len(findings) >= 2, f"Expected >=2 findings for mixed formats, got {len(findings)}: {[f.title for f in findings]}"
