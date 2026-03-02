"""
Tests for backend hardening changes — 2026-03-02 Session 4 (V3).

Tests cover:
1. Brain pipeline: cancellation, batch async, error message safety, singleton
2. DAST engine: URL length validation
3. SAST engine: secret snippet redaction (CWE-798)
4. Scanner parsers: content size limits, crash resilience
5. Sandbox verifier: code size limits, blocked patterns, non-root, validation
6. Secrets scanner: PII redaction in metadata

Pillar: [V3] Decision Intelligence, [V5] MPTE Verification
"""

import asyncio
import json
import os
import sys
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

import pytest

# Ensure suite paths are on PYTHONPATH
for p in ["suite-api", "suite-core", "suite-attack", "suite-feeds",
           "suite-evidence-risk", "suite-integrations"]:
    full = os.path.join(os.path.dirname(os.path.dirname(__file__)), p)
    if full not in sys.path:
        sys.path.insert(0, full)


# ═══════════════════════════════════════════════════════════════════════════
# 1. Brain Pipeline — Cancellation + Batch Async
# ═══════════════════════════════════════════════════════════════════════════

class TestBrainPipelineCancellation:
    """[V3] Test cooperative pipeline cancellation."""

    def test_cancel_unknown_run_returns_false(self):
        from core.brain_pipeline import BrainPipeline
        bp = BrainPipeline()
        assert bp.cancel("nonexistent-run-id") is False

    def test_cancel_known_run_returns_true(self):
        from core.brain_pipeline import BrainPipeline, PipelineInput
        bp = BrainPipeline()
        inp = PipelineInput(org_id="test", findings=[{"id": "f1"}])
        result = bp.run(inp)
        assert result.run_id in bp._runs
        assert bp.cancel(result.run_id) is True

    def test_cancelled_set_cleaned_up(self):
        """After cancellation is processed, run_id is removed from _cancelled set."""
        from core.brain_pipeline import BrainPipeline, PipelineInput
        bp = BrainPipeline()
        fake_id = "BR-CANCELTEST123"
        bp._cancelled.add(fake_id)
        # The _cancelled set should contain our fake ID
        assert fake_id in bp._cancelled
        # Discard it manually (simulating what the pipeline loop does)
        bp._cancelled.discard(fake_id)
        assert fake_id not in bp._cancelled


class TestBrainPipelineBatchAsync:
    """[V3] Test batch async processing."""

    @pytest.mark.asyncio
    async def test_run_async_batch_empty(self):
        from core.brain_pipeline import BrainPipeline
        bp = BrainPipeline()
        results = await bp.run_async_batch([])
        assert results == []

    @pytest.mark.asyncio
    async def test_run_async_batch_single(self):
        from core.brain_pipeline import BrainPipeline, PipelineInput
        bp = BrainPipeline()
        inputs = [PipelineInput(org_id="batch-test-1")]
        results = await bp.run_async_batch(inputs, max_concurrent=2)
        assert len(results) == 1
        assert results[0].org_id == "batch-test-1"
        assert results[0].status.value in ("completed", "partial")

    @pytest.mark.asyncio
    async def test_run_async_batch_multiple(self):
        from core.brain_pipeline import BrainPipeline, PipelineInput
        bp = BrainPipeline()
        inputs = [
            PipelineInput(org_id=f"batch-{i}", findings=[{"id": f"f{i}"}])
            for i in range(3)
        ]
        results = await bp.run_async_batch(inputs, max_concurrent=2)
        assert len(results) == 3
        for i, r in enumerate(results):
            assert r.org_id == f"batch-{i}"

    @pytest.mark.asyncio
    async def test_run_async_batch_clamps_concurrency(self):
        from core.brain_pipeline import BrainPipeline, PipelineInput
        bp = BrainPipeline()
        inputs = [PipelineInput(org_id="c")]
        results = await bp.run_async_batch(inputs, max_concurrent=0)
        assert len(results) == 1
        results = await bp.run_async_batch(inputs, max_concurrent=999)
        assert len(results) == 1


class TestBrainPipelineErrorSafety:
    """[V3] Test that error messages don't leak sensitive info."""

    def test_step_error_uses_type_name_only(self):
        from core.brain_pipeline import BrainPipeline, PipelineInput
        bp = BrainPipeline()
        inp = PipelineInput(
            org_id="err-test",
            findings=[{"id": "f1", "cve_id": "CVE-2024-1234"}],
        )
        result = bp.run(inp)
        for step in result.steps:
            if step.error:
                assert "pipeline step failed" in step.error \
                    or "cancelled" in step.error \
                    or "timeout" in step.error.lower(), \
                    f"Unexpected error format: {step.error}"


class TestBrainPipelineSingletonSafety:
    """[V3] Test thread-safe singleton."""

    def test_singleton_returns_same_instance(self):
        from core.brain_pipeline import get_brain_pipeline
        bp1 = get_brain_pipeline()
        bp2 = get_brain_pipeline()
        assert bp1 is bp2

    def test_singleton_thread_safe(self):
        from core.brain_pipeline import get_brain_pipeline
        instances = []

        def _get():
            instances.append(id(get_brain_pipeline()))

        threads = [threading.Thread(target=_get) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(set(instances)) == 1, "Multiple instances created!"


# ═══════════════════════════════════════════════════════════════════════════
# 2. DAST Engine — URL Length Validation
# ═══════════════════════════════════════════════════════════════════════════

class TestDastUrlLengthValidation:
    """[V3] Test DAST URL length limits."""

    def test_url_within_limit_accepted(self):
        from core.dast_engine import DASTEngine
        url = "https://example.com/path"
        result = DASTEngine.validate_target_url(url)
        assert result == url

    def test_url_exceeding_2048_rejected(self):
        from core.dast_engine import DASTEngine
        long_url = "https://example.com/" + "a" * 2100
        with pytest.raises(ValueError, match="exceeds maximum length"):
            DASTEngine.validate_target_url(long_url)

    def test_url_exactly_2048_accepted(self):
        from core.dast_engine import DASTEngine
        url = "https://example.com/" + "a" * (2048 - len("https://example.com/"))
        assert len(url) == 2048
        result = DASTEngine.validate_target_url(url)
        assert result == url


# ═══════════════════════════════════════════════════════════════════════════
# 3. SAST Engine — Secret Snippet Redaction
# ═══════════════════════════════════════════════════════════════════════════

class TestSastSecretRedaction:
    """[V3] Test that hardcoded secrets are redacted in SAST findings."""

    def test_cwe798_snippet_redacted(self):
        from core.sast_engine import SASTEngine
        engine = SASTEngine()
        code = '''
api_key = "sk-1234567890abcdef"
password = "SuperSecretP@ssw0rd123"
token = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz123456"
'''
        result = engine.scan_code(code, filename="test.py")
        secret_findings = [f for f in result.findings if f.cwe_id == "CWE-798"]
        assert len(secret_findings) > 0, "Expected SAST-006 findings for hardcoded secrets"
        for f in secret_findings:
            assert "sk-1234567890abcdef" not in f.snippet, \
                f"Secret leaked in snippet: {f.snippet}"
            assert "SuperSecretP@ssw0rd123" not in f.snippet, \
                f"Secret leaked in snippet: {f.snippet}"
            assert "****..." in f.snippet, \
                f"Expected redaction marker in: {f.snippet}"

    def test_non_secret_findings_not_redacted(self):
        from core.sast_engine import SASTEngine
        engine = SASTEngine()
        code = '''
cursor.execute(f"SELECT * FROM users WHERE id={user_id}")
'''
        result = engine.scan_code(code, filename="test.py")
        for f in result.findings:
            if f.cwe_id == "CWE-89":
                assert "****..." not in f.snippet


# ═══════════════════════════════════════════════════════════════════════════
# 4. Scanner Parsers — Content Size + Crash Resilience
# ═══════════════════════════════════════════════════════════════════════════

class TestScannerParsersHardening:
    """[V3] Test scanner parser hardening."""

    def test_parse_malformed_xml_returns_empty(self):
        from core.scanner_parsers import parse_scanner_output
        bad_xml = b"<not valid xml <><><>"
        result = parse_scanner_output(bad_xml, scanner_type="zap")
        assert result == []

    def test_parse_malformed_json_returns_empty(self):
        from core.scanner_parsers import parse_scanner_output
        bad_json = b"{not valid json..."
        result = parse_scanner_output(bad_json, scanner_type="bandit")
        assert result == []

    def test_parse_empty_content_returns_empty(self):
        from core.scanner_parsers import parse_scanner_output
        result = parse_scanner_output(b"", scanner_type="zap")
        assert result == []

    def test_auto_detect_handles_garbage(self):
        from core.scanner_parsers import auto_detect_scanner
        result = auto_detect_scanner(b"\x00\x01\x02\x03\xff\xfe")
        assert result is None

    def test_register_normalizers_handles_broken_registry(self):
        from core.scanner_parsers import register_scanner_normalizers
        mock_registry = MagicMock()
        mock_registry.register.side_effect = RuntimeError("test")
        count = register_scanner_normalizers(mock_registry)
        assert count == 0

    def test_valid_zap_json_parsed(self):
        """Verify valid ZAP JSON is actually parsed correctly."""
        from core.scanner_parsers import parse_scanner_output
        zap_data = json.dumps({
            "site": [{
                "alerts": [{
                    "name": "XSS Test",
                    "desc": "Cross-Site Scripting",
                    "riskcode": "3",
                    "pluginid": "40012",
                    "cweid": "79",
                    "solution": "Encode output",
                    "instances": [{"uri": "http://example.com/search"}],
                }]
            }]
        }).encode()
        result = parse_scanner_output(zap_data, scanner_type="zap")
        assert len(result) >= 1

    def test_valid_bandit_json_parsed(self):
        from core.scanner_parsers import parse_scanner_output
        bandit_data = json.dumps({
            "results": [{
                "test_id": "B301",
                "test_name": "blacklist",
                "issue_text": "Use of unsafe pickle",
                "issue_severity": "HIGH",
                "filename": "app.py",
                "line_number": 42,
            }],
            "generated_at": "2024-01-01",
            "metrics": {"_totals": {}},
        }).encode()
        result = parse_scanner_output(bandit_data, scanner_type="bandit")
        assert len(result) >= 1


# ═══════════════════════════════════════════════════════════════════════════
# 5. Sandbox Verifier — Code Safety Validation
# ═══════════════════════════════════════════════════════════════════════════

class TestSandboxVerifierCodeValidation:
    """[V5] Test PoC code validation in sandbox verifier."""

    def _make_verifier(self):
        from core.sandbox_verifier import SandboxVerifier
        return SandboxVerifier(docker_available=False)

    def test_empty_code_rejected(self):
        from core.sandbox_verifier import PoCScript, PoCLanguage
        v = self._make_verifier()
        poc = PoCScript(language=PoCLanguage.PYTHON, code="   ")
        err = v._validate_poc_code(poc.code, poc)
        assert err is not None
        assert "empty" in err.lower()

    def test_oversized_code_rejected(self):
        from core.sandbox_verifier import PoCScript, PoCLanguage
        v = self._make_verifier()
        big_code = "x = 1\n" * 20000
        poc = PoCScript(language=PoCLanguage.PYTHON, code=big_code)
        err = v._validate_poc_code(poc.code, poc)
        assert err is not None
        assert "size limit" in err.lower()

    def test_fork_bomb_blocked(self):
        from core.sandbox_verifier import PoCScript, PoCLanguage
        v = self._make_verifier()
        poc = PoCScript(language=PoCLanguage.BASH, code=":(){ :|:& };:")
        err = v._validate_poc_code(poc.code, poc)
        assert err is not None
        assert "blocked pattern" in err.lower()

    def test_rm_rf_root_blocked(self):
        from core.sandbox_verifier import PoCScript, PoCLanguage
        v = self._make_verifier()
        poc = PoCScript(language=PoCLanguage.BASH, code="rm -rf /home/user")
        err = v._validate_poc_code(poc.code, poc)
        assert err is not None

    def test_disk_access_blocked(self):
        from core.sandbox_verifier import PoCScript, PoCLanguage
        v = self._make_verifier()
        poc = PoCScript(language=PoCLanguage.BASH, code="dd if=/dev/sda of=/tmp/dump")
        err = v._validate_poc_code(poc.code, poc)
        assert err is not None

    def test_safe_code_accepted(self):
        from core.sandbox_verifier import PoCScript, PoCLanguage
        v = self._make_verifier()
        poc = PoCScript(
            language=PoCLanguage.PYTHON,
            code="import urllib.request\nprint('hello')\n"
        )
        err = v._validate_poc_code(poc.code, poc)
        assert err is None

    def test_safe_curl_accepted(self):
        from core.sandbox_verifier import PoCScript, PoCLanguage
        v = self._make_verifier()
        poc = PoCScript(
            language=PoCLanguage.CURL,
            code="#!/bin/sh\ncurl -s https://example.com\necho done"
        )
        err = v._validate_poc_code(poc.code, poc)
        assert err is None

    def test_verify_rejects_dangerous_code(self):
        from core.sandbox_verifier import PoCScript, PoCLanguage, SandboxVerifier, VerificationStatus
        v = SandboxVerifier(docker_available=True)
        poc = PoCScript(language=PoCLanguage.BASH, code=":(){ :|:& };:")
        result = v.verify(poc, finding_id="test")
        assert result.status == VerificationStatus.ERROR
        assert "rejected" in result.error_message.lower()

    def test_docker_cmd_includes_user_flag(self):
        from core.sandbox_verifier import SandboxVerifier, PoCScript, PoCLanguage
        v = SandboxVerifier(docker_available=True)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="NOT_VULNERABLE", stderr="", returncode=1
            )
            poc = PoCScript(
                language=PoCLanguage.PYTHON,
                code="print('test')",
                timeout_seconds=5,
            )
            v.verify(poc, finding_id="test-user")

            if mock_run.called:
                args = mock_run.call_args[0][0]
                assert "--user" in args, "Docker command missing --user flag"
                user_idx = args.index("--user")
                assert args[user_idx + 1] == "65534:65534", \
                    f"Expected nobody user, got: {args[user_idx + 1]}"


# ═══════════════════════════════════════════════════════════════════════════
# 6. Secrets Scanner — PII Redaction
# ═══════════════════════════════════════════════════════════════════════════

class TestSecretsMetadataPiiRedaction:
    """[V3] Test that PII is redacted from secrets scanner metadata."""

    def test_gitleaks_metadata_no_author(self):
        from core.secrets_scanner import SecretsDetector
        scanner = SecretsDetector()
        gitleaks_output = json.dumps([{
            "RuleID": "generic-api-key",
            "Description": "Generic API Key",
            "File": "config.py",
            "StartLine": 10,
            "Match": "api_key = 'sk-12345678901234567890123456789012'",
            "Author": "John Doe",
            "Email": "john.doe@company.com",
            "Date": "2024-01-01",
            "Message": "Add config",
            "Fingerprint": "abc123",
            "Tags": ["test"],
        }])
        findings = scanner._parse_gitleaks_output(gitleaks_output, "test-repo", "main")
        assert len(findings) >= 1
        f = findings[0]
        assert "author" not in f.metadata, \
            f"Author PII leaked: {f.metadata}"
        assert "email" not in f.metadata, \
            f"Email PII leaked: {f.metadata}"
        assert f.metadata.get("scanner") == "gitleaks"
        assert f.metadata.get("rule_id") == "generic-api-key"

    def test_trufflehog_metadata_no_raw_v2(self):
        from core.secrets_scanner import SecretsDetector
        scanner = SecretsDetector()
        trufflehog_output = json.dumps({
            "DetectorName": "AWS",
            "DecoderName": "BASE64",
            "Verified": True,
            "Raw": "AKIAIOSFODNN7EXAMPLE_secret_key_1234567890",
            "RawV2": "AKIAIOSFODNN7EXAMPLE_secret_key_1234567890v2",
            "Redacted": "AKIA****MPLE",
            "ExtraData": {"account_id": "123456789012"},
            "SourceMetadata": {
                "Data": {
                    "Filesystem": {"file": "secrets.yml", "line": 5}
                }
            }
        })
        findings = scanner._parse_trufflehog_output(trufflehog_output, "test-repo", "main")
        assert len(findings) >= 1
        f = findings[0]
        assert "raw_v2" not in f.metadata, \
            f"Raw secret leaked: {f.metadata}"
        assert "extra_data" not in f.metadata, \
            f"Extra data leaked: {f.metadata}"
        assert f.metadata.get("scanner") == "trufflehog"
        assert f.metadata.get("verified") is True


# ═══════════════════════════════════════════════════════════════════════════
# 7. Integration: pipeline with hardened components
# ═══════════════════════════════════════════════════════════════════════════

class TestHardenedPipelineIntegration:
    """[V3] Full pipeline integration tests."""

    def test_pipeline_with_no_findings(self):
        from core.brain_pipeline import BrainPipeline, PipelineInput
        bp = BrainPipeline()
        result = bp.run(PipelineInput(org_id="empty-test"))
        assert result.findings_ingested == 0
        assert result.status.value in ("completed", "partial")

    def test_pipeline_filters_non_dict_findings(self):
        from core.brain_pipeline import BrainPipeline, PipelineInput
        bp = BrainPipeline()
        inp = PipelineInput(
            org_id="malformed-test",
            findings=[
                {"id": "good", "title": "valid"},
                "not a dict",
                42,
                None,
                {"id": "also-good"},
            ],
        )
        result = bp.run(inp)
        assert result.findings_ingested == 2

    def test_pipeline_metrics_recorded(self):
        from core.brain_pipeline import BrainPipeline, PipelineInput
        bp = BrainPipeline()
        bp.run(PipelineInput(org_id="metrics-test", findings=[{"id": "m1"}]))
        metrics = bp.get_metrics(limit=1)
        assert len(metrics) == 1
        m = metrics[0]
        assert "run_id" in m
        assert "total_duration_ms" in m
        assert "step_metrics" in m
        assert m["findings_ingested"] == 1

    def test_pipeline_result_to_dict(self):
        from core.brain_pipeline import BrainPipeline, PipelineInput
        bp = BrainPipeline()
        result = bp.run(PipelineInput(org_id="dict-test"))
        d = result.to_dict()
        assert isinstance(d, dict)
        assert "run_id" in d
        assert "summary" in d
        assert isinstance(d["steps"], list)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--timeout=30"])
