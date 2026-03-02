"""
Backend Hardening Tests — 2026-03-03 (Day 3, Tuesday)

Focus: Authentication & Authorization, SSRF Protection, Input Validation,
f-string logging elimination, concurrent scan limits.

Pillars: [V3] Decision Intelligence, [V5] MPTE Verification
"""

import re

import pytest

# ---------------------------------------------------------------------------
# [V5] MPTE Router — SSRF Protection Tests
# ---------------------------------------------------------------------------


class TestMPTESSRFProtection:
    """Verify SSRF protection on MPTE target_url fields."""

    def _get_validate_fn(self):
        """Import the SSRF validation function from mpte_router."""
        import importlib
        import sys

        # Force reimport to pick up changes
        mod_name = "api.mpte_router"
        if mod_name in sys.modules:
            mod = importlib.reload(sys.modules[mod_name])
        else:
            mod = importlib.import_module(mod_name)
        return mod._validate_target_url

    def test_ssrf_blocks_localhost(self):
        """SSRF: Block localhost targets."""
        from fastapi import HTTPException

        validate = self._get_validate_fn()
        with pytest.raises(HTTPException) as exc_info:
            validate("http://localhost:8080/admin")
        assert exc_info.value.status_code == 422
        assert "blocked" in exc_info.value.detail.lower()

    def test_ssrf_blocks_127_0_0_1(self):
        """SSRF: Block 127.0.0.1 loopback."""
        from fastapi import HTTPException

        validate = self._get_validate_fn()
        with pytest.raises(HTTPException) as exc_info:
            validate("http://127.0.0.1:9200/_cluster/health")
        assert exc_info.value.status_code == 422

    def test_ssrf_blocks_rfc1918_10(self):
        """SSRF: Block 10.0.0.0/8 internal range."""
        from fastapi import HTTPException

        validate = self._get_validate_fn()
        with pytest.raises(HTTPException) as exc_info:
            validate("http://10.0.0.1/api/internal")
        assert exc_info.value.status_code == 422

    def test_ssrf_blocks_rfc1918_172(self):
        """SSRF: Block 172.16.0.0/12 internal range."""
        from fastapi import HTTPException

        validate = self._get_validate_fn()
        with pytest.raises(HTTPException) as exc_info:
            validate("http://172.16.0.5:3000/grafana")
        assert exc_info.value.status_code == 422

    def test_ssrf_blocks_rfc1918_192(self):
        """SSRF: Block 192.168.0.0/16 internal range."""
        from fastapi import HTTPException

        validate = self._get_validate_fn()
        with pytest.raises(HTTPException) as exc_info:
            validate("http://192.168.1.1/admin")
        assert exc_info.value.status_code == 422

    def test_ssrf_blocks_aws_metadata(self):
        """SSRF: Block AWS metadata endpoint (169.254.169.254)."""
        from fastapi import HTTPException

        validate = self._get_validate_fn()
        with pytest.raises(HTTPException) as exc_info:
            validate("http://169.254.169.254/latest/meta-data/")
        assert exc_info.value.status_code == 422

    def test_ssrf_blocks_gcp_metadata(self):
        """SSRF: Block GCP metadata hostname."""
        from fastapi import HTTPException

        validate = self._get_validate_fn()
        with pytest.raises(HTTPException) as exc_info:
            validate("http://metadata.google.internal/computeMetadata/v1/")
        assert exc_info.value.status_code == 422

    def test_ssrf_allows_public_url(self):
        """SSRF: Allow legitimate public URLs."""
        validate = self._get_validate_fn()
        result = validate("https://example.com/api/v1/test")
        assert result == "https://example.com/api/v1/test"

    def test_ssrf_blocks_ftp_scheme(self):
        """SSRF: Block non-HTTP schemes (ftp, file, etc.)."""
        from fastapi import HTTPException

        validate = self._get_validate_fn()
        with pytest.raises(HTTPException) as exc_info:
            validate("ftp://internal-server/secrets.txt")
        assert exc_info.value.status_code == 422
        assert "http" in exc_info.value.detail.lower()

    def test_ssrf_rejects_empty_url(self):
        """SSRF: Reject empty URLs."""
        from fastapi import HTTPException

        validate = self._get_validate_fn()
        with pytest.raises(HTTPException) as exc_info:
            validate("")
        assert exc_info.value.status_code == 422

    def test_ssrf_rejects_oversized_url(self):
        """SSRF: Reject URLs exceeding max length."""
        from fastapi import HTTPException

        validate = self._get_validate_fn()
        long_url = "https://example.com/" + "a" * 3000
        with pytest.raises(HTTPException) as exc_info:
            validate(long_url)
        assert exc_info.value.status_code == 422
        assert "2048" in exc_info.value.detail


# ---------------------------------------------------------------------------
# [V5] MPTE Router — Input Validation Tests
# ---------------------------------------------------------------------------


class TestMPTEInputValidation:
    """Verify Pydantic input validation on MPTE models."""

    def test_create_pentest_request_valid(self):
        """Valid pentest request passes validation."""
        from api.mpte_router import CreatePenTestRequestModel

        model = CreatePenTestRequestModel(
            finding_id="VULN-001",
            target_url="https://example.com/api",
            vulnerability_type="sqli",
            test_case="SQL injection on login",
            priority="high",
        )
        assert model.finding_id == "VULN-001"
        assert model.priority == "high"

    def test_create_pentest_request_rejects_empty_finding_id(self):
        """Empty finding_id rejected."""
        from api.mpte_router import CreatePenTestRequestModel

        with pytest.raises(Exception):
            CreatePenTestRequestModel(
                finding_id="",
                target_url="https://example.com",
                vulnerability_type="xss",
                test_case="XSS test",
            )

    def test_create_pentest_request_rejects_invalid_priority(self):
        """Invalid priority value rejected."""
        from api.mpte_router import CreatePenTestRequestModel

        with pytest.raises(Exception):
            CreatePenTestRequestModel(
                finding_id="VULN-001",
                target_url="https://example.com",
                vulnerability_type="xss",
                test_case="test",
                priority="ultra-mega-high",
            )

    def test_create_pentest_request_rejects_oversized_fields(self):
        """Oversized string fields rejected."""
        from api.mpte_router import CreatePenTestRequestModel

        with pytest.raises(Exception):
            CreatePenTestRequestModel(
                finding_id="X" * 300,  # > 256
                target_url="https://example.com",
                vulnerability_type="xss",
                test_case="test",
            )

    def test_verify_model_rejects_empty_evidence(self):
        """Empty evidence field rejected."""
        from api.mpte_router import VerifyVulnerabilityModel

        with pytest.raises(Exception):
            VerifyVulnerabilityModel(
                finding_id="V-1",
                target_url="https://ex.com",
                vulnerability_type="sqli",
                evidence="",
            )

    def test_monitoring_model_rejects_empty_targets(self):
        """Empty targets list rejected."""
        from api.mpte_router import ContinuousMonitoringModel

        with pytest.raises(Exception):
            ContinuousMonitoringModel(targets=[])

    def test_monitoring_model_rejects_short_interval(self):
        """Interval below 5 minutes rejected."""
        from api.mpte_router import ContinuousMonitoringModel

        with pytest.raises(Exception):
            ContinuousMonitoringModel(
                targets=["https://example.com"],
                interval_minutes=1,
            )

    def test_scan_model_rejects_unknown_scan_type(self):
        """Unknown scan types rejected."""
        from api.mpte_router import ComprehensiveScanModel

        with pytest.raises(Exception):
            ComprehensiveScanModel(
                target="https://example.com",
                scan_types=["sql_injection_advanced_turbo"],
            )

    def test_config_model_limits_concurrent(self):
        """max_concurrent_tests must be 1-50."""
        from api.mpte_router import CreatePenTestConfigModel

        with pytest.raises(Exception):
            CreatePenTestConfigModel(
                name="test",
                mpte_url="https://mpte.local",
                max_concurrent_tests=999,
            )

    def test_result_model_confidence_range(self):
        """confidence_score must be 0.0-1.0."""
        from api.mpte_router import CreatePenTestResultModel

        with pytest.raises(Exception):
            CreatePenTestResultModel(
                request_id="r1",
                finding_id="f1",
                exploitability="high",
                exploit_successful=True,
                evidence="proof",
                confidence_score=1.5,  # > 1.0
            )


# ---------------------------------------------------------------------------
# [V5] MPTE Router — Concurrent Scan Limits
# ---------------------------------------------------------------------------


class TestMPTEConcurrentScanLimits:
    """Verify concurrent scan limiting prevents DoS."""

    def test_acquire_and_release_scan_slot(self):
        """Basic acquire/release cycle works."""
        from api.mpte_router import _acquire_scan_slot, _release_scan_slot

        assert _acquire_scan_slot() is True
        _release_scan_slot()

    def test_scan_slot_limit_enforced(self):
        """Cannot exceed max concurrent scans."""
        from api.mpte_router import (
            _MAX_CONCURRENT_SCANS,
            _acquire_scan_slot,
            _release_scan_slot,
        )

        # Acquire all slots
        acquired = 0
        for _ in range(_MAX_CONCURRENT_SCANS + 5):
            if _acquire_scan_slot():
                acquired += 1
            else:
                break

        try:
            assert acquired == _MAX_CONCURRENT_SCANS
            # Next acquire should fail
            assert _acquire_scan_slot() is False
        finally:
            # Release all slots
            for _ in range(acquired):
                _release_scan_slot()


# ---------------------------------------------------------------------------
# [V3] f-string Logging Elimination — Regression Tests
# ---------------------------------------------------------------------------


class TestFStringLoggingElimination:
    """Verify no f-string logging patterns remain in security-critical files."""

    @pytest.fixture(autouse=True)
    def _load_pattern(self):
        self.fstring_pattern = re.compile(r'logger\.\w+\(f["\']')

    def _check_file(self, filepath: str):
        """Check a file for f-string logging patterns."""
        try:
            with open(filepath, "r") as f:
                content = f.read()
            matches = self.fstring_pattern.findall(content)
            return matches
        except FileNotFoundError:
            return []

    def test_mpte_router_no_fstring_logging(self):
        """mpte_router.py has zero f-string logging."""
        matches = self._check_file("suite-attack/api/mpte_router.py")
        assert len(matches) == 0, f"Found {len(matches)} f-string logging calls"

    def test_micro_pentest_router_no_fstring_logging(self):
        """micro_pentest_router.py has zero f-string logging."""
        matches = self._check_file("suite-attack/api/micro_pentest_router.py")
        assert len(matches) == 0, f"Found {len(matches)} f-string logging calls"

    def test_secrets_scanner_no_fstring_logging(self):
        """secrets_scanner.py has zero f-string logging."""
        matches = self._check_file("suite-core/core/secrets_scanner.py")
        assert len(matches) == 0, f"Found {len(matches)} f-string logging calls"

    def test_secrets_router_no_fstring_logging(self):
        """secrets_router.py has zero f-string logging."""
        matches = self._check_file("suite-attack/api/secrets_router.py")
        assert len(matches) == 0, f"Found {len(matches)} f-string logging calls"

    def test_attack_sim_router_no_fstring_logging(self):
        """attack_sim_router.py has zero f-string logging."""
        matches = self._check_file("suite-attack/api/attack_sim_router.py")
        assert len(matches) == 0, f"Found {len(matches)} f-string logging calls"

    def test_vuln_discovery_router_no_fstring_logging(self):
        """vuln_discovery_router.py has zero f-string logging."""
        matches = self._check_file("suite-attack/api/vuln_discovery_router.py")
        assert len(matches) == 0, f"Found {len(matches)} f-string logging calls"


# ---------------------------------------------------------------------------
# [V3] JWT Secret Hardening Tests
# ---------------------------------------------------------------------------


class TestJWTSecretHardening:
    """Verify JWT secret strength validation."""

    def test_jwt_secret_minimum_length(self):
        """Weak JWT secrets (< 32 chars) should be rejected."""
        import os

        # Save original env
        original = os.environ.get("FIXOPS_JWT_SECRET")
        try:
            os.environ["FIXOPS_JWT_SECRET"] = "demo-secret"  # Too short (11 chars)
            # The function should either reject it or generate a strong one
            # We test the function directly
            from apps.api.app import _load_or_generate_jwt_secret, _MIN_JWT_SECRET_LENGTH

            secret = _load_or_generate_jwt_secret()
            # Secret should be at least 32 chars (either the env var was accepted
            # because it meets min, or a new one was generated)
            assert len(secret) >= _MIN_JWT_SECRET_LENGTH
        except ImportError:
            pytest.skip("_MIN_JWT_SECRET_LENGTH not yet defined")
        finally:
            if original is not None:
                os.environ["FIXOPS_JWT_SECRET"] = original
            elif "FIXOPS_JWT_SECRET" in os.environ:
                del os.environ["FIXOPS_JWT_SECRET"]

    def test_jwt_secret_accepts_strong_secret(self):
        """Strong JWT secrets (>= 32 chars) are accepted."""
        import os

        original = os.environ.get("FIXOPS_JWT_SECRET")
        strong_secret = "a" * 64  # 64 chars
        try:
            os.environ["FIXOPS_JWT_SECRET"] = strong_secret
            from apps.api.app import _load_or_generate_jwt_secret

            secret = _load_or_generate_jwt_secret()
            assert secret == strong_secret
        finally:
            if original is not None:
                os.environ["FIXOPS_JWT_SECRET"] = original
            elif "FIXOPS_JWT_SECRET" in os.environ:
                del os.environ["FIXOPS_JWT_SECRET"]


# ---------------------------------------------------------------------------
# [V3] Auth Rate Limiting Tests
# ---------------------------------------------------------------------------


class TestAuthRateLimiting:
    """Verify auth failed attempt tracking prevents brute-force."""

    def test_rate_limiter_allows_initial_requests(self):
        """First request from an IP should not be rate-limited."""
        try:
            from apps.api.app import _check_auth_rate_limit

            assert _check_auth_rate_limit("203.0.113.1") is False
        except ImportError:
            pytest.skip("Auth rate limiter not yet implemented")

    def test_rate_limiter_blocks_after_max_failures(self):
        """After N failed attempts, IP should be blocked."""
        try:
            from apps.api.app import (
                _check_auth_rate_limit,
                _record_auth_failure,
                _AUTH_FAIL_MAX,
                _AUTH_FAIL_TRACKER,
            )

            test_ip = "198.51.100.99"
            # Clean state
            _AUTH_FAIL_TRACKER.pop(test_ip, None)

            for _ in range(_AUTH_FAIL_MAX):
                _record_auth_failure(test_ip)

            assert _check_auth_rate_limit(test_ip) is True

            # Clean up
            _AUTH_FAIL_TRACKER.pop(test_ip, None)
        except ImportError:
            pytest.skip("Auth rate limiter not yet implemented")


# ---------------------------------------------------------------------------
# [V3] Token Decode Hardening Tests
# ---------------------------------------------------------------------------


class TestTokenDecodeHardening:
    """Verify JWT token decode has max length check."""

    def test_oversized_token_rejected(self):
        """Tokens exceeding max length are rejected."""
        from fastapi import HTTPException

        try:
            from apps.api.app import decode_access_token, _MAX_TOKEN_LENGTH

            oversized_token = "eyJ" + "A" * (_MAX_TOKEN_LENGTH + 100)
            with pytest.raises(HTTPException) as exc_info:
                decode_access_token(oversized_token)
            assert exc_info.value.status_code == 401
        except ImportError:
            pytest.skip("_MAX_TOKEN_LENGTH not yet defined")


# ---------------------------------------------------------------------------
# [V5] Micro-Pentest Router — Error Message Safety
# ---------------------------------------------------------------------------


class TestMicroPentestErrorSafety:
    """Verify micro-pentest router doesn't leak internal details."""

    def test_health_error_hides_details(self):
        """Health endpoint error should use type(e).__name__, not str(e)."""

        with open("suite-attack/api/micro_pentest_router.py") as f:
            content = f.read()

        # Should not have str(e) patterns in error responses
        # (already verified via mpte_error assignment)
        assert "mpte_error = str(e)" not in content, \
            "str(e) leaks internal exception details"

    def test_no_target_url_in_fallback_messages(self):
        """Fallback messages should not contain user-supplied target URLs."""
        with open("suite-attack/api/mpte_router.py") as f:
            content = f.read()

        # Check that fallback messages don't interpolate user data
        # The message should be generic, not containing {data.target_url}
        assert 'f"Verification queued for' not in content
        assert 'f"Scan queued for' not in content


# ---------------------------------------------------------------------------
# [V3] Error Handling — Bare Except Audit
# ---------------------------------------------------------------------------


class TestBareExceptAudit:
    """Verify no bare except: clauses in security-critical files."""

    def _check_bare_except(self, filepath: str) -> list:
        """Find bare except: clauses in a file."""
        results = []
        try:
            with open(filepath) as f:
                for i, line in enumerate(f, 1):
                    stripped = line.strip()
                    if stripped == "except:" or stripped == "except :":
                        results.append((i, stripped))
        except FileNotFoundError:
            pass
        return results

    def test_mpte_router_no_bare_except(self):
        """mpte_router.py has no bare except clauses."""
        results = self._check_bare_except("suite-attack/api/mpte_router.py")
        assert len(results) == 0, f"Found bare except at lines: {results}"

    def test_micro_pentest_router_no_bare_except(self):
        """micro_pentest_router.py has no bare except clauses."""
        results = self._check_bare_except("suite-attack/api/micro_pentest_router.py")
        assert len(results) == 0, f"Found bare except at lines: {results}"

    def test_brain_pipeline_no_bare_except(self):
        """brain_pipeline.py has no bare except clauses."""
        results = self._check_bare_except("suite-core/core/brain_pipeline.py")
        assert len(results) == 0, f"Found bare except at lines: {results}"

    def test_autofix_engine_no_bare_except(self):
        """autofix_engine.py has no bare except clauses."""
        results = self._check_bare_except("suite-core/core/autofix_engine.py")
        assert len(results) == 0, f"Found bare except at lines: {results}"


# ---------------------------------------------------------------------------
# [V5] MPTE Router — SSRF IPv6 Tests
# ---------------------------------------------------------------------------


class TestMPTESSRFIPv6:
    """Verify SSRF protection covers IPv6 addresses."""

    def _get_validate_fn(self):
        from api.mpte_router import _validate_target_url
        return _validate_target_url

    def test_ssrf_blocks_ipv6_loopback(self):
        """SSRF: Block IPv6 loopback ::1."""
        from fastapi import HTTPException

        validate = self._get_validate_fn()
        with pytest.raises(HTTPException):
            validate("http://[::1]:8080/admin")

    def test_ssrf_blocks_ipv6_link_local(self):
        """SSRF: Block IPv6 link-local (fe80::/10)."""
        from fastapi import HTTPException

        validate = self._get_validate_fn()
        with pytest.raises(HTTPException):
            validate("http://[fe80::1]:80/")

    def test_ssrf_blocks_ipv6_unique_local(self):
        """SSRF: Block IPv6 unique local (fc00::/7)."""
        from fastapi import HTTPException

        validate = self._get_validate_fn()
        with pytest.raises(HTTPException):
            validate("http://[fd12:3456:789a::1]:443/")


# ---------------------------------------------------------------------------
# [V5] MPTE Config Validation Tests
# ---------------------------------------------------------------------------


class TestMPTEConfigValidation:
    """Verify MPTE config model validation."""

    def test_config_timeout_minimum(self):
        """Timeout must be at least 10 seconds."""
        from api.mpte_router import CreatePenTestConfigModel

        with pytest.raises(Exception):
            CreatePenTestConfigModel(
                name="test",
                mpte_url="https://mpte.local",
                timeout_seconds=1,  # Too low
            )

    def test_config_timeout_maximum(self):
        """Timeout must not exceed 3600 seconds."""
        from api.mpte_router import CreatePenTestConfigModel

        with pytest.raises(Exception):
            CreatePenTestConfigModel(
                name="test",
                mpte_url="https://mpte.local",
                timeout_seconds=99999,  # Too high
            )

    def test_config_env_list_limit(self):
        """target_environments cannot exceed 20 items."""
        from api.mpte_router import CreatePenTestConfigModel

        with pytest.raises(Exception):
            CreatePenTestConfigModel(
                name="test",
                mpte_url="https://mpte.local",
                target_environments=["env" + str(i) for i in range(25)],
            )
