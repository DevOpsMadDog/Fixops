"""Security hardening tests — Session 2, 2026-03-03.

Tests for:
1. micro_pentest_router.py SSRF protection [V5]
2. micro_pentest_router.py input validation (CVE format, list limits) [V5]
3. micro_pentest_router.py concurrent scan limiter [V5]
4. webhooks_router.py external_url SSRF protection [V7]
5. f-string logging audit across core engines [V3/V5/V7]
6. connectors.py error message sanitization [V7]
7. bare except block elimination audit [V5]
"""
from __future__ import annotations

import os
import re
import sys
import threading

import pytest

# ---------------------------------------------------------------------------
# Ensure suite paths are on sys.path
# ---------------------------------------------------------------------------
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _d in (
    "suite-api",
    "suite-core",
    "suite-attack",
    "suite-feeds",
    "suite-evidence-risk",
    "suite-integrations",
):
    _p = os.path.join(_ROOT, _d)
    if _p not in sys.path:
        sys.path.insert(0, _p)


# ===================================================================
# Section 1: micro_pentest_router SSRF Protection [V5]
# ===================================================================


class TestMicroPentestSSRFProtection:
    """Validate SSRF protection on micro_pentest_router target URLs."""

    @pytest.fixture(autouse=True)
    def _load_validator(self):
        from api.micro_pentest_router import _validate_pentest_url
        self._validate = _validate_pentest_url

    def test_ssrf_blocks_localhost(self):
        with pytest.raises(Exception) as exc_info:
            self._validate("http://localhost/admin")
        assert "blocked" in str(exc_info.value.detail).lower()

    def test_ssrf_blocks_127_0_0_1(self):
        with pytest.raises(Exception) as exc_info:
            self._validate("http://127.0.0.1:8080/secret")
        assert "blocked" in str(exc_info.value.detail).lower()

    def test_ssrf_blocks_rfc1918_10(self):
        with pytest.raises(Exception) as exc_info:
            self._validate("http://10.0.0.1/internal")
        assert "blocked" in str(exc_info.value.detail).lower()

    def test_ssrf_blocks_rfc1918_172(self):
        with pytest.raises(Exception) as exc_info:
            self._validate("http://172.16.0.1/internal")
        assert "blocked" in str(exc_info.value.detail).lower()

    def test_ssrf_blocks_rfc1918_192(self):
        with pytest.raises(Exception) as exc_info:
            self._validate("http://192.168.1.1/admin")
        assert "blocked" in str(exc_info.value.detail).lower()

    def test_ssrf_blocks_aws_metadata(self):
        with pytest.raises(Exception) as exc_info:
            self._validate("http://169.254.169.254/latest/meta-data/")
        assert "blocked" in str(exc_info.value.detail).lower()

    def test_ssrf_blocks_gcp_metadata(self):
        with pytest.raises(Exception) as exc_info:
            self._validate("http://metadata.google.internal/computeMetadata/v1/")
        assert "blocked" in str(exc_info.value.detail).lower()

    def test_ssrf_blocks_ipv6_loopback(self):
        with pytest.raises(Exception) as exc_info:
            self._validate("http://[::1]/admin")
        assert "blocked" in str(exc_info.value.detail).lower()

    def test_ssrf_allows_public_url(self):
        result = self._validate("https://example.com/test")
        assert result == "https://example.com/test"

    def test_ssrf_allows_public_ip(self):
        result = self._validate("https://93.184.216.34/test")
        assert "93.184.216.34" in result

    def test_ssrf_rejects_ftp_scheme(self):
        with pytest.raises(Exception) as exc_info:
            self._validate("ftp://evil.com/payload")
        assert "http" in str(exc_info.value.detail).lower()

    def test_ssrf_rejects_empty_url(self):
        with pytest.raises(Exception):
            self._validate("")

    def test_ssrf_rejects_overlength_url(self):
        long_url = "https://example.com/" + "a" * 2100
        with pytest.raises(Exception) as exc_info:
            self._validate(long_url)
        assert "2048" in str(exc_info.value.detail)

    def test_ssrf_auto_adds_https_scheme(self):
        result = self._validate("example.com/test")
        assert result.startswith("https://")


# ===================================================================
# Section 2: micro_pentest_router Input Validation [V5]
# ===================================================================


class TestMicroPentestInputValidation:
    """Validate Pydantic request model constraints."""

    @pytest.fixture(autouse=True)
    def _load_models(self):
        from api.micro_pentest_router import (
            RunMicroPentestRequest,
            BatchMicroPentestRequest,
            BatchTestConfigModel,
        )
        self.RunRequest = RunMicroPentestRequest
        self.BatchRequest = BatchMicroPentestRequest
        self.BatchConfig = BatchTestConfigModel

    def test_cve_id_format_valid(self):
        """Valid CVE IDs should be accepted."""
        req = self.RunRequest(
            cve_ids=["CVE-2024-1234", "CVE-2023-99999"],
            target_urls=["https://example.com"],
        )
        assert len(req.cve_ids) == 2

    def test_cve_id_format_invalid(self):
        """Invalid CVE ID format should be rejected."""
        with pytest.raises(Exception):
            self.RunRequest(
                cve_ids=["NOT-A-CVE"],
                target_urls=["https://example.com"],
            )

    def test_cve_id_injection_attempt(self):
        """SQL injection in CVE ID should be rejected."""
        with pytest.raises(Exception):
            self.RunRequest(
                cve_ids=["CVE-2024-1234; DROP TABLE vulns;--"],
                target_urls=["https://example.com"],
            )

    def test_empty_cve_list_rejected(self):
        """Empty CVE list should be rejected (min_length=1)."""
        with pytest.raises(Exception):
            self.RunRequest(
                cve_ids=[],
                target_urls=["https://example.com"],
            )

    def test_empty_target_urls_rejected(self):
        """Empty target URL list should be rejected (min_length=1)."""
        with pytest.raises(Exception):
            self.RunRequest(
                cve_ids=["CVE-2024-1234"],
                target_urls=[],
            )

    def test_too_many_cve_ids_rejected(self):
        """More than 100 CVE IDs should be rejected."""
        with pytest.raises(Exception):
            self.RunRequest(
                cve_ids=[f"CVE-2024-{i:04d}" for i in range(1, 102)],
                target_urls=["https://example.com"],
            )

    def test_too_many_target_urls_rejected(self):
        """More than 50 target URLs should be rejected."""
        with pytest.raises(Exception):
            self.RunRequest(
                cve_ids=["CVE-2024-1234"],
                target_urls=[f"https://target{i}.example.com" for i in range(51)],
            )

    def test_overlength_url_in_request_rejected(self):
        """URL > 2048 chars should be rejected by field validator."""
        with pytest.raises(Exception):
            self.RunRequest(
                cve_ids=["CVE-2024-1234"],
                target_urls=["https://example.com/" + "a" * 2100],
            )

    def test_batch_size_limit(self):
        """Batch request should enforce max test count."""
        with pytest.raises(Exception):
            self.BatchRequest(
                test_configs=[
                    self.BatchConfig(
                        cve_ids=["CVE-2024-0001"],
                        target_urls=["https://example.com"],
                    )
                    for _ in range(21)  # Over _MAX_BATCH_TESTS=20
                ]
            )

    def test_batch_empty_rejected(self):
        """Empty batch should be rejected."""
        with pytest.raises(Exception):
            self.BatchRequest(test_configs=[])


# ===================================================================
# Section 3: Concurrent Scan Limiter [V5]
# ===================================================================


class TestConcurrentScanLimiter:
    """Validate concurrent pentest slot limiting."""

    @pytest.fixture(autouse=True)
    def _load_limiter(self):
        from api.micro_pentest_router import (
            _acquire_pentest_slot,
            _release_pentest_slot,
            _MAX_CONCURRENT_PENTESTS,
        )
        self._acquire = _acquire_pentest_slot
        self._release = _release_pentest_slot
        self._max = _MAX_CONCURRENT_PENTESTS

    def test_acquire_returns_true_when_available(self):
        """Should acquire slot when under limit."""
        result = self._acquire()
        assert result is True
        self._release()

    def test_release_decrements_counter(self):
        """Release should free a slot."""
        self._acquire()
        self._release()
        # Should be able to acquire again
        assert self._acquire() is True
        self._release()

    def test_release_never_goes_negative(self):
        """Releasing when no slots held should not go negative."""
        self._release()  # Release without acquire
        self._release()  # Extra release
        # Should still be able to acquire max slots
        acquired = 0
        for _ in range(self._max):
            if self._acquire():
                acquired += 1
        assert acquired == self._max
        for _ in range(acquired):
            self._release()

    def test_thread_safety(self):
        """Concurrent acquire/release should be thread-safe."""
        errors = []
        acquired = []

        def worker():
            try:
                if self._acquire():
                    acquired.append(1)
                    import time
                    time.sleep(0.01)
                    self._release()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert len(errors) == 0, f"Thread safety violations: {errors}"


# ===================================================================
# Section 4: webhooks_router SSRF Protection [V7]
# ===================================================================


class TestWebhookSSRFProtection:
    """Validate SSRF protection on webhook external_url fields."""

    @pytest.fixture(autouse=True)
    def _load(self):
        from api.webhooks_router import _validate_external_url
        self._validate = _validate_external_url

    def test_blocks_localhost(self):
        with pytest.raises(ValueError, match="blocked"):
            self._validate("http://localhost/admin")

    def test_blocks_internal_10(self):
        with pytest.raises(ValueError, match="blocked"):
            self._validate("http://10.0.0.5/api")

    def test_blocks_internal_172(self):
        with pytest.raises(ValueError, match="blocked"):
            self._validate("http://172.16.1.1/api")

    def test_blocks_aws_metadata(self):
        with pytest.raises(ValueError, match="blocked"):
            self._validate("http://169.254.169.254/latest/")

    def test_allows_public_url(self):
        result = self._validate("https://jira.company.com/browse/SEC-123")
        assert "jira.company.com" in result

    def test_allows_none(self):
        """None should pass through (field is Optional)."""
        # Just validate it doesn't raise
        self._validate("")
        # Empty string returns as-is (original behavior)

    def test_blocks_ftp(self):
        with pytest.raises(ValueError, match="http"):
            self._validate("ftp://internal.corp/data")

    def test_overlength_rejected(self):
        with pytest.raises(ValueError, match="2048"):
            self._validate("https://example.com/" + "x" * 2100)


class TestWebhookPydanticValidation:
    """Validate Pydantic model constraints on CreateMappingRequest."""

    @pytest.fixture(autouse=True)
    def _load(self):
        from api.webhooks_router import CreateMappingRequest
        self.CreateMapping = CreateMappingRequest

    def test_valid_request_accepted(self):
        req = self.CreateMapping(
            cluster_id="cluster-123",
            integration_type="jira",
            external_id="SEC-456",
            external_url="https://jira.company.com/browse/SEC-456",
        )
        assert req.cluster_id == "cluster-123"

    def test_ssrf_in_external_url_rejected(self):
        with pytest.raises(Exception):
            self.CreateMapping(
                cluster_id="cluster-123",
                integration_type="jira",
                external_id="SEC-456",
                external_url="http://169.254.169.254/latest/",
            )

    def test_overlength_cluster_id_rejected(self):
        with pytest.raises(Exception):
            self.CreateMapping(
                cluster_id="x" * 600,
                integration_type="jira",
                external_id="SEC-456",
            )


# ===================================================================
# Section 5: f-string Logging Audit [V3/V5/V7]
# ===================================================================


class TestFStringLoggingAudit:
    """Ensure no f-string logging in security-critical code.

    f-string logging eagerly evaluates expressions, which can:
    1. Leak secrets/credentials into logs
    2. Cause unnecessary computation for suppressed log levels
    3. Raise exceptions during string formatting
    """

    # Files that MUST NOT have f-string logging (security-critical)
    CRITICAL_FILES = [
        "suite-core/core/connectors.py",
        "suite-core/core/mcp_server.py",
        "suite-core/core/single_agent.py",
        "suite-core/core/automated_remediation.py",
        "suite-core/core/brain_pipeline.py",
        "suite-core/core/autofix_engine.py",
        "suite-core/core/sast_engine.py",
        "suite-core/core/dast_engine.py",
        "suite-core/core/secrets_scanner.py",
        "suite-core/core/container_scanner.py",
        "suite-core/core/cspm_engine.py",
        "suite-attack/api/mpte_router.py",
        "suite-attack/api/micro_pentest_router.py",
        "suite-core/core/playbook_runner.py",
        "suite-core/core/services/remediation.py",
    ]

    _FSTRING_LOG_PATTERN = re.compile(r'logger\.\w+\(f["\']')

    @pytest.fixture(autouse=True)
    def _setup(self):
        self._root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def test_no_fstring_logging_in_critical_files(self):
        """No f-string logging in security-critical engine files."""
        violations = []
        for rel_path in self.CRITICAL_FILES:
            full_path = os.path.join(self._root, rel_path)
            if not os.path.exists(full_path):
                continue
            with open(full_path, "r") as f:
                for i, line in enumerate(f, 1):
                    if self._FSTRING_LOG_PATTERN.search(line):
                        violations.append(f"{rel_path}:{i}: {line.strip()[:100]}")

        assert not violations, (
            f"Found {len(violations)} f-string logging violations in "
            f"security-critical files:\n" + "\n".join(violations)
        )


# ===================================================================
# Section 6: Bare Except Audit [V5]
# ===================================================================


class TestBareExceptAudit:
    """Ensure no untyped bare except blocks in micro_pentest_router.py.

    Bare `except:` or `except Exception:` without logging
    silently swallows errors, making debugging impossible and
    potentially hiding security issues.
    """

    _BARE_EXCEPT_PATTERN = re.compile(r"^\s*except\s*:\s*$")

    def test_no_bare_except_in_micro_pentest_router(self):
        """micro_pentest_router.py should have zero bare except blocks."""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(root, "suite-attack/api/micro_pentest_router.py")
        violations = []
        with open(path, "r") as f:
            for i, line in enumerate(f, 1):
                if self._BARE_EXCEPT_PATTERN.match(line):
                    violations.append(f"Line {i}: {line.strip()}")
        assert not violations, (
            f"Found {len(violations)} bare except blocks:\n" + "\n".join(violations)
        )


# ===================================================================
# Section 7: Connectors Error Message Sanitization [V7]
# ===================================================================


class TestConnectorsErrorSanitization:
    """Validate that connectors.py never logs raw exception messages."""

    def test_no_str_exc_in_error_log(self):
        """connectors.py must not use str(exc) or f'{exc}' in logger.error."""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(root, "suite-core/core/connectors.py")
        violations = []
        fstring_pat = re.compile(r'logger\.\w+\(f["\'].*\{exc\}')
        strexc_pat = re.compile(r'logger\.\w+\(.*str\(exc\)')
        with open(path, "r") as f:
            for i, line in enumerate(f, 1):
                if fstring_pat.search(line) or strexc_pat.search(line):
                    violations.append(f"Line {i}: {line.strip()[:100]}")
        assert not violations, (
            f"Found {len(violations)} raw exception in log messages:\n"
            + "\n".join(violations)
        )


# ===================================================================
# Section 8: SSRF Constants Verification [V5/V7]
# ===================================================================


class TestSSRFConstantsConsistency:
    """Ensure SSRF protection constants are consistent across routers."""

    def test_micro_pentest_has_all_blocked_nets(self):
        from api.micro_pentest_router import _BLOCKED_NETS
        # Must include at least: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8
        import ipaddress
        required = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("169.254.0.0/16"),
        ]
        for net in required:
            assert net in _BLOCKED_NETS, f"Missing blocked network: {net}"

    def test_micro_pentest_blocked_hosts(self):
        from api.micro_pentest_router import _BLOCKED_HOSTS
        assert "localhost" in _BLOCKED_HOSTS
        assert "metadata.google.internal" in _BLOCKED_HOSTS
        assert "169.254.169.254" in _BLOCKED_HOSTS

    def test_webhook_has_blocked_hosts(self):
        from api.webhooks_router import _WEBHOOK_BLOCKED_HOSTS
        assert "localhost" in _WEBHOOK_BLOCKED_HOSTS
        assert "metadata.google.internal" in _WEBHOOK_BLOCKED_HOSTS

    def test_mpte_has_blocked_nets(self):
        from api.mpte_router import _BLOCKED_NETS
        import ipaddress
        assert ipaddress.ip_network("10.0.0.0/8") in _BLOCKED_NETS
        assert ipaddress.ip_network("127.0.0.0/8") in _BLOCKED_NETS


# ===================================================================
# Section 9: Input Validation Constants [V5]
# ===================================================================


class TestInputValidationConstants:
    """Verify input validation constants are properly set."""

    def test_max_url_length(self):
        from api.micro_pentest_router import _MAX_URL_LEN
        assert _MAX_URL_LEN == 2048  # RFC 2616

    def test_max_cve_ids(self):
        from api.micro_pentest_router import _MAX_CVE_IDS
        assert _MAX_CVE_IDS >= 1
        assert _MAX_CVE_IDS <= 1000  # Reasonable upper bound

    def test_max_target_urls(self):
        from api.micro_pentest_router import _MAX_TARGET_URLS
        assert _MAX_TARGET_URLS >= 1
        assert _MAX_TARGET_URLS <= 1000

    def test_max_concurrent_pentests(self):
        from api.micro_pentest_router import _MAX_CONCURRENT_PENTESTS
        assert _MAX_CONCURRENT_PENTESTS >= 1
        assert _MAX_CONCURRENT_PENTESTS <= 100

    def test_cve_pattern_matches_valid(self):
        from api.micro_pentest_router import _CVE_ID_PATTERN
        assert _CVE_ID_PATTERN.match("CVE-2024-1234")
        assert _CVE_ID_PATTERN.match("CVE-2023-999999")

    def test_cve_pattern_rejects_invalid(self):
        from api.micro_pentest_router import _CVE_ID_PATTERN
        assert not _CVE_ID_PATTERN.match("NOT-CVE")
        assert not _CVE_ID_PATTERN.match("CVE-2024")
        assert not _CVE_ID_PATTERN.match("CVE-ABCD-1234")
        assert not _CVE_ID_PATTERN.match("")
