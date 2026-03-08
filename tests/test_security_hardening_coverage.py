"""Comprehensive tests for core.security_hardening module (1598 LOC).

Covers:
- InputSanitizer: string, identifier, email, URL, filename, dict sanitization
- SQLInjectionPreventer: detection, checking, safe_like_value, column/table validation
- PathTraversalPreventer: detection, safe_path, filename sanitization
- SSRFProtection: URL validation, private IP blocking, cloud metadata blocking
- RateLimiter: config lookup, rate checking, penalty enforcement
- IPAccessManager: allowlist/denylist, IP checking
- SessionManager: create, get, delete, cleanup
- SecurityAuditLogger: auth, access, change, admin, security event logging
- EndpointRateLimitConfig: dataclass fields
"""

import os
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "suite-core"))

from core.security_hardening import (
    EndpointRateLimitConfig,
    IPAccessManager,
    InputSanitizer,
    PathTraversalPreventer,
    RateLimiter,
    SQLInjectionPreventer,
    SSRFProtection,
    SecurityAuditLogger,
    SessionManager,
)


# ===========================================================================
# InputSanitizer
# ===========================================================================


class TestInputSanitizer:
    """Test InputSanitizer class methods."""

    def test_sanitize_string_rejects_script_tags(self):
        with pytest.raises(ValueError, match="malicious"):
            InputSanitizer.sanitize_string("<script>alert('xss')</script>hello")

    def test_sanitize_string_rejects_javascript_protocol(self):
        with pytest.raises(ValueError, match="malicious"):
            InputSanitizer.sanitize_string("javascript:alert(1)")

    def test_sanitize_string_rejects_event_handlers(self):
        with pytest.raises(ValueError, match="malicious"):
            InputSanitizer.sanitize_string('<img onerror="alert(1)">')

    def test_sanitize_string_rejects_long_input(self):
        long_str = "A" * 100000
        with pytest.raises(ValueError, match="maximum length"):
            InputSanitizer.sanitize_string(long_str, max_length=1000)

    def test_sanitize_string_handles_empty(self):
        result = InputSanitizer.sanitize_string("")
        assert result == ""

    def test_sanitize_string_handles_unicode(self):
        result = InputSanitizer.sanitize_string("héllo wörld 中文")
        assert isinstance(result, str)

    def test_sanitize_identifier_valid(self):
        result = InputSanitizer.sanitize_identifier("my_app_123")
        assert result == "my_app_123"

    def test_sanitize_identifier_rejects_special_chars(self):
        with pytest.raises(ValueError, match="invalid characters"):
            InputSanitizer.sanitize_identifier("my-app!@#$%")

    def test_sanitize_identifier_rejects_max_length(self):
        with pytest.raises(ValueError, match="maximum length"):
            InputSanitizer.sanitize_identifier("a" * 200, max_length=50)

    def test_sanitize_email_valid(self):
        result = InputSanitizer.sanitize_email("user@example.com")
        assert result == "user@example.com"

    def test_sanitize_email_rejects_dangerous(self):
        with pytest.raises(ValueError, match="malicious"):
            InputSanitizer.sanitize_email("user+<script>@evil.com")

    def test_sanitize_url_valid(self):
        result = InputSanitizer.sanitize_url("https://example.com/path?q=1")
        assert "example.com" in result

    def test_sanitize_url_rejects_javascript(self):
        with pytest.raises(ValueError, match="malicious"):
            InputSanitizer.sanitize_url("javascript:alert(1)")

    def test_sanitize_filename_basic(self):
        result = InputSanitizer.sanitize_filename("report.pdf")
        assert result == "report.pdf"

    def test_sanitize_filename_strips_path_separators(self):
        result = InputSanitizer.sanitize_filename("../../etc/passwd")
        assert "/" not in result
        assert "\\" not in result

    def test_sanitize_dict_recursion(self):
        data = {"name": "safe_value", "nested": {"key": "also_safe"}}
        result = InputSanitizer.sanitize_dict(data)
        assert result["name"] == "safe_value"
        assert "nested" in result

    def test_sanitize_dict_rejects_xss(self):
        data = {"name": "<script>xss</script>", "nested": {"key": "value"}}
        with pytest.raises(ValueError, match="malicious"):
            InputSanitizer.sanitize_dict(data)

    def test_sanitize_dict_max_depth_raises(self):
        # Build deeply nested dict
        data = {"level": "0"}
        current = data
        for i in range(10):
            current["child"] = {"level": str(i + 1)}
            current = current["child"]
        with pytest.raises(ValueError, match="maximum depth"):
            InputSanitizer.sanitize_dict(data, max_depth=3)


# ===========================================================================
# SQLInjectionPreventer
# ===========================================================================


class TestSQLInjectionPreventer:
    """Test SQL injection detection and prevention."""

    @pytest.mark.parametrize(
        "payload",
        [
            "' OR 1=1 --",
            "UNION SELECT * FROM users",
            "'; DROP TABLE users; --",
            "1; DELETE FROM sessions",
            "admin' AND 1=1",
            "INSERT INTO logs VALUES('hack')",
            "UPDATE users SET role='admin'",
            "EXEC xp_cmdshell('whoami')",
            "SELECT * FROM INFORMATION_SCHEMA",
        ],
    )
    def test_detect_injection_catches_attacks(self, payload):
        assert SQLInjectionPreventer.detect_injection(payload) is True

    @pytest.mark.parametrize(
        "safe_input",
        [
            "normal user input",
            "john.doe@example.com",
            "my-application-name",
            "CVE-2024-1234",
            "Report for Q4 2024",
        ],
    )
    def test_detect_injection_allows_safe(self, safe_input):
        assert SQLInjectionPreventer.detect_injection(safe_input) is False

    def test_check_injection_raises_on_attack(self):
        with pytest.raises(Exception):
            SQLInjectionPreventer.check_injection("' OR 1=1 --", "username")

    def test_check_injection_passes_safe(self):
        result = SQLInjectionPreventer.check_injection("normal_value", "field")
        assert result == "normal_value"

    def test_safe_like_value_escapes_wildcards(self):
        result = SQLInjectionPreventer.safe_like_value("100%_discount")
        assert "%" not in result or result != "100%_discount"

    def test_validate_column_name_allowed(self):
        allowed = {"id", "name", "email", "created_at"}
        result = SQLInjectionPreventer.validate_column_name("name", allowed)
        assert result == "name"

    def test_validate_column_name_rejected(self):
        allowed = {"id", "name"}
        with pytest.raises(Exception):
            SQLInjectionPreventer.validate_column_name("password_hash", allowed)

    def test_validate_table_name_allowed(self):
        allowed = {"users", "findings", "scans"}
        result = SQLInjectionPreventer.validate_table_name("findings", allowed)
        assert result == "findings"

    def test_validate_table_name_rejected(self):
        allowed = {"users", "findings"}
        with pytest.raises(Exception):
            SQLInjectionPreventer.validate_table_name("admin_secrets", allowed)

    def test_build_safe_params(self):
        data = {"name": "test", "value": "safe"}
        result = SQLInjectionPreventer.build_safe_params(data)
        assert isinstance(result, dict)
        assert "name" in result


# ===========================================================================
# PathTraversalPreventer
# ===========================================================================


class TestPathTraversalPreventer:
    """Test path traversal detection and prevention."""

    @pytest.mark.parametrize(
        "path",
        [
            "../../etc/passwd",
            "..\\windows\\system32",
            "%2e%2e%2fetc/passwd",
            "foo/../../../etc/shadow",
            "%252e%252e%252f",
        ],
    )
    def test_detect_traversal_catches_attacks(self, path):
        assert PathTraversalPreventer.detect_traversal(path) is True

    @pytest.mark.parametrize(
        "safe_path",
        [
            "reports/2024/scan.pdf",
            "uploads/image.png",
            "data/findings.json",
        ],
    )
    def test_detect_traversal_allows_safe(self, safe_path):
        assert PathTraversalPreventer.detect_traversal(safe_path) is False

    def test_safe_path_with_base_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            result = PathTraversalPreventer.safe_path("subdir/file.txt", base)
            assert str(base) in str(result)

    def test_safe_path_rejects_traversal(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            with pytest.raises(Exception):
                PathTraversalPreventer.safe_path("../../etc/passwd", base)

    def test_sanitize_filename_removes_path(self):
        result = PathTraversalPreventer.sanitize_filename("../../etc/passwd")
        assert ".." not in result
        assert result == "passwd" or "passwd" in result


# ===========================================================================
# SSRFProtection
# ===========================================================================


class TestSSRFProtection:
    """Test SSRF protection URL validation."""

    def setup_method(self):
        self.ssrf = SSRFProtection()

    def test_valid_https_url(self):
        result = self.ssrf.validate_url("https://example.com/api")
        assert result == "https://example.com/api"

    def test_rejects_http_by_default(self):
        with pytest.raises(ValueError, match="scheme"):
            self.ssrf.validate_url("http://example.com")

    def test_allows_http_when_configured(self):
        ssrf = SSRFProtection(allowed_schemes=["http", "https"])
        result = ssrf.validate_url("http://example.com")
        assert result == "http://example.com"

    def test_rejects_ftp_scheme(self):
        with pytest.raises(ValueError, match="scheme"):
            self.ssrf.validate_url("ftp://files.example.com")

    def test_rejects_file_scheme(self):
        with pytest.raises(ValueError, match="scheme"):
            self.ssrf.validate_url("file:///etc/passwd")

    def test_blocks_cloud_metadata_aws(self):
        with pytest.raises(ValueError, match="blocked"):
            self.ssrf.validate_url("https://169.254.169.254/latest/meta-data")

    def test_blocks_cloud_metadata_gcp(self):
        with pytest.raises(ValueError, match="blocked"):
            self.ssrf.validate_url("https://metadata.google.internal/computeMetadata")

    def test_blocks_private_ip_loopback(self):
        with pytest.raises(ValueError, match="private"):
            self.ssrf.validate_url("https://127.0.0.1/admin")

    def test_blocks_private_ip_10_range(self):
        with pytest.raises(ValueError, match="private"):
            self.ssrf.validate_url("https://10.0.0.1/internal")

    def test_blocks_private_ip_172_range(self):
        with pytest.raises(ValueError, match="private"):
            self.ssrf.validate_url("https://172.16.0.1/internal")

    def test_blocks_private_ip_192_range(self):
        with pytest.raises(ValueError, match="private"):
            self.ssrf.validate_url("https://192.168.1.1/internal")

    def test_allows_private_when_configured(self):
        ssrf = SSRFProtection(allow_private=True, allowed_schemes=["https"])
        result = ssrf.validate_url("https://10.0.0.1/api")
        assert result == "https://10.0.0.1/api"

    def test_rejects_empty_hostname(self):
        with pytest.raises(ValueError):
            self.ssrf.validate_url("https:///no-host")

    def test_rejects_invalid_url(self):
        with pytest.raises(ValueError):
            self.ssrf.validate_url("")


# ===========================================================================
# RateLimiter
# ===========================================================================


class TestRateLimiter:
    """Test rate limiter functionality."""

    def _make_request(self, path="/api/v1/test", ip="1.2.3.4"):
        """Create a mock request object."""
        request = MagicMock()
        request.url.path = path
        request.client.host = ip
        request.headers = {}
        request.state = MagicMock()
        return request

    def test_get_config_exact_match(self):
        config = EndpointRateLimitConfig(max_requests=5, window_seconds=60)
        limiter = RateLimiter(configs={"/api/v1/auth/login": config})
        result = limiter.get_config("/api/v1/auth/login")
        assert result.max_requests == 5

    def test_get_config_prefix_match(self):
        config = EndpointRateLimitConfig(max_requests=10)
        limiter = RateLimiter(configs={"/api/v1/scan": config})
        result = limiter.get_config("/api/v1/scan/start")
        assert result.max_requests == 10

    def test_get_config_default_fallback(self):
        limiter = RateLimiter()
        result = limiter.get_config("/api/v1/unknown")
        assert result.max_requests == limiter.default_config.max_requests

    def test_check_allows_under_limit(self):
        config = EndpointRateLimitConfig(max_requests=100, window_seconds=60)
        limiter = RateLimiter(configs={"/test": config})
        request = self._make_request("/test")
        # Should not raise
        limiter.check(request, "/test")

    def test_check_rate_limit_exceeded(self):
        config = EndpointRateLimitConfig(max_requests=2, window_seconds=60)
        limiter = RateLimiter(configs={"/test": config})
        request = self._make_request("/test")
        # First 2 should pass
        limiter.check(request, "/test")
        limiter.check(request, "/test")
        # 3rd should be limited (but allow burst)
        # Check with very low limit
        config2 = EndpointRateLimitConfig(max_requests=1, window_seconds=60, burst_multiplier=1.0)
        limiter2 = RateLimiter(configs={"/strict": config2})
        request2 = self._make_request("/strict")
        limiter2.check(request2, "/strict")
        with pytest.raises(Exception):  # HTTPException 429
            limiter2.check(request2, "/strict")

    def test_remaining_returns_count(self):
        config = EndpointRateLimitConfig(max_requests=10, window_seconds=60)
        limiter = RateLimiter(configs={"/test": config})
        request = self._make_request("/test")
        remaining = limiter.remaining(request, "/test")
        assert remaining >= 0

    def test_endpoint_rate_limit_config_defaults(self):
        config = EndpointRateLimitConfig()
        assert config.burst_multiplier == 1.5
        assert config.penalty_seconds == 60
        assert config.key_by == "ip"


# ===========================================================================
# IPAccessManager
# ===========================================================================


class TestIPAccessManager:
    """Test IP allowlist/denylist management."""

    def test_default_allows_all(self):
        mgr = IPAccessManager()
        assert mgr.is_allowed("8.8.8.8") is True

    def test_denylist_blocks_ip(self):
        mgr = IPAccessManager(denylist=["10.0.0.0/8"])
        assert mgr.is_allowed("10.1.2.3") is False
        assert mgr.is_allowed("8.8.8.8") is True

    def test_allowlist_only_permits_listed(self):
        mgr = IPAccessManager(allowlist=["192.168.1.0/24"], mode="allowlist")
        assert mgr.is_allowed("192.168.1.100") is True
        assert mgr.is_allowed("10.0.0.1") is False

    def test_add_to_denylist(self):
        mgr = IPAccessManager()
        mgr.add_to_denylist("10.0.0.1")
        assert mgr.is_allowed("10.0.0.1") is False

    def test_remove_from_denylist(self):
        mgr = IPAccessManager(denylist=["10.0.0.1/32"])
        mgr.remove_from_denylist("10.0.0.1/32")
        assert mgr.is_allowed("10.0.0.1") is True

    def test_add_to_allowlist(self):
        mgr = IPAccessManager(allowlist=["192.168.0.0/16"], mode="allowlist")
        mgr.add_to_allowlist("10.0.0.0/8")
        assert mgr.is_allowed("10.1.2.3") is True

    def test_ipv6_support(self):
        mgr = IPAccessManager(denylist=["::1/128"])
        assert mgr.is_allowed("::1") is False

    def test_check_with_request(self):
        mgr = IPAccessManager(denylist=["10.0.0.1/32"])
        request = MagicMock()
        request.client.host = "10.0.0.1"
        with pytest.raises(Exception):  # HTTPException 403
            mgr.check(request)


# ===========================================================================
# SessionManager
# ===========================================================================


class TestSessionManager:
    """Test session management with SQLite backend."""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "sessions.db")
        self.mgr = SessionManager(db_path=self.db_path)

    def _make_request(self, ip="1.2.3.4", user_agent="TestAgent/1.0"):
        request = MagicMock()
        request.client.host = ip
        request.headers = {"user-agent": user_agent}
        return request

    def test_create_session(self):
        request = self._make_request()
        session_id = self.mgr.create("user@test.com", request)
        assert isinstance(session_id, str)
        assert len(session_id) > 0

    def test_get_session(self):
        request = self._make_request()
        session_id = self.mgr.create("user@test.com", request)
        session = self.mgr.get(session_id, request)
        assert session is not None
        assert session.user_id == "user@test.com"

    def test_get_nonexistent_session_raises(self):
        request = self._make_request()
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            self.mgr.get("nonexistent-session-id", request)
        assert exc_info.value.status_code == 401

    def test_delete_session(self):
        request = self._make_request()
        session_id = self.mgr.create("user@test.com", request)
        self.mgr.delete(session_id)
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            self.mgr.get(session_id, request)
        assert exc_info.value.status_code == 401

    def test_delete_all_user_sessions(self):
        request = self._make_request()
        self.mgr.create("user@test.com", request)
        self.mgr.create("user@test.com", request)
        count = self.mgr.delete_all("user@test.com")
        assert count >= 2

    def test_cleanup_expired(self):
        count = self.mgr.cleanup_expired()
        assert isinstance(count, int)


# ===========================================================================
# SecurityAuditLogger
# ===========================================================================


class TestSecurityAuditLogger:
    """Test audit event logging."""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "audit.db")
        self.logger = SecurityAuditLogger(db_path=self.db_path)

    def test_log_auth_event(self):
        event_id = self.logger.log_auth(action="login", outcome="success")
        assert isinstance(event_id, str)
        assert len(event_id) > 0

    def test_log_auth_failed(self):
        event_id = self.logger.log_auth(action="login", outcome="failure")
        assert isinstance(event_id, str)

    def test_log_access_event(self):
        event_id = self.logger.log_access(
            action="read",
            resource_type="finding",
            resource_id="finding-123",
        )
        assert isinstance(event_id, str)

    def test_log_access_denied(self):
        event_id = self.logger.log_access(
            action="read",
            resource_type="admin_panel",
            outcome="denied",
        )
        assert isinstance(event_id, str)

    def test_log_change_event(self):
        event_id = self.logger.log_change(
            action="update",
            resource_type="finding",
            resource_id="finding-123",
            details={"status": "resolved"},
        )
        assert isinstance(event_id, str)

    def test_log_admin_event(self):
        event_id = self.logger.log_admin(
            action="create_api_key",
            details={"key_name": "ci-cd-key"},
        )
        assert isinstance(event_id, str)

    def test_log_security_event(self):
        event_id = self.logger.log_security_event(
            action="rate_limit_exceeded",
            details={"ip": "6.6.6.6", "path": "/api/v1/auth/login"},
        )
        assert isinstance(event_id, str)

    def test_multiple_events_in_sequence(self):
        for i in range(10):
            event_id = self.logger.log_access(
                action="read",
                resource_type="finding",
                resource_id=f"finding-{i}",
            )
            assert isinstance(event_id, str)
