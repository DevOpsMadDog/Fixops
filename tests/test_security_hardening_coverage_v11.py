"""Comprehensive coverage tests for core.security_hardening — v11 swarm coverage push.

Targets: InputSanitizer, SQLInjectionPreventer, PathTraversalPreventer,
         SSRFProtection, EndpointRateLimitConfig, RateLimiter, IPAccessManager,
         SessionManager, SecurityAuditLogger
"""

import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.security_hardening import (
    EndpointRateLimitConfig,
    InputSanitizer,
    PathTraversalPreventer,
    SQLInjectionPreventer,
    SSRFProtection,
)


# ---------------------------------------------------------------------------
# InputSanitizer
# ---------------------------------------------------------------------------


class TestInputSanitizer:
    def test_sanitize_basic_string(self):
        result = InputSanitizer.sanitize_string("  hello world  ")
        assert result == "hello world"

    def test_sanitize_null_bytes_removed(self):
        result = InputSanitizer.sanitize_string("hello\x00world")
        assert "\x00" not in result

    def test_sanitize_max_length_exceeded(self):
        with pytest.raises(ValueError, match="maximum length"):
            InputSanitizer.sanitize_string("a" * 5000, max_length=100)

    def test_sanitize_xss_rejected(self):
        with pytest.raises(ValueError, match="malicious"):
            InputSanitizer.sanitize_string("<script>alert(1)</script>")

    def test_sanitize_javascript_protocol_rejected(self):
        with pytest.raises(ValueError, match="malicious"):
            InputSanitizer.sanitize_string("javascript:void(0)")

    def test_sanitize_html_escaped_by_default(self):
        result = InputSanitizer.sanitize_string("a < b & c > d")
        assert "&lt;" in result
        assert "&gt;" in result
        assert "&amp;" in result

    def test_sanitize_non_string_raises(self):
        with pytest.raises(ValueError, match="Expected string"):
            InputSanitizer.sanitize_string(12345)

    def test_sanitize_unicode_normalized(self):
        # NFC normalization of combining characters
        result = InputSanitizer.sanitize_string("café")
        assert "caf" in result

    def test_sanitize_identifier_valid(self):
        result = InputSanitizer.sanitize_identifier("my_var_123")
        assert result == "my_var_123"

    def test_sanitize_identifier_with_dots(self):
        result = InputSanitizer.sanitize_identifier("my.identifier")
        assert result == "my.identifier"

    def test_sanitize_identifier_invalid_chars(self):
        with pytest.raises(ValueError, match="invalid characters"):
            InputSanitizer.sanitize_identifier("my var!@#")

    def test_sanitize_email_valid(self):
        result = InputSanitizer.sanitize_email("Test@Example.COM")
        assert result == "test@example.com"

    def test_sanitize_email_invalid(self):
        with pytest.raises(ValueError, match="email"):
            InputSanitizer.sanitize_email("not-an-email")

    def test_sanitize_url_valid(self):
        result = InputSanitizer.sanitize_url("https://example.com/path")
        assert "example.com" in result

    def test_sanitize_url_bad_scheme(self):
        with pytest.raises(ValueError, match="scheme"):
            InputSanitizer.sanitize_url("ftp://example.com/file")

    def test_sanitize_url_no_host(self):
        with pytest.raises(ValueError, match="hostname"):
            InputSanitizer.sanitize_url("https://")

    def test_sanitize_filename_basic(self):
        result = InputSanitizer.sanitize_filename("report.pdf")
        assert result == "report.pdf"

    def test_sanitize_filename_strips_path(self):
        result = InputSanitizer.sanitize_filename("../../etc/passwd")
        # Should not contain path separators
        assert "/" not in result
        assert "\\" not in result

    def test_sanitize_filename_empty_after_sanitization(self):
        with pytest.raises(ValueError, match="empty"):
            InputSanitizer.sanitize_filename("...")

    def test_sanitize_dict_basic(self):
        result = InputSanitizer.sanitize_dict({"key": "value", "num": 42})
        assert result["num"] == 42
        assert isinstance(result["key"], str)

    def test_sanitize_dict_nested(self):
        result = InputSanitizer.sanitize_dict({"a": {"b": "c"}})
        assert result["a"]["b"] == "c"

    def test_sanitize_dict_max_depth_exceeded(self):
        deep = {"a": {"b": {"c": {"d": {"e": {"f": "too deep"}}}}}}
        with pytest.raises(ValueError, match="depth"):
            InputSanitizer.sanitize_dict(deep, max_depth=3)

    def test_sanitize_dict_list_values(self):
        result = InputSanitizer.sanitize_dict({"items": ["a", "b"]})
        assert result["items"] == ["a", "b"]

    def test_sanitize_dict_unsupported_type(self):
        with pytest.raises(TypeError, match="Unsupported"):
            InputSanitizer.sanitize_dict({"key": object()})

    def test_sanitize_dict_bool_and_none(self):
        result = InputSanitizer.sanitize_dict({"flag": True, "empty": None})
        assert result["flag"] is True
        assert result["empty"] is None

    def test_sanitize_iframe_rejected(self):
        with pytest.raises(ValueError, match="malicious"):
            InputSanitizer.sanitize_string("<iframe src='evil.com'></iframe>")

    def test_sanitize_event_handler_rejected(self):
        with pytest.raises(ValueError, match="malicious"):
            InputSanitizer.sanitize_string('div onload="steal()"')


# ---------------------------------------------------------------------------
# SQLInjectionPreventer
# ---------------------------------------------------------------------------


class TestSQLInjectionPreventer:
    def test_detect_union_select(self):
        assert SQLInjectionPreventer.detect_injection("1 UNION SELECT * FROM users") is True

    def test_detect_drop_table(self):
        assert SQLInjectionPreventer.detect_injection("DROP TABLE users") is True

    def test_detect_insert_into(self):
        assert SQLInjectionPreventer.detect_injection("INSERT INTO users VALUES (1)") is True

    def test_detect_update_set(self):
        assert SQLInjectionPreventer.detect_injection("UPDATE users SET admin=1") is True

    def test_detect_delete_from(self):
        assert SQLInjectionPreventer.detect_injection("DELETE FROM users WHERE 1=1") is True

    def test_detect_or_equals(self):
        assert SQLInjectionPreventer.detect_injection("' OR 1=1 --") is True

    def test_detect_xp_cmdshell(self):
        assert SQLInjectionPreventer.detect_injection("EXEC xp_cmdshell 'dir'") is True

    def test_detect_information_schema(self):
        assert SQLInjectionPreventer.detect_injection("SELECT * FROM INFORMATION_SCHEMA.TABLES") is True

    def test_safe_input(self):
        assert SQLInjectionPreventer.detect_injection("John Smith") is False

    def test_safe_uuid(self):
        assert SQLInjectionPreventer.detect_injection("550e8400-e29b-41d4-a716-446655440000") is False

    def test_check_injection_raises(self):
        with pytest.raises(ValueError, match="malicious SQL"):
            SQLInjectionPreventer.check_injection("UNION SELECT 1", "user_input")

    def test_check_injection_safe(self):
        result = SQLInjectionPreventer.check_injection("hello", "field")
        assert result == "hello"

    def test_safe_like_value(self):
        result = SQLInjectionPreventer.safe_like_value("100%_done\\end")
        assert "\\%" in result
        assert "\\_" in result
        assert "\\\\" in result

    def test_validate_column_name_valid(self):
        result = SQLInjectionPreventer.validate_column_name(
            "severity", {"severity", "created_at", "status"}
        )
        assert result == "severity"

    def test_validate_column_name_not_in_allowed(self):
        with pytest.raises(ValueError, match="not in the allowed list"):
            SQLInjectionPreventer.validate_column_name(
                "password_hash", {"severity", "created_at"}
            )

    def test_validate_column_name_invalid_chars(self):
        with pytest.raises(ValueError, match="invalid characters"):
            SQLInjectionPreventer.validate_column_name("col;DROP", {"col;DROP"})

    def test_validate_table_name_valid(self):
        result = SQLInjectionPreventer.validate_table_name(
            "findings", {"findings", "users"}
        )
        assert result == "findings"

    def test_validate_table_name_invalid(self):
        with pytest.raises(ValueError, match="not in the allowed list"):
            SQLInjectionPreventer.validate_table_name("admin_table", {"findings"})

    def test_validate_table_name_bad_chars(self):
        with pytest.raises(ValueError, match="invalid characters"):
            SQLInjectionPreventer.validate_table_name("t;--", {"t;--"})

    def test_build_safe_params_clean(self):
        params = {"name": "John", "age": 30}
        result = SQLInjectionPreventer.build_safe_params(params)
        assert result == params

    def test_build_safe_params_with_injection(self):
        with pytest.raises(ValueError, match="malicious SQL"):
            SQLInjectionPreventer.build_safe_params({
                "name": "'; DROP TABLE users; --"
            })

    def test_build_safe_params_non_string_passthrough(self):
        params = {"count": 42, "active": True, "ratio": 0.5}
        result = SQLInjectionPreventer.build_safe_params(params)
        assert result["count"] == 42
        assert result["active"] is True


# ---------------------------------------------------------------------------
# PathTraversalPreventer
# ---------------------------------------------------------------------------


class TestPathTraversalPreventer:
    def test_detect_dot_dot_slash(self):
        assert PathTraversalPreventer.detect_traversal("../../etc/passwd") is True

    def test_detect_encoded_traversal(self):
        assert PathTraversalPreventer.detect_traversal("%2e%2e%2f") is True

    def test_detect_double_encoded(self):
        assert PathTraversalPreventer.detect_traversal("%252e%252e%252f") is True

    def test_safe_path_component(self):
        assert PathTraversalPreventer.detect_traversal("report.pdf") is False

    def test_safe_path_resolution(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            # Create a test file
            test_file = base / "report.pdf"
            test_file.touch()
            result = PathTraversalPreventer.safe_path("report.pdf", base)
            assert result == test_file.resolve()

    def test_safe_path_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            with pytest.raises(ValueError, match="traversal"):
                PathTraversalPreventer.safe_path("../../etc/passwd", base)

    def test_safe_path_extension_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "file.exe").touch()
            with pytest.raises(ValueError, match="extension"):
                PathTraversalPreventer.safe_path(
                    "file.exe", base, allow_extensions=[".pdf", ".json"]
                )

    def test_safe_path_allowed_extension(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "report.json").touch()
            result = PathTraversalPreventer.safe_path(
                "report.json", base, allow_extensions=[".json", ".pdf"]
            )
            assert result.suffix == ".json"

    def test_sanitize_filename(self):
        result = PathTraversalPreventer.sanitize_filename("/etc/passwd")
        assert result == "passwd"

    def test_sanitize_filename_strips_dots(self):
        result = PathTraversalPreventer.sanitize_filename(".hidden")
        assert result == "hidden"

    def test_sanitize_filename_empty_raises(self):
        with pytest.raises(ValueError, match="empty"):
            PathTraversalPreventer.sanitize_filename("...")

    def test_backslash_traversal(self):
        assert PathTraversalPreventer.detect_traversal("..\\windows\\system32") is True


# ---------------------------------------------------------------------------
# SSRFProtection
# ---------------------------------------------------------------------------


class TestSSRFProtection:
    def test_valid_https_url(self):
        ssrf = SSRFProtection()
        result = ssrf.validate_url("https://api.example.com/data")
        assert result == "https://api.example.com/data"

    def test_rejects_http_by_default(self):
        ssrf = SSRFProtection()
        with pytest.raises(ValueError, match="scheme"):
            ssrf.validate_url("http://example.com")

    def test_allows_http_when_configured(self):
        ssrf = SSRFProtection(allowed_schemes=["http", "https"])
        result = ssrf.validate_url("http://example.com")
        assert result == "http://example.com"

    def test_rejects_ftp(self):
        ssrf = SSRFProtection()
        with pytest.raises(ValueError, match="scheme"):
            ssrf.validate_url("ftp://example.com/file")

    def test_rejects_cloud_metadata(self):
        ssrf = SSRFProtection(allowed_schemes=["http", "https"])
        with pytest.raises(ValueError, match="blocked"):
            ssrf.validate_url("http://169.254.169.254/latest/meta-data/")

    def test_rejects_private_ip(self):
        ssrf = SSRFProtection(allowed_schemes=["http", "https"])
        with pytest.raises(ValueError, match="private"):
            ssrf.validate_url("http://10.0.0.1/admin")

    def test_rejects_loopback(self):
        ssrf = SSRFProtection(allowed_schemes=["http", "https"])
        with pytest.raises(ValueError, match="private"):
            ssrf.validate_url("http://127.0.0.1/admin")

    def test_rejects_link_local(self):
        ssrf = SSRFProtection(allowed_schemes=["http", "https"])
        with pytest.raises(ValueError, match="private"):
            ssrf.validate_url("http://169.254.1.1/info")

    def test_allows_private_when_configured(self):
        ssrf = SSRFProtection(allowed_schemes=["http", "https"], allow_private=True)
        result = ssrf.validate_url("http://192.168.1.1/api")
        assert "192.168.1.1" in result

    def test_rejects_no_hostname(self):
        ssrf = SSRFProtection()
        with pytest.raises(ValueError, match="hostname"):
            ssrf.validate_url("https://")

    def test_rejects_gcp_metadata(self):
        ssrf = SSRFProtection(allowed_schemes=["http", "https"])
        with pytest.raises(ValueError, match="blocked"):
            ssrf.validate_url("http://metadata.google.internal/computeMetadata/")

    def test_custom_blocked_hosts(self):
        ssrf = SSRFProtection(
            allowed_schemes=["https"],
            blocked_hosts={"evil.internal"},
        )
        with pytest.raises(ValueError, match="blocked"):
            ssrf.validate_url("https://evil.internal/steal")

    def test_rejects_rfc1918_172_range(self):
        ssrf = SSRFProtection(allowed_schemes=["http", "https"])
        with pytest.raises(ValueError, match="private"):
            ssrf.validate_url("http://172.16.0.1/internal")


# ---------------------------------------------------------------------------
# EndpointRateLimitConfig
# ---------------------------------------------------------------------------


class TestEndpointRateLimitConfig:
    def test_defaults(self):
        config = EndpointRateLimitConfig()
        assert config.max_requests == 100  # default from env
        assert config.window_seconds == 60
        assert config.burst_multiplier == 1.5
        assert config.penalty_seconds == 60
        assert config.key_by == "ip"

    def test_custom_config(self):
        config = EndpointRateLimitConfig(
            max_requests=5, window_seconds=30, key_by="api_key"
        )
        assert config.max_requests == 5
        assert config.window_seconds == 30
        assert config.key_by == "api_key"


# ---------------------------------------------------------------------------
# RateLimiter
# ---------------------------------------------------------------------------


class TestSecurityRateLimiter:
    def test_init_default(self):
        from core.security_hardening import RateLimiter as SHRateLimiter
        limiter = SHRateLimiter()
        assert limiter.default_config is not None
        assert limiter.configs == {}

    def test_get_config_default(self):
        from core.security_hardening import RateLimiter as SHRateLimiter
        limiter = SHRateLimiter()
        config = limiter.get_config("/api/v1/some/path")
        assert config.max_requests == 100

    def test_get_config_exact_match(self):
        from core.security_hardening import RateLimiter as SHRateLimiter
        custom = EndpointRateLimitConfig(max_requests=5)
        limiter = SHRateLimiter(configs={"/api/v1/auth/login": custom})
        config = limiter.get_config("/api/v1/auth/login")
        assert config.max_requests == 5

    def test_get_config_prefix_match(self):
        from core.security_hardening import RateLimiter as SHRateLimiter
        custom = EndpointRateLimitConfig(max_requests=10)
        limiter = SHRateLimiter(configs={"/api/v1/scan": custom})
        config = limiter.get_config("/api/v1/scan/start")
        assert config.max_requests == 10


# ---------------------------------------------------------------------------
# IPAccessManager
# ---------------------------------------------------------------------------


class TestIPAccessManager:
    def test_init(self):
        from core.security_hardening import IPAccessManager
        mgr = IPAccessManager()
        assert mgr is not None

    def test_add_to_allowlist(self):
        from core.security_hardening import IPAccessManager
        mgr = IPAccessManager()
        mgr.add_to_allowlist("10.0.0.1")
        assert mgr.is_allowed("10.0.0.1") is True

    def test_add_to_denylist(self):
        from core.security_hardening import IPAccessManager
        mgr = IPAccessManager()
        mgr.add_to_denylist("192.168.1.100")
        # Denied IPs should NOT be allowed
        assert mgr.is_allowed("192.168.1.100") is False

    def test_denylist_allows_other_ips(self):
        from core.security_hardening import IPAccessManager
        mgr = IPAccessManager()
        mgr.add_to_denylist("192.168.1.100")
        # Other IPs should still be allowed
        assert mgr.is_allowed("10.0.0.1") is True

    def test_remove_from_denylist(self):
        from core.security_hardening import IPAccessManager
        mgr = IPAccessManager()
        mgr.add_to_denylist("192.168.1.100")
        mgr.remove_from_denylist("192.168.1.100")
        assert mgr.is_allowed("192.168.1.100") is True

    def test_invalid_ip_denied(self):
        from core.security_hardening import IPAccessManager
        mgr = IPAccessManager()
        # Invalid IP should be denied
        assert mgr.is_allowed("not-an-ip") is False


# ---------------------------------------------------------------------------
# SessionManager
# ---------------------------------------------------------------------------


class TestSessionManager:
    def _mock_request(self, ip="1.2.3.4"):
        """Create a minimal mock request for SessionManager."""
        from unittest.mock import MagicMock
        req = MagicMock()
        req.client.host = ip
        req.headers = {}
        return req

    def test_init(self):
        from core.security_hardening import SessionManager
        mgr = SessionManager()
        assert mgr is not None
        assert mgr.timeout_minutes == 60  # default

    def test_create_session(self):
        from core.security_hardening import SessionManager
        mgr = SessionManager()
        req = self._mock_request()
        session_id = mgr.create(user_id="user-123", request=req)
        assert session_id is not None
        assert len(session_id) > 0

    def test_get_session(self):
        from core.security_hardening import SessionManager
        mgr = SessionManager()
        req = self._mock_request()
        session_id = mgr.create(user_id="user-456", request=req)
        session = mgr.get(session_id, request=req)
        assert session is not None
        assert session.user_id == "user-456"

    def test_delete_session(self):
        from core.security_hardening import SessionManager
        mgr = SessionManager()
        req = self._mock_request()
        session_id = mgr.create(user_id="user-789", request=req)
        mgr.delete(session_id)
        with pytest.raises(Exception):
            mgr.get(session_id)

    def test_max_sessions_per_user(self):
        from core.security_hardening import SessionManager
        mgr = SessionManager(max_sessions_per_user=2)
        req = self._mock_request()
        mgr.create("user-max", req)
        mgr.create("user-max", req)
        # Third should still work (evicts oldest)
        sid3 = mgr.create("user-max", req)
        assert sid3 is not None


# ---------------------------------------------------------------------------
# SecurityAuditLogger
# ---------------------------------------------------------------------------


class TestSecurityAuditLogger:
    def test_init(self):
        from core.security_hardening import SecurityAuditLogger
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "audit.db")
            audit_logger = SecurityAuditLogger(db_path=db_path)
            assert audit_logger is not None

    def test_event_type_constants(self):
        from core.security_hardening import SecurityAuditLogger
        assert SecurityAuditLogger.EVENT_AUTH == "AUTH"
        assert SecurityAuditLogger.EVENT_ACCESS == "ACCESS"
        assert SecurityAuditLogger.EVENT_SECURITY == "SECURITY"
        assert SecurityAuditLogger.EVENT_SYSTEM == "SYSTEM"

    def test_severity_constants(self):
        from core.security_hardening import SecurityAuditLogger
        assert SecurityAuditLogger.SEV_INFO == "INFO"
        assert SecurityAuditLogger.SEV_HIGH == "HIGH"
        assert SecurityAuditLogger.SEV_CRITICAL == "CRITICAL"

    def test_log_auth(self):
        from core.security_hardening import SecurityAuditLogger
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "audit.db")
            audit = SecurityAuditLogger(db_path=db_path)
            audit.log_auth(
                action="login_success",
                outcome="success",
                user_id="user-001",
                ip_address="1.2.3.4",
            )

    def test_log_security_event(self):
        from core.security_hardening import SecurityAuditLogger
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "audit.db")
            audit = SecurityAuditLogger(db_path=db_path)
            audit.log_security_event(
                action="sql_injection_attempt",
                details={"field": "username", "pattern": "UNION SELECT"},
                ip_address="1.2.3.4",
            )

    def test_log_access(self):
        from core.security_hardening import SecurityAuditLogger
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "audit.db")
            audit = SecurityAuditLogger(db_path=db_path)
            audit.log_access(
                action="read",
                resource_type="finding",
                resource_id="FIND-001",
                user_id="user-002",
            )

    def test_query_events(self):
        from core.security_hardening import SecurityAuditLogger
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, "audit.db")
            audit = SecurityAuditLogger(db_path=db_path)
            audit.log_auth(action="login", user_id="user-q")
            events = audit.query_events(user_id="user-q")
            assert isinstance(events, list)
            assert len(events) >= 1
