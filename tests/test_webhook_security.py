"""
Webhook security hardening tests for ALDECI.

Tests cover:
- SSRF protection: private IP ranges, DNS rebinding, localhost variants, metadata endpoints
- Payload guard: oversized body, deeply nested JSON, key explosion, content type validation
- URL validation: decimal IP, hex IP, IPv6 mapped, double encoding bypass attempts
- Rate limiting: webhook and SSO callback endpoints
- Event emitter: SSRF check on webhook registration

Run with:
    python -m pytest tests/test_webhook_security.py -x --tb=short --timeout=10 -q
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Ensure suite-core and suite-api are importable
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))

from core.exceptions import SSRFError, ValidationError
from core.ssrf_protection import (
    is_private_ip,
    sanitize_redirect_url,
    validate_url,
    validate_url_with_dns,
)
from core.payload_guard import PayloadGuard, _json_depth, _count_keys, payload_guard


# ===========================================================================
# SSRF Protection — is_private_ip
# ===========================================================================


class TestIsPrivateIp:
    def test_loopback_127(self):
        assert is_private_ip("127.0.0.1") is True

    def test_loopback_127_other(self):
        assert is_private_ip("127.100.200.1") is True

    def test_private_10(self):
        assert is_private_ip("10.0.0.1") is True

    def test_private_10_range(self):
        assert is_private_ip("10.255.255.255") is True

    def test_private_172_16(self):
        assert is_private_ip("172.16.0.1") is True

    def test_private_172_31(self):
        assert is_private_ip("172.31.255.255") is True

    def test_private_192_168(self):
        assert is_private_ip("192.168.1.100") is True

    def test_link_local_169_254(self):
        assert is_private_ip("169.254.169.254") is True

    def test_unspecified_0_0_0_0(self):
        assert is_private_ip("0.0.0.0") is True

    def test_ipv6_loopback(self):
        assert is_private_ip("::1") is True

    def test_ipv6_link_local(self):
        assert is_private_ip("fe80::1") is True

    def test_ipv6_unique_local(self):
        assert is_private_ip("fc00::1") is True

    def test_ipv4_mapped_private(self):
        # ::ffff:10.0.0.1 maps to 10.0.0.1
        assert is_private_ip("::ffff:10.0.0.1") is True

    def test_decimal_ip_loopback(self):
        # 2130706433 == 127.0.0.1
        assert is_private_ip("2130706433") is True

    def test_hex_ip_loopback(self):
        # 0x7f000001 == 127.0.0.1
        assert is_private_ip("0x7f000001") is True

    def test_public_ip_not_private(self):
        assert is_private_ip("8.8.8.8") is False

    def test_public_ip_1_1_1_1(self):
        assert is_private_ip("1.1.1.1") is False

    def test_172_15_not_private(self):
        # 172.15.x.x is NOT in RFC1918 (172.16.0.0/12 starts at 172.16)
        assert is_private_ip("172.15.255.255") is False

    def test_172_32_not_private(self):
        # 172.32.x.x is NOT in RFC1918 (172.16.0.0/12 ends at 172.31)
        assert is_private_ip("172.32.0.1") is False


# ===========================================================================
# SSRF Protection — validate_url
# ===========================================================================


class TestValidateUrl:
    def test_valid_https(self):
        result = validate_url("https://example.com/webhook")
        assert "example.com" in result

    def test_valid_http(self):
        result = validate_url("http://example.com/hook")
        assert result is not None

    def test_blocked_localhost(self):
        with pytest.raises(SSRFError, match="loopback|blocked"):
            validate_url("http://localhost/admin")

    def test_blocked_localhost_subdomain(self):
        with pytest.raises(SSRFError):
            validate_url("http://evil.localhost/")

    def test_blocked_127_loopback(self):
        with pytest.raises(SSRFError):
            validate_url("http://127.0.0.1/secret")

    def test_blocked_private_10(self):
        with pytest.raises(SSRFError):
            validate_url("http://10.0.0.1/internal")

    def test_blocked_private_192_168(self):
        with pytest.raises(SSRFError):
            validate_url("http://192.168.1.1/router")

    def test_blocked_private_172_16(self):
        with pytest.raises(SSRFError):
            validate_url("http://172.16.0.1/")

    def test_blocked_link_local_metadata(self):
        with pytest.raises(SSRFError):
            validate_url("http://169.254.169.254/latest/meta-data/")

    def test_blocked_metadata_hostname(self):
        with pytest.raises(SSRFError):
            validate_url("http://metadata.google.internal/computeMetadata/v1/")

    def test_blocked_file_scheme(self):
        with pytest.raises(SSRFError, match="scheme"):
            validate_url("file:///etc/passwd")

    def test_blocked_ftp_scheme(self):
        with pytest.raises(SSRFError, match="scheme"):
            validate_url("ftp://example.com/file")

    def test_blocked_decimal_ip_loopback(self):
        # http://2130706433/ == http://127.0.0.1/
        with pytest.raises(SSRFError):
            validate_url("http://2130706433/")

    def test_blocked_hex_ip_loopback(self):
        # http://0x7f000001/ == http://127.0.0.1/
        with pytest.raises(SSRFError):
            validate_url("http://0x7f000001/")

    def test_double_encoded_scheme_blocked(self):
        # Double-encoded colon in scheme should not bypass check
        with pytest.raises(SSRFError):
            validate_url("http%3A%2F%2F127.0.0.1/")

    def test_empty_url_raises(self):
        with pytest.raises(SSRFError):
            validate_url("")

    def test_ipv6_loopback_blocked(self):
        with pytest.raises(SSRFError):
            validate_url("http://[::1]/secret")

    def test_ipv6_private_blocked(self):
        with pytest.raises(SSRFError):
            validate_url("http://[fc00::1]/internal")


# ===========================================================================
# SSRF Protection — sanitize_redirect_url
# ===========================================================================


class TestSanitizeRedirectUrl:
    def test_relative_path_allowed(self):
        result = sanitize_redirect_url("/dashboard", [])
        assert result == "/dashboard"

    def test_relative_path_with_query(self):
        result = sanitize_redirect_url("/login?next=/home", [])
        assert result.startswith("/")

    def test_allowed_domain_exact_match(self):
        result = sanitize_redirect_url("https://app.example.com/done", ["example.com"])
        assert "example.com" in result

    def test_allowed_domain_subdomain_match(self):
        result = sanitize_redirect_url("https://sub.example.com/done", ["example.com"])
        assert "sub.example.com" in result

    def test_blocked_domain_not_in_allowlist(self):
        with pytest.raises(SSRFError, match="not permitted"):
            sanitize_redirect_url("https://evil.com/steal", ["example.com"])

    def test_blocked_absolute_url_no_allowed_domains(self):
        with pytest.raises(SSRFError):
            sanitize_redirect_url("https://example.com/done", [])

    def test_blocked_private_ip_redirect(self):
        with pytest.raises(SSRFError):
            sanitize_redirect_url("http://192.168.1.1/admin", ["example.com"])

    def test_empty_url_raises(self):
        with pytest.raises(SSRFError):
            sanitize_redirect_url("", [])


# ===========================================================================
# Payload Guard — JSON structure
# ===========================================================================


class TestJsonDepth:
    def test_flat_dict(self):
        assert _json_depth({"a": 1, "b": 2}) == 1

    def test_nested_dict(self):
        assert _json_depth({"a": {"b": {"c": 1}}}) == 3

    def test_empty_dict(self):
        assert _json_depth({}) == 1

    def test_list_of_dicts(self):
        data = [{"a": 1}, {"b": {"c": 2}}]
        assert _json_depth(data) == 3

    def test_scalar(self):
        assert _json_depth(42) == 0

    def test_deeply_nested(self):
        data: Any = {}
        current = data
        for i in range(15):
            current["child"] = {}
            current = current["child"]
        assert _json_depth(data) > 10


class TestCountKeys:
    def test_flat_dict(self):
        assert _count_keys({"a": 1, "b": 2, "c": 3}) == 3

    def test_nested_dict(self):
        assert _count_keys({"a": {"b": 1, "c": 2}}) == 3

    def test_empty_dict(self):
        assert _count_keys({}) == 0

    def test_list_of_dicts(self):
        assert _count_keys([{"a": 1}, {"b": 2}]) == 2

    def test_scalar(self):
        assert _count_keys(42) == 0


class TestPayloadGuard:
    def setup_method(self):
        self.guard = PayloadGuard(
            max_body_size=100,
            max_json_depth=3,
            max_json_keys=5,
        )

    def test_validate_json_depth_ok(self):
        self.guard.validate_json_depth({"a": {"b": 1}})  # depth 2 — ok

    def test_validate_json_depth_exceeded(self):
        deep = {"a": {"b": {"c": {"d": 1}}}}  # depth 4 > 3
        with pytest.raises(ValidationError, match="depth"):
            self.guard.validate_json_depth(deep)

    def test_validate_json_keys_ok(self):
        self.guard.validate_json_keys({"a": 1, "b": 2})  # 2 keys — ok

    def test_validate_json_keys_exceeded(self):
        data = {str(i): i for i in range(10)}  # 10 keys > 5
        with pytest.raises(ValidationError, match="keys"):
            self.guard.validate_json_keys(data)

    def test_validate_content_type_ok(self):
        request = MagicMock()
        request.headers = {"content-type": "application/json; charset=utf-8"}
        self.guard.validate_content_type(request, ["application/json"])

    def test_validate_content_type_wrong(self):
        request = MagicMock()
        request.headers = {"content-type": "text/plain"}
        with pytest.raises(Exception) as exc_info:
            self.guard.validate_content_type(request, ["application/json"])
        assert exc_info.value.status_code == 415

    def test_validate_content_type_no_restriction(self):
        request = MagicMock()
        request.headers = {"content-type": "text/plain"}
        # Should not raise when allowed list is empty
        self.guard.validate_content_type(request, [])


# ===========================================================================
# Payload Guard — async body size (using async generator mocking)
# ===========================================================================


@pytest.mark.asyncio
async def test_body_size_within_limit():
    guard = PayloadGuard(max_body_size=100)
    body_data = b"x" * 50  # 50 bytes — under 100 limit

    async def _stream():
        yield body_data

    request = MagicMock()
    request.stream = _stream
    result = await guard.validate_body_size(request)
    assert result == body_data


@pytest.mark.asyncio
async def test_body_size_exceeds_limit():
    from fastapi import HTTPException as FastAPIHTTPException
    guard = PayloadGuard(max_body_size=100)
    body_data = b"x" * 200  # 200 bytes — over 100 limit

    async def _stream():
        yield body_data

    request = MagicMock()
    request.stream = _stream
    with pytest.raises(FastAPIHTTPException) as exc_info:
        await guard.validate_body_size(request)
    assert exc_info.value.status_code == 413


# ===========================================================================
# Event Emitter SSRF protection
# ===========================================================================


class TestEventEmitterSsrf:
    def test_register_private_ip_blocked(self):
        from core.event_emitter import EventEmitter, EventType
        emitter = EventEmitter(db_path=":memory:")
        from core.exceptions import ConnectorError
        with pytest.raises(ConnectorError, match="SSRF"):
            emitter.register_webhook(
                "http://10.0.0.1/hook",
                [EventType.FINDING_CREATED],
                "secret",
            )

    def test_register_localhost_blocked(self):
        from core.event_emitter import EventEmitter, EventType
        from core.exceptions import ConnectorError
        emitter = EventEmitter(db_path=":memory:")
        with pytest.raises(ConnectorError, match="SSRF"):
            emitter.register_webhook(
                "http://localhost/hook",
                [EventType.FINDING_CREATED],
            )

    def test_register_metadata_endpoint_blocked(self):
        from core.event_emitter import EventEmitter, EventType
        from core.exceptions import ConnectorError
        emitter = EventEmitter(db_path=":memory:")
        with pytest.raises(ConnectorError, match="SSRF"):
            emitter.register_webhook(
                "http://169.254.169.254/latest/meta-data/",
                [EventType.FINDING_CREATED],
            )

    def test_register_valid_url_accepted(self):
        from core.event_emitter import EventEmitter, EventType
        emitter = EventEmitter(db_path=":memory:")
        # patch sqlite to avoid actual db write, just verify no SSRF error raised
        with patch.object(emitter, "_lock"), \
             patch("core.event_emitter._get_db") as mock_db:
            mock_conn = MagicMock()
            mock_conn.__enter__ = MagicMock(return_value=mock_conn)
            mock_conn.__exit__ = MagicMock(return_value=False)
            mock_db.return_value = mock_conn
            # Should not raise SSRFError — public URL
            try:
                emitter.register_webhook(
                    "https://hooks.example.com/aldeci",
                    [EventType.FINDING_CREATED],
                    "secret",
                )
            except Exception as exc:
                # Allow DB errors (sqlite in-memory mock), but not SSRF errors
                assert "SSRF" not in str(exc), f"Unexpected SSRF error: {exc}"


# ===========================================================================
# Webhook rate limiting
# ===========================================================================


class TestWebhookRateLimiting:
    def test_rate_limit_blocks_after_limit(self):
        """After 10 requests, the 11th should be rate-limited."""
        from apps.api.material_change_router import _check_webhook_rate_limit, _rate_store, _WEBHOOK_RATE_LIMIT
        from fastapi import HTTPException

        # Clear any existing state for test IP
        test_ip = "203.0.113.99"
        _rate_store[test_ip] = []

        mock_request = MagicMock()
        mock_request.client.host = test_ip

        # Fill up to the limit
        for _ in range(_WEBHOOK_RATE_LIMIT):
            _check_webhook_rate_limit(mock_request)

        # The next one should be blocked
        with pytest.raises(HTTPException) as exc_info:
            _check_webhook_rate_limit(mock_request)
        assert exc_info.value.status_code == 429

    def test_rate_limit_resets_after_window(self):
        """After the window expires, requests should be allowed again."""
        from apps.api.material_change_router import _check_webhook_rate_limit, _rate_store, _WEBHOOK_RATE_LIMIT
        from fastapi import HTTPException

        test_ip = "203.0.113.88"
        # Simulate old timestamps (outside window)
        old_time = time.monotonic() - 120  # 2 minutes ago
        _rate_store[test_ip] = [old_time] * _WEBHOOK_RATE_LIMIT

        mock_request = MagicMock()
        mock_request.client.host = test_ip

        # Should succeed because old timestamps are evicted
        _check_webhook_rate_limit(mock_request)  # Must not raise


# ===========================================================================
# validate_url_with_dns — basic smoke test (mocked DNS)
# ===========================================================================


class TestValidateUrlWithDns:
    def test_public_hostname_with_public_ip(self):
        """DNS resolving to a public IP should pass."""
        import socket
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 0))
            ]
            result = validate_url_with_dns("https://example.com/hook")
            assert "example.com" in result

    def test_dns_rebinding_blocked(self):
        """DNS rebinding: hostname looks public but resolves to private IP."""
        import socket
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("192.168.1.1", 0))
            ]
            with pytest.raises(SSRFError, match="private IP"):
                validate_url_with_dns("https://evil-rebind.example.com/hook")

    def test_dns_failure_raises_ssrf(self):
        """DNS resolution failure should raise SSRFError."""
        import socket
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("DNS failed")):
            with pytest.raises(SSRFError, match="DNS resolution failed"):
                validate_url_with_dns("https://nonexistent.invalid/hook")
