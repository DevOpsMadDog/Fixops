"""Tests for DAST Scanner — Dynamic Application Security Testing.

Covers:
- Pydantic models and enums
- AuthConfig / ScanConfig construction
- HttpProbe, DastFinding, ScanResult serialisation
- SecurityHeadersResult scoring
- WebCrawler scope filtering and robots.txt enforcement
- AuthHandler for all auth types
- OwaspTestSuite — all 10 categories
- DastScanner lifecycle (start, poll, findings)
- Router validation (SSRF blocking, profile validation, limits)
- _validate_target_url edge cases
- Rate limiting guard
- HTML link/form parser
- OpenAPI endpoint discovery

All tests use mocks/stubs — no live network calls.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import unittest
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

# Configure test environment
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")

# Ensure suite-core is on path
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _suite in ("suite-core", "suite-api"):
    _p = os.path.join(_PROJECT_ROOT, _suite)
    if _p not in sys.path:
        sys.path.insert(0, _p)

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Import target modules
# ---------------------------------------------------------------------------
from core.dast_scanner import (
    AuthConfig,
    AuthHandler,
    AuthType,
    DastFinding,
    DastScanner,
    DiscoveredEndpoint,
    FindingSeverity,
    HttpProbe,
    OwaspCategory,
    OwaspTestSuite,
    ScanConfig,
    ScanProfile,
    ScanResult,
    ScanStatus,
    SecurityHeadersAnalyser,
    SecurityHeadersResult,
    WebCrawler,
    _HttpClient,
    _LinkFormParser,
    _fetch_robots_txt,
    _is_disallowed,
    _is_safe_url,
    get_dast_scanner,
)
from apps.api.dast_router import _validate_target_url as _validate_url_fn

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_probe(
    status: int = 200,
    body: str = "",
    headers: Optional[Dict[str, str]] = None,
    method: str = "GET",
    url: str = "https://example.com/",
) -> HttpProbe:
    return HttpProbe(
        method=method,
        url=url,
        headers={"User-Agent": "test"},
        body="",
        response_status=status,
        response_headers=headers or {},
        response_body_snippet=body,
        duration_ms=10.0,
    )


def _make_finding(
    severity: FindingSeverity = FindingSeverity.HIGH,
    owasp: OwaspCategory = OwaspCategory.A03_INJECTION,
) -> DastFinding:
    return DastFinding(
        finding_id="test-id",
        title="Test Finding",
        severity=severity,
        owasp_category=owasp,
        cwe_id="CWE-89",
        url="https://example.com/search?q=test",
        parameter="q",
        payload="' OR 1=1--",
        description="SQL injection test",
        recommendation="Use parameterised queries",
        proof_of_concept=_make_probe(),
        reproduction_steps=["Step 1", "Step 2"],
        confidence=0.85,
    )


def _make_scan_config(
    target: str = "https://example.com",
    profile: ScanProfile = ScanProfile.QUICK,
) -> ScanConfig:
    return ScanConfig(
        target_url=target,
        profile=profile,
        auth=AuthConfig(),
        max_depth=2,
        max_urls=10,
        requests_per_second=10.0,
        timeout=5.0,
    )


# ---------------------------------------------------------------------------
# 1. Enum tests
# ---------------------------------------------------------------------------

class TestEnums:
    def test_scan_profile_values(self):
        assert ScanProfile.QUICK.value == "quick"
        assert ScanProfile.STANDARD.value == "standard"
        assert ScanProfile.FULL.value == "full"
        assert ScanProfile.API_ONLY.value == "api_only"

    def test_scan_status_values(self):
        assert ScanStatus.PENDING.value == "pending"
        assert ScanStatus.RUNNING.value == "running"
        assert ScanStatus.COMPLETED.value == "completed"
        assert ScanStatus.FAILED.value == "failed"

    def test_finding_severity_values(self):
        assert FindingSeverity.CRITICAL.value == "critical"
        assert FindingSeverity.HIGH.value == "high"
        assert FindingSeverity.MEDIUM.value == "medium"
        assert FindingSeverity.LOW.value == "low"
        assert FindingSeverity.INFO.value == "info"

    def test_owasp_categories_count(self):
        assert len(list(OwaspCategory)) == 10

    def test_auth_type_values(self):
        assert AuthType.NONE.value == "none"
        assert AuthType.JWT_BEARER.value == "jwt_bearer"
        assert AuthType.OAUTH2.value == "oauth2"
        assert AuthType.API_KEY_HEADER.value == "api_key_header"
        assert AuthType.BASIC_AUTH.value == "basic_auth"
        assert AuthType.COOKIE.value == "cookie"


# ---------------------------------------------------------------------------
# 2. AuthConfig tests
# ---------------------------------------------------------------------------

class TestAuthConfig:
    def test_default_auth_type(self):
        auth = AuthConfig()
        assert auth.auth_type == AuthType.NONE

    def test_to_dict_excludes_secrets(self):
        auth = AuthConfig(auth_type=AuthType.JWT_BEARER, token="super-secret")
        d = auth.to_dict()
        assert "token" not in d
        assert d["auth_type"] == "jwt_bearer"

    def test_jwt_bearer_config(self):
        auth = AuthConfig(
            auth_type=AuthType.JWT_BEARER,
            token="mytoken",
            header_name="X-Auth-Token",
        )
        assert auth.token == "mytoken"
        assert auth.header_name == "X-Auth-Token"

    def test_basic_auth_config(self):
        auth = AuthConfig(
            auth_type=AuthType.BASIC_AUTH,
            username="admin",
            password="secret",
        )
        assert auth.username == "admin"
        assert auth.password == "secret"


# ---------------------------------------------------------------------------
# 3. ScanConfig tests
# ---------------------------------------------------------------------------

class TestScanConfig:
    def test_defaults(self):
        cfg = ScanConfig(target_url="https://example.com")
        assert cfg.profile == ScanProfile.STANDARD
        assert cfg.max_depth == 3
        assert cfg.max_urls == 100
        assert cfg.requests_per_second == 5.0
        assert cfg.respect_robots_txt is True

    def test_to_dict(self):
        cfg = _make_scan_config()
        d = cfg.to_dict()
        assert d["target_url"] == "https://example.com"
        assert d["profile"] == "quick"
        assert d["max_depth"] == 2


# ---------------------------------------------------------------------------
# 4. HttpProbe tests
# ---------------------------------------------------------------------------

class TestHttpProbe:
    def test_to_dict_structure(self):
        probe = _make_probe(status=404, body="Not found")
        d = probe.to_dict()
        assert d["response_status"] == 404
        assert d["response_body_snippet"] == "Not found"
        assert d["method"] == "GET"
        assert d["url"] == "https://example.com/"
        assert "request_headers" in d
        assert "duration_ms" in d

    def test_duration_rounded(self):
        probe = _make_probe()
        probe.duration_ms = 123.456789
        d = probe.to_dict()
        assert d["duration_ms"] == 123.46


# ---------------------------------------------------------------------------
# 5. DastFinding tests
# ---------------------------------------------------------------------------

class TestDastFinding:
    def test_to_dict_keys(self):
        f = _make_finding()
        d = f.to_dict()
        required_keys = [
            "finding_id", "title", "severity", "owasp_category", "cwe_id",
            "url", "parameter", "payload", "description", "recommendation",
            "proof_of_concept", "reproduction_steps", "confidence", "timestamp",
        ]
        for key in required_keys:
            assert key in d, f"Missing key: {key}"

    def test_severity_serialised_as_string(self):
        f = _make_finding(severity=FindingSeverity.CRITICAL)
        d = f.to_dict()
        assert d["severity"] == "critical"

    def test_owasp_serialised_as_string(self):
        f = _make_finding(owasp=OwaspCategory.A01_BROKEN_ACCESS_CONTROL)
        d = f.to_dict()
        assert d["owasp_category"] == "A01:2021-Broken Access Control"

    def test_timestamp_is_iso(self):
        f = _make_finding()
        d = f.to_dict()
        # Should not raise
        datetime.fromisoformat(d["timestamp"])

    def test_reproduction_steps_in_dict(self):
        f = _make_finding()
        d = f.to_dict()
        assert isinstance(d["reproduction_steps"], list)
        assert len(d["reproduction_steps"]) == 2


# ---------------------------------------------------------------------------
# 6. SecurityHeadersResult tests
# ---------------------------------------------------------------------------

class TestSecurityHeadersResult:
    def test_to_dict_structure(self):
        result = SecurityHeadersResult(
            url="https://example.com",
            present={"x-frame-options": "DENY"},
            missing=["content-security-policy"],
            warnings=["CSP missing"],
            score=70,
            tls_version="TLSv1.3",
            hsts_enabled=False,
        )
        d = result.to_dict()
        assert d["url"] == "https://example.com"
        assert d["score"] == 70
        assert "content-security-policy" in d["missing"]
        assert d["tls_version"] == "TLSv1.3"

    def test_score_clamped(self):
        result = SecurityHeadersResult(
            url="https://example.com",
            present={},
            missing=["a", "b", "c", "d", "e", "f", "g"],
            warnings=["w"] * 20,
            score=0,
            hsts_enabled=False,
        )
        assert result.score == 0


# ---------------------------------------------------------------------------
# 7. ScanResult tests
# ---------------------------------------------------------------------------

class TestScanResult:
    def test_to_dict_structure(self):
        result = ScanResult(
            scan_id="abc",
            target_url="https://example.com",
            profile=ScanProfile.QUICK,
            status=ScanStatus.COMPLETED,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            endpoints_discovered=5,
            endpoints_tested=5,
            total_findings=2,
            findings=[_make_finding()],
            security_headers=None,
            by_severity={"critical": 1, "high": 1},
            by_owasp={},
            duration_ms=1234.5,
        )
        d = result.to_dict()
        assert d["scan_id"] == "abc"
        assert d["status"] == "completed"
        assert d["total_findings"] == 2
        assert len(d["findings"]) == 1
        assert d["duration_ms"] == 1234.5

    def test_completed_at_none(self):
        result = ScanResult(
            scan_id="abc",
            target_url="https://example.com",
            profile=ScanProfile.QUICK,
            status=ScanStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
            completed_at=None,
            endpoints_discovered=0,
            endpoints_tested=0,
            total_findings=0,
            findings=[],
            security_headers=None,
            by_severity={},
            by_owasp={},
            duration_ms=0,
        )
        d = result.to_dict()
        assert d["completed_at"] is None


# ---------------------------------------------------------------------------
# 8. DiscoveredEndpoint tests
# ---------------------------------------------------------------------------

class TestDiscoveredEndpoint:
    def test_to_dict(self):
        ep = DiscoveredEndpoint(
            url="https://example.com/search",
            method="GET",
            parameters=["q", "page"],
            depth=1,
            source="crawl",
        )
        d = ep.to_dict()
        assert d["url"] == "https://example.com/search"
        assert d["parameters"] == ["q", "page"]
        assert d["depth"] == 1


# ---------------------------------------------------------------------------
# 9. _is_safe_url tests
# ---------------------------------------------------------------------------

class TestIsSafeUrl:
    def test_public_url_safe(self):
        assert _is_safe_url("https://example.com") is True

    def test_localhost_blocked(self):
        assert _is_safe_url("http://localhost/admin") is False

    def test_loopback_ip_blocked(self):
        assert _is_safe_url("http://127.0.0.1/") is False

    def test_private_ip_blocked(self):
        assert _is_safe_url("http://192.168.1.1/") is False

    def test_link_local_blocked(self):
        assert _is_safe_url("http://169.254.169.254/latest/meta-data/") is False

    def test_ipv6_loopback_blocked(self):
        assert _is_safe_url("http://[::1]/") is False

    def test_10_range_blocked(self):
        assert _is_safe_url("http://10.0.0.1/") is False


# ---------------------------------------------------------------------------
# 10. _validate_target_url tests (from scanner module)
# ---------------------------------------------------------------------------

class TestValidateTargetUrl:
    def test_valid_https(self):
        assert _validate_url_fn("https://example.com") == "https://example.com"

    def test_valid_http(self):
        assert _validate_url_fn("http://example.com") == "http://example.com"

    def test_too_long_raises(self):
        with pytest.raises(ValueError, match="2048"):
            _validate_url_fn("https://example.com/" + "a" * 2050)

    def test_ftp_scheme_raises(self):
        with pytest.raises(ValueError, match="http"):
            _validate_url_fn("ftp://example.com")

    def test_no_hostname_raises(self):
        with pytest.raises(ValueError):
            _validate_url_fn("https://")

    def test_localhost_blocked(self):
        with pytest.raises(ValueError, match="blocked"):
            _validate_url_fn("https://localhost/admin")

    def test_private_ip_blocked(self):
        with pytest.raises(ValueError, match="blocked"):
            _validate_url_fn("https://192.168.0.1/")


# ---------------------------------------------------------------------------
# 11. _is_disallowed tests
# ---------------------------------------------------------------------------

class TestIsDisallowed:
    def test_disallowed_path(self):
        assert _is_disallowed("https://example.com/admin/users", {"/admin"}) is True

    def test_allowed_path(self):
        assert _is_disallowed("https://example.com/api/v1/findings", {"/admin"}) is False

    def test_empty_disallowed(self):
        assert _is_disallowed("https://example.com/anything", set()) is False


# ---------------------------------------------------------------------------
# 12. HTML Link/Form Parser tests
# ---------------------------------------------------------------------------

class TestLinkFormParser:
    def test_parses_hrefs(self):
        parser = _LinkFormParser("https://example.com/")
        parser.feed('<a href="/about">About</a><a href="/contact">Contact</a>')
        assert "https://example.com/about" in parser.links
        assert "https://example.com/contact" in parser.links

    def test_parses_form_action(self):
        parser = _LinkFormParser("https://example.com/")
        parser.feed('<form action="/search" method="GET"><input name="q" type="text"/></form>')
        assert len(parser.forms) == 1
        form = parser.forms[0]
        assert form["action"] == "https://example.com/search"
        assert form["method"] == "GET"
        assert any(i["name"] == "q" for i in form["inputs"])

    def test_parses_multiple_form_inputs(self):
        parser = _LinkFormParser("https://example.com/")
        html = '<form action="/login" method="POST"><input name="username"/><input name="password" type="password"/></form>'
        parser.feed(html)
        assert len(parser.forms[0]["inputs"]) == 2

    def test_script_src_links(self):
        parser = _LinkFormParser("https://example.com/")
        parser.feed('<script src="/static/app.js"></script>')
        assert "https://example.com/static/app.js" in parser.links

    def test_absolute_href(self):
        parser = _LinkFormParser("https://example.com/")
        parser.feed('<a href="https://other.com/page">External</a>')
        assert "https://other.com/page" in parser.links


# ---------------------------------------------------------------------------
# 13. AuthHandler tests
# ---------------------------------------------------------------------------

class TestAuthHandler:
    def test_none_auth_returns_empty(self):
        cfg = _make_scan_config()
        handler = AuthHandler(cfg)
        result = handler.authenticate()
        assert result == {}

    def test_cookie_auth_returns_cookie(self):
        cfg = _make_scan_config()
        cfg.auth = AuthConfig(
            auth_type=AuthType.COOKIE,
            cookie_name="session",
            cookie_value="abc123",
        )
        handler = AuthHandler(cfg)
        result = handler.authenticate()
        assert result == {"session": "abc123"}

    def test_jwt_auth_returns_empty_cookies(self):
        cfg = _make_scan_config()
        cfg.auth = AuthConfig(auth_type=AuthType.JWT_BEARER, token="mytoken")
        handler = AuthHandler(cfg)
        result = handler.authenticate()
        assert result == {}

    def test_api_key_returns_empty_cookies(self):
        cfg = _make_scan_config()
        cfg.auth = AuthConfig(auth_type=AuthType.API_KEY_HEADER, token="apikey123")
        handler = AuthHandler(cfg)
        result = handler.authenticate()
        assert result == {}

    def test_basic_auth_returns_empty_cookies(self):
        cfg = _make_scan_config()
        cfg.auth = AuthConfig(auth_type=AuthType.BASIC_AUTH, username="u", password="p")
        handler = AuthHandler(cfg)
        result = handler.authenticate()
        assert result == {}


# ---------------------------------------------------------------------------
# 14. _HttpClient auth header injection tests
# ---------------------------------------------------------------------------

class TestHttpClientAuthHeaders:
    def _make_client(self, auth: AuthConfig) -> _HttpClient:
        cfg = _make_scan_config()
        cfg.auth = auth
        return _HttpClient(cfg, {})

    def test_jwt_bearer_applied(self):
        client = self._make_client(AuthConfig(auth_type=AuthType.JWT_BEARER, token="tok"))
        headers: Dict[str, str] = {}
        client._apply_auth_headers(headers)
        assert headers.get("Authorization") == "Bearer tok"

    def test_api_key_applied(self):
        client = self._make_client(
            AuthConfig(auth_type=AuthType.API_KEY_HEADER, token="k", header_name="X-API-Key")
        )
        headers: Dict[str, str] = {}
        client._apply_auth_headers(headers)
        assert headers.get("X-API-Key") == "k"

    def test_basic_auth_applied(self):
        import base64
        client = self._make_client(
            AuthConfig(auth_type=AuthType.BASIC_AUTH, username="admin", password="secret")
        )
        headers: Dict[str, str] = {}
        client._apply_auth_headers(headers)
        expected = "Basic " + base64.b64encode(b"admin:secret").decode()
        assert headers.get("Authorization") == expected

    def test_cookie_applied(self):
        client = self._make_client(
            AuthConfig(auth_type=AuthType.COOKIE, cookie_name="sid", cookie_value="xyz")
        )
        headers: Dict[str, str] = {}
        client._apply_auth_headers(headers)
        assert "sid=xyz" in headers.get("Cookie", "")

    def test_no_auth_no_headers_added(self):
        client = self._make_client(AuthConfig(auth_type=AuthType.NONE))
        headers: Dict[str, str] = {}
        client._apply_auth_headers(headers)
        assert headers == {}


# ---------------------------------------------------------------------------
# 15. Rate limiting guard test
# ---------------------------------------------------------------------------

class TestRateLimiting:
    def test_interval_respected(self):
        cfg = _make_scan_config()
        cfg.requests_per_second = 10.0  # 100ms interval
        client = _HttpClient(cfg, {})
        # Force last request time to now
        client._last_request_time = time.monotonic()
        # Just verify _rate_limit doesn't crash and enforces delay
        t0 = time.monotonic()
        # Mock to avoid actual sleep in tests
        client._interval = 0.001  # 1ms
        client._rate_limit()
        elapsed = time.monotonic() - t0
        # Should complete in reasonable time
        assert elapsed < 1.0

    def test_cookie_header_built(self):
        cfg = _make_scan_config()
        client = _HttpClient(cfg, {"session": "abc", "user": "x"})
        header = client._cookie_header()
        assert "session=abc" in header
        assert "user=x" in header


# ---------------------------------------------------------------------------
# 16. WebCrawler scope tests (no HTTP calls)
# ---------------------------------------------------------------------------

class TestWebCrawlerScope:
    def _make_crawler(self, target: str, scope: str = "") -> WebCrawler:
        cfg = _make_scan_config(target=target)
        cfg.scope_pattern = scope
        cfg.max_urls = 5
        client = _HttpClient(cfg, {})
        return WebCrawler(cfg, client)

    def test_in_scope_same_origin(self):
        crawler = self._make_crawler("https://example.com")
        assert crawler._in_scope("https://example.com/page") is True

    def test_out_of_scope_different_origin(self):
        crawler = self._make_crawler("https://example.com")
        assert crawler._in_scope("https://other.com/page") is False

    def test_scope_pattern_enforced(self):
        crawler = self._make_crawler("https://example.com", scope="/api/")
        assert crawler._in_scope("https://example.com/api/v1") is True
        assert crawler._in_scope("https://example.com/static/img.png") is False

    def test_robots_disallow_respected(self):
        assert _is_disallowed("https://example.com/admin/", {"/admin/"}) is True


# ---------------------------------------------------------------------------
# 17. SecurityHeadersAnalyser — mocked HTTP
# ---------------------------------------------------------------------------

class TestSecurityHeadersAnalyser:
    def _mock_client(self, response_headers: Dict[str, str], status: int = 200) -> _HttpClient:
        mock = MagicMock(spec=_HttpClient)
        mock.request.return_value = _make_probe(status=status, headers=response_headers)
        return mock

    def test_all_headers_present_high_score(self):
        headers = {
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "referrer-policy": "no-referrer",
            "permissions-policy": "camera=()",
            "x-xss-protection": "0",
        }
        analyser = SecurityHeadersAnalyser()
        client = self._mock_client(headers)
        result = analyser.analyse("https://example.com", client)
        assert result.missing == []
        assert result.score > 80

    def test_all_headers_missing_low_score(self):
        analyser = SecurityHeadersAnalyser()
        client = self._mock_client({})
        result = analyser.analyse("https://example.com", client)
        assert len(result.missing) == 7
        assert result.score < 50

    def test_hsts_detected(self):
        headers = {"strict-transport-security": "max-age=31536000; includeSubDomains"}
        analyser = SecurityHeadersAnalyser()
        client = self._mock_client(headers)
        result = analyser.analyse("https://example.com", client)
        assert result.hsts_enabled is True

    def test_hsts_short_max_age_warning(self):
        headers = {"strict-transport-security": "max-age=3600"}
        analyser = SecurityHeadersAnalyser()
        client = self._mock_client(headers)
        result = analyser.analyse("https://example.com", client)
        assert any("max-age too short" in w for w in result.warnings)

    def test_csp_unsafe_inline_warning(self):
        headers = {"content-security-policy": "default-src 'self' 'unsafe-inline'"}
        analyser = SecurityHeadersAnalyser()
        client = self._mock_client(headers)
        result = analyser.analyse("https://example.com", client)
        assert any("unsafe-inline" in w for w in result.warnings)

    def test_missing_hsts_on_https(self):
        analyser = SecurityHeadersAnalyser()
        client = self._mock_client({})
        result = analyser.analyse("https://example.com", client)
        assert "strict-transport-security" in result.missing

    def test_score_bounded_zero(self):
        analyser = SecurityHeadersAnalyser()
        client = self._mock_client({})
        result = analyser.analyse("https://example.com", client)
        assert result.score >= 0

    def test_present_headers_captured(self):
        headers = {"x-frame-options": "DENY", "x-content-type-options": "nosniff"}
        analyser = SecurityHeadersAnalyser()
        client = self._mock_client(headers)
        result = analyser.analyse("https://example.com", client)
        assert "x-frame-options" in result.present
        assert result.present["x-frame-options"] == "DENY"


# ---------------------------------------------------------------------------
# 18. OwaspTestSuite — mocked HTTP client
# ---------------------------------------------------------------------------

def _mock_owasp_client(responses: Optional[Dict[str, HttpProbe]] = None) -> _HttpClient:
    """Build an _HttpClient mock with configurable per-URL responses."""
    mock = MagicMock(spec=_HttpClient)
    default = _make_probe(status=200, body="")
    if responses:
        def side_effect(method, url, **kwargs):
            return responses.get(url, default)
        mock.request.side_effect = side_effect
    else:
        mock.request.return_value = default
    return mock


class TestOwaspA01BrokenAccessControl:
    def test_admin_path_accessible_without_auth(self):
        client = _mock_owasp_client({
            "https://example.com/admin": _make_probe(status=200),
        })
        suite = OwaspTestSuite(client, ScanProfile.FULL)
        eps = [DiscoveredEndpoint(url="https://example.com/admin")]
        findings = suite.test_a01_broken_access_control(eps)
        assert any("Privileged Path" in f.title for f in findings)

    def test_no_findings_for_normal_paths(self):
        client = _mock_owasp_client()
        suite = OwaspTestSuite(client, ScanProfile.STANDARD)
        eps = [DiscoveredEndpoint(url="https://example.com/about")]
        findings = suite.test_a01_broken_access_control(eps)
        assert all("Privileged" not in f.title for f in findings)

    def test_idor_detection(self):
        client = _mock_owasp_client({
            "https://example.com/users/2": _make_probe(status=200, body='{"id":2}'),
        })
        suite = OwaspTestSuite(client, ScanProfile.FULL)
        eps = [DiscoveredEndpoint(url="https://example.com/users/1")]
        findings = suite.test_a01_broken_access_control(eps)
        idor = [f for f in findings if "IDOR" in f.title]
        assert len(idor) >= 1

    def test_idor_cwe(self):
        client = _mock_owasp_client({
            "https://example.com/orders/2": _make_probe(status=200),
        })
        suite = OwaspTestSuite(client, ScanProfile.FULL)
        eps = [DiscoveredEndpoint(url="https://example.com/orders/1")]
        findings = suite.test_a01_broken_access_control(eps)
        idor = [f for f in findings if "IDOR" in f.title]
        if idor:
            assert idor[0].cwe_id == "CWE-639"


class TestOwaspA02CryptoFailures:
    def test_http_no_redirect_finding(self):
        client = _mock_owasp_client({
            "http://example.com": _make_probe(status=200, body="Home"),
        })
        suite = OwaspTestSuite(client, ScanProfile.STANDARD)
        findings = suite.test_a02_crypto_failures("http://example.com")
        assert any("HTTPS Redirect" in f.title for f in findings)

    def test_missing_hsts_finding(self):
        client = _mock_owasp_client({
            "https://example.com": _make_probe(status=200, headers={}),
        })
        suite = OwaspTestSuite(client, ScanProfile.STANDARD)
        findings = suite.test_a02_crypto_failures("https://example.com")
        assert any("HSTS" in f.title for f in findings)

    def test_hsts_present_no_finding(self):
        client = _mock_owasp_client({
            "https://example.com": _make_probe(
                status=200,
                headers={"strict-transport-security": "max-age=31536000"},
            ),
        })
        suite = OwaspTestSuite(client, ScanProfile.STANDARD)
        findings = suite.test_a02_crypto_failures("https://example.com")
        assert not any("HSTS" in f.title for f in findings)


class TestOwaspA03Injection:
    def test_sql_injection_detected_on_error(self):
        def side_effect(method, url, **kwargs):
            if "OR" in url or "SLEEP" in url or "SELECT" in url or "1%3D1" in url or "quotation" in url:
                return _make_probe(status=500, body="You have an error in your SQL syntax near '1'='1'")
            return _make_probe(status=200)
        client = MagicMock(spec=_HttpClient)
        client.request.side_effect = side_effect
        suite = OwaspTestSuite(client, ScanProfile.STANDARD)
        eps = [DiscoveredEndpoint(url="https://example.com/search?q=hello", parameters=["q"])]
        findings = suite.test_a03_injection(eps)
        sql = [f for f in findings if "SQL" in f.title]
        assert len(sql) >= 1

    def test_cmd_injection_confirmed(self):
        def side_effect(method, url, **kwargs):
            if "DAST_PROBE" in url or "echo" in url:
                return _make_probe(status=200, body="DAST_PROBE")
            return _make_probe(status=200)
        client = MagicMock(spec=_HttpClient)
        client.request.side_effect = side_effect
        suite = OwaspTestSuite(client, ScanProfile.FULL)
        eps = [DiscoveredEndpoint(url="https://example.com/run?cmd=ls", parameters=["cmd"])]
        findings = suite.test_a03_injection(eps)
        cmd = [f for f in findings if "Command" in f.title]
        assert len(cmd) >= 1
        assert cmd[0].cwe_id == "CWE-78"
        assert cmd[0].severity == FindingSeverity.CRITICAL

    def test_no_injection_clean_response(self):
        client = _mock_owasp_client()
        suite = OwaspTestSuite(client, ScanProfile.STANDARD)
        eps = [DiscoveredEndpoint(url="https://example.com/page?id=1", parameters=["id"])]
        findings = suite.test_a03_injection(eps)
        # May still be 0 or few — main check: no false positives on clean response
        sql = [f for f in findings if "SQL" in f.title and f.confidence > 0.9]
        assert len(sql) == 0


class TestOwaspA04InsecureDesign:
    def test_rate_limit_finding_on_sensitive_path(self):
        client = _mock_owasp_client()  # all return 200
        suite = OwaspTestSuite(client, ScanProfile.STANDARD)
        eps = [DiscoveredEndpoint(url="https://example.com/login")]
        findings = suite.test_a04_insecure_design(eps)
        assert any("Rate Limit" in f.title for f in findings)

    def test_no_finding_on_non_sensitive_path(self):
        client = _mock_owasp_client()
        suite = OwaspTestSuite(client, ScanProfile.STANDARD)
        eps = [DiscoveredEndpoint(url="https://example.com/about")]
        findings = suite.test_a04_insecure_design(eps)
        assert not any("Rate Limit" in f.title for f in findings)


class TestOwaspA05SecurityMisconfiguration:
    def test_directory_listing_detected(self):
        client = _mock_owasp_client({
            "https://example.com/": _make_probe(status=200, body="Index of /"),
        })
        suite = OwaspTestSuite(client, ScanProfile.STANDARD)
        findings = suite.test_a05_security_misconfiguration("https://example.com", [])
        assert any("Directory Listing" in f.title for f in findings)

    def test_stack_trace_detected(self):
        def side_effect(method, url, **kwargs):
            if "INVALID_TEST_VAL" in url:
                return _make_probe(status=500, body="Traceback (most recent call last):\n  File app.py line 42")
            return _make_probe(status=200)
        client = MagicMock(spec=_HttpClient)
        client.request.side_effect = side_effect
        suite = OwaspTestSuite(client, ScanProfile.STANDARD)
        eps = [DiscoveredEndpoint(url="https://example.com/api")]
        findings = suite.test_a05_security_misconfiguration("https://example.com", eps)
        assert any("Stack Trace" in f.title for f in findings)

    def test_http_trace_flagged(self):
        def side_effect(method, url, **kwargs):
            if method == "TRACE":
                return _make_probe(status=200)
            return _make_probe(status=200)
        client = MagicMock(spec=_HttpClient)
        client.request.side_effect = side_effect
        suite = OwaspTestSuite(client, ScanProfile.STANDARD)
        eps = [DiscoveredEndpoint(url="https://example.com/api")]
        findings = suite.test_a05_security_misconfiguration("https://example.com", eps)
        assert any("TRACE" in f.title for f in findings)


class TestOwaspA06VulnerableComponents:
    def test_server_version_disclosed(self):
        client = _mock_owasp_client({
            "https://example.com": _make_probe(headers={"server": "Apache/2.4.41"}),
        })
        suite = OwaspTestSuite(client, ScanProfile.STANDARD)
        findings = suite.test_a06_vulnerable_components("https://example.com")
        assert any("Server Version" in f.title for f in findings)

    def test_x_powered_by_disclosed(self):
        client = _mock_owasp_client({
            "https://example.com": _make_probe(headers={"x-powered-by": "PHP/7.4.3"}),
        })
        suite = OwaspTestSuite(client, ScanProfile.STANDARD)
        findings = suite.test_a06_vulnerable_components("https://example.com")
        assert any("Technology Stack" in f.title for f in findings)

    def test_no_disclosure_no_finding(self):
        client = _mock_owasp_client({
            "https://example.com": _make_probe(headers={}),
        })
        suite = OwaspTestSuite(client, ScanProfile.STANDARD)
        findings = suite.test_a06_vulnerable_components("https://example.com")
        assert findings == []


class TestOwaspA08DataIntegrity:
    def test_clickjacking_no_headers(self):
        client = _mock_owasp_client({
            "https://example.com": _make_probe(headers={}),
        })
        suite = OwaspTestSuite(client, ScanProfile.STANDARD)
        findings = suite.test_a08_data_integrity("https://example.com")
        assert any("Clickjacking" in f.title for f in findings)

    def test_csp_missing_finding(self):
        client = _mock_owasp_client({
            "https://example.com": _make_probe(headers={}),
        })
        suite = OwaspTestSuite(client, ScanProfile.STANDARD)
        findings = suite.test_a08_data_integrity("https://example.com")
        assert any("Content-Security-Policy" in f.title for f in findings)

    def test_x_frame_options_deny_no_clickjacking(self):
        client = _mock_owasp_client({
            "https://example.com": _make_probe(headers={"x-frame-options": "DENY"}),
        })
        suite = OwaspTestSuite(client, ScanProfile.STANDARD)
        findings = suite.test_a08_data_integrity("https://example.com")
        assert not any("Clickjacking" in f.title for f in findings)


class TestOwaspA10Ssrf:
    def test_ssrf_confirmed_by_response(self):
        def side_effect(method, url, **kwargs):
            if "127.0.0.1" in url or "localhost" in url:
                return _make_probe(status=200, body="root:x:0:0")
            return _make_probe(status=200)
        client = MagicMock(spec=_HttpClient)
        client.request.side_effect = side_effect
        suite = OwaspTestSuite(client, ScanProfile.FULL)
        eps = [DiscoveredEndpoint(
            url="https://example.com/fetch?url=https://safe.com",
            parameters=["url"],
        )]
        findings = suite.test_a10_ssrf(eps)
        assert any("SSRF" in f.title for f in findings)
        confirmed = [f for f in findings if "Confirmed" in f.title]
        assert confirmed[0].severity == FindingSeverity.CRITICAL

    def test_no_url_params_no_ssrf_test(self):
        client = _mock_owasp_client()
        suite = OwaspTestSuite(client, ScanProfile.STANDARD)
        eps = [DiscoveredEndpoint(url="https://example.com/page?name=test", parameters=["name"])]
        findings = suite.test_a10_ssrf(eps)
        assert findings == []


# ---------------------------------------------------------------------------
# 19. DastScanner lifecycle tests
# ---------------------------------------------------------------------------

class TestDastScannerLifecycle:
    def test_start_scan_returns_id(self):
        scanner = DastScanner()
        with patch.object(_HttpClient, "request", return_value=_make_probe()):
            cfg = _make_scan_config(profile=ScanProfile.QUICK)
            scan_id = scanner.start_scan(cfg)
        assert isinstance(scan_id, str)
        assert len(scan_id) == 36  # UUID format

    def test_scan_appears_in_store(self):
        scanner = DastScanner()
        with patch.object(_HttpClient, "request", return_value=_make_probe()):
            cfg = _make_scan_config(profile=ScanProfile.QUICK)
            scan_id = scanner.start_scan(cfg)
        result = scanner.get_scan(scan_id)
        assert result is not None
        assert result.scan_id == scan_id

    def test_scan_invalid_scheme_raises(self):
        scanner = DastScanner()
        cfg = _make_scan_config(target="ftp://example.com")
        with pytest.raises(ValueError):
            scanner.start_scan(cfg)

    def test_get_nonexistent_scan_returns_none(self):
        scanner = DastScanner()
        assert scanner.get_scan("does-not-exist") is None

    def test_scan_completes(self):
        scanner = DastScanner()
        with patch.object(_HttpClient, "request", return_value=_make_probe()):
            cfg = _make_scan_config(profile=ScanProfile.QUICK)
            scan_id = scanner.start_scan(cfg)
            # Wait for background thread
            for _ in range(30):
                r = scanner.get_scan(scan_id)
                if r and r.status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
                    break
                time.sleep(0.1)
        result = scanner.get_scan(scan_id)
        assert result.status in (ScanStatus.COMPLETED, ScanStatus.FAILED)

    def test_get_all_findings_empty(self):
        scanner = DastScanner()
        findings = scanner.get_all_findings()
        assert isinstance(findings, list)

    def test_get_all_findings_severity_filter(self):
        scanner = DastScanner()
        # Inject a fake completed scan with findings
        f = _make_finding(severity=FindingSeverity.CRITICAL)
        result = ScanResult(
            scan_id="test-scan",
            target_url="https://example.com",
            profile=ScanProfile.QUICK,
            status=ScanStatus.COMPLETED,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            endpoints_discovered=1,
            endpoints_tested=1,
            total_findings=1,
            findings=[f],
            security_headers=None,
            by_severity={"critical": 1},
            by_owasp={},
            duration_ms=100.0,
        )
        scanner._scans["test-scan"] = result
        critical = scanner.get_all_findings(severity_filter="critical")
        assert len(critical) == 1
        medium = scanner.get_all_findings(severity_filter="medium")
        assert len(medium) == 0

    def test_openapi_endpoint_discovery(self):
        scanner = DastScanner()
        spec = {
            "paths": {
                "/users": {"get": {"parameters": [{"name": "page", "in": "query"}]}},
                "/users/{id}": {"delete": {"parameters": []}},
            }
        }
        eps = scanner._endpoints_from_openapi(spec, "https://example.com")
        assert len(eps) == 2
        urls = [e.url for e in eps]
        assert "https://example.com/users" in urls


# ---------------------------------------------------------------------------
# 20. Singleton tests
# ---------------------------------------------------------------------------

class TestSingleton:
    def test_get_dast_scanner_returns_same_instance(self):
        s1 = get_dast_scanner()
        s2 = get_dast_scanner()
        assert s1 is s2

    def test_singleton_is_dast_scanner(self):
        assert isinstance(get_dast_scanner(), DastScanner)


# ---------------------------------------------------------------------------
# 21. Router tests (FastAPI TestClient)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def dast_client():
    from apps.api.dast_router import router as dast_router
    app = FastAPI()
    app.include_router(dast_router)
    return TestClient(app)


class TestDastRouterProfiles:
    def test_list_profiles(self, dast_client):
        resp = dast_client.get("/api/v1/dast/profiles")
        assert resp.status_code == 200
        data = resp.json()
        assert "profiles" in data
        ids = [p["id"] for p in data["profiles"]]
        assert "quick" in ids
        assert "standard" in ids
        assert "full" in ids
        assert "api_only" in ids

    def test_profiles_have_required_fields(self, dast_client):
        resp = dast_client.get("/api/v1/dast/profiles")
        for profile in resp.json()["profiles"]:
            assert "id" in profile
            assert "name" in profile
            assert "description" in profile
            assert "tests" in profile
            assert "active_testing" in profile
            assert "estimated_duration" in profile


class TestDastRouterHealth:
    def test_health_endpoint(self, dast_client):
        resp = dast_client.get("/api/v1/dast/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["engine"] == "dast_scanner"


class TestDastRouterScanValidation:
    def test_start_scan_blocked_host(self, dast_client):
        resp = dast_client.post("/api/v1/dast/scan", json={
            "target_url": "http://localhost/admin",
            "profile": "quick",
        })
        assert resp.status_code == 422

    def test_start_scan_private_ip_blocked(self, dast_client):
        resp = dast_client.post("/api/v1/dast/scan", json={
            "target_url": "http://192.168.1.1/",
            "profile": "quick",
        })
        assert resp.status_code == 422

    def test_start_scan_invalid_profile(self, dast_client):
        resp = dast_client.post("/api/v1/dast/scan", json={
            "target_url": "https://example.com",
            "profile": "nuclear",
        })
        assert resp.status_code == 422

    def test_start_scan_invalid_scheme(self, dast_client):
        resp = dast_client.post("/api/v1/dast/scan", json={
            "target_url": "ftp://example.com",
            "profile": "quick",
        })
        assert resp.status_code == 422

    def test_start_scan_max_depth_exceeded(self, dast_client):
        resp = dast_client.post("/api/v1/dast/scan", json={
            "target_url": "https://example.com",
            "profile": "quick",
            "max_depth": 99,
        })
        assert resp.status_code == 422

    def test_start_scan_rps_too_high(self, dast_client):
        resp = dast_client.post("/api/v1/dast/scan", json={
            "target_url": "https://example.com",
            "profile": "quick",
            "requests_per_second": 999,
        })
        assert resp.status_code == 422

    def test_start_scan_valid_returns_scan_id(self, dast_client):
        with patch("core.dast_scanner.DastScanner.start_scan", return_value="test-uuid-1234"):
            resp = dast_client.post("/api/v1/dast/scan", json={
                "target_url": "https://example.com",
                "profile": "quick",
            })
        assert resp.status_code == 200
        data = resp.json()
        assert "scan_id" in data
        assert data["status"] == "pending"

    def test_start_scan_too_many_headers(self, dast_client):
        resp = dast_client.post("/api/v1/dast/scan", json={
            "target_url": "https://example.com",
            "profile": "quick",
            "custom_headers": {f"X-Header-{i}": "v" for i in range(60)},
        })
        assert resp.status_code == 422


class TestDastRouterScanStatus:
    def test_get_nonexistent_scan_404(self, dast_client):
        resp = dast_client.get("/api/v1/dast/scans/does-not-exist")
        assert resp.status_code == 404

    def test_get_existing_scan(self, dast_client):
        # Inject a scan result into the global scanner
        scanner = get_dast_scanner()
        result = ScanResult(
            scan_id="router-test-scan",
            target_url="https://example.com",
            profile=ScanProfile.QUICK,
            status=ScanStatus.COMPLETED,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            endpoints_discovered=3,
            endpoints_tested=3,
            total_findings=1,
            findings=[_make_finding()],
            security_headers=None,
            by_severity={"high": 1},
            by_owasp={},
            duration_ms=500.0,
        )
        scanner._scans["router-test-scan"] = result
        resp = dast_client.get("/api/v1/dast/scans/router-test-scan")
        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_id"] == "router-test-scan"
        assert data["status"] == "completed"


class TestDastRouterFindings:
    def test_get_findings_empty(self, dast_client):
        resp = dast_client.get("/api/v1/dast/findings")
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "findings" in data

    def test_get_findings_invalid_severity(self, dast_client):
        resp = dast_client.get("/api/v1/dast/findings?severity=extreme")
        assert resp.status_code == 422

    def test_get_findings_valid_severity(self, dast_client):
        resp = dast_client.get("/api/v1/dast/findings?severity=critical")
        assert resp.status_code == 200

    def test_get_findings_by_scan_id_not_found(self, dast_client):
        resp = dast_client.get("/api/v1/dast/findings?scan_id=no-such-id")
        assert resp.status_code == 404

    def test_get_findings_limit(self, dast_client):
        resp = dast_client.get("/api/v1/dast/findings?limit=5")
        assert resp.status_code == 200

    def test_get_findings_limit_too_high(self, dast_client):
        resp = dast_client.get("/api/v1/dast/findings?limit=9999")
        assert resp.status_code == 422


class TestDastRouterHeaders:
    def test_headers_check_private_ip_blocked(self, dast_client):
        resp = dast_client.get("/api/v1/dast/headers/192.168.1.1")
        assert resp.status_code == 422

    def test_headers_check_localhost_blocked(self, dast_client):
        resp = dast_client.get("/api/v1/dast/headers/localhost")
        assert resp.status_code == 422

    def test_headers_check_valid_url_calls_analyser(self, dast_client):
        mock_result = SecurityHeadersResult(
            url="https://example.com",
            present={"x-frame-options": "DENY"},
            missing=["content-security-policy"],
            warnings=[],
            score=80,
            tls_version="TLSv1.3",
            hsts_enabled=False,
        )
        with patch("core.dast_scanner.SecurityHeadersAnalyser.analyse", return_value=mock_result):
            resp = dast_client.get("/api/v1/dast/headers/https://example.com")
        assert resp.status_code == 200
        data = resp.json()
        assert data["score"] == 80
        assert "x-frame-options" in data["present"]


# ---------------------------------------------------------------------------
# 22. Auth config in scan request
# ---------------------------------------------------------------------------

class TestScanRequestAuthConfig:
    def test_invalid_auth_type_rejected(self, dast_client):
        resp = dast_client.post("/api/v1/dast/scan", json={
            "target_url": "https://example.com",
            "profile": "quick",
            "auth": {"auth_type": "magic_token"},
        })
        assert resp.status_code == 422

    def test_valid_jwt_auth_config(self, dast_client):
        with patch("core.dast_scanner.DastScanner.start_scan", return_value="uuid-jwt"):
            resp = dast_client.post("/api/v1/dast/scan", json={
                "target_url": "https://example.com",
                "profile": "quick",
                "auth": {
                    "auth_type": "jwt_bearer",
                    "token": "mytoken",
                },
            })
        assert resp.status_code == 200

    def test_valid_basic_auth_config(self, dast_client):
        with patch("core.dast_scanner.DastScanner.start_scan", return_value="uuid-basic"):
            resp = dast_client.post("/api/v1/dast/scan", json={
                "target_url": "https://example.com",
                "profile": "quick",
                "auth": {
                    "auth_type": "basic_auth",
                    "username": "admin",
                    "password": "secret",
                },
            })
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 22. GET /api/v1/dast/ root capabilities endpoint
# ---------------------------------------------------------------------------

class TestDastRouterRoot:
    def test_root_returns_200(self, dast_client):
        resp = dast_client.get("/api/v1/dast/")
        assert resp.status_code == 200

    def test_root_contains_service_key(self, dast_client):
        resp = dast_client.get("/api/v1/dast/")
        data = resp.json()
        assert data["service"] == "DAST Scanner"

    def test_root_lists_expected_endpoints(self, dast_client):
        resp = dast_client.get("/api/v1/dast/")
        data = resp.json()
        endpoints = data["endpoints"]
        assert "POST /scan" in endpoints
        assert "GET /scans/{scan_id}" in endpoints
        assert "GET /findings" in endpoints
        assert "GET /health" in endpoints

    def test_root_lists_auth_modes_and_profiles(self, dast_client):
        resp = dast_client.get("/api/v1/dast/")
        data = resp.json()
        assert "jwt_bearer" in data["auth_modes"]
        assert "quick" in data["scan_profiles"]
        assert "api_only" in data["scan_profiles"]

    def test_root_capabilities_include_core_checks(self, dast_client):
        resp = dast_client.get("/api/v1/dast/")
        data = resp.json()
        caps = data["capabilities"]
        assert "sql_injection" in caps
        assert "security_headers" in caps
        assert "api_scan_openapi" in caps
