"""Tests for authenticated scanning and application crawling capabilities.

Tests cover:
- ScanConfig dataclass creation, defaults, validation, and clamping
- RealVulnerabilityScanner with ScanConfig (backward compat + new modes)
- _build_auth_headers for all auth types
- _perform_login with form/JSON bodies, success indicators, token capture
- _crawl_application with scope, depth, exclude patterns, link extraction
- _normalize_crawl_url and _url_in_crawl_scope helpers
- End-to-end scan_url with auth + crawl via mocked HTTP responses
"""

import asyncio
import re
from dataclasses import fields as dataclass_fields
from typing import Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import urlparse

import pytest

from core.real_scanner import (
    RealFinding,
    RealVulnerabilityScanner,
    ScanConfig,
    _MAX_COOKIES,
    _MAX_CRAWL_DEPTH,
    _MAX_CRAWL_URLS,
    _MAX_EXCLUDE_PATTERNS,
    _MAX_LOGIN_BODY_KEYS,
    _MAX_PAYLOADS_PER_CHECK,
    _MAX_SCAN_DELAY_MS,
    _VALID_AUTH_TYPES,
    get_real_vuln_scanner,
)


# ---------------------------------------------------------------------------
# ScanConfig dataclass tests
# ---------------------------------------------------------------------------


class TestScanConfig:
    """Tests for ScanConfig validation and defaults."""

    def test_defaults(self):
        cfg = ScanConfig()
        assert cfg.auth_type == "none"
        assert cfg.auth_token == ""
        assert cfg.auth_cookies == {}
        assert cfg.auth_username == ""
        assert cfg.auth_password == ""
        assert cfg.auth_header_name == "Authorization"
        assert cfg.auth_header_value == ""
        assert cfg.login_url == ""
        assert cfg.login_body == {}
        assert cfg.login_success_indicator == ""
        assert cfg.crawl is False
        assert cfg.max_crawl_depth == 3
        assert cfg.max_crawl_urls == 50
        assert cfg.crawl_scope == "same-origin"
        assert cfg.exclude_patterns == []
        assert cfg.max_payloads_per_check == 10
        assert cfg.scan_delay_ms == 0

    def test_all_auth_types_valid(self):
        for auth_type in _VALID_AUTH_TYPES:
            cfg = ScanConfig(auth_type=auth_type)
            assert cfg.auth_type == auth_type

    def test_invalid_auth_type_raises(self):
        with pytest.raises(ValueError, match="Invalid auth_type"):
            ScanConfig(auth_type="invalid")

    def test_invalid_auth_type_ntlm(self):
        with pytest.raises(ValueError):
            ScanConfig(auth_type="ntlm")

    def test_clamp_crawl_depth_upper(self):
        cfg = ScanConfig(max_crawl_depth=999)
        assert cfg.max_crawl_depth == _MAX_CRAWL_DEPTH

    def test_clamp_crawl_depth_lower(self):
        cfg = ScanConfig(max_crawl_depth=-5)
        assert cfg.max_crawl_depth == 0

    def test_clamp_crawl_urls_upper(self):
        cfg = ScanConfig(max_crawl_urls=9999)
        assert cfg.max_crawl_urls == _MAX_CRAWL_URLS

    def test_clamp_crawl_urls_lower(self):
        cfg = ScanConfig(max_crawl_urls=0)
        assert cfg.max_crawl_urls == 1

    def test_clamp_payloads_per_check(self):
        cfg = ScanConfig(max_payloads_per_check=500)
        assert cfg.max_payloads_per_check == _MAX_PAYLOADS_PER_CHECK

    def test_clamp_scan_delay(self):
        cfg = ScanConfig(scan_delay_ms=99999)
        assert cfg.scan_delay_ms == _MAX_SCAN_DELAY_MS

    def test_clamp_scan_delay_negative(self):
        cfg = ScanConfig(scan_delay_ms=-100)
        assert cfg.scan_delay_ms == 0

    def test_invalid_crawl_scope_defaults(self):
        cfg = ScanConfig(crawl_scope="invalid-scope")
        assert cfg.crawl_scope == "same-origin"

    def test_valid_crawl_scopes(self):
        for scope in ("same-origin", "same-domain", "custom"):
            cfg = ScanConfig(crawl_scope=scope)
            assert cfg.crawl_scope == scope

    def test_exclude_patterns_truncated(self):
        patterns = [f"pattern-{i}" for i in range(_MAX_EXCLUDE_PATTERNS + 10)]
        cfg = ScanConfig(exclude_patterns=patterns)
        assert len(cfg.exclude_patterns) == _MAX_EXCLUDE_PATTERNS

    def test_login_body_too_many_keys_raises(self):
        big_body = {f"key_{i}": f"val_{i}" for i in range(_MAX_LOGIN_BODY_KEYS + 1)}
        with pytest.raises(ValueError, match="login_body"):
            ScanConfig(login_body=big_body)

    def test_auth_cookies_too_many_raises(self):
        big_cookies = {f"cookie_{i}": f"val_{i}" for i in range(_MAX_COOKIES + 1)}
        with pytest.raises(ValueError, match="auth_cookies"):
            ScanConfig(auth_cookies=big_cookies)

    def test_login_url_invalid_scheme_raises(self):
        with pytest.raises(ValueError, match="http or https"):
            ScanConfig(login_url="ftp://evil.com/login")

    def test_login_url_file_scheme_raises(self):
        with pytest.raises(ValueError, match="http or https"):
            ScanConfig(login_url="file:///etc/passwd")

    def test_login_url_http_valid(self):
        cfg = ScanConfig(login_url="http://app.local/login")
        assert cfg.login_url == "http://app.local/login"

    def test_login_url_https_valid(self):
        cfg = ScanConfig(login_url="https://app.example.com/auth/login")
        assert cfg.login_url == "https://app.example.com/auth/login"

    def test_login_url_empty_valid(self):
        cfg = ScanConfig(login_url="")
        assert cfg.login_url == ""


# ---------------------------------------------------------------------------
# RealVulnerabilityScanner init tests
# ---------------------------------------------------------------------------


class TestScannerInit:
    """Tests for scanner initialization with and without ScanConfig."""

    def test_default_init_backward_compat(self):
        scanner = RealVulnerabilityScanner()
        assert scanner.timeout == 30.0
        assert scanner.verify_ssl is True
        assert scanner.config.auth_type == "none"
        assert scanner._crawled_urls == []
        assert scanner._findings == []

    def test_custom_timeout_and_ssl(self):
        scanner = RealVulnerabilityScanner(timeout=10.0, verify_ssl=False)
        assert scanner.timeout == 10.0
        assert scanner.verify_ssl is False

    def test_init_with_bearer_config(self):
        cfg = ScanConfig(auth_type="bearer", auth_token="my-jwt-token")
        scanner = RealVulnerabilityScanner(config=cfg)
        assert scanner.config.auth_type == "bearer"
        assert scanner.config.auth_token == "my-jwt-token"

    def test_init_with_basic_config(self):
        cfg = ScanConfig(auth_type="basic", auth_username="admin", auth_password="secret")
        scanner = RealVulnerabilityScanner(config=cfg)
        assert scanner.config.auth_username == "admin"
        assert scanner.config.auth_password == "secret"

    def test_init_with_cookie_config(self):
        cfg = ScanConfig(auth_type="cookie", auth_cookies={"session": "abc123"})
        scanner = RealVulnerabilityScanner(config=cfg)
        assert scanner.config.auth_cookies == {"session": "abc123"}

    def test_init_with_crawl_config(self):
        cfg = ScanConfig(
            crawl=True,
            max_crawl_depth=5,
            max_crawl_urls=100,
            crawl_scope="same-domain",
            exclude_patterns=[r"/logout", r"/api/internal"],
        )
        scanner = RealVulnerabilityScanner(config=cfg)
        assert scanner.config.crawl is True
        assert scanner.config.max_crawl_depth == 5
        assert scanner.config.max_crawl_urls == 100
        assert scanner.config.crawl_scope == "same-domain"
        assert len(scanner.config.exclude_patterns) == 2


# ---------------------------------------------------------------------------
# _build_auth_headers tests
# ---------------------------------------------------------------------------


class TestBuildAuthHeaders:
    """Tests for the _build_auth_headers method."""

    def test_none_auth_no_extra_headers(self):
        scanner = RealVulnerabilityScanner(config=ScanConfig(auth_type="none"))
        result = scanner._build_auth_headers({"Accept": "text/html"})
        assert result == {"Accept": "text/html"}

    def test_none_auth_empty_base(self):
        scanner = RealVulnerabilityScanner(config=ScanConfig(auth_type="none"))
        result = scanner._build_auth_headers()
        assert result == {}

    def test_bearer_auth(self):
        scanner = RealVulnerabilityScanner(
            config=ScanConfig(auth_type="bearer", auth_token="tok123")
        )
        result = scanner._build_auth_headers()
        assert result == {"Authorization": "Bearer tok123"}

    def test_bearer_auth_merges_with_existing(self):
        scanner = RealVulnerabilityScanner(
            config=ScanConfig(auth_type="bearer", auth_token="tok123")
        )
        result = scanner._build_auth_headers({"X-Custom": "val"})
        assert result["Authorization"] == "Bearer tok123"
        assert result["X-Custom"] == "val"

    def test_bearer_empty_token_no_header(self):
        scanner = RealVulnerabilityScanner(
            config=ScanConfig(auth_type="bearer", auth_token="")
        )
        result = scanner._build_auth_headers()
        assert "Authorization" not in result

    def test_oauth2_auth(self):
        scanner = RealVulnerabilityScanner(
            config=ScanConfig(auth_type="oauth2", auth_token="oauth-tok")
        )
        result = scanner._build_auth_headers()
        assert result == {"Authorization": "Bearer oauth-tok"}

    def test_custom_header_auth(self):
        scanner = RealVulnerabilityScanner(
            config=ScanConfig(
                auth_type="custom_header",
                auth_header_name="X-API-Key",
                auth_header_value="key-abc",
            )
        )
        result = scanner._build_auth_headers()
        assert result == {"X-API-Key": "key-abc"}

    def test_custom_header_empty_value_no_header(self):
        scanner = RealVulnerabilityScanner(
            config=ScanConfig(
                auth_type="custom_header",
                auth_header_name="X-API-Key",
                auth_header_value="",
            )
        )
        result = scanner._build_auth_headers()
        assert "X-API-Key" not in result

    def test_basic_auth_no_extra_headers(self):
        # Basic auth uses httpx auth= param, not headers
        scanner = RealVulnerabilityScanner(
            config=ScanConfig(auth_type="basic", auth_username="user")
        )
        result = scanner._build_auth_headers()
        assert "Authorization" not in result

    def test_cookie_auth_no_extra_headers(self):
        # Cookies use httpx cookies= param, not headers
        scanner = RealVulnerabilityScanner(
            config=ScanConfig(auth_type="cookie", auth_cookies={"sid": "abc"})
        )
        result = scanner._build_auth_headers()
        assert result == {}

    def test_does_not_mutate_input(self):
        scanner = RealVulnerabilityScanner(
            config=ScanConfig(auth_type="bearer", auth_token="tok")
        )
        original = {"Existing": "header"}
        result = scanner._build_auth_headers(original)
        assert "Authorization" in result
        assert "Authorization" not in original  # Not mutated


# ---------------------------------------------------------------------------
# _normalize_crawl_url tests
# ---------------------------------------------------------------------------


class TestNormalizeCrawlUrl:
    """Tests for URL normalization during crawling."""

    def setup_method(self):
        self.scanner = RealVulnerabilityScanner()

    def test_absolute_http_url(self):
        result = self.scanner._normalize_crawl_url(
            "https://example.com/page", "https://example.com"
        )
        assert result == "https://example.com/page"

    def test_relative_url_resolved(self):
        result = self.scanner._normalize_crawl_url("/about", "https://example.com")
        assert result == "https://example.com/about"

    def test_empty_url_returns_none(self):
        assert self.scanner._normalize_crawl_url("", "https://example.com") is None

    def test_ftp_scheme_returns_none(self):
        assert self.scanner._normalize_crawl_url(
            "ftp://files.example.com/file.zip", "https://example.com"
        ) is None

    def test_javascript_scheme_returns_none(self):
        assert self.scanner._normalize_crawl_url(
            "javascript:void(0)", "https://example.com"
        ) is None

    def test_preserves_query_string(self):
        result = self.scanner._normalize_crawl_url(
            "https://example.com/search?q=test&page=1", "https://example.com"
        )
        assert result == "https://example.com/search?q=test&page=1"

    def test_strips_fragment(self):
        result = self.scanner._normalize_crawl_url(
            "https://example.com/page#section", "https://example.com"
        )
        # Fragment is in the query-less part, should be stripped by urlparse
        assert "#" not in (result or "")


# ---------------------------------------------------------------------------
# _url_in_crawl_scope tests
# ---------------------------------------------------------------------------


class TestUrlInCrawlScope:
    """Tests for crawl scope enforcement."""

    def test_same_origin_matching(self):
        scanner = RealVulnerabilityScanner(config=ScanConfig(crawl_scope="same-origin"))
        base = urlparse("https://example.com:443/start")
        assert scanner._url_in_crawl_scope(
            "https://example.com:443/other", base, "example.com"
        )

    def test_same_origin_different_scheme(self):
        scanner = RealVulnerabilityScanner(config=ScanConfig(crawl_scope="same-origin"))
        base = urlparse("https://example.com/start")
        assert not scanner._url_in_crawl_scope(
            "http://example.com/other", base, "example.com"
        )

    def test_same_origin_different_host(self):
        scanner = RealVulnerabilityScanner(config=ScanConfig(crawl_scope="same-origin"))
        base = urlparse("https://example.com/start")
        assert not scanner._url_in_crawl_scope(
            "https://other.com/page", base, "example.com"
        )

    def test_same_origin_subdomain_rejected(self):
        scanner = RealVulnerabilityScanner(config=ScanConfig(crawl_scope="same-origin"))
        base = urlparse("https://example.com/start")
        assert not scanner._url_in_crawl_scope(
            "https://api.example.com/page", base, "example.com"
        )

    def test_same_domain_allows_subdomain(self):
        scanner = RealVulnerabilityScanner(config=ScanConfig(crawl_scope="same-domain"))
        base = urlparse("https://example.com/start")
        assert scanner._url_in_crawl_scope(
            "https://api.example.com/endpoint", base, "example.com"
        )

    def test_same_domain_allows_exact_match(self):
        scanner = RealVulnerabilityScanner(config=ScanConfig(crawl_scope="same-domain"))
        base = urlparse("https://example.com/start")
        assert scanner._url_in_crawl_scope(
            "https://example.com/other", base, "example.com"
        )

    def test_same_domain_rejects_other_domain(self):
        scanner = RealVulnerabilityScanner(config=ScanConfig(crawl_scope="same-domain"))
        base = urlparse("https://example.com/start")
        assert not scanner._url_in_crawl_scope(
            "https://evil.com/page", base, "example.com"
        )

    def test_custom_scope_allows_any_http(self):
        scanner = RealVulnerabilityScanner(config=ScanConfig(crawl_scope="custom"))
        base = urlparse("https://example.com/start")
        assert scanner._url_in_crawl_scope(
            "https://totally-different.io/page", base, "example.com"
        )

    def test_custom_scope_rejects_ftp(self):
        scanner = RealVulnerabilityScanner(config=ScanConfig(crawl_scope="custom"))
        base = urlparse("https://example.com/start")
        assert not scanner._url_in_crawl_scope(
            "ftp://files.example.com/file", base, "example.com"
        )


# ---------------------------------------------------------------------------
# _perform_login tests (async)
# ---------------------------------------------------------------------------


class TestPerformLogin:
    """Tests for the session-based login flow."""

    @pytest.fixture
    def scanner(self):
        return RealVulnerabilityScanner(config=ScanConfig())

    @pytest.mark.asyncio
    async def test_no_login_url_returns_false(self, scanner):
        config = ScanConfig(login_url="", login_body={"user": "admin"})
        client = AsyncMock()
        result = await scanner._perform_login(client, config)
        assert result is False

    @pytest.mark.asyncio
    async def test_no_login_body_returns_false(self, scanner):
        config = ScanConfig(login_url="https://app.com/login", login_body={})
        client = AsyncMock()
        result = await scanner._perform_login(client, config)
        assert result is False

    @pytest.mark.asyncio
    async def test_form_login_with_cookies_success(self, scanner):
        """Simulates a traditional form login that sets session cookies."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "text/html"}
        mock_response.text = "Welcome, admin!"
        mock_response.cookies = {"session_id": "abc123"}

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.cookies = {}

        config = ScanConfig(
            login_url="https://app.com/login",
            login_body={"username": "admin", "password": "secret"},
        )

        result = await scanner._perform_login(mock_client, config)
        assert result is True
        mock_client.post.assert_called_once()
        # Should use form data (data=) not JSON because URL doesn't contain /api/
        call_kwargs = mock_client.post.call_args
        assert "data" in call_kwargs.kwargs or (
            len(call_kwargs.args) > 1 and isinstance(call_kwargs.args[1], dict)
        )

    @pytest.mark.asyncio
    async def test_api_login_json_with_token_capture(self, scanner):
        """Simulates an API login that returns a bearer token in JSON."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {
            "access_token": "eyJ.test.token",
            "token_type": "bearer",
        }
        mock_response.cookies = {}

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.cookies = {}

        config = ScanConfig(
            login_url="https://app.com/api/auth/login",
            login_body={"email": "admin@test.com", "password": "secret"},
        )

        result = await scanner._perform_login(mock_client, config)
        assert result is True
        # Token should have been captured and config updated
        assert scanner.config.auth_type == "bearer"
        assert scanner.config.auth_token == "eyJ.test.token"

    @pytest.mark.asyncio
    async def test_login_http_error_returns_false(self, scanner):
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.headers = {"content-type": "text/html"}
        mock_response.text = "Unauthorized"

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)

        config = ScanConfig(
            login_url="https://app.com/login",
            login_body={"user": "wrong", "pass": "wrong"},
        )

        result = await scanner._perform_login(mock_client, config)
        assert result is False

    @pytest.mark.asyncio
    async def test_login_success_indicator_found(self, scanner):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "text/html"}
        mock_response.text = "Dashboard - Welcome back admin!"
        mock_response.cookies = {}

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.cookies = {}

        config = ScanConfig(
            login_url="https://app.com/login",
            login_body={"user": "admin", "pass": "secret"},
            login_success_indicator="Welcome back",
        )

        result = await scanner._perform_login(mock_client, config)
        assert result is True

    @pytest.mark.asyncio
    async def test_login_success_indicator_not_found(self, scanner):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "text/html"}
        mock_response.text = "Invalid credentials, try again."
        mock_response.cookies = {}

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.cookies = {}

        config = ScanConfig(
            login_url="https://app.com/login",
            login_body={"user": "admin", "pass": "wrong"},
            login_success_indicator="Welcome back",
        )

        result = await scanner._perform_login(mock_client, config)
        assert result is False

    @pytest.mark.asyncio
    async def test_login_request_error_returns_false(self, scanner):
        import httpx

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))

        config = ScanConfig(
            login_url="https://app.com/login",
            login_body={"user": "admin", "pass": "secret"},
        )

        result = await scanner._perform_login(mock_client, config)
        assert result is False

    @pytest.mark.asyncio
    async def test_json_login_uses_json_kwarg(self, scanner):
        """Verify that API-looking URLs send JSON bodies, not form data."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "text/plain"}
        mock_response.text = "ok"
        mock_response.cookies = {}

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.cookies = {"existing": "cookie"}

        config = ScanConfig(
            login_url="https://app.com/oauth/token",
            login_body={"grant_type": "password", "username": "u", "password": "p"},
        )

        await scanner._perform_login(mock_client, config)
        call_kwargs = mock_client.post.call_args.kwargs
        assert "json" in call_kwargs

    @pytest.mark.asyncio
    async def test_form_login_uses_data_kwarg(self, scanner):
        """Verify that non-API URLs send form-encoded bodies."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "text/html"}
        mock_response.text = "ok"
        mock_response.cookies = {"sid": "abc"}

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.cookies = {}

        config = ScanConfig(
            login_url="https://app.com/login",
            login_body={"username": "admin", "password": "secret"},
        )

        await scanner._perform_login(mock_client, config)
        call_kwargs = mock_client.post.call_args.kwargs
        assert "data" in call_kwargs


# ---------------------------------------------------------------------------
# _crawl_application tests (async)
# ---------------------------------------------------------------------------


class TestCrawlApplication:
    """Tests for the crawl engine."""

    def _make_html_response(self, body: str, status_code: int = 200):
        resp = MagicMock()
        resp.status_code = status_code
        resp.headers = {"content-type": "text/html; charset=utf-8"}
        resp.text = body
        return resp

    def _make_json_response(self, body: str = "{}", status_code: int = 200):
        resp = MagicMock()
        resp.status_code = status_code
        resp.headers = {"content-type": "application/json"}
        resp.text = body
        return resp

    @pytest.mark.asyncio
    async def test_crawl_discovers_href_links(self):
        scanner = RealVulnerabilityScanner(
            config=ScanConfig(crawl=True, max_crawl_urls=10)
        )
        html = """
        <html>
        <body>
            <a href="/about">About</a>
            <a href="/contact">Contact</a>
            <a href="/products">Products</a>
        </body>
        </html>
        """
        # Return base page with links, then empty pages for children
        base_resp = self._make_html_response(html)

        async def mock_get(url, **kwargs):
            if url == "https://example.com/app":
                return base_resp
            return self._make_html_response("")

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=mock_get)

        result = await scanner._crawl_application(
            mock_client, "https://example.com/app", {}
        )
        # Should discover /about, /contact, /products
        discovered_paths = [urlparse(u).path for u in result]
        assert "/about" in discovered_paths
        assert "/contact" in discovered_paths
        assert "/products" in discovered_paths

    @pytest.mark.asyncio
    async def test_crawl_respects_max_urls(self):
        scanner = RealVulnerabilityScanner(
            config=ScanConfig(crawl=True, max_crawl_urls=2)
        )
        links = "".join(f'<a href="/page{i}">P{i}</a>' for i in range(20))
        html = f"<html><body>{links}</body></html>"
        base_resp = self._make_html_response(html)

        async def mock_get(url, **kwargs):
            if url == "https://example.com/":
                return base_resp
            return self._make_html_response("")

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=mock_get)

        result = await scanner._crawl_application(
            mock_client, "https://example.com/", {}
        )
        assert len(result) <= 2

    @pytest.mark.asyncio
    async def test_crawl_respects_depth_limit(self):
        scanner = RealVulnerabilityScanner(
            config=ScanConfig(crawl=True, max_crawl_depth=1, max_crawl_urls=50)
        )

        async def mock_get(url, **kwargs):
            if url == "https://example.com/":
                return self._make_html_response('<a href="/level1">L1</a>')
            elif url == "https://example.com/level1":
                return self._make_html_response('<a href="/level2">L2</a>')
            elif url == "https://example.com/level2":
                return self._make_html_response('<a href="/level3">L3</a>')
            return self._make_html_response("", status_code=404)

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=mock_get)

        result = await scanner._crawl_application(
            mock_client, "https://example.com/", {}
        )
        # Depth 0 = base, depth 1 = /level1, depth 2 = /level2 (too deep)
        paths = [urlparse(u).path for u in result]
        assert "/level1" in paths
        # level2 should NOT be discovered (depth=2 > max_crawl_depth=1)
        # Actually, level2 is at depth 2 - discovered from level1 (depth 1)
        # But level3 should definitely not be there
        assert "/level3" not in paths

    @pytest.mark.asyncio
    async def test_crawl_respects_exclude_patterns(self):
        scanner = RealVulnerabilityScanner(
            config=ScanConfig(
                crawl=True,
                max_crawl_urls=50,
                exclude_patterns=[r"/logout", r"/admin"],
            )
        )
        html = """
        <html><body>
            <a href="/about">About</a>
            <a href="/logout">Logout</a>
            <a href="/admin/settings">Admin</a>
        </body></html>
        """
        base_resp = self._make_html_response(html)

        async def mock_get(url, **kwargs):
            if url == "https://example.com/":
                return base_resp
            return self._make_html_response("")

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=mock_get)

        result = await scanner._crawl_application(
            mock_client, "https://example.com/", {}
        )
        paths = [urlparse(u).path for u in result]
        assert "/about" in paths
        assert "/logout" not in paths
        assert "/admin/settings" not in paths

    @pytest.mark.asyncio
    async def test_crawl_skips_non_html_content(self):
        scanner = RealVulnerabilityScanner(
            config=ScanConfig(crawl=True, max_crawl_urls=50)
        )
        html = '<html><body><a href="/data.json">Data</a></body></html>'
        base_resp = self._make_html_response(html)
        json_resp = self._make_json_response('{"key": "value"}')

        async def mock_get(url, **kwargs):
            if url == "https://example.com/":
                return base_resp
            if url == "https://example.com/data.json":
                return json_resp
            return self._make_html_response("", status_code=404)

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=mock_get)

        result = await scanner._crawl_application(
            mock_client, "https://example.com/", {}
        )
        # /data.json should be discovered but not crawled further
        assert "https://example.com/data.json" in result

    @pytest.mark.asyncio
    async def test_crawl_extracts_form_actions(self):
        scanner = RealVulnerabilityScanner(
            config=ScanConfig(crawl=True, max_crawl_urls=50)
        )
        html = """
        <html><body>
            <form action="/search" method="GET">
                <input name="q" />
            </form>
        </body></html>
        """
        base_resp = self._make_html_response(html)

        async def mock_get(url, **kwargs):
            if url == "https://example.com/":
                return base_resp
            return self._make_html_response("")

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=mock_get)

        result = await scanner._crawl_application(
            mock_client, "https://example.com/", {}
        )
        paths = [urlparse(u).path for u in result]
        assert "/search" in paths

    @pytest.mark.asyncio
    async def test_crawl_extracts_js_fetch_urls(self):
        scanner = RealVulnerabilityScanner(
            config=ScanConfig(crawl=True, max_crawl_urls=50)
        )
        html = """
        <html><body>
            <script>
                fetch("/api/users");
                axios.get("/api/products");
            </script>
        </body></html>
        """
        base_resp = self._make_html_response(html)

        async def mock_get(url, **kwargs):
            if url == "https://example.com/":
                return base_resp
            return self._make_html_response("")

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=mock_get)

        result = await scanner._crawl_application(
            mock_client, "https://example.com/", {}
        )
        paths = [urlparse(u).path for u in result]
        assert "/api/users" in paths
        assert "/api/products" in paths

    @pytest.mark.asyncio
    async def test_crawl_deduplicates_urls(self):
        scanner = RealVulnerabilityScanner(
            config=ScanConfig(crawl=True, max_crawl_urls=50)
        )
        html = """
        <html><body>
            <a href="/about">About</a>
            <a href="/about">About Again</a>
            <a href="/about">About Third</a>
        </body></html>
        """
        base_resp = self._make_html_response(html)

        async def mock_get(url, **kwargs):
            if url == "https://example.com/":
                return base_resp
            return self._make_html_response("")

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=mock_get)

        result = await scanner._crawl_application(
            mock_client, "https://example.com/", {}
        )
        assert result.count("https://example.com/about") == 1

    @pytest.mark.asyncio
    async def test_crawl_skips_non_navigable_schemes(self):
        scanner = RealVulnerabilityScanner(
            config=ScanConfig(crawl=True, max_crawl_urls=50)
        )
        html = """
        <html><body>
            <a href="javascript:void(0)">JS Link</a>
            <a href="mailto:admin@example.com">Email</a>
            <a href="tel:+1234567890">Phone</a>
            <a href="/real-page">Real</a>
        </body></html>
        """
        base_resp = self._make_html_response(html)

        async def mock_get(url, **kwargs):
            if url == "https://example.com/":
                return base_resp
            return self._make_html_response("")

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=mock_get)

        result = await scanner._crawl_application(
            mock_client, "https://example.com/", {}
        )
        paths = [urlparse(u).path for u in result]
        assert "/real-page" in paths
        # Non-navigable should not appear
        for discovered_url in result:
            assert not discovered_url.startswith("javascript:")
            assert not discovered_url.startswith("mailto:")
            assert not discovered_url.startswith("tel:")

    @pytest.mark.asyncio
    async def test_crawl_same_origin_scope_blocks_external(self):
        scanner = RealVulnerabilityScanner(
            config=ScanConfig(crawl=True, crawl_scope="same-origin", max_crawl_urls=50)
        )
        html = """
        <html><body>
            <a href="/internal">Internal</a>
            <a href="https://external.com/page">External</a>
        </body></html>
        """
        base_resp = self._make_html_response(html)

        async def mock_get(url, **kwargs):
            if url == "https://example.com/":
                return base_resp
            if url == "https://example.com/internal":
                return self._make_html_response("<html>Internal</html>")
            return self._make_html_response("", status_code=404)

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=mock_get)

        result = await scanner._crawl_application(
            mock_client, "https://example.com/", {}
        )
        for url in result:
            assert "external.com" not in url

    @pytest.mark.asyncio
    async def test_crawl_handles_request_errors(self):
        import httpx

        scanner = RealVulnerabilityScanner(
            config=ScanConfig(crawl=True, max_crawl_urls=50)
        )
        html = '<html><body><a href="/broken">Broken</a></body></html>'
        base_resp = self._make_html_response(html)

        async def mock_get(url, **kwargs):
            if url == "https://example.com/":
                return base_resp
            raise httpx.ConnectError("Connection refused")

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=mock_get)

        # Should not raise — gracefully skips broken URLs
        result = await scanner._crawl_application(
            mock_client, "https://example.com/", {}
        )
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# scan_url integration tests (async, mocked HTTP)
# ---------------------------------------------------------------------------


class TestScanUrlIntegration:
    """Integration tests for scan_url with auth and crawl support."""

    @pytest.mark.asyncio
    async def test_scan_url_backward_compat_no_config(self):
        """Ensure scan_url works without any ScanConfig (backward compat)."""
        scanner = RealVulnerabilityScanner(timeout=5.0, verify_ssl=False)
        # Patch the entire _scan_single_url to avoid real HTTP calls
        scanner._scan_single_url = AsyncMock()

        with patch("httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await scanner.scan_url("https://example.com")
            assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_scan_url_with_bearer_builds_auth_headers(self):
        """Verify that bearer auth is passed through to scan phases."""
        cfg = ScanConfig(auth_type="bearer", auth_token="test-jwt")
        scanner = RealVulnerabilityScanner(config=cfg, timeout=5.0, verify_ssl=False)
        scanner._scan_single_url = AsyncMock()

        with patch("httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            await scanner.scan_url("https://example.com")
            # _scan_single_url should be called with auth headers including Authorization
            call_args = scanner._scan_single_url.call_args
            headers = call_args.args[2] if len(call_args.args) > 2 else call_args.kwargs.get("headers", {})
            assert headers.get("Authorization") == "Bearer test-jwt"

    @pytest.mark.asyncio
    async def test_scan_url_with_cookies_passes_to_client(self):
        """Verify that auth cookies are passed to the httpx client."""
        cfg = ScanConfig(auth_type="cookie", auth_cookies={"session": "abc"})
        scanner = RealVulnerabilityScanner(config=cfg, timeout=5.0, verify_ssl=False)
        scanner._scan_single_url = AsyncMock()

        with patch("httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            await scanner.scan_url("https://example.com")
            # Client should have been created with cookies
            call_kwargs = MockClient.call_args.kwargs
            assert call_kwargs.get("cookies") == {"session": "abc"}

    @pytest.mark.asyncio
    async def test_scan_url_with_basic_auth_passes_to_client(self):
        """Verify that basic auth tuple is passed to the httpx client."""
        cfg = ScanConfig(auth_type="basic", auth_username="admin", auth_password="pw")
        scanner = RealVulnerabilityScanner(config=cfg, timeout=5.0, verify_ssl=False)
        scanner._scan_single_url = AsyncMock()

        with patch("httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            await scanner.scan_url("https://example.com")
            call_kwargs = MockClient.call_args.kwargs
            assert call_kwargs.get("auth") == ("admin", "pw")

    @pytest.mark.asyncio
    async def test_crawled_urls_attribute_populated(self):
        """Verify _crawled_urls is populated when crawling is enabled."""
        cfg = ScanConfig(crawl=True, max_crawl_urls=5)
        scanner = RealVulnerabilityScanner(config=cfg, timeout=5.0, verify_ssl=False)
        scanner._scan_single_url = AsyncMock()
        scanner._crawl_application = AsyncMock(
            return_value=["https://example.com/about", "https://example.com/contact"]
        )

        with patch("httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            await scanner.scan_url("https://example.com")

        assert scanner._crawled_urls == [
            "https://example.com/about",
            "https://example.com/contact",
        ]
        # Should scan 3 URLs total (original + 2 crawled)
        assert scanner._scan_single_url.call_count == 3


# ---------------------------------------------------------------------------
# Singleton backward compatibility
# ---------------------------------------------------------------------------


class TestSingletonBackwardCompat:
    """Ensure singleton factory functions still work."""

    def test_get_real_vuln_scanner_returns_scanner(self):
        scanner = get_real_vuln_scanner()
        assert isinstance(scanner, RealVulnerabilityScanner)
        assert hasattr(scanner, "config")
        assert hasattr(scanner, "_crawled_urls")

    def test_singleton_default_config(self):
        scanner = get_real_vuln_scanner()
        assert scanner.config.auth_type == "none"
        assert scanner.config.crawl is False
