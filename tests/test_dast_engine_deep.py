"""Deep unit tests for DASTEngine — covering all async scan methods.

Supplementary test file targeting the uncovered lines:
  Line 270, 298, 318-353, 376-406, 411-448, 453-483, 486-515, 520-545,
  550-582, 587-623

Strategy:
  - Patch core.dast_engine.httpx.AsyncClient so the async context manager
    yields a mock client whose .get() returns pre-built httpx.Response objects.
  - Call engine methods (scan, _crawl, _check_headers, _test_sqli, etc.)
    directly via the mocked client to exercise every branch.
  - Never make real HTTP requests.
"""
from __future__ import annotations

import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch, call

import httpx
import pytest

# ── sys.path setup ──────────────────────────────────────────────────
sys.path.insert(0, "/Users/devops.ai/developement/fixops/Fixops/suite-core")

# ── env vars required before import ─────────────────────────────────
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-jwt-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from core.dast_engine import (  # noqa: E402
    DASTEngine,
    DastCategory,
    DastFinding,
    DastScanResult,
    DastSeverity,
    SQL_PAYLOADS,
    XSS_PAYLOADS,
    SSRF_PAYLOADS,
    PATH_TRAVERSAL_PAYLOADS,
    SQL_ERROR_PATTERNS,
    SECURITY_HEADERS,
    _LinkParser,
    get_dast_engine,
)


# ── Helpers ──────────────────────────────────────────────────────────

def _resp(
    status: int = 200,
    text: str = "",
    headers: dict | None = None,
) -> httpx.Response:
    """Build a real httpx.Response without a network call."""
    h = headers or {}
    return httpx.Response(status, text=text, headers=h)


def _html_resp(text: str = "<html></html>") -> httpx.Response:
    return _resp(200, text=text, headers={"content-type": "text/html; charset=utf-8"})


def _ctx_manager(mock_client: AsyncMock):
    """Return a class instance that acts as an async context manager yielding mock_client."""
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=mock_client)
    cm.__aexit__ = AsyncMock(return_value=None)
    return cm


@pytest.fixture
def engine():
    return DASTEngine(timeout=5.0, max_crawl=5)


@pytest.fixture
def mock_client():
    client = AsyncMock()
    client.get = AsyncMock(return_value=_resp())
    return client


# ════════════════════════════════════════════════════════════════════
# Section A: validate_target_url — URL length limit (line 270)
# ════════════════════════════════════════════════════════════════════

class TestURLLengthLimit:
    """Line 270: URL exceeds 2048 chars."""

    def test_url_exactly_2048_chars_accepted(self):
        # A 2048-char URL at the boundary should be accepted
        # (domain + path that totals exactly 2048)
        base = "https://example.com/"
        path = "a" * (2048 - len(base))
        url = base + path
        assert len(url) == 2048
        result = DASTEngine.validate_target_url(url)
        assert result == url

    def test_url_2049_chars_rejected(self):
        base = "https://example.com/"
        path = "a" * (2049 - len(base))
        url = base + path
        assert len(url) == 2049
        with pytest.raises(ValueError, match="exceeds maximum length"):
            DASTEngine.validate_target_url(url)

    def test_url_3000_chars_rejected(self):
        url = "https://example.com/" + "x" * 3000
        with pytest.raises(ValueError, match="exceeds maximum length"):
            DASTEngine.validate_target_url(url)

    def test_url_100_chars_accepted(self):
        url = "https://example.com/short"
        result = DASTEngine.validate_target_url(url)
        assert result == url


# ════════════════════════════════════════════════════════════════════
# Section B: validate_target_url — DNS resolution gaierror (line 298)
# ════════════════════════════════════════════════════════════════════

class TestURLValidationDNSFail:
    """Line 298: socket.gaierror — unresolvable host is allowed through."""

    def test_unknown_host_allowed_when_dns_fails(self):
        import socket
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("DNS fail")):
            # Should NOT raise; DNS failure means we allow the URL
            result = DASTEngine.validate_target_url("https://definitely-not-real-host-xyz.example")
            assert "definitely-not-real-host" in result

    def test_known_bad_ip_blocked_despite_mock(self):
        """When DNS resolves to private IP, still blocked (covers lines 288-296)."""
        import socket
        # Simulate DNS returning 192.168.1.1
        addr_info = [(socket.AF_INET, None, None, None, ("192.168.1.1", 0))]
        with patch("socket.getaddrinfo", return_value=addr_info):
            with pytest.raises(ValueError, match="private/reserved"):
                DASTEngine.validate_target_url("https://some-internal-host.example")

    def test_known_public_ip_allowed(self):
        """When DNS resolves to public IP, URL passes."""
        import socket
        addr_info = [(socket.AF_INET, None, None, None, ("8.8.8.8", 0))]
        with patch("socket.getaddrinfo", return_value=addr_info):
            result = DASTEngine.validate_target_url("https://dns-as-public.example")
            assert result is not None


# ════════════════════════════════════════════════════════════════════
# Section C: scan() — full orchestration (lines 318-353)
# ════════════════════════════════════════════════════════════════════

class TestScanOrchestration:
    """Lines 318-353: The main scan() method orchestration."""

    async def test_scan_no_crawl_returns_result(self, engine, mock_client):
        """scan() with crawl=False skips crawl, adds target URL, runs checks."""
        mock_client.get = AsyncMock(return_value=_resp(200, text="", headers={}))
        with patch("core.dast_engine.httpx.AsyncClient", return_value=_ctx_manager(mock_client)):
            result = await engine.scan("https://example.com", crawl=False)

        assert isinstance(result, DastScanResult)
        assert result.target == "https://example.com"
        assert result.urls_crawled == 1  # just the target
        assert result.scan_id.startswith("dast-")
        assert result.duration_ms >= 0

    async def test_scan_with_crawl_calls_crawl(self, engine, mock_client):
        """scan() with crawl=True calls _crawl."""
        # Return non-html so crawl stops immediately after visiting root
        mock_client.get = AsyncMock(
            return_value=_resp(200, text="", headers={"content-type": "application/json"})
        )
        with patch("core.dast_engine.httpx.AsyncClient", return_value=_ctx_manager(mock_client)):
            result = await engine.scan("https://example.com", crawl=True)

        assert result.urls_crawled >= 1

    async def test_scan_authenticated_with_cookies(self, engine, mock_client):
        """scan() sets authenticated=True when cookies are provided."""
        mock_client.get = AsyncMock(return_value=_resp(200, text=""))
        with patch("core.dast_engine.httpx.AsyncClient", return_value=_ctx_manager(mock_client)):
            result = await engine.scan(
                "https://example.com",
                crawl=False,
                cookies={"session": "abc123"},
            )
        assert result.authenticated is True

    async def test_scan_authenticated_with_auth_header(self, engine, mock_client):
        """scan() sets authenticated=True when Authorization header is provided."""
        mock_client.get = AsyncMock(return_value=_resp(200, text=""))
        with patch("core.dast_engine.httpx.AsyncClient", return_value=_ctx_manager(mock_client)):
            result = await engine.scan(
                "https://example.com",
                crawl=False,
                headers={"Authorization": "Bearer eyJtoken"},
            )
        assert result.authenticated is True

    async def test_scan_not_authenticated_no_creds(self, engine, mock_client):
        """scan() sets authenticated=False when no auth provided."""
        mock_client.get = AsyncMock(return_value=_resp(200, text=""))
        with patch("core.dast_engine.httpx.AsyncClient", return_value=_ctx_manager(mock_client)):
            result = await engine.scan("https://example.com", crawl=False)
        assert result.authenticated is False

    async def test_scan_by_severity_populated(self, engine, mock_client):
        """scan() aggregates findings by severity."""
        # Return a response with missing security headers + SQL error pattern
        # Use a URL with a query string so SQLi gets triggered
        target = "https://example.com/search?q=test"
        sql_response = _resp(200, text="SQL syntax error in query", headers={})
        mock_client.get = AsyncMock(return_value=sql_response)
        with patch("core.dast_engine.httpx.AsyncClient", return_value=_ctx_manager(mock_client)):
            result = await engine.scan(target, crawl=False)
        # Should have findings (security headers missing + possibly SQL injection)
        assert isinstance(result.by_severity, dict)
        assert isinstance(result.by_category, dict)

    async def test_scan_by_category_populated(self, engine, mock_client):
        """by_category dict is built from findings."""
        mock_client.get = AsyncMock(return_value=_resp(200, text=""))
        with patch("core.dast_engine.httpx.AsyncClient", return_value=_ctx_manager(mock_client)):
            result = await engine.scan("https://example.com", crawl=False)
        # security_header category should appear (7 headers missing)
        assert "security_header" in result.by_category

    async def test_scan_crawled_urls_in_result(self, engine, mock_client):
        """DastScanResult.crawled_urls contains visited URLs."""
        mock_client.get = AsyncMock(return_value=_resp(200, text=""))
        with patch("core.dast_engine.httpx.AsyncClient", return_value=_ctx_manager(mock_client)):
            result = await engine.scan("https://example.com", crawl=False)
        assert "https://example.com" in result.crawled_urls

    async def test_scan_blocks_too_long_url(self, engine):
        """scan() raises ValueError for URLs over 2048 chars before HTTP is attempted."""
        bad_url = "https://example.com/" + "a" * 3000
        with pytest.raises(ValueError, match="exceeds maximum length"):
            await engine.scan(bad_url)

    async def test_scan_custom_headers_forwarded(self, engine, mock_client):
        """Custom headers are forwarded to AsyncClient constructor."""
        mock_client.get = AsyncMock(return_value=_resp(200, text=""))
        custom_headers = {"X-Custom": "value"}
        with patch("core.dast_engine.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value = _ctx_manager(mock_client)
            await engine.scan("https://example.com", crawl=False, headers=custom_headers)
        # Verify AsyncClient was called with the headers kwarg
        _, kwargs = mock_cls.call_args
        assert kwargs.get("headers") == custom_headers

    async def test_scan_max_crawl_respected(self):
        """scan() limits crawled URLs to max_crawl."""
        engine = DASTEngine(timeout=5.0, max_crawl=2)
        mock_client = AsyncMock()
        # Build HTML with many links
        links = "".join(f'<a href="/page{i}">p{i}</a>' for i in range(20))
        html = f'<html>{links}</html>'
        mock_client.get = AsyncMock(
            return_value=_resp(200, text=html, headers={"content-type": "text/html"})
        )
        with patch("core.dast_engine.httpx.AsyncClient", return_value=_ctx_manager(mock_client)):
            result = await engine.scan("https://example.com", crawl=True)
        # max_crawl=2 means at most 2 URLs in phase 3 loop (but crawled may be more)
        assert result.urls_crawled <= engine._max_crawl + 1  # small tolerance for root


# ════════════════════════════════════════════════════════════════════
# Section D: _crawl() — link discovery (lines 376-406)
# ════════════════════════════════════════════════════════════════════

class TestCrawl:
    """Lines 376-406: _crawl method."""

    async def test_crawl_visits_root(self, engine, mock_client):
        """_crawl visits the given URL and adds it to visited."""
        mock_client.get = AsyncMock(
            return_value=_resp(200, text="<html></html>", headers={"content-type": "text/html"})
        )
        visited = set()
        await engine._crawl(mock_client, "https://example.com", visited, max_depth=1, depth=0)
        assert "https://example.com" in visited

    async def test_crawl_skips_already_visited(self, engine, mock_client):
        """_crawl does not re-visit already visited URLs."""
        visited = {"https://example.com"}
        await engine._crawl(mock_client, "https://example.com", visited, max_depth=1, depth=0)
        mock_client.get.assert_not_called()

    async def test_crawl_stops_at_max_depth(self, engine, mock_client):
        """_crawl stops when depth > max_depth."""
        visited = set()
        await engine._crawl(mock_client, "https://example.com", visited, max_depth=0, depth=1)
        mock_client.get.assert_not_called()
        assert len(visited) == 0

    async def test_crawl_stops_at_max_crawl(self, engine, mock_client):
        """_crawl stops when visited set reaches max_crawl."""
        engine._max_crawl = 2
        visited = {"https://example.com/a", "https://example.com/b"}
        await engine._crawl(mock_client, "https://example.com/c", visited, max_depth=2, depth=0)
        mock_client.get.assert_not_called()

    async def test_crawl_follows_absolute_links(self, engine, mock_client):
        """_crawl follows absolute links on same host."""
        html = '<html><a href="/about">About</a></html>'
        responses = [
            _resp(200, text=html, headers={"content-type": "text/html"}),
            _resp(200, text="<html></html>", headers={"content-type": "text/html"}),
        ]
        mock_client.get = AsyncMock(side_effect=responses)
        visited = set()
        await engine._crawl(mock_client, "https://example.com", visited, max_depth=2, depth=0)
        assert "https://example.com" in visited
        assert "https://example.com/about" in visited

    async def test_crawl_follows_full_url_links_same_host(self, engine, mock_client):
        """_crawl follows full http/https links on the same host."""
        html = '<html><a href="https://example.com/page2">page2</a></html>'
        responses = [
            _resp(200, text=html, headers={"content-type": "text/html"}),
            _resp(200, text="<html></html>", headers={"content-type": "text/html"}),
        ]
        mock_client.get = AsyncMock(side_effect=responses)
        visited = set()
        await engine._crawl(mock_client, "https://example.com", visited, max_depth=2, depth=0)
        assert "https://example.com/page2" in visited

    async def test_crawl_skips_links_on_other_host(self, engine, mock_client):
        """_crawl ignores links pointing to a different host."""
        html = '<html><a href="https://evil.com/payload">bad</a></html>'
        mock_client.get = AsyncMock(
            return_value=_resp(200, text=html, headers={"content-type": "text/html"})
        )
        visited = set()
        await engine._crawl(mock_client, "https://example.com", visited, max_depth=2, depth=0)
        # evil.com should NOT be in visited
        assert not any("evil.com" in v for v in visited)

    async def test_crawl_non_html_response_stops(self, engine, mock_client):
        """_crawl stops link extraction for non-HTML content-type."""
        mock_client.get = AsyncMock(
            return_value=_resp(200, text='{"key":"value"}', headers={"content-type": "application/json"})
        )
        visited = set()
        await engine._crawl(mock_client, "https://example.com/api/data", visited, max_depth=2, depth=0)
        assert "https://example.com/api/data" in visited
        # Should only have visited the root (no further links extracted)
        assert len(visited) == 1

    async def test_crawl_handles_timeout(self, engine, mock_client):
        """_crawl handles httpx.TimeoutException gracefully."""
        mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
        visited = set()
        # Should NOT raise
        await engine._crawl(mock_client, "https://example.com", visited, max_depth=2, depth=0)
        assert "https://example.com" in visited  # was added before request

    async def test_crawl_handles_generic_exception(self, engine, mock_client):
        """_crawl handles generic exceptions gracefully."""
        mock_client.get = AsyncMock(side_effect=ConnectionError("connection refused"))
        visited = set()
        await engine._crawl(mock_client, "https://example.com", visited, max_depth=2, depth=0)
        assert "https://example.com" in visited

    async def test_crawl_depth_increments(self, engine, mock_client):
        """_crawl passes depth+1 to recursive calls."""
        # depth=max_depth means next recursion (depth+1) will be > max_depth
        html = '<html><a href="/page">page</a></html>'
        mock_client.get = AsyncMock(
            return_value=_resp(200, text=html, headers={"content-type": "text/html"})
        )
        visited = set()
        await engine._crawl(mock_client, "https://example.com", visited, max_depth=0, depth=0)
        # At depth=0, max_depth=0: visit root (depth=0 not > 0), then try link at depth=1
        # depth=1 > max_depth=0 so link is skipped
        assert "https://example.com" in visited
        assert "https://example.com/page" not in visited


# ════════════════════════════════════════════════════════════════════
# Section E: _check_headers() (lines 411-448)
# ════════════════════════════════════════════════════════════════════

class TestCheckHeaders:
    """Lines 411-448: Security header checking."""

    async def test_all_security_headers_missing_generates_findings(self, engine, mock_client):
        """When response has no security headers, 7 findings are generated."""
        mock_client.get = AsyncMock(return_value=_resp(200, text="hello", headers={}))
        findings = await engine._check_headers(mock_client, "https://example.com")
        header_findings = [f for f in findings if f.category == DastCategory.HEADER]
        assert len(header_findings) == len(SECURITY_HEADERS)  # 7 headers checked

    async def test_security_header_present_no_finding(self, engine, mock_client):
        """When a security header is present, no finding for that header."""
        mock_client.get = AsyncMock(return_value=_resp(
            200,
            text="",
            headers={
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "X-XSS-Protection": "1; mode=block",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "geolocation=()",
            },
        ))
        findings = await engine._check_headers(mock_client, "https://example.com")
        header_findings = [f for f in findings if f.category == DastCategory.HEADER]
        assert len(header_findings) == 0

    async def test_server_version_disclosure_detected(self, engine, mock_client):
        """Server header with version triggers an info disclosure finding."""
        mock_client.get = AsyncMock(return_value=_resp(
            200, text="", headers={"server": "Apache/2.4.51 (Ubuntu)"}
        ))
        findings = await engine._check_headers(mock_client, "https://example.com")
        info_findings = [f for f in findings if f.category == DastCategory.INFO_DISCLOSURE]
        assert len(info_findings) == 1
        assert info_findings[0].title == "Server Version Disclosure"
        assert info_findings[0].severity == DastSeverity.LOW
        assert "Apache" in info_findings[0].evidence

    async def test_server_header_no_version_no_finding(self, engine, mock_client):
        """Server header without a version number does NOT trigger disclosure."""
        mock_client.get = AsyncMock(return_value=_resp(
            200, text="", headers={"server": "nginx"}
        ))
        findings = await engine._check_headers(mock_client, "https://example.com")
        info_findings = [f for f in findings if f.category == DastCategory.INFO_DISCLOSURE]
        # "nginx" has no digit pattern — no version finding
        assert all(f.title != "Server Version Disclosure" for f in info_findings)

    async def test_check_headers_timeout_returns_empty(self, engine, mock_client):
        """Timeout during header check returns empty findings."""
        mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
        findings = await engine._check_headers(mock_client, "https://example.com")
        assert findings == []

    async def test_check_headers_generic_exception_returns_empty(self, engine, mock_client):
        """Generic exception during header check returns empty findings."""
        mock_client.get = AsyncMock(side_effect=RuntimeError("something broke"))
        findings = await engine._check_headers(mock_client, "https://example.com")
        assert findings == []

    async def test_check_headers_finding_has_cwe(self, engine, mock_client):
        """Security header findings have CWE-693."""
        mock_client.get = AsyncMock(return_value=_resp(200, text="", headers={}))
        findings = await engine._check_headers(mock_client, "https://example.com")
        header_findings = [f for f in findings if f.category == DastCategory.HEADER]
        for finding in header_findings:
            assert finding.cwe_id == "CWE-693"

    async def test_check_headers_finding_has_recommendation(self, engine, mock_client):
        """Each header finding has a recommendation to add the header."""
        mock_client.get = AsyncMock(return_value=_resp(200, text="", headers={}))
        findings = await engine._check_headers(mock_client, "https://example.com")
        header_findings = [f for f in findings if f.category == DastCategory.HEADER]
        for finding in header_findings:
            assert "Add" in finding.recommendation

    async def test_partial_headers_missing(self, engine, mock_client):
        """Only missing headers generate findings."""
        mock_client.get = AsyncMock(return_value=_resp(
            200,
            text="",
            headers={
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
            },
        ))
        findings = await engine._check_headers(mock_client, "https://example.com")
        header_findings = [f for f in findings if f.category == DastCategory.HEADER]
        assert len(header_findings) == len(SECURITY_HEADERS) - 2

    async def test_server_version_finding_cwe(self, engine, mock_client):
        """Server version disclosure finding has CWE-200."""
        mock_client.get = AsyncMock(return_value=_resp(
            200, text="", headers={"server": "nginx/1.18.0"}
        ))
        findings = await engine._check_headers(mock_client, "https://example.com")
        ver_findings = [f for f in findings if f.title == "Server Version Disclosure"]
        assert len(ver_findings) == 1
        assert ver_findings[0].cwe_id == "CWE-200"


# ════════════════════════════════════════════════════════════════════
# Section F: _test_sqli() (lines 453-483)
# ════════════════════════════════════════════════════════════════════

class TestSQLiTesting:
    """Lines 453-483: SQL injection testing."""

    async def test_sqli_no_query_string_returns_empty(self, engine, mock_client):
        """URL without query string → no SQLi tests run."""
        findings = await engine._test_sqli(mock_client, "https://example.com/page")
        assert findings == []
        mock_client.get.assert_not_called()

    async def test_sqli_detects_sql_error_pattern(self, engine, mock_client):
        """SQL error in response generates a CRITICAL finding."""
        mock_client.get = AsyncMock(
            return_value=_resp(200, text="You have an error in your SQL syntax near 'DROP'")
        )
        findings = await engine._test_sqli(mock_client, "https://example.com/search?q=test")
        assert len(findings) == 1
        assert findings[0].title == "SQL Injection"
        assert findings[0].severity == DastSeverity.CRITICAL
        assert findings[0].category == DastCategory.INJECTION
        assert findings[0].cwe_id == "CWE-89"

    async def test_sqli_returns_on_first_match(self, engine, mock_client):
        """Once SQLi is found, no more payloads are tested."""
        sql_err = _resp(200, text="SQL syntax error detected")
        mock_client.get = AsyncMock(return_value=sql_err)
        findings = await engine._test_sqli(mock_client, "https://example.com/search?q=test")
        # Should return after first match, not try all 3 payloads
        assert len(findings) == 1
        assert mock_client.get.call_count == 1

    async def test_sqli_no_error_pattern_no_finding(self, engine, mock_client):
        """Clean response with no SQL errors returns no findings."""
        mock_client.get = AsyncMock(return_value=_resp(200, text="Search results: 42 items found"))
        findings = await engine._test_sqli(mock_client, "https://example.com/search?q=test")
        assert findings == []

    async def test_sqli_timeout_handled_gracefully(self, engine, mock_client):
        """Timeout during SQLi test is handled without exception."""
        mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
        findings = await engine._test_sqli(mock_client, "https://example.com/search?q=x")
        assert findings == []

    async def test_sqli_generic_exception_handled(self, engine, mock_client):
        """Generic exception during SQLi test is handled without exception."""
        mock_client.get = AsyncMock(side_effect=ConnectionError("refused"))
        findings = await engine._test_sqli(mock_client, "https://example.com/search?q=x")
        assert findings == []

    async def test_sqli_finding_payload_in_result(self, engine, mock_client):
        """SQLi finding contains the payload used."""
        mock_client.get = AsyncMock(
            return_value=_resp(200, text="mysql_fetch_array() error")
        )
        findings = await engine._test_sqli(mock_client, "https://example.com/item?id=1")
        assert len(findings) == 1
        # Payload should be one of the first 3 SQL_PAYLOADS
        assert findings[0].payload in SQL_PAYLOADS[:3]
        assert findings[0].parameter == "test"

    async def test_sqli_ora_pattern_detected(self, engine, mock_client):
        """Oracle ORA-NNNNN error pattern triggers SQLi finding."""
        mock_client.get = AsyncMock(
            return_value=_resp(200, text="ORA-00907: missing right parenthesis")
        )
        findings = await engine._test_sqli(mock_client, "https://example.com/api?id=5")
        assert len(findings) == 1
        assert findings[0].severity == DastSeverity.CRITICAL

    async def test_sqli_sqlstate_pattern_detected(self, engine, mock_client):
        """SQLSTATE error pattern triggers finding."""
        mock_client.get = AsyncMock(
            return_value=_resp(200, text="SQLSTATE[42000]: Syntax error or access violation")
        )
        findings = await engine._test_sqli(mock_client, "https://example.com/api?cat=1")
        assert len(findings) == 1

    async def test_sqli_multiple_payloads_tried_until_match(self, engine, mock_client):
        """When first payload gives no error, second payload is tried."""
        clean = _resp(200, text="No results")
        error = _resp(200, text="pg_query(): query failed: ERROR: syntax error at or near")
        mock_client.get = AsyncMock(side_effect=[clean, error])
        findings = await engine._test_sqli(mock_client, "https://example.com/search?q=test")
        assert len(findings) == 1
        assert mock_client.get.call_count == 2

    async def test_sqli_evidence_truncated(self, engine, mock_client):
        """Evidence in SQLi finding is at most 200 chars from resp.text."""
        long_body = "SQL syntax " + "x" * 500
        mock_client.get = AsyncMock(return_value=_resp(200, text=long_body))
        findings = await engine._test_sqli(mock_client, "https://example.com/s?q=x")
        assert len(findings) == 1
        assert len(findings[0].evidence) == 200


# ════════════════════════════════════════════════════════════════════
# Section G: _test_xss() (lines 486-515)
# ════════════════════════════════════════════════════════════════════

class TestXSSTesting:
    """Lines 486-515: XSS testing."""

    async def test_xss_no_query_string_returns_empty(self, engine, mock_client):
        """URL without query string → no XSS tests run."""
        findings = await engine._test_xss(mock_client, "https://example.com/page")
        assert findings == []
        mock_client.get.assert_not_called()

    async def test_xss_payload_reflected_generates_finding(self, engine, mock_client):
        """Payload reflected in response → HIGH XSS finding."""
        payload = XSS_PAYLOADS[0]  # <script>alert(1)</script>
        mock_client.get = AsyncMock(
            return_value=_resp(200, text=f"<html>Search: {payload}</html>")
        )
        findings = await engine._test_xss(mock_client, "https://example.com/search?q=test")
        assert len(findings) == 1
        assert findings[0].title == "Reflected XSS"
        assert findings[0].severity == DastSeverity.HIGH
        assert findings[0].category == DastCategory.XSS
        assert findings[0].cwe_id == "CWE-79"

    async def test_xss_returns_on_first_match(self, engine, mock_client):
        """XSS stops after first matching payload."""
        payload = XSS_PAYLOADS[0]
        mock_client.get = AsyncMock(
            return_value=_resp(200, text=f"<p>{payload}</p>")
        )
        findings = await engine._test_xss(mock_client, "https://example.com/search?q=x")
        assert len(findings) == 1
        assert mock_client.get.call_count == 1

    async def test_xss_no_reflection_no_finding(self, engine, mock_client):
        """Response without reflected payload → no findings."""
        mock_client.get = AsyncMock(
            return_value=_resp(200, text="<html>Encoded result: &lt;script&gt;</html>")
        )
        findings = await engine._test_xss(mock_client, "https://example.com/search?q=test")
        assert findings == []

    async def test_xss_timeout_handled(self, engine, mock_client):
        """Timeout during XSS test handled gracefully."""
        mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timed out"))
        findings = await engine._test_xss(mock_client, "https://example.com/search?q=x")
        assert findings == []

    async def test_xss_generic_exception_handled(self, engine, mock_client):
        """Generic exception during XSS test handled gracefully."""
        mock_client.get = AsyncMock(side_effect=ValueError("bad response"))
        findings = await engine._test_xss(mock_client, "https://example.com/search?q=x")
        assert findings == []

    async def test_xss_parameter_name_in_finding(self, engine, mock_client):
        """XSS finding uses 'q' as parameter name."""
        payload = XSS_PAYLOADS[0]
        mock_client.get = AsyncMock(
            return_value=_resp(200, text=f"You searched: {payload}")
        )
        findings = await engine._test_xss(mock_client, "https://example.com/search?term=abc")
        assert len(findings) == 1
        assert findings[0].parameter == "q"

    async def test_xss_second_payload_triggers(self, engine, mock_client):
        """When first payload not reflected, second payload is tried."""
        p0 = XSS_PAYLOADS[0]
        p1 = XSS_PAYLOADS[1]  # <img src=x onerror=alert(1)>
        clean = _resp(200, text="no match")
        reflected = _resp(200, text=f"result: {p1}")
        mock_client.get = AsyncMock(side_effect=[clean, reflected])
        findings = await engine._test_xss(mock_client, "https://example.com/search?q=x")
        assert len(findings) == 1
        assert findings[0].payload == p1
        assert mock_client.get.call_count == 2

    async def test_xss_test_url_built_correctly(self, engine, mock_client):
        """The test URL appends &q=<payload> to the base URL."""
        payload = XSS_PAYLOADS[0]
        mock_client.get = AsyncMock(return_value=_resp(200, text="no match"))
        await engine._test_xss(mock_client, "https://example.com/search?existing=val")
        # Check that .get was called with URL containing &q=
        call_url = mock_client.get.call_args_list[0][0][0]
        assert "&q=" in call_url
        assert "existing=val" in call_url


# ════════════════════════════════════════════════════════════════════
# Section H: _test_path_traversal() (lines 520-545)
# ════════════════════════════════════════════════════════════════════

class TestPathTraversal:
    """Lines 520-545: Path traversal testing."""

    async def test_path_traversal_root_in_response_triggers_finding(self, engine, mock_client):
        """'root:' in response triggers path traversal finding."""
        mock_client.get = AsyncMock(
            return_value=_resp(200, text="root:x:0:0:root:/root:/bin/bash")
        )
        findings = await engine._test_path_traversal(mock_client, "https://example.com/file")
        assert len(findings) == 1
        assert findings[0].title == "Path Traversal"
        assert findings[0].severity == DastSeverity.CRITICAL
        assert findings[0].category == DastCategory.INJECTION
        assert findings[0].cwe_id == "CWE-22"

    async def test_path_traversal_boot_loader_in_response(self, engine, mock_client):
        """'[boot loader]' in response triggers Windows path traversal finding."""
        mock_client.get = AsyncMock(
            return_value=_resp(200, text="[boot loader]\ntimeout=30")
        )
        findings = await engine._test_path_traversal(mock_client, "https://example.com/file")
        assert len(findings) == 1
        assert findings[0].severity == DastSeverity.CRITICAL

    async def test_path_traversal_clean_response_no_finding(self, engine, mock_client):
        """Normal response → no path traversal finding."""
        mock_client.get = AsyncMock(return_value=_resp(200, text="File not found"))
        findings = await engine._test_path_traversal(mock_client, "https://example.com/file")
        assert findings == []

    async def test_path_traversal_returns_on_first_match(self, engine, mock_client):
        """Stops after first matching payload."""
        mock_client.get = AsyncMock(
            return_value=_resp(200, text="root:x:0:0:root:/root:/bin/bash")
        )
        findings = await engine._test_path_traversal(mock_client, "https://example.com/file")
        assert len(findings) == 1
        assert mock_client.get.call_count == 1

    async def test_path_traversal_timeout_handled(self, engine, mock_client):
        """Timeout handled gracefully."""
        mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
        findings = await engine._test_path_traversal(mock_client, "https://example.com/file")
        assert findings == []

    async def test_path_traversal_generic_exception_handled(self, engine, mock_client):
        """Generic exception handled gracefully."""
        mock_client.get = AsyncMock(side_effect=OSError("connection error"))
        findings = await engine._test_path_traversal(mock_client, "https://example.com/file")
        assert findings == []

    async def test_path_traversal_url_built_with_trailing_slash_stripped(self, engine, mock_client):
        """URL has trailing slash stripped before appending payload."""
        mock_client.get = AsyncMock(return_value=_resp(200, text="clean"))
        await engine._test_path_traversal(mock_client, "https://example.com/files/")
        call_url = mock_client.get.call_args_list[0][0][0]
        assert not call_url.startswith("https://example.com/files//")

    async def test_path_traversal_payload_in_finding(self, engine, mock_client):
        """Path traversal finding contains the payload used."""
        mock_client.get = AsyncMock(
            return_value=_resp(200, text="root:x:0:0:root:/root:/bin/bash")
        )
        findings = await engine._test_path_traversal(mock_client, "https://example.com/file")
        assert findings[0].payload in PATH_TRAVERSAL_PAYLOADS[:2]

    async def test_path_traversal_second_payload_tried(self, engine, mock_client):
        """When first payload clean, second payload is tried."""
        clean = _resp(200, text="not found")
        triggered = _resp(200, text="root:x:0:0:root:/root:/bin/bash")
        mock_client.get = AsyncMock(side_effect=[clean, triggered])
        findings = await engine._test_path_traversal(mock_client, "https://example.com/file")
        assert len(findings) == 1
        assert mock_client.get.call_count == 2
        assert findings[0].payload == PATH_TRAVERSAL_PAYLOADS[1]


# ════════════════════════════════════════════════════════════════════
# Section I: _test_ssrf() (lines 550-582)
# ════════════════════════════════════════════════════════════════════

class TestSSRFTesting:
    """Lines 550-582: SSRF testing."""

    async def test_ssrf_no_query_string_returns_empty(self, engine, mock_client):
        """URL without query string → no SSRF tests run."""
        findings = await engine._test_ssrf(mock_client, "https://example.com/page")
        assert findings == []
        mock_client.get.assert_not_called()

    async def test_ssrf_ami_id_in_response_triggers_finding(self, engine, mock_client):
        """'ami-id' in response (AWS metadata) triggers SSRF finding."""
        mock_client.get = AsyncMock(
            return_value=_resp(200, text="ami-id: ami-12345678\ninstance-type: t2.micro")
        )
        findings = await engine._test_ssrf(mock_client, "https://example.com/fetch?q=test")
        assert len(findings) == 1
        assert findings[0].title == "Server-Side Request Forgery"
        assert findings[0].severity == DastSeverity.CRITICAL
        assert findings[0].category == DastCategory.SSRF
        assert findings[0].cwe_id == "CWE-918"

    async def test_ssrf_instance_id_in_response_triggers_finding(self, engine, mock_client):
        """'instance-id' keyword triggers SSRF finding."""
        mock_client.get = AsyncMock(
            return_value=_resp(200, text="instance-id: i-0abc123")
        )
        findings = await engine._test_ssrf(mock_client, "https://example.com/proxy?q=1")
        assert len(findings) == 1
        assert findings[0].parameter == "url"

    async def test_ssrf_root_colon_triggers_finding(self, engine, mock_client):
        """'root:' keyword triggers SSRF finding."""
        mock_client.get = AsyncMock(
            return_value=_resp(200, text="root:x:0:0:root:/root:/bin/bash")
        )
        findings = await engine._test_ssrf(mock_client, "https://example.com/load?q=x")
        assert len(findings) == 1

    async def test_ssrf_sshd_triggers_finding(self, engine, mock_client):
        """'sshd' keyword triggers SSRF finding."""
        mock_client.get = AsyncMock(
            return_value=_resp(200, text="sshd: server socket port 22")
        )
        findings = await engine._test_ssrf(mock_client, "https://example.com/check?q=x")
        assert len(findings) == 1

    async def test_ssrf_clean_response_no_finding(self, engine, mock_client):
        """Clean response → no SSRF finding."""
        mock_client.get = AsyncMock(return_value=_resp(200, text="URL fetched: 200 OK"))
        findings = await engine._test_ssrf(mock_client, "https://example.com/fetch?q=x")
        assert findings == []

    async def test_ssrf_returns_on_first_match(self, engine, mock_client):
        """Stops after first matching payload."""
        mock_client.get = AsyncMock(
            return_value=_resp(200, text="ami-id: ami-0123")
        )
        findings = await engine._test_ssrf(mock_client, "https://example.com/proxy?q=x")
        assert len(findings) == 1
        assert mock_client.get.call_count == 1

    async def test_ssrf_timeout_handled(self, engine, mock_client):
        """Timeout handled gracefully."""
        mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
        findings = await engine._test_ssrf(mock_client, "https://example.com/fetch?q=x")
        assert findings == []

    async def test_ssrf_generic_exception_handled(self, engine, mock_client):
        """Generic exception handled gracefully."""
        mock_client.get = AsyncMock(side_effect=RuntimeError("bad"))
        findings = await engine._test_ssrf(mock_client, "https://example.com/fetch?q=x")
        assert findings == []

    async def test_ssrf_test_url_built_correctly(self, engine, mock_client):
        """SSRF test URL appends &url=<payload>."""
        mock_client.get = AsyncMock(return_value=_resp(200, text="clean"))
        await engine._test_ssrf(mock_client, "https://example.com/proxy?existing=1")
        call_url = mock_client.get.call_args_list[0][0][0]
        assert "&url=" in call_url
        assert "existing=1" in call_url

    async def test_ssrf_payload_in_finding(self, engine, mock_client):
        """SSRF finding contains the payload used."""
        mock_client.get = AsyncMock(
            return_value=_resp(200, text="ami-id: ami-0123")
        )
        findings = await engine._test_ssrf(mock_client, "https://example.com/fetch?q=x")
        assert findings[0].payload in SSRF_PAYLOADS[:2]

    async def test_ssrf_second_payload_tried(self, engine, mock_client):
        """When first payload gives clean response, second is tried."""
        clean = _resp(200, text="OK")
        triggered = _resp(200, text="instance-id: i-abc")
        mock_client.get = AsyncMock(side_effect=[clean, triggered])
        findings = await engine._test_ssrf(mock_client, "https://example.com/proxy?q=x")
        assert len(findings) == 1
        assert mock_client.get.call_count == 2
        assert findings[0].payload == SSRF_PAYLOADS[1]


# ════════════════════════════════════════════════════════════════════
# Section J: _check_info_disclosure() (lines 587-623)
# ════════════════════════════════════════════════════════════════════

class TestInfoDisclosure:
    """Lines 587-623: Sensitive file disclosure checking."""

    async def test_env_file_exposed_with_password_triggers_finding(self, engine, mock_client):
        """/.env with 'password' keyword triggers HIGH finding (body must be >50 chars)."""
        env_body = "DB_PASSWORD=supersecret_value\nDB_HOST=prod-db.example.com\nDB_PORT=5432"
        assert len(env_body) > 50 and "password" in env_body.lower()

        async def get_side_effect(url):
            if url.endswith("/.env"):
                return _resp(200, text=env_body)
            return _resp(404, text="Not found")

        mock_client.get = get_side_effect
        findings = await engine._check_info_disclosure(mock_client, "https://example.com")
        env_findings = [f for f in findings if "/.env" in f.title]
        assert len(env_findings) == 1
        assert env_findings[0].severity == DastSeverity.HIGH
        assert env_findings[0].category == DastCategory.INFO_DISCLOSURE
        assert env_findings[0].cwe_id == "CWE-200"

    async def test_git_config_exposed_triggers_finding(self, engine, mock_client):
        """/.git/config with '[core]' keyword triggers finding (body must be >50 chars)."""
        git_body = "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\nurl = git@github.com:org/secret.git"
        assert len(git_body) > 50 and "[core]" in git_body.lower()

        async def get_side_effect(url):
            if "/.git/config" in url:
                return _resp(200, text=git_body)
            return _resp(404, text="Not found")

        mock_client.get = get_side_effect
        findings = await engine._check_info_disclosure(mock_client, "https://example.com")
        git_findings = [f for f in findings if ".git" in f.title]
        assert len(git_findings) == 1
        assert git_findings[0].severity == DastSeverity.HIGH

    async def test_sensitive_file_with_secret_keyword(self, engine, mock_client):
        """File containing 'secret' triggers finding (body must be >50 chars)."""
        body = "API_SECRET=abc123xyz_long_enough_value_to_pass_the_length_check_threshold"
        assert len(body) > 50 and "secret" in body.lower()

        async def get_side_effect(url):
            if url.endswith("/.env"):
                return _resp(200, text=body)
            return _resp(404, text="Not found")

        mock_client.get = get_side_effect
        findings = await engine._check_info_disclosure(mock_client, "https://example.com")
        assert len(findings) >= 1

    async def test_sensitive_file_with_api_key_keyword(self, engine, mock_client):
        """File containing 'api_key' triggers finding (body must be >50 chars)."""
        body = "api_key=my-super-secret-api-key-here-production-value-1234567890"
        assert len(body) > 50 and "api_key" in body.lower()

        async def get_side_effect(url):
            if url.endswith("/.env"):
                return _resp(200, text=body)
            return _resp(404, text="Not found")

        mock_client.get = get_side_effect
        findings = await engine._check_info_disclosure(mock_client, "https://example.com")
        assert len(findings) >= 1

    async def test_sensitive_file_with_db_host_keyword(self, engine, mock_client):
        """File containing 'db_host' triggers finding (body must be >50 chars)."""
        body = "db_host=prod-db.internal.example.com\ndb_port=5432\ndb_name=production"
        assert len(body) > 50 and "db_host" in body.lower()

        async def get_side_effect(url):
            if url.endswith("/.env"):
                return _resp(200, text=body)
            return _resp(404, text="Not found")

        mock_client.get = get_side_effect
        findings = await engine._check_info_disclosure(mock_client, "https://example.com")
        assert len(findings) >= 1

    async def test_404_response_no_finding(self, engine, mock_client):
        """404 response for sensitive paths → no findings."""
        mock_client.get = AsyncMock(return_value=_resp(404, text="Not Found"))
        findings = await engine._check_info_disclosure(mock_client, "https://example.com")
        assert findings == []

    async def test_200_but_short_body_no_finding(self, engine, mock_client):
        """200 response with body <= 50 chars → no finding (too short to be meaningful)."""
        mock_client.get = AsyncMock(return_value=_resp(200, text="password=x"))
        findings = await engine._check_info_disclosure(mock_client, "https://example.com")
        assert findings == []

    async def test_200_but_no_sensitive_keyword_no_finding(self, engine, mock_client):
        """200 response with long body but no sensitive keywords → no finding."""
        long_safe_body = "This is the robots.txt file. " * 5  # >50 chars, no sensitive keywords
        mock_client.get = AsyncMock(return_value=_resp(200, text=long_safe_body))
        findings = await engine._check_info_disclosure(mock_client, "https://example.com")
        assert findings == []

    async def test_info_disclosure_timeout_handled(self, engine, mock_client):
        """Timeout during info disclosure check handled gracefully."""
        mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
        findings = await engine._check_info_disclosure(mock_client, "https://example.com")
        assert findings == []

    async def test_info_disclosure_generic_exception_handled(self, engine, mock_client):
        """Generic exception handled gracefully."""
        mock_client.get = AsyncMock(side_effect=RuntimeError("bad"))
        findings = await engine._check_info_disclosure(mock_client, "https://example.com")
        assert findings == []

    async def test_info_disclosure_base_url_strips_query(self, engine, mock_client):
        """Query string is stripped from base URL before appending paths."""
        call_urls = []

        async def capture_get(url):
            call_urls.append(url)
            return _resp(404, text="Not found")

        mock_client.get = capture_get
        await engine._check_info_disclosure(
            mock_client, "https://example.com/page?q=search"
        )
        # Sensitive paths should NOT include the query string
        for url in call_urls:
            assert "?q=search" not in url

    async def test_info_disclosure_checks_up_to_4_paths(self, engine, mock_client):
        """Only first 4 sensitive paths are checked (sensitive_paths[:4])."""
        mock_client.get = AsyncMock(return_value=_resp(404, text="Not found"))
        await engine._check_info_disclosure(mock_client, "https://example.com")
        # Should have made exactly 4 requests (paths[:4])
        assert mock_client.get.call_count == 4

    async def test_info_disclosure_finding_url_includes_path(self, engine, mock_client):
        """Finding URL includes the sensitive path (body must be >50 chars)."""
        body = "password=supersecret_long_enough_body_to_pass_the_fifty_char_minimum_check"
        assert len(body) > 50 and "password" in body.lower()

        async def get_side_effect(url):
            if url.endswith("/.env"):
                return _resp(200, text=body)
            return _resp(404, text="Not found")

        mock_client.get = get_side_effect
        findings = await engine._check_info_disclosure(mock_client, "https://example.com")
        env_findings = [f for f in findings if "/.env" in f.url]
        assert len(env_findings) == 1
        assert "/.env" in env_findings[0].url


# ════════════════════════════════════════════════════════════════════
# Section K: Full scan() integration with findings
# ════════════════════════════════════════════════════════════════════

class TestScanIntegration:
    """Integration tests verifying scan() produces correct DastScanResult."""

    async def test_scan_with_sql_injection_target(self, engine, mock_client):
        """Full scan on SQLi-vulnerable URL returns CRITICAL finding."""
        target = "https://example.com/search?q=test"
        mock_client.get = AsyncMock(
            return_value=_resp(200, text="SQL syntax error in query: DROP TABLE")
        )
        with patch("core.dast_engine.httpx.AsyncClient", return_value=_ctx_manager(mock_client)):
            result = await engine.scan(target, crawl=False)
        assert result.total_findings > 0
        assert "critical" in result.by_severity or "high" in result.by_severity

    async def test_scan_with_xss_target(self, engine, mock_client):
        """Full scan on XSS-vulnerable URL returns HIGH finding."""
        target = "https://example.com/search?q=test"
        payload = XSS_PAYLOADS[0]
        # Return the XSS payload in response for XSS check
        mock_client.get = AsyncMock(
            return_value=_resp(200, text=f"<html>{payload}</html>")
        )
        with patch("core.dast_engine.httpx.AsyncClient", return_value=_ctx_manager(mock_client)):
            result = await engine.scan(target, crawl=False)
        assert result.total_findings > 0

    async def test_scan_result_to_dict_is_serializable(self, engine, mock_client):
        """DastScanResult.to_dict() produces a fully serializable dict."""
        mock_client.get = AsyncMock(return_value=_resp(200, text="clean"))
        with patch("core.dast_engine.httpx.AsyncClient", return_value=_ctx_manager(mock_client)):
            result = await engine.scan("https://example.com", crawl=False)
        import json
        d = result.to_dict()
        serialized = json.dumps(d)
        assert "scan_id" in serialized

    async def test_scan_with_path_traversal_target(self, engine, mock_client):
        """Full scan on path-traversal-vulnerable URL returns CRITICAL finding."""
        mock_client.get = AsyncMock(
            return_value=_resp(200, text="root:x:0:0:root:/root:/bin/bash")
        )
        with patch("core.dast_engine.httpx.AsyncClient", return_value=_ctx_manager(mock_client)):
            result = await engine.scan("https://example.com/files", crawl=False)
        assert result.total_findings > 0

    async def test_scan_with_ssrf_vulnerable_target(self, engine, mock_client):
        """Full scan on SSRF-vulnerable URL (with query string) returns finding."""
        target = "https://example.com/proxy?q=test"
        mock_client.get = AsyncMock(
            return_value=_resp(200, text="ami-id: ami-0123456789abcdef0")
        )
        with patch("core.dast_engine.httpx.AsyncClient", return_value=_ctx_manager(mock_client)):
            result = await engine.scan(target, crawl=False)
        assert result.total_findings > 0

    async def test_scan_crawled_urls_limited_to_50(self, engine, mock_client):
        """DastScanResult.to_dict() only returns first 50 crawled URLs."""
        # Create result with 100 crawled URLs
        result = DastScanResult(
            scan_id="dast-test",
            target="https://example.com",
            urls_crawled=100,
            total_findings=0,
            findings=[],
            by_severity={},
            by_category={},
            crawled_urls=[f"https://example.com/page{i}" for i in range(100)],
        )
        d = result.to_dict()
        assert len(d["crawled_urls"]) == 50

    async def test_scan_findings_count_matches_total(self, engine, mock_client):
        """total_findings in result equals len(findings)."""
        mock_client.get = AsyncMock(return_value=_resp(200, text="clean page"))
        with patch("core.dast_engine.httpx.AsyncClient", return_value=_ctx_manager(mock_client)):
            result = await engine.scan("https://example.com", crawl=False)
        assert result.total_findings == len(result.findings)


# ════════════════════════════════════════════════════════════════════
# Section L: Payload constant coverage
# ════════════════════════════════════════════════════════════════════

class TestPayloadConstants:
    """Verify payload arrays are populated correctly."""

    def test_sql_payloads_count(self):
        assert len(SQL_PAYLOADS) == 6

    def test_xss_payloads_count(self):
        assert len(XSS_PAYLOADS) == 6

    def test_ssrf_payloads_count(self):
        assert len(SSRF_PAYLOADS) == 5

    def test_path_traversal_payloads_count(self):
        assert len(PATH_TRAVERSAL_PAYLOADS) == 4

    def test_sql_error_patterns_count(self):
        assert len(SQL_ERROR_PATTERNS) == 9

    def test_security_headers_count(self):
        assert len(SECURITY_HEADERS) == 7

    def test_sql_payloads_include_union(self):
        assert any("UNION" in p for p in SQL_PAYLOADS)

    def test_xss_payloads_include_script_tag(self):
        assert any("<script>" in p for p in XSS_PAYLOADS)

    def test_ssrf_payloads_include_metadata_url(self):
        assert any("169.254.169.254" in p for p in SSRF_PAYLOADS)

    def test_path_traversal_includes_unix(self):
        assert any("etc/passwd" in p for p in PATH_TRAVERSAL_PAYLOADS)

    def test_path_traversal_includes_windows(self):
        assert any("windows" in p.lower() for p in PATH_TRAVERSAL_PAYLOADS)


# ════════════════════════════════════════════════════════════════════
# Section M: Edge cases in scan orchestration
# ════════════════════════════════════════════════════════════════════

class TestScanEdgeCases:
    """Additional edge cases to maximize coverage."""

    async def test_scan_with_max_depth_param(self, engine, mock_client):
        """scan() accepts max_depth parameter."""
        mock_client.get = AsyncMock(
            return_value=_resp(200, text="<html></html>", headers={"content-type": "text/html"})
        )
        with patch("core.dast_engine.httpx.AsyncClient", return_value=_ctx_manager(mock_client)):
            result = await engine.scan(
                "https://example.com", crawl=True, max_depth=1
            )
        assert isinstance(result, DastScanResult)

    async def test_scan_url_with_long_but_valid_path(self, engine, mock_client):
        """scan() accepts URLs with long paths (under 2048 chars)."""
        url = "https://example.com/" + "a" * 100
        mock_client.get = AsyncMock(return_value=_resp(200, text="clean"))
        with patch("core.dast_engine.httpx.AsyncClient", return_value=_ctx_manager(mock_client)):
            result = await engine.scan(url, crawl=False)
        assert result.target == url

    async def test_scan_empty_findings_still_builds_result(self, engine, mock_client):
        """scan() with no findings builds a valid DastScanResult."""
        # Return all security headers so no findings are generated
        all_headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        }
        mock_client.get = AsyncMock(return_value=_resp(200, text="clean", headers=all_headers))
        with patch("core.dast_engine.httpx.AsyncClient", return_value=_ctx_manager(mock_client)):
            result = await engine.scan("https://example.com", crawl=False)
        assert result.total_findings == 0
        assert result.by_severity == {}
        assert result.by_category == {}

    async def test_check_headers_case_insensitive_header_matching(self, engine, mock_client):
        """Header matching is case-insensitive (lowercase headers still match)."""
        # Headers in lowercase should still be matched as present
        mock_client.get = AsyncMock(return_value=_resp(
            200,
            text="",
            headers={
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self'",
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
                "x-xss-protection": "1; mode=block",
                "referrer-policy": "no-referrer",
                "permissions-policy": "geolocation=()",
            },
        ))
        findings = await engine._check_headers(mock_client, "https://example.com")
        header_findings = [f for f in findings if f.category == DastCategory.HEADER]
        # Lowercase headers should be recognized — 0 header findings
        assert len(header_findings) == 0

    async def test_sqli_uses_base_url_and_qs_split(self, engine, mock_client):
        """_test_sqli correctly splits on first '?' only."""
        mock_client.get = AsyncMock(return_value=_resp(200, text="clean"))
        await engine._test_sqli(mock_client, "https://example.com/path?a=1&b=2")
        call_url = mock_client.get.call_args_list[0][0][0]
        # Should start with base URL
        assert call_url.startswith("https://example.com/path?a=1&b=2&test=")

    async def test_xss_uses_base_url_and_qs_split(self, engine, mock_client):
        """_test_xss correctly splits on first '?' only."""
        mock_client.get = AsyncMock(return_value=_resp(200, text="clean"))
        await engine._test_xss(mock_client, "https://example.com/path?a=1&b=2")
        call_url = mock_client.get.call_args_list[0][0][0]
        assert call_url.startswith("https://example.com/path?a=1&b=2&q=")

    async def test_ssrf_uses_base_url_and_qs_split(self, engine, mock_client):
        """_test_ssrf correctly splits on first '?' only."""
        mock_client.get = AsyncMock(return_value=_resp(200, text="clean"))
        await engine._test_ssrf(mock_client, "https://example.com/proxy?a=1&b=2")
        call_url = mock_client.get.call_args_list[0][0][0]
        assert call_url.startswith("https://example.com/proxy?a=1&b=2&url=")
