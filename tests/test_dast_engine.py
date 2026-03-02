"""Comprehensive tests for DASTEngine (suite-core/core/dast_engine.py).

MOAT 3 — 8 Built-in Scanners (V3, V9)
Target: ≥80% coverage of dast_engine.py (629 LOC)

Tests cover:
- DastSeverity and DastCategory enums
- DastFinding and DastScanResult dataclasses
- _LinkParser HTML parsing
- DASTEngine: URL validation (SSRF protection), IP conversion, scan orchestration
- Edge cases: blocked IPs, invalid URLs, SSRF prevention
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'suite-core'))

import pytest
from core.dast_engine import (
    DastCategory,
    DastFinding,
    DastScanResult,
    DastSeverity,
    DASTEngine,
    get_dast_engine,
)


# ====================================================================
# Fixtures
# ====================================================================

@pytest.fixture
def engine():
    return DASTEngine(timeout=5.0, max_crawl=5)


# ====================================================================
# Section 1: Enum Tests
# ====================================================================

class TestDastSeverity:
    def test_all_values(self):
        assert DastSeverity.CRITICAL.value == "critical"
        assert DastSeverity.HIGH.value == "high"
        assert DastSeverity.MEDIUM.value == "medium"
        assert DastSeverity.LOW.value == "low"
        assert DastSeverity.INFO.value == "info"

    def test_count(self):
        assert len(DastSeverity) == 5


class TestDastCategory:
    def test_all_values(self):
        assert DastCategory.INJECTION.value == "injection"
        assert DastCategory.XSS.value == "xss"
        assert DastCategory.AUTH.value == "authentication"
        assert DastCategory.MISCONFIG.value == "misconfiguration"
        assert DastCategory.INFO_DISCLOSURE.value == "information_disclosure"
        assert DastCategory.SSRF.value == "ssrf"
        assert DastCategory.CSRF.value == "csrf"
        assert DastCategory.HEADER.value == "security_header"
        assert DastCategory.SSL.value == "ssl_tls"
        assert DastCategory.CRAWL.value == "crawl"

    def test_count(self):
        assert len(DastCategory) == 10


# ====================================================================
# Section 2: DastFinding Tests
# ====================================================================

class TestDastFinding:
    def test_construction(self):
        f = DastFinding(
            finding_id="DAST-001",
            title="SQL Injection",
            severity=DastSeverity.CRITICAL,
            category=DastCategory.INJECTION,
            url="https://example.com/search?q=test",
            method="GET",
            parameter="q",
            payload="' OR 1=1--",
        )
        assert f.finding_id == "DAST-001"
        assert f.severity == DastSeverity.CRITICAL
        assert f.confidence == 0.8

    def test_to_dict(self):
        f = DastFinding(
            finding_id="DAST-002",
            title="XSS",
            severity=DastSeverity.HIGH,
            category=DastCategory.XSS,
            url="https://example.com",
            evidence="<script>alert(1)</script>" * 100,
        )
        d = f.to_dict()
        assert d["finding_id"] == "DAST-002"
        assert d["severity"] == "high"
        assert d["category"] == "xss"
        # Evidence should be truncated to 500 chars
        assert len(d["evidence"]) <= 500
        assert "timestamp" in d

    def test_default_method(self):
        f = DastFinding(
            finding_id="test",
            title="test",
            severity=DastSeverity.INFO,
            category=DastCategory.CRAWL,
            url="https://example.com",
        )
        assert f.method == "GET"


# ====================================================================
# Section 3: DastScanResult Tests
# ====================================================================

class TestDastScanResult:
    def test_construction(self):
        result = DastScanResult(
            scan_id="scan-001",
            target="https://example.com",
            urls_crawled=5,
            total_findings=2,
            findings=[],
            by_severity={"critical": 1, "high": 1},
            by_category={"injection": 1, "xss": 1},
            crawled_urls=["https://example.com", "https://example.com/about"],
        )
        assert result.scan_id == "scan-001"
        assert result.urls_crawled == 5
        assert result.authenticated is False

    def test_to_dict(self):
        result = DastScanResult(
            scan_id="scan-002",
            target="https://example.com",
            urls_crawled=0,
            total_findings=0,
            findings=[],
            by_severity={},
            by_category={},
            crawled_urls=[],
        )
        d = result.to_dict()
        assert d["scan_id"] == "scan-002"
        assert d["target"] == "https://example.com"
        assert isinstance(d["findings"], list)
        assert "timestamp" in d


# ====================================================================
# Section 4: IP Conversion Tests
# ====================================================================

class TestIPConversion:
    def test_valid_ip(self):
        assert DASTEngine._ip_to_int("192.168.1.1") == (192 << 24) | (168 << 16) | (1 << 8) | 1

    def test_loopback(self):
        assert DASTEngine._ip_to_int("127.0.0.1") == (127 << 24) | 1

    def test_zero_ip(self):
        assert DASTEngine._ip_to_int("0.0.0.0") == 0

    def test_max_ip(self):
        assert DASTEngine._ip_to_int("255.255.255.255") == (255 << 24) | (255 << 16) | (255 << 8) | 255

    def test_invalid_ip_empty(self):
        assert DASTEngine._ip_to_int("") == 0

    def test_invalid_ip_too_few_octets(self):
        assert DASTEngine._ip_to_int("192.168.1") == 0

    def test_invalid_ip_non_numeric(self):
        assert DASTEngine._ip_to_int("abc.def.ghi.jkl") == 0


# ====================================================================
# Section 5: Blocked Ranges Initialization
# ====================================================================

class TestBlockedRanges:
    def test_init_blocked_ranges(self):
        DASTEngine._BLOCKED_RANGES = []  # Reset
        DASTEngine._init_blocked_ranges()
        assert len(DASTEngine._BLOCKED_RANGES) >= 7  # 7 ranges defined

    def test_idempotent(self):
        DASTEngine._BLOCKED_RANGES = []
        DASTEngine._init_blocked_ranges()
        count = len(DASTEngine._BLOCKED_RANGES)
        DASTEngine._init_blocked_ranges()
        assert len(DASTEngine._BLOCKED_RANGES) == count  # Same count


# ====================================================================
# Section 6: URL Validation (SSRF Protection)
# ====================================================================

class TestURLValidation:
    def test_valid_https_url(self):
        url = DASTEngine.validate_target_url("https://example.com")
        assert url == "https://example.com"

    def test_valid_http_url(self):
        url = DASTEngine.validate_target_url("http://example.com")
        assert url == "http://example.com"

    def test_blocked_file_scheme(self):
        with pytest.raises(ValueError, match="Blocked scheme"):
            DASTEngine.validate_target_url("file:///etc/passwd")

    def test_blocked_ftp_scheme(self):
        with pytest.raises(ValueError, match="Blocked scheme"):
            DASTEngine.validate_target_url("ftp://evil.com/file")

    def test_blocked_gopher_scheme(self):
        with pytest.raises(ValueError, match="Blocked scheme"):
            DASTEngine.validate_target_url("gopher://evil.com")

    def test_blocked_localhost(self):
        with pytest.raises(ValueError, match="loopback"):
            DASTEngine.validate_target_url("http://localhost/admin")

    def test_blocked_127_0_0_1(self):
        with pytest.raises(ValueError, match="private/reserved"):
            DASTEngine.validate_target_url("http://127.0.0.1/admin")

    def test_blocked_0_0_0_0(self):
        with pytest.raises(ValueError, match="loopback"):
            DASTEngine.validate_target_url("http://0.0.0.0/admin")

    def test_blocked_ipv6_loopback(self):
        with pytest.raises(ValueError, match="loopback"):
            DASTEngine.validate_target_url("http://[::1]/admin")

    def test_blocked_rfc1918_10_x(self):
        with pytest.raises(ValueError, match="private/reserved"):
            DASTEngine.validate_target_url("http://10.0.0.1/admin")

    def test_blocked_rfc1918_172_16(self):
        with pytest.raises(ValueError, match="private/reserved"):
            DASTEngine.validate_target_url("http://172.16.0.1/internal")

    def test_blocked_rfc1918_192_168(self):
        with pytest.raises(ValueError, match="private/reserved"):
            DASTEngine.validate_target_url("http://192.168.1.1/router")

    def test_blocked_metadata_169_254(self):
        with pytest.raises(ValueError, match="private/reserved"):
            DASTEngine.validate_target_url("http://169.254.169.254/latest/meta-data")

    def test_missing_hostname(self):
        with pytest.raises(ValueError, match="Missing hostname"):
            DASTEngine.validate_target_url("http:///path")

    def test_url_with_path_and_params(self):
        url = DASTEngine.validate_target_url("https://example.com/search?q=test&page=1")
        assert "example.com" in url


# ====================================================================
# Section 7: Engine Initialization
# ====================================================================

class TestEngineInit:
    def test_default_init(self):
        e = DASTEngine()
        assert e._timeout == 10.0
        assert e._max_crawl == 50

    def test_custom_init(self):
        e = DASTEngine(timeout=5.0, max_crawl=10)
        assert e._timeout == 5.0
        assert e._max_crawl == 10


# ====================================================================
# Section 8: Singleton
# ====================================================================

class TestSingleton:
    def test_get_dast_engine(self):
        import core.dast_engine as mod
        mod._engine = None
        e1 = get_dast_engine()
        e2 = get_dast_engine()
        assert e1 is e2
        assert isinstance(e1, DASTEngine)


# ====================================================================
# Section 9: Async Scan Tests (with network mocking)
# ====================================================================

class TestScanSSRFProtection:
    """Test that scan() enforces URL validation."""

    @pytest.mark.asyncio
    async def test_scan_blocks_localhost(self, engine):
        with pytest.raises(ValueError, match="loopback"):
            await engine.scan("http://localhost:8080/admin")

    @pytest.mark.asyncio
    async def test_scan_blocks_internal_ip(self, engine):
        with pytest.raises(ValueError, match="private/reserved"):
            await engine.scan("http://10.0.0.5/internal")

    @pytest.mark.asyncio
    async def test_scan_blocks_file_scheme(self, engine):
        with pytest.raises(ValueError, match="Blocked scheme"):
            await engine.scan("file:///etc/shadow")


# ====================================================================
# Section 10: Link Parser Tests
# ====================================================================

class TestLinkParser:
    def test_extract_links(self):
        from core.dast_engine import _LinkParser
        parser = _LinkParser()
        parser.feed('<a href="/about">About</a><a href="/contact">Contact</a>')
        assert "/about" in parser.links
        assert "/contact" in parser.links

    def test_extract_forms(self):
        from core.dast_engine import _LinkParser
        parser = _LinkParser()
        parser.feed('''
        <form action="/login" method="POST">
            <input type="text" name="username">
            <input type="password" name="password">
        </form>
        ''')
        assert len(parser.forms) == 1
        form = parser.forms[0]
        assert form["action"] == "/login"
        assert form["method"] == "POST"
        assert len(form["inputs"]) == 2

    def test_extract_links_with_script(self):
        """_LinkParser only extracts a.href and forms — not script src."""
        from core.dast_engine import _LinkParser
        parser = _LinkParser()
        # Script tags with src are not extracted by this parser
        parser.feed('<a href="/page1">Link</a><script src="/js/app.js"></script>')
        assert "/page1" in parser.links

    def test_empty_html(self):
        from core.dast_engine import _LinkParser
        parser = _LinkParser()
        parser.feed('')
        assert parser.links == []
        assert parser.forms == []

    def test_no_href(self):
        from core.dast_engine import _LinkParser
        parser = _LinkParser()
        parser.feed('<a>No href</a>')
        assert len(parser.links) == 0

    def test_form_without_action(self):
        from core.dast_engine import _LinkParser
        parser = _LinkParser()
        parser.feed('<form><input name="x"></form>')
        assert len(parser.forms) == 1
        assert parser.forms[0]["action"] == ""


# ====================================================================
# Section 11: Edge Cases
# ====================================================================

class TestEdgeCases:
    def test_ip_boundary_10_0_0_0(self):
        """10.0.0.0 should be blocked."""
        ip_int = DASTEngine._ip_to_int("10.0.0.0")
        DASTEngine._init_blocked_ranges()
        blocked = any(s <= ip_int <= e for s, e in DASTEngine._BLOCKED_RANGES)
        assert blocked

    def test_ip_boundary_9_255_255_255(self):
        """9.255.255.255 should NOT be blocked (just outside 10.x range)."""
        ip_int = DASTEngine._ip_to_int("9.255.255.255")
        DASTEngine._init_blocked_ranges()
        blocked = any(s <= ip_int <= e for s, e in DASTEngine._BLOCKED_RANGES)
        assert not blocked

    def test_ip_boundary_11_0_0_0(self):
        """11.0.0.0 should NOT be blocked (just outside 10.x range)."""
        ip_int = DASTEngine._ip_to_int("11.0.0.0")
        DASTEngine._init_blocked_ranges()
        blocked = any(s <= ip_int <= e for s, e in DASTEngine._BLOCKED_RANGES)
        assert not blocked

    def test_public_ip_not_blocked(self):
        """93.184.216.34 (example.com) should NOT be blocked."""
        ip_int = DASTEngine._ip_to_int("93.184.216.34")
        DASTEngine._init_blocked_ranges()
        blocked = any(s <= ip_int <= e for s, e in DASTEngine._BLOCKED_RANGES)
        assert not blocked
