"""Unit tests for ALdeci DAST Engine — Dynamic Application Security Testing.

Tests data models, HTML parser, header checks, injection test logic,
and scan orchestration. Uses httpx mocking for async HTTP tests.
Covers V7 (scanner engine) pillar.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from core.dast_engine import (
    AuthMode,
    AuthSessionConfig,
    AuthSessionManager,
    DASTEngine,
    DastCategory,
    DastFinding,
    DastScanResult,
    DastSeverity,
    OpenAPIEndpoint,
    SQL_PAYLOADS,
    XSS_PAYLOADS,
    SSRF_PAYLOADS,
    PATH_TRAVERSAL_PAYLOADS,
    COMMAND_INJECTION_PAYLOADS,
    SQL_ERROR_PATTERNS,
    SECURITY_HEADERS,
    _LinkParser,
    get_dast_engine,
    parse_openapi_spec,
    _generate_param_value,
)


# ── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture
def engine():
    return DASTEngine(timeout=5.0, max_crawl=10)


# ── Enum Tests ──────────────────────────────────────────────────────


class TestEnums:
    def test_severity_values(self):
        assert DastSeverity.CRITICAL.value == "critical"
        assert DastSeverity.HIGH.value == "high"
        assert DastSeverity.MEDIUM.value == "medium"
        assert DastSeverity.LOW.value == "low"
        assert DastSeverity.INFO.value == "info"

    def test_category_values(self):
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


# ── Data Model Tests ────────────────────────────────────────────────


class TestDastFinding:
    def test_to_dict_basic(self):
        f = DastFinding(
            finding_id="DAST-001",
            title="SQL Injection",
            severity=DastSeverity.CRITICAL,
            category=DastCategory.INJECTION,
            url="http://example.com/search?q=test",
            method="GET",
            parameter="q",
            payload="' OR '1'='1",
            evidence="SQL syntax error",
            cwe_id="CWE-89",
            description="SQL injection vulnerability",
            recommendation="Use parameterized queries",
        )
        d = f.to_dict()
        assert d["finding_id"] == "DAST-001"
        assert d["severity"] == "critical"
        assert d["category"] == "injection"
        assert d["url"] == "http://example.com/search?q=test"
        assert d["method"] == "GET"
        assert d["parameter"] == "q"
        assert d["cwe_id"] == "CWE-89"
        assert "timestamp" in d
        assert d["confidence"] == 0.8  # default

    def test_evidence_truncation(self):
        f = DastFinding(
            finding_id="DAST-002",
            title="Test",
            severity=DastSeverity.LOW,
            category=DastCategory.XSS,
            url="http://test.com",
            evidence="x" * 1000,
        )
        d = f.to_dict()
        assert len(d["evidence"]) <= 500

    def test_default_values(self):
        f = DastFinding(
            finding_id="test",
            title="t",
            severity=DastSeverity.INFO,
            category=DastCategory.CRAWL,
            url="http://localhost",
        )
        assert f.method == "GET"
        assert f.parameter == ""
        assert f.payload == ""
        assert f.evidence == ""
        assert f.cwe_id == ""
        assert f.confidence == 0.8


class TestDastScanResult:
    def test_to_dict(self):
        result = DastScanResult(
            scan_id="dast-123",
            target="http://target.com",
            urls_crawled=5,
            total_findings=2,
            findings=[],
            by_severity={"critical": 1, "high": 1},
            by_category={"injection": 1, "xss": 1},
            crawled_urls=["http://target.com/a", "http://target.com/b"],
            duration_ms=1234.5,
            authenticated=True,
        )
        d = result.to_dict()
        assert d["scan_id"] == "dast-123"
        assert d["target"] == "http://target.com"
        assert d["urls_crawled"] == 5
        assert d["total_findings"] == 2
        assert d["authenticated"] is True
        assert "timestamp" in d

    def test_crawled_urls_limit(self):
        urls = [f"http://example.com/{i}" for i in range(100)]
        result = DastScanResult(
            scan_id="dast-xxx",
            target="http://example.com",
            urls_crawled=100,
            total_findings=0,
            findings=[],
            by_severity={},
            by_category={},
            crawled_urls=urls,
        )
        d = result.to_dict()
        assert len(d["crawled_urls"]) <= 50


# ── Payload Tests ───────────────────────────────────────────────────


class TestPayloads:
    def test_sql_payloads_exist(self):
        assert len(SQL_PAYLOADS) >= 6
        assert any("OR" in p for p in SQL_PAYLOADS)
        assert any("UNION" in p for p in SQL_PAYLOADS)

    def test_xss_payloads_exist(self):
        assert len(XSS_PAYLOADS) >= 6
        assert any("<script>" in p for p in XSS_PAYLOADS)
        assert any("onerror" in p for p in XSS_PAYLOADS)

    def test_ssrf_payloads_exist(self):
        assert len(SSRF_PAYLOADS) >= 5
        assert any("169.254.169.254" in p for p in SSRF_PAYLOADS)

    def test_path_traversal_payloads_exist(self):
        assert len(PATH_TRAVERSAL_PAYLOADS) >= 4
        assert any("etc/passwd" in p for p in PATH_TRAVERSAL_PAYLOADS)

    def test_command_injection_payloads_exist(self):
        assert len(COMMAND_INJECTION_PAYLOADS) >= 6

    def test_sql_error_patterns(self):
        assert len(SQL_ERROR_PATTERNS) >= 9

    def test_security_headers(self):
        assert len(SECURITY_HEADERS) >= 7
        header_names = [h[0] for h in SECURITY_HEADERS]
        assert "Strict-Transport-Security" in header_names
        assert "Content-Security-Policy" in header_names
        assert "X-Content-Type-Options" in header_names


# ── HTML Parser Tests ───────────────────────────────────────────────


class TestLinkParser:
    def test_extract_links(self):
        parser = _LinkParser()
        parser.feed('<html><body><a href="/page1">Link</a><a href="/page2">Link2</a></body></html>')
        assert len(parser.links) == 2
        assert "/page1" in parser.links
        assert "/page2" in parser.links

    def test_extract_forms(self):
        parser = _LinkParser()
        parser.feed('''
        <form action="/login" method="POST">
            <input name="username" type="text" value="">
            <input name="password" type="password" value="">
        </form>
        ''')
        assert len(parser.forms) == 1
        assert parser.forms[0]["action"] == "/login"
        assert parser.forms[0]["method"] == "POST"
        assert len(parser.forms[0]["inputs"]) == 2

    def test_no_links(self):
        parser = _LinkParser()
        parser.feed("<html><body><p>No links here</p></body></html>")
        assert len(parser.links) == 0
        assert len(parser.forms) == 0

    def test_form_default_method(self):
        parser = _LinkParser()
        parser.feed('<form action="/search"><input name="q" type="text"></form>')
        assert parser.forms[0]["method"] == "GET"

    def test_nested_input_without_form(self):
        parser = _LinkParser()
        parser.feed('<input name="loose" type="text">')
        assert len(parser.forms) == 0

    def test_multiple_forms(self):
        parser = _LinkParser()
        parser.feed('''
        <form action="/a" method="GET"></form>
        <form action="/b" method="POST"><input name="x"></form>
        ''')
        assert len(parser.forms) == 2


# ── Engine Init Tests ───────────────────────────────────────────────


class TestEngineInit:
    def test_default_config(self):
        e = DASTEngine()
        assert e._timeout == 10.0
        assert e._max_crawl == 50

    def test_custom_config(self):
        e = DASTEngine(timeout=5.0, max_crawl=20)
        assert e._timeout == 5.0
        assert e._max_crawl == 20


# ── Singleton Tests ─────────────────────────────────────────────────


class TestSingleton:
    def test_get_dast_engine_returns_engine(self):
        e = get_dast_engine()
        assert isinstance(e, DASTEngine)

    def test_get_dast_engine_singleton(self):
        e1 = get_dast_engine()
        e2 = get_dast_engine()
        assert e1 is e2


# ── Header Check Tests (mocked) ────────────────────────────────────


class TestHeaderCheck:
    @pytest.mark.asyncio
    async def test_missing_headers_detected(self, engine):
        """Test that missing security headers are flagged."""
        mock_response = MagicMock()
        mock_response.headers = {}  # No security headers
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        findings = await engine._check_headers(mock_client, "http://test.com")
        assert len(findings) >= 7  # All 7 security headers missing
        categories = {f.category for f in findings}
        assert DastCategory.HEADER in categories

    @pytest.mark.asyncio
    async def test_present_headers_not_flagged(self, engine):
        """Test that present security headers are not flagged."""
        headers = {h[0]: "value" for h in SECURITY_HEADERS}
        mock_response = MagicMock()
        mock_response.headers = headers
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        findings = await engine._check_headers(mock_client, "http://test.com")
        header_findings = [f for f in findings if f.category == DastCategory.HEADER]
        assert len(header_findings) == 0

    @pytest.mark.asyncio
    async def test_server_version_disclosure(self, engine):
        """Test server version disclosure detection."""
        mock_response = MagicMock()
        mock_response.headers = {"server": "Apache/2.4.52"}
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        findings = await engine._check_headers(mock_client, "http://test.com")
        info_disc = [f for f in findings if f.category == DastCategory.INFO_DISCLOSURE]
        assert len(info_disc) >= 1
        assert any("Server Version" in f.title for f in info_disc)

    @pytest.mark.asyncio
    async def test_header_check_exception(self, engine):
        """Test graceful handling of connection errors."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=OSError("Connection refused"))

        findings = await engine._check_headers(mock_client, "http://unreachable.com")
        assert findings == []


# ── SQL Injection Test Logic ────────────────────────────────────────


class TestSQLiCheck:
    @pytest.mark.asyncio
    async def test_no_query_string_skips(self, engine):
        mock_client = AsyncMock()
        findings = await engine._test_sqli(mock_client, "http://test.com/page")
        assert findings == []

    @pytest.mark.asyncio
    async def test_sql_error_detected(self, engine):
        mock_response = MagicMock()
        mock_response.text = "You have an error in your SQL syntax near..."

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        findings = await engine._test_sqli(mock_client, "http://test.com/page?id=1")
        assert len(findings) >= 1
        assert findings[0].severity == DastSeverity.CRITICAL
        assert findings[0].category == DastCategory.INJECTION
        assert findings[0].cwe_id == "CWE-89"

    @pytest.mark.asyncio
    async def test_no_sql_error(self, engine):
        mock_response = MagicMock()
        mock_response.text = "Normal page content"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        findings = await engine._test_sqli(mock_client, "http://test.com/page?id=1")
        assert len(findings) == 0


# ── XSS Test Logic ─────────────────────────────────────────────────


class TestXSSCheck:
    @pytest.mark.asyncio
    async def test_no_query_string_skips(self, engine):
        mock_client = AsyncMock()
        findings = await engine._test_xss(mock_client, "http://test.com/page")
        assert findings == []

    @pytest.mark.asyncio
    async def test_reflected_xss_detected(self, engine):
        mock_response = MagicMock()
        mock_response.text = f"Search results for: {XSS_PAYLOADS[0]}"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        findings = await engine._test_xss(mock_client, "http://test.com/search?q=test")
        assert len(findings) >= 1
        assert findings[0].severity == DastSeverity.HIGH
        assert findings[0].category == DastCategory.XSS
        assert findings[0].cwe_id == "CWE-79"

    @pytest.mark.asyncio
    async def test_no_xss(self, engine):
        mock_response = MagicMock()
        mock_response.text = "Safe output"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        findings = await engine._test_xss(mock_client, "http://test.com/search?q=test")
        assert len(findings) == 0


# ── Path Traversal Test Logic ───────────────────────────────────────


class TestPathTraversal:
    @pytest.mark.asyncio
    async def test_traversal_detected(self, engine):
        mock_response = MagicMock()
        mock_response.text = "root:x:0:0:root:/root:/bin/bash"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        findings = await engine._test_path_traversal(mock_client, "http://test.com/files")
        assert len(findings) >= 1
        assert findings[0].severity == DastSeverity.CRITICAL
        assert findings[0].cwe_id == "CWE-22"

    @pytest.mark.asyncio
    async def test_no_traversal(self, engine):
        mock_response = MagicMock()
        mock_response.text = "404 Not Found"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        findings = await engine._test_path_traversal(mock_client, "http://test.com/files")
        assert len(findings) == 0


# ── SSRF Test Logic ─────────────────────────────────────────────────


class TestSSRFCheck:
    @pytest.mark.asyncio
    async def test_no_query_string_skips(self, engine):
        mock_client = AsyncMock()
        findings = await engine._test_ssrf(mock_client, "http://test.com/page")
        assert findings == []

    @pytest.mark.asyncio
    async def test_ssrf_detected(self, engine):
        mock_response = MagicMock()
        mock_response.text = "ami-id: ami-12345678"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        findings = await engine._test_ssrf(mock_client, "http://test.com/fetch?url=x")
        assert len(findings) >= 1
        assert findings[0].severity == DastSeverity.CRITICAL
        assert findings[0].category == DastCategory.SSRF
        assert findings[0].cwe_id == "CWE-918"


# ── Info Disclosure Test Logic ──────────────────────────────────────


class TestInfoDisclosure:
    @pytest.mark.asyncio
    async def test_sensitive_file_detected(self, engine):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "DB_HOST=localhost\npassword=secret123\nAPI_KEY=abc" + "x" * 50

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        findings = await engine._check_info_disclosure(mock_client, "http://test.com")
        assert len(findings) >= 1
        assert any(f.category == DastCategory.INFO_DISCLOSURE for f in findings)

    @pytest.mark.asyncio
    async def test_404_not_flagged(self, engine):
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.text = ""

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        findings = await engine._check_info_disclosure(mock_client, "http://test.com")
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_small_response_not_flagged(self, engine):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "small"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        findings = await engine._check_info_disclosure(mock_client, "http://test.com")
        assert len(findings) == 0



# ── Auth Mode & Config Tests ──────────────────────────────────────


class TestAuthMode:
    def test_auth_mode_values(self):
        assert AuthMode.BEARER.value == "bearer"
        assert AuthMode.BASIC.value == "basic"
        assert AuthMode.API_KEY.value == "api_key"
        assert AuthMode.FORM_LOGIN.value == "form_login"
        assert AuthMode.COOKIE.value == "cookie"
        assert AuthMode.OAUTH2.value == "oauth2"
        assert AuthMode.NONE.value == "none"

    def test_auth_session_config_defaults(self):
        cfg = AuthSessionConfig()
        assert cfg.mode == AuthMode.NONE
        assert cfg.bearer_token == ""
        assert cfg.reauth_on_401 is True
        assert cfg.max_reauth_attempts == 3

    def test_auth_session_config_to_dict(self):
        cfg = AuthSessionConfig(mode=AuthMode.BEARER, bearer_token="tok123")
        d = cfg.to_dict()
        assert d["mode"] == "bearer"
        assert d["has_credentials"] is True

    def test_auth_session_config_no_creds(self):
        cfg = AuthSessionConfig(mode=AuthMode.NONE)
        d = cfg.to_dict()
        assert d["has_credentials"] is False


# ── AuthSessionManager Tests ──────────────────────────────────────


class TestAuthSessionManager:
    def test_init(self):
        cfg = AuthSessionConfig(mode=AuthMode.BEARER, bearer_token="tok")
        mgr = AuthSessionManager(cfg)
        assert mgr.is_authenticated is False
        assert mgr.session_cookies == {}
        assert mgr.auth_headers == {}

    @pytest.mark.asyncio
    async def test_auth_bearer(self):
        cfg = AuthSessionConfig(mode=AuthMode.BEARER, bearer_token="my-jwt-token")
        mgr = AuthSessionManager(cfg)
        client = AsyncMock()
        result = await mgr.authenticate(client)
        assert result is True
        assert mgr.is_authenticated is True
        assert mgr.auth_headers["Authorization"] == "Bearer my-jwt-token"

    @pytest.mark.asyncio
    async def test_auth_bearer_no_token(self):
        cfg = AuthSessionConfig(mode=AuthMode.BEARER, bearer_token="")
        mgr = AuthSessionManager(cfg)
        client = AsyncMock()
        result = await mgr.authenticate(client)
        assert result is False

    @pytest.mark.asyncio
    async def test_auth_basic(self):
        cfg = AuthSessionConfig(mode=AuthMode.BASIC, basic_username="admin", basic_password="pass123")
        mgr = AuthSessionManager(cfg)
        client = AsyncMock()
        result = await mgr.authenticate(client)
        assert result is True
        assert "Authorization" in mgr.auth_headers
        assert mgr.auth_headers["Authorization"].startswith("Basic ")

    @pytest.mark.asyncio
    async def test_auth_api_key(self):
        cfg = AuthSessionConfig(mode=AuthMode.API_KEY, api_key_header="X-Custom-Key", api_key_value="key123")
        mgr = AuthSessionManager(cfg)
        client = AsyncMock()
        result = await mgr.authenticate(client)
        assert result is True
        assert mgr.auth_headers["X-Custom-Key"] == "key123"

    @pytest.mark.asyncio
    async def test_auth_cookie_mode(self):
        cfg = AuthSessionConfig(mode=AuthMode.COOKIE)
        mgr = AuthSessionManager(cfg)
        client = AsyncMock()
        result = await mgr.authenticate(client)
        assert result is True

    @pytest.mark.asyncio
    async def test_auth_none(self):
        cfg = AuthSessionConfig(mode=AuthMode.NONE)
        mgr = AuthSessionManager(cfg)
        client = AsyncMock()
        result = await mgr.authenticate(client)
        assert result is True

    @pytest.mark.asyncio
    async def test_auth_form_login_success(self):
        cfg = AuthSessionConfig(
            mode=AuthMode.FORM_LOGIN,
            login_url="http://example.com/login",
            login_username="user",
            login_password="pass",
            success_indicator="Welcome",
        )
        mgr = AuthSessionManager(cfg)

        mock_cookies = MagicMock()
        mock_cookies.items.return_value = [("session_id", "abc123")]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "Welcome to dashboard"
        mock_resp.cookies = mock_cookies

        client = AsyncMock()
        client.post = AsyncMock(return_value=mock_resp)

        result = await mgr.authenticate(client)
        assert result is True
        assert mgr.is_authenticated is True

    @pytest.mark.asyncio
    async def test_auth_form_login_failure_indicator(self):
        cfg = AuthSessionConfig(
            mode=AuthMode.FORM_LOGIN,
            login_url="http://example.com/login",
            login_username="user",
            login_password="wrong",
            failure_indicator="Invalid credentials",
        )
        mgr = AuthSessionManager(cfg)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "Invalid credentials. Please try again."
        mock_resp.cookies = {}

        client = AsyncMock()
        client.post = AsyncMock(return_value=mock_resp)

        result = await mgr.authenticate(client)
        assert result is False

    def test_apply_to_client_kwargs(self):
        cfg = AuthSessionConfig(mode=AuthMode.BEARER, bearer_token="tok")
        mgr = AuthSessionManager(cfg)
        mgr._auth_headers = {"Authorization": "Bearer tok"}
        mgr._session_cookies = {"sid": "abc"}
        h, c = mgr.apply_to_client_kwargs({"X-Custom": "val"}, {"existing": "cookie"})
        assert h["Authorization"] == "Bearer tok"
        assert h["X-Custom"] == "val"
        assert c["sid"] == "abc"
        assert c["existing"] == "cookie"

    @pytest.mark.asyncio
    async def test_handle_401_reauth(self):
        cfg = AuthSessionConfig(mode=AuthMode.BEARER, bearer_token="tok", reauth_on_401=True, max_reauth_attempts=2)
        mgr = AuthSessionManager(cfg)
        client = AsyncMock()
        result = await mgr.handle_401(client)
        assert result is True
        assert mgr._reauth_count == 1

    @pytest.mark.asyncio
    async def test_handle_401_max_reached(self):
        cfg = AuthSessionConfig(mode=AuthMode.BEARER, bearer_token="tok", reauth_on_401=True, max_reauth_attempts=1)
        mgr = AuthSessionManager(cfg)
        mgr._reauth_count = 1
        client = AsyncMock()
        result = await mgr.handle_401(client)
        assert result is False


# ── OpenAPI Parser Tests ──────────────────────────────────────────


class TestOpenAPIParser:
    def test_parse_basic_spec(self):
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/users": {
                    "get": {
                        "operationId": "listUsers",
                        "summary": "List users",
                        "parameters": [
                            {"name": "limit", "in": "query", "schema": {"type": "integer"}},
                        ],
                    },
                    "post": {
                        "operationId": "createUser",
                        "requestBody": {"content": {"application/json": {}}},
                    },
                },
                "/users/{id}": {
                    "get": {
                        "operationId": "getUser",
                        "parameters": [
                            {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}},
                        ],
                    },
                },
            },
        }
        endpoints = parse_openapi_spec(spec)
        assert len(endpoints) == 3
        methods = {e.method for e in endpoints}
        assert "GET" in methods
        assert "POST" in methods

    def test_parse_with_security(self):
        spec = {
            "openapi": "3.0.0",
            "security": [{"bearerAuth": []}],
            "paths": {
                "/protected": {
                    "get": {"operationId": "protectedGet"},
                },
            },
        }
        endpoints = parse_openapi_spec(spec)
        assert len(endpoints) == 1
        assert endpoints[0].security == [{"bearerAuth": []}]

    def test_parse_empty_paths(self):
        spec = {"openapi": "3.0.0", "paths": {}}
        endpoints = parse_openapi_spec(spec)
        assert endpoints == []

    def test_endpoint_to_dict(self):
        ep = OpenAPIEndpoint(path="/test", method="GET", operation_id="testOp")
        d = ep.to_dict()
        assert d["path"] == "/test"
        assert d["method"] == "GET"
        assert d["operation_id"] == "testOp"

    def test_generate_param_value(self):
        assert _generate_param_value("integer", "id") == 1
        assert _generate_param_value("number", "score") == 1.0
        assert _generate_param_value("boolean", "active") is True
        assert _generate_param_value("string", "name") == "test_name"


# ── DastCategory API Value ────────────────────────────────────────


class TestNewCategory:
    def test_api_category(self):
        assert DastCategory.API.value == "api_security"


# ── ScanResult New Fields ─────────────────────────────────────────


class TestScanResultNewFields:
    def test_auth_mode_field(self):
        result = DastScanResult(
            scan_id="test",
            target="http://test.com",
            urls_crawled=1,
            total_findings=0,
            findings=[],
            by_severity={},
            by_category={},
            crawled_urls=[],
            auth_mode="bearer",
            api_endpoints_tested=5,
        )
        d = result.to_dict()
        assert d["auth_mode"] == "bearer"
        assert d["api_endpoints_tested"] == 5

    def test_default_auth_mode(self):
        result = DastScanResult(
            scan_id="test",
            target="http://test.com",
            urls_crawled=0,
            total_findings=0,
            findings=[],
            by_severity={},
            by_category={},
            crawled_urls=[],
        )
        assert result.auth_mode == "none"
        assert result.api_endpoints_tested == 0
