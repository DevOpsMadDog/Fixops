"""Tests for DASTEngine — 26 tests covering public methods, models, and helpers."""

from __future__ import annotations

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
    _generate_param_value,
    get_dast_engine,
    parse_openapi_spec,
)
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# DASTEngine construction
# ---------------------------------------------------------------------------

def test_engine_default_construction():
    engine = DASTEngine()
    assert engine._timeout == 10.0
    assert engine._max_crawl == 50


def test_engine_custom_construction():
    engine = DASTEngine(timeout=5.0, max_crawl=20)
    assert engine._timeout == 5.0
    assert engine._max_crawl == 20


def test_get_dast_engine_singleton():
    e1 = get_dast_engine()
    e2 = get_dast_engine()
    assert e1 is e2


# ---------------------------------------------------------------------------
# validate_target_url
# ---------------------------------------------------------------------------

def test_validate_target_url_valid():
    engine = DASTEngine()
    # A valid public URL passes through unchanged
    url = engine.validate_target_url("https://example.com/api")
    assert url == "https://example.com/api"


def test_validate_target_url_http_valid():
    engine = DASTEngine()
    url = engine.validate_target_url("http://example.com")
    assert url == "http://example.com"


def test_validate_target_url_invalid_scheme():
    engine = DASTEngine()
    with pytest.raises(ValueError, match="scheme"):
        engine.validate_target_url("ftp://example.com")


def test_validate_target_url_file_scheme():
    engine = DASTEngine()
    with pytest.raises(ValueError, match="scheme"):
        engine.validate_target_url("file:///etc/passwd")


def test_validate_target_url_localhost_blocked():
    engine = DASTEngine()
    with pytest.raises(ValueError, match="loopback"):
        engine.validate_target_url("http://localhost/admin")


def test_validate_target_url_too_long():
    engine = DASTEngine()
    long_url = "http://example.com/" + "a" * 2100
    with pytest.raises(ValueError, match="length"):
        engine.validate_target_url(long_url)


def test_validate_target_url_missing_hostname():
    engine = DASTEngine()
    with pytest.raises(ValueError):
        engine.validate_target_url("http:///no-host")


# ---------------------------------------------------------------------------
# DastFinding model
# ---------------------------------------------------------------------------

def test_dast_finding_to_dict():
    f = DastFinding(
        finding_id="DAST-abc123",
        title="SQL Injection",
        severity=DastSeverity.HIGH,
        category=DastCategory.INJECTION,
        url="https://example.com/api",
        method="GET",
        parameter="id",
        payload="' OR 1=1",
        evidence="Error: syntax near",
        cwe_id="CWE-89",
        description="SQL injection found",
        recommendation="Use parameterized queries",
        confidence=0.95,
    )
    d = f.to_dict()
    assert d["finding_id"] == "DAST-abc123"
    assert d["severity"] == "high"
    assert d["category"] == "injection"
    assert d["cwe_id"] == "CWE-89"
    assert d["confidence"] == 0.95
    assert "timestamp" in d


def test_dast_finding_evidence_truncated():
    long_evidence = "x" * 1000
    f = DastFinding(
        finding_id="DAST-xyz",
        title="XSS",
        severity=DastSeverity.MEDIUM,
        category=DastCategory.XSS,
        url="https://example.com",
        evidence=long_evidence,
    )
    d = f.to_dict()
    assert len(d["evidence"]) <= 500


# ---------------------------------------------------------------------------
# DastScanResult model
# ---------------------------------------------------------------------------

def test_dast_scan_result_to_dict():
    result = DastScanResult(
        scan_id="dast-scan-001",
        target="https://example.com",
        urls_crawled=5,
        total_findings=2,
        findings=[],
        by_severity={"high": 1, "medium": 1},
        by_category={"injection": 1, "xss": 1},
        crawled_urls=["https://example.com/", "https://example.com/api"],
        duration_ms=1234.5,
        authenticated=False,
        auth_mode="none",
    )
    d = result.to_dict()
    assert d["scan_id"] == "dast-scan-001"
    assert d["target"] == "https://example.com"
    assert d["urls_crawled"] == 5
    assert d["total_findings"] == 2
    assert d["duration_ms"] == 1234.5
    assert d["authenticated"] is False
    assert "timestamp" in d


def test_dast_scan_result_crawled_urls_capped():
    urls = [f"https://example.com/page{i}" for i in range(100)]
    result = DastScanResult(
        scan_id="dast-cap",
        target="https://example.com",
        urls_crawled=100,
        total_findings=0,
        findings=[],
        by_severity={},
        by_category={},
        crawled_urls=urls,
    )
    d = result.to_dict()
    assert len(d["crawled_urls"]) <= 50


# ---------------------------------------------------------------------------
# AuthSessionConfig
# ---------------------------------------------------------------------------

def test_auth_session_config_to_dict_none():
    cfg = AuthSessionConfig(mode=AuthMode.NONE)
    d = cfg.to_dict()
    assert d["mode"] == "none"
    assert d["has_credentials"] is False


def test_auth_session_config_to_dict_bearer():
    cfg = AuthSessionConfig(mode=AuthMode.BEARER, bearer_token="tok123")
    d = cfg.to_dict()
    assert d["mode"] == "bearer"
    assert d["has_credentials"] is True


def test_auth_session_config_to_dict_api_key():
    cfg = AuthSessionConfig(
        mode=AuthMode.API_KEY,
        api_key_header="X-Custom-Key",
        api_key_value="secret",
    )
    d = cfg.to_dict()
    assert d["mode"] == "api_key"
    assert d["api_key_header"] == "X-Custom-Key"


# ---------------------------------------------------------------------------
# AuthSessionManager — synchronous auth paths
# ---------------------------------------------------------------------------

def test_auth_manager_none_mode():
    import asyncio
    cfg = AuthSessionConfig(mode=AuthMode.NONE)
    mgr = AuthSessionManager(cfg)
    result = asyncio.run(mgr.authenticate(None))
    assert result is True
    assert mgr.is_authenticated is True


def test_auth_manager_bearer_success():
    import asyncio
    cfg = AuthSessionConfig(mode=AuthMode.BEARER, bearer_token="mytoken")
    mgr = AuthSessionManager(cfg)
    result = asyncio.run(mgr.authenticate(None))
    assert result is True
    assert "Authorization" in mgr.auth_headers
    assert mgr.auth_headers["Authorization"] == "Bearer mytoken"


def test_auth_manager_bearer_no_token_fails():
    import asyncio
    cfg = AuthSessionConfig(mode=AuthMode.BEARER, bearer_token="")
    mgr = AuthSessionManager(cfg)
    result = asyncio.run(mgr.authenticate(None))
    assert result is False


def test_auth_manager_basic_success():
    import asyncio
    cfg = AuthSessionConfig(mode=AuthMode.BASIC, basic_username="admin", basic_password="pass")
    mgr = AuthSessionManager(cfg)
    result = asyncio.run(mgr.authenticate(None))
    assert result is True
    assert "Authorization" in mgr.auth_headers
    assert mgr.auth_headers["Authorization"].startswith("Basic ")


def test_auth_manager_basic_no_username_fails():
    import asyncio
    cfg = AuthSessionConfig(mode=AuthMode.BASIC, basic_username="")
    mgr = AuthSessionManager(cfg)
    result = asyncio.run(mgr.authenticate(None))
    assert result is False


def test_auth_manager_api_key_success():
    import asyncio
    cfg = AuthSessionConfig(
        mode=AuthMode.API_KEY,
        api_key_header="X-Api-Key",
        api_key_value="my-api-key-123",
    )
    mgr = AuthSessionManager(cfg)
    result = asyncio.run(mgr.authenticate(None))
    assert result is True
    assert mgr.auth_headers.get("X-Api-Key") == "my-api-key-123"


def test_auth_manager_api_key_no_value_fails():
    import asyncio
    cfg = AuthSessionConfig(mode=AuthMode.API_KEY, api_key_value="")
    mgr = AuthSessionManager(cfg)
    result = asyncio.run(mgr.authenticate(None))
    assert result is False


def test_auth_manager_cookie_mode():
    import asyncio
    cfg = AuthSessionConfig(mode=AuthMode.COOKIE)
    mgr = AuthSessionManager(cfg)
    result = asyncio.run(mgr.authenticate(None))
    assert result is True
    assert mgr.is_authenticated is True


def test_auth_manager_apply_to_client_kwargs():
    cfg = AuthSessionConfig(mode=AuthMode.BEARER, bearer_token="tok")
    import asyncio
    mgr = AuthSessionManager(cfg)
    asyncio.run(mgr.authenticate(None))
    headers, cookies = mgr.apply_to_client_kwargs(
        headers={"X-Custom": "val"}, cookies={"session": "abc"}
    )
    assert headers["Authorization"] == "Bearer tok"
    assert headers["X-Custom"] == "val"
    assert cookies["session"] == "abc"


# ---------------------------------------------------------------------------
# parse_openapi_spec
# ---------------------------------------------------------------------------

def test_parse_openapi_spec_basic():
    spec = {
        "paths": {
            "/users": {
                "get": {
                    "operationId": "listUsers",
                    "summary": "List all users",
                    "parameters": [
                        {"name": "page", "in": "query", "schema": {"type": "integer"}},
                    ],
                },
                "post": {
                    "operationId": "createUser",
                    "requestBody": {"content": {}},
                },
            },
            "/users/{id}": {
                "delete": {
                    "parameters": [
                        {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}},
                    ],
                },
            },
        }
    }
    endpoints = parse_openapi_spec(spec)
    assert len(endpoints) == 3
    methods = {e.method for e in endpoints}
    assert "GET" in methods
    assert "POST" in methods
    assert "DELETE" in methods


def test_parse_openapi_spec_empty_paths():
    endpoints = parse_openapi_spec({"paths": {}})
    assert endpoints == []


def test_parse_openapi_spec_no_paths_key():
    endpoints = parse_openapi_spec({})
    assert endpoints == []


def test_openapi_endpoint_to_dict():
    ep = OpenAPIEndpoint(
        path="/api/test",
        method="POST",
        parameters=[{"name": "q", "in": "query"}],
        request_body={"content": {}},
        operation_id="testOp",
        description="A test op",
    )
    d = ep.to_dict()
    assert d["path"] == "/api/test"
    assert d["method"] == "POST"
    assert d["has_request_body"] is True
    assert d["operation_id"] == "testOp"


# ---------------------------------------------------------------------------
# _generate_param_value
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("param_type,expected", [
    ("integer", 1),
    ("number", 1.0),
    ("boolean", True),
    ("array", []),
    ("string", "test_myfield"),
])
def test_generate_param_value(param_type, expected):
    result = _generate_param_value(param_type, "myfield")
    assert result == expected
