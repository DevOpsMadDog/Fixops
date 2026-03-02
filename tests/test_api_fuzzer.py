"""Comprehensive unit tests for suite-core/core/api_fuzzer.py.

Covers:
  - FuzzSeverity and FuzzCategory enums
  - ApiEndpoint dataclass: construction, defaults, to_dict
  - FuzzFinding dataclass: construction, defaults, to_dict (truncation at 300 chars)
  - FuzzScanResult dataclass: construction, to_dict (endpoints capped at 100)
  - FUZZ_PAYLOADS: structure and content
  - ApiFuzzerEngine.__init__: timeout storage
  - ApiFuzzerEngine.discover_from_openapi: full spec, empty spec, unknown methods,
    parameters with missing fields, requestBody, auth/security flag
  - ApiFuzzerEngine._analyze_response: 5xx triggers ERROR_DISCLOSURE, stack trace
    keywords trigger STACK_TRACE finding, SQL keywords trigger INJECTION finding,
    benign 200 response yields no findings
  - ApiFuzzerEngine.fuzz_endpoints: full async path mocked, GET and non-GET methods,
    auth_bypass branch when auth_required=True + status < 400, endpoint cap at 50,
    parameter cap at 3, exception swallowing, by_severity / by_category aggregation
  - get_api_fuzzer_engine: singleton pattern
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

import os
import sys

# Ensure suite-core is on sys.path (sitecustomize.py handles this in normal run,
# but we add it explicitly for isolated pytest invocations)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from core.api_fuzzer import (
    ApiFuzzerEngine,
    ApiEndpoint,
    FuzzCategory,
    FuzzFinding,
    FuzzScanResult,
    FuzzSeverity,
    FUZZ_PAYLOADS,
    get_api_fuzzer_engine,
)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_response(status_code: int, text: str = "") -> httpx.Response:
    """Build a minimal httpx.Response stub without a real network call."""
    return httpx.Response(status_code=status_code, text=text)


def _make_endpoint(
    method: str = "GET",
    path: str = "/api/test",
    parameters: List[Dict[str, Any]] | None = None,
    auth_required: bool = False,
    source: str = "openapi",
) -> ApiEndpoint:
    return ApiEndpoint(
        method=method,
        path=path,
        parameters=parameters or [],
        auth_required=auth_required,
        source=source,
    )


# ── FuzzSeverity ──────────────────────────────────────────────────────────────


class TestFuzzSeverity:
    def test_all_values_exist(self):
        expected = {"critical", "high", "medium", "low", "info"}
        assert {s.value for s in FuzzSeverity} == expected

    def test_critical_value(self):
        assert FuzzSeverity.CRITICAL.value == "critical"

    def test_high_value(self):
        assert FuzzSeverity.HIGH.value == "high"

    def test_medium_value(self):
        assert FuzzSeverity.MEDIUM.value == "medium"

    def test_low_value(self):
        assert FuzzSeverity.LOW.value == "low"

    def test_info_value(self):
        assert FuzzSeverity.INFO.value == "info"

    def test_is_str_subclass(self):
        # FuzzSeverity inherits from str — useful for JSON serialisation
        assert isinstance(FuzzSeverity.HIGH, str)


# ── FuzzCategory ──────────────────────────────────────────────────────────────


class TestFuzzCategory:
    def test_all_values_exist(self):
        expected = {
            "auth_bypass",
            "injection",
            "broken_access",
            "data_exposure",
            "rate_limit",
            "schema_violation",
            "error_disclosure",
            "ssrf",
        }
        assert {c.value for c in FuzzCategory} == expected

    def test_auth_bypass_value(self):
        assert FuzzCategory.AUTH_BYPASS.value == "auth_bypass"

    def test_injection_value(self):
        assert FuzzCategory.INJECTION.value == "injection"

    def test_ssrf_value(self):
        assert FuzzCategory.SSRF.value == "ssrf"

    def test_is_str_subclass(self):
        assert isinstance(FuzzCategory.INJECTION, str)


# ── ApiEndpoint ────────────────────────────────────────────────────────────────


class TestApiEndpoint:
    def test_basic_construction(self):
        ep = ApiEndpoint(method="GET", path="/users")
        assert ep.method == "GET"
        assert ep.path == "/users"

    def test_defaults(self):
        ep = ApiEndpoint(method="POST", path="/items")
        assert ep.parameters == []
        assert ep.request_body is None
        assert ep.auth_required is False
        assert ep.description == ""
        assert ep.source == "openapi"

    def test_full_construction(self):
        params = [{"name": "id", "in": "path", "type": "integer", "required": True}]
        body = {"content": {"application/json": {}}}
        ep = ApiEndpoint(
            method="PUT",
            path="/items/{id}",
            parameters=params,
            request_body=body,
            auth_required=True,
            description="Update an item",
            source="traffic",
        )
        assert ep.method == "PUT"
        assert ep.auth_required is True
        assert ep.description == "Update an item"
        assert ep.source == "traffic"
        assert ep.request_body == body
        assert len(ep.parameters) == 1

    def test_to_dict_keys(self):
        ep = ApiEndpoint(method="DELETE", path="/resource/1")
        d = ep.to_dict()
        expected_keys = {"method", "path", "parameters", "auth_required", "description", "source"}
        assert expected_keys == set(d.keys())

    def test_to_dict_values(self):
        ep = ApiEndpoint(method="GET", path="/ping", auth_required=False, source="code")
        d = ep.to_dict()
        assert d["method"] == "GET"
        assert d["path"] == "/ping"
        assert d["auth_required"] is False
        assert d["source"] == "code"

    def test_to_dict_does_not_include_request_body(self):
        # request_body is intentionally excluded from to_dict
        ep = ApiEndpoint(method="POST", path="/data", request_body={"foo": "bar"})
        d = ep.to_dict()
        assert "request_body" not in d

    def test_parameters_default_is_independent(self):
        ep1 = ApiEndpoint(method="GET", path="/a")
        ep2 = ApiEndpoint(method="GET", path="/b")
        ep1.parameters.append({"name": "x"})
        assert ep2.parameters == []


# ── FuzzFinding ────────────────────────────────────────────────────────────────


class TestFuzzFinding:
    def _make_finding(self, **overrides) -> FuzzFinding:
        base = dict(
            finding_id="FUZZ-abc12345",
            title="Test Finding",
            severity=FuzzSeverity.MEDIUM,
            category=FuzzCategory.ERROR_DISCLOSURE,
            endpoint="/api/test",
            method="GET",
        )
        base.update(overrides)
        return FuzzFinding(**base)

    def test_basic_construction(self):
        f = self._make_finding()
        assert f.finding_id == "FUZZ-abc12345"
        assert f.title == "Test Finding"
        assert f.severity == FuzzSeverity.MEDIUM
        assert f.category == FuzzCategory.ERROR_DISCLOSURE

    def test_defaults(self):
        f = self._make_finding()
        assert f.parameter == ""
        assert f.payload == ""
        assert f.status_code == 0
        assert f.response_snippet == ""
        assert f.cwe_id == ""
        assert f.description == ""
        assert f.recommendation == ""
        assert f.confidence == 0.8
        assert isinstance(f.timestamp, datetime)

    def test_timestamp_is_utc(self):
        f = self._make_finding()
        assert f.timestamp.tzinfo is not None

    def test_to_dict_keys(self):
        f = self._make_finding()
        d = f.to_dict()
        expected = {
            "finding_id", "title", "severity", "category", "endpoint",
            "method", "parameter", "payload", "status_code",
            "response_snippet", "cwe_id", "description",
            "recommendation", "confidence", "timestamp",
        }
        assert expected == set(d.keys())

    def test_to_dict_severity_is_string(self):
        f = self._make_finding(severity=FuzzSeverity.CRITICAL)
        d = f.to_dict()
        assert d["severity"] == "critical"
        assert isinstance(d["severity"], str)

    def test_to_dict_category_is_string(self):
        f = self._make_finding(category=FuzzCategory.INJECTION)
        d = f.to_dict()
        assert d["category"] == "injection"

    def test_to_dict_response_snippet_truncated_at_300(self):
        long_text = "X" * 500
        f = self._make_finding(response_snippet=long_text)
        d = f.to_dict()
        assert len(d["response_snippet"]) == 300

    def test_to_dict_response_snippet_short_is_unchanged(self):
        short_text = "error"
        f = self._make_finding(response_snippet=short_text)
        d = f.to_dict()
        assert d["response_snippet"] == "error"

    def test_to_dict_timestamp_is_iso_string(self):
        f = self._make_finding()
        d = f.to_dict()
        # Should be parseable as an ISO 8601 datetime
        parsed = datetime.fromisoformat(d["timestamp"])
        assert parsed is not None

    def test_to_dict_confidence_value(self):
        f = self._make_finding(confidence=0.95)
        d = f.to_dict()
        assert d["confidence"] == 0.95


# ── FuzzScanResult ─────────────────────────────────────────────────────────────


class TestFuzzScanResult:
    def _make_finding(self) -> FuzzFinding:
        return FuzzFinding(
            finding_id="FUZZ-001",
            title="Test",
            severity=FuzzSeverity.LOW,
            category=FuzzCategory.SCHEMA_VIOLATION,
            endpoint="/api/v1/test",
            method="GET",
        )

    def test_basic_construction(self):
        result = FuzzScanResult(
            scan_id="fuzz-abc123",
            target_base_url="http://localhost:8000",
            endpoints_discovered=5,
            endpoints_fuzzed=3,
            total_findings=1,
            findings=[self._make_finding()],
            endpoints=[{"method": "GET", "path": "/api/v1/test"}],
            by_severity={"low": 1},
            by_category={"schema_violation": 1},
        )
        assert result.scan_id == "fuzz-abc123"
        assert result.endpoints_discovered == 5
        assert result.total_findings == 1

    def test_duration_ms_default(self):
        result = FuzzScanResult(
            scan_id="s1",
            target_base_url="http://localhost",
            endpoints_discovered=0,
            endpoints_fuzzed=0,
            total_findings=0,
            findings=[],
            endpoints=[],
            by_severity={},
            by_category={},
        )
        assert result.duration_ms == 0.0

    def test_to_dict_keys(self):
        result = FuzzScanResult(
            scan_id="s1",
            target_base_url="http://localhost",
            endpoints_discovered=0,
            endpoints_fuzzed=0,
            total_findings=0,
            findings=[],
            endpoints=[],
            by_severity={},
            by_category={},
        )
        d = result.to_dict()
        expected = {
            "scan_id", "target_base_url", "endpoints_discovered", "endpoints_fuzzed",
            "total_findings", "findings", "endpoints", "by_severity", "by_category",
            "duration_ms", "timestamp",
        }
        assert expected == set(d.keys())

    def test_to_dict_findings_are_serialised(self):
        result = FuzzScanResult(
            scan_id="s1",
            target_base_url="http://localhost",
            endpoints_discovered=1,
            endpoints_fuzzed=1,
            total_findings=1,
            findings=[self._make_finding()],
            endpoints=[],
            by_severity={"low": 1},
            by_category={"schema_violation": 1},
        )
        d = result.to_dict()
        assert len(d["findings"]) == 1
        # Each finding in the list should be a dict, not a FuzzFinding object
        assert isinstance(d["findings"][0], dict)
        assert d["findings"][0]["finding_id"] == "FUZZ-001"

    def test_to_dict_endpoints_capped_at_100(self):
        many_endpoints = [{"method": "GET", "path": f"/ep/{i}"} for i in range(150)]
        result = FuzzScanResult(
            scan_id="s1",
            target_base_url="http://localhost",
            endpoints_discovered=150,
            endpoints_fuzzed=50,
            total_findings=0,
            findings=[],
            endpoints=many_endpoints,
            by_severity={},
            by_category={},
        )
        d = result.to_dict()
        assert len(d["endpoints"]) == 100

    def test_to_dict_timestamp_is_iso(self):
        result = FuzzScanResult(
            scan_id="s1",
            target_base_url="http://localhost",
            endpoints_discovered=0,
            endpoints_fuzzed=0,
            total_findings=0,
            findings=[],
            endpoints=[],
            by_severity={},
            by_category={},
        )
        d = result.to_dict()
        assert isinstance(d["timestamp"], str)
        datetime.fromisoformat(d["timestamp"])  # must not raise


# ── FUZZ_PAYLOADS ─────────────────────────────────────────────────────────────


class TestFuzzPayloads:
    def test_required_type_keys_present(self):
        required = {"string", "integer", "boolean", "array", "auth_bypass"}
        assert required.issubset(set(FUZZ_PAYLOADS.keys()))

    def test_string_payloads_is_list(self):
        assert isinstance(FUZZ_PAYLOADS["string"], list)

    def test_string_payloads_includes_empty_string(self):
        assert "" in FUZZ_PAYLOADS["string"]

    def test_string_payloads_includes_xss(self):
        xss = "<script>alert(1)</script>"
        assert xss in FUZZ_PAYLOADS["string"]

    def test_string_payloads_includes_sqli(self):
        sqli = "' OR '1'='1"
        assert sqli in FUZZ_PAYLOADS["string"]

    def test_string_payloads_includes_path_traversal(self):
        traversal = "../../../etc/passwd"
        assert traversal in FUZZ_PAYLOADS["string"]

    def test_integer_payloads_includes_boundary_values(self):
        assert 0 in FUZZ_PAYLOADS["integer"]
        assert -1 in FUZZ_PAYLOADS["integer"]
        assert 2147483647 in FUZZ_PAYLOADS["integer"]
        assert -2147483648 in FUZZ_PAYLOADS["integer"]

    def test_boolean_payloads_non_empty(self):
        assert len(FUZZ_PAYLOADS["boolean"]) > 0

    def test_auth_bypass_payloads_are_dicts(self):
        for item in FUZZ_PAYLOADS["auth_bypass"]:
            assert isinstance(item, dict)

    def test_auth_bypass_includes_empty_authorization(self):
        assert any(
            d.get("Authorization") == "" for d in FUZZ_PAYLOADS["auth_bypass"]
        )

    def test_array_payloads_includes_prototype_pollution(self):
        proto_payload = [{"__proto__": {"admin": True}}]
        assert proto_payload in FUZZ_PAYLOADS["array"]


# ── ApiFuzzerEngine.__init__ ──────────────────────────────────────────────────


class TestApiFuzzerEngineInit:
    def test_default_timeout(self):
        engine = ApiFuzzerEngine()
        assert engine._timeout == 10.0

    def test_custom_timeout(self):
        engine = ApiFuzzerEngine(timeout=30.0)
        assert engine._timeout == 30.0

    def test_zero_timeout(self):
        engine = ApiFuzzerEngine(timeout=0.0)
        assert engine._timeout == 0.0


# ── ApiFuzzerEngine.discover_from_openapi ────────────────────────────────────


class TestDiscoverFromOpenapi:
    @pytest.fixture
    def engine(self):
        return ApiFuzzerEngine()

    def test_empty_spec_returns_empty_list(self, engine):
        result = engine.discover_from_openapi({})
        assert result == []

    def test_empty_paths_returns_empty_list(self, engine):
        result = engine.discover_from_openapi({"paths": {}})
        assert result == []

    def test_single_get_endpoint(self, engine):
        spec = {
            "paths": {
                "/health": {
                    "get": {"summary": "Health check", "parameters": []}
                }
            }
        }
        endpoints = engine.discover_from_openapi(spec)
        assert len(endpoints) == 1
        ep = endpoints[0]
        assert ep.method == "GET"
        assert ep.path == "/health"
        assert ep.description == "Health check"
        assert ep.source == "openapi"

    def test_multiple_methods_on_same_path(self, engine):
        spec = {
            "paths": {
                "/items": {
                    "get": {"summary": "List items"},
                    "post": {"summary": "Create item"},
                }
            }
        }
        endpoints = engine.discover_from_openapi(spec)
        methods = {ep.method for ep in endpoints}
        assert "GET" in methods
        assert "POST" in methods
        assert len(endpoints) == 2

    def test_all_valid_methods_parsed(self, engine):
        spec = {
            "paths": {
                "/resource": {
                    "get": {},
                    "post": {},
                    "put": {},
                    "patch": {},
                    "delete": {},
                }
            }
        }
        endpoints = engine.discover_from_openapi(spec)
        assert len(endpoints) == 5

    def test_invalid_methods_skipped(self, engine):
        spec = {
            "paths": {
                "/resource": {
                    "head": {"summary": "head method"},
                    "options": {"summary": "options method"},
                    "get": {"summary": "valid"},
                }
            }
        }
        endpoints = engine.discover_from_openapi(spec)
        assert len(endpoints) == 1
        assert endpoints[0].method == "GET"

    def test_parameter_extraction(self, engine):
        spec = {
            "paths": {
                "/users/{id}": {
                    "get": {
                        "parameters": [
                            {
                                "name": "id",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "integer"},
                            }
                        ]
                    }
                }
            }
        }
        endpoints = engine.discover_from_openapi(spec)
        assert len(endpoints) == 1
        params = endpoints[0].parameters
        assert len(params) == 1
        assert params[0]["name"] == "id"
        assert params[0]["in"] == "path"
        assert params[0]["type"] == "integer"
        assert params[0]["required"] is True

    def test_parameter_missing_schema_defaults_to_string(self, engine):
        spec = {
            "paths": {
                "/search": {
                    "get": {
                        "parameters": [{"name": "q", "in": "query"}]
                    }
                }
            }
        }
        endpoints = engine.discover_from_openapi(spec)
        assert endpoints[0].parameters[0]["type"] == "string"

    def test_parameter_missing_required_defaults_false(self, engine):
        spec = {
            "paths": {
                "/search": {
                    "get": {
                        "parameters": [{"name": "q", "in": "query"}]
                    }
                }
            }
        }
        endpoints = engine.discover_from_openapi(spec)
        assert endpoints[0].parameters[0]["required"] is False

    def test_request_body_captured(self, engine):
        body = {"content": {"application/json": {"schema": {"type": "object"}}}}
        spec = {
            "paths": {
                "/items": {
                    "post": {"requestBody": body}
                }
            }
        }
        endpoints = engine.discover_from_openapi(spec)
        assert endpoints[0].request_body == body

    def test_no_security_means_auth_not_required(self, engine):
        spec = {
            "paths": {
                "/public": {
                    "get": {}
                }
            }
        }
        endpoints = engine.discover_from_openapi(spec)
        assert endpoints[0].auth_required is False

    def test_security_field_sets_auth_required(self, engine):
        spec = {
            "paths": {
                "/private": {
                    "get": {
                        "security": [{"apiKey": []}]
                    }
                }
            }
        }
        endpoints = engine.discover_from_openapi(spec)
        assert endpoints[0].auth_required is True

    def test_multiple_paths(self, engine):
        spec = {
            "paths": {
                "/a": {"get": {}},
                "/b": {"post": {}},
                "/c": {"delete": {}},
            }
        }
        endpoints = engine.discover_from_openapi(spec)
        paths = {ep.path for ep in endpoints}
        assert paths == {"/a", "/b", "/c"}

    def test_no_summary_defaults_empty_description(self, engine):
        spec = {"paths": {"/test": {"get": {}}}}
        endpoints = engine.discover_from_openapi(spec)
        assert endpoints[0].description == ""


# ── ApiFuzzerEngine._analyze_response ────────────────────────────────────────


class TestAnalyzeResponse:
    @pytest.fixture
    def engine(self):
        return ApiFuzzerEngine()

    @pytest.fixture
    def endpoint(self):
        return _make_endpoint(method="GET", path="/api/v1/test")

    def test_benign_200_no_findings(self, engine, endpoint):
        resp = _make_response(200, "OK everything fine")
        findings = engine._analyze_response(resp, endpoint, "param", "value")
        assert findings == []

    def test_500_creates_error_disclosure_finding(self, engine, endpoint):
        resp = _make_response(500, "Internal Server Error")
        findings = engine._analyze_response(resp, endpoint, "id", "' OR '1'='1")
        assert len(findings) >= 1
        titles = [f.title for f in findings]
        assert "Server Error on Fuzz Input" in titles

    def test_500_finding_has_correct_severity(self, engine, endpoint):
        resp = _make_response(500, "")
        findings = engine._analyze_response(resp, endpoint, "x", "bad")
        server_err = next(f for f in findings if f.title == "Server Error on Fuzz Input")
        assert server_err.severity == FuzzSeverity.MEDIUM

    def test_500_finding_has_correct_category(self, engine, endpoint):
        resp = _make_response(500, "")
        findings = engine._analyze_response(resp, endpoint, "x", "bad")
        server_err = next(f for f in findings if f.title == "Server Error on Fuzz Input")
        assert server_err.category == FuzzCategory.ERROR_DISCLOSURE

    def test_500_finding_cwe_is_209(self, engine, endpoint):
        resp = _make_response(500, "")
        findings = engine._analyze_response(resp, endpoint, "x", "bad")
        server_err = next(f for f in findings if f.title == "Server Error on Fuzz Input")
        assert server_err.cwe_id == "CWE-209"

    def test_500_finding_captures_status_code(self, engine, endpoint):
        resp = _make_response(503, "Service Unavailable")
        findings = engine._analyze_response(resp, endpoint, "x", "bad")
        server_err = next(f for f in findings if f.title == "Server Error on Fuzz Input")
        assert server_err.status_code == 503

    def test_stack_trace_keyword_traceback(self, engine, endpoint):
        resp = _make_response(200, "Traceback (most recent call last): ...")
        findings = engine._analyze_response(resp, endpoint, "q", "test")
        titles = [f.title for f in findings]
        assert "Stack Trace Disclosure" in titles

    def test_stack_trace_keyword_stack_trace(self, engine, endpoint):
        resp = _make_response(200, "stack trace at com.example.Foo line 42")
        findings = engine._analyze_response(resp, endpoint, "q", "test")
        titles = [f.title for f in findings]
        assert "Stack Trace Disclosure" in titles

    def test_stack_trace_keyword_at_line(self, engine, endpoint):
        resp = _make_response(200, "Error at line 99 in module X")
        findings = engine._analyze_response(resp, endpoint, "q", "test")
        titles = [f.title for f in findings]
        assert "Stack Trace Disclosure" in titles

    def test_stack_trace_keyword_exception_in(self, engine, endpoint):
        resp = _make_response(200, "exception in thread main java.lang.NullPointerException")
        findings = engine._analyze_response(resp, endpoint, "q", "test")
        titles = [f.title for f in findings]
        assert "Stack Trace Disclosure" in titles

    def test_stack_trace_finding_severity(self, engine, endpoint):
        resp = _make_response(200, "Traceback (most recent call last):")
        findings = engine._analyze_response(resp, endpoint, "q", "test")
        st = next(f for f in findings if f.title == "Stack Trace Disclosure")
        assert st.severity == FuzzSeverity.MEDIUM

    def test_sql_error_keyword_sql_syntax(self, engine, endpoint):
        resp = _make_response(200, "You have an error in your SQL syntax near '...'")
        findings = engine._analyze_response(resp, endpoint, "id", "' OR 1=1")
        titles = [f.title for f in findings]
        assert "SQL Injection via API" in titles

    def test_sql_error_keyword_sqlstate(self, engine, endpoint):
        resp = _make_response(200, "SQLSTATE[42000]: Syntax error")
        findings = engine._analyze_response(resp, endpoint, "id", "test")
        titles = [f.title for f in findings]
        assert "SQL Injection via API" in titles

    def test_sql_error_keyword_pg_query(self, engine, endpoint):
        resp = _make_response(200, "pg_query(): Query failed: ERROR:  syntax error")
        findings = engine._analyze_response(resp, endpoint, "id", "test")
        titles = [f.title for f in findings]
        assert "SQL Injection via API" in titles

    def test_sql_error_keyword_ora(self, engine, endpoint):
        resp = _make_response(200, "ORA-00907: missing right parenthesis")
        findings = engine._analyze_response(resp, endpoint, "id", "test")
        titles = [f.title for f in findings]
        assert "SQL Injection via API" in titles

    def test_sql_finding_severity_is_critical(self, engine, endpoint):
        resp = _make_response(200, "sql syntax error in query")
        findings = engine._analyze_response(resp, endpoint, "id", "' OR 1=1")
        sql = next(f for f in findings if f.title == "SQL Injection via API")
        assert sql.severity == FuzzSeverity.CRITICAL

    def test_sql_finding_category_is_injection(self, engine, endpoint):
        resp = _make_response(200, "sql syntax error in query")
        findings = engine._analyze_response(resp, endpoint, "id", "payload")
        sql = next(f for f in findings if f.title == "SQL Injection via API")
        assert sql.category == FuzzCategory.INJECTION

    def test_sql_finding_cwe_is_89(self, engine, endpoint):
        resp = _make_response(200, "sql syntax error")
        findings = engine._analyze_response(resp, endpoint, "id", "payload")
        sql = next(f for f in findings if f.title == "SQL Injection via API")
        assert sql.cwe_id == "CWE-89"

    def test_multiple_findings_on_same_response(self, engine, endpoint):
        # 500 + stack trace → at least 2 findings
        resp = _make_response(500, "Traceback (most recent call last): Internal error")
        findings = engine._analyze_response(resp, endpoint, "x", "bad")
        assert len(findings) >= 2

    def test_finding_captures_endpoint_path(self, engine):
        ep = _make_endpoint(path="/api/v1/widgets", method="POST")
        resp = _make_response(500, "crash")
        findings = engine._analyze_response(resp, ep, "data", "evil")
        assert findings[0].endpoint == "/api/v1/widgets"

    def test_finding_captures_method(self, engine):
        ep = _make_endpoint(path="/api/v1/widgets", method="POST")
        resp = _make_response(500, "crash")
        findings = engine._analyze_response(resp, ep, "data", "evil")
        assert findings[0].method == "POST"

    def test_finding_captures_parameter(self, engine, endpoint):
        resp = _make_response(500, "error")
        findings = engine._analyze_response(resp, endpoint, "email", "fuzz")
        assert findings[0].parameter == "email"

    def test_finding_captures_payload(self, engine, endpoint):
        resp = _make_response(500, "error")
        findings = engine._analyze_response(resp, endpoint, "x", "SQL_PAYLOAD")
        assert findings[0].payload == "SQL_PAYLOAD"

    def test_finding_id_format(self, engine, endpoint):
        resp = _make_response(500, "error")
        findings = engine._analyze_response(resp, endpoint, "x", "bad")
        assert findings[0].finding_id.startswith("FUZZ-")

    def test_response_text_analysis_is_case_insensitive(self, engine, endpoint):
        # Keywords are lowercased before matching → uppercase input still detected
        resp = _make_response(200, "TRACEBACK (MOST RECENT CALL LAST):")
        findings = engine._analyze_response(resp, endpoint, "q", "test")
        titles = [f.title for f in findings]
        assert "Stack Trace Disclosure" in titles

    def test_404_with_clean_body_no_findings(self, engine, endpoint):
        resp = _make_response(404, "Not found")
        findings = engine._analyze_response(resp, endpoint, "id", "99999")
        assert findings == []


# ── ApiFuzzerEngine.fuzz_endpoints (async) ───────────────────────────────────


class TestFuzzEndpoints:
    """Tests for the async fuzz_endpoints method using httpx mocking.

    These are async def tests — pytest-asyncio auto mode (configured in pyproject.toml)
    handles the event loop setup automatically.
    """

    def _make_engine(self) -> ApiFuzzerEngine:
        return ApiFuzzerEngine(timeout=5.0)

    async def test_empty_endpoints_returns_scan_result(self):
        engine = self._make_engine()
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            result = await engine.fuzz_endpoints("http://localhost:8000", [])
        assert isinstance(result, FuzzScanResult)
        assert result.endpoints_discovered == 0
        assert result.endpoints_fuzzed == 0
        assert result.total_findings == 0

    async def test_scan_id_format(self):
        engine = self._make_engine()
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            result = await engine.fuzz_endpoints("http://localhost:8000", [])
        assert result.scan_id.startswith("fuzz-")

    async def test_target_base_url_preserved(self):
        engine = self._make_engine()
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            result = await engine.fuzz_endpoints("http://my-api.com", [])
        assert result.target_base_url == "http://my-api.com"

    async def test_endpoints_discovered_count(self):
        engine = self._make_engine()
        endpoints = [_make_endpoint() for _ in range(3)]
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=_make_response(200, "ok"))
            mock_client.request = AsyncMock(return_value=_make_response(200, "ok"))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            result = await engine.fuzz_endpoints("http://localhost", endpoints)
        assert result.endpoints_discovered == 3

    async def test_get_method_uses_client_get(self):
        engine = self._make_engine()
        ep = _make_endpoint(
            method="GET",
            path="/api/v1/search",
            parameters=[{"name": "q", "in": "query", "type": "string", "required": False}],
        )
        mock_get = AsyncMock(return_value=_make_response(200, "ok"))
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get = mock_get
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            await engine.fuzz_endpoints("http://localhost", [ep], max_per_endpoint=1)
        assert mock_get.called

    async def test_post_method_uses_client_request(self):
        engine = self._make_engine()
        ep = _make_endpoint(
            method="POST",
            path="/api/v1/items",
            parameters=[{"name": "data", "in": "body", "type": "string", "required": True}],
        )
        mock_request = AsyncMock(return_value=_make_response(200, "ok"))
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.request = mock_request
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            await engine.fuzz_endpoints("http://localhost", [ep], max_per_endpoint=1)
        assert mock_request.called

    async def test_500_response_produces_findings(self):
        engine = self._make_engine()
        ep = _make_endpoint(
            method="GET",
            path="/api/crash",
            parameters=[{"name": "id", "in": "query", "type": "integer", "required": False}],
        )
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=_make_response(500, "Internal Server Error"))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            result = await engine.fuzz_endpoints("http://localhost", [ep], max_per_endpoint=1)
        assert result.total_findings >= 1
        assert result.total_findings == len(result.findings)

    async def test_by_severity_aggregation(self):
        engine = self._make_engine()
        ep = _make_endpoint(
            method="GET",
            path="/api/crash",
            parameters=[{"name": "id", "in": "query", "type": "integer", "required": False}],
        )
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=_make_response(500, "Internal error"))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            result = await engine.fuzz_endpoints("http://localhost", [ep], max_per_endpoint=1)
        assert isinstance(result.by_severity, dict)
        total = sum(result.by_severity.values())
        assert total == result.total_findings

    async def test_by_category_aggregation(self):
        engine = self._make_engine()
        ep = _make_endpoint(
            method="GET",
            path="/api/crash",
            parameters=[{"name": "id", "in": "query", "type": "integer", "required": False}],
        )
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=_make_response(500, "Internal error"))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            result = await engine.fuzz_endpoints("http://localhost", [ep], max_per_endpoint=1)
        assert isinstance(result.by_category, dict)
        total = sum(result.by_category.values())
        assert total == result.total_findings

    async def test_network_exception_is_swallowed(self):
        engine = self._make_engine()
        ep = _make_endpoint(
            method="GET",
            path="/api/test",
            parameters=[{"name": "q", "in": "query", "type": "string", "required": False}],
        )
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            # Should not raise despite the network exception
            result = await engine.fuzz_endpoints("http://localhost", [ep], max_per_endpoint=1)
        assert isinstance(result, FuzzScanResult)
        assert result.total_findings == 0

    async def test_auth_bypass_finding_when_protected_endpoint_returns_200(self):
        engine = self._make_engine()
        ep = _make_endpoint(method="GET", path="/api/admin", auth_required=True)
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            # No parameters → no param-level fuzzing, but auth_bypass branch runs
            mock_client.get = AsyncMock(return_value=_make_response(200, "Admin dashboard"))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            result = await engine.fuzz_endpoints("http://localhost", [ep])
        auth_findings = [f for f in result.findings if f.category == FuzzCategory.AUTH_BYPASS]
        assert len(auth_findings) >= 1
        assert auth_findings[0].severity == FuzzSeverity.CRITICAL
        assert auth_findings[0].cwe_id == "CWE-287"

    async def test_auth_bypass_skipped_when_endpoint_returns_401(self):
        engine = self._make_engine()
        ep = _make_endpoint(method="GET", path="/api/admin", auth_required=True)
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=_make_response(401, "Unauthorized"))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            result = await engine.fuzz_endpoints("http://localhost", [ep])
        auth_findings = [f for f in result.findings if f.category == FuzzCategory.AUTH_BYPASS]
        assert len(auth_findings) == 0

    async def test_endpoints_capped_at_50(self):
        """fuzz_endpoints only processes the first 50 endpoints."""
        engine = self._make_engine()
        endpoints = [_make_endpoint(path=f"/ep/{i}") for i in range(70)]
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=_make_response(200, "ok"))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            result = await engine.fuzz_endpoints("http://localhost", endpoints)
        assert result.endpoints_fuzzed == 50  # capped at 50, not 70

    async def test_duration_ms_is_non_negative(self):
        engine = self._make_engine()
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            result = await engine.fuzz_endpoints("http://localhost", [])
        assert result.duration_ms >= 0.0

    async def test_headers_passed_to_client(self):
        """The headers dict is forwarded to the httpx.AsyncClient constructor."""
        engine = self._make_engine()
        captured_kwargs: Dict[str, Any] = {}

        # Patch at the module level where api_fuzzer imports httpx
        with patch("core.api_fuzzer.httpx.AsyncClient") as mock_cls:
            mock_context = MagicMock()
            mock_client = AsyncMock()
            mock_context.__aenter__ = AsyncMock(return_value=mock_client)
            mock_context.__aexit__ = AsyncMock(return_value=None)

            def record_and_return(*args, **kwargs):
                captured_kwargs.update(kwargs)
                return mock_context

            mock_cls.side_effect = record_and_return

            await engine.fuzz_endpoints(
                "http://localhost", [], headers={"X-API-Key": "secret"}
            )
        assert captured_kwargs.get("headers") == {"X-API-Key": "secret"}

    async def test_base_url_trailing_slash_stripped(self):
        """Verify that a trailing slash on base_url does not produce double slashes."""
        engine = self._make_engine()
        ep = _make_endpoint(
            method="GET",
            path="/api/v1/test",
            parameters=[{"name": "q", "in": "query", "type": "string", "required": False}],
        )
        called_urls: List[str] = []

        async def fake_get(url, **kwargs):
            called_urls.append(url)
            return _make_response(200, "ok")

        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get = fake_get
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            await engine.fuzz_endpoints("http://localhost:8000/", [ep], max_per_endpoint=1)

        assert len(called_urls) > 0
        for url in called_urls:
            # Strip scheme before checking for double-slash
            assert "//" not in url.replace("http://", "").replace("https://", "")

    async def test_parameter_type_fallback_to_string_payloads(self):
        """Unknown parameter type falls back to string payloads (no KeyError)."""
        engine = self._make_engine()
        ep = _make_endpoint(
            method="GET",
            path="/api/v1/search",
            parameters=[{"name": "q", "in": "query", "type": "unknown_custom_type", "required": False}],
        )
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=_make_response(200, "ok"))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            result = await engine.fuzz_endpoints("http://localhost", [ep], max_per_endpoint=2)
        assert isinstance(result, FuzzScanResult)

    async def test_auth_bypass_exception_is_swallowed(self):
        """Exceptions during auth_bypass loop are silently caught."""
        engine = self._make_engine()
        ep = _make_endpoint(method="GET", path="/api/admin", auth_required=True)
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            result = await engine.fuzz_endpoints("http://localhost", [ep])
        assert isinstance(result, FuzzScanResult)


# ── get_api_fuzzer_engine ─────────────────────────────────────────────────────


class TestGetApiFuzzerEngine:
    def test_returns_engine_instance(self):
        # Reset global state for isolation
        import core.api_fuzzer as mod
        mod._engine = None
        engine = get_api_fuzzer_engine()
        assert isinstance(engine, ApiFuzzerEngine)

    def test_singleton_returns_same_instance(self):
        import core.api_fuzzer as mod
        mod._engine = None
        e1 = get_api_fuzzer_engine()
        e2 = get_api_fuzzer_engine()
        assert e1 is e2

    def test_singleton_not_recreated_if_already_set(self):
        import core.api_fuzzer as mod
        existing = ApiFuzzerEngine(timeout=99.9)
        mod._engine = existing
        result = get_api_fuzzer_engine()
        assert result is existing
        assert result._timeout == 99.9

    def teardown_method(self, method):
        # Clean up singleton after each test in this class
        import core.api_fuzzer as mod
        mod._engine = None
