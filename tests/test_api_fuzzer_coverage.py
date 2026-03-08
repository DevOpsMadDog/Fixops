"""Tests for core.api_fuzzer — API discovery, fuzzing, and finding models."""

import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.api_fuzzer import (  # noqa: E402
    ApiEndpoint,
    ApiFuzzerEngine,
    FUZZ_PAYLOADS,
    FuzzCategory,
    FuzzFinding,
    FuzzScanResult,
    FuzzSeverity,
)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TestFuzzSeverity:
    def test_all_values(self):
        assert FuzzSeverity.CRITICAL.value == "critical"
        assert FuzzSeverity.HIGH.value == "high"
        assert FuzzSeverity.MEDIUM.value == "medium"
        assert FuzzSeverity.LOW.value == "low"
        assert FuzzSeverity.INFO.value == "info"

    def test_count(self):
        assert len(FuzzSeverity) == 5


class TestFuzzCategory:
    def test_all_values(self):
        assert FuzzCategory.AUTH_BYPASS.value == "auth_bypass"
        assert FuzzCategory.INJECTION.value == "injection"
        assert FuzzCategory.BROKEN_ACCESS.value == "broken_access"
        assert FuzzCategory.DATA_EXPOSURE.value == "data_exposure"
        assert FuzzCategory.RATE_LIMIT.value == "rate_limit"
        assert FuzzCategory.SCHEMA_VIOLATION.value == "schema_violation"
        assert FuzzCategory.ERROR_DISCLOSURE.value == "error_disclosure"
        assert FuzzCategory.SSRF.value == "ssrf"

    def test_count(self):
        assert len(FuzzCategory) == 8


# ---------------------------------------------------------------------------
# ApiEndpoint
# ---------------------------------------------------------------------------


class TestApiEndpoint:
    def test_defaults(self):
        ep = ApiEndpoint(method="GET", path="/api/v1/users")
        assert ep.method == "GET"
        assert ep.path == "/api/v1/users"
        assert ep.parameters == []
        assert ep.request_body is None
        assert ep.auth_required is False
        assert ep.source == "openapi"

    def test_to_dict(self):
        ep = ApiEndpoint(
            method="POST",
            path="/api/v1/scan",
            parameters=[{"name": "target", "in": "query"}],
            auth_required=True,
            description="Start a scan",
            source="code",
        )
        d = ep.to_dict()
        assert d["method"] == "POST"
        assert d["path"] == "/api/v1/scan"
        assert len(d["parameters"]) == 1
        assert d["auth_required"] is True
        assert d["source"] == "code"


# ---------------------------------------------------------------------------
# FuzzFinding
# ---------------------------------------------------------------------------


class TestFuzzFinding:
    def test_create(self):
        f = FuzzFinding(
            finding_id="FF-001",
            title="SQL Injection in user_id",
            severity=FuzzSeverity.CRITICAL,
            category=FuzzCategory.INJECTION,
            endpoint="/api/v1/users/{id}",
            method="GET",
            parameter="id",
            payload="' OR 1=1 --",
            status_code=500,
            cwe_id="CWE-89",
        )
        assert f.finding_id == "FF-001"
        assert f.severity == FuzzSeverity.CRITICAL

    def test_to_dict(self):
        f = FuzzFinding(
            finding_id="FF-002",
            title="XSS in name param",
            severity=FuzzSeverity.HIGH,
            category=FuzzCategory.INJECTION,
            endpoint="/api/v1/users",
            method="POST",
            payload="<script>",
            status_code=200,
            response_snippet="x" * 400,  # Long snippet
        )
        d = f.to_dict()
        assert d["severity"] == "high"
        assert d["category"] == "injection"
        assert len(d["response_snippet"]) <= 300  # Truncated
        assert "timestamp" in d

    def test_defaults(self):
        f = FuzzFinding(
            finding_id="FF-003",
            title="Test",
            severity=FuzzSeverity.INFO,
            category=FuzzCategory.SCHEMA_VIOLATION,
            endpoint="/test",
            method="GET",
        )
        assert f.parameter == ""
        assert f.payload == ""
        assert f.status_code == 0
        assert f.confidence == 0.8


# ---------------------------------------------------------------------------
# FuzzScanResult
# ---------------------------------------------------------------------------


class TestFuzzScanResult:
    def test_create(self):
        finding = FuzzFinding(
            finding_id="FF-001",
            title="Test Finding",
            severity=FuzzSeverity.MEDIUM,
            category=FuzzCategory.ERROR_DISCLOSURE,
            endpoint="/api/test",
            method="GET",
        )
        result = FuzzScanResult(
            scan_id="SCAN-001",
            target_base_url="http://localhost:8000",
            endpoints_discovered=10,
            endpoints_fuzzed=8,
            total_findings=1,
            findings=[finding],
            endpoints=[{"method": "GET", "path": "/api/test"}],
            by_severity={"medium": 1},
            by_category={"error_disclosure": 1},
            duration_ms=1234.5,
        )
        assert result.scan_id == "SCAN-001"
        assert result.total_findings == 1

    def test_to_dict(self):
        result = FuzzScanResult(
            scan_id="SCAN-002",
            target_base_url="http://localhost:8000",
            endpoints_discovered=5,
            endpoints_fuzzed=3,
            total_findings=0,
            findings=[],
            endpoints=[],
            by_severity={},
            by_category={},
        )
        d = result.to_dict()
        assert d["scan_id"] == "SCAN-002"
        assert d["total_findings"] == 0
        assert d["findings"] == []
        assert "timestamp" in d

    def test_to_dict_truncates_endpoints(self):
        endpoints = [{"method": "GET", "path": f"/api/v{i}"} for i in range(200)]
        result = FuzzScanResult(
            scan_id="SCAN-003",
            target_base_url="http://localhost",
            endpoints_discovered=200,
            endpoints_fuzzed=0,
            total_findings=0,
            findings=[],
            endpoints=endpoints,
            by_severity={},
            by_category={},
        )
        d = result.to_dict()
        assert len(d["endpoints"]) <= 100


# ---------------------------------------------------------------------------
# FUZZ_PAYLOADS
# ---------------------------------------------------------------------------


class TestFuzzPayloads:
    def test_payload_categories(self):
        assert "string" in FUZZ_PAYLOADS
        assert "integer" in FUZZ_PAYLOADS
        assert "boolean" in FUZZ_PAYLOADS
        assert "array" in FUZZ_PAYLOADS
        assert "auth_bypass" in FUZZ_PAYLOADS

    def test_string_payloads_contain_injection(self):
        string_payloads = FUZZ_PAYLOADS["string"]
        assert any("script" in str(p) for p in string_payloads)
        assert any("OR" in str(p) for p in string_payloads)

    def test_payloads_are_nonempty(self):
        for category, payloads in FUZZ_PAYLOADS.items():
            assert len(payloads) > 0, f"Payload category {category} is empty"


# ---------------------------------------------------------------------------
# ApiFuzzerEngine — discover from OpenAPI
# ---------------------------------------------------------------------------


class TestApiFuzzerEngine:
    def test_init(self):
        engine = ApiFuzzerEngine(timeout=5.0)
        assert engine._timeout == 5.0

    def test_discover_from_openapi_basic(self):
        engine = ApiFuzzerEngine()
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/api/v1/users": {
                    "get": {
                        "summary": "List users",
                        "parameters": [
                            {"name": "limit", "in": "query", "schema": {"type": "integer"}},
                        ],
                    },
                    "post": {
                        "summary": "Create user",
                        "requestBody": {"content": {"application/json": {}}},
                    },
                },
                "/api/v1/users/{id}": {
                    "get": {"summary": "Get user"},
                    "delete": {"summary": "Delete user"},
                },
            },
        }
        endpoints = engine.discover_from_openapi(spec)
        assert len(endpoints) == 4
        methods = {(ep.method.upper(), ep.path) for ep in endpoints}
        assert ("GET", "/api/v1/users") in methods
        assert ("POST", "/api/v1/users") in methods

    def test_discover_from_openapi_empty(self):
        engine = ApiFuzzerEngine()
        endpoints = engine.discover_from_openapi({})
        assert endpoints == []

    def test_discover_from_openapi_no_paths(self):
        engine = ApiFuzzerEngine()
        endpoints = engine.discover_from_openapi({"paths": {}})
        assert endpoints == []
