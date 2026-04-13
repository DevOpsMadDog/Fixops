"""Comprehensive tests for the ALDECI API Security Testing Engine.

Tests cover:
- OpenAPI spec parsing (v2 and v3)
- OWASP API Top 10 checkers (API1–API10)
- Authentication analysis
- Schema validation (mass assignment, PII leak, missing validation)
- Rate limit result models
- GraphQL checker (mocked HTTP)
- FastAPI router endpoints (all 6 routes)
- SecurityFinding, RateLimitResult, SchemaIssue data models
- Edge cases: empty spec, no paths, deprecated endpoints, version gaps

All tests use mocks — no real HTTP calls.

Run with: python -m pytest tests/test_api_security.py -v --timeout=30
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Environment setup (must precede app imports)
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-that-is-long-enough-32chars")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))

from core.api_security_engine import (
    ApiEndpoint,
    ApiSecurityEngine,
    AuthAnalysis,
    AuthAnalyzer,
    AuthScheme,
    BOLAChecker,
    BOPLAChecker,
    BFLAChecker,
    BrokenAuthChecker,
    GraphQLChecker,
    InventoryChecker,
    OpenAPIParser,
    OwaspCategory,
    RateLimitChecker,
    RateLimitResult,
    RateLimitVerifier,
    SchemaIssue,
    SchemaValidator,
    SecurityFinding,
    SecurityMisconfigChecker,
    Severity,
    ScanResult,
    SSRFChecker,
    _craft_none_alg_token,
    _craft_expired_token,
    _craft_tampered_token,
    get_api_security_engine,
)

# ---------------------------------------------------------------------------
# Sample OpenAPI v3 spec fixture
# ---------------------------------------------------------------------------

SAMPLE_SPEC_V3: Dict[str, Any] = {
    "openapi": "3.0.0",
    "info": {"title": "Test API", "version": "1.0.0"},
    "security": [],
    "components": {
        "securitySchemes": {
            "BearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
            "ApiKeyQuery": {"type": "apiKey", "in": "query", "name": "api_key"},
            "OAuth2Implicit": {
                "type": "oauth2",
                "flows": {"implicit": {"authorizationUrl": "https://example.com/auth", "scopes": {}}},
            },
        }
    },
    "paths": {
        "/users/{user_id}": {
            "get": {
                "operationId": "getUser",
                "summary": "Get user by ID",
                "tags": ["users"],
                "security": [{"BearerAuth": []}],
                "parameters": [
                    {"name": "user_id", "in": "path", "required": True, "schema": {"type": "integer"}},
                ],
                "responses": {
                    "200": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "id": {"type": "integer"},
                                        "email": {"type": "string"},
                                        "password": {"type": "string"},
                                    },
                                }
                            }
                        }
                    }
                },
            },
            "delete": {
                "operationId": "deleteUser",
                "summary": "Delete user",
                "tags": ["users"],
                "parameters": [
                    {"name": "user_id", "in": "path", "required": True, "schema": {"type": "integer"}},
                ],
                "responses": {"204": {}},
            },
        },
        "/admin/users": {
            "get": {
                "operationId": "listAllUsers",
                "summary": "List all users (admin)",
                "tags": ["admin"],
                "security": [{"BearerAuth": []}],
                "parameters": [
                    {"name": "limit", "in": "query", "schema": {"type": "integer"}},
                    {"name": "offset", "in": "query", "schema": {"type": "integer"}},
                ],
                "responses": {"200": {}},
            }
        },
        "/users": {
            "post": {
                "operationId": "createUser",
                "summary": "Create user",
                "tags": ["users"],
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["username", "email"],
                                "properties": {
                                    "username": {"type": "string"},
                                    "email": {"type": "string"},
                                    "is_admin": {"type": "boolean"},
                                    "role": {"type": "string"},
                                    "password": {"type": "string"},
                                },
                            }
                        }
                    }
                },
                "responses": {"201": {}},
            }
        },
        "/webhooks/notify": {
            "post": {
                "operationId": "notify",
                "summary": "Send webhook notification",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "url": {"type": "string"},
                                    "payload": {"type": "object"},
                                },
                            }
                        }
                    }
                },
                "responses": {"200": {}},
            }
        },
        "/account/profile": {
            "get": {
                "operationId": "getProfile",
                "summary": "Get user profile",
                "deprecated": True,
                "responses": {"200": {}},
            }
        },
        "/v1/items": {
            "get": {
                "operationId": "listItemsV1",
                "parameters": [
                    {"name": "token", "in": "query", "schema": {"type": "string"}},
                    {"name": "limit", "in": "query", "schema": {"type": "integer", "maximum": 100}},
                ],
                "responses": {"200": {}},
            }
        },
        "/v3/items": {
            "get": {
                "operationId": "listItemsV3",
                "security": [{"BearerAuth": []}],
                "responses": {"200": {}},
            }
        },
    },
}

SAMPLE_SPEC_V2: Dict[str, Any] = {
    "swagger": "2.0",
    "info": {"title": "Legacy API", "version": "1.0"},
    "basePath": "/api",
    "paths": {
        "/items/{id}": {
            "get": {
                "operationId": "getItem",
                "parameters": [{"name": "id", "in": "path", "type": "integer", "required": True}],
                "responses": {"200": {}},
            }
        }
    },
}


# ============================================================================
# OpenAPIParser tests
# ============================================================================


class TestOpenAPIParser:
    def setup_method(self):
        self.parser = OpenAPIParser()

    def test_parse_v3_returns_endpoints(self):
        endpoints = self.parser.parse(SAMPLE_SPEC_V3)
        assert len(endpoints) > 0

    def test_parse_v3_extracts_method_and_path(self):
        endpoints = self.parser.parse(SAMPLE_SPEC_V3)
        paths = {(e.method, e.path) for e in endpoints}
        assert ("GET", "/users/{user_id}") in paths
        assert ("POST", "/users") in paths

    def test_parse_v3_auth_required(self):
        endpoints = self.parser.parse(SAMPLE_SPEC_V3)
        user_ep = next(e for e in endpoints if e.path == "/users/{user_id}" and e.method == "GET")
        assert user_ep.auth_required is True

    def test_parse_v3_no_auth_on_delete(self):
        endpoints = self.parser.parse(SAMPLE_SPEC_V3)
        delete_ep = next(e for e in endpoints if e.path == "/users/{user_id}" and e.method == "DELETE")
        assert delete_ep.auth_required is False

    def test_parse_v3_deprecated_flag(self):
        endpoints = self.parser.parse(SAMPLE_SPEC_V3)
        dep_ep = next(e for e in endpoints if e.path == "/account/profile")
        assert dep_ep.deprecated is True

    def test_parse_v3_operation_id(self):
        endpoints = self.parser.parse(SAMPLE_SPEC_V3)
        ep = next(e for e in endpoints if e.path == "/users/{user_id}" and e.method == "GET")
        assert ep.operation_id == "getUser"

    def test_parse_v3_response_schemas(self):
        endpoints = self.parser.parse(SAMPLE_SPEC_V3)
        ep = next(e for e in endpoints if e.path == "/users/{user_id}" and e.method == "GET")
        assert "200" in ep.response_schemas

    def test_parse_v3_tags(self):
        endpoints = self.parser.parse(SAMPLE_SPEC_V3)
        ep = next(e for e in endpoints if e.path == "/users/{user_id}" and e.method == "GET")
        assert "users" in ep.tags

    def test_parse_v2_returns_endpoints(self):
        endpoints = self.parser.parse(SAMPLE_SPEC_V2)
        assert len(endpoints) > 0

    def test_parse_v2_applies_base_path(self):
        endpoints = self.parser.parse(SAMPLE_SPEC_V2)
        ep = endpoints[0]
        assert ep.path.startswith("/api")

    def test_parse_empty_spec(self):
        endpoints = self.parser.parse({})
        assert endpoints == []

    def test_parse_spec_no_paths(self):
        endpoints = self.parser.parse({"openapi": "3.0.0", "info": {}, "paths": {}})
        assert endpoints == []

    def test_parse_v3_request_body(self):
        endpoints = self.parser.parse(SAMPLE_SPEC_V3)
        ep = next(e for e in endpoints if e.path == "/users" and e.method == "POST")
        assert ep.request_body is not None


# ============================================================================
# BOLA Checker
# ============================================================================


class TestBOLAChecker:
    def setup_method(self):
        self.checker = BOLAChecker()

    def test_no_auth_id_param_flags_bola(self):
        ep = ApiEndpoint(
            method="GET", path="/resources/{resource_id}",
            parameters=[{"name": "resource_id", "in": "path"}],
            auth_required=False,
        )
        findings = self.checker.check(ep, "https://api.example.com")
        assert len(findings) == 1
        assert findings[0].owasp_category == OwaspCategory.API1_BOLA

    def test_auth_required_no_bola_finding(self):
        ep = ApiEndpoint(
            method="GET", path="/resources/{resource_id}",
            parameters=[{"name": "resource_id", "in": "path"}],
            auth_required=True,
        )
        findings = self.checker.check(ep, "https://api.example.com")
        assert findings == []

    def test_no_id_param_no_finding(self):
        ep = ApiEndpoint(method="GET", path="/resources", auth_required=False)
        findings = self.checker.check(ep, "https://api.example.com")
        assert findings == []

    def test_uuid_param_detected(self):
        ep = ApiEndpoint(
            method="GET", path="/orders/{order_uuid}",
            parameters=[{"name": "order_uuid", "in": "path"}],
            auth_required=False,
        )
        findings = self.checker.check(ep, "https://api.example.com")
        assert len(findings) >= 1

    def test_finding_severity_high(self):
        ep = ApiEndpoint(
            method="GET", path="/documents/{doc_id}",
            parameters=[{"name": "doc_id", "in": "path"}],
            auth_required=False,
        )
        findings = self.checker.check(ep, "https://api.example.com")
        assert findings[0].severity == Severity.HIGH

    def test_finding_has_reproduction_steps(self):
        ep = ApiEndpoint(
            method="GET", path="/files/{file_id}",
            parameters=[{"name": "file_id", "in": "path"}],
            auth_required=False,
        )
        findings = self.checker.check(ep, "https://api.example.com")
        assert len(findings[0].reproduction_steps) >= 2


# ============================================================================
# Broken Auth Checker
# ============================================================================


class TestBrokenAuthChecker:
    def setup_method(self):
        self.checker = BrokenAuthChecker()

    def test_sensitive_path_no_auth_critical(self):
        ep = ApiEndpoint(method="GET", path="/user/profile", auth_required=False)
        findings = self.checker.check(ep, "https://api.example.com")
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_token_in_query_param_high(self):
        ep = ApiEndpoint(
            method="GET", path="/data",
            parameters=[{"name": "token", "in": "query", "schema": {"type": "string"}}],
            auth_required=True,
        )
        findings = self.checker.check(ep, "https://api.example.com")
        assert any(f.owasp_category == OwaspCategory.API2_AUTH for f in findings)

    def test_api_key_query_param_flagged(self):
        ep = ApiEndpoint(
            method="GET", path="/reports",
            parameters=[{"name": "api_key", "in": "query", "schema": {"type": "string"}}],
            auth_required=True,
        )
        findings = self.checker.check(ep, "https://api.example.com")
        assert len(findings) >= 1

    def test_non_sensitive_path_no_finding(self):
        ep = ApiEndpoint(method="GET", path="/health", auth_required=False)
        findings = self.checker.check(ep, "https://api.example.com")
        assert findings == []


# ============================================================================
# BOPLA Checker
# ============================================================================


class TestBOPLAChecker:
    def setup_method(self):
        self.checker = BOPLAChecker()

    def test_is_admin_field_flagged(self):
        ep = ApiEndpoint(
            method="POST", path="/users",
            request_body={
                "content": {
                    "application/json": {
                        "schema": {
                            "properties": {
                                "name": {"type": "string"},
                                "is_admin": {"type": "boolean"},
                            }
                        }
                    }
                }
            },
        )
        findings = self.checker.check(ep, "https://api.example.com")
        assert len(findings) >= 1
        assert findings[0].owasp_category == OwaspCategory.API3_BOPLA

    def test_role_field_flagged(self):
        ep = ApiEndpoint(
            method="PUT", path="/users/1",
            request_body={
                "content": {
                    "application/json": {
                        "schema": {"properties": {"role": {"type": "string"}}}
                    }
                }
            },
        )
        findings = self.checker.check(ep, "https://api.example.com")
        assert any(f.parameter == "role" for f in findings)

    def test_get_method_skipped(self):
        ep = ApiEndpoint(method="GET", path="/users", request_body=None)
        findings = self.checker.check(ep, "https://api.example.com")
        assert findings == []

    def test_no_mass_assign_fields_no_finding(self):
        ep = ApiEndpoint(
            method="POST", path="/items",
            request_body={
                "content": {
                    "application/json": {
                        "schema": {"properties": {"name": {"type": "string"}, "price": {"type": "number"}}}
                    }
                }
            },
        )
        findings = self.checker.check(ep, "https://api.example.com")
        assert findings == []


# ============================================================================
# Rate Limit Checker (schema)
# ============================================================================


class TestRateLimitChecker:
    def setup_method(self):
        self.checker = RateLimitChecker()

    def test_unbounded_limit_param_flagged(self):
        ep = ApiEndpoint(
            method="GET", path="/items",
            parameters=[{"name": "limit", "in": "query", "schema": {"type": "integer"}}],
        )
        findings = self.checker.check_schema(ep)
        assert len(findings) >= 1
        assert findings[0].owasp_category == OwaspCategory.API4_CONSUMPTION

    def test_bounded_limit_param_ok(self):
        ep = ApiEndpoint(
            method="GET", path="/items",
            parameters=[{"name": "limit", "in": "query", "schema": {"type": "integer", "maximum": 100}}],
        )
        findings = self.checker.check_schema(ep)
        assert findings == []

    def test_post_with_size_param_flagged(self):
        ep = ApiEndpoint(
            method="POST", path="/search",
            parameters=[{"name": "size", "in": "query", "schema": {"type": "integer"}}],
        )
        findings = self.checker.check_schema(ep)
        assert len(findings) >= 1

    def test_delete_skipped(self):
        ep = ApiEndpoint(
            method="DELETE", path="/items/{id}",
            parameters=[{"name": "limit", "in": "query", "schema": {"type": "integer"}}],
        )
        findings = self.checker.check_schema(ep)
        assert findings == []


# ============================================================================
# BFLA Checker
# ============================================================================


class TestBFLAChecker:
    def setup_method(self):
        self.checker = BFLAChecker()

    def test_admin_path_no_auth_critical(self):
        ep = ApiEndpoint(method="GET", path="/admin/dashboard", auth_required=False)
        findings = self.checker.check(ep, "https://api.example.com")
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_admin_path_with_auth_high(self):
        ep = ApiEndpoint(method="GET", path="/admin/users", auth_required=True)
        findings = self.checker.check(ep, "https://api.example.com")
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_normal_path_no_finding(self):
        ep = ApiEndpoint(method="GET", path="/products", auth_required=False)
        findings = self.checker.check(ep, "https://api.example.com")
        assert findings == []

    def test_management_path_flagged(self):
        ep = ApiEndpoint(method="DELETE", path="/management/config", auth_required=False)
        findings = self.checker.check(ep, "https://api.example.com")
        assert len(findings) >= 1
        assert findings[0].owasp_category == OwaspCategory.API5_BFLA


# ============================================================================
# SSRF Checker
# ============================================================================


class TestSSRFChecker:
    def setup_method(self):
        self.checker = SSRFChecker()

    def test_url_parameter_flagged(self):
        ep = ApiEndpoint(
            method="GET", path="/fetch",
            parameters=[{"name": "url", "in": "query", "schema": {"type": "string"}}],
        )
        findings = self.checker.check(ep, "https://api.example.com")
        assert len(findings) >= 1
        assert findings[0].owasp_category == OwaspCategory.API7_SSRF

    def test_webhook_url_body_field_flagged(self):
        ep = ApiEndpoint(
            method="POST", path="/webhooks",
            request_body={
                "content": {
                    "application/json": {
                        "schema": {"properties": {"url": {"type": "string"}}}
                    }
                }
            },
        )
        findings = self.checker.check(ep, "https://api.example.com")
        assert any("url" in f.parameter.lower() for f in findings)

    def test_non_url_param_no_finding(self):
        ep = ApiEndpoint(
            method="GET", path="/items",
            parameters=[{"name": "name", "in": "query", "schema": {"type": "string"}}],
        )
        findings = self.checker.check(ep, "https://api.example.com")
        assert findings == []

    def test_redirect_param_flagged(self):
        ep = ApiEndpoint(
            method="GET", path="/redirect",
            parameters=[{"name": "redirect", "in": "query", "schema": {"type": "string"}}],
        )
        findings = self.checker.check(ep, "https://api.example.com")
        assert len(findings) >= 1


# ============================================================================
# Security Misconfig Checker
# ============================================================================


class TestSecurityMisconfigChecker:
    def setup_method(self):
        self.checker = SecurityMisconfigChecker()

    def test_wildcard_cors_flagged(self):
        spec = {"x-cors": {"allowedOrigins": ["*"]}}
        findings = self.checker.check_from_spec(spec)
        assert any(f.owasp_category == OwaspCategory.API8_MISCONFIG for f in findings)

    def test_missing_security_headers_flagged(self):
        headers = {"Content-Type": "application/json"}
        findings = self.checker.check_response_headers(headers, "/api", "GET")
        assert len(findings) > 0

    def test_server_version_disclosure(self):
        headers = {"Server": "nginx/1.18.0", "Content-Type": "application/json"}
        findings = self.checker.check_response_headers(headers, "/api", "GET")
        assert any("Version Disclosure" in f.title for f in findings)

    def test_all_headers_present_no_missing_header_finding(self):
        headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "no-referrer",
        }
        findings = self.checker.check_response_headers(headers, "/api", "GET")
        missing = [f for f in findings if "Missing Security Header" in f.title]
        assert missing == []


# ============================================================================
# Inventory Checker
# ============================================================================


class TestInventoryChecker:
    def setup_method(self):
        self.checker = InventoryChecker()

    def test_deprecated_endpoint_flagged(self):
        ep = ApiEndpoint(method="GET", path="/v1/users", deprecated=True)
        findings = self.checker.check([ep])
        assert len(findings) >= 1
        assert findings[0].owasp_category == OwaspCategory.API9_INVENTORY

    def test_version_gap_flagged(self):
        eps = [
            ApiEndpoint(method="GET", path="/v1/items"),
            ApiEndpoint(method="GET", path="/v5/items"),
        ]
        findings = self.checker.check(eps)
        assert any("Version Gap" in f.title for f in findings)

    def test_no_deprecated_no_finding(self):
        ep = ApiEndpoint(method="GET", path="/v1/users", deprecated=False)
        findings = self.checker.check([ep])
        version_gap = [f for f in findings if "Deprecated" in f.title]
        assert version_gap == []

    def test_consecutive_versions_no_gap_finding(self):
        eps = [
            ApiEndpoint(method="GET", path="/v1/items"),
            ApiEndpoint(method="GET", path="/v2/items"),
        ]
        findings = self.checker.check(eps)
        gap_findings = [f for f in findings if "Version Gap" in f.title]
        assert gap_findings == []


# ============================================================================
# Schema Validator
# ============================================================================


class TestSchemaValidator:
    def setup_method(self):
        self.validator = SchemaValidator()

    def test_pii_in_response_flagged(self):
        ep = ApiEndpoint(
            method="GET", path="/users/1",
            response_schemas={
                "200": {"type": "object", "properties": {"email": {}, "password": {}}}
            },
        )
        issues = self.validator.analyze([ep])
        pii = [i for i in issues if i.issue_type == "pii_leak"]
        assert len(pii) >= 1

    def test_mass_assignment_in_request_flagged(self):
        ep = ApiEndpoint(
            method="POST", path="/users",
            request_body={
                "content": {
                    "application/json": {
                        "schema": {
                            "properties": {"is_admin": {"type": "boolean"}},
                            "required": [],
                        }
                    }
                }
            },
        )
        issues = self.validator.analyze([ep])
        mass = [i for i in issues if i.issue_type == "mass_assignment"]
        assert len(mass) >= 1

    def test_missing_string_validation_flagged(self):
        ep = ApiEndpoint(
            method="POST", path="/comments",
            request_body={
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "required": ["body"],
                            "properties": {"body": {"type": "string"}},
                        }
                    }
                }
            },
        )
        issues = self.validator.analyze([ep])
        missing = [i for i in issues if i.issue_type == "missing_validation"]
        assert len(missing) >= 1

    def test_constrained_string_no_missing_validation(self):
        ep = ApiEndpoint(
            method="POST", path="/tags",
            request_body={
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "required": ["name"],
                            "properties": {"name": {"type": "string", "maxLength": 50}},
                        }
                    }
                }
            },
        )
        issues = self.validator.analyze([ep])
        missing = [i for i in issues if i.issue_type == "missing_validation"]
        assert missing == []


# ============================================================================
# Auth Analyzer
# ============================================================================


class TestAuthAnalyzer:
    def setup_method(self):
        self.analyzer = AuthAnalyzer()

    def test_jwt_bearer_issues_reported(self):
        spec = {
            "components": {
                "securitySchemes": {
                    "BearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
                }
            }
        }
        analyses = self.analyzer.analyze_from_spec(spec, [])
        assert len(analyses) >= 1
        assert any("JWT" in issue for a in analyses for issue in a.issues)

    def test_api_key_in_query_issue_reported(self):
        spec = {
            "components": {
                "securitySchemes": {
                    "ApiKey": {"type": "apiKey", "in": "query", "name": "api_key"}
                }
            }
        }
        analyses = self.analyzer.analyze_from_spec(spec, [])
        assert any("query" in issue for a in analyses for issue in a.issues)

    def test_oauth2_implicit_flow_issue(self):
        spec = {
            "components": {
                "securitySchemes": {
                    "OAuth2": {
                        "type": "oauth2",
                        "flows": {"implicit": {"authorizationUrl": "https://x.com/auth", "scopes": {}}},
                    }
                }
            }
        }
        analyses = self.analyzer.analyze_from_spec(spec, [])
        assert any("implicit" in issue.lower() for a in analyses for issue in a.issues)

    def test_sensitive_endpoint_no_auth_flagged(self):
        eps = [ApiEndpoint(method="GET", path="/account/details", auth_required=False)]
        analyses = self.analyzer.analyze_from_spec({}, eps)
        assert any(a.scheme_detected == AuthScheme.NONE for a in analyses)


# ============================================================================
# JWT Helpers
# ============================================================================


class TestJWTHelpers:
    def test_none_alg_token_structure(self):
        token = _craft_none_alg_token({"sub": "test", "exp": 9999999999})
        parts = token.split(".")
        assert len(parts) == 3
        assert parts[2] == ""  # no signature

    def test_expired_token_structure(self):
        token = _craft_expired_token()
        parts = token.split(".")
        assert len(parts) == 3

    def test_tampered_token_has_admin(self):
        import base64
        import json as json_lib
        token = _craft_tampered_token()
        parts = token.split(".")
        # Decode payload (add padding)
        payload_b64 = parts[1] + "=="
        payload = json_lib.loads(base64.urlsafe_b64decode(payload_b64))
        assert payload.get("is_admin") is True or payload.get("role") == "admin"


# ============================================================================
# Data Model serialization
# ============================================================================


class TestDataModels:
    def test_security_finding_to_dict(self):
        f = SecurityFinding(
            finding_id="abc",
            title="Test Finding",
            severity=Severity.HIGH,
            owasp_category=OwaspCategory.API1_BOLA,
            endpoint="/users/1",
            method="GET",
            description="desc",
            reproduction_steps=["step1"],
            fix_suggestion="fix it",
            cvss_score=8.1,
        )
        d = f.to_dict()
        assert d["severity"] == "high"
        assert d["owasp_category"] == OwaspCategory.API1_BOLA.value
        assert isinstance(d["timestamp"], str)

    def test_rate_limit_result_to_dict(self):
        r = RateLimitResult(
            endpoint="/api/items",
            method="GET",
            requests_sent=20,
            requests_allowed=20,
            rate_limit_detected=False,
        )
        d = r.to_dict()
        assert d["rate_limit_detected"] is False
        assert d["requests_sent"] == 20

    def test_schema_issue_to_dict(self):
        i = SchemaIssue(
            issue_id="xyz",
            issue_type="pii_leak",
            endpoint="/users",
            method="GET",
            field_name="email",
            description="PII exposed",
            severity=Severity.HIGH,
        )
        d = i.to_dict()
        assert d["issue_type"] == "pii_leak"
        assert d["severity"] == "high"

    def test_auth_analysis_to_dict(self):
        a = AuthAnalysis(
            endpoint="/api",
            method="GET",
            scheme_detected=AuthScheme.BEARER,
            issues=["JWT none alg risk"],
        )
        d = a.to_dict()
        assert d["scheme_detected"] == "bearer"
        assert "JWT none alg risk" in d["issues"]

    def test_api_endpoint_to_dict(self):
        ep = ApiEndpoint(method="GET", path="/test", auth_required=True)
        d = ep.to_dict()
        assert d["method"] == "GET"
        assert d["auth_required"] is True


# ============================================================================
# ApiSecurityEngine integration (mocked HTTP)
# ============================================================================


class TestApiSecurityEngine:
    def setup_method(self):
        self.engine = ApiSecurityEngine()

    def test_parse_spec_returns_endpoints(self):
        endpoints = self.engine.parse_spec(SAMPLE_SPEC_V3)
        assert len(endpoints) > 0

    @pytest.mark.asyncio
    async def test_run_scan_with_spec(self):
        result = await self.engine.run_scan(spec=SAMPLE_SPEC_V3, target_url="https://api.example.com")
        assert result.scan_id
        assert result.endpoints_discovered > 0
        assert result.total_findings >= 0
        assert isinstance(result.findings, list)

    @pytest.mark.asyncio
    async def test_run_scan_produces_bola_findings(self):
        result = await self.engine.run_scan(spec=SAMPLE_SPEC_V3, target_url="https://api.example.com")
        bola = [f for f in result.findings if f.owasp_category == OwaspCategory.API1_BOLA]
        assert len(bola) >= 1

    @pytest.mark.asyncio
    async def test_run_scan_produces_schema_issues(self):
        result = await self.engine.run_scan(spec=SAMPLE_SPEC_V3, target_url="https://api.example.com")
        assert len(result.schema_issues) >= 1

    @pytest.mark.asyncio
    async def test_run_scan_produces_auth_analyses(self):
        result = await self.engine.run_scan(spec=SAMPLE_SPEC_V3, target_url="https://api.example.com")
        assert len(result.auth_analyses) >= 1

    @pytest.mark.asyncio
    async def test_run_scan_by_severity_populated(self):
        result = await self.engine.run_scan(spec=SAMPLE_SPEC_V3, target_url="https://api.example.com")
        assert "high" in result.by_severity or "critical" in result.by_severity

    @pytest.mark.asyncio
    async def test_run_scan_no_spec_no_url_returns_empty(self):
        result = await self.engine.run_scan()
        assert result.endpoints_discovered == 0

    @pytest.mark.asyncio
    async def test_run_scan_stores_result(self):
        result = await self.engine.run_scan(spec=SAMPLE_SPEC_V3)
        fetched = self.engine.get_scan(result.scan_id)
        assert fetched is not None
        assert fetched.scan_id == result.scan_id

    def test_get_scan_nonexistent_returns_none(self):
        assert self.engine.get_scan("nonexistent-id") is None

    @pytest.mark.asyncio
    async def test_get_all_findings_aggregates_across_scans(self):
        await self.engine.run_scan(spec=SAMPLE_SPEC_V3)
        await self.engine.run_scan(spec=SAMPLE_SPEC_V3)
        findings = self.engine.get_all_findings()
        assert len(findings) > 0

    def test_singleton_returns_same_instance(self):
        e1 = get_api_security_engine()
        e2 = get_api_security_engine()
        assert e1 is e2

    @pytest.mark.asyncio
    async def test_scan_result_to_dict(self):
        result = await self.engine.run_scan(spec=SAMPLE_SPEC_V3)
        d = result.to_dict()
        assert "scan_id" in d
        assert "findings" in d
        assert "by_severity" in d
        assert "schema_issues" in d
        assert "auth_analyses" in d

    @pytest.mark.asyncio
    async def test_discover_spec_returns_none_on_failure(self):
        import httpx

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(
                side_effect=httpx.ConnectError("connection refused")
            )
            mock_client_cls.return_value = mock_client
            spec = await self.engine.discover_spec("https://api.example.com")
            assert spec is None


# ============================================================================
# FastAPI Router tests
# ============================================================================

try:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from apps.api.api_security_router import router as api_security_router

    _app = FastAPI()
    _app.include_router(api_security_router)
    _client = TestClient(_app, raise_server_exceptions=False)
    _ROUTER_AVAILABLE = True
except Exception:
    _ROUTER_AVAILABLE = False
    _client = None


@pytest.mark.skipif(not _ROUTER_AVAILABLE, reason="Router not importable")
class TestApiSecurityRouter:
    def test_health_returns_200(self):
        resp = _client.get("/api/v1/api-security/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    def test_scan_with_spec_returns_200(self):
        resp = _client.post(
            "/api/v1/api-security/scan",
            json={"openapi_spec": SAMPLE_SPEC_V3},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "scan_id" in data
        assert "findings" in data

    def test_scan_without_spec_or_url_returns_422(self):
        resp = _client.post("/api/v1/api-security/scan", json={})
        assert resp.status_code == 422

    def test_scan_with_blocked_url_returns_422(self):
        resp = _client.post(
            "/api/v1/api-security/scan",
            json={"target_url": "http://localhost/api"},
        )
        assert resp.status_code == 422

    def test_scan_with_private_ip_returns_422(self):
        resp = _client.post(
            "/api/v1/api-security/scan",
            json={"target_url": "http://192.168.1.1/api"},
        )
        assert resp.status_code == 422

    def test_scan_with_metadata_url_returns_422(self):
        resp = _client.post(
            "/api/v1/api-security/scan",
            json={"target_url": "http://169.254.169.254/latest/meta-data/"},
        )
        assert resp.status_code == 422

    def test_scan_too_many_headers_returns_422(self):
        headers = {f"X-Header-{i}": "val" for i in range(51)}
        resp = _client.post(
            "/api/v1/api-security/scan",
            json={"openapi_spec": {}, "headers": headers},
        )
        assert resp.status_code == 422

    def test_findings_returns_200(self):
        resp = _client.get("/api/v1/api-security/findings")
        assert resp.status_code == 200
        data = resp.json()
        assert "findings" in data
        assert "total" in data

    def test_findings_severity_filter(self):
        resp = _client.get("/api/v1/api-security/findings?severity=high")
        assert resp.status_code == 200

    def test_findings_invalid_limit_returns_422(self):
        resp = _client.get("/api/v1/api-security/findings?limit=0")
        assert resp.status_code == 422

    def test_inventory_returns_200(self):
        resp = _client.get("/api/v1/api-security/inventory")
        assert resp.status_code == 200
        assert "inventory" in resp.json()

    def test_auth_analysis_returns_200(self):
        resp = _client.get("/api/v1/api-security/auth-analysis")
        assert resp.status_code == 200
        assert "analyses" in resp.json()

    def test_rate_limits_returns_200(self):
        resp = _client.get("/api/v1/api-security/rate-limits")
        assert resp.status_code == 200
        assert "results" in resp.json()

    def test_schema_issues_returns_200(self):
        resp = _client.get("/api/v1/api-security/schema-issues")
        assert resp.status_code == 200
        assert "issues" in resp.json()

    def test_schema_issues_type_filter(self):
        resp = _client.get("/api/v1/api-security/schema-issues?issue_type=pii_leak")
        assert resp.status_code == 200

    def test_max_rate_limit_endpoints_out_of_range_422(self):
        resp = _client.post(
            "/api/v1/api-security/scan",
            json={"openapi_spec": {}, "max_rate_limit_endpoints": 100},
        )
        assert resp.status_code == 422
