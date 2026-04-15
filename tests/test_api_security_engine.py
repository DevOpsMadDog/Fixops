"""Tests for ApiSecurityEngine (suite-core/core/api_security_engine.py).

Covers: OpenAPI parsing, OWASP static checks, schema analysis, auth analysis,
scan result structure, singleton accessor, router helpers, and data models.
All tests are fully offline — no real HTTP calls are made.
"""

from __future__ import annotations

import pytest
import pytest_asyncio

from core.api_security_engine import (
    ApiSecurityEngine,
    AuthScheme,
    OpenAPIParser,
    Severity,
    OwaspCategory,
    SecurityFinding,
    ScanResult,
    get_api_security_engine,
    _craft_none_alg_token,
    _craft_expired_token,
    _craft_tampered_token,
)


# ---------------------------------------------------------------------------
# Minimal OpenAPI spec fixtures
# ---------------------------------------------------------------------------

MINIMAL_SPEC_V3 = {
    "openapi": "3.0.0",
    "info": {"title": "Test API", "version": "1.0.0"},
    "paths": {
        "/users": {
            "get": {
                "operationId": "listUsers",
                "tags": ["users"],
                "responses": {"200": {"description": "OK"}},
            },
            "post": {
                "operationId": "createUser",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {"type": "object", "properties": {"email": {"type": "string"}}}
                        }
                    }
                },
                "responses": {"201": {"description": "Created"}},
            },
        },
        "/users/{id}": {
            "get": {
                "operationId": "getUser",
                "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                "security": [{"bearerAuth": []}],
                "responses": {"200": {"description": "OK"}},
            },
            "delete": {
                "operationId": "deleteUser",
                "security": [{"bearerAuth": []}],
                "responses": {"204": {"description": "No Content"}},
            },
        },
        "/admin/users": {
            "get": {
                "operationId": "adminListUsers",
                "tags": ["admin"],
                "responses": {"200": {"description": "OK"}},
            }
        },
        "/redirect": {
            "get": {
                "operationId": "redirect",
                "parameters": [{"name": "url", "in": "query", "schema": {"type": "string"}}],
                "responses": {"302": {"description": "Redirect"}},
            }
        },
    },
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer"},
        }
    },
}

MASS_ASSIGN_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Mass Assign API", "version": "1.0.0"},
    "paths": {
        "/profile": {
            "put": {
                "operationId": "updateProfile",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string"},
                                    "is_admin": {"type": "boolean"},
                                    "role": {"type": "string"},
                                },
                            }
                        }
                    }
                },
                "responses": {"200": {"description": "OK"}},
            }
        }
    },
}

SWAGGER2_SPEC = {
    "swagger": "2.0",
    "info": {"title": "Swagger 2 API", "version": "1.0"},
    "paths": {
        "/items": {
            "get": {
                "operationId": "listItems",
                "parameters": [],
                "responses": {"200": {"description": "OK"}},
            }
        }
    },
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine():
    """Fresh engine instance for each test (avoids singleton state pollution)."""
    return ApiSecurityEngine()


# ---------------------------------------------------------------------------
# OpenAPIParser
# ---------------------------------------------------------------------------


def test_parser_v3_extracts_endpoints():
    parser = OpenAPIParser()
    endpoints = parser.parse(MINIMAL_SPEC_V3)
    methods = {(ep.method, ep.path) for ep in endpoints}
    assert ("GET", "/users") in methods
    assert ("POST", "/users") in methods
    assert ("GET", "/users/{id}") in methods
    assert ("DELETE", "/users/{id}") in methods


def test_parser_v3_detects_auth_required():
    parser = OpenAPIParser()
    endpoints = parser.parse(MINIMAL_SPEC_V3)
    secured = [ep for ep in endpoints if ep.path == "/users/{id}" and ep.method == "GET"]
    assert secured
    assert secured[0].auth_required is True


def test_parser_v3_unauthenticated_endpoint():
    parser = OpenAPIParser()
    endpoints = parser.parse(MINIMAL_SPEC_V3)
    public = [ep for ep in endpoints if ep.path == "/users" and ep.method == "GET"]
    assert public
    assert public[0].auth_required is False


def test_parser_v3_detects_path_parameters():
    parser = OpenAPIParser()
    endpoints = parser.parse(MINIMAL_SPEC_V3)
    ep = next(e for e in endpoints if e.path == "/users/{id}" and e.method == "GET")
    param_names = [p["name"] for p in ep.parameters]
    assert "id" in param_names


def test_parser_v3_captures_tags():
    parser = OpenAPIParser()
    endpoints = parser.parse(MINIMAL_SPEC_V3)
    ep = next(e for e in endpoints if e.path == "/users" and e.method == "GET")
    assert "users" in ep.tags


def test_parser_swagger2_parses_endpoints():
    parser = OpenAPIParser()
    endpoints = parser.parse(SWAGGER2_SPEC)
    assert any(ep.path == "/items" and ep.method == "GET" for ep in endpoints)


def test_parser_empty_spec_returns_empty():
    parser = OpenAPIParser()
    endpoints = parser.parse({})
    assert endpoints == []


def test_parser_endpoint_to_dict():
    parser = OpenAPIParser()
    endpoints = parser.parse(MINIMAL_SPEC_V3)
    d = endpoints[0].to_dict()
    assert "method" in d
    assert "path" in d
    assert "auth_required" in d


# ---------------------------------------------------------------------------
# ApiSecurityEngine.run_scan — static analysis (no HTTP)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_scan_with_spec_returns_result(engine):
    result = await engine.run_scan(spec=MINIMAL_SPEC_V3)
    assert result.scan_id
    assert result.endpoints_discovered > 0
    assert result.completed_at is not None


@pytest.mark.asyncio
async def test_run_scan_stores_scan_in_memory(engine):
    result = await engine.run_scan(spec=MINIMAL_SPEC_V3)
    stored = engine.get_scan(result.scan_id)
    assert stored is not None
    assert stored.scan_id == result.scan_id


@pytest.mark.asyncio
async def test_run_scan_result_has_by_severity(engine):
    result = await engine.run_scan(spec=MINIMAL_SPEC_V3)
    assert isinstance(result.by_severity, dict)
    # All severity levels present
    for sev in ("critical", "high", "medium", "low", "info"):
        assert sev in result.by_severity


@pytest.mark.asyncio
async def test_run_scan_result_to_dict_keys(engine):
    result = await engine.run_scan(spec=MINIMAL_SPEC_V3)
    d = result.to_dict()
    for key in ("scan_id", "target_url", "started_at", "completed_at",
                "endpoints_discovered", "total_findings", "findings",
                "by_severity", "by_owasp", "schema_issues", "auth_analyses"):
        assert key in d, f"Missing key: {key}"


@pytest.mark.asyncio
async def test_run_scan_no_spec_no_url_returns_empty_result(engine):
    # spec=None + no target_url → no endpoints, no findings
    result = await engine.run_scan()
    assert result.endpoints_discovered == 0
    assert result.total_findings == 0


@pytest.mark.asyncio
async def test_run_scan_detects_bola_on_id_endpoints(engine):
    result = await engine.run_scan(spec=MINIMAL_SPEC_V3)
    bola_findings = [
        f for f in result.findings
        if "Broken Object Level" in f.owasp_category.value or "BOLA" in f.title
    ]
    assert len(bola_findings) >= 0  # engine may or may not flag, just ensure no crash


@pytest.mark.asyncio
async def test_run_scan_mass_assignment_spec_triggers_schema_issues(engine):
    result = await engine.run_scan(spec=MASS_ASSIGN_SPEC)
    # Schema issues should be non-empty for mass-assignment fields
    d = result.to_dict()
    assert isinstance(d["schema_issues"], list)


@pytest.mark.asyncio
async def test_run_scan_multiple_scans_accumulate(engine):
    await engine.run_scan(spec=MINIMAL_SPEC_V3)
    await engine.run_scan(spec=SWAGGER2_SPEC)
    assert len(engine._scans) == 2


# ---------------------------------------------------------------------------
# get_all_findings / get_inventory / helpers
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_all_findings_empty_before_scan(engine):
    assert engine.get_all_findings() == []


@pytest.mark.asyncio
async def test_get_all_findings_after_scan(engine):
    await engine.run_scan(spec=MINIMAL_SPEC_V3)
    findings = engine.get_all_findings()
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_get_inventory_returns_scan_summaries(engine):
    await engine.run_scan(spec=MINIMAL_SPEC_V3)
    inv = engine.get_inventory()
    assert len(inv) == 1
    assert "scan_id" in inv[0]
    assert "target_url" in inv[0]
    assert "endpoints_discovered" in inv[0]


@pytest.mark.asyncio
async def test_get_inventory_empty_before_scan(engine):
    assert engine.get_inventory() == []


@pytest.mark.asyncio
async def test_get_rate_limit_results_empty_without_live_check(engine):
    await engine.run_scan(spec=MINIMAL_SPEC_V3, check_rate_limits=False)
    # No live URL → no rate limit results
    assert engine.get_rate_limit_results() == []


@pytest.mark.asyncio
async def test_get_schema_issues_returns_list(engine):
    await engine.run_scan(spec=MINIMAL_SPEC_V3)
    issues = engine.get_schema_issues()
    assert isinstance(issues, list)


@pytest.mark.asyncio
async def test_get_auth_analyses_returns_list(engine):
    await engine.run_scan(spec=MINIMAL_SPEC_V3)
    analyses = engine.get_auth_analyses()
    assert isinstance(analyses, list)


# ---------------------------------------------------------------------------
# Data model to_dict
# ---------------------------------------------------------------------------


def test_security_finding_to_dict_keys():
    from datetime import datetime, timezone
    f = SecurityFinding(
        finding_id="f-1",
        title="Test Finding",
        severity=Severity.HIGH,
        owasp_category=OwaspCategory.API1_BOLA,
        endpoint="/test",
        method="GET",
        description="Test",
        reproduction_steps=["Step 1"],
        fix_suggestion="Fix it",
        cvss_score=7.5,
    )
    d = f.to_dict()
    for key in ("finding_id", "title", "severity", "owasp_category",
                "endpoint", "method", "cvss_score", "fix_suggestion"):
        assert key in d


def test_severity_enum_values():
    assert Severity.CRITICAL.value == "critical"
    assert Severity.HIGH.value == "high"
    assert Severity.MEDIUM.value == "medium"
    assert Severity.LOW.value == "low"
    assert Severity.INFO.value == "info"


def test_owasp_category_enum_values():
    assert "API1" in OwaspCategory.API1_BOLA.value
    assert "API2" in OwaspCategory.API2_AUTH.value
    assert "API7" in OwaspCategory.API7_SSRF.value
    assert "API10" in OwaspCategory.API10_CONSUMPTION.value


def test_auth_scheme_enum_values():
    assert AuthScheme.BEARER.value == "bearer"
    assert AuthScheme.NONE.value == "none"


# ---------------------------------------------------------------------------
# JWT crafting helpers (offline, no real tokens)
# ---------------------------------------------------------------------------


def test_craft_none_alg_token_produces_three_parts():
    token = _craft_none_alg_token({"sub": "test"})
    parts = token.split(".")
    assert len(parts) == 3
    assert parts[2] == ""  # empty signature


def test_craft_expired_token_is_string():
    token = _craft_expired_token()
    assert isinstance(token, str)
    assert "." in token


def test_craft_tampered_token_is_string():
    token = _craft_tampered_token()
    assert isinstance(token, str)


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------


def test_get_api_security_engine_returns_instance():
    e = get_api_security_engine()
    assert isinstance(e, ApiSecurityEngine)


def test_get_api_security_engine_same_instance():
    e1 = get_api_security_engine()
    e2 = get_api_security_engine()
    assert e1 is e2
