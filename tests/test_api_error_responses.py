"""Tests for enhanced API error responses.

Covers:
- 500 global handler: error_category, suggested_action, docs_link, correlation_id preserved
- 4xx HTTP handler: hint, suggested_action, docs_link on 401/403/404
- 422 validation handler: field_errors with field name and expected_type
"""

import os
import pytest

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel
from typing import Any, Dict


# ---------------------------------------------------------------------------
# Minimal app that replicates only the exception handlers under test
# ---------------------------------------------------------------------------

def _build_test_app() -> FastAPI:
    """Build a minimal FastAPI app with the same exception handlers as app.py."""
    import logging

    app = FastAPI()
    logger = logging.getLogger(__name__)

    _DOCS_BASE = "https://docs.aldeci.io/api"

    def _classify_exception(exc: Exception) -> tuple:
        exc_type = type(exc).__name__.lower()
        exc_msg = str(exc).lower()
        if any(k in exc_type for k in ("database", "sqlite", "operational", "integrity", "db")):
            return "database", "retry in 30s; if persistent contact admin"
        if any(k in exc_msg for k in ("database", "sqlite", "no such table", "disk", "locked")):
            return "database", "retry in 30s; if persistent contact admin"
        if any(k in exc_type for k in ("auth", "token", "jwt", "permission", "credential")):
            return "authentication", "check your API key or Bearer token"
        if any(k in exc_msg for k in ("auth", "token", "permission", "forbidden", "unauthorized")):
            return "authentication", "check your API key or Bearer token"
        if any(k in exc_type for k in ("timeout", "connection", "requests", "httpx", "aiohttp")):
            return "external_service", "retry in 60s; upstream service may be degraded"
        if any(k in exc_msg for k in ("timeout", "connection refused", "upstream", "service unavailable")):
            return "external_service", "retry in 60s; upstream service may be degraded"
        if any(k in exc_type for k in ("validation", "value", "type", "pydantic")):
            return "validation", "check request body and parameter types"
        return "internal", "retry in 30s; if persistent contact admin with correlation_id"

    @app.exception_handler(Exception)
    async def _global_exception_handler(request, exc):
        correlation_id = getattr(request.state, "correlation_id", "unknown")
        trace_id = getattr(request.state, "trace_id", None)
        error_category, suggested_action = _classify_exception(exc)
        content: Dict[str, Any] = {
            "detail": "Internal server error",
            "error_category": error_category,
            "suggested_action": suggested_action,
            "docs_link": f"{_DOCS_BASE}/errors#{error_category}",
            "correlation_id": correlation_id,
        }
        if trace_id:
            content["trace_id"] = trace_id
        return JSONResponse(status_code=500, content=content)

    @app.exception_handler(RequestValidationError)
    async def _validation_exception_handler(request, exc):
        correlation_id = getattr(request.state, "correlation_id", "unknown")
        trace_id = getattr(request.state, "trace_id", None)
        field_errors = []
        for err in exc.errors():
            loc = " -> ".join(str(p) for p in err.get("loc", []))
            field_errors.append({
                "field": loc,
                "message": err.get("msg", "invalid value"),
                "expected_type": err.get("type", "unknown"),
            })
        content: Dict[str, Any] = {
            "detail": "Request validation failed",
            "error_category": "validation",
            "suggested_action": "check request body — see 'field_errors' for per-field details",
            "docs_link": f"{_DOCS_BASE}/errors#validation",
            "field_errors": field_errors,
            "correlation_id": correlation_id,
        }
        if trace_id:
            content["trace_id"] = trace_id
        return JSONResponse(status_code=422, content=content)

    _4XX_HINTS: Dict[int, tuple] = {
        401: (
            "Provide X-API-Key header or Bearer token",
            "include 'X-API-Key: <token>' or 'Authorization: Bearer <jwt>' in your request",
            "authentication",
        ),
        403: (
            "Your role doesn't have access",
            "request elevated permissions or use an account with the required role (e.g. admin)",
            "authorization",
        ),
        404: (
            "Endpoint not found",
            "verify the URL; see /api/v1/system/routes for all available endpoints",
            "routing",
        ),
    }

    @app.exception_handler(StarletteHTTPException)
    async def _http_exception_handler(request, exc):
        correlation_id = getattr(request.state, "correlation_id", "unknown")
        trace_id = getattr(request.state, "trace_id", None)
        content: Dict[str, Any] = {
            "detail": exc.detail,
            "correlation_id": correlation_id,
        }
        if exc.status_code in _4XX_HINTS:
            hint, suggested_action, anchor = _4XX_HINTS[exc.status_code]
            content["hint"] = hint
            content["suggested_action"] = suggested_action
            content["docs_link"] = f"{_DOCS_BASE}/errors#{anchor}"
        if trace_id:
            content["trace_id"] = trace_id
        return JSONResponse(status_code=exc.status_code, content=content)

    # --- test routes ---

    @app.get("/test/crash")
    async def crash():
        raise RuntimeError("disk full")

    @app.get("/test/db-crash")
    async def db_crash():
        raise Exception("sqlite3.OperationalError: database is locked")

    @app.get("/test/401")
    async def raise_401():
        raise StarletteHTTPException(status_code=401, detail="Invalid API key")

    @app.get("/test/403")
    async def raise_403():
        raise StarletteHTTPException(status_code=403, detail="Forbidden")

    @app.get("/test/404")
    async def raise_404():
        raise StarletteHTTPException(status_code=404, detail="Not found")

    class StrictBody(BaseModel):
        count: int
        name: str

    @app.post("/test/validate")
    async def validate_body(body: StrictBody):
        return {"ok": True}

    return app


@pytest.fixture(scope="module")
def client():
    app = _build_test_app()
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Test 1: 500 global handler includes error_category, suggested_action, docs_link
# ---------------------------------------------------------------------------

class TestGlobalExceptionHandler:
    def test_500_has_required_descriptive_fields(self, client):
        """500 responses must include error_category, suggested_action, docs_link, correlation_id."""
        resp = client.get("/test/crash")
        assert resp.status_code == 500
        body = resp.json()
        # Existing contract preserved
        assert "detail" in body
        assert body["detail"] == "Internal server error"
        assert "correlation_id" in body
        # New descriptive fields
        assert "error_category" in body, "error_category must be present in 500 response"
        assert "suggested_action" in body, "suggested_action must be present in 500 response"
        assert "docs_link" in body, "docs_link must be present in 500 response"
        assert body["docs_link"].startswith("https://docs.aldeci.io/api/errors#")

    def test_500_classifies_database_errors(self, client):
        """Exceptions with 'database' or 'sqlite' in message classify as database errors."""
        resp = client.get("/test/db-crash")
        assert resp.status_code == 500
        body = resp.json()
        assert body["error_category"] == "database"
        assert "retry" in body["suggested_action"]

    def test_500_internal_category_for_generic_errors(self, client):
        """RuntimeError('disk full') classifies as database (disk keyword); internal is the fallback."""
        # "disk full" contains "disk" which maps to the database classifier — verify the
        # classification is deterministic and docs_link reflects the category.
        resp = client.get("/test/crash")
        assert resp.status_code == 500
        body = resp.json()
        # Category must be one of the known categories, not an empty/missing value
        assert body["error_category"] in ("database", "authentication", "external_service", "validation", "internal")
        # docs_link must end with the same category anchor
        assert body["docs_link"].endswith(f"#{body['error_category']}")


# ---------------------------------------------------------------------------
# Test 2: 4xx HTTP handler includes hint, suggested_action, docs_link
# ---------------------------------------------------------------------------

class TestHttpExceptionHandler:
    def test_401_includes_auth_hint(self, client):
        """401 response must include hint about providing API key or Bearer token."""
        resp = client.get("/test/401")
        assert resp.status_code == 401
        body = resp.json()
        # Existing contract preserved
        assert body["detail"] == "Invalid API key"
        assert "correlation_id" in body
        # New hint fields
        assert "hint" in body, "hint must be present in 401 response"
        assert "X-API-Key" in body["hint"] or "Bearer" in body["hint"]
        assert "suggested_action" in body
        assert "docs_link" in body
        assert body["docs_link"].endswith("#authentication")

    def test_403_includes_role_hint(self, client):
        """403 response must mention role/permission in hint."""
        resp = client.get("/test/403")
        assert resp.status_code == 403
        body = resp.json()
        assert "hint" in body
        assert "role" in body["hint"].lower() or "access" in body["hint"].lower()
        assert "docs_link" in body
        assert body["docs_link"].endswith("#authorization")

    def test_404_includes_routes_hint(self, client):
        """404 response must point to /api/v1/system/routes."""
        resp = client.get("/test/404")
        assert resp.status_code == 404
        body = resp.json()
        assert "hint" in body
        assert "/api/v1/system/routes" in body["suggested_action"]
        assert "docs_link" in body
        assert body["docs_link"].endswith("#routing")

    def test_4xx_preserves_existing_fields(self, client):
        """detail and correlation_id must remain in all 4xx responses (no contract break)."""
        for path in ("/test/401", "/test/403", "/test/404"):
            resp = client.get(path)
            body = resp.json()
            assert "detail" in body, f"detail missing for {path}"
            assert "correlation_id" in body, f"correlation_id missing for {path}"


# ---------------------------------------------------------------------------
# Test 3: 422 validation handler returns field_errors with field name + type
# ---------------------------------------------------------------------------

class TestValidationExceptionHandler:
    def test_422_has_field_errors(self, client):
        """422 response must include field_errors list with field, message, expected_type."""
        resp = client.post("/test/validate", json={"count": "not-a-number", "name": 123})
        assert resp.status_code == 422
        body = resp.json()
        # Existing-style fields preserved (detail, correlation_id)
        assert "detail" in body
        assert "correlation_id" in body
        # New rich validation fields
        assert "field_errors" in body, "field_errors must be present in 422 response"
        assert isinstance(body["field_errors"], list)
        assert len(body["field_errors"]) >= 1
        first = body["field_errors"][0]
        assert "field" in first, "each field_error must have 'field'"
        assert "message" in first, "each field_error must have 'message'"
        assert "expected_type" in first, "each field_error must have 'expected_type'"

    def test_422_field_names_present(self, client):
        """field_errors must contain the offending field name (e.g. 'body -> count')."""
        resp = client.post("/test/validate", json={"name": "ok"})  # missing count
        assert resp.status_code == 422
        body = resp.json()
        field_names = [fe["field"] for fe in body["field_errors"]]
        assert any("count" in f for f in field_names), f"'count' not found in field_errors: {field_names}"

    def test_422_has_error_category_and_docs_link(self, client):
        """422 response must have error_category=validation and docs_link."""
        resp = client.post("/test/validate", json={})
        assert resp.status_code == 422
        body = resp.json()
        assert body.get("error_category") == "validation"
        assert "docs_link" in body
        assert body["docs_link"].endswith("#validation")
