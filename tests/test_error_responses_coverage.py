"""Tests for core.error_responses — standardized API error responses."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.error_responses import (
    ErrorCode,
    ErrorDetail,
    ErrorResponse,
    create_error_response,
    internal_error_response,
    not_found_error_response,
    rate_limit_error_response,
    validation_error_response,
)


# ── ErrorCode constants ─────────────────────────────────────────────

class TestErrorCode:
    def test_client_errors(self):
        assert ErrorCode.BAD_REQUEST == "bad_request"
        assert ErrorCode.UNAUTHORIZED == "unauthorized"
        assert ErrorCode.FORBIDDEN == "forbidden"
        assert ErrorCode.NOT_FOUND == "not_found"
        assert ErrorCode.CONFLICT == "conflict"
        assert ErrorCode.VALIDATION_ERROR == "validation_error"
        assert ErrorCode.RATE_LIMIT_EXCEEDED == "rate_limit_exceeded"
        assert ErrorCode.PAYLOAD_TOO_LARGE == "payload_too_large"

    def test_server_errors(self):
        assert ErrorCode.INTERNAL_ERROR == "internal_server_error"
        assert ErrorCode.SERVICE_UNAVAILABLE == "service_unavailable"
        assert ErrorCode.GATEWAY_TIMEOUT == "gateway_timeout"
        assert ErrorCode.DEPENDENCY_FAILURE == "dependency_failure"


# ── ErrorDetail ──────────────────────────────────────────────────────

class TestErrorDetail:
    def test_basic(self):
        detail = ErrorDetail(code="validation_error", message="Field required")
        assert detail.code == "validation_error"
        assert detail.message == "Field required"
        assert detail.field is None
        assert detail.details is None

    def test_with_field(self):
        detail = ErrorDetail(
            code="validation_error",
            message="Must be > 0",
            field="age",
            details={"min_value": 0},
        )
        assert detail.field == "age"
        assert detail.details == {"min_value": 0}


# ── ErrorResponse ────────────────────────────────────────────────────

class TestErrorResponse:
    def test_minimal(self):
        resp = ErrorResponse(
            error="bad_request",
            message="Invalid input",
            status_code=400,
        )
        assert resp.error == "bad_request"
        assert resp.status_code == 400
        assert resp.details is None
        assert resp.correlation_id is None

    def test_with_details(self):
        detail = ErrorDetail(code="validation_error", message="Required")
        resp = ErrorResponse(
            error="validation_error",
            message="Validation failed",
            status_code=422,
            details=[detail],
            correlation_id="req-123",
        )
        assert len(resp.details) == 1
        assert resp.correlation_id == "req-123"


# ── create_error_response ───────────────────────────────────────────

class TestCreateErrorResponse:
    def test_basic(self):
        resp = create_error_response(
            error_code=ErrorCode.BAD_REQUEST,
            message="Bad request",
            status_code=400,
        )
        assert resp["error"] == "bad_request"
        assert resp["message"] == "Bad request"
        assert resp["status_code"] == 400
        assert "timestamp" in resp

    def test_with_correlation_id(self):
        resp = create_error_response(
            error_code=ErrorCode.INTERNAL_ERROR,
            message="Oops",
            status_code=500,
            correlation_id="corr-456",
        )
        assert resp["correlation_id"] == "corr-456"

    def test_without_correlation_id(self):
        resp = create_error_response(
            error_code=ErrorCode.NOT_FOUND,
            message="Not found",
            status_code=404,
        )
        assert "correlation_id" not in resp

    def test_with_details(self):
        details = [
            ErrorDetail(code="validation_error", message="Required", field="name")
        ]
        resp = create_error_response(
            error_code=ErrorCode.VALIDATION_ERROR,
            message="Validation failed",
            status_code=422,
            details=details,
        )
        assert "details" in resp
        assert len(resp["details"]) == 1


# ── validation_error_response ───────────────────────────────────────

class TestValidationErrorResponse:
    def test_basic(self):
        errors = [
            {"msg": "Field required", "loc": ["body", "name"]},
            {"msg": "Must be > 0", "loc": ["body", "age"]},
        ]
        resp = validation_error_response(errors=errors)
        assert resp["error"] == "validation_error"
        assert resp["status_code"] == 422
        assert "details" in resp
        assert len(resp["details"]) == 2

    def test_custom_message(self):
        resp = validation_error_response(
            message="Custom validation error",
            errors=[{"msg": "bad"}],
        )
        assert resp["message"] == "Custom validation error"

    def test_with_correlation_id(self):
        resp = validation_error_response(
            errors=[{"msg": "err"}],
            correlation_id="corr-789",
        )
        assert resp["correlation_id"] == "corr-789"


# ── not_found_error_response ────────────────────────────────────────

class TestNotFoundErrorResponse:
    def test_basic(self):
        resp = not_found_error_response(
            resource="artifact",
            resource_id="abc-123",
        )
        assert resp["error"] == "not_found"
        assert resp["status_code"] == 404
        assert "Artifact not found: abc-123" in resp["message"]

    def test_with_correlation_id(self):
        resp = not_found_error_response(
            resource="decision",
            resource_id="d-456",
            correlation_id="corr-999",
        )
        assert resp["correlation_id"] == "corr-999"


# ── internal_error_response ─────────────────────────────────────────

class TestInternalErrorResponse:
    def test_default_message(self):
        resp = internal_error_response()
        assert resp["error"] == "internal_server_error"
        assert resp["status_code"] == 500
        assert "internal error" in resp["message"].lower()

    def test_custom_message(self):
        resp = internal_error_response(message="Database connection failed")
        assert resp["message"] == "Database connection failed"


# ── rate_limit_error_response ───────────────────────────────────────

class TestRateLimitErrorResponse:
    def test_basic(self):
        resp = rate_limit_error_response(retry_after=60)
        assert resp["error"] == "rate_limit_exceeded"
        assert resp["status_code"] == 429
        assert "60" in resp["message"]

    def test_with_correlation_id(self):
        resp = rate_limit_error_response(
            retry_after=30,
            correlation_id="rl-001",
        )
        assert resp["correlation_id"] == "rl-001"
