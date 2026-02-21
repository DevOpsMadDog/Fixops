"""Standardized error response formats for API endpoints."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import status
from pydantic import BaseModel


class ErrorDetail(BaseModel):
    """Detailed error information."""

    code: str
    message: str
    field: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class ErrorResponse(BaseModel):
    """Standardized error response format."""

    error: str
    message: str
    status_code: int
    details: Optional[list[ErrorDetail]] = None
    correlation_id: Optional[str] = None
    timestamp: Optional[str] = None


class ErrorCode:
    """Standard error codes for the API."""

    BAD_REQUEST = "bad_request"
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    VALIDATION_ERROR = "validation_error"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    PAYLOAD_TOO_LARGE = "payload_too_large"

    INTERNAL_ERROR = "internal_server_error"
    SERVICE_UNAVAILABLE = "service_unavailable"
    GATEWAY_TIMEOUT = "gateway_timeout"
    DEPENDENCY_FAILURE = "dependency_failure"


def create_error_response(
    *,
    error_code: str,
    message: str,
    status_code: int,
    details: Optional[list[ErrorDetail]] = None,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create a standardized error response.

    Args:
        error_code: Error code (use ErrorCode constants)
        message: Human-readable error message
        status_code: HTTP status code
        details: Optional list of detailed error information
        correlation_id: Optional correlation ID for tracing

    Returns:
        Error response dictionary
    """
    from datetime import datetime

    response = {
        "error": error_code,
        "message": message,
        "status_code": status_code,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }

    if details:
        response["details"] = [d.dict() for d in details]

    if correlation_id:
        response["correlation_id"] = correlation_id

    return response


def validation_error_response(
    *,
    message: str = "Validation failed",
    errors: list[Dict[str, Any]],
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create a validation error response.

    Args:
        message: Error message
        errors: List of validation errors
        correlation_id: Optional correlation ID

    Returns:
        Error response dictionary
    """
    details = [
        ErrorDetail(
            code=ErrorCode.VALIDATION_ERROR,
            message=error.get("msg", "Validation error"),
            field=".".join(str(loc) for loc in error.get("loc", [])),
        )
        for error in errors
    ]

    return create_error_response(
        error_code=ErrorCode.VALIDATION_ERROR,
        message=message,
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        details=details,
        correlation_id=correlation_id,
    )


def not_found_error_response(
    *,
    resource: str,
    resource_id: str,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create a not found error response.

    Args:
        resource: Resource type (e.g., "artifact", "decision")
        resource_id: Resource identifier
        correlation_id: Optional correlation ID

    Returns:
        Error response dictionary
    """
    return create_error_response(
        error_code=ErrorCode.NOT_FOUND,
        message=f"{resource.capitalize()} not found: {resource_id}",
        status_code=status.HTTP_404_NOT_FOUND,
        correlation_id=correlation_id,
    )


def internal_error_response(
    *,
    message: str = "An internal error occurred",
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create an internal server error response.

    Args:
        message: Error message
        correlation_id: Optional correlation ID

    Returns:
        Error response dictionary
    """
    return create_error_response(
        error_code=ErrorCode.INTERNAL_ERROR,
        message=message,
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        correlation_id=correlation_id,
    )


def rate_limit_error_response(
    *,
    retry_after: int,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create a rate limit error response.

    Args:
        retry_after: Seconds until retry is allowed
        correlation_id: Optional correlation ID

    Returns:
        Error response dictionary
    """
    return create_error_response(
        error_code=ErrorCode.RATE_LIMIT_EXCEEDED,
        message=f"Rate limit exceeded. Retry after {retry_after} seconds.",
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        correlation_id=correlation_id,
    )
