"""
Enterprise exception handling with security and compliance features
"""

import traceback
from typing import Dict, Any, Optional
import structlog
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from sqlalchemy.exc import SQLAlchemyError
import asyncio

from src.utils.logger import log_security_event

logger = structlog.get_logger()


class FixOpsException(Exception):
    """Base exception for FixOps application"""
    
    def __init__(
        self,
        message: str,
        error_code: str = "FIXOPS_ERROR",
        status_code: int = 500,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        self.details = details or {}


class AuthenticationError(FixOpsException):
    """Authentication related errors"""
    
    def __init__(self, message: str = "Authentication failed", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code="AUTH_ERROR",
            status_code=401,
            details=details
        )


class AuthorizationError(FixOpsException):
    """Authorization related errors"""
    
    def __init__(self, message: str = "Insufficient permissions", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code="AUTHZ_ERROR",
            status_code=403,
            details=details
        )


class ValidationError(FixOpsException):
    """Data validation errors"""
    
    def __init__(self, message: str = "Validation failed", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code="VALIDATION_ERROR",
            status_code=422,
            details=details
        )


class NotFoundError(FixOpsException):
    """Resource not found errors"""
    
    def __init__(self, message: str = "Resource not found", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code="NOT_FOUND",
            status_code=404,
            details=details
        )


class ConflictError(FixOpsException):
    """Resource conflict errors"""
    
    def __init__(self, message: str = "Resource conflict", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code="CONFLICT",
            status_code=409,
            details=details
        )


class RateLimitError(FixOpsException):
    """Rate limiting errors"""
    
    def __init__(self, message: str = "Rate limit exceeded", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code="RATE_LIMIT",
            status_code=429,
            details=details
        )


class ServiceUnavailableError(FixOpsException):
    """Service unavailable errors"""
    
    def __init__(self, message: str = "Service temporarily unavailable", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code="SERVICE_UNAVAILABLE",
            status_code=503,
            details=details
        )


class DatabaseError(FixOpsException):
    """Database related errors"""
    
    def __init__(self, message: str = "Database operation failed", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code="DATABASE_ERROR",
            status_code=500,
            details=details
        )


class CacheError(FixOpsException):
    """Cache related errors"""
    
    def __init__(self, message: str = "Cache operation failed", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code="CACHE_ERROR",
            status_code=500,
            details=details
        )


class SecurityError(FixOpsException):
    """Security related errors"""
    
    def __init__(self, message: str = "Security violation detected", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code="SECURITY_ERROR",
            status_code=403,
            details=details
        )


class ComplianceError(FixOpsException):
    """Compliance related errors"""
    
    def __init__(self, message: str = "Compliance violation", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code="COMPLIANCE_ERROR",
            status_code=400,
            details=details
        )


async def log_exception_security_event(
    request: Request,
    exception: Exception,
    user_id: Optional[str] = None
):
    """Log security-relevant exceptions for monitoring"""
    
    # Determine if this is a security-relevant exception
    security_relevant = isinstance(exception, (
        AuthenticationError,
        AuthorizationError,
        SecurityError,
        RateLimitError
    ))
    
    if security_relevant:
        # Don't await - run in background to not impact response time
        asyncio.create_task(
            log_security_event(
                action="security_exception",
                user_id=user_id,
                ip_address=request.client.host if request.client else "unknown",
                user_agent=request.headers.get("user-agent"),
                details={
                    "exception_type": type(exception).__name__,
                    "message": str(exception),
                    "path": str(request.url.path),
                    "method": request.method
                },
                success=False
            )
        )


def create_error_response(
    error_code: str,
    message: str,
    status_code: int,
    details: Optional[Dict[str, Any]] = None,
    request_id: Optional[str] = None
) -> JSONResponse:
    """Create standardized error response"""
    
    error_response = {
        "error": {
            "code": error_code,
            "message": message,
            "timestamp": "2024-01-01T00:00:00Z",  # This would be dynamic
        }
    }
    
    if details:
        error_response["error"]["details"] = details
    
    if request_id:
        error_response["error"]["request_id"] = request_id
    
    return JSONResponse(
        status_code=status_code,
        content=error_response,
        headers={
            "X-Error-Code": error_code,
            "X-Request-ID": request_id or "unknown"
        }
    )


def setup_exception_handlers(app: FastAPI):
    """Setup global exception handlers for the FastAPI application"""
    
    @app.exception_handler(FixOpsException)
    async def fixops_exception_handler(request: Request, exc: FixOpsException):
        """Handle custom FixOps exceptions"""
        
        # Log exception
        logger.error(
            "FixOps exception",
            error_code=exc.error_code,
            message=exc.message,
            path=request.url.path,
            method=request.method
        )
        
        # Log security events for relevant exceptions
        await log_exception_security_event(request, exc)
        
        return create_error_response(
            error_code=exc.error_code,
            message=exc.message,
            status_code=exc.status_code,
            details=exc.details,
            request_id=getattr(request.state, "correlation_id", None)
        )
    
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        """Handle FastAPI HTTP exceptions"""
        
        logger.warning(
            "HTTP exception",
            status_code=exc.status_code,
            detail=exc.detail,
            path=request.url.path,
            method=request.method
        )
        
        return create_error_response(
            error_code="HTTP_ERROR",
            message=exc.detail,
            status_code=exc.status_code,
            request_id=getattr(request.state, "correlation_id", None)
        )
    
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        """Handle request validation errors"""
        
        logger.warning(
            "Validation error",
            errors=exc.errors(),
            path=request.url.path,
            method=request.method
        )
        
        return create_error_response(
            error_code="VALIDATION_ERROR",
            message="Request validation failed",
            status_code=422,
            details={"validation_errors": exc.errors()},
            request_id=getattr(request.state, "correlation_id", None)
        )
    
    @app.exception_handler(SQLAlchemyError)
    async def database_exception_handler(request: Request, exc: SQLAlchemyError):
        """Handle database errors"""
        
        logger.error(
            "Database error",
            error=str(exc),
            path=request.url.path,
            method=request.method
        )
        
        # Don't expose internal database errors to users
        return create_error_response(
            error_code="DATABASE_ERROR",
            message="Internal database error",
            status_code=500,
            request_id=getattr(request.state, "correlation_id", None)
        )
    
    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception):
        """Handle unexpected exceptions"""
        
        # Log full traceback for debugging
        logger.error(
            "Unexpected exception",
            error=str(exc),
            traceback=traceback.format_exc(),
            path=request.url.path,
            method=request.method
        )
        
        # Log as security event if it might be an attack
        if any(keyword in str(exc).lower() for keyword in ["injection", "attack", "malicious", "exploit"]):
            await log_exception_security_event(request, exc)
        
        return create_error_response(
            error_code="INTERNAL_ERROR",
            message="Internal server error",
            status_code=500,
            request_id=getattr(request.state, "correlation_id", None)
        )
    
    @app.exception_handler(StarletteHTTPException)
    async def starlette_exception_handler(request: Request, exc: StarletteHTTPException):
        """Handle Starlette HTTP exceptions"""
        
        logger.warning(
            "Starlette HTTP exception",
            status_code=exc.status_code,
            detail=exc.detail,
            path=request.url.path,
            method=request.method
        )
        
        return create_error_response(
            error_code="HTTP_ERROR",
            message=exc.detail,
            status_code=exc.status_code,
            request_id=getattr(request.state, "correlation_id", None)
        )


# Security exception helpers
class SecurityViolationDetector:
    """Detect potential security violations in exceptions"""
    
    SUSPICIOUS_PATTERNS = [
        "sql injection",
        "xss",
        "csrf",
        "script injection",
        "path traversal",
        "../",
        "<script",
        "javascript:",
        "eval(",
        "exec(",
        "system(",
        "os.system",
        "subprocess",
        "shell_exec"
    ]
    
    @classmethod
    def is_suspicious_exception(cls, exception: Exception) -> bool:
        """Check if exception contains suspicious patterns"""
        exc_str = str(exception).lower()
        return any(pattern in exc_str for pattern in cls.SUSPICIOUS_PATTERNS)
    
    @classmethod
    def extract_security_context(cls, exception: Exception, request: Request) -> Dict[str, Any]:
        """Extract security context from exception and request"""
        return {
            "exception_type": type(exception).__name__,
            "suspicious": cls.is_suspicious_exception(exception),
            "user_agent": request.headers.get("user-agent"),
            "ip_address": request.client.host if request.client else "unknown",
            "path": str(request.url.path),
            "method": request.method,
            "query_params": str(request.query_params),
            "headers": dict(request.headers)
        }