"""ALdeci custom exception hierarchy.

Usage:
    from core.exceptions import DatabaseError, ScannerError, ConnectorError

All ALdeci-specific errors derive from ALdeciError so callers can catch
the base class for broad handling while still being able to distinguish
sub-types when finer-grained recovery is needed.
"""


class ALdeciError(Exception):
    """Base exception for all ALdeci errors."""

    # Alias used in task spec (ALDECI spelling)


ALDECIError = ALdeciError


class DatabaseError(ALdeciError):
    """Database operation failed (SQLite, connection, schema error)."""


class ScannerError(ALdeciError):
    """Scanner execution or output parsing failed."""


# Alias from spec
ScannerParseError = ScannerError


class AuthorizationError(ALdeciError):
    """Authorization or permission check failed."""


# Alias from spec
AuthenticationError = AuthorizationError


class TenantIsolationError(ALdeciError):
    """Cross-tenant data access attempted."""


class PipelineError(ALdeciError):
    """Brain pipeline step failed (use for unrecoverable step errors)."""


# Alias from spec
PipelineStepError = PipelineError


class ConnectorError(ALdeciError):
    """External connector (Jira, Slack, GitHub, etc.) call failed."""


class ExternalServiceError(ConnectorError):
    """External API/service call failed (HTTP errors, timeouts, etc.)."""


class LLMProviderError(ALdeciError):
    """LLM provider call failed (timeout, auth, quota, etc.)."""


class TrustGraphError(ALdeciError):
    """TrustGraph query or indexing operation failed."""


class ValidationError(ALdeciError):
    """Input validation failed — malformed request or parameter."""


class EvidenceError(ALdeciError):
    """Evidence generation or cryptographic signing failed."""


class RateLimitError(ALdeciError):
    """Rate limit exceeded — caller should back off and retry."""


class SSRFError(ValidationError):
    """SSRF-blocked URL — target is an internal/reserved address."""


class InjectionError(ValidationError):
    """Injection attempt detected in user-supplied input."""
