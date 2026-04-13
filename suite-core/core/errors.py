"""
ALDECI Error Hierarchy.

Provides a structured exception tree for all ALDECI components so callers
can catch errors at the right level of granularity instead of relying on
bare ``except Exception``.

Usage::

    from core.errors import ConnectorError, ScannerError

    try:
        connector.pull(...)
    except ConnectorError as exc:
        logger.error("connector failed", error=str(exc))
        raise
"""

from __future__ import annotations


class ALDECIError(Exception):
    """Base class for all ALDECI exceptions."""


class ScannerError(ALDECIError):
    """Raised when a scanner or parser fails to process output."""


class ConnectorError(ALDECIError):
    """Raised when a pull or bidirectional connector encounters an error."""


class TrustGraphError(ALDECIError):
    """Raised when TrustGraph operations (query, index, sync) fail."""


class AuthError(ALDECIError):
    """Raised on authentication or authorisation failures."""


class ValidationError(ALDECIError):
    """Raised when input data fails schema or semantic validation."""


class RateLimitError(ALDECIError):
    """Raised when a rate limit is exceeded (internal or external)."""


class ExternalServiceError(ALDECIError):
    """Raised when an external service (API, webhook, LLM provider) returns an error."""
