"""Structured logging configuration with correlation IDs for enterprise observability."""

from __future__ import annotations

import contextvars
import logging
import sys
from typing import Any, Dict, Optional

import structlog

correlation_id_ctx: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "correlation_id", default=None
)


def get_correlation_id() -> Optional[str]:
    """Get the current correlation ID from context."""
    return correlation_id_ctx.get()


def set_correlation_id(correlation_id: str) -> None:
    """Set the correlation ID in context."""
    correlation_id_ctx.set(correlation_id)


def clear_correlation_id() -> None:
    """Clear the correlation ID from context."""
    correlation_id_ctx.set(None)


def add_correlation_id(
    logger: logging.Logger, method_name: str, event_dict: Dict[str, Any]
) -> Dict[str, Any]:
    """Add correlation ID to log event if present in context."""
    correlation_id = get_correlation_id()
    if correlation_id:
        event_dict["correlation_id"] = correlation_id
    return event_dict


def add_service_context(
    logger: logging.Logger, method_name: str, event_dict: Dict[str, Any]
) -> Dict[str, Any]:
    """Add service-level context to all log events."""
    import os

    event_dict.setdefault("service", "fixops-api")
    event_dict.setdefault("environment", os.getenv("FIXOPS_MODE", "unknown"))
    event_dict.setdefault("version", os.getenv("FIXOPS_VERSION", "0.1.0"))
    return event_dict


def redact_sensitive_data(
    logger: logging.Logger, method_name: str, event_dict: Dict[str, Any]
) -> Dict[str, Any]:
    """Redact sensitive data from logs (PII, secrets, tokens)."""
    sensitive_keys = {
        "password",
        "secret",
        "token",
        "api_key",
        "apikey",
        "authorization",
        "auth",
        "jwt",
        "bearer",
        "credential",
        "private_key",
        "access_token",
        "refresh_token",
    }

    def redact_dict(data: Any) -> Any:
        """Recursively redact sensitive keys from dictionaries."""
        if isinstance(data, dict):
            return {
                key: (
                    "***REDACTED***"
                    if key.lower() in sensitive_keys
                    else redact_dict(value)
                )
                for key, value in data.items()
            }
        elif isinstance(data, (list, tuple)):
            return [redact_dict(item) for item in data]
        return data

    for key in list(event_dict.keys()):
        if key.lower() in sensitive_keys:
            event_dict[key] = "***REDACTED***"
        elif isinstance(event_dict[key], dict):
            event_dict[key] = redact_dict(event_dict[key])

    return event_dict


def configure_structured_logging(
    *,
    log_level: str = "INFO",
    json_logs: bool = False,
    development_mode: bool = False,
) -> None:
    """
    Configure structured logging for the application.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        json_logs: If True, output logs in JSON format (recommended for production)
        development_mode: If True, use human-readable console output
    """
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, log_level.upper(), logging.INFO),
    )

    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        add_correlation_id,
        add_service_context,
        redact_sensitive_data,
    ]

    if development_mode:
        processors.extend(
            [
                structlog.processors.format_exc_info,
                structlog.dev.ConsoleRenderer(colors=True),
            ]
        )
    elif json_logs:
        processors.extend(
            [
                structlog.processors.format_exc_info,
                structlog.processors.JSONRenderer(),
            ]
        )
    else:
        processors.extend(
            [
                structlog.processors.format_exc_info,
                structlog.processors.KeyValueRenderer(
                    key_order=["timestamp", "level", "event", "correlation_id"],
                    drop_missing=True,
                ),
            ]
        )

    structlog.configure(
        processors=processors,  # type: ignore[arg-type]
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """
    Get a structured logger instance.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Structured logger instance
    """
    return structlog.get_logger(name)


__all__ = [
    "configure_structured_logging",
    "get_logger",
    "get_correlation_id",
    "set_correlation_id",
    "clear_correlation_id",
]
