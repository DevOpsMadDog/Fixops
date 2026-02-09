"""Structured logging helpers for the FixOps runtime."""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any, Dict, Mapping, Optional

import structlog


def setup_structured_logging() -> None:
    """Initialise a predictable structlog pipeline."""

    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


async def log_security_event(
    action: str,
    *,
    user_id: str | None = None,
    ip_address: str | None = None,
    resource: str | None = None,
    success: bool = True,
    details: Mapping[str, Any] | None = None,
    error: str | None = None,
) -> None:
    """Emit a structured security audit record."""

    logger = structlog.get_logger().bind(category="security")
    payload = {
        "action": action,
        "user_id": user_id,
        "ip_address": ip_address or "unknown",
        "resource": resource,
        "success": success,
        "details": dict(details or {}),
        "error": error,
        "timestamp": datetime.utcnow().isoformat(),
    }
    logger.info("audit.event", **payload)


class PerformanceLogger:
    """Helpers for emitting latency and throughput signals."""

    @staticmethod
    def log_hot_path_performance(
        endpoint: str,
        latency_us: float,
        *,
        target_us: float | None = None,
        user_id: str | None = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        logger = structlog.get_logger().bind(category="performance")
        payload = {
            "endpoint": endpoint,
            "latency_us": latency_us,
            "target_us": target_us,
            "user_id": user_id,
            "timestamp": datetime.utcnow().isoformat(),
        }
        if extra:
            payload.update(extra)
        level = "warning" if target_us and latency_us > target_us else "info"
        getattr(logger, level)("hot_path.latency", **payload)

    @staticmethod
    def log_database_operation(
        operation: str,
        duration_ms: float,
        *,
        table: str | None = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        logger = structlog.get_logger().bind(category="performance")
        payload = {
            "operation": operation,
            "duration_ms": duration_ms,
            "table": table,
            "timestamp": datetime.utcnow().isoformat(),
        }
        if extra:
            payload.update(extra)
        level = "warning" if duration_ms > 100 else "debug"
        getattr(logger, level)("database.operation", **payload)


async def _log_background(name: str, **payload: Any) -> None:
    logger = structlog.get_logger().bind(category="background")
    logger.info(name, **payload)


def log_background_event(name: str, **payload: Any) -> None:
    """Fire and forget background log emission."""

    asyncio.create_task(_log_background(name, **payload))


__all__ = [
    "setup_structured_logging",
    "log_security_event",
    "PerformanceLogger",
    "log_background_event",
]
