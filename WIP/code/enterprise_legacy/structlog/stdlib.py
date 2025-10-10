"""Subset of ``structlog.stdlib`` used by the FixOps codebase."""

from __future__ import annotations

import logging
from typing import Any, Dict


def filter_by_level(logger: logging.Logger, method_name: str, event_dict: Dict[str, Any]) -> Dict[str, Any]:
    return event_dict


def add_logger_name(logger: logging.Logger, method_name: str, event_dict: Dict[str, Any]) -> Dict[str, Any]:
    event_dict.setdefault("logger", logger.name)
    return event_dict


def add_log_level(logger: logging.Logger, method_name: str, event_dict: Dict[str, Any]) -> Dict[str, Any]:
    event_dict.setdefault("level", method_name)
    return event_dict


class PositionalArgumentsFormatter:
    def __call__(self, logger: logging.Logger, method_name: str, event_dict: Dict[str, Any]) -> Dict[str, Any]:
        return event_dict


class LoggerFactory:
    def __call__(self, *args: Any, **kwargs: Any) -> logging.Logger:
        name = kwargs.get("name")
        return logging.getLogger(name)


BoundLogger = logging.Logger


__all__ = [
    "filter_by_level",
    "add_logger_name",
    "add_log_level",
    "PositionalArgumentsFormatter",
    "LoggerFactory",
    "BoundLogger",
]
