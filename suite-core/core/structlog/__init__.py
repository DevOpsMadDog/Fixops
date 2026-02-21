"""Minimal structlog compatibility layer for offline environments."""

from __future__ import annotations

import logging
from typing import Any

from . import processors, stdlib  # noqa: F401  (re-exported)

_CONFIGURED = False


def configure(*args: Any, **kwargs: Any) -> None:
    """Lightweight replacement for :func:`structlog.configure`.

    The real library wires a complex processor pipeline. Our fallback simply
    ensures the standard logging module is initialised so calls to
    :func:`get_logger` return usable loggers.
    """

    global _CONFIGURED
    if not _CONFIGURED:
        kwargs.get("cache_logger_on_first_use")
        logging.basicConfig(level=logging.INFO)
        _CONFIGURED = True


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a standard library logger."""

    configure()
    return logging.getLogger(name or "fixops")


__all__ = [
    "configure",
    "get_logger",
    "processors",
    "stdlib",
]
