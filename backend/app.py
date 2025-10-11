"""FastAPI entrypoint compatible with the README uvicorn command."""
from __future__ import annotations

from apps.api.app import create_app as _create_app

__all__ = ["create_app"]


def create_app():
    """Return the canonical FixOps FastAPI application."""

    return _create_app()
