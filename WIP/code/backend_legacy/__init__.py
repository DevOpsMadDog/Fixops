"""Compatibility wrapper for the legacy `backend` package path."""

from apps.api.app import create_app

__all__ = ["create_app"]
