"""Compat package exposing the FastAPI factory for uvicorn."""
from .app import create_app

__all__ = ["create_app"]
