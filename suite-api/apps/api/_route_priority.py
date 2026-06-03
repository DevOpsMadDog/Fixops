"""Shared helper: ensure literal routes match before greedy ``/{param}`` routes.

Starlette matches routes in list order, so a ``/{id}`` route defined *before* literal
sub-paths (e.g. ``/stats``, ``/summary``, ``/health``) silently swallows them — the
literal is resolved as ``id="stats"`` and returns the param handler's 404. Call
``prioritize_literal_routes(router)`` at the END of a router module (after all routes
are declared, before the router is mounted) to reorder once at import time:
fully-literal paths first, then ``{param}`` paths.

This is always safe: an exact literal match is the desired winner over a pattern match,
and reordering preserves relative order within each group.
"""

from __future__ import annotations

from fastapi import APIRouter


def prioritize_literal_routes(router: APIRouter) -> None:
    """Reorder ``router.routes`` so fully-literal paths precede ``{param}`` paths."""
    literal, param = [], []
    for route in list(router.routes):
        if "{" in getattr(route, "path", ""):
            param.append(route)
        else:
            literal.append(route)
    router.routes[:] = literal + param
