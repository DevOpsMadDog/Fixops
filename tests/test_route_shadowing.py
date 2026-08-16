"""No concrete route may be shadowed by an earlier ``{param}`` route.

Starlette serves the first route whose pattern matches. With 800+ routers mounted from
many files, registration order is effectively accidental — so a generic
``/api/v1/workflows/{id}`` mounted before a specific ``/api/v1/workflows/stats`` swallows
it. The specific endpoint still exists, still imports, and still passes its own tests
against a TestClient; it is simply unreachable in the running application.

Measured 2026-08-17 before the fix: **55 concrete GET routes were permanently
unreachable**, 14 of them under ``/api/v1/connectors`` — part of the integration surface
the product is sold on. ``/api/v1/workflows/stats`` answered "Workflow not found" because
``{id}`` matched with ``id="stats"``; ``/api/v1/changes/health`` answered "Change health
not found" for the same reason.

This is the class of bug that unit tests cannot catch, because in isolation each router
is fine. It only appears once everything is mounted together — so it is asserted here,
against the fully assembled app.
"""

from __future__ import annotations

import collections
from typing import Dict, List, Tuple

import pytest

from apps.api.app import create_app

HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}


@pytest.fixture(scope="module")
def app():
    return create_app()


def _pattern_matches(pattern: str, concrete: str) -> bool:
    """Would ``pattern`` capture a request for the literal path ``concrete``?"""
    left = pattern.split("/")
    right = concrete.split("/")
    if len(left) != len(right):
        return False
    return all(part.startswith("{") or part == other for part, other in zip(left, right))


def _routes(app) -> List[Tuple[int, str, str]]:
    collected: List[Tuple[int, str, str]] = []
    for index, route in enumerate(app.router.routes):
        path = getattr(route, "path", "") or ""
        if not path.startswith("/api/"):
            continue
        for method in getattr(route, "methods", set()) or set():
            if method in HTTP_METHODS:
                collected.append((index, method, path))
    return collected


def _shadowed(app) -> List[Tuple[str, str, str]]:
    by_method: Dict[str, List[Tuple[int, str]]] = collections.defaultdict(list)
    for index, method, path in _routes(app):
        by_method[method].append((index, path))

    found: List[Tuple[str, str, str]] = []
    for method, entries in by_method.items():
        parameterised = [(i, p) for i, p in entries if "{" in p]
        concrete = [(i, p) for i, p in entries if "{" not in p]
        for concrete_index, concrete_path in concrete:
            for param_index, param_path in parameterised:
                if param_index < concrete_index and _pattern_matches(
                    param_path, concrete_path
                ):
                    found.append((method, concrete_path, param_path))
                    break
    return found


def test_no_concrete_route_is_unreachable(app) -> None:
    shadowed = _shadowed(app)
    detail = "\n".join(
        f"  {method} {path}  <-- swallowed by {by}" for method, path, by in shadowed[:20]
    )
    assert not shadowed, (
        f"{len(shadowed)} concrete routes are unreachable in the assembled app:\n{detail}"
    )


def test_specific_endpoints_that_regressed_before_are_registered_first(app) -> None:
    """Spot-check the exact paths that were broken, so the fix cannot silently lapse."""
    positions: Dict[str, List[int]] = collections.defaultdict(list)
    for index, method, path in _routes(app):
        if method == "GET":
            positions[path].append(index)

    for concrete, generic in (
        ("/api/v1/workflows/stats", "/api/v1/workflows/{id}"),
        ("/api/v1/changes/health", "/api/v1/changes/{change_id}"),
    ):
        assert positions.get(concrete), f"{concrete} is no longer registered"
        if positions.get(generic):
            assert min(positions[concrete]) < min(positions[generic]), (
                f"{concrete} is registered after {generic} and would be shadowed again"
            )


def test_the_spa_catch_all_stays_last(app) -> None:
    """Reordering must not promote an API route past the SPA fallback."""
    routes = app.router.routes
    catch_all = [
        index
        for index, route in enumerate(routes)
        if ":path}" in (getattr(route, "path", "") or "")
    ]
    if not catch_all:
        pytest.skip("no SPA catch-all mounted in this configuration")
    api_indices = [
        index
        for index, route in enumerate(routes)
        if (getattr(route, "path", "") or "").startswith("/api/")
    ]
    assert max(api_indices) < max(catch_all), (
        "an API route is registered after the SPA catch-all and is unreachable"
    )
