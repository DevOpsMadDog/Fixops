"""SPEC-031 — UI routing integrity (guards the dead-redirect class fixed 2026-06-06).

A whole class of customer-facing nav bugs was found this session: routes that
redirected to `<Navigate to="/?view=…">` — a dead query param that the index
route (→ /executive) silently stripped, so SOC / alert-triage / incident /
dev-security nav items all landed on the Executive dashboard instead of their
real workspace.

This deterministic test parses suite-ui/aldeci-ui-new/src/App.tsx and asserts the
routing invariants so the class cannot regress:

  1. No `<Navigate to="/?…">` redirects (dead root-with-query — the index redirect
     strips the query, so these never reach a real view).
  2. Every `<Navigate to="…">` target's base path (sans query) resolves to a real
     declared route (either an element-route or another declared route path).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_APP_TSX = (
    Path(__file__).resolve().parents[1]
    / "suite-ui" / "aldeci-ui-new" / "src" / "App.tsx"
)


@pytest.fixture(scope="module")
def app_src() -> str:
    if not _APP_TSX.exists():
        pytest.skip(f"App.tsx not found at {_APP_TSX}")
    return _APP_TSX.read_text(encoding="utf-8")


def test_no_dead_root_query_redirects(app_src: str) -> None:
    """No `<Navigate to="/?...">` — the index redirect to /executive strips the
    query, so these are dead (the SOC/dev/executive ?view= bug class)."""
    dead = re.findall(r'<Navigate\s+to="(/\?[^"]*)"', app_src)
    assert dead == [], f"dead root-query redirects (query gets stripped): {sorted(set(dead))}"


def test_all_navigate_targets_resolve_to_a_real_route(app_src: str) -> None:
    """Every Navigate target base-path must resolve to a declared route."""
    all_route_paths = {
        p.split("?")[0] for p in re.findall(r'<Route\s+path="([^"]+)"', app_src)
    }
    nav_targets = {
        t.split("?")[0] for t in re.findall(r'<Navigate\s+to="([^"]+)"', app_src)
    }
    unresolved = sorted(
        t for t in nav_targets
        if t and t != "/" and t not in all_route_paths
    )
    assert unresolved == [], f"Navigate targets with no matching route: {unresolved}"
