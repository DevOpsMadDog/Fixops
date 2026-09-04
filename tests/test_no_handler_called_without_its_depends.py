"""A route handler called directly never gets its Depends resolved.

FastAPI evaluates Depends() only when IT calls the function. Call the handler
yourself and the parameter keeps its default — the Depends object — which then
travels wherever the value would have gone. Measured on the CISO dashboard:

    GET /api/v1/analytics/dashboard/executive -> 500
    sqlite3.ProgrammingError: Error binding parameter 1:
    type 'Depends' is not supported

get_dashboard_executive called executive_summary(request) directly, so org_id
stayed a Depends object and went into SQL. Nothing caught it: the module
imports, the route registers, and Depends is inert until FastAPI resolves it.

This test scans for handlers decorated with @router.<verb> that have
Depends()-defaulted parameters and are ALSO called directly with fewer
arguments than they declare.

VALIDATED: against the pre-fix analytics_router the same scan reports 10
findings including executive_summary; against the fixed tree, 9 — all of them
health endpoints that currently ignore the leaked value, and none returning 500
when probed live. They are latent, not broken, and are listed here so the count
is a known baseline rather than an unexplained number.
"""

from __future__ import annotations

import ast
import pathlib

API = pathlib.Path(__file__).resolve().parents[1] / "suite-api" / "apps" / "api"

# Latent instances measured 2026-09-04: all return 200 because the handler never
# uses the leaked parameter. Each becomes a 500 the moment someone does.
KNOWN_LATENT = 9


def _leaks(path: pathlib.Path) -> list[str]:
    try:
        tree = ast.parse(path.read_text())
    except SyntaxError:
        return []
    handlers: dict[str, int] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        decorated = any(
            isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
            and isinstance(d.func.value, ast.Name) and d.func.value.id == "router"
            for d in node.decorator_list
        )
        if not decorated or not node.args.defaults:
            continue
        has_depends = any(
            isinstance(d, ast.Call) and isinstance(d.func, ast.Name) and d.func.id == "Depends"
            for d in node.args.defaults
        )
        if has_depends:
            handlers[node.name] = len(node.args.args)

    out = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id in handlers):
            supplied = len(node.args) + len(node.keywords)
            if supplied < handlers[node.func.id]:
                out.append(f"{path.name}:{node.lineno} {node.func.id}() "
                           f"supplied {supplied}/{handlers[node.func.id]}")
    return out


def test_the_count_of_unresolved_depends_calls_does_not_grow() -> None:
    found: list[str] = []
    for path in sorted(API.glob("*.py")):
        found.extend(_leaks(path))
    assert len(found) <= KNOWN_LATENT, (
        f"{len(found)} handlers are called without their Depends resolved "
        f"(baseline {KNOWN_LATENT}). Each is a 500 waiting for someone to use "
        f"the parameter:\n  " + "\n  ".join(found[:20])
    )


def test_the_executive_dashboard_is_not_among_them() -> None:
    """The one that was actually returning 500."""
    found = _leaks(API / "analytics_router.py")
    assert not any("executive_summary" in f for f in found), found


def test_the_scan_detects_a_planted_leak(tmp_path) -> None:
    """A baseline count means nothing if the scan has stopped working."""
    src = (
        "from fastapi import APIRouter, Depends, Request\n"
        "router = APIRouter()\n"
        "def get_org_id():\n"
        "    return 'x'\n"
        "\n"
        "@router.get('/a')\n"
        "async def handler(request: Request, org_id: str = Depends(get_org_id)):\n"
        "    return org_id\n"
        "\n"
        "@router.get('/b')\n"
        "async def caller(request: Request):\n"
        "    return await handler(request)\n"
    )
    path = tmp_path / "planted_router.py"
    path.write_text(src)
    assert _leaks(path), "the scan missed a planted unresolved-Depends call"
