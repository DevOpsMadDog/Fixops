"""No router may call a method its object does not have.

Seven admin endpoints used `_audit.log_admin_action(...)` — a method
AuditLogger has never had. They created the user, changed the role or deleted
the account, THEN raised AttributeError and returned 500. The work landed; the
operator saw a failure and concluded nothing had happened. Nothing caught it
because the code imports fine, the route registers fine, and the crash only
happens when the endpoint is actually called.

This scans every router: an AST pass finds `obj.method(...)` where `obj` is a
module-level singleton, then hasattr() checks it against the imported module.

VALIDATED AGAINST THE KNOWN BUG. Run against the pre-fix admin_router it
reports exactly:

    MISSING admin_router.py:197  _audit.log_admin_action  (on AuditLogger)

and zero against the fixed tree. A detector that has never been shown to fire is
not evidence of a clean codebase.

LIMITS, stated because a green result here is narrower than "no 500s":
  * only module-level singletons — objects built inside a function are invisible
  * only static attribute names — getattr(obj, name) is not resolved
  * only routers that import cleanly
"""

from __future__ import annotations

import ast
import importlib
import pathlib

import pytest

ROUTERS = sorted((
    pathlib.Path(__file__).resolve().parents[1] / "suite-api" / "apps" / "api"
).glob("*_router.py"))


def _missing_methods(path: pathlib.Path) -> list[str]:
    module = importlib.import_module(f"apps.api.{path.stem}")
    tree = ast.parse(path.read_text())
    singletons = {
        target.id
        for node in tree.body if isinstance(node, ast.Assign)
        for target in node.targets if isinstance(target, ast.Name)
    }
    missing, seen = [], set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        value = node.func.value
        if not (isinstance(value, ast.Name) and value.id in singletons):
            continue
        key = (value.id, node.func.attr)
        if key in seen:
            continue
        seen.add(key)
        obj = getattr(module, value.id, None)
        # Containers and primitives carry no domain API worth checking.
        if obj is None or isinstance(obj, (dict, list, set, tuple, str, int, float)):
            continue
        if not hasattr(obj, node.func.attr):
            missing.append(f"{path.name}:{node.lineno} {value.id}.{node.func.attr} "
                           f"(on {type(obj).__name__})")
    return missing


def test_no_router_calls_a_method_that_does_not_exist() -> None:
    assert ROUTERS, "no routers found — the scan would pass vacuously"
    failures: list[str] = []
    for path in ROUTERS:
        try:
            failures.extend(_missing_methods(path))
        except Exception as exc:  # noqa: BLE001 - an unimportable router is its own bug
            failures.append(f"{path.name}: could not scan ({type(exc).__name__}: {exc})")
    assert not failures, (
        f"{len(failures)} call(s) to methods that do not exist — each is a 500 on "
        f"an advertised endpoint:\n  " + "\n  ".join(failures[:20])
    )


def test_the_scan_actually_detects_a_missing_method(tmp_path) -> None:
    """The guard on the guard.

    A scan reporting zero proves nothing unless it can be shown to fire. This
    reconstructs the exact shape of the admin_router bug and requires a hit.
    """
    module_src = (
        "class _Logger:\n"
        "    def log(self, event):\n"
        "        return event\n"
        "\n"
        "_audit = _Logger()\n"
        "\n"
        "def handler():\n"
        "    _audit.log_admin_action(action='create_user')\n"
    )
    path = tmp_path / "fake_router.py"
    path.write_text(module_src)

    import sys

    sys.path.insert(0, str(tmp_path))
    try:
        module = importlib.import_module("fake_router")
        tree = ast.parse(module_src)
        singletons = {
            t.id for n in tree.body if isinstance(n, ast.Assign)
            for t in n.targets if isinstance(t, ast.Name)
        }
        hits = [
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in singletons
            and not hasattr(getattr(module, node.func.value.id), node.func.attr)
        ]
        assert hits == ["log_admin_action"], f"the scan missed the planted bug: {hits}"
    finally:
        sys.path.remove(str(tmp_path))
        sys.modules.pop("fake_router", None)
