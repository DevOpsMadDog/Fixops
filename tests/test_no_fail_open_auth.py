"""Regression guard: no router may ship a FAIL-OPEN auth fallback.

GAP_MAP auth sweep (2026-06-22) fixed two fail-open idioms that drop endpoints to
unauthenticated if `from apps.api.auth_deps import api_key_auth` ever fails:
  1. `_AUTH_DEP = []`  (empty dependency list)
  2. a fallback `def api_key_auth(): return None` / `return "anon"` (permissive)
This test keeps them from coming back. Pure source scan — no app boot.
"""

from __future__ import annotations

import pathlib
import re

_ROOTS = [
    pathlib.Path(__file__).resolve().parent.parent / "suite-api" / "apps" / "api",
    pathlib.Path(__file__).resolve().parent.parent / "suite-core" / "api",
]
_EMPTY_DEP = re.compile(r"^\s*_?AUTH_DEP\s*(:\s*list)?\s*=\s*\[\s*\]\s*$", re.M)
# a fallback auth function whose body just returns None / a string (permissive)
_PERMISSIVE_FN = re.compile(
    r"def\s+api_key_auth\s*\([^)]*\)[^:]*:\s*(?:#[^\n]*\n\s*)?return\s+(None|['\"]\w+['\"])",
)


def _py_files():
    for root in _ROOTS:
        if root.exists():
            yield from root.rglob("*.py")


def test_no_empty_auth_dep_fallback():
    offenders = [p.name for p in _py_files() if _EMPTY_DEP.search(p.read_text())]
    assert not offenders, (
        "Fail-OPEN auth: these routers set the auth dep list to [] (unauthenticated "
        f"if auth import fails). Use a fail-closed dep that raises 503: {sorted(offenders)}"
    )


def test_no_permissive_api_key_auth_fallback():
    offenders = [p.name for p in _py_files() if _PERMISSIVE_FN.search(p.read_text())]
    assert not offenders, (
        "Fail-OPEN auth: these define a permissive api_key_auth fallback returning "
        f"None/'anon'. Make the fallback raise HTTPException(503): {sorted(offenders)}"
    )
