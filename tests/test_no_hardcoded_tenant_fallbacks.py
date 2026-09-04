"""A tenant must never be decided by a constant.

Two routers resolved the caller's organisation like this:

    def _get_org_id() -> str:
        return "default"

connectors_router as an ImportError fallback, playbook_routes as its actual
implementation. The playbook one collapsed twelve mounted routes onto a single
shared org: any tenant could read, overwrite and execute any other tenant's
incident-response playbooks, while the 403 check written to prevent exactly
that compared "default" to "default" and never fired.

The connectors one was fail-OPEN in waiting. That branch is not hypothetical —
deduplication_router took its own ImportError fallback in this codebase, which
is how the NameError inside it was discovered.

The rule this encodes: a function whose job is to say WHICH TENANT is speaking
must derive that from the request. If it cannot see the request or a
dependency, it cannot know, and returning a plausible constant is the worst
available answer — it does not fail, it silently merges tenants.
"""

from __future__ import annotations

import ast
import pathlib

REPO = pathlib.Path(__file__).resolve().parents[1]
ROOTS = ["suite-api/apps/api", "suite-core/api"]


def _offenders(paths) -> list[str]:
    problems: list[str] = []
    for path in paths:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            name = node.name.lower()
            if "org" not in name and "tenant" not in name:
                continue

            # Body is a single `return "<literal>"`, docstring aside.
            body = [
                stmt for stmt in node.body
                if not (isinstance(stmt, ast.Expr)
                        and isinstance(stmt.value, ast.Constant))
            ]
            if len(body) != 1 or not isinstance(body[0], ast.Return):
                continue
            returned = body[0].value
            if not (isinstance(returned, ast.Constant)
                    and isinstance(returned.value, str)):
                continue

            # Does it look at the request at all?
            defaults = [d for d in
                        list(node.args.defaults) + list(node.args.kw_defaults) if d]
            takes_dependency = any(
                isinstance(d, ast.Call) and getattr(d.func, "id", None) == "Depends"
                for d in defaults
            )
            takes_request = any(
                a.arg in ("request", "req")
                for a in node.args.args + node.args.kwonlyargs
            )
            if takes_dependency or takes_request:
                continue

            try:
                rel = path.relative_to(REPO).as_posix()
            except ValueError:
                rel = str(path)
            problems.append(
                f"{rel}:{node.lineno} {node.name}() returns the constant "
                f"{returned.value!r} without reading the request or a dependency"
            )
    return problems


def _router_files():
    for root in ROOTS:
        base = REPO / root
        if base.is_dir():
            for path in base.rglob("*.py"):
                if not path.is_symlink():
                    yield path


def test_no_router_decides_the_tenant_with_a_constant() -> None:
    problems = _offenders(_router_files())
    assert not problems, (
        "A tenant resolver returns a hardcoded organisation. Every caller then "
        "shares one tenant's data, and any org check downstream compares that "
        "constant to itself and passes:\n  " + "\n  ".join(problems)
    )


def test_this_gate_catches_the_shape_it_was_written_for(tmp_path) -> None:
    """Plant both real defects; a scanner that matches nothing passes forever."""
    planted = tmp_path / "planted_router.py"
    planted.write_text(
        "def _get_org_id() -> str:\n"
        '    """Extract org_id from request context. In production, from JWT."""\n'
        '    return "default"\n'
    )
    problems = _offenders([planted])
    assert len(problems) == 1, f"the gate missed the known defect: {problems}"
    assert "_get_org_id" in problems[0] and "'default'" in problems[0]


def test_the_corrected_forms_are_not_flagged(tmp_path) -> None:
    """Credential-derived resolvers must pass, or the gate is noise.

    Both accepted shapes appear in the real fixes: wrapping the dependency,
    and reading request.state where the auth layer wrote the validated org.
    """
    ok = tmp_path / "ok_router.py"
    ok.write_text(
        "from fastapi import Depends, Request\n"
        "def _org_via_dependency(org_id: str = Depends(get_org_id)) -> str:\n"
        '    return org_id or "default"\n'
        "def _org_via_request(request: Request) -> str:\n"
        "    state_org = getattr(request.state, 'org_id', None)\n"
        '    return str(state_org).strip() if state_org else "default"\n'
    )
    assert _offenders([ok]) == []
