"""The caller must not be able to name the tenant it acts on.

Two breaches this session had the same root cause in different clothes:

* a QUERY parameter — a customer key read and wrote another tenant's data by
  putting that org in the URL (docs/SECURITY_FINDING_cross_tenant_org_id.md);
* a REQUEST BODY — ``effective_org = body.org_id or org_id``, where the model
  declared ``org_id: str = Field("default")``. A defaulted field is always
  truthy, so the body always won and the credential was unreachable. Every SOC2
  evidence pack was written into "default" while the org-scoped listing looked
  in the caller's real tenant and found nothing.

This is a RATCHET, not a full cleanup. 567 request models still declare an
``org_id`` field and 222 default it to a literal; rewriting all of them in one
pass would be reckless. What must not happen is the count growing, or a new
call site preferring caller input over the credential.
"""

from __future__ import annotations

import ast
import pathlib

REPO = pathlib.Path(__file__).resolve().parents[1]
ROUTER_DIRS = [REPO / "suite-api" / "apps" / "api", REPO / "suite-core" / "api"]


def _router_files():
    for d in ROUTER_DIRS:
        if d.exists():
            yield from sorted(d.glob("*_router*.py"))
            yield from sorted(d.glob("*_routes.py"))


def test_no_handler_prefers_caller_supplied_org_over_the_credential() -> None:
    """`body.org_id or org_id` makes the credential dead code. Zero tolerance."""
    offenders = []
    for path in _router_files():
        text = path.read_text()
        for lineno, line in enumerate(text.split("\n"), 1):
            stripped = line.strip()
            if stripped.startswith(("#", "*", '"', "'")) or "``" in line:
                continue  # prose about the pattern, not the pattern
            for pat in ("body.org_id or org_id", "req.org_id or org_id", "request.org_id or org_id"):
                if pat in stripped:
                    offenders.append(f"{path.name}:{lineno}: {stripped[:88]}")

    assert not offenders, (
        "these hand the tenant choice to the caller — use resolve_tenant(org_id, body):\n  "
        + "\n  ".join(offenders)
    )


def test_org_id_is_never_a_required_query_parameter_on_a_route() -> None:
    """A bare `org_id: str` becomes a client-settable query param."""
    offenders = []
    for path in _router_files():
        try:
            tree = ast.parse(path.read_text())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            route = None
            for dec in node.decorator_list:
                fn = dec.func if isinstance(dec, ast.Call) else dec
                if isinstance(fn, ast.Attribute) and fn.attr in {"get", "post", "put", "patch", "delete"}:
                    route = (
                        dec.args[0].value
                        if isinstance(dec, ast.Call) and dec.args and isinstance(dec.args[0], ast.Constant)
                        else ""
                    )
            if route is None or "{org_id}" in (route or ""):
                continue

            args = node.args
            defaults = dict(
                zip([a.arg for a in args.args][-len(args.defaults):] if args.defaults else [], args.defaults)
            )
            for arg in args.args:
                if arg.arg != "org_id":
                    continue
                default = defaults.get("org_id")
                if default is None:
                    offenders.append(f"{path.name}::{node.name} — bare `org_id: str` is a query param")
                elif "Depends" not in ast.unparse(default):
                    offenders.append(f"{path.name}::{node.name} — org_id = {ast.unparse(default)[:40]}")

    assert not offenders, "the tenant must come from Depends(get_org_id):\n  " + "\n  ".join(offenders)


def test_the_body_supplied_tenant_count_does_not_grow() -> None:
    """Ratchet on the remaining debt: 567 models, and it must not increase."""
    # Measured 2026-08-19, not estimated. This is debt to shrink, not a target.
    BASELINE = 773

    count = 0
    for path in _router_files():
        try:
            tree = ast.parse(path.read_text())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if not any("BaseModel" in ast.unparse(b) for b in node.bases):
                continue
            for stmt in node.body:
                if (
                    isinstance(stmt, ast.AnnAssign)
                    and isinstance(stmt.target, ast.Name)
                    and stmt.target.id == "org_id"
                ):
                    count += 1

    assert count <= BASELINE, (
        f"{count} request models let the client name its tenant, up from {BASELINE}. "
        "The tenant comes from the credential — do not add another."
    )


def test_resolve_tenant_lets_the_credential_win() -> None:
    from apps.api.tenant_resolution import resolve_tenant

    class Body:
        org_id = "someone-elses-org"

    assert resolve_tenant("org-mine", Body()) == "org-mine", "a body overrode a pinned credential"
    assert resolve_tenant("", Body()) == "someone-elses-org", "operator direction was refused"
    assert resolve_tenant("default", Body()) == "someone-elses-org", "operator direction was refused"
    assert resolve_tenant("org-mine", None) == "org-mine"
    assert resolve_tenant("", None) == "default"
