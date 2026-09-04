"""A route's auth dependency must be satisfiable by a credential we issue.

``core.enterprise.security.verify_token`` requires ``iss: fixops-enterprise``
and ``aud: fixops-api``. The only function that sets those claims is
``SecurityManager.create_access_token`` — and it has **zero call sites**. The
login endpoint uses a different minter, whose tokens carry neither claim.

So every route guarded by the enterprise ``get_current_user`` answered 401 to
every credential the product can produce, including a freshly-minted valid
login, for as long as it had existed. Nothing failed loudly: the route was
mounted, the tests that existed did not call it authenticated, and the 401
looked like ordinary auth rather than a gate no key fits.

Two of the three such routes are now on the same dependency as the rest of
their router. The third is deliberately still closed — see the test below.
"""

from __future__ import annotations

import ast
import pathlib

REPO = pathlib.Path(__file__).resolve().parents[1]
DECISIONS = REPO / "suite-core" / "api" / "decisions.py"


def _handlers_using(dependency: str, path: pathlib.Path) -> set[str]:
    """Names of async handlers taking ``Depends(<dependency>)``."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
            continue
        for default in node.args.defaults + node.args.kw_defaults:
            if (
                isinstance(default, ast.Call)
                and getattr(default.func, "id", None) == "Depends"
                and default.args
                and getattr(default.args[0], "id", None) == dependency
            ):
                found.add(node.name)
    return found


def test_the_enterprise_token_minter_still_has_no_callers() -> None:
    """The fact the fix rests on. If this changes, revisit the routes below.

    Counted by AST rather than grep: the first version of this test matched the
    word in its own docstring and failed on prose. A call site is a call, not a
    mention.
    """
    call_sites: list[str] = []
    for suite in ("suite-api", "suite-core"):
        for path in (REPO / suite).rglob("*.py"):
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except (SyntaxError, UnicodeDecodeError):
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                name = getattr(func, "attr", None) or getattr(func, "id", None)
                if name == "create_access_token":
                    rel = path.relative_to(REPO).as_posix()
                    call_sites.append(f"{rel}:{node.lineno}")
    assert not call_sites, (
        "Something now mints enterprise-issuer tokens:\n  "
        + "\n  ".join(call_sites)
        + "\nIf tokens with iss=fixops-enterprise are actually issued, the "
          "enterprise get_current_user gate becomes satisfiable and the routes "
          "moved off it should be reconsidered."
    )


def test_only_the_known_closed_route_uses_the_unsatisfiable_gate() -> None:
    """A new route on this gate would 401 forever. Fail here instead."""
    using = _handlers_using("get_current_user", DECISIONS)
    assert using == {"get_evidence_record"}, (
        f"routes depending on the enterprise get_current_user: {sorted(using)}.\n"
        "Only get_evidence_record may, and only because it is the one route "
        "here returning tenant data while no tenant column exists to scope it "
        "by. Any other route on this dependency answers 401 to every "
        "credential the product issues — use get_org_id, which the rest of "
        "this router uses and which sits behind the same middleware auth."
    )


def test_the_reachable_routes_declare_that_their_counts_are_not_tenant_scoped() -> None:
    """Aggregates that cannot be filtered must say so.

    The enterprise models (services, security_findings, policy_decision_logs)
    have no org_id column, so these totals span the deployment. Saying it is
    what separates an honest aggregate from the copilot defect, where another
    tenant's counts were returned as the caller's own.
    """
    source = DECISIONS.read_text(encoding="utf-8")
    assert source.count('"scope": "deployment-wide"') == 2


def test_the_enterprise_models_really_have_no_tenant_column() -> None:
    """Pin the premise. When tenancy lands there, this fails and the
    deployment-wide markers above should be revisited rather than left to
    quietly understate what the endpoint now knows."""
    models = REPO / "suite-core" / "core" / "models" / "enterprise"
    with_org = [
        p.relative_to(REPO).as_posix()
        for p in models.rglob("*.py")
        if "org_id" in p.read_text(encoding="utf-8")
    ]
    assert not with_org, (
        "enterprise models gained an org_id column: " + ", ".join(with_org)
    )
