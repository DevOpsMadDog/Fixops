"""A route with {org_id} in its path must not trust the caller's URL.

This is the single most productive defect class in this codebase. Handlers
took the tenant from the path — /orgs/{org_id}/…, /stats/{org_id},
/{org_id}/badges — and never checked it against the credential. Proven live,
one tenant could:

  * read and overwrite another tenant's incident-response playbooks, and run them
  * read and WRITE INTO another tenant's STRIDE threat models
  * publish a forged SOC2 badge on another company's PUBLIC trust page
  * read another tenant's employee training records
  * set another tenant's API rate-limit quota to the minimum tier

The fix is resolve_tenant(credential_org, …): the credential wins whenever it
pins a tenant, and only an unpinned operator credential may be directed by the
URL.

This gate holds the line. Every exception below is deliberate and explained —
an allowlist is only honest if each entry says why, because the failure mode
of a gate like this is that someone adds a name to make it pass.
"""

from __future__ import annotations

import ast
import pathlib

REPO = pathlib.Path(__file__).resolve().parents[1]
ROOTS = ["suite-api/apps/api", "suite-core/api"]

# ---------------------------------------------------------------------------
# Deliberate exceptions
# ---------------------------------------------------------------------------

# 1. VENDOR APIs. {org_id} here is NOT a FixOps tenant — it is an identifier
#    belonging to the vendor whose API is being mirrored. Resolving it against
#    the caller's credential would overwrite a Contrast/Snyk/Atlas/Workday id
#    with a FixOps org and break the endpoint. An automated pass DID patch
#    workday_router, and the resulting import failure is what exposed this.
#
#    Whose credentials do they use? Measured: DEPLOYMENT-LEVEL environment
#    variables — CONTRAST_API_KEY, SNYK_TOKEN, MONGODB_ATLAS_PUBLIC_KEY — not
#    per-tenant ones. These are therefore operator-scoped integrations, which
#    is coherent for the on-prem single-tenant deployments this product ships
#    into, and is NOT safe to expose to arbitrary tenants in a shared one: the
#    platform would use the operator's vendor key to fetch whatever vendor org
#    the URL named.
#
#    The default posture is closed, and honestly so — with the variables unset
#    each returns 503 naming exactly what is missing (test below). Anyone
#    configuring a vendor key in a multi-tenant deployment needs to gate these
#    routes to platform operators first. Recorded here rather than "fixed",
#    because bolting resolve_tenant on would break the integration without
#    addressing the credential model, which is a deployment decision.
VENDOR_ROUTERS = {
    "contrast_router.py",        # /api/ng/{org_id}/applications      — Contrast
    "snyk_router.py",            # /v1/orgs/{org_id}/projects         — Snyk
    "mongodb_atlas_router.py",   # /orgs/{org_id}/projects            — Atlas
    "workday_router.py",         # /ccx/api/staffing/v6/{tenant}/orgChart/{org_id}
}

# 2. INTENTIONALLY PUBLIC. The org in the path is the whole point: an
#    anonymous reader asks for a named company's page. Resolving it would make
#    an unauthenticated caller resolve to "default" and 404 the feature.
PUBLIC_HANDLERS = {
    "get_public_page",      # trust_center — documented "no auth required"
    "get_security_report",  # trust_center — same
    "get_public_score",     # security_scorecard — "designed for partner sharing"
}

# 3. GUARDED MORE STRICTLY THAN resolve_tenant. These demand a platform
#    operator, or operator-or-self; that is stronger, not weaker.
OPERATOR_GUARDED = {
    "get_tenant_stats_endpoint",  # _require_admin_or_self(request, org_id)
    "delete_tenant_endpoint",     # _require_admin(request) — operator only
}

# 4. PATH PARAMETER SHADOWED BY THE CREDENTIAL. The signature reads
#    `org_id: str = Depends(_get_org_id_dep)`, so FastAPI supplies the
#    credential's org and the URL segment is never read. Safe, though the
#    route still advertises a path parameter it ignores.
SHADOWED = {"get_dedup_stats"}


def _handlers():
    for root in ROOTS:
        base = REPO / root
        if not base.is_dir():
            continue
        for path in base.rglob("*.py"):
            if path.is_symlink():
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except (SyntaxError, UnicodeDecodeError):
                continue
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                routes = [d for d in node.decorator_list
                          if isinstance(d, ast.Call)
                          and getattr(d.func, "attr", "") in
                          ("get", "post", "put", "patch", "delete")]
                if not routes:
                    continue
                route = (routes[0].args[0].value
                         if routes[0].args
                         and isinstance(routes[0].args[0], ast.Constant) else "")
                if "{org_id}" not in str(route):
                    continue
                yield path, node, str(route)


def test_every_path_org_handler_resolves_the_tenant() -> None:
    offenders = []
    for path, node, route in _handlers():
        if path.name in VENDOR_ROUTERS:
            continue
        if node.name in PUBLIC_HANDLERS | OPERATOR_GUARDED | SHADOWED:
            continue
        if "resolve_tenant(" in ast.unparse(node):
            continue
        offenders.append(f"{path.relative_to(REPO).as_posix()}:{node.lineno} "
                         f"{node.name}  {route}")

    assert not offenders, (
        "These handlers take the tenant from the URL and never check it "
        "against the credential. Add resolve_tenant(credential_org, "
        "SimpleNamespace(org_id=org_id)) — or, if the route is genuinely an "
        "exception, add it to the allowlist above WITH the reason:\n  "
        + "\n  ".join(offenders)
    )


def test_the_public_handlers_have_not_been_quietly_scoped() -> None:
    """The allowlist cuts both ways.

    Scoping a public route does not look like a bug — it looks like a fix —
    and it silently removes the anonymous access the feature exists for. An
    automated pass did exactly this to get_public_score.
    """
    scoped = [
        f"{path.name}:{node.name}"
        for path, node, _ in _handlers()
        if node.name in PUBLIC_HANDLERS and "resolve_tenant(" in ast.unparse(node)
    ]
    assert not scoped, (
        f"a documented public route now resolves a tenant and will stop "
        f"answering anonymous callers: {scoped}"
    )


def test_the_gate_sees_a_real_population() -> None:
    """A scanner that matches nothing passes forever.

    If this count collapses, the detector broke — not the codebase.
    """
    total = len(list(_handlers()))
    assert total > 60, f"only {total} path-org handlers found; the scan is broken"


def test_the_allowlist_names_only_handlers_that_exist() -> None:
    """Dead allowlist entries hide regressions: a name that no longer matches
    anything is an exemption nobody is checking."""
    names = {node.name for _, node, _ in _handlers()}
    stale = (PUBLIC_HANDLERS | OPERATOR_GUARDED | SHADOWED) - names
    assert not stale, f"allowlisted handlers no longer exist: {sorted(stale)}"


def test_vendor_proxies_are_inert_until_an_operator_configures_them() -> None:
    """The default posture for the vendor exception must be closed.

    These routes are excluded from tenant scoping because {org_id} is a vendor
    identifier, so the usual protection does not apply to them. What stands in
    for it is that they do nothing at all until a deployment-level credential
    is configured — and that they say so rather than returning an empty result
    that reads like "this org has no applications".

    Skipped rather than failed when a credential IS configured: that is a
    legitimate deployment, and this test has nothing true to say about it.
    """
    import os
    import re

    for router_name, variables in (
        ("contrast_router.py", ("CONTRAST_API_KEY", "CONTRAST_BASE_URL")),
        ("snyk_router.py", ("SNYK_TOKEN",)),
        ("mongodb_atlas_router.py", ("MONGODB_ATLAS_PUBLIC_KEY",)),
    ):
        if any(os.environ.get(v) for v in variables):
            continue  # configured deployment — nothing to assert here

        source = None
        for root in ROOTS:
            candidate = REPO / root / router_name
            if candidate.is_file():
                source = candidate.read_text(encoding="utf-8")
                break
        assert source is not None, f"{router_name} not found"

        # A 503 path must exist and name the missing configuration.
        assert re.search(r"503", source), (
            f"{router_name} has no 503 not-configured path; an unconfigured "
            f"vendor integration must refuse, not return an empty result that "
            f"looks like real data"
        )
        assert any(v in source for v in variables), (
            f"{router_name} does not name the credential it needs, so an "
            f"operator cannot tell what to configure"
        )
