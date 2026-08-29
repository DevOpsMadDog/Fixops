"""A route put on the customer surface must not take its tenant from the caller.

Nine capability prefixes were added to ``_CORE_PREFIXES`` so customers could
finally see what this deployment can do. Advertising a route raises the bar on
it: a tenancy hole behind core mode is a latent bug, and the same hole on the
advertised surface is a breach with a documented path to it.

Sweeping the nine found two:

* ``function_reachability_router`` — all three POST handlers took
  ``body.org_id`` (defaulted to ``"default"``) and never looked at the
  credential, while the two GET handlers on the same router correctly used
  ``Depends(get_org_id)``. An authenticated customer could parse a call graph
  into any org they named, and read reachability back out of it.

* ``cspm_router`` — ``register_resource`` and ``trigger_scan`` took **no
  credential dependency at all**, writing wherever ``req.org_id`` pointed. Every
  other handler on that router scopes by the credential.

Both are the request-body twin of the query-parameter breach in
``docs/SECURITY_FINDING_cross_tenant_org_id.md``. This test is a source-level
guard rather than a request-level one deliberately: the defect is "the handler
never consults the credential", which is visible in the source and does not
depend on having two live tenants to prove it.
"""

from __future__ import annotations

import pathlib
import re

import pytest

API = pathlib.Path(__file__).resolve().parents[1] / "suite-api/apps/api"

# Routers backing prefixes advertised to customers in core mode.
SURFACED = [
    "function_reachability_router.py",
    "cspm_router.py",
    "sast_router.py",
    "secret_scanner_router.py",
    "iac_scanner_router.py",
    "dast_router.py",
    "autofix_router.py",
]


def _strip_comments_and_docstrings(src: str) -> str:
    """A guard that matches its own explanatory comment proves nothing.

    This module documents the bad pattern in prose above; without stripping,
    the scan would find `body.org_id` in a comment and fail on a fixed file.
    """
    src = re.sub(r'"""(?:.|\n)*?"""', "", src)
    src = re.sub(r"^\s*#.*$", "", src, flags=re.M)
    return src


@pytest.mark.parametrize("filename", SURFACED)
def test_no_surfaced_handler_trusts_a_caller_supplied_org(filename: str) -> None:
    path = API / filename
    if not path.exists():
        pytest.skip(f"{filename} not present")

    code = _strip_comments_and_docstrings(path.read_text())

    offenders = re.findall(r"\b(?:body|req|request|payload)\.org_id\b", code)
    assert not offenders, (
        f"{filename} passes a caller-supplied org_id straight through "
        f"({len(offenders)} site(s)). The credential must decide: take "
        f"org_id: str = Depends(get_org_id) and route it through "
        f"resolve_tenant(org_id, body). A body-supplied tenant is honoured only "
        f"for the unpinned operator credential."
    )


def test_the_two_fixed_routers_actually_resolve_the_tenant() -> None:
    """Absence of the bad pattern is not presence of the fix — a handler that
    dropped org_id entirely would also pass the sweep above."""
    for filename in ("function_reachability_router.py", "cspm_router.py"):
        code = (API / filename).read_text()
        assert "resolve_tenant" in code, f"{filename} no longer resolves a tenant at all"
        assert "get_org_id" in code, f"{filename} does not take the credential org"
