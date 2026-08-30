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

def _advertised_prefixes() -> list[str]:
    """Read the advertised surface from app.py rather than restating it.

    A hardcoded list goes stale the moment someone surfaces a capability — and
    surfacing is exactly when the tenancy bar rises, because a hole behind core
    mode is latent while the same hole on the advertised surface is a breach
    with a documented path to it. Deriving the list means the guard follows the
    surface automatically.
    """
    src = (pathlib.Path(__file__).resolve().parents[1]
           / "suite-api/apps/api/app.py").read_text()
    block = src.split("_CORE_PREFIXES = (", 1)[1].split(")", 1)[0]
    return re.findall(r'"(/api/v1/[a-z0-9-]+)"', block)


def _routers_for(prefix: str) -> list[pathlib.Path]:
    """Every router module declaring this exact prefix."""
    found = []
    for candidate in list(API.glob("*_router.py")) + list(API.glob("*_routes.py")):
        try:
            if f'prefix="{prefix}"' in candidate.read_text():
                found.append(candidate)
        except OSError:
            continue
    return found


SURFACED = sorted(
    {r.name for prefix in _advertised_prefixes() for r in _routers_for(prefix)}
)


# A site may declare itself exempt IN THE SOURCE, next to the code, with a
# reason. Two are legitimate today: minting a dev token (naming the org is the
# purpose, and the route 403s outside FIXOPS_DEV_MODE) and creating an org (the
# field is a requested slug for a NEW tenant — there is no other tenant to cross
# into). Keeping the exemption at the call site rather than in a list here means
# a reviewer sees it while reading the code that relies on it, and adding one is
# a visible act rather than an edit to a test nobody opens.
_EXEMPT = "tenancy-exempt:"


def _exempt_lines(src: str) -> set[int]:
    """Line numbers covered by a preceding ``# tenancy-exempt:`` comment."""
    covered: set[int] = set()
    lines = src.splitlines()
    for i, line in enumerate(lines):
        if _EXEMPT in line:
            for j in range(i + 1, min(i + 6, len(lines))):
                covered.add(j)
    return covered


def _strip_comments_and_docstrings(src: str) -> str:
    """A guard that matches its own explanatory comment proves nothing.

    This module documents the bad pattern in prose above; without stripping,
    the scan would find `body.org_id` in a comment and fail on a fixed file.

    Line numbers must be PRESERVED, because the exemption markers are matched
    by line. Blanking a docstring outright collapses the file and shifts every
    line after it, which silently misaligns the exemptions against the code —
    the guard then reports a fixed site as broken and an exempt one as fine.
    Substitute an equal number of newlines instead.
    """
    src = re.sub(
        r'"""(?:.|\n)*?"""',
        lambda m: "\n" * m.group(0).count("\n"),
        src,
    )
    src = re.sub(r"^(\s*)#.*$", r"\1", src, flags=re.M)
    return src


def test_the_advertised_surface_was_actually_discovered() -> None:
    """Guard the guard. If the _CORE_PREFIXES parse breaks, SURFACED goes empty
    and every parametrised case below silently vanishes — a guard that passes
    because it checked nothing."""
    assert len(SURFACED) >= 7, f"only found {len(SURFACED)} advertised routers: {SURFACED}"


@pytest.mark.parametrize("filename", SURFACED)
def test_no_surfaced_handler_trusts_a_caller_supplied_org(filename: str) -> None:
    path = API / filename
    if not path.exists():
        pytest.skip(f"{filename} not present")

    raw = path.read_text()
    exempt = _exempt_lines(raw)
    code_lines = _strip_comments_and_docstrings(raw).splitlines()

    offenders = [
        line
        for n, line in enumerate(code_lines)
        if n not in exempt and re.search(r"\b(?:body|req|request|payload)\.org_id\b", line)
    ]
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
