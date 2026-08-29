"""Every endpoint the console names must exist on the app.

The console declares its endpoints in two places — ``flows.ts`` (per flow) and
the capability table in ``screens/Coverage.tsx`` — and the header comment on
``flows.ts`` promises that "every endpoint referenced here was measured
returning tenant-varying data".

That promise had already rotted. ``/api/v1/security-findings/stats`` was listed
against the triage flow and 404s: the router exposes ``/summary`` and ``/``, and
nothing ever exposed ``/stats``. It went unnoticed because a 404 on a secondary
panel looks exactly like a quiet empty state, and because a promise written in a
comment is not checked by anything.

This is the check. It does not assert that an endpoint returns *data* — that
depends on what a tenant has ingested, and asserting it would make the suite
depend on fixture state. It asserts the far weaker and far more durable thing:
the path the UI will request is a path the API actually serves. A wrong path is
a permanent, tenant-independent defect, and it is exactly the class of mistake
that survives a passing typecheck.
"""

from __future__ import annotations

import functools
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
CONSOLE = REPO / "suite-ui/aldeci-ui-new/src/console"

# Paths the console builds at call time rather than naming literally.
_DYNAMIC = re.compile(r"\$\{|\{[a-z_]+\}")


def _declared_endpoints() -> set[str]:
    """Pull every literal /api/... path the console commits to calling."""
    found: set[str] = set()
    for source in (CONSOLE / "flows.ts", CONSOLE / "screens/Coverage.tsx"):
        for match in re.finditer(r'"(/api/v1/[^"]*)"', source.read_text()):
            path = match.group(1)
            if not _DYNAMIC.search(path):
                found.add(path)
    return found


@functools.lru_cache(maxsize=1)
def _served_paths() -> frozenset[str]:
    """Cached: create_app() boots ~8,000 routes and takes roughly 15 seconds.

    Without the cache this module pays that cost once PER PARAMETRISED CASE —
    forty-odd boots for a check whose whole value is being cheap enough to keep
    in the change gate. A slow guard gets skipped, and a skipped guard is the
    same as no guard.
    """
    from apps.api.app import create_app

    return frozenset(getattr(r, "path", "") for r in create_app().routes)


def test_console_names_at_least_the_known_capability_surface() -> None:
    """Guard the guard: if the parse breaks, the test must fail loudly, not pass
    vacuously on an empty set."""
    declared = _declared_endpoints()
    assert len(declared) >= 20, f"only parsed {len(declared)} endpoints — the extractor is broken"


@pytest.mark.parametrize("path", sorted(_declared_endpoints()))
def test_every_console_endpoint_is_served(path: str) -> None:
    served = _served_paths()

    # FastAPI registers "/api/v1/secrets/" and the console may call either form;
    # a trailing-slash difference is a redirect, not a missing endpoint.
    candidates = {path, path.rstrip("/"), path + "/"}
    if candidates & served:
        return

    # A concrete path may legitimately be served by a parameterised route
    # ("/api/v1/evidence/bundles" under "/api/v1/evidence/{kind}"). That is not a
    # 404, though it IS the shadowing hazard that hid /api/v1/iac/stats — so
    # allow it, and let the browser check catch a genuine mis-dispatch.
    segments = path.strip("/").split("/")
    for candidate in served:
        parts = candidate.strip("/").split("/")
        if len(parts) != len(segments):
            continue
        if all(p.startswith("{") or p == s for p, s in zip(parts, segments)):
            return

    pytest.fail(
        f"The console calls {path}, which the API does not serve. "
        "Either the path is wrong or the route was removed — both render as an "
        "empty panel rather than an error, so nothing else will report it."
    )
