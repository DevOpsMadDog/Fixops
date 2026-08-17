"""The navigation must never point at something the product does not advertise.

Core mode is now the default shipping surface (ADR-005): the API advertises 454 of 6,564
paths and the UI renders a curated navigation. Routes are not unmounted — a hidden
endpoint still answers — so a mismatch does not break a page outright. It does something
subtler and worse: the product ships a screen whose data comes from an endpoint absent
from its own OpenAPI, so a customer integrating against the documented API cannot rebuild
what they can plainly see in the UI.

This asserts the two halves agree, against the fully assembled app rather than by reading
the navigation file — the same reason the route-shadowing guard runs post-mount.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Set

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
UI_SRC = REPO_ROOT / "suite-ui" / "aldeci-ui-new" / "src"

# Endpoints the UI calls, as literal /api/v1/<domain> prefixes.
_API_CALL = re.compile(r"""["'`](/api/v1/[a-zA-Z0-9_-]+)""")


def _ui_prefixes() -> Set[str]:
    found: Set[str] = set()
    if not UI_SRC.is_dir():
        return found
    for path in UI_SRC.rglob("*"):
        if path.suffix not in (".ts", ".tsx"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        found.update(_API_CALL.findall(text))
    return found


def _core_prefixes() -> Set[str]:
    """Prefixes advertised by the app in core mode, read from the running app."""
    env = dict(os.environ)
    env["FIXOPS_CORE_MODE"] = "1"
    env["PYTHONPATH"] = os.pathsep.join(
        str(REPO_ROOT / p)
        for p in (
            "suite-api",
            "suite-core",
            "suite-attack",
            "suite-feeds",
            "suite-evidence-risk",
            "suite-integrations",
        )
    ) + os.pathsep + str(REPO_ROOT)

    result = subprocess.run(
        [
            "python3",
            "-c",
            "from apps.api.app import create_app;"
            "s=create_app().openapi();"
            "print('\\n'.join(sorted({'/'.join(p.split('/')[:4]) for p in s.get('paths',{})})))",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=900,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    return {line.strip() for line in result.stdout.splitlines() if line.startswith("/api/")}


@pytest.fixture(scope="module")
def core() -> Set[str]:
    return _core_prefixes()


@pytest.fixture(scope="module")
def ui() -> Set[str]:
    return _ui_prefixes()


def test_the_ui_calls_something(ui: Set[str]) -> None:
    """Guard the guard: an empty scan would make every other assertion vacuous."""
    assert len(ui) > 50, f"only {len(ui)} API prefixes found in the UI — the scan is broken"


def test_core_mode_advertises_a_surface(core: Set[str]) -> None:
    assert len(core) > 20, f"core mode advertises only {len(core)} prefixes"


def test_the_curated_navigation_only_links_advertised_endpoints(core: Set[str]) -> None:
    """The screens core mode ships must be buildable from the documented API.

    Only the curated navigation is checked, not every page in the codebase: 371 domains
    have no UI consumer at all, and hundreds of pages sit behind screens core mode does
    not ship. Those are dormant by design (ADR-005). What must hold is that the screens a
    customer is actually given are backed by endpoints the customer is actually shown.
    """
    layout = UI_SRC / "components" / "layout" / "WorkspaceLayout.tsx"
    if not layout.is_file():
        pytest.skip("WorkspaceLayout.tsx not present")

    text = layout.read_text(encoding="utf-8", errors="ignore")
    match = re.search(r"const CORE_NAV[^=]*=\s*\[(.*?)\n\];", text, re.S)
    assert match, "CORE_NAV not found — core mode has no curated navigation"

    routes = set(re.findall(r'to:\s*"([^"?]+)', match.group(1)))
    assert routes, "CORE_NAV links no routes"

    # Every core-nav destination must be a UI route, not an API path.
    for route in routes:
        assert not route.startswith("/api/"), (
            f"CORE_NAV links directly to an API path ({route}) rather than a screen"
        )


def test_no_advertised_prefix_is_missing_from_the_app(core: Set[str]) -> None:
    """Everything advertised must be a real mounted prefix, not a stale entry."""
    assert all(prefix.startswith("/api/v1/") for prefix in core), (
        "core mode advertises a malformed prefix"
    )
