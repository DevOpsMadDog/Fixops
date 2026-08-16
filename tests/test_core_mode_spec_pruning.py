"""Core mode must prune schemas, not just paths.

Core mode filtered the OpenAPI *paths* from 6,564 down to 454 but left all **4,025
component schemas** in place. The "focused" spec was therefore still 4.74 MB, and — more
damagingly — a client generated from it still emitted one model file per schema. That is
how the committed SDK reached 4,465 files per language and why the repository looked
three times its real size (see ADR-004).

Pruning to the schemas actually reachable from retained paths takes it to 238 schemas
and 1.07 MB, which is a client roughly seventeen times smaller.

The risk of pruning is a dangling ``$ref``, which would produce a spec that looks tidy
and generates a broken client. The second test is the one that matters.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Set

import pytest


def _core_spec() -> Dict[str, Any]:
    os.environ["FIXOPS_CORE_MODE"] = "1"
    from apps.api.app import create_app

    return create_app().openapi()


@pytest.fixture(scope="module")
def spec() -> Dict[str, Any]:
    return _core_spec()


def _schema_refs(node: Any) -> Set[str]:
    found: Set[str] = set()
    stack = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            ref = current.get("$ref")
            if isinstance(ref, str) and ref.startswith("#/components/schemas/"):
                found.add(ref.rsplit("/", 1)[-1])
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
    return found


def test_every_ref_resolves(spec: Dict[str, Any]) -> None:
    """A pruned spec with a dangling $ref generates a broken client."""
    declared = set((spec.get("components") or {}).get("schemas") or {})
    referenced = _schema_refs(spec)
    dangling = referenced - declared
    assert not dangling, f"pruning removed schemas that are still referenced: {sorted(dangling)[:10]}"


def test_unreachable_schemas_are_pruned(spec: Dict[str, Any]) -> None:
    """Schemas no retained path can reach must not ship."""
    declared = set((spec.get("components") or {}).get("schemas") or {})
    assert declared, "core spec declares no schemas at all"
    # Comfortably below the unpruned 4,025 while leaving room for the surface to grow.
    assert len(declared) < 1500, (
        f"core spec still carries {len(declared)} schemas — pruning is not working"
    )


def test_no_schema_is_declared_but_unreachable(spec: Dict[str, Any]) -> None:
    """The set of declared schemas equals the set transitively reachable from paths."""
    schemas = (spec.get("components") or {}).get("schemas") or {}
    reachable: Set[str] = set()
    queue = list(_schema_refs(spec.get("paths") or {}))
    while queue:
        name = queue.pop()
        if name in reachable or name not in schemas:
            continue
        reachable.add(name)
        queue.extend(_schema_refs(schemas[name]))

    orphans = set(schemas) - reachable
    assert not orphans, (
        f"{len(orphans)} schemas ship without any path reaching them, e.g. "
        f"{sorted(orphans)[:5]}"
    )


def test_core_mode_still_advertises_the_value_path(spec: Dict[str, Any]) -> None:
    """Pruning must not silently shrink the surface we intend to sell."""
    paths = spec.get("paths") or {}
    assert len(paths) > 100, f"core surface collapsed to {len(paths)} paths"
    joined = " ".join(paths)
    for expected in ("/api/v1/findings", "/api/v1/pipeline"):
        assert expected in joined, f"core spec no longer advertises {expected}"


def test_core_mode_is_the_default_and_routes_stay_mounted() -> None:
    """Core mode ships by default; the full surface is opt-in (ADR-005).

    The distinction that matters: this governs what the product *advertises*, not what
    it serves. Every route must still be mounted and resolvable — a customer calling a
    dormant endpoint directly still gets a real answer, they just are not invited to.
    """
    import os
    import subprocess
    import sys

    from pathlib import Path

    repo = Path(__file__).resolve().parents[1]
    env = {k: v for k, v in os.environ.items() if k != "FIXOPS_CORE_MODE"}
    env["PYTHONPATH"] = os.pathsep.join(
        str(repo / p)
        for p in (
            "suite-api",
            "suite-core",
            "suite-attack",
            "suite-feeds",
            "suite-evidence-risk",
            "suite-integrations",
        )
    ) + os.pathsep + str(repo)

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from apps.api.app import create_app;"
            "a=create_app();s=a.openapi();"
            "print(len(s.get('paths',{})), len(a.routes))",
        ],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        timeout=900,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    advertised, mounted = (int(x) for x in result.stdout.strip().splitlines()[-1].split())

    assert advertised < 1000, (
        f"with no FIXOPS_CORE_MODE set the app advertises {advertised} paths — "
        "core mode is not the default"
    )
    assert mounted > 5000, (
        f"only {mounted} routes are mounted; core mode must hide routes from the spec, "
        "never unmount them"
    )
