#!/usr/bin/env python3
"""Export the OpenAPI contract that client SDKs are generated from.

The committed SDKs were generated once, by hand, from a spec that no longer exists in the
repository — 12,189 tracked files with no reproducible source (ADR-004). Untracking them
would have destroyed the only copy, so the spec has to come first: a committed contract
means a client can be regenerated at any time and its diff reviewed.

The exported spec is the **core** surface, not the full one. Core mode advertises 454 of
6,564 paths and, once unreachable schemas are pruned, 238 of 4,025 component schemas — and
a generator emits roughly one model file per schema. That difference is the entire reason
the SDK reached 4,465 files per language. A client for 6,564 endpoints, half of them
dormant, is not a client anyone wants.

Keys are sorted so regeneration produces a reviewable diff rather than a reshuffle.

Usage::

    python scripts/export_openapi_spec.py                       # contracts/openapi-core.json
    python scripts/export_openapi_spec.py --full                # the whole surface
    python scripts/export_openapi_spec.py --check               # CI: fail if stale
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = REPO_ROOT / "contracts" / "openapi-core.json"

for suite in (
    "suite-api",
    "suite-core",
    "suite-attack",
    "suite-feeds",
    "suite-evidence-risk",
    "suite-integrations",
):
    path = REPO_ROOT / suite
    if path.is_dir() and str(path) not in sys.path:
        sys.path.insert(0, str(path))


def render(full: bool) -> str:
    os.environ["FIXOPS_CORE_MODE"] = "0" if full else "1"
    from apps.api.app import create_app

    spec = create_app().openapi()
    return json.dumps(spec, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full", action="store_true", help="export the entire surface")
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the committed spec matches the code; exit 1 if it does not",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    rendered = render(args.full)
    spec = json.loads(rendered)
    paths = len(spec.get("paths", {}))
    schemas = len((spec.get("components") or {}).get("schemas") or {})

    if args.check:
        if not args.output.exists():
            print(f"FAIL  {args.output} does not exist — run this script without --check")
            return 1
        if args.output.read_text(encoding="utf-8") == rendered:
            print(f"OK    {args.output.name} matches the code ({paths} paths, {schemas} schemas)")
            return 0
        print(
            f"FAIL  {args.output.name} is stale. The API changed without the contract "
            f"being regenerated, so any client built from it is already wrong.\n"
            f"      Run: python scripts/export_openapi_spec.py"
        )
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    print(
        f"wrote {args.output.relative_to(REPO_ROOT)} — "
        f"{paths} paths, {schemas} schemas, {len(rendered) / 1048576:.2f} MB"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
