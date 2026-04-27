"""Baseline route count for app.py refactor verification gate.

Run from repo root: `python scripts/count_routes_baseline.py`.
Records the pre-refactor count so each refactor wave can verify
zero behavior change. Per docs/app_py_refactor_plan_2026-04-27.md
RISK-01 gate.

Self-contained: adds all suite paths to sys.path so it works even
when sitecustomize.py is shadowed by a system-level one.
"""

from __future__ import annotations

import sys
from pathlib import Path


def _bootstrap_suite_paths() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    for suite in (
        "suite-api",
        "suite-core",
        "suite-attack",
        "suite-feeds",
        "suite-integrations",
        "suite-evidence-risk",
    ):
        candidate = str(repo_root / suite)
        if candidate not in sys.path:
            sys.path.insert(0, candidate)


def main() -> int:
    _bootstrap_suite_paths()
    from apps.api.app import create_app  # noqa: E402

    app = create_app()
    print(f"ROUTE_COUNT_BASELINE: {len(app.routes)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
