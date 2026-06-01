"""
REQ-010-01 — Router Inventory
==============================
Imports create_app(), enumerates mounted route prefixes, then scans all
*_router.py files under the known suite directories and classifies each as
mounted or unmounted.

Usage
-----
    python scripts/router_inventory.py            # human-readable
    python scripts/router_inventory.py --json     # machine-readable JSON

Exit codes: 0 always (read-only tool).
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Repo root — the script lives at <root>/scripts/router_inventory.py
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent

SUITE_DIRS = [
    REPO_ROOT / "suite-api" / "apps" / "api",
    REPO_ROOT / "suite-core" / "api",
    REPO_ROOT / "suite-attack" / "api",
    REPO_ROOT / "suite-integrations" / "api",
    REPO_ROOT / "suite-feeds" / "api",
    REPO_ROOT / "suite-evidence-risk" / "api",
]

# Directories that should be EXCLUDED from the router file scan
EXCLUDE_DIRS = {
    REPO_ROOT / ".claude",
    REPO_ROOT / "archive",
}

# ---------------------------------------------------------------------------
# Step 1: boot create_app() and harvest mounted module stems
# ---------------------------------------------------------------------------

def _setup_path() -> None:
    """Prepend all suite paths so imports resolve."""
    additions = [
        str(REPO_ROOT),
        str(REPO_ROOT / "suite-api"),
        str(REPO_ROOT / "suite-core"),
        str(REPO_ROOT / "suite-attack"),
        str(REPO_ROOT / "suite-feeds"),
        str(REPO_ROOT / "suite-integrations"),
        str(REPO_ROOT / "suite-evidence-risk"),
        str(REPO_ROOT / "archive" / "legacy"),
        str(REPO_ROOT / "archive" / "enterprise_legacy"),
    ]
    for p in reversed(additions):
        if p not in sys.path:
            sys.path.insert(0, p)


def _collect_mounted_route_count() -> int:
    """Return the live route count from create_app()."""
    import logging
    _setup_path()
    # Silence noisy boot logs so --json output is clean JSON only.
    logging.disable(logging.CRITICAL)
    try:
        from apps.api.app import create_app  # type: ignore[import]
        app = create_app()
        return len(app.routes)
    finally:
        logging.disable(logging.NOTSET)


# ---------------------------------------------------------------------------
# Step 2: static-analysis pass — harvest every *_router module imported
#         inside app.py + sub_apps/*.py (handles lazy try/except imports)
# ---------------------------------------------------------------------------

_IMPORT_RE = re.compile(
    r"""from\s+apps\.api\.([a-zA-Z0-9_]+)\s+import""",
    re.MULTILINE,
)

# Also catch suite-level imports like `from suite_feeds.api.feeds_router import`
_SUITE_IMPORT_RE = re.compile(
    r"""from\s+[\w.]*?([a-zA-Z0-9_]+_router)\s+import""",
    re.MULTILINE,
)


def _extract_imported_router_stems(source: str) -> set[str]:
    """Return the set of module stems (without .py) imported in *source*."""
    stems: set[str] = set()
    for m in _IMPORT_RE.finditer(source):
        stem = m.group(1)
        if stem.endswith("_router") or "_router" in stem:
            stems.add(stem)
    # catch any remaining pattern like `from feeds_router import ...`
    for m in _SUITE_IMPORT_RE.finditer(source):
        stems.add(m.group(1))
    return stems


def _gather_imported_stems() -> set[str]:
    """Scan app.py + sub_apps/*.py and return all imported router stems."""
    files_to_scan: list[Path] = [
        REPO_ROOT / "suite-api" / "apps" / "api" / "app.py",
    ]
    sub_apps_dir = REPO_ROOT / "suite-api" / "apps" / "api" / "sub_apps"
    if sub_apps_dir.is_dir():
        files_to_scan.extend(sub_apps_dir.glob("*.py"))

    all_stems: set[str] = set()
    for f in files_to_scan:
        if f.is_file():
            try:
                all_stems |= _extract_imported_router_stems(f.read_text(errors="replace"))
            except Exception:
                pass
    return all_stems


# ---------------------------------------------------------------------------
# Step 3: enumerate all *_router.py files on disk
# ---------------------------------------------------------------------------

def _is_excluded(path: Path) -> bool:
    for excl in EXCLUDE_DIRS:
        try:
            path.relative_to(excl)
            return True
        except ValueError:
            pass
    return False


def _find_all_router_files() -> list[Path]:
    results: list[Path] = []
    for suite_dir in SUITE_DIRS:
        if not suite_dir.is_dir():
            continue
        for f in suite_dir.rglob("*_router.py"):
            if not _is_excluded(f):
                results.append(f)
    # Also search any other locations that might have router files
    # (e.g., suite-core/core if they use _router naming there)
    extra_dirs = [
        REPO_ROOT / "suite-core" / "core",
        REPO_ROOT / "suite-feeds",
        REPO_ROOT / "suite-integrations",
        REPO_ROOT / "suite-evidence-risk",
        REPO_ROOT / "suite-attack",
    ]
    already = {f.resolve() for f in results}
    for d in extra_dirs:
        if not d.is_dir():
            continue
        for f in d.rglob("*_router.py"):
            r = f.resolve()
            if r not in already and not _is_excluded(f):
                results.append(f)
                already.add(r)
    return sorted(results)


# ---------------------------------------------------------------------------
# Step 4: classify mounted vs unmounted
# ---------------------------------------------------------------------------

def classify_routers() -> dict:
    """
    Returns a dict with keys:
      mounted_route_count  : int
      total_router_files   : int
      mounted_count        : int
      unmounted_count      : int
      mounted_files        : list[str]   (relative paths)
      unmounted_files      : list[str]   (relative paths)
    """
    imported_stems = _gather_imported_stems()
    all_router_files = _find_all_router_files()

    mounted_files: list[str] = []
    unmounted_files: list[str] = []

    for f in all_router_files:
        stem = f.stem  # e.g. "access_control_router"
        rel = str(f.relative_to(REPO_ROOT))
        if stem in imported_stems:
            mounted_files.append(rel)
        else:
            unmounted_files.append(rel)

    mounted_route_count = _collect_mounted_route_count()

    return {
        "mounted_route_count": mounted_route_count,
        "total_router_files": len(all_router_files),
        "mounted_count": len(mounted_files),
        "unmounted_count": len(unmounted_files),
        "mounted_files": sorted(mounted_files),
        "unmounted_files": sorted(unmounted_files),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Router inventory for ALDECI suite")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument(
        "--unmounted-only",
        action="store_true",
        help="Only list unmounted routers (implies text mode)",
    )
    args = parser.parse_args()

    data = classify_routers()

    if args.json:
        print(json.dumps(data, indent=2))
        return

    print("=" * 60)
    print("ALDECI Router Inventory")
    print("=" * 60)
    print(f"Total *_router.py files scanned : {data['total_router_files']}")
    print(f"Mounted (imported in app)        : {data['mounted_count']}")
    print(f"Unmounted (dead surface)         : {data['unmounted_count']}")
    print(f"Live route count (create_app)    : {data['mounted_route_count']}")
    print()

    if not args.unmounted_only:
        print("--- MOUNTED routers ---")
        for f in data["mounted_files"]:
            print(f"  [M] {f}")
        print()

    print("--- UNMOUNTED routers ---")
    for f in data["unmounted_files"]:
        print(f"  [U] {f}")

    print()
    print(
        f"Summary: {data['mounted_count']} mounted / "
        f"{data['unmounted_count']} unmounted / "
        f"{data['total_router_files']} total"
    )


if __name__ == "__main__":
    main()
