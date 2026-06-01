"""
REQ-010-02 — CI gate: dead-router count is frozen.
====================================================
This test FAILS if a NEW unmounted router appears beyond the allowlist.
It PASSES today (5 known dead routers, all in the allowlist).

The test also proves the gate *bites* by temporarily creating a synthetic
dead router and asserting the gate detects it.
"""
from __future__ import annotations

import sys
import os
import re
import tempfile
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Ensure scripts/ is importable
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

# ---------------------------------------------------------------------------
# Helpers — pure static analysis (no create_app boot required for the gate)
# ---------------------------------------------------------------------------

SUITE_DIRS = [
    REPO_ROOT / "suite-api" / "apps" / "api",
    REPO_ROOT / "suite-core" / "api",
    REPO_ROOT / "suite-attack" / "api",
    REPO_ROOT / "suite-integrations" / "api",
    REPO_ROOT / "suite-feeds" / "api",
    REPO_ROOT / "suite-evidence-risk" / "api",
    REPO_ROOT / "suite-core" / "core",  # llm_distill_router lives here
]

EXCLUDE_DIRS = {
    REPO_ROOT / ".claude",
    REPO_ROOT / "archive",
}

_IMPORT_RE = re.compile(r"""from\s+apps\.api\.([a-zA-Z0-9_]+)\s+import""", re.MULTILINE)
_SUITE_RE  = re.compile(r"""from\s+[\w.]*?([a-zA-Z0-9_]+_router)\s+import""", re.MULTILINE)


def _is_excluded(path: Path) -> bool:
    for excl in EXCLUDE_DIRS:
        try:
            path.relative_to(excl)
            return True
        except ValueError:
            pass
    return False


def _gather_imported_stems(extra_source_text: str = "") -> set[str]:
    """Statically extract router module stems imported in app.py + sub_apps."""
    files = [REPO_ROOT / "suite-api" / "apps" / "api" / "app.py"]
    sub = REPO_ROOT / "suite-api" / "apps" / "api" / "sub_apps"
    if sub.is_dir():
        files.extend(sub.glob("*.py"))
    stems: set[str] = set()
    for f in files:
        if f.is_file():
            try:
                src = f.read_text(errors="replace")
                for m in _IMPORT_RE.finditer(src):
                    s = m.group(1)
                    if "_router" in s:
                        stems.add(s)
                for m in _SUITE_RE.finditer(src):
                    stems.add(m.group(1))
            except Exception:
                pass
    if extra_source_text:
        for m in _IMPORT_RE.finditer(extra_source_text):
            s = m.group(1)
            if "_router" in s:
                stems.add(s)
        for m in _SUITE_RE.finditer(extra_source_text):
            stems.add(m.group(1))
    return stems


def _find_router_files(extra_dir: Path | None = None) -> list[Path]:
    dirs = list(SUITE_DIRS)
    if extra_dir:
        dirs.append(extra_dir)
    seen: set[Path] = set()
    results: list[Path] = []
    for d in dirs:
        if not d.is_dir():
            continue
        for f in d.rglob("*_router.py"):
            r = f.resolve()
            if r not in seen and not _is_excluded(f):
                seen.add(r)
                results.append(f)
    return results


def _classify(extra_dir: Path | None = None) -> tuple[set[str], set[str]]:
    """Return (mounted_rel_paths, unmounted_rel_paths) relative to REPO_ROOT."""
    stems = _gather_imported_stems()
    files = _find_router_files(extra_dir)
    mounted: set[str] = set()
    unmounted: set[str] = set()
    for f in files:
        try:
            rel = str(f.relative_to(REPO_ROOT))
        except ValueError:
            # File is outside the repo (e.g. tmp_path in tests) — use abs path
            rel = str(f)
        if f.stem in stems:
            mounted.add(rel)
        else:
            unmounted.add(rel)
    return mounted, unmounted


def _load_allowlist() -> set[str]:
    allowlist_path = REPO_ROOT / "specs" / "dead_router_allowlist.txt"
    result: set[str] = set()
    for line in allowlist_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            result.add(line)
    return result


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_no_new_dead_routers():
    """
    AC-010-02 (part 1): the current unmounted set must be a subset of the
    frozen allowlist.  If a developer adds a new *_router.py that is never
    mounted in create_app(), this test fails.
    """
    _, unmounted = _classify()
    allowlist = _load_allowlist()
    new_dead = unmounted - allowlist
    assert new_dead == set(), (
        f"NEW unmounted routers detected (not in allowlist): {sorted(new_dead)}\n"
        "Either mount them in create_app() or add them to specs/dead_router_allowlist.txt."
    )


def test_allowlist_entries_exist():
    """
    Sanity: every entry in the allowlist actually exists on disk (guards
    against stale allowlist entries after archiving).
    """
    allowlist = _load_allowlist()
    missing = [p for p in allowlist if not (REPO_ROOT / p).exists()]
    assert missing == [], (
        f"Allowlist entries no longer on disk (archived? update allowlist): {missing}"
    )


def test_gate_bites_on_synthetic_dead_router(tmp_path):
    """
    AC-010-02 (part 2): prove the gate actually fires when a new dead router
    appears.  We create a synthetic *_router.py in a temp directory, add that
    temp directory to the scan list, and confirm it shows up as unmounted.
    """
    # Write a minimal fake router file
    fake_router = tmp_path / "synthetic_dead_test_router.py"
    fake_router.write_text(
        "from fastapi import APIRouter\nrouter = APIRouter(prefix='/synthetic-dead')\n"
    )

    # Classify with the temp dir in scope
    _, unmounted = _classify(extra_dir=tmp_path)
    allowlist = _load_allowlist()

    new_dead = unmounted - allowlist
    assert "synthetic_dead_test_router" in " ".join(new_dead) or any(
        "synthetic_dead_test_router" in p for p in new_dead
    ), (
        f"Gate did NOT detect synthetic dead router. unmounted={sorted(unmounted)}"
    )


def test_mounted_count_is_reasonable():
    """Sanity: at least 100 routers are mounted (guard against scan regression)."""
    mounted, _ = _classify()
    assert len(mounted) >= 100, f"Only {len(mounted)} mounted routers found — scan may be broken"
