"""Generated code must not be committed.

Measured 2026-08-17: **12,189 of 17,961 tracked files (68%) were generated SDK**, every
one carrying a ``generated ... do not edit`` header, and the Python client was committed
*twice* under two names with identical 4,465-file sets. That is what made the repository
look three times its real size — hand-written product Python is 2,086 files — and what
put an external analysis pass at 801 LLM batches.

Committed generated code has no owner. Two copies drift, nothing says which is canonical,
and a regeneration buries real changes under an unreviewable diff.

These tests do not remove what is already tracked (ADR-004 sequences that behind a
working generator, since no generator and no committed spec exist yet). They stop the
problem *growing*, and they name the specific artifacts already present so the count can
only fall.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import List

REPO_ROOT = Path(__file__).resolve().parents[1]

# Frozen at the 2026-08-17 measurement, after the duplicate Python client was deleted
# in c2c67f36. Lower it as artifacts move to CI; never raise it.
MAX_TRACKED_SDK_FILES = 7724

_GENERATED_HEADER = re.compile(
    r"generated (?:using|by|with)[^\n]{0,80}(?:do not edit|DO NOT EDIT)", re.IGNORECASE
)
# Vite/webpack style content-hashed bundles, e.g. index-B8aPzWeF.js
_HASHED_BUNDLE = re.compile(r"[A-Za-z0-9_]+-[A-Za-z0-9_-]{8}\.(?:js|css)$")


def _tracked(*patterns: str) -> List[str]:
    result = subprocess.run(
        ["git", "ls-files", *patterns],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return [line for line in result.stdout.splitlines() if line.strip()]


def test_tracked_sdk_file_count_does_not_grow() -> None:
    count = len(_tracked("sdks/"))
    assert count <= MAX_TRACKED_SDK_FILES, (
        f"{count} generated SDK files are tracked, above the frozen "
        f"{MAX_TRACKED_SDK_FILES}. Generated clients belong in CI and a published "
        "package, not in version control (ADR-004)."
    )


def test_no_duplicate_client_reappears() -> None:
    """The Python client was committed twice under two names; once is enough."""
    clients = {
        path.split("/")[2]
        for path in _tracked("sdks/python/")
        if path.count("/") >= 2 and path.startswith("sdks/python/")
    }
    packages = {name for name in clients if name.endswith("_client")}
    assert len(packages) <= 1, (
        f"more than one Python client package is tracked: {sorted(packages)}. "
        "Two copies of a generated client guarantee drift and name no canonical one."
    )


def test_no_new_generated_file_outside_sdks() -> None:
    """A 'do not edit' header anywhere but sdks/ is a build artifact that slipped in."""
    offenders: List[str] = []
    for path in _tracked("*.ts", "*.js", "*.py"):
        if path.startswith("sdks/") or "node_modules" in path:
            continue
        full = REPO_ROOT / path
        try:
            head = full.read_text(encoding="utf-8", errors="ignore")[:600]
        except OSError:
            continue
        if _GENERATED_HEADER.search(head):
            offenders.append(path)
    assert not offenders, (
        "generated files are tracked outside sdks/:\n  " + "\n  ".join(offenders[:10])
    )


def test_content_hashed_bundles_are_not_tracked() -> None:
    """A hash in the filename means it came out of a bundler.

    ``suite-integrations/mpte-aldeci/index-B8aPzWeF.js`` — 391 functions in 936 minified
    lines — was already committed and carries no 'do not edit' header, so the header
    check alone would miss it.
    """
    offenders = [
        path
        for path in _tracked("*.js", "*.css")
        if "node_modules" not in path
        and not path.startswith("sdks/")
        and _HASHED_BUNDLE.search(path.split("/")[-1])
        # dist/ is already gitignored; if one appears here it was force-added
    ]
    assert not offenders, (
        "content-hashed build bundles are tracked:\n  " + "\n  ".join(offenders[:10])
    )
