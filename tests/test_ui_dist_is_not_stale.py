"""The served UI must not predate the source it was built from.

The API serves suite-ui/aldeci-ui-new/dist as the product. Nothing checked that
the bundle matched the source, and on 2026-09-03 the demo was serving a build
from Aug 25 with SEVEN newer source files — including the entire console the
session had just written. Every UI fix was invisible, and the only symptom was
a screen that looked slightly wrong for reasons no log explained.

TypeScript compiling proves nothing here: the stale bundle compiled fine, it
just was not the code being served.

This is a staleness check, not a build. It fails with the command to run.

Deliberately a LOCAL gate, not a CI one: dist/ is gitignored and CI builds the
UI fresh on every run, so this assertion is vacuous there — it would always
pass and prove nothing. The failure it catches is a developer or a demo serving
yesterday's bundle, which is precisely where it bit.
"""

from __future__ import annotations

import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
UI = REPO / "suite-ui" / "aldeci-ui-new"
SRC = UI / "src"
DIST = UI / "dist"

# Anything that cannot change what the bundle contains.
_IGNORED_SUFFIXES = (".md", ".snap", ".test.ts", ".test.tsx", ".spec.ts", ".spec.tsx")
_IGNORED_PARTS = ("__tests__", "__snapshots__", "assets/docs")


def _source_files() -> list[pathlib.Path]:
    out = []
    for path in SRC.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(SRC).as_posix()
        if any(part in rel for part in _IGNORED_PARTS):
            continue
        if path.name.endswith(_IGNORED_SUFFIXES):
            continue
        out.append(path)
    return out


@pytest.mark.skipif(not DIST.is_dir(), reason="no dist/ built in this checkout")
def test_the_built_bundle_is_newer_than_every_source_file() -> None:
    index = DIST / "index.html"
    assert index.is_file(), "dist/ exists but has no index.html — a broken build"

    built_at = index.stat().st_mtime
    newer = [
        p.relative_to(REPO).as_posix()
        for p in _source_files()
        if p.stat().st_mtime > built_at
    ]
    assert not newer, (
        f"{len(newer)} source file(s) are newer than dist/index.html, so the "
        f"served UI does not contain them:\n  "
        + "\n  ".join(sorted(newer)[:12])
        + "\n\nRebuild with:  cd suite-ui/aldeci-ui-new && npm run build"
    )


@pytest.mark.skipif(not DIST.is_dir(), reason="no dist/ built in this checkout")
def test_the_bundle_actually_has_assets() -> None:
    """A dist/ containing only index.html serves a blank page with HTTP 200 —
    which is exactly the failure that looks like success."""
    assets = list((DIST / "assets").glob("*.js")) if (DIST / "assets").is_dir() else []
    assert assets, "dist/assets has no JavaScript — the page would render blank"
