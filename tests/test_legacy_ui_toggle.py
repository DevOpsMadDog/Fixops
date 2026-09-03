"""The ~291 unreachable screens are parked behind a flag, not deleted.

The console surfaces 9 screens; src/pages holds 300 components, one per engine
from an earlier era. They are mounted behind VITE_LEGACY_UI=1 rather than
removed, because twice this month something that looked dead turned out to be
load-bearing. A flag survives that mistake; `git rm` under time pressure does
not.

VERIFIED IN A REAL BROWSER against a live server, both directions:

    default build          GET /pricing -> redirected to /console/triage
    VITE_LEGACY_UI=1 build GET /pricing -> "Simple, transparent pricing" renders

The second half is the half that matters. "Stashed for later" is only true if
later actually works, and a flag nobody exercises is indistinguishable from a
deletion.

This test guards the wiring, not the rendering — a browser check cannot run in
the unit suite, so it pins the mechanism the browser check confirmed.
"""

from __future__ import annotations

import pathlib

MAIN = (
    pathlib.Path(__file__).resolve().parents[1]
    / "suite-ui" / "aldeci-ui-new" / "src" / "main.tsx"
)


def test_the_console_is_the_default_surface() -> None:
    src = MAIN.read_text()
    assert 'import.meta.env.VITE_LEGACY_UI === "1"' in src, (
        "the legacy toggle changed shape — a demo could ship 300 screens"
    )
    # The ternary must render Console when the flag is absent.
    assert "USE_LEGACY_UI ? <App /> : <Console />" in src, (
        "the default branch no longer renders the console"
    )


def test_the_legacy_surface_is_still_importable() -> None:
    """Parked, not deleted. If App stops being imported the screens are gone in
    practice, whatever the flag says."""
    src = MAIN.read_text()
    assert 'import App from "./App"' in src
    assert 'import Console from "./console/Console"' in src


def test_the_legacy_pages_still_exist_on_disk() -> None:
    pages = (
        pathlib.Path(__file__).resolve().parents[1]
        / "suite-ui" / "aldeci-ui-new" / "src" / "pages"
    )
    count = len(list(pages.rglob("*.tsx")))
    assert count > 100, (
        f"only {count} legacy pages remain — they were meant to be parked for "
        f"later, not removed"
    )
