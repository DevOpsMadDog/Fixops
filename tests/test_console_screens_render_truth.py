"""A screen must not display a number nobody measured, or a reason it never checked.

Both defects here were found the same way every serious defect this month was
found: by opening the screen and reading the value back against the API.

1. **"Tenants: 0" on a deployment with 1,029 organisations.**
   ``GET /api/v1/orgs`` returns a BARE ARRAY. The screen read ``.total``, then
   ``.orgs?.length``, then ``.items?.length`` — none of which exist on an array —
   and the ?? chain fell through to 0. A shape mismatch that renders as a
   plausible number is worse than a crash, because nobody investigates a zero.

2. **"no CVE to reason about" for a finding that has a CVE.**
   The Decide screen labelled its not-assessed bucket with a CAUSE it had never
   checked. Ingest alone does not run the pipeline, so a finding can carry
   CVE-2022-22965 and still have no verdict. The count was right; the
   explanation was false.

These are guarded here rather than only in the browser, because the shapes they
depend on are API contracts that can drift.
"""

from __future__ import annotations

import pathlib
import re

import pytest

CONSOLE = pathlib.Path(__file__).resolve().parents[1] / "suite-ui/aldeci-ui-new/src/console"


def test_org_count_handles_a_bare_array() -> None:
    """The /orgs contract is a list, not an envelope."""
    src = (CONSOLE / "screens/Operate.tsx").read_text()

    assert "Array.isArray" in src, (
        "Operate reads the org count off object keys only; /api/v1/orgs returns a "
        "bare array, so it will render 0 for any number of tenants"
    )


def _strip_comments(src: str) -> str:
    """Only what the user SEES counts.

    The first version of this test matched the phrase inside the comment
    explaining the fix, and failed on correct code. A test that reads source
    text when it means rendered text will keep doing that.
    """
    src = re.sub(r"/\*[\s\S]*?\*/", "", src)   # /* ... */ and JSX {/* ... */}
    src = re.sub(r"^\s*//.*$", "", src, flags=re.M)
    return src


def test_no_screen_asserts_an_unchecked_cause_for_missing_verdicts() -> None:
    """"Not assessed" may state the count; it may not invent the reason."""
    src = _strip_comments((CONSOLE / "screens/Decide.tsx").read_text())

    assert "no CVE to reason about" not in src, (
        "the not-assessed tile asserts a cause the screen never checked — a "
        "finding can carry a CVE and still have no verdict, because ingest does "
        "not run the pipeline"
    )


@pytest.mark.parametrize(
    "screen",
    ["Ingest", "Triage", "Decide", "Prove", "Declare", "Comply", "Connect", "Operate"],
)
def test_every_screen_distinguishes_empty_from_failed(screen: str) -> None:
    """A blank panel reads as "this product does nothing".

    Each screen must route its data through Resolve/Empty/Failed rather than
    rendering a bare falsy value, so "still loading", "nothing yet", and "the
    call failed" stay three different things on screen.
    """
    src = (CONSOLE / f"screens/{screen}.tsx").read_text()

    assert "Resolve" in src or "Failed" in src, (
        f"{screen} does not use the load-state primitives; it can render an "
        f"error as an empty panel"
    )


@pytest.mark.parametrize(
    "screen",
    ["Ingest", "Triage", "Decide", "Prove", "Declare", "Comply", "Connect", "Operate"],
)
def test_no_screen_falls_back_to_fabricated_data(screen: str) -> None:
    """The failure mode every prior generation of this UI grew."""
    src = (CONSOLE / f"screens/{screen}.tsx").read_text()

    for pattern in (r"\?\?\s*MOCK", r"\|\|\s*MOCK", r"MOCK_[A-Z_]+", r"SAMPLE_[A-Z_]+"):
        assert not re.search(pattern, src), (
            f"{screen} falls back to fabricated data — an outage would render as "
            f"a plausible dashboard"
        )


def test_counts_go_through_the_shared_shape_helper() -> None:
    """The same shape mismatch has now shipped twice.

    Operate read ``.total``, ``.orgs?.length``, ``.items?.length`` off
    ``/api/v1/orgs`` — a BARE ARRAY — and rendered "Tenants 0" against 1,029
    organisations. Comply then read ``.total ?? .gaps?.length ?? 0`` off
    ``/api/v1/compliance/gaps``, also a bare array, and rendered "Open gaps 0"
    IN GREEN against 94 real control gaps across seven frameworks.

    A shape mismatch that renders as a plausible number is worse than a crash,
    because nobody investigates a zero. ``countOf`` handles arrays, envelopes
    and unknown shapes in one place, and returns null — not 0 — when the count
    is genuinely unknown.
    """
    api = (CONSOLE / "api.ts").read_text()
    assert "export function countOf" in api, "the shared count helper is gone"
    assert "return null" in api, (
        "countOf must be able to say 'unknown'; collapsing that to 0 is the bug"
    )

    comply = (CONSOLE / "screens/Comply.tsx").read_text()
    assert "countOf(gaps" in comply, "Comply no longer uses the shared helper"
    assert "?? 0" not in comply.split("const gapCount")[1].split("\n")[0], (
        "Comply defaults its gap count to 0 again — that is the defect"
    )


def test_an_unknown_gap_count_is_not_rendered_as_zero() -> None:
    """Loading or failing must not read as 'you have no gaps'. A compliance
    officer glancing at a green 0 concludes they are clean."""
    comply = (CONSOLE / "screens/Comply.tsx").read_text()
    assert 'gapCount ?? "—"' in comply, "unknown must render as em-dash, not 0"
    assert 'gapCount === null ? "muted"' in comply, (
        "unknown must not be toned as good — green says 'clean', which is a claim"
    )
