"""SPEC-028 — NO-MOCKS static CI gate for the UI (suite-ui/aldeci-ui-new).

Closes the SPEC-028 follow-up: a deterministic scanner that fails CI if a page ships fabricated
data instead of a real /api/v1 call. Catches the *unambiguous* signatures (a plain `MOCK_` grep
misses the worst ones, but these four are zero-false-positive in this codebase as of 2026-06-03):

  1. imports from a fixtures/mocks/sample/seed/src-data module,
  2. displayed mock literals (MOCK_X / lorem ipsum / Acme Corp / "John Doe") outside placeholders,
  3. fetch-then-discard (`void d;`),
  4. presence of a `src/data` or `src/fixtures` directory.

Heuristic signatures (set-but-unused liveX state, useState(MOCK), frozen dates) are intentionally
NOT enforced here — they need human judgment and would false-positive on legit editor/tester
defaults (e.g. RuntimeCodeTrace `SAMPLE`, WebhookIngestionHub `DEFAULT_SAMPLE`). Those remain a
review-time concern (SPEC-028 §2).

Run: python -m pytest tests/test_ui_no_mocks_static.py -q -o "addopts="
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
UI_SRC = REPO_ROOT / "suite-ui" / "aldeci-ui-new" / "src"

_SKIP = re.compile(r"__tests__|\.test\.|\.spec\.")
_FIXTURE_IMPORT = re.compile(
    r"""import\s+[^;]*?from\s+['"][^'"]*(?:/fixtures?/|/mocks?/|/sampleData|/seed|/dummyData|['"/]src/data/)[^'"]*['"]"""
)
_DISPLAYED_MOCK = re.compile(r"""MOCK_[A-Z]|lorem ipsum|Acme Corp|["']John Doe["']""")
_VOID_DISCARD = re.compile(r"\bvoid\s+(?:d|data|res|resp|r)\s*;")


def _ui_source_files():
    if not UI_SRC.is_dir():
        pytest.skip(f"UI src not found at {UI_SRC}")
    return [
        f for f in UI_SRC.rglob("*.ts*")
        if f.suffix in (".ts", ".tsx") and not _SKIP.search(str(f))
    ]


def test_no_fixture_module_imports():
    hits = []
    for f in _ui_source_files():
        for i, line in enumerate(f.read_text(errors="ignore").splitlines(), 1):
            if _FIXTURE_IMPORT.search(line):
                hits.append(f"{f.relative_to(REPO_ROOT)}:{i}: {line.strip()}")
    assert not hits, "Pages importing fixture/mock data modules (NO-MOCKS):\n  " + "\n  ".join(hits)


def test_no_displayed_mock_literals():
    hits = []
    for f in _ui_source_files():
        for i, line in enumerate(f.read_text(errors="ignore").splitlines(), 1):
            if _DISPLAYED_MOCK.search(line) and "placeholder" not in line.lower():
                hits.append(f"{f.relative_to(REPO_ROOT)}:{i}: {line.strip()}")
    assert not hits, "Displayed mock literals (use real data or an EmptyState):\n  " + "\n  ".join(hits)


def test_no_fetch_then_discard():
    hits = []
    for f in _ui_source_files():
        for i, line in enumerate(f.read_text(errors="ignore").splitlines(), 1):
            if _VOID_DISCARD.search(line):
                hits.append(f"{f.relative_to(REPO_ROOT)}:{i}: {line.strip()}")
    assert not hits, "fetch-then-discard (`void d;`) — the response is fetched then thrown away:\n  " + "\n  ".join(hits)


def test_no_fixture_directories():
    bad = [d for d in (UI_SRC / "data", UI_SRC / "fixtures") if d.is_dir()]
    assert not bad, f"Banned fixture directories present: {[str(b) for b in bad]}"


# --- gate-bites self-tests: the detectors must actually match synthetic violations ---

def test_detectors_bite():
    assert _FIXTURE_IMPORT.search('import { MOCK_REVIEWS } from "@/fixtures/reviews";')
    assert _FIXTURE_IMPORT.search('import data from "../src/data/seed";')
    assert _DISPLAYED_MOCK.search('<span>{MOCK_FINDINGS.length}</span>')
    assert _DISPLAYED_MOCK.search('name: "John Doe",')
    assert _VOID_DISCARD.search('      void d;')
    # must NOT flag legitimate patterns
    assert not _FIXTURE_IMPORT.search('import { apiFetch } from "@/lib/api";')
    assert not _VOID_DISCARD.search('const voided = compute();')
    # placeholder= form-hints are exempt — the exclusion is the loop's `"placeholder" not in line`,
    # so assert the FULL gate logic (regex + exclusion), not the bare regex.
    def _displayed_mock_flagged(line: str) -> bool:
        return bool(_DISPLAYED_MOCK.search(line)) and "placeholder" not in line.lower()
    assert not _displayed_mock_flagged('placeholder="John Doe"')
    assert _displayed_mock_flagged('name: "John Doe",')
