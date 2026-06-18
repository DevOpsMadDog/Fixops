"""SPEC-032 — real-moat E2E (CI-safe): the product's $100K value, end-to-end, no live LLM.

The Beast smoke proves wiring; THIS proves the moat: a real scanner file ingests into
real findings, and the multi-LLM council is real-or-honestly-unconfigured — it must NEVER
silently fabricate a verdict (the founder's NO-MOCKS / ingest-first rule applied to the moat).

CI-safe: makes no paid LLM call. The live cost>0 assertion is test_real_moat_live.py (nightly).
See feedback_smoke_not_the_goal.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("FIXOPS_API_TOKEN", "ci-test-token")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

_SARIF = Path(__file__).resolve().parent / "fixtures" / "real_world" / "scan.sarif"


def _as_dict(f):
    if isinstance(f, dict):
        return f
    for m in ("to_dict", "model_dump", "dict"):
        fn = getattr(f, m, None)
        if callable(fn):
            try:
                return fn()
            except Exception:  # pragma: no cover - defensive
                pass
    return {
        k: getattr(f, k)
        for k in dir(f)
        if not k.startswith("_") and not callable(getattr(f, k, None))
    }


def _load_findings():
    # Use the real public ingest API the product uses (auto-detects the scanner,
    # builds the normalizer with its config, normalizes) — not a hand-built normalizer.
    from core.scanner_parsers import parse_scanner_output

    if not _SARIF.exists():
        pytest.skip(f"real SARIF fixture missing: {_SARIF}")
    return parse_scanner_output(_SARIF.read_bytes())


# ── Stage 1: real scanner ingest → real findings ────────────────────────────
def test_ingest_real_sarif_yields_real_findings():
    findings = _load_findings()
    assert isinstance(findings, list) and len(findings) > 0, "SARIF ingest produced no findings"
    d = _as_dict(findings[0])
    has_title = any(d.get(k) for k in ("title", "rule_id", "name", "message", "description"))
    has_sev = any(d.get(k) for k in ("severity", "level"))
    assert has_title and has_sev, f"normalized finding lacks real fields: {sorted(d)[:12]}"


def test_ingest_preserves_multiple_distinct_findings():
    """A real multi-result SARIF must yield multiple findings (no collapse-to-one bug)."""
    findings = _load_findings()
    assert len(findings) >= 2, f"expected multiple findings from a multi-result SARIF, got {len(findings)}"


# ── Stage 2: the moat is real-or-honestly-unconfigured (NEVER fabricated) ─────
def test_council_never_silently_fabricates():
    """CouncilFactory.create_default_council() builds a real OpenRouter council when keys
    exist, else raises CouncilNotConfiguredError. It must NOT return an all-deterministic
    placeholder council pretending to be real (the moat's NO-MOCKS invariant)."""
    from core.llm_council import CouncilFactory
    from core.llm_providers import CouncilNotConfiguredError

    try:
        council = CouncilFactory().create_default_council()
    except CouncilNotConfiguredError:
        pytest.skip("no LLM API key — council honestly unconfigured (correct: no fabricated verdict)")

    assert len(council.members) >= 2, "real council must have multiple members"
    provider_types = [type(m.provider).__name__ for m in council.members]
    assert not all("Deterministic" in n for n in provider_types), (
        f"council is all-deterministic placeholders (fabricated moat): {provider_types}"
    )
