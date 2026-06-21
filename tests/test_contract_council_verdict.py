"""SPEC-033 C6 — contract: council verdict schema + real-or-honestly-unconfigured.

Pins the CouncilVerdict shape the pipeline/UI consume (confidence, reasoning,
cost_usd, raw_analyses) so it can't drift, and asserts the council is never a
silent fabrication (real members or CouncilNotConfiguredError). CI-safe: no paid
call. The live cost_usd>0 proof lives in tests/test_real_moat_live.py (nightly).
"""

from __future__ import annotations

import dataclasses
import os

import pytest

os.environ.setdefault("FIXOPS_API_TOKEN", "ci-test-token")


def test_council_verdict_schema_fields():
    from core.llm_council import CouncilVerdict

    names = {f.name for f in dataclasses.fields(CouncilVerdict)}
    # the fields the pipeline/UI rely on — pin them so a rename can't break consumers
    for required in ("confidence", "reasoning", "cost_usd", "raw_analyses"):
        assert required in names, f"CouncilVerdict missing contract field '{required}': {sorted(names)}"


def test_council_never_silently_fabricates():
    from core.llm_council import CouncilFactory
    from core.llm_providers import CouncilNotConfiguredError

    try:
        council = CouncilFactory().create_default_council()
    except CouncilNotConfiguredError:
        pytest.skip("no LLM key — council honestly unconfigured (correct: no fabricated verdict)")
    assert len(council.members) >= 2, "real council must have multiple members"
    provider_types = [type(m.provider).__name__ for m in council.members]
    assert not all("Deterministic" in n for n in provider_types), (
        f"council is all-deterministic placeholders (fabricated moat): {provider_types}"
    )
