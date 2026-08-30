"""The pipeline must ask reachability at symbol granularity, and must not
mistake an unanswerable question for a safe answer.

Two defects, both live before this:

1. **It never used the symbol.** ``_apply_reachability_verdicts`` built its
   query from ``dependency_fqn_pattern`` or ``package_name`` and ignored the
   ``vulnerable_symbols`` that ingest had already recovered from the advisory.
   A package-level query asks "do you use this library" — which the dependency
   file already answered — so every finding came back reachable and the noise
   reduction was zero. Measured on 119 real findings in
   ``docs/REACHABILITY_MEASURED_2026-08-29.md``.

2. **"No callers" was treated as proof of safety.** The verdict was a straight
   binary: no callers meant ``unreachable``, which DOWNGRADED the finding's
   ``consensus_priority``. But "no callers" only means something when the
   question was specific enough to answer. Asking ``requests.%`` and getting
   nothing means the library is unused; asking it while we *do* use the library
   and simply do not know where the flaw lives means nothing at all — and that
   case was quietly pushing real findings down the queue.

The fix gives the middle case a name. ``undetermined`` does not downgrade
anything, and the exploitability fusion already routes it to
``exploited_unknown_reach`` / ``insufficient_evidence`` — verdicts the console
renders.
"""

from __future__ import annotations

import pytest

from core.brain_pipeline import BrainPipeline


class _FakeEngine:
    """Records what was asked, and answers from a fixed call graph."""

    def __init__(self, known_callers: dict[str, list[str]]):
        self.known = known_callers
        self.asked: list[str] = []

    def vulnerable_reachability(self, org_id, cve_id, pattern):
        self.asked.append(pattern)
        return self.known.get(pattern, [])

    def record_finding_verdict(self, *a, **k):
        return None


def _run(monkeypatch, finding: dict, engine: _FakeEngine) -> dict:
    import core.function_reachability_engine as fre

    monkeypatch.setattr(fre, "get_engine", lambda *a, **k: engine)
    pipeline = BrainPipeline()
    ctx = {"org_id": "t1", "findings": [finding]}
    pipeline._apply_reachability_verdicts(ctx)
    return ctx["findings"][0]


def test_the_symbol_is_used_when_ingest_recovered_one(monkeypatch) -> None:
    engine = _FakeEngine({"cryptography.%pkcs7_decrypt_der%": ["app.mod.f"]})
    finding = {
        "cve_id": "PYSEC-2026-3552",
        "package_name": "cryptography",
        "vulnerable_symbols": ["pkcs7_decrypt_der"],
    }
    result = _run(monkeypatch, finding, engine)

    assert any("pkcs7_decrypt_der" in q for q in engine.asked), (
        f"the pipeline never asked about the symbol; it asked {engine.asked}"
    )
    assert result["reachability_verdict"] == "reachable"
    assert result["reachability_evidence"] == "symbol"


def test_a_symbol_query_with_no_callers_rules_the_finding_out(monkeypatch) -> None:
    """A specific question that comes back empty IS evidence of absence."""
    engine = _FakeEngine({})
    finding = {
        "cve_id": "PYSEC-2026-3552",
        "package_name": "cryptography",
        "vulnerable_symbols": ["pkcs7_decrypt_der"],
        "consensus_priority": 1,
    }
    result = _run(monkeypatch, finding, engine)
    assert result["reachability_verdict"] == "unreachable"
    assert result["consensus_priority"] == 2, "an established rule-out should downgrade"


def test_no_symbol_but_the_package_IS_used_is_undetermined(monkeypatch) -> None:
    """The case that was silently deleting findings.

    We use the library, and the advisory never told us where the flaw is. There
    is no question here that a call graph can answer, so the honest verdict is
    "undetermined" — and it must NOT downgrade priority.
    """
    engine = _FakeEngine({"cryptography.%": ["app.mod.uses_crypto"]})
    finding = {
        "cve_id": "PYSEC-2026-3554",
        "package_name": "cryptography",
        "consensus_priority": 1,
    }
    result = _run(monkeypatch, finding, engine)

    assert result["reachability_verdict"] == "undetermined"
    assert result["consensus_priority"] == 1, (
        "an unanswerable question downgraded a real finding — this is the bug"
    )


def test_a_package_we_never_call_is_still_ruled_out(monkeypatch) -> None:
    """The blunt filter must keep working: it does most of the elimination.

    Measured at scale, 95 of 119 findings were eliminated purely because the
    package is never called from our code at all.
    """
    engine = _FakeEngine({})
    finding = {"cve_id": "PYSEC-1", "package_name": "somelib", "consensus_priority": 1}
    result = _run(monkeypatch, finding, engine)
    assert result["reachability_verdict"] == "unreachable"
    assert result["consensus_priority"] == 2


def test_undetermined_reaches_the_exploitability_fusion_as_unknown(monkeypatch) -> None:
    """Adding a third state must not fall through the fusion's branches."""
    pipeline = BrainPipeline()
    ctx = {
        "org_id": "t1",
        "findings": [
            {
                "cve_id": "CVE-2024-1",
                "reachability_verdict": "undetermined",
                "kev": True,
            }
        ],
    }
    pipeline._apply_exploitability_verdict(ctx)
    verdict = ctx["findings"][0].get("exploitability")
    assert verdict in {"exploited_unknown_reach", "insufficient_evidence"}, verdict
