"""The evidence bundle has to survive the request that made it.

Evidence is the commercial wedge (ADR-008) — the artifact we ask an assessor to trust.
The pipeline built one, signed it, attached provenance, and put it in a context dict that
died with the request. Meanwhile ``GET /api/v1/pipeline/evidence/packs`` read
``soc2_evidence_generator``'s store, which the pipeline never wrote to.

So every run produced evidence and every listing answered ``{"total": 0, "packs": []}``.
On screen it looked like an empty state — a customer with no data yet — rather than the
entire feature going missing.

A second defect sat underneath it. ``EvidencePack.to_dict()`` nests the timeframe under
``timeframe`` and the counts under ``controls_summary``, while ``_dict_to_evidence_pack``
read flat keys (``timeframe_start``, ``controls_assessed``) that were never written. Any
pack that *was* persisted reloaded with an empty timeframe and every control count at
zero — and ``to_dict()`` never emitted ``pipeline_data`` at all, so provenance existed only
in the live response and never in the archive.

Two components, each correct on its own, and the product lying between them.
"""

from __future__ import annotations

import tempfile

import pytest

from core.brain_pipeline import BrainPipeline


@pytest.fixture()
def clean_store(monkeypatch):
    """A generator backed by a throwaway store."""
    monkeypatch.setenv("FIXOPS_DATA_DIR", tempfile.mkdtemp())
    from core.soc2_evidence_generator import get_evidence_generator

    generator = get_evidence_generator()
    generator._packs.clear()
    return generator


def _evidence(ctx):
    return {
        "framework": "SOC2",
        "generated_at": "2026-08-18T00:00:00Z",
        "timeframe_days": 90,
        "summary": {"total_findings": 1},
        "controls": BrainPipeline._assess_controls(ctx),
        "provenance": BrainPipeline._evidence_provenance(ctx),
    }


CONTEXT = {
    "org_id": "acme",
    "run_id": "BR-TEST",
    "findings": [{"risk_score": 0.9, "source_tool": "trivy", "cve_id": "CVE-2021-44228"}],
    "risk_scores": {"avg": 0.9, "critical": 1},
    "policy_decisions": [{"a": 1}],
    "graph_stats": {"total_nodes": 5},
}


def test_a_generated_bundle_is_findable_afterwards(clean_store) -> None:
    """The whole defect in one assertion."""
    pack_id = BrainPipeline._persist_evidence_pack(CONTEXT, _evidence(CONTEXT))
    assert pack_id, "the bundle was not persisted"

    clean_store._packs.clear()  # force a read from the store, not the in-memory cache
    assert any(p.pack_id == pack_id for p in clean_store.list_packs())


def test_control_counts_survive_persistence(clean_store) -> None:
    """to_dict nests them; the reader looked for flat keys and got zeros."""
    pack_id = BrainPipeline._persist_evidence_pack(CONTEXT, _evidence(CONTEXT))
    clean_store._packs.clear()

    pack = next(p for p in clean_store.list_packs() if p.pack_id == pack_id)
    assert pack.controls_assessed > 0, "control counts were lost on reload"
    assert pack.timeframe_days == 90, "the timeframe was lost on reload"


def test_provenance_survives_persistence(clean_store) -> None:
    """An archived conclusion without its provenance is not evidence."""
    pack_id = BrainPipeline._persist_evidence_pack(CONTEXT, _evidence(CONTEXT))
    clean_store._packs.clear()

    pack = next(p for p in clean_store.list_packs() if p.pack_id == pack_id)
    stored = pack.pipeline_data or {}

    assert stored.get("provenance"), "provenance did not reach the archive"
    assert stored.get("run_id") == "BR-TEST", "the run that produced it was not recorded"
    assert set(stored.get("controls") or {}) >= {"vulnerability_management"}


def test_a_run_that_assessed_nothing_stores_zero_rather_than_inventing(clean_store) -> None:
    """An empty run must archive as assessed-nothing, not as effective."""
    empty_ctx = {"org_id": "acme", "run_id": "BR-EMPTY", "findings": []}
    pack_id = BrainPipeline._persist_evidence_pack(empty_ctx, _evidence(empty_ctx))
    clean_store._packs.clear()

    pack = next(p for p in clean_store.list_packs() if p.pack_id == pack_id)
    assert pack.controls_assessed == 0
    assert pack.controls_effective == 0


def test_archiving_failure_never_loses_the_bundle(monkeypatch) -> None:
    """Evidence generation must not fail because the archive is unavailable."""
    import core.soc2_evidence_generator as module

    def boom():
        raise RuntimeError("store offline")

    monkeypatch.setattr(module, "get_evidence_generator", boom)

    # Returns None rather than raising — the caller still has its bundle.
    assert BrainPipeline._persist_evidence_pack(CONTEXT, _evidence(CONTEXT)) is None
