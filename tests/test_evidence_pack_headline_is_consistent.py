"""A compliance pack must not contradict itself.

Two code paths build an EvidencePack — SOC2EvidenceGenerator.generate and
BrainPipeline._persist_evidence_pack — and only the first computed the headline.
The second set the control COUNTS and left overall_score / overall_status at
their dataclass defaults, so /api/v1/pipeline/evidence/packs served:

    "overall_score": 0.0, "overall_status": "not_assessed",
    "controls_summary": {"assessed": 3, "effective": 2, "needs_improvement": 1}

Both halves of one artifact, disagreeing, on the document an auditor reads. Now
both writers derive it from score_and_status().
"""

from __future__ import annotations

import pytest

from core.soc2_evidence_generator import score_and_status


def test_nothing_assessed_is_not_assessed_not_a_failing_grade() -> None:
    """The honest-absence rule.

    Assessing zero controls and then reporting "not_qualified" is a fabricated
    negative verdict — it looks like a real judgement about a real posture.
    """
    assert score_and_status(0, 0) == (0.0, "not_assessed")


def test_zero_effective_out_of_some_assessed_IS_a_failing_grade() -> None:
    """The distinction the previous test rests on: this one really was assessed
    and really did fail, so it must not be softened to "not_assessed"."""
    score, status = score_and_status(0, 2)
    assert (score, status) == (0.0, "not_qualified")


@pytest.mark.parametrize(
    "effective,assessed,expected_status",
    [
        (3, 3, "qualified"),
        (2, 3, "qualified_with_exceptions"),
        (1, 3, "not_qualified"),
        (4, 5, "qualified"),
    ],
)
def test_the_thresholds(effective, assessed, expected_status) -> None:
    score, status = score_and_status(effective, assessed)
    assert status == expected_status
    assert score == pytest.approx(effective / assessed, abs=1e-4)


def test_the_pipeline_writer_sets_the_headline() -> None:
    """The actual regression: a pack persisted by the pipeline must carry a
    status consistent with its own counts, not the dataclass default."""
    from core.brain_pipeline import BrainPipeline

    pack_id = BrainPipeline._persist_evidence_pack(
        {"org_id": "acme", "run_id": "r1"},
        {
            "framework": "SOC2",
            "generated_at": "2026-09-03T00:00:00+00:00",
            "controls": {
                "CC6.1": {"status": "effective"},
                "CC6.2": {"status": "effective"},
                "CC6.3": {"status": "needs_improvement"},
            },
        },
    )
    if pack_id is None:
        pytest.skip("evidence store unavailable in this environment")

    from core.soc2_evidence_generator import get_evidence_generator

    pack = get_evidence_generator().get_pack(pack_id)
    assert pack is not None
    assert pack.controls_assessed == 3
    assert pack.controls_effective == 2
    assert pack.overall_status == "qualified_with_exceptions", (
        "a pipeline-persisted pack kept the dataclass default while its own "
        "counts said otherwise"
    )
    assert pack.overall_score == pytest.approx(2 / 3, abs=1e-4)
